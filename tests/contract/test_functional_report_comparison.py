# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Check the offline comparison of two independently selected functional reports."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.functional_metrics import (
    BuildReport,
    FunctionalRun,
    OracleCheck,
    RawEvidence,
    RunStatus,
    ScenarioOracle,
    SerializeReport,
)

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/compare_functional_reports.py"
SPEC = importlib.util.spec_from_file_location("compare_functional_reports", TOOL)
assert SPEC is not None and SPEC.loader is not None, "Comparison tool source is unavailable"
comparison = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = comparison
SPEC.loader.exec_module(comparison)

SCANNER = "native.web-check"
PROFILE = "owned.synthetic.v1"
BEFORE = comparison.Selection("baseline-1", PROFILE)
AFTER = comparison.Selection("candidate-2", PROFILE)


def Oracle(**changes):
    """Declare complete independent positive, negative and non-applicable checks."""

    oracle = ScenarioOracle("owned.case", "owned", "target-v1", "owned-oracle-v1", (
        OracleCheck("positive", "web.positive", True),
        OracleCheck("negative", "web.negative", False),
        OracleCheck("irrelevant", "web.irrelevant", None, applicable=False),
    ), complete=True, required_evidence=("stdout", "stderr"))
    return replace(oracle, **changes)


def Run(selection, detections=(), **changes):
    """Supply exact synthetic run facts for one selected release."""

    run = FunctionalRun("owned.case", SCANNER, selection.release_id, RunStatus.COMPLETED,
        1.25, detections, evidence=(RawEvidence("stdout", "text/plain", "original\n"),))
    return replace(run, **changes)


def Report(scenarios, runs):
    """Serialize reports through the unchanged functional metrics producer."""

    return SerializeReport(BuildReport(scenarios, runs)).encode("utf-8")


def Compare(before_oracle, after_oracle, before_run, after_run, *, after=AFTER):
    """Compare one selected scenario and expose its exact scenario row."""

    left = Report((before_oracle,), (before_run,) if before_run else ())
    right = Report((after_oracle,), (after_run,) if after_run else ())
    return comparison.CompareReports(left, right, SCANNER, BEFORE, after)["scenarios"][0]


def test_FiniteComparisonKeepsMissesAndFalsePositivesSeparateFromAnomalies():
    """Detect finite regressions while keeping duplicate and unknown detections out of counts."""

    oracle = Oracle()
    before = Run(BEFORE, ("positive", "positive", "irrelevant"))
    after = Run(AFTER, ("negative", "negative", "unknown"), duration_seconds=2.5)
    row = Compare(oracle, oracle, before, after)

    assert row["state"] == "comparable", "The exact oracle and selected profiles must join."
    assert row["reason"] is None, "Comparable runs do not have an incomparability reason."
    assert row["baseline"]["finite_counts"] == {"tp": 1, "fp": 0, "fn": 0, "tn": 1}
    assert row["candidate"]["finite_counts"] == {"tp": 0, "fp": 1, "fn": 1, "tn": 0}
    assert row["baseline"]["unexpected_detections"] == ["irrelevant"]
    assert row["candidate"]["unexpected_detections"] == ["unknown"]
    assert row["candidate"]["missing_evidence"] == ["stderr"]
    assert row["candidate"]["evidence_completeness"] == 0.5
    assert row["baseline"]["duration_seconds"] == 1.25
    assert row["candidate"]["duration_seconds"] == 2.5
    assert row["checks"] == [
        {"check_id": "negative", "baseline": "tn", "candidate": "fp", "change": "regressed"},
        {"check_id": "positive", "baseline": "tp", "candidate": "fn", "change": "regressed"},
    ]


@pytest.mark.parametrize(("after_detections", "verdicts"), [
    (("positive",), [("fp", "tn", "improved"), ("fn", "tp", "improved")]),
    (("negative",), [("fp", "fp", "unchanged"), ("fn", "fn", "unchanged")]),
])
def test_StableOrCorrectedMistakesStayVisible(after_detections, verdicts):
    """Keep exact per-check improvements and unchanged mistakes rather than a net score."""

    oracle = Oracle()
    row = Compare(oracle, oracle, Run(BEFORE, ("negative",)), Run(AFTER, after_detections))

    assert [(check["baseline"], check["candidate"], check["change"])
            for check in row["checks"]] == verdicts


def test_CompatibleOracleIgnoresOnlyDeclarationOrder():
    """Match exactly equal oracle semantics even if record or evidence-role order changes."""

    oracle = Oracle()
    reordered = replace(oracle, checks=oracle.checks[::-1],
        required_evidence=oracle.required_evidence[::-1])
    row = Compare(oracle, reordered, Run(BEFORE), Run(AFTER))

    assert row["state"] == "comparable"
    assert row["baseline"]["oracle_sha256"] == row["candidate"]["oracle_sha256"]


@pytest.mark.parametrize(("oracle_change", "profile", "reason"), [
    ({"target_pack": "other"}, PROFILE, "target-mismatch"),
    ({"target_version": "target-v2"}, PROFILE, "target-mismatch"),
    ({"provenance": "changed-provenance"}, PROFILE, "oracle-mismatch"),
    ({"checks": (OracleCheck("positive", "web.positive", False),)}, PROFILE, "oracle-mismatch"),
    ({"checks": (OracleCheck("positive", "web.changed", True),)}, PROFILE, "oracle-mismatch"),
    ({"required_evidence": ("stdout",)}, PROFILE, "oracle-mismatch"),
    ({"complete": False}, PROFILE, "oracle-mismatch"),
    ({}, "owned.synthetic.v2", "profile-mismatch"),
])
def test_IncompatibleOracleOrProfileCannotSupplyComparisonCredits(oracle_change, profile, reason):
    """Refuse cross-definition accuracy while retaining each side's execution facts."""

    row = Compare(Oracle(), Oracle(**oracle_change), Run(BEFORE), Run(AFTER),
        after=comparison.Selection(AFTER.release_id, profile))

    assert row["state"] == "incomparable"
    assert row["reason"] == reason
    assert row["checks"] == []
    assert row["baseline"]["finite_counts"] is row["candidate"]["finite_counts"] is None
    assert row["baseline"]["state"] == row["candidate"]["state"] == "completed"


@pytest.mark.parametrize(("state", "oracle", "reason"), [
    (RunStatus.CRASHED, Oracle(), "incomplete-run"),
    (RunStatus.TIMED_OUT, Oracle(), "incomplete-run"),
    (RunStatus.COMPLETED, Oracle(complete=False), "incomplete-oracle"),
    (RunStatus.COMPLETED, Oracle(checks=()), "empty-oracle"),
])
def test_PartialOrQualitativeEvidenceDoesNotBecomeAccuracy(state, oracle, reason):
    """Report retained durations and failures without creating negative or passing results."""

    row = Compare(oracle, oracle, Run(BEFORE), Run(AFTER, status=state))

    assert row["reason"] == reason
    assert row["candidate"]["state"] == state.value
    assert row["candidate"]["duration_seconds"] == 1.25
    assert row["candidate"]["detected_checks"] == []
    assert row["candidate"]["finite_counts"] is None


def test_MissingScenarioAndMissingSelectedRunStayDistinct():
    """A nearby producer or release cannot substitute for a missing selected run."""

    oracle = Oracle()
    extra = Oracle(identifier="owned.absent")
    declared = Oracle(identifier="owned.unexecuted")
    left = Report((oracle, extra, declared), (Run(BEFORE),))
    right = Report((oracle, declared), (
        Run(AFTER, scanner_id="other.scanner"), Run(BEFORE, ("positive",)),
    ))
    rows = comparison.CompareReports(left, right, SCANNER, BEFORE, AFTER)["scenarios"]

    assert [(row["scenario_id"], row["reason"], row["candidate"]["state"]) for row in rows] == [
        ("owned.absent", "missing-scenario", "absent-scenario"),
        ("owned.case", "missing-run", "not-run"),
        ("owned.unexecuted", "missing-run", "not-run"),
    ]
    assert all(row["candidate"]["duration_seconds"] is None for row in rows)
    assert all(row["candidate"]["finite_counts"] is None for row in rows)


def test_MatrixAndScoreClaimsCannotOverrideOriginalRecords():
    """Recompute verdicts from typed source records even if derived summaries disagree."""

    left = Report((Oracle(),), (Run(BEFORE, ("positive",)),))
    right = json.loads(Report((Oracle(),), (Run(AFTER, ("negative",)),)))
    right["matrix"] = {"columns": [None], "rows": [42]}
    right["runs"][0]["metrics"] = {"tp": 999, "fn": 0}
    result = comparison.CompareReports(left, SerializeReport(right).encode(), SCANNER,
        BEFORE, AFTER)

    assert result["scenarios"][0]["candidate"]["finite_counts"] == {
        "tp": 0, "fp": 1, "fn": 1, "tn": 0,
    }


@pytest.mark.parametrize("malformed", [
    b'{"schema_version":1,"schema_version":1}',
    b'{"schema_version":1,"pack_id":"native","cells":[]}',
    b'{"schema_version":2,"matrix":{"columns":[],"rows":[]},"runs":[],"scenarios":[]}',
    b'{"schema_version":true,"matrix":{"columns":[],"rows":[]},"runs":[],"scenarios":[]}',
    b'{"schema_version":1,"matrix":{"columns":[],"rows":[]},"runs":[],"scenarios":"text"}',
    b'{"schema_version":1,"matrix":{"columns":null,"rows":[]},"runs":[],"scenarios":[]}',
    b'{"schema_version":1,"matrix":{"columns":[],"rows":42},"runs":[],"scenarios":[]}',
    b'{"schema_version":1,"matrix":{"columns":[],"rows":[1e999]},"runs":[],"scenarios":[]}',
    b'{"schema_version":1,"matrix":{"columns":[],"rows":[NaN]},"runs":[],"scenarios":[]}',
    b'\xff',
])
def test_UnsupportedOrInvalidSourcesFailClosed(malformed):
    """Reject wrong report families, malformed values and unverifiable source bytes."""

    valid = Report((Oracle(),), (Run(AFTER),))

    with pytest.raises(ValueError):
        comparison.CompareReports(malformed, valid, SCANNER, BEFORE, AFTER)


@pytest.mark.parametrize("damage", ["scenario", "run", "undeclared", "status", "sequence"])
def test_MalformedTypedRecordsCannotBeUsed(damage):
    """Reject aliased scenarios, orphaned runs and malformed canonical record fields."""

    left = Report((Oracle(),), (Run(BEFORE),))
    right = json.loads(Report((Oracle(),), (Run(AFTER),)))

    if damage == "scenario":
        right["scenarios"] *= 2

    elif damage == "run":
        right["runs"] *= 2

    elif damage == "undeclared":
        right["runs"][0]["run"]["scenario_id"] = "other.case"

    elif damage == "status":
        right["runs"][0]["run"]["status"] = "skipped"

    else:
        right["runs"][0]["run"]["detected_checks"] = "positive"

    with pytest.raises(ValueError):
        comparison.CompareReports(left, SerializeReport(right).encode(), SCANNER, BEFORE, AFTER)


def test_ProfileMustDeclareAVersion():
    """Refuse a profile selection that supplies no exact versioned identity."""

    with pytest.raises(ValueError, match="version suffix"):
        comparison.Selection("candidate", "owned.synthetic")


def test_AggregateOracleBudgetRefusesBeforeScoring(monkeypatch):
    """Limit total checks even when each individual scenario is small."""

    left = Report((Oracle(), Oracle(identifier="owned.other")), (Run(BEFORE),))
    right = Report((Oracle(),), (Run(AFTER),))
    monkeypatch.setattr(comparison, "MAX_TOTAL_CHECKS", 5)

    with pytest.raises(ValueError, match="total check limit"):
        comparison.CompareReports(left, right, SCANNER, BEFORE, AFTER)


def test_OversizedInputAndNonregularFileRefuseBeforeComparison(tmp_path, monkeypatch):
    """The explicit local input boundary rejects directories and byte-budget excess."""

    report = Report((Oracle(),), (Run(BEFORE),))
    path = tmp_path / "report.json"
    path.write_bytes(report)
    monkeypatch.setattr(comparison, "MAX_REPORT_BYTES", len(report) - 1)

    with pytest.raises(ValueError):
        comparison.ReadReport(path)

    with pytest.raises(ValueError):
        comparison.ReadReport(tmp_path)

    with pytest.raises(ValueError):
        comparison.DecodeReport(report, SCANNER, BEFORE)


def test_OfflineToolRunsDeterministicallyAndLeavesOriginalInputsUntouched(tmp_path):
    """Exercise the actual process boundary and its truthful malformed-input exit."""

    before = Report((Oracle(),), (Run(BEFORE, ("positive",)),))
    after = Report((Oracle(),), (Run(AFTER, ("negative",)),))
    left = tmp_path / "baseline.json"
    right = tmp_path / "candidate.json"
    left.write_bytes(before)
    right.write_bytes(after)
    args = [sys.executable, str(TOOL), str(left), str(right), "--scanner", SCANNER,
        "--baseline-release", BEFORE.release_id, "--candidate-release", AFTER.release_id,
        "--baseline-profile", PROFILE, "--candidate-profile", PROFILE]

    first = subprocess.run(args, cwd=ROOT, capture_output=True, check=True, timeout=10)
    second = subprocess.run(args, cwd=ROOT, capture_output=True, check=True, timeout=10)
    assert first.stdout == second.stdout
    assert json.loads(first.stdout)["baseline"]["report_sha256"] == (
        hashlib.sha256(before).hexdigest()
    )
    assert json.loads(first.stdout)["candidate"]["report_sha256"] == (
        hashlib.sha256(after).hexdigest()
    )
    assert left.read_bytes() == before and right.read_bytes() == after
    assert b"original" not in first.stdout, "Source evidence content must not appear in output."

    invalid = b"private invalid input"
    right.write_bytes(invalid)
    failure = subprocess.run(args, cwd=ROOT, capture_output=True, check=False, timeout=10)

    assert failure.returncode == 2 and not failure.stdout
    assert invalid not in failure.stderr
    assert right.read_bytes() == invalid
