# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Compare two explicitly selected local functional-metrics reports without scanning."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

from fuzzy1337.adapters.contracts import RequireIdentifier, RequireText
from fuzzy1337.functional_metrics import (
    FUNCTIONAL_REPORT_VERSION,
    FunctionalRun,
    OracleCheck,
    RawEvidence,
    RunStatus,
    ScenarioOracle,
    ScoreRun,
    SerializeReport,
)

MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_SCENARIOS = 256
MAX_CHECKS = 128
MAX_TOTAL_CHECKS = 4096
MAX_RUNS = 512
MAX_RECORD_ITEMS = 128
COMPARISON_VERSION = 1


@dataclass(frozen=True, slots=True)
class Selection:
    """Select one release and identify its caller-declared profile."""

    release_id: str
    profile_id: str

    def __post_init__(self) -> None:
        """Require a valid release and versioned profile identity."""

        RequireText(self.release_id, "release identifier")
        RequireIdentifier(self.profile_id, "profile identifier")

        if re.fullmatch(r".+\.v[1-9][0-9]*", self.profile_id) is None:
            raise ValueError("profile identifier requires a .vN version suffix")


def ReadReport(path: Path) -> bytes:
    """Read a bounded regular file, refusing links at the final path component.

    An explicitly supplied parent directory may resolve through an alias.

    Args:
        path: Explicit local JSON file.

    Returns:
        The exact source bytes.
    """

    original = path.lstat()

    if not stat.S_ISREG(original.st_mode) or original.st_size > MAX_REPORT_BYTES:
        raise ValueError("expected a bounded regular report file")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)

    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())

        if (
            not stat.S_ISREG(opened.st_mode)
            or not os.path.samestat(original, opened)
            or opened.st_size > MAX_REPORT_BYTES
        ):
            raise ValueError("report file changed before it was read")

        raw = stream.read(MAX_REPORT_BYTES + 1)
        final = os.fstat(stream.fileno())

    if (
        len(raw) != opened.st_size or len(raw) > MAX_REPORT_BYTES
        or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        != (final.st_size, final.st_mtime_ns, final.st_ctime_ns)
    ):
        raise ValueError("report file changed during the read")

    return raw


def UniqueObject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object only if each property occurs once.

    Args:
        pairs: Decoded properties before dictionary construction.

    Returns:
        The unique properties.
    """

    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate report property")

        result[key] = value

    return result


def FiniteNumber(value: str) -> float:
    """Reject non-finite JSON numbers, including numeric overflow.

    Args:
        value: JSON numeric token.

    Returns:
        The finite decoded number.
    """

    result = float(value)

    if not math.isfinite(result):
        raise ValueError("report numbers must be finite")

    return result


def Record(value: Any, keys: set[str]) -> dict[str, Any]:
    """Require the exact producer record shape without echoing input data.

    Args:
        value: Decoded JSON object.
        keys: Exact producer fields.

    Returns:
        The validated record.
    """

    if not isinstance(value, dict) or value.keys() != keys:
        raise ValueError("unexpected report record fields")

    return value


def Array(value: Any, limit: int) -> list[Any]:
    """Admit only bounded JSON arrays for sequence-valued fields.

    Args:
        value: Decoded JSON array.
        limit: Maximum number of items.

    Returns:
        The validated array.
    """

    if not isinstance(value, list) or len(value) > limit:
        raise ValueError("invalid or oversized report array")

    return value


def DecodeReport(
    raw: bytes, scanner_id: str, selection: Selection,
) -> tuple[dict[str, ScenarioOracle], dict[str, FunctionalRun]]:
    """Validate producer records and index the explicitly selected runs.

    Args:
        raw: Exact original functional report bytes.
        scanner_id: Selected scanner identity.
        selection: Selected release and declared profile.

    Returns:
        Scenario oracles and selected runs, both indexed by scenario identifier.
    """

    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("report exceeds its byte limit")

    payload = Record(json.loads(raw.decode("utf-8"), object_pairs_hook=UniqueObject,
        parse_float=FiniteNumber, parse_constant=FiniteNumber),
        {"schema_version", "scenarios", "runs", "matrix"})

    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != FUNCTIONAL_REPORT_VERSION
    ):
        raise ValueError("unsupported functional report version")

    matrix = Record(payload["matrix"], {"columns", "rows"})

    if not isinstance(matrix["columns"], list) or not isinstance(matrix["rows"], list):
        raise ValueError("expected report matrix columns and rows arrays")

    oracles: dict[str, ScenarioOracle] = {}
    runs: dict[str, FunctionalRun] = {}
    identities: set[tuple[str, str, str]] = set()
    totalChecks = 0
    checkFields = {field.name for field in fields(OracleCheck)}
    evidenceFields = {field.name for field in fields(RawEvidence)}
    runFields = {field.name for field in fields(FunctionalRun)}
    scenarioFields = {field.name for field in fields(ScenarioOracle)}

    for row in Array(payload["scenarios"], MAX_SCENARIOS):
        data = Record(row, scenarioFields)
        checkRows = Array(data["checks"], MAX_CHECKS)
        totalChecks += len(checkRows)

        if totalChecks > MAX_TOTAL_CHECKS:
            raise ValueError("report exceeds its total check limit")

        checks = tuple(OracleCheck(**Record(item, checkFields)) for item in checkRows)
        roles = tuple(Array(data["required_evidence"], MAX_RECORD_ITEMS))
        oracle = ScenarioOracle(**(data | {"checks": checks, "required_evidence": roles}))

        if oracle.identifier in oracles:
            raise ValueError("duplicate scenario identity")

        oracles[oracle.identifier] = oracle

    for row in Array(payload["runs"], MAX_RUNS):
        scored = Record(row, {"run", "metrics"})

        if not isinstance(scored["metrics"], dict):
            raise ValueError("expected a report metrics object")

        data = Record(scored["run"], runFields)
        evidence = tuple(RawEvidence(**Record(item, evidenceFields))
                         for item in Array(data["evidence"], MAX_RECORD_ITEMS))
        run = FunctionalRun(**(data | {
            "status": RunStatus(data["status"]),
            "detected_checks": tuple(Array(data["detected_checks"], MAX_RECORD_ITEMS)),
            "discovered_objects": tuple(Array(data["discovered_objects"], MAX_RECORD_ITEMS)),
            "evidence": evidence,
        }))
        identity = (run.scenario_id, run.scanner_id, run.release_id)

        if run.scenario_id not in oracles or identity in identities:
            raise ValueError("undeclared scenario or duplicate run identity")

        identities.add(identity)

        if (run.scanner_id, run.release_id) == (scanner_id, selection.release_id):
            runs[run.scenario_id] = run

    return oracles, runs


def OracleIdentity(oracle: ScenarioOracle) -> str:
    """Hash exact target and oracle semantics independently of sequence order.

    Args:
        oracle: Validated source oracle.

    Returns:
        SHA-256 of its canonical comparison semantics.
    """

    facts = asdict(oracle)
    facts["checks"] = sorted(facts["checks"], key=lambda check: check["identifier"])
    facts["required_evidence"] = sorted(oracle.required_evidence)
    return hashlib.sha256(SerializeReport(facts).encode("utf-8")).hexdigest()


def SideFacts(oracle: ScenarioOracle | None, run: FunctionalRun | None) -> dict[str, Any]:
    """Keep source truth and elapsed time visible even for incomparable rows.

    Args:
        oracle: Source scenario when present.
        run: Selected source run when present.

    Returns:
        Side facts with no inferred measurements or finite counts.
    """

    state = run.status.value if run else "not-run" if oracle else "absent-scenario"

    return {
        "state": state,
        "target_pack": oracle.target_pack if oracle else None,
        "target_version": oracle.target_version if oracle else None,
        "oracle_sha256": OracleIdentity(oracle) if oracle else None,
        "duration_seconds": run.duration_seconds if run else None,
        "detected_checks": sorted(set(run.detected_checks)) if run else None,
        "unexpected_detections": None,
        "missing_evidence": None,
        "evidence_completeness": None,
        "finite_counts": None,
    }


def Outcome(expected: bool, detected: bool) -> str:
    """Name the confusion outcome for one applicable closed-world check.

    Args:
        expected: Declared detection truth.
        detected: Actual normalized detection.

    Returns:
        The finite confusion outcome.
    """

    if expected:
        return "tp" if detected else "fn"

    return "fp" if detected else "tn"


def CompareScenario(
    scenario_id: str, before_oracle: ScenarioOracle | None, before_run: FunctionalRun | None,
    after_oracle: ScenarioOracle | None, after_run: FunctionalRun | None, same_profile: bool,
) -> dict[str, Any]:
    """Compare one stable scenario only on the exact same eligible finite oracle.

    Args:
        scenario_id: Shared stable scenario key.
        before_oracle: Baseline declaration.
        before_run: Selected baseline run.
        after_oracle: Candidate declaration.
        after_run: Selected candidate run.
        same_profile: Declared profiles match.

    Returns:
        Separate side facts and eligible per-check changes, or an incompatibility reason.
    """

    baseline = SideFacts(before_oracle, before_run)
    candidate = SideFacts(after_oracle, after_run)
    row: dict[str, Any] = {"scenario_id": scenario_id, "baseline": baseline,
        "candidate": candidate,
        "state": "incomparable", "reason": None, "checks": []}

    finiteCounts = []

    for side, oracle, run in ((baseline, before_oracle, before_run),
                              (candidate, after_oracle, after_run)):
        if oracle is not None and run is not None:
            metrics = ScoreRun(oracle, run)
            side["unexpected_detections"] = metrics["unexpected_detections"]
            side["missing_evidence"] = metrics["missing_evidence"]
            side["evidence_completeness"] = metrics["evidence_completeness"]
            finiteCounts.append({name: metrics[name] for name in ("tp", "fp", "fn", "tn")})

    if before_oracle is None or after_oracle is None:
        row["reason"] = "missing-scenario"

    elif not same_profile:
        row["reason"] = "profile-mismatch"

    elif (before_oracle.target_pack, before_oracle.target_version) != (
        after_oracle.target_pack, after_oracle.target_version,
    ):
        row["reason"] = "target-mismatch"

    elif baseline["oracle_sha256"] != candidate["oracle_sha256"]:
        row["reason"] = "oracle-mismatch"

    elif before_run is None or after_run is None:
        row["reason"] = "missing-run"

    elif (
        before_run.status is not RunStatus.COMPLETED
        or after_run.status is not RunStatus.COMPLETED
    ):
        row["reason"] = "incomplete-run"

    elif not before_oracle.complete:
        row["reason"] = "incomplete-oracle"

    elif not any(check.applicable for check in before_oracle.checks):
        row["reason"] = "empty-oracle"

    else:
        row["state"] = "comparable"
        beforeDetected = set(before_run.detected_checks)
        afterDetected = set(after_run.detected_checks)
        checks = []

        for check in sorted(before_oracle.checks, key=lambda item: item.identifier):
            if not check.applicable:
                continue

            before = Outcome(check.expected is True, check.identifier in beforeDetected)
            after = Outcome(check.expected is True, check.identifier in afterDetected)
            change = "unchanged" if before == after else (
                "improved" if after in {"tp", "tn"} else "regressed"
            )
            checks.append({"check_id": check.identifier, "baseline": before, "candidate": after,
                "change": change})

        row["checks"] = checks
        baseline["finite_counts"], candidate["finite_counts"] = finiteCounts

    return row


def CompareReports(
    baseline: bytes, candidate: bytes, scanner_id: str,
    baseline_selection: Selection, candidate_selection: Selection,
) -> dict[str, Any]:
    """Bind source report bytes and compare the same declared scanner profile offline.

    Args:
        baseline: Original baseline report bytes.
        candidate: Original candidate report bytes.
        scanner_id: Selected scanner identity.
        baseline_selection: Baseline release and profile.
        candidate_selection: Candidate release and profile.

    Returns:
        Deterministically ordered internal comparison and source identities.
    """

    RequireIdentifier(scanner_id, "scanner identifier")
    beforeOracles, beforeRuns = DecodeReport(baseline, scanner_id, baseline_selection)
    afterOracles, afterRuns = DecodeReport(candidate, scanner_id, candidate_selection)
    sameProfile = baseline_selection.profile_id == candidate_selection.profile_id
    scenarios = sorted(beforeOracles.keys() | afterOracles.keys())

    return {
        "kind": "functional-report-comparison",
        "schema_version": COMPARISON_VERSION,
        "scanner_id": scanner_id,
        "baseline": asdict(baseline_selection)
        | {"report_sha256": hashlib.sha256(baseline).hexdigest()},
        "candidate": asdict(candidate_selection)
        | {"report_sha256": hashlib.sha256(candidate).hexdigest()},
        "scenarios": [
            CompareScenario(scenarioId, beforeOracles.get(scenarioId),
                beforeRuns.get(scenarioId), afterOracles.get(scenarioId),
                afterRuns.get(scenarioId), sameProfile)
            for scenarioId in scenarios
        ],
    }


def Main(argv: Sequence[str] | None = None) -> int:
    """Emit deterministic comparison JSON or fail without printing input data.

    Args:
        argv: Optional explicit command arguments.

    Returns:
        Zero on comparison output, or two for invalid or unreadable input.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--scanner", required=True)
    parser.add_argument("--baseline-release", required=True)
    parser.add_argument("--candidate-release", required=True)
    parser.add_argument("--baseline-profile", required=True)
    parser.add_argument("--candidate-profile", required=True)
    args = parser.parse_args(argv)

    try:
        report = CompareReports(ReadReport(args.baseline), ReadReport(args.candidate), args.scanner,
            Selection(args.baseline_release, args.baseline_profile),
            Selection(args.candidate_release, args.candidate_profile))

    except (OSError, OverflowError, RecursionError, TypeError, ValueError):
        print("Cannot compare the selected functional reports: invalid or unreadable input.",
              file=sys.stderr)
        return 2

    sys.stdout.write(SerializeReport(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
