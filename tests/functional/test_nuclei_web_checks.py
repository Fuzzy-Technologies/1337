# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Genuine reviewed response checks against independently authored vulnerable/fixed web targets."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import fuzzy1337
from fuzzy1337.adapters import ImpactLevel, SerializeContract
from fuzzy1337.adapters.nuclei import NucleiProfile, NucleiTemplate
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import InvocationDigest
from fuzzy1337.findings import Findings, FindingStatus
from fuzzy1337.functional_metrics import (
    BuildReport,
    FunctionalRun,
    OracleCheck,
    RawEvidence,
    RenderHtml,
    RenderMarkdown,
    RunStatus,
    ScenarioOracle,
    SerializeReport,
)
from fuzzy1337.jobs import JobFailureCode, JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.nucleiscan import PlanNucleiScan, RunNucleiScan
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, PolicyConfirmation
from fuzzy1337.reporting import ReportSnapshot, VerifyReportEvidence
from fuzzy1337.scan_commands import CreateWorkspace, OpenWorkspace
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from tests.web_vulnerability_helpers import Oracle, OwnedWebVulnerabilityTarget

PACK = Path(fuzzy1337.__file__).parent / "data/nuclei"
MANIFEST = json.loads((PACK / "manifest.v1.json").read_text(encoding="utf-8"))
EVIDENCE = Path("functional-evidence/nuclei-web-checks")


@pytest.fixture(scope="module")
def native_web_check_binary():
    """Require the explicit real provider before starting any owned target or scan."""

    supplied = os.environ.get("FUZZY1337_NUCLEI_BINARY")

    if supplied is None:
        pytest.skip("Genuine web-check acceptance requires FUZZY1337_NUCLEI_BINARY")

    executable = Path(supplied).absolute()
    assert executable.is_file(), "Explicit native acceptance requires an installed provider."

    return executable


def Policy():
    """Allow only the existing STANDARD Nuclei capability with separate exact-plan confirmation."""

    return ImpactPolicy("owned-web-checks", maximum_impact=ImpactLevel.STANDARD,
        permissions=(CapabilityPermission("web.http-template-check", "native.nuclei",
                                          ImpactLevel.STANDARD),))


def SelectedProfile(root, family):
    """Materialize one declared first-party artifact and preserve all reviewed identity fields."""

    record = next(item for item in MANIFEST["templates"] if item["family"] == family)
    raw = (PACK / record["filename"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == record["sha256"], "Selected review pin drifted."
    template_path = root / record["filename"]
    template_path.write_bytes(raw)
    configuration = root / "empty.yaml"
    configuration.write_bytes(b"{}\n")
    template = NucleiTemplate(record["template_id"], str(template_path), record["sha256"],
        record["size_bytes"], record["source_reference"], record["source_revision"],
        record["review_reference"], record["reviewed_profile"])

    return NucleiProfile("owned-" + family, (template,), str(configuration))


def ScopedWorkspace(root, url, family):
    """Create an explicit owner and exact URL/IP consent without default target expansion."""

    CreateWorkspace(root, "web-checks", "Owned native web-check acceptance")
    target = Target(TargetKind.URL, url)
    assert target.value == url, "The handwritten target route must already be canonical."
    address = Target(TargetKind.IP, "127.0.0.1")
    now = datetime.now(UTC)
    LocalScopeStore(root).Create(ScopeSnapshot("local", "web-checks", ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:owned", "consent:owned-web-checks",
        (now - timedelta(minutes=1)).isoformat(), (now + timedelta(minutes=10)).isoformat(),
    ), targets=(target, address), allow=(target, address)))

    return target, SelectedProfile(root, family)


def Scenario(metadata, case):
    """Translate only independent target expectations into the existing finite oracle schema."""

    return ScenarioOracle(
        identifier=case["id"], target_pack=metadata["target_pack"],
        target_version=metadata["target_version"], provenance=metadata["provenance"],
        complete=True,
        checks=(OracleCheck(case["id"], case["capability"], case["expected_match"]),),
    )


def PersistMatrix(scenarios, runs):
    """Preserve actual completed/failed/not-run cells from one unchanged independent oracle."""

    report = BuildReport(scenarios, runs)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "report.json").write_text(SerializeReport(report), encoding="utf-8")
    (EVIDENCE / "matrix.md").write_text(RenderMarkdown(report), encoding="utf-8")
    (EVIDENCE / "matrix.html").write_text(RenderHtml(report), encoding="utf-8")

    return report


def VerifiedRunEvidence(root, plan, summary):
    """Read exact owning raw stdout/stderr and bind both to the actual selected invocation."""

    store = LocalEvidenceStore(root / "evidence")
    evidence = []

    for artifact in summary.snapshot.artifacts:
        record = artifact.evidence
        assert store.Get(record.evidence_id) == record, "Raw acquisition identity changed."
        assert record.provenance.invocation_sha256 == InvocationDigest(plan.invocation), (
            "Native streams must belong to the exact reviewed prepared invocation."
        )
        assert record.provenance.tool_version == plan.invocation.provider_version, (
            "Native streams must retain the observed real provider version."
        )
        evidence.append(RawEvidence(record.reference.role, record.reference.media_type,
                                    store.Read(record.reference).decode("utf-8")))

    evidence.append(RawEvidence("invocation", "application/json",
                                SerializeContract(plan.invocation)))

    return tuple(evidence)


def VerifyFindingProvenance(model, profile, plan):
    """Check durable detector identity, unknown confidence and review-attributed observations."""

    template = profile.templates[0]
    matches = [item for item in model.observations if item.kind == "nuclei.template-match"]

    for finding in Findings(model):
        assert finding.check_id == "nuclei." + template.template_id, (
            "Canonical findings must come from the explicitly selected reviewed check."
        )
        assert finding.status is FindingStatus.OPEN and finding.confidence == 0.0, (
            "A response match must not invent operator confirmation or exploit confidence."
        )
        assert len(finding.provenance) == 1, "A fresh case must retain its actual acquisition."
        provenance = finding.provenance[0]
        assert provenance.provider_version == plan.invocation.provider_version, (
            "Finding attribution lost the actual native provider version."
        )
        assert {item.role for item in provenance.evidence_references} == {"stdout", "stderr"}, (
            "Findings must preserve the real enclosing native execution evidence."
        )

    assert len(matches) == len(Findings(model)), "Template review metadata was not persisted."

    for observation in matches:
        expected = {
            "template_id": template.template_id,
            "template_sha256": template.sha256,
            "template_source": template.source_reference,
            "template_revision": template.source_revision,
            "template_review": template.review_reference,
            "profile_sha256": profile.Digest,
        }
        assert all(observation.attributes[key] == value for key, value in expected.items()), (
            "Persisted response observations must retain exact template/source/review binding."
        )


def test_GenuineReviewedChecksProduceIndependentOracleMetricsAndReopen(
    tmp_path, native_web_check_binary,
):
    """Run real single-GET checks against file/SQLite/HTML behavior and finite negative controls."""

    metadata = Oracle()
    cases = metadata["cases"]
    scenarios = tuple(Scenario(metadata, case) for case in cases)
    runs = []
    binary_sha256 = hashlib.sha256(native_web_check_binary.read_bytes()).hexdigest()
    report = PersistMatrix(scenarios, runs)

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        for case in cases:
            root = tmp_path / ("workspace-" + case["id"])
            target, profile = ScopedWorkspace(root, service.Url(case), case["family"])
            before = service.Observe()
            started = time.monotonic()
            plan = PlanNucleiScan(root, "local", target, "operator:owned", profile,
                                  str(native_web_check_binary), Policy)
            assert "synthetic" not in plan.invocation.provider_version, (
                "Synthetic executables cannot establish genuine scanner acceptance."
            )
            assert service.Observe() == before, "Planning contacted the owned target."
            confirmation = PolicyConfirmation(plan.policy_plan.intent_sha256,
                                               "approval:owned-" + case["id"])
            summary = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
                str(native_web_check_binary), Policy, confirmation=confirmation))
            observed = service.Observe()
            model = LocalModelStore(root).Open()
            actual_findings = Findings(model)
            expected_check_id = "nuclei." + profile.templates[0].template_id
            detected = tuple(case["id"] if finding.check_id == expected_check_id else
                             finding.check_id for finding in actual_findings)
            status = RunStatus.COMPLETED if summary.snapshot.state is JobState.COMPLETED else (
                RunStatus.TIMED_OUT if summary.snapshot.failure is not None and
                summary.snapshot.failure.code is JobFailureCode.TIMEOUT else RunStatus.CRASHED
            )
            raw = VerifiedRunEvidence(root, plan, summary)
            runs.append(FunctionalRun(case["id"], "1337.nuclei.web-checks",
                "nuclei-" + plan.invocation.provider_version + "+checks-" + MANIFEST["version"],
                status, time.monotonic() - started, detected_checks=detected,
                evidence=(*raw, RawEvidence("provider", "application/json", json.dumps({
                    "executable_sha256": binary_sha256,
                    "version": plan.invocation.provider_version,
                    "profile": json.loads(SerializeContract(profile)),
                }, sort_keys=True)))))
            report = PersistMatrix(scenarios, runs)
            output = EVIDENCE / case["id"]
            output.mkdir(parents=True, exist_ok=True)
            shutil.copytree(root / "evidence", output / "evidence", dirs_exist_ok=True)
            (output / "plan.json").write_text(json.dumps(plan.ToDict(), indent=2), encoding="utf-8")
            (output / "summary.json").write_text(json.dumps(summary.ToDict(), indent=2),
                                                  encoding="utf-8")
            (output / "target-observations.json").write_text(json.dumps(observed, indent=2),
                                                             encoding="utf-8")
            assert summary.ExitCode() == 0, "A genuine scanner failure must fail acceptance."
            assert {item.role for item in raw} == {"stdout", "stderr", "invocation"}, (
                "Successful native acceptance must preserve both actual terminal streams."
            )
            assert observed["requests"][len(before["requests"]):] == [case["route"]], (
                "The selected template expanded, changed or followed its exact approved GET."
            )
            assert not observed["errors"], "The owned target reported a real mechanism failure."
            assert len(actual_findings) == int(case["expected_match"]), (
                "Actual persisted findings disagree with the independently authored target oracle."
            )
            VerifyFindingProvenance(model, profile, plan)
            assert OpenWorkspace(root)["verified_evidence_records"] == 2, (
                "Actual native raw acquisitions must survive workspace reopen."
            )
            verified = VerifyReportEvidence(ReportSnapshot(model), root)
            assert len(verified.EvidenceReferences()) == 2, (
                "Report verification must use the actual saved execution streams."
            )
            metrics = next(item["metrics"] for item in report["runs"]
                           if item["run"]["scenario_id"] == case["id"])
            assert metrics["fp"] == metrics["fn"] == metrics["unexpected_detection_count"] == 0, (
                "The genuine detector missed a positive or invented a response finding."
            )
            assert metrics["evidence_completeness"] == 1, "A scored run lost raw execution proof."

        observations = service.Observe()
        assert any(item["rows"] == ["owned-private-row"] and not item["parameterized"]
                   for item in observations["queries"]), (
            "The SQL positive must come from actual read-only interpolated query behavior."
        )
        assert any(item["rows"] == [] and item["parameterized"]
                   for item in observations["queries"]), (
            "The fixed SQL control must execute the real parameterized query."
        )
        assert observations["file_reads"], "Git acceptance must expose an actual owned file."

    metrics = [item["metrics"] for item in report["runs"]]
    assert sum(item["tp"] for item in metrics) == sum(case["expected_match"] for case in cases), (
        "The finite detector matrix must count actual matched positive cases only."
    )
    expected_negatives = sum(not case["expected_match"] for case in cases)
    assert sum(item["tn"] for item in metrics) == expected_negatives, (
        "Every declared fixed, decoy and redirect control must be a measured true negative."
    )


def test_GenuineSelectedCheckRequiresSeparateConfirmation(tmp_path, native_web_check_binary):
    """Even shipped checks cannot contact a target or create findings without exact consent."""

    case = next(item for item in Oracle()["cases"] if item["id"] == "git-exposed")

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        root = tmp_path / "workspace"
        target, profile = ScopedWorkspace(root, service.Url(case), case["family"])
        summary = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
                                           str(native_web_check_binary), Policy))
        assert summary.ExitCode() == 3, "Missing exact STANDARD confirmation must deny execution."
        assert service.Observe()["requests"] == [], "A shipped template granted target access."
        assert Findings(LocalModelStore(root).Open()) == (), "Denied work invented a finding."
        assert summary.snapshot.artifacts == (), "Denied execution invented raw provider streams."
