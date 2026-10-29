# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Accept the finite owned-loopback canary check through actual files and saved native Findings."""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from fuzzy1337.adapters import ImpactLevel, SerializeContract
from fuzzy1337.adapters.contracts import JsonValue
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import InvocationDigest
from fuzzy1337.findings import Findings, FindingSeverity, FindingStatus
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
from fuzzy1337.jobs import JobState
from fuzzy1337.model import LocalModelStore, ModelProvenance, ObjectKind, SecurityObject
from fuzzy1337.native_web import (
    NATIVE_WEB_CAPABILITY,
    NATIVE_WEB_PROVIDER_ID,
    PlanNativeWebScan,
    RunNativeWebScan,
)
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, PolicyConfirmation
from fuzzy1337.reporting import ReportSnapshot, VerifyReportEvidence
from fuzzy1337.requests import (
    BodyKind,
    Endpoint,
    InjectionLocation,
    InjectionPoint,
    ProjectRequests,
    RequestsFromObject,
    RequestTemplate,
    ValueBinding,
)
from fuzzy1337.scan_commands import CreateWorkspace, OpenWorkspace
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from tests.web_file_access_helpers import Oracle, OwnedWebFileAccessTarget

CHECK_ID = "native.file-canary-disclosure"
CAPABILITY = "web.file-canary-check"
REQUEST_PROFILE = "owned-loopback-file-canary-query-v1"
WORKSPACE_ID = "native-file-canary"
NOW = datetime(2026, 10, 23, 12, tzinfo=UTC)
EVIDENCE = Path("functional-evidence/native-file-canary")


def AuthorityClock():
    """Fix authority time independently of real transport and process deadline measurements."""

    return NOW


def CanaryPolicy(capability=CAPABILITY):
    """Permit only one explicitly named STANDARD capability without implicit loopback authority."""

    return ImpactPolicy("owned-file-canary", maximum_impact=ImpactLevel.STANDARD,
        permissions=(CapabilityPermission(capability, NATIVE_WEB_PROVIDER_ID,
                                          ImpactLevel.STANDARD),))


def CanaryWorkspace(root, url, extra_urls=()):
    """Authorize only the declared fixture URL choices and their sole literal-loopback address."""

    CreateWorkspace(root, WORKSPACE_ID, "Owned loopback file-canary acceptance")
    targets = tuple(Target(TargetKind.URL, value) for value in (url, *extra_urls))
    assert tuple(target.value for target in targets) == (url, *extra_urls), (
        "Independent fixture URLs must already use the exact selected canonical spelling."
    )
    address = Target(TargetKind.IP, "127.0.0.1")
    allowed = (*targets, address)
    LocalScopeStore(root).Create(ScopeSnapshot("local", WORKSPACE_ID, ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:owned", "consent:owned-file-canary",
        (NOW - timedelta(minutes=1)).isoformat(), (NOW + timedelta(minutes=10)).isoformat(),
    ), targets=allowed, allow=allowed))

    return targets[0]


def CanaryRun(root, target, *, confirmation=True):
    """Plan and explicitly confirm the single finite selected local-fixture operation."""

    plan = PlanNativeWebScan(root, "local", target, "operator:owned", CanaryPolicy,
                            check_id=CHECK_ID, clock=AuthorityClock)
    approval = PolicyConfirmation(plan.policy_plan.intent_sha256, "approval:owned-canary")
    summary = asyncio.run(RunNativeWebScan(root, "local", target, "operator:owned", CanaryPolicy,
        check_id=CHECK_ID, confirmation=approval if confirmation else None, clock=AuthorityClock))

    return plan, summary


def CanaryEvidence(root, plan, summary):
    """Read the original worker report and exact invocation through the existing evidence owner."""

    store = LocalEvidenceStore(root / "evidence")
    raw = []

    for artifact in summary.snapshot.artifacts:
        record = artifact.evidence
        assert store.Get(record.evidence_id) == record, "Original acquisition identity drifted."
        assert record.provenance.invocation_sha256 == InvocationDigest(plan.invocation), (
            "Original canary streams must bind the exact selected approved invocation."
        )
        raw.append(RawEvidence(record.reference.role, record.reference.media_type,
                               store.Read(record.reference).decode("utf-8")))

    raw.append(RawEvidence("invocation", "application/json", SerializeContract(plan.invocation)))
    assert {item.role for item in raw} == {"stdout", "stderr", "invocation"}, (
        "An assessed canary case must retain original stdout/stderr and exact invocation metadata."
    )

    return tuple(raw)


def PersistCanaryMatrix(scenarios, runs):
    """Retain scored outcomes and unassessed cells without altering the independent oracle."""

    report = BuildReport(scenarios, runs)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "report.json").write_text(SerializeReport(report), encoding="utf-8")
    (EVIDENCE / "matrix.md").write_text(RenderMarkdown(report), encoding="utf-8")
    (EVIDENCE / "matrix.html").write_text(RenderHtml(report), encoding="utf-8")

    return report


def test_OwnedCanaryMatrixUsesActualReadsAndReopensOriginalEvidenceOffline(tmp_path):
    """Score one real private-file disclosure and five independent negative controls."""

    metadata = Oracle()
    cases = metadata["cases"]
    scenarios = tuple(ScenarioOracle(case["id"], metadata["target_pack"],
        metadata["target_version"], metadata["provenance"],
        (OracleCheck(case["id"], CAPABILITY, case["expected_private_file_disclosure"]),),
        complete=True) for case in cases)
    runs = []
    reopen = []
    PersistCanaryMatrix(scenarios, runs)

    with OwnedWebFileAccessTarget(tmp_path / "target") as service:
        for case in cases:
            root = tmp_path / ("workspace-" + case["id"])
            target = CanaryWorkspace(root, service.Url(case))
            before = service.Observe()
            plan = PlanNativeWebScan(root, "local", target, "operator:owned", CanaryPolicy,
                                    check_id=CHECK_ID, clock=AuthorityClock)
            assert service.Observe() == before, "Read-only canary planning contacted the target."
            assert plan.invocation.argv[1:4] == ("-I", "-m", "fuzzy1337.native_web_worker"), (
                "Canary acceptance must run the installed isolated first-party worker."
            )
            started = time.monotonic()
            summary = asyncio.run(RunNativeWebScan(root, "local", target, "operator:owned",
                CanaryPolicy, check_id=CHECK_ID, clock=AuthorityClock,
                confirmation=PolicyConfirmation(plan.policy_plan.intent_sha256,
                                                "approval:owned-" + case["id"])))
            model = LocalModelStore(root).Open()
            findings = Findings(model)
            observed = service.Observe()
            raw = CanaryEvidence(root, plan, summary)
            detected = tuple(case["id"] if finding.check_id == CHECK_ID else finding.check_id
                             for finding in findings)
            status = RunStatus.COMPLETED if summary.snapshot.state is JobState.COMPLETED else (
                RunStatus.CRASHED)
            runs.append(FunctionalRun(case["id"], NATIVE_WEB_PROVIDER_ID,
                "development-contract-" + plan.invocation.provider_version, status,
                time.monotonic() - started, detected_checks=detected, evidence=raw))
            report = PersistCanaryMatrix(scenarios, runs)
            output = EVIDENCE / case["id"]
            output.mkdir(parents=True, exist_ok=True)
            shutil.copytree(root / "evidence", output / "evidence", dirs_exist_ok=True)
            (output / "plan.json").write_text(json.dumps(plan.ToDict(), indent=2), encoding="utf-8")
            (output / "summary.json").write_text(json.dumps(summary.ToDict(), indent=2),
                                                 encoding="utf-8")
            (output / "target-observations.json").write_text(json.dumps(observed, indent=2),
                                                            encoding="utf-8")
            assert summary.ExitCode() == 0 and summary.snapshot.state is JobState.COMPLETED, (
                "An incomplete/failed acquisition cannot count as an assessed canary control."
            )
            assert observed["requests"][len(before["requests"]):] == [case["route"]], (
                "The file check changed, expanded or repeated the single approved query."
            )
            expected = case["expected_behavior"]
            body = expected["body"].encode("utf-8")
            reads = observed["file_reads"][len(before["file_reads"]):]
            assert [item["path"] for item in reads] == expected["file_reads"], (
                "Actual owned-file reads disagree with the handwritten independent mechanism."
            )
            assert observed["denials"][len(before["denials"]):] == expected["denials"], (
                "A containment refusal was replaced with a private file read."
            )
            assert observed["errors"][len(before["errors"]):] == expected["errors"], (
                "Missing-file state or a target failure lost its actual fixed error observation."
            )

            for record in reads:
                assert record == {"input": expected["input"], "path": expected["file_reads"][0],
                    "size_bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}, (
                        "File-read evidence must bind actual owned path, input and disclosed bytes."
                    )

            expected_match = case["expected_private_file_disclosure"]
            assert len(findings) == int(expected_match), (
                "Persisted native Findings disagree with independent private-disclosure truth."
            )
            stdout = next(item.content for item in raw if item.role == "stdout")
            worker = json.loads(stdout)
            template = RequestTemplate.FromDict(JsonValue(
                plan.invocation.request.parameters["request_template"]))
            endpoint = Endpoint(WORKSPACE_ID, service.base_url, urlsplit(case["route"]).path)
            point, = template.injection_points
            assert template.endpoint == endpoint and point.Coordinate() == ("query", "name", 0), (
                "The selected request lost its existing endpoint owner or sole explicit QUERY slot."
            )
            assert template.body_kind is BodyKind.NONE and template.session_reference is None, (
                "A fixture canary check unexpectedly acquired body or credential/session inputs."
            )
            assert "private/canary.txt" not in json.dumps(template.ToDict()), (
                "A structural template retained concrete file input instead of an unresolved slot."
            )
            assert worker["request_reference"] == template.Reference() and (
                worker["injection_reference"] == point.Reference(template.Reference())
            ), "Original worker report does not bind the independently revalidated #58 references."
            assert (worker["request_profile"], worker["check_id"]) == (REQUEST_PROFILE, CHECK_ID), (
                "Original evidence changed the selected finite request profile or native check."
            )
            assert worker["url"] == target.value and worker["status"] == case["expected_status"], (
                "The original record lost its exact selected URL or observed response status."
            )
            assert worker["body_bytes"] == len(body) and worker["body_sha256"] == (
                hashlib.sha256(body).hexdigest()), "Original report lost response attribution."
            assert worker["matched"] is expected_match and expected["body"].strip() not in stdout, (
                "The predicate changed or transient response text leaked into worker output."
            )
            endpoints = model.Objects(ObjectKind.ENDPOINT)
            assert len(endpoints) == 1 and endpoints[0].identity == endpoint.Identity(), (
                "Query checks must reuse the #58 endpoint rather than create another identity."
            )
            assert RequestsFromObject(endpoints[0]) == (template,), (
                "The actual structural request was not durably projected through its owner."
            )

            for finding in findings:
                assert (finding.subject_reference, finding.location_key, finding.check_id,
                        finding.severity, finding.status, finding.confidence) == (
                    endpoint.Identity().Reference(), target.value, CHECK_ID,
                    FindingSeverity.LOW, FindingStatus.OPEN, 0.0,
                ), "A finite canary response must not invent general traversal or confirmed impact."

            metrics = next(item["metrics"] for item in report["runs"]
                           if item["run"]["scenario_id"] == case["id"])
            assert metrics["fp"] == metrics["fn"] == metrics["unexpected_detection_count"] == 0, (
                "The native finite check missed a disclosure or invented a control finding."
            )
            assert metrics["evidence_completeness"] == 1, "An assessed case lost original evidence."
            reopen.append((root, model))

    assert not service.root.exists() and not service.thread.is_alive(), (
        "Canary acceptance leaked its owned files, listener or non-daemon thread."
    )

    for root, model in reopen:
        assert OpenWorkspace(root)["verified_evidence_records"] == 2, (
            "Closed-target offline reopen lost original canary stdout/stderr evidence."
        )
        verified = VerifyReportEvidence(ReportSnapshot(model), root)
        assert len(verified.EvidenceReferences()) == 2, "Offline verification lost provenance."

    metrics = [item["metrics"] for item in report["runs"]]
    assert sum(item["tp"] for item in metrics) == 1 and sum(item["tn"] for item in metrics) == 5, (
        "Six-case acceptance must score exactly TP1/TN5 without inferring clean failures."
    )


@pytest.mark.parametrize("case_id,path,body,matched", [
    ("private-traversal", "private/canary.txt", b"changed-owned-nonsecret-file\n", False),
    ("missing-control", "private/missing.txt", b"owned-private-file-canary\n", True),
])
def test_CanaryPredicateFollowsActualOwnedBytesInsteadOfPriorRouteLabels(
    tmp_path, case_id, path, body, matched,
):
    """Alter only the two declared owned files and falsify the original positive/negative labels."""

    with OwnedWebFileAccessTarget(tmp_path / "target") as service:
        (service.root / path).write_bytes(body)
        root = tmp_path / "workspace"
        target = CanaryWorkspace(root, service.Url(case_id))
        _, summary = CanaryRun(root, target)
        assert summary.ExitCode() == 0, "Changed owned bytes must remain an assessed response."
        assert len(Findings(LocalModelStore(root).Open())) == int(matched), (
            "Canary detection followed the prior oracle/route label instead of actual file bytes."
        )
        assert service.Observe()["file_reads"] == [{
            "input": "../" + path, "path": path, "size_bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }], "The falsification probe must execute the real declared owned-file read."


@pytest.mark.parametrize("denial", ["confirmation", "git-only-permission"])
def test_OwnedLoopbackMembershipDoesNotGrantCanaryExecution(tmp_path, denial):
    """Neither a local fixture URL nor the existing Git capability authorizes this new operation."""

    with OwnedWebFileAccessTarget(tmp_path / "target") as service:
        root = tmp_path / "workspace"
        target = CanaryWorkspace(root, service.Url("private-traversal"))

        if denial == "git-only-permission":
            with pytest.raises(PermissionError):
                PlanNativeWebScan(root, "local", target, "operator:owned",
                    lambda: CanaryPolicy(NATIVE_WEB_CAPABILITY), check_id=CHECK_ID,
                    clock=AuthorityClock)

        else:
            _, summary = CanaryRun(root, target, confirmation=False)
            assert summary.ExitCode() == 3 and summary.snapshot.artifacts == (), (
                "Missing exact-plan confirmation must deny before launching a native worker."
            )

        assert service.Observe()["requests"] == [], "Denied canary execution contacted the fixture."
        assert Findings(LocalModelStore(root).Open()) == (), "Denied canary work invented Findings."


def test_CanaryConfirmationCannotSubstituteAnotherExplicitlyScopedQuery(tmp_path):
    """Two allowed fixture URLs still require separate exact invocation confirmation."""

    with OwnedWebFileAccessTarget(tmp_path / "target") as service:
        root = tmp_path / "workspace"
        original = service.Url("private-traversal")
        replacement = service.Url("fixed-public")
        target = CanaryWorkspace(root, original, (replacement,))
        plan = PlanNativeWebScan(root, "local", target, "operator:owned", CanaryPolicy,
                                check_id=CHECK_ID, clock=AuthorityClock)
        summary = asyncio.run(RunNativeWebScan(root, "local", Target(TargetKind.URL, replacement),
            "operator:owned", CanaryPolicy, check_id=CHECK_ID, clock=AuthorityClock,
            confirmation=PolicyConfirmation(plan.policy_plan.intent_sha256,
                                            "approval:other-selected-query")))
        assert summary.ExitCode() == 3 and summary.snapshot.artifacts == (), (
            "Changing a selected allowed query reused a different invocation's confirmation."
        )
        assert service.Observe()["requests"] == [], "An intent mismatch reached the owned fixture."
        assert Findings(LocalModelStore(root).Open()) == (), "Mismatched intent invented Findings."


def test_CanaryExecutionPreservesPriorEndpointTemplatesAndOperatorData(tmp_path):
    """One actual acquisition merges its request without replacing existing endpoint ownership."""

    with OwnedWebFileAccessTarget(tmp_path / "target") as service:
        root = tmp_path / "workspace"
        target = CanaryWorkspace(root, service.Url("private-traversal"))
        endpoint = Endpoint(WORKSPACE_ID, service.base_url, "/files/vulnerable")
        prior = (RequestTemplate(endpoint), RequestTemplate(endpoint, (
            InjectionPoint(InjectionLocation.HEADER, "X-Note", ValueBinding("operator-note")),
        )))
        attribution = ModelProvenance("operator.annotation", "run:prior", NOW.isoformat(),
                                      "local", target.Reference())
        patch = ProjectRequests(prior, provenance=(attribution,))
        store = LocalModelStore(root)
        original = store.Open()
        seeded, _ = original.Apply(objects=(SecurityObject(endpoint.Identity(),
            {**patch.attributes, "operator_note": "retain this annotation"}, (attribution,)),))
        store.Save(seeded, expected_revision=original.revision)
        plan, summary = CanaryRun(root, target)
        assert summary.ExitCode() == 0, "The actual canary acquisition failed after seeding data."
        model = store.Open()
        endpoints = model.Objects(ObjectKind.ENDPOINT)
        assert len(endpoints) == 1 and endpoints[0].identity == endpoint.Identity(), (
            "A query acquisition duplicated the existing structural endpoint."
        )
        template = RequestTemplate.FromDict(JsonValue(
            plan.invocation.request.parameters["request_template"]))
        assert RequestsFromObject(endpoints[0]) == tuple(sorted((*prior, template),
            key=RequestTemplate.Reference)), "Canary ingestion replaced existing request shapes."
        assert endpoints[0].attributes["operator_note"] == "retain this annotation" and (
            attribution in endpoints[0].provenance
        ), "Canary ingestion discarded operator data or its original attribution."
        assert len(Findings(model)) == 1, "The actual positive response did not create one Finding."
        assert OpenWorkspace(root)["object_counts"]["endpoint"] == 1, (
            "Durable reopen changed the merged endpoint model."
        )
