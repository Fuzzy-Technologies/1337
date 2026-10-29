# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Synthetic contract fixtures verify comparison semantics, never scanner effectiveness."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path, PureWindowsPath
from unittest.mock import MagicMock

import pytest
import yaml
from jsonschema import ValidationError

from fuzzy1337.adapters import AdapterRequest, ImpactLevel
from fuzzy1337.adapters.nuclei import NucleiAdapter, NucleiProfile, NucleiTemplate
from tests.functional import external_benchmark
from tests.functional.external_benchmark import (
    CONTRACT_DIRECTORY,
    BuildComparison,
    DecodeJson,
    LoadPack,
    ReadJson,
    ValidateObservation,
)


def ContractObservation(pack, target, root, *, case_id="metrics.exposed",
                        track="native-engine", matched=False):
    """Construct clearly synthetic local byte records for isolated validator tests only."""

    case = next(item for item in pack["cases"] if item["id"] == case_id)
    provider = next(item for item in pack["scanner_tracks"] if item["id"] == track)
    execution = {
        "scanner_id": provider["scanner_id"],
        "scanner_version": "contract-fixture",
        "scanner_sha256": "a" * 64,
        "product_revision": None if track == "external-nuclei" else "b" * 40,
        "rule_sha256": provider["artifact"]["sha256"] if provider["artifact"] else "c" * 64,
        "source_revision": pack["source_revision"],
        "image_index_digest": target["index_digest"],
        "platform_digest": target["platform_digests"]["linux/amd64"],
        "target_url": "http://172.20.0.2:3000" + case["path"],
        "target_instance": "contract-fixture-" + track,
        "reset_contract_sha256": "d" * 64, "network_internal": True, "published_ports": 0,
        "argv": ["contract-fixture-not-a-scanner", "--no-execution"],
        "exit_code": 0, "duration_seconds": 0.1, "request_count": 1,
        "effective_budget": copy.deepcopy(pack["requested_budget"]),
        "findings": ([{"rule_id": provider["rule_ids"][0], "path": case["path"]}]
                     if matched else []),
        "evidence": [],
    }
    WriteContractEvidence(execution, root)

    return {"schema_version": 1, "pack_id": pack["pack_id"], "case_id": case_id,
            "scanner_track": track, "status": "completed",
            "reason": "Synthetic contract fixture; no scanner or Docker executed",
            "execution": execution}


def WriteContractEvidence(execution, root, *, content_overrides=None):
    """Refresh synthetic bytes and hashes so mutations exercise their intended contract."""

    invocation_keys = ("argv", "scanner_id", "scanner_version", "scanner_sha256", "rule_sha256",
                       "product_revision", "effective_budget")
    target_keys = ("source_revision", "image_index_digest", "platform_digest", "target_url",
                   "target_instance", "reset_contract_sha256", "network_internal",
                   "published_ports")
    content = {
        "stdout": b"synthetic contract fixture; no provider executed\n", "stderr": b"",
        "invocation": json.dumps({key: execution[key] for key in invocation_keys}).encode(),
        "findings": json.dumps(execution["findings"]).encode(),
        "target-provenance": json.dumps({key: execution[key] for key in target_keys}).encode(),
        "requests": json.dumps([{"method": "GET", "url": execution["target_url"]}]).encode(),
    }
    content.update(content_overrides or {})
    execution["evidence"] = []

    for role, raw in content.items():
        relative = Path(execution["target_instance"]) / (role + ".json")
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        execution["evidence"].append({"role": role, "path": relative.as_posix(),
                                      "sha256": hashlib.sha256(raw).hexdigest(),
                                      "size_bytes": len(raw)})


def ContractNucleiObservation(pack, target, root, *, case_id="metrics.exposed",
                              track="external-nuclei", matched=False):
    """Build inert v2 records without implying genuine Nuclei execution or runtime custody."""

    observation = ContractObservation(pack, target, root, case_id=case_id,
                                      track=track, matched=matched)
    observation.update(schema_version=2, status="completed" if matched else "unproven")
    execution = observation["execution"]
    execution["scanner_version"] = "3.4.10"

    for finding in execution["findings"]:
        finding["target_url"] = execution["target_url"]

    WriteNucleiContractEvidence(observation, root)

    return observation


def WriteNucleiContractEvidence(observation, root, *, stdout=None, attempt=None):
    """Keep synthetic raw identities and unknown contact provenance independently mutable."""

    execution = observation["execution"]
    prefix = "nuclei." if observation["scanner_track"] == "whole1337" else ""
    records = [{"template-id": finding["rule_id"].removeprefix(prefix), "type": "http",
                "matched-at": finding["target_url"]} for finding in execution["findings"]]
    raw = b"".join(json.dumps(item).encode() + b"\n" for item in records)
    accounting = {"basis": "approved-single-configured-nuclei-invocation",
                  "approved_attempt_count": 1, "independent_server_contact_count": None}
    WriteContractEvidence(execution, root, content_overrides={
        "stdout": raw if stdout is None else stdout,
        "attempt-provenance": json.dumps(accounting if attempt is None else attempt).encode(),
    })


@pytest.fixture
def available_contract_pack():
    """Make every track available only within synthetic comparison contract fixtures."""

    pack, target = LoadPack()

    for track in pack["scanner_tracks"]:
        track["implementation"] = "available"

    return pack, target


def test_SourceOnlyInventoryKeepsAllNineCellsUnrun(tmp_path):
    """No source oracle or candidate artifact can create scanner execution evidence."""

    pack, target = LoadPack()
    report = BuildComparison(pack, target, [], tmp_path)
    assert len(report["cells"]) == 9, "The unexecuted matrix must retain all nine declared cells."
    assert {item["status"] for item in report["cells"]} == {"not-run"}, (
        "Unexecuted cells must remain explicitly not run."
    )
    assert all(item["score"] is None for item in report["cells"]), (
        "Unexecuted cells must not receive detection scores."
    )
    assert report["whole_application_accuracy"] is None and report["observations"] == [], (
        "An empty run must not invent observations or whole-application accuracy."
    )
    assert {item["expected"] for item in pack["cases"]} == {True, False}, (
        "The finite oracle must retain both positive and negative cases."
    )


def test_PlannedDetectorCannotClaimCompletedAcceptance(tmp_path):
    """The native source mapping stays a visible gap until its actual implementation lands."""

    pack, target = LoadPack()
    pack["scanner_tracks"][0]["implementation"] = "planned"
    observation = ContractObservation(pack, target, tmp_path)

    with pytest.raises(ValueError, match="Planned detectors"):
        BuildComparison(pack, target, [observation], tmp_path)


@pytest.mark.parametrize("case_id,matched,score", [
    ("metrics.exposed", True, "tp"), ("metrics.exposed", False, "fn"),
    ("metrics.json-control", True, "fp"), ("metrics.html-control", False, "tn"),
])
def test_ExactFiniteCasesHaveDeterministicClassifications(
    available_contract_pack, tmp_path, case_id, matched, score,
):
    """Known positives and real endpoint controls score supplied synthetic observations exactly."""

    pack, target = available_contract_pack
    observation = ContractObservation(pack, target, tmp_path, case_id=case_id, matched=matched)
    report = BuildComparison(pack, target, [observation], tmp_path)
    cell = next(item for item in report["cells"]
                if item["case_id"] == case_id and item["scanner_track"] == "native-engine")
    assert cell["score"] == score, (
        "The completed observation must receive its declared finite classification."
    )
    assert report["finite_completed_case_counts"]["native-engine"][score] == 1, (
        "The finite count must include exactly one classified observation."
    )
    assert report["whole_application_accuracy"] is None, (
        "Finite case classification must not imply whole-application accuracy."
    )


@pytest.mark.parametrize("status", ["not-run", "prerequisite-failed", "unsupported"])
def test_PrerequisitesAndUnsupportedCapabilitiesNeverBecomeApplicationNegatives(tmp_path, status):
    """Missing Docker/provider and capability gaps remain unscored applicable cases."""

    pack, target = LoadPack()
    observation = {"schema_version": 1, "pack_id": pack["pack_id"],
                   "case_id": "metrics.exposed", "scanner_track": "native-engine",
                   "status": status, "reason": "Explicit prerequisite or capability gap",
                   "execution": None}
    cell = BuildComparison(pack, target, [observation], tmp_path)["cells"][0]
    assert cell["status"] == status and cell["score"] is None, (
        "Incomplete execution must retain its status without a detection score."
    )
    assert cell["applicability"] == "applicable" and cell["expected"] is True, (
        "Execution failure must not rewrite case applicability or expected truth."
    )
    observation["status"] = "not-applicable"

    with pytest.raises(ValueError, match="applicability"):
        ValidateObservation(pack, target, observation, tmp_path)


@pytest.mark.parametrize("status", ["crashed", "timed-out"])
def test_FailedExecutionRetainsPartialFindingsWithoutScores(
    available_contract_pack, tmp_path, status,
):
    """A partial detection and raw artifacts survive failures without invented success."""

    pack, target = available_contract_pack
    observation = ContractObservation(pack, target, tmp_path, matched=True)
    observation["status"] = status
    observation["execution"]["exit_code"] = 124 if status == "timed-out" else 1
    report = BuildComparison(pack, target, [observation], tmp_path)
    assert report["cells"][0]["score"] is None, "Unadjudicated execution must remain unscored."
    assert report["observations"][0]["execution"]["findings"], (
        "Unscored execution must preserve its original Findings."
    )


def test_UnmappedAndOffRouteFindingsNeedAdjudication(available_contract_pack, tmp_path):
    """An unfamiliar rule or route is neither a true positive nor an invented false positive."""

    pack, target = available_contract_pack
    observation = ContractObservation(pack, target, tmp_path)
    observation["execution"]["findings"] = [
        {"rule_id": "unknown.external.rule", "path": "/metrics"},
        {"rule_id": "native.prometheus-exposition", "path": "/different-route"},
    ]
    WriteContractEvidence(observation["execution"], tmp_path)
    report = BuildComparison(pack, target, [observation], tmp_path)
    assert report["cells"][0]["score"] == "fn", (
        "An unmatched expected-positive case must remain a false negative."
    )
    assert len(report["cells"][0]["unadjudicated_findings"]) == 2, (
        "Unrelated Findings must remain visible for independent adjudication."
    )
    assert report["finite_completed_case_counts"]["native-engine"]["fp"] == 0, (
        "Unrelated Findings must not silently become adjudicated false positives."
    )


def test_EvidenceMutationAndMissingRecordsCannotEstablishCompletion(
    available_contract_pack, tmp_path,
):
    """Raw byte custody and all required roles are mandatory for completed cases."""

    pack, target = available_contract_pack
    observation = ContractObservation(pack, target, tmp_path)
    record = observation["execution"]["evidence"][0]
    (tmp_path / record["path"]).write_bytes(b"changed")

    with pytest.raises(ValueError, match="acquisition record"):
        ValidateObservation(pack, target, observation, tmp_path)

    WriteContractEvidence(observation["execution"], tmp_path)
    observation["execution"]["evidence"].pop()

    with pytest.raises(ValueError, match="bounded execution and evidence"):
        ValidateObservation(pack, target, observation, tmp_path)


@pytest.mark.parametrize("field,value", [
    ("target_url", "http://203.0.113.9:3000/metrics"),
    ("target_url", "http://172.20.0.2:3000/other"),
    ("scanner_id", "different-provider"),
    ("source_revision", "e" * 40), ("exit_code", 1), ("request_count", 0),
])
def test_ChangedTargetOrFailedProviderCannotClaimCompletedRun(
    available_contract_pack, tmp_path, field, value,
):
    """Successful comparison cannot hide target drift or lack of an actual request."""

    pack, target = available_contract_pack
    observation = ContractObservation(pack, target, tmp_path)
    observation["execution"][field] = value
    WriteContractEvidence(observation["execution"], tmp_path)

    with pytest.raises(ValueError):
        ValidateObservation(pack, target, observation, tmp_path)


def test_BudgetAndResetDifferencesStayVisible(available_contract_pack, tmp_path):
    """Different actual resource limits or reused state cannot imply equal-budget comparison."""

    pack, target = available_contract_pack
    native = ContractObservation(pack, target, tmp_path)
    external = ContractObservation(pack, target, tmp_path, track="external-nuclei")
    external["execution"]["effective_budget"]["max_response_bytes"] = 1048576
    WriteContractEvidence(external["execution"], tmp_path)
    report = BuildComparison(pack, target, [native, external], tmp_path)
    assert report["pairwise_conditions"][0]["differences"] == ["effective-budgets-differ"], (
        "Pairwise conditions must disclose differing effective budgets."
    )
    assert any(item["budget_deviation"] for item in report["cells"]), (
        "The matrix must expose at least one declared budget deviation."
    )


@pytest.mark.parametrize("applicability", ["manual", "not-applicable", "applicable"])
def test_ManualInapplicableAndUnknownTruthRemainUnscored(
    available_contract_pack, tmp_path, applicability,
):
    """No expectation may be invented from missing truth or a scanner's supported feature set."""

    pack, target = available_contract_pack
    pack["cases"][0].update(applicability=applicability, expected=None)
    observation = ContractObservation(pack, target, tmp_path)

    if applicability != "applicable":
        observation.update(status=applicability, execution=None)

    cell = BuildComparison(pack, target, [observation], tmp_path)["cells"][0]
    assert cell["score"] is None and cell["expected"] is None, (
        "A case without declared truth must remain unscored."
    )


@pytest.mark.parametrize("path", [
    "../escaped.json", "/tmp/escaped.json", pytest.param(None, id="native-absolute"),
])
def test_EvidenceCannotEscapeItsOwnedDirectory(available_contract_pack, tmp_path, path):
    """Traversal, rooted paths, and native absolute paths fail before artifact reads."""

    pack, target = available_contract_pack
    observation = ContractObservation(pack, target, tmp_path)

    if path is None:
        path = str(tmp_path.parent / "escaped.json")

    observation["execution"]["evidence"][0]["path"] = path

    with pytest.raises(ValueError, match="beneath"):
        ValidateObservation(pack, target, observation, tmp_path)


@pytest.mark.parametrize("path", [
    "/tmp/escaped.json", r"\tmp\escaped.json", r"C:escaped.json",
    r"C:\tmp\escaped.json", r"\\server\share\escaped.json",
])
def test_WindowsAnchoredEvidenceFailsBeforeFilesystemAccess(monkeypatch, path):
    """Windows root, drive, and UNC paths cannot reset the owned evidence prefix."""

    evidence_root = MagicMock(spec=Path)
    monkeypatch.setattr(external_benchmark, "Path", PureWindowsPath)

    with pytest.raises(ValueError, match="beneath"):
        external_benchmark.VerifiedEvidence({"evidence": [{"path": path}]}, evidence_root)

    assert evidence_root.mock_calls == [], (
        "Anchored evidence must fail before the evidence root is joined or accessed."
    )


def test_ConsistentHashesCannotHideChangedAcquisitionMetadata(available_contract_pack, tmp_path):
    """A rewritten invocation with a fresh hash must still match the declared approved inputs."""

    pack, target = available_contract_pack
    observation = ContractObservation(pack, target, tmp_path)
    record = next(item for item in observation["execution"]["evidence"]
                  if item["role"] == "invocation")
    raw = json.dumps({"argv": ["different-provider"]}).encode()
    (tmp_path / record["path"]).write_bytes(raw)
    record.update(sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw))

    with pytest.raises(ValueError, match="invocation differs"):
        ValidateObservation(pack, target, observation, tmp_path)


@pytest.mark.parametrize("role,key", [
    ("invocation", "scanner_id"), ("target-provenance", "source_revision"),
])
def test_ContradictoryAcquisitionKeysCannotHideBehindFreshHashes(
    available_contract_pack, tmp_path, role, key,
):
    """Every acquired structured role uses the strict contract decoder before field matching."""

    pack, target = available_contract_pack
    observation = ContractObservation(pack, target, tmp_path)
    record = next(item for item in observation["execution"]["evidence"] if item["role"] == role)
    path = tmp_path / record["path"]
    raw = ('{"' + key + '":"contradictory-first-value",').encode() + path.read_bytes()[1:]
    path.write_bytes(raw)
    record.update(sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw))

    with pytest.raises(ValueError, match="repeats a key"):
        ValidateObservation(pack, target, observation, tmp_path)


@pytest.mark.parametrize("raw", [
    b'[{"nested":{"key":1,"key":2}}]', b'[{"nested":NaN}]',
    b'{"nested":[{"key":Infinity}]}',
    b'{"nested":[{"key":1e999}]}', b'[{"nested":{"key":-1e999}}]',
])
def test_StructuredEvidenceRejectsNestedAmbiguityAndNonfiniteValues(raw):
    """List-shaped findings/request roles cannot hide nested duplicate or nonfinite metadata."""

    with pytest.raises(ValueError):
        DecodeJson(raw)


def test_CandidateTemplateUsesRealAdapterPreparationWithoutExecution(tmp_path):
    """Prepare genuine adapter arguments while explicitly providing no scanner execution proof."""

    path = CONTRACT_DIRECTORY / "templates/prometheus-exposition.yaml"
    raw = path.read_bytes()
    template = yaml.safe_load(raw)
    request = template["http"][0]
    assert set(template) == {"id", "info", "http"}, (
        "The pinned template must retain its closed top-level shape."
    )
    assert set(request) == {"method", "path", "redirects", "matchers-condition", "matchers"}, (
        "The pinned request must retain its closed execution and matcher fields."
    )
    assert request["method"] == "GET" and request["path"] == ["{{BaseURL}}"], (
        "The template must issue only the selected exact GET."
    )
    assert request["redirects"] is False and request["matchers-condition"] == "and", (
        "The template must disable redirects and require all matchers."
    )
    predicate = request["matchers"][2]["regex"][0]
    assert re.search(predicate, "# HELP process_cpu_user_seconds_total User CPU\n"
                     "# TYPE process_cpu_user_seconds_total counter\n"
                     'process_cpu_user_seconds_total{app="示例"} 1.2e-3\n'), (
        "The pinned predicate must recognize the declared valid exposition sample."
    )
    assert not re.search(predicate, '<html>process_cpu_user_seconds_total</html>'), (
        "An HTML identifier mention must not satisfy the exposition predicate."
    )
    configuration = tmp_path / "empty.yaml"
    configuration.write_bytes(b"{}\n")
    selected = NucleiTemplate(template["id"], str(path), hashlib.sha256(raw).hexdigest(),
                              len(raw), "first-party:labs/external/benchmark", "1",
                              "contract-only:unexecuted-candidate", "single-get-exact-url")
    profile = NucleiProfile("contract-only-prometheus", (selected,), str(configuration))
    adapter = NucleiAdapter(lambda reference: b"", profile, provider_version="3.4.10")
    invocation = adapter.PrepareInvocation(
        AdapterRequest("web.http-template-check", "target:contract-fixture", ImpactLevel.STANDARD,
                       {"url": "http://172.20.0.2:3000/metrics", "profile_sha256": profile.Digest,
                        "timeout_seconds": 3, "rate_limit": 1}))
    assert "-no-stdin" in invocation.argv and "-ni" in invocation.argv, (
        "The candidate invocation must disable stdin and interaction."
    )


def test_ObservationSchemaRejectsUnknownFieldsAndAmbiguousJson(tmp_path):
    """Versioned result shape and JSON identities fail closed."""

    pack, target = LoadPack()
    observation = {"schema_version": 1, "pack_id": pack["pack_id"],
                   "case_id": "metrics.exposed", "scanner_track": "native-engine",
                   "status": "not-run", "reason": "No Docker", "execution": None,
                   "invented_accuracy": 1}

    with pytest.raises(ValidationError):
        ValidateObservation(pack, target, observation, tmp_path)

    path = tmp_path / "duplicate.json"
    path.write_text('{"status":"not-run","status":"completed"}')

    with pytest.raises(ValueError, match="repeats a key"):
        ReadJson(path)


@pytest.mark.parametrize("track", ["whole1337", "external-nuclei"])
@pytest.mark.parametrize("case_id", [
    "metrics.exposed", "metrics.json-control", "metrics.html-control",
])
def test_V2EmptySuccessfulInvocationStaysUnproven(
    available_contract_pack, tmp_path, track, case_id,
):
    """Exit zero with empty JSONL proves neither response success nor finite absence."""

    pack, target = available_contract_pack
    observation = ContractNucleiObservation(pack, target, tmp_path, track=track, case_id=case_id)
    report = BuildComparison(pack, target, [observation], tmp_path)
    cell = next(item for item in report["cells"]
                if item["case_id"] == case_id and item["scanner_track"] == track)
    evidence = external_benchmark.VerifiedEvidence(observation["execution"], tmp_path)
    assert report["schema_version"] == 2 and cell["status"] == "unproven", (
        "The v2 report must retain successful invocation as an unproven case outcome."
    )
    assert cell["score"] is None and report["pairwise_conditions"] == [], (
        "Unproven output cannot receive a response-level score or completed-case comparison."
    )
    assert all(report["finite_completed_case_counts"][track][key] == 0
               for key in ("tp", "fp", "fn", "tn")), (
        "Neither positive nor negative truth can convert empty output to FN or TN."
    )
    assert evidence["stdout"] == b"" and observation["execution"]["exit_code"] == 0, (
        "The original empty output and successful process status must remain available."
    )
    assert DecodeJson(evidence["attempt-provenance"])["independent_server_contact_count"] is None, (
        "The approved attempt cannot invent independent contact telemetry."
    )
    observation["status"] = "completed"

    with pytest.raises(ValueError, match="absence stays unproven"):
        ValidateObservation(pack, target, observation, tmp_path)


@pytest.mark.parametrize("track", ["whole1337", "external-nuclei"])
@pytest.mark.parametrize("case_id,score", [
    ("metrics.exposed", "tp"), ("metrics.json-control", "fp"),
])
def test_V2ExplicitBoundMatchMayReceiveOnlyPositiveScores(
    available_contract_pack, tmp_path, track, case_id, score,
):
    """Raw exact rule/input identity permits a finite TP or FP without claiming real execution."""

    pack, target = available_contract_pack
    observation = ContractNucleiObservation(pack, target, tmp_path, track=track,
                                          case_id=case_id, matched=True)
    report = BuildComparison(pack, target, [observation], tmp_path)
    cell = next(item for item in report["cells"]
                if item["case_id"] == case_id and item["scanner_track"] == track)
    assert cell["score"] == score and report["finite_completed_case_counts"][track][score] == 1, (
        "Only a bound explicit match may contribute its finite positive classification."
    )
    assert report["observations"] == [observation], (
        "The report must preserve original observation identities."
    )
    assert report["whole_application_accuracy"] is None, (
        "The report must preserve acquired observations without application-wide accuracy."
    )
    observation["status"] = "unproven"

    with pytest.raises(ValueError, match="mapped match"):
        ValidateObservation(pack, target, observation, tmp_path)


@pytest.mark.parametrize("track", ["whole1337", "external-nuclei"])
@pytest.mark.parametrize("change", ["rule", "path", "authority"])
def test_V2UnmappedRecordsRemainVisibleWithoutAbsenceCredit(
    available_contract_pack, tmp_path, track, change,
):
    """Unknown rules, off-route matches and another authority cannot become scored observations."""

    pack, target = available_contract_pack
    observation = ContractNucleiObservation(pack, target, tmp_path, track=track, matched=True)
    finding = observation["execution"]["findings"][0]

    if change == "rule":
        finding["rule_id"] = ("nuclei." if track == "whole1337" else "") + "unknown.external.rule"

    elif change == "path":
        finding.update(path="/off-case", target_url="http://172.20.0.2:3000/off-case")

    else:
        finding["target_url"] = "http://172.20.0.99:3000/metrics"

    observation["status"] = "unproven"
    WriteNucleiContractEvidence(observation, tmp_path)
    report = BuildComparison(pack, target, [observation], tmp_path)
    cell = next(item for item in report["cells"]
                if item["case_id"] == "metrics.exposed" and item["scanner_track"] == track)
    assert cell["score"] is None and cell["unadjudicated_findings"] == [finding], (
        "Unmapped explicit records must remain visible without receiving TP, FP or absence credit."
    )
    assert cell["applicability"] == "applicable" and cell["expected"] is True, (
        "Unmapped records cannot rewrite independent application truth."
    )


@pytest.mark.parametrize("status", ["failed", "crashed", "timed-out"])
def test_V2FailedExecutionRetainsOriginalBytesAndPartialMatches(
    available_contract_pack, tmp_path, status,
):
    """Malformed output and actual failures preserve available bytes and matches without scoring."""

    pack, target = available_contract_pack
    observation = ContractNucleiObservation(pack, target, tmp_path, matched=True)
    observation["status"] = status
    observation["execution"]["exit_code"] = 0 if status == "failed" else 1
    raw = b'{"truncated":\xff\r\n'
    WriteNucleiContractEvidence(observation, tmp_path, stdout=raw)
    report = BuildComparison(pack, target, [observation], tmp_path)
    cell = next(item for item in report["cells"] if item["scanner_track"] == "external-nuclei")
    assert cell["status"] == status and cell["score"] is None, (
        "A failure cannot turn an available partial match into completed acceptance."
    )
    assert report["observations"][0]["execution"]["findings"], (
        "Failed observations must preserve their available partial matches."
    )
    evidence = external_benchmark.VerifiedEvidence(observation["execution"], tmp_path)
    assert evidence["stdout"] == raw, (
        "Unscored malformed stdout must remain byte-exact instead of being normalized away."
    )


@pytest.mark.parametrize("change", [
    "missing-role", "known-contacts", "wrong-basis", "missing-count",
])
def test_V2InvocationOnlyProvenanceCannotClaimServerTelemetry(
    available_contract_pack, tmp_path, change,
):
    """Successful Nuclei envelopes require an explicit attempt basis and unknown contact count."""

    pack, target = available_contract_pack
    observation = ContractNucleiObservation(pack, target, tmp_path)
    attempt = {"basis": "approved-single-configured-nuclei-invocation",
               "approved_attempt_count": 1, "independent_server_contact_count": None}

    if change == "known-contacts":
        attempt["independent_server_contact_count"] = 1

    elif change == "wrong-basis":
        attempt["basis"] = "observed-response"

    elif change == "missing-count":
        del attempt["independent_server_contact_count"]

    WriteNucleiContractEvidence(observation, tmp_path, attempt=attempt)

    if change == "missing-role":
        observation["execution"]["evidence"] = [
            item for item in observation["execution"]["evidence"]
            if item["role"] != "attempt-provenance"
        ]

    with pytest.raises(ValueError, match="attempt provenance|independent server contacts"):
        ValidateObservation(pack, target, observation, tmp_path)


@pytest.mark.parametrize("raw", [
    b'not JSON\n', b'{}\n', b'{"type":"http","type":"other"}\n',
    b'{"type":"http","template-id":"rule","matched-at":"http://172.20.0.2:3000/metrics",'
    b'"matcher-status":false}\n',
])
def test_V2InvalidOutputCannotBecomeSuccessfulInvocation(available_contract_pack, tmp_path, raw):
    """Fresh byte hashes cannot turn malformed or nonmatching records into accepted output."""

    pack, target = available_contract_pack
    observation = ContractNucleiObservation(pack, target, tmp_path)
    WriteNucleiContractEvidence(observation, tmp_path, stdout=raw)

    with pytest.raises(ValueError):
        ValidateObservation(pack, target, observation, tmp_path)


def test_V2NormalizedMatchCannotReplaceMissingRawMatch(available_contract_pack, tmp_path):
    """A self-consistent normalized Finding still needs its original explicit matching record."""

    pack, target = available_contract_pack
    observation = ContractNucleiObservation(pack, target, tmp_path, matched=True)
    WriteNucleiContractEvidence(observation, tmp_path, stdout=b"")

    with pytest.raises(ValueError, match="explicit raw match identities"):
        ValidateObservation(pack, target, observation, tmp_path)


@pytest.mark.parametrize("track", ["whole1337", "external-nuclei"])
def test_V2CandidateTrackCannotAttestSuccessfulInvocation(tmp_path, track):
    """Versioning the observation cannot bypass source acceptance of the actual runner."""

    pack, target = LoadPack()
    for selected in pack["scanner_tracks"]:
        if selected["id"] == track:
            selected["implementation"] = "candidate"

    observation = ContractNucleiObservation(pack, target, tmp_path, track=track)

    with pytest.raises(ValueError, match="Planned detectors"):
        ValidateObservation(pack, target, observation, tmp_path)


@pytest.mark.parametrize("change", [
    "unknown-field", "missing-input", "wrong-version", "native-track", "v1-unproven",
])
def test_V2SchemaRefusesUnboundOrIncompatibleEnvelopes(
    available_contract_pack, tmp_path, change,
):
    """The new envelope stays explicit, pinned and additive to the unchanged native v1 schema."""

    pack, target = available_contract_pack
    observation = ContractNucleiObservation(pack, target, tmp_path, matched=True)

    if change == "unknown-field":
        observation["response_success"] = True

    elif change == "missing-input":
        del observation["execution"]["findings"][0]["target_url"]

    elif change == "wrong-version":
        observation["execution"]["scanner_version"] = "3.4.11"

    elif change == "native-track":
        observation["scanner_track"] = "native-engine"

    else:
        observation.update(schema_version=1, status="unproven")

    with pytest.raises(ValidationError):
        ValidateObservation(pack, target, observation, tmp_path)


def test_V2MixedReportPreservesV1NativeClassifications(available_contract_pack, tmp_path):
    """Adding invocation-only v2 observations does not reinterpret completed native responses."""

    pack, target = available_contract_pack
    native = ContractObservation(pack, target, tmp_path)
    external = ContractNucleiObservation(pack, target, tmp_path)
    report = BuildComparison(pack, target, [native, external], tmp_path)
    assert report["finite_completed_case_counts"]["native-engine"]["fn"] == 1, (
        "Existing v1 completed native positive-case absence must keep its original FN meaning."
    )
    assert report["finite_completed_case_counts"]["external-nuclei"]["fn"] == 0, (
        "A mixed report cannot transfer native response evidence to empty Nuclei output."
    )
    assert native["schema_version"] == 1 and report["pairwise_conditions"] == [], (
        "Original versions stay intact and unproven cases remain outside completed pairs."
    )


def test_V2EvidenceOversizeMetadataFailsBeforeFilesystemAccess():
    """The reader enforces 2 MiB even when called without observation schema validation."""

    evidence_root = MagicMock(spec=Path)
    execution = {"evidence": [{"path": "oversize.raw", "size_bytes": 2097153}]}

    with pytest.raises(ValueError, match="2 MiB per-file ceiling"):
        external_benchmark.VerifiedEvidence(execution, evidence_root)

    assert evidence_root.mock_calls == [], "Oversize metadata must fail before any filesystem read."


@pytest.mark.parametrize("extra_byte", [False, True])
def test_V2EvidenceExactCeilingNeverTruncatesAcquiredBytes(tmp_path, extra_byte):
    """Exactly 2 MiB is retained; an extra byte cannot pass through matching-prefix truncation."""

    raw = b"x" * 2097152
    path = tmp_path / "bounded.raw"
    path.write_bytes(raw + (b"x" if extra_byte else b""))
    execution = {"evidence": [{"role": "stdout", "path": "bounded.raw",
                               "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}]}

    if extra_byte:
        with pytest.raises(ValueError, match="acquisition record"):
            external_benchmark.VerifiedEvidence(execution, tmp_path)

    else:
        assert external_benchmark.VerifiedEvidence(execution, tmp_path)["stdout"] == raw, (
            "The exact transport ceiling must preserve the complete original bytes."
        )
