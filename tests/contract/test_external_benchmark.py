# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Synthetic contract fixtures verify comparison semantics, never scanner effectiveness."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

import pytest
import yaml
from jsonschema import ValidationError

from fuzzy1337.adapters import AdapterRequest, ImpactLevel
from fuzzy1337.adapters.nuclei import NucleiAdapter, NucleiProfile, NucleiTemplate
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


def WriteContractEvidence(execution, root):
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
    execution["evidence"] = []

    for role, raw in content.items():
        relative = Path(execution["target_instance"]) / (role + ".json")
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        execution["evidence"].append({"role": role, "path": relative.as_posix(),
                                      "sha256": hashlib.sha256(raw).hexdigest(),
                                      "size_bytes": len(raw)})


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


@pytest.mark.parametrize("path", ["../escaped.json", "/tmp/escaped.json"])
def test_EvidenceCannotEscapeItsOwnedDirectory(available_contract_pack, tmp_path, path):
    """Relative traversal and absolute paths fail before artifact bytes are opened."""

    pack, target = available_contract_pack
    observation = ContractObservation(pack, target, tmp_path)
    observation["execution"]["evidence"][0]["path"] = path

    with pytest.raises(ValueError, match="beneath"):
        ValidateObservation(pack, target, observation, tmp_path)


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
