# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Synthetic body-decoy CI tampering checks; no SDK, source or process is executed."""

from __future__ import annotations

import copy
import json

import pytest

from tests.contract import owned_content_response_ci_body_decoy_evidence as evidence
from tests.contract.owned_content_response_ci_evidence import CASE_NAME as MISSING_CASE_NAME
from tests.contract.owned_content_response_header_v2_oracle import PROFILE, SOURCE_PROFILE
from tests.unit.test_owned_content_response_header_v2_oracle import Fixture as HeaderFixture


def Fixture(tmp_path, source_case="body-decoy"):
    """Create explicitly synthetic body-decoy originals and attributed persisted/replay records."""

    before, after, summary, saves, options = HeaderFixture(source_case)
    identities = {key: summary[key] for key in ("original_receipt_id", "analysis_reference",
        "assessment_reference", "finding_reference", "condition_observed")}
    calls = {key: 0 for key in ("socket.audit", "socket.socket", "subprocess.Popen",
        "LocalExecutor.Execute", "GovernedLocalExecutor.Execute", "PolicyEngine.Authorize",
        "LocalEvidenceStore.Put", "LocalEvidenceStore.PublishStoredBytes",
        "OwnedResponseStage.__init__", "LocalModelStore.Save", "LocalWorkspaceStore.Save",
        "LocalScopeStore.Open")}
    guard = {"calls": calls, "audit_probe_seen": True, "saves": saves}
    documents = {"pipeline-result.json": {"state": "checked-header-replay", "expected_findings": 1,
        "runtime_acceptance": "passed", "source_delivery": "normal-eof", "identities": identities},
        "pipeline-plan.json": {"selection": {"case": "body-decoy", "scenario": "positive",
            "url": options["url"]}, "analysis_reference": options["analysis"],
            "owner_reference": options["authority"]["owner_reference"],
            "expected_state": "completed", "expected_findings": 1},
        "process-003-sdk-fresh-setup/stdout.bin": {"summary": {
            "scope": options["authority"]["scope"], "policies": {"analysis": {
                "document": options["authority"]["policy"]}}}},
        "sdk-analyze-offline-consumer.json": {"exception_type": None, "summary": summary},
        "sdk-analyze-offline-guard.json": {"authority_scenario": "positive", "guard": guard},
        "physical-relocation.json": {"original_root_absent": True, "relocated_root_present": True},
        "sdk-replay-offline-consumer.json": {"exception_type": None, "summary": {
            **copy.deepcopy(identities), "state": "verified", "profile": PROFILE,
            "source_profile": SOURCE_PROFILE}},
        "sdk-replay-offline-guard.json": {"authority_scenario": None, "guard": {
            "calls": copy.deepcopy(calls), "audit_probe_seen": True, "saves": []}}}

    for index, state in ((5, before), (7, after), (8, after), (10, after)):
        documents[f"process-{index:03d}-sdk-inspect/stdout.bin"] = {
            "summary": {"original_inspection": copy.deepcopy(state)}}

    junit = tmp_path / "body-decoy.xml"
    junit.write_text('<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
        f'<testcase classname="{evidence.CASE_CLASS}" name="{evidence.CASE_NAME}"/>'
        '</testsuite></testsuites>')
    retained = tmp_path / "retained"

    return junit, retained, retained / "run-mock-only/body-decoy-positive", documents


@pytest.mark.parametrize("mutation", [None, "wrong-case", "wrong-owner", "two-results", "skipped",
    "hidden-skip", "wrong-scenario", "missing-case", "bool-plan-count", "bool-count",
    "no-finding", "false-condition", "integer-true", "substituted-body", "substituted-header",
    "substituted-missing-source", "substituted-fixed-source",
    "no-assessment", "guard-call", "lost-ack", "changed-relocation", "missing-relocation",
    "changed-replay", "replay-save", "incomplete-source"])
def test_BodyDecoyRequiresOriginalHttpPartsAndAnAcknowledgedFinding(tmp_path, mutation):
    """A mock JUnit/result cannot hide header-like body text or missing original state evidence."""

    source_case = {"substituted-missing-source": "missing",
        "substituted-fixed-source": "fixed"}.get(mutation, "body-decoy")
    junit, retained, case, documents = Fixture(tmp_path, source_case=source_case)
    result = documents["pipeline-result.json"]

    if mutation == "wrong-case":
        junit.write_text(junit.read_text().replace(evidence.CASE_NAME, MISSING_CASE_NAME))

    elif mutation == "wrong-owner":
        case = retained / "run-mock-only/missing-positive"

    elif mutation in ("skipped", "hidden-skip"):
        raw = junit.read_text().replace('skipped="0"', 'skipped="1"') if mutation == (
            "skipped") else junit.read_text().replace('/>', '><skipped/></testcase>')
        junit.write_text(raw)

    elif mutation in ("wrong-scenario", "missing-case"):
        key, value = ("scenario", "policy-denied") if mutation == "wrong-scenario" else (
            "case", "missing")
        documents["pipeline-plan.json"]["selection"][key] = value

    elif mutation == "bool-plan-count":
        documents["pipeline-plan.json"]["expected_findings"] = True

    elif mutation == "bool-count":
        result["expected_findings"] = True

    elif mutation == "no-finding":
        result["identities"]["finding_reference"] = None

    elif mutation in ("false-condition", "integer-true"):
        result["identities"]["condition_observed"] = False if mutation == "false-condition" else 1

    elif mutation in ("substituted-body", "substituted-header"):
        state = documents["process-005-sdk-inspect/stdout.bin"]["summary"]["original_inspection"]
        source = state["model"]["observations"][0]["attributes"]
        role = "owned-response-body" if mutation == "substituted-body" else "owned-response-headers"
        identity = source["original_role_ids"][role]
        state["originals"][identity]["data_hex"] = (b"unrelated" if mutation == (
            "substituted-body") else b"X-Content-Type-Options: nosniff\r\n\r\n").hex()

    elif mutation == "no-assessment":
        documents["sdk-analyze-offline-consumer.json"]["summary"]["assessment_reference"] = None

    elif mutation == "guard-call":
        documents["sdk-analyze-offline-guard.json"]["guard"]["calls"]["LocalEvidenceStore.Put"] = 1

    elif mutation == "lost-ack":
        documents["sdk-analyze-offline-guard.json"]["guard"]["saves"][0]["returned"] = None

    elif mutation == "changed-relocation":
        documents["process-008-sdk-inspect/stdout.bin"]["summary"]["original_inspection"][
            "model"]["revision"] += 1

    elif mutation == "missing-relocation":
        documents["physical-relocation.json"]["original_root_absent"] = False

    elif mutation == "changed-replay":
        documents["sdk-replay-offline-consumer.json"]["summary"]["finding_reference"] = "foreign"

    elif mutation == "replay-save":
        documents["sdk-replay-offline-guard.json"]["guard"]["saves"] = [{"owner": "model"}]

    elif mutation == "incomplete-source":
        result["source_delivery"] = "refused-source-error"

    for name, value in documents.items():
        path = case / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    if mutation == "two-results":
        path = retained / "run-second/body-decoy-positive/pipeline-result.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(result))

    if mutation is None:
        assert evidence.RequireOutcome(junit, retained) == result, (
            "The exact synthetic body-decoy Finding and original replay must remain admissible")
        assert evidence.Main([str(junit), str(retained)]) == 0, (
            "The dedicated body-decoy entrypoint must enforce the same original-evidence gate")

    else:
        with pytest.raises((AssertionError, ValueError)):
            evidence.RequireOutcome(junit, retained)


@pytest.mark.parametrize("arguments", [[], ["one"], ["one", "two", "fixed"]])
def test_BodyDecoyEntrypointAcceptsOnlyItsTwoOriginalEvidencePaths(arguments):
    """The separate checker never selects an old positive, fixed or authority-refusal identity."""

    with pytest.raises(ValueError):
        evidence.Main(arguments)
