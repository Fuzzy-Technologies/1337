# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Causal policy-refusal CI controls; all documents are synthetic and no runtime is executed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from tests.contract import owned_content_response_ci_denial_evidence as evidence
from tests.unit.test_owned_content_response_sdk_pipeline import Guard


def Fixture(tmp_path):
    """Write explicitly mocked original document shapes for only this closed refusal checker."""

    junit = tmp_path / "denied.xml"
    junit.write_text('<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
        f'<testcase classname="{evidence.CASE_CLASS}" name="{evidence.CASE_NAME}"/>'
        '</testsuite></testsuites>')
    retained = tmp_path / "retained"
    case = retained / "run-mock-only/policy-denied"
    documents = {
        "pipeline-result.json": {"state": "checked-authority-refusal", "expected_findings": 0,
            "runtime_acceptance": "passed", "source_delivery": "normal-eof"},
        "pipeline-plan.json": {"selection": {"case": "missing", "scenario": "policy-denied"}},
        "stage-04-input.json": {"selection": {"authority_scenario": "policy-denied",
            "approve_passive_header_check": True, "policy": "/mock-only/denied-policy.json"}},
        "process-003-sdk-fresh-setup/stdout.bin": {"summary": {"policies": {"analysis-denied": {
            "path": "/mock-only/denied-policy.json", "document": {"permissions": []}}},
            "scope": {"authorization": {"state": "granted"}}}},
        "sdk-analyze-offline-consumer.json": {"exception_type": None, "summary": {
            "state": "denied", "failure": "authorization", "condition_observed": None,
            "assessment_reference": None, "finding_reference": None}},
        "sdk-analyze-offline-guard.json": {"authority_scenario": "policy-denied", "guard": Guard()},
        "process-005-sdk-inspect/stdout.bin": {"summary": {"original_inspection": {
            "model": {"revision": 3}, "workspace": {"revision": 2}, "originals": {"mock": True}}}},
        "process-007-sdk-inspect/stdout.bin": {"summary": {"original_inspection": {
            "model": {"revision": 3}, "workspace": {"revision": 2}, "originals": {"mock": True}}}},
    }

    return junit, retained, case, documents


@pytest.mark.parametrize("mutation", [None, "wrong-case", "clean-negative", "assessment",
    "finding", "approval-denied", "different-policy", "granted-policy", "save", "changed-state",
    "guard-call", "late-stage", "bool-count"])
def test_RequiredPolicyRefusalCannotHideInterpretationWritesOrAnotherDenial(tmp_path, mutation):
    """Only this independently selected policy boundary may satisfy the unassessed refusal gate."""

    junit, retained, case, documents = Fixture(tmp_path)
    consumer = documents["sdk-analyze-offline-consumer.json"]["summary"]

    if mutation == "wrong-case":
        junit.write_text(junit.read_text().replace(evidence.CASE_NAME, "unrelated_case"))

    elif mutation == "clean-negative":
        consumer.update(state="completed", failure=None, condition_observed=False)

    elif mutation in ("assessment", "finding"):
        consumer[mutation + "_reference"] = mutation + ":unexpected"

    elif mutation == "approval-denied":
        documents["stage-04-input.json"]["selection"]["approve_passive_header_check"] = False

    elif mutation == "different-policy":
        documents["stage-04-input.json"]["selection"]["policy"] = "/mock-only/another-policy.json"

    elif mutation == "granted-policy":
        documents["process-003-sdk-fresh-setup/stdout.bin"]["summary"]["policies"][
            "analysis-denied"]["document"]["permissions"] = [{"mock_granted": True}]

    elif mutation == "save":
        documents["sdk-analyze-offline-guard.json"]["guard"]["saves"] = [{"owner": "model"}]

    elif mutation == "changed-state":
        documents["process-007-sdk-inspect/stdout.bin"]["summary"]["original_inspection"][
            "model"]["revision"] = 4

    elif mutation == "guard-call":
        documents["sdk-analyze-offline-guard.json"]["guard"]["calls"]["LocalEvidenceStore.Put"] = 1

    elif mutation == "late-stage":
        documents["physical-relocation.json"] = {"original_root_absent": True}

    elif mutation == "bool-count":
        documents["pipeline-result.json"]["expected_findings"] = False

    for name, value in documents.items():
        path = case / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    if mutation is None:
        assert evidence.RequireOutcome(junit, retained) == documents["pipeline-result.json"], (
            "The exact mocked no-write policy refusal must remain admissible")
        assert evidence.Main([str(junit), str(retained)]) == 0, (
            "The dedicated workflow entrypoint must enforce this same refusal gate")

    else:
        with pytest.raises((AssertionError, ValueError)):
            evidence.RequireOutcome(junit, retained)


def test_PolicyCheckpointCannotActivateTheAcceptedPositiveOrFixedJobs():
    """Only the new bounded refusal identity owns this draft marker and evidence artifact."""

    path = Path(__file__).resolve().parents[2] / (
        ".github/workflows/owned-content-header-acceptance.yml")
    jobs = yaml.safe_load(path.read_text())["jobs"]
    denied = jobs["policy-denied-content-header"]
    marker = "[owned-content-header-policy-denied-checkpoint]"
    assert marker in denied["if"] and all(marker not in jobs[name]["if"] for name in (
        "installed-content-header", "fixed-content-header")), (
            "Selecting policy refusal must not repeat either accepted runtime cohort")
    assert denied["runs-on"] == "ubuntu-24.04" and denied["env"] == {
        "FUZZY1337_RUN_OWNED_CONTENT_HEADER_ACCEPTANCE": "1"}, (
            "Required genuine refusal needs supported Linux and fail-on-missing prerequisites")
    executions = [step for step in denied["steps"] if "pytest" in step.get("run", "")]
    assert len(executions) == 1 and "::" + evidence.CASE_NAME in executions[0]["run"] and all(
        option in executions[0]["run"] for option in ("-n0", "--no-cov", "--timeout=150")), (
            "The denial checkpoint runs exactly one bounded serial genuine case")
    upload = denied["steps"][-1]
    assert upload["if"] == "always()" and upload["with"]["if-no-files-found"] == "error", (
        "Original refusal evidence must be retained even when acceptance fails")
