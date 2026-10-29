# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Causal explicit-approval refusal controls using synthetic documents without product execution."""

from __future__ import annotations

import copy
import json
import shlex
from pathlib import Path

import pytest
import yaml

from tests.contract import owned_content_response_ci_approval_evidence as evidence
from tests.contract.owned_content_response_ci_actor_evidence import CASE_NAME as ACTOR_CASE_NAME
from tests.unit.test_owned_content_response_ci_actor import Fixture as ActorFixture


def Fixture(tmp_path):
    """Select explicit False approval while preserving the independently granted mock authority."""

    junit, retained, _actor_case, documents = ActorFixture(tmp_path)
    junit.write_text(junit.read_text().replace(ACTOR_CASE_NAME, evidence.CASE_NAME))
    case = retained / "run-mock-only/approval-denied"
    documents["pipeline-plan.json"]["selection"]["scenario"] = "approval-denied"
    selected = documents["stage-04-input.json"]["selection"]
    selected.update(authority_scenario="approval-denied", approve_passive_header_check=False)

    for name in ("sdk-analyze-offline-guard.json", "process-006-sdk-analyze-offline/stdout.bin"):
        documents[name]["authority_scenario"] = "approval-denied"

    return junit, retained, case, documents


@pytest.mark.parametrize("mutation", [None, "wrong-case", "skipped", "extra-case",
    "missing-approval", "null-approval", "integer-approval", "true-approval", "denied-policy",
    "different-policy", "denied-scope", "other-scenario", "owner-basis", "helper-hash",
    "child-helper", "one-read", "bool-child-read", "child-summary", "child-guard",
    "clean-negative", "condition-false", "assessment", "finding", "exception", "save",
    "changed-state", "guard-call", "late-stage", "replay", "duplicate-result", "bool-count"])
def test_ExplicitApprovalRefusalRequiresGrantedAuthorityAndUnchangedAcquiredState(
    tmp_path, mutation,
):
    """A missing opt-in, another denied gate or an interpretation cannot satisfy this identity."""

    junit, retained, case, documents = Fixture(tmp_path)
    selected = documents["stage-04-input.json"]["selection"]
    setup = documents["process-003-sdk-fresh-setup/stdout.bin"]["summary"]
    guard = documents["sdk-analyze-offline-guard.json"]
    child = documents["process-006-sdk-analyze-offline/stdout.bin"]
    consumer = documents["sdk-analyze-offline-consumer.json"]

    if mutation == "wrong-case":
        junit.write_text(junit.read_text().replace(evidence.CASE_NAME, ACTOR_CASE_NAME))

    elif mutation == "skipped":
        junit.write_text(junit.read_text().replace('skipped="0"', 'skipped="1"'))

    elif mutation == "extra-case":
        junit.write_text(junit.read_text().replace('</testsuite>', '<testcase/></testsuite>'))

    elif mutation == "missing-approval":
        del selected["approve_passive_header_check"]

    elif mutation in ("null-approval", "integer-approval", "true-approval"):
        selected["approve_passive_header_check"] = {
            "null-approval": None, "integer-approval": 0, "true-approval": True}[mutation]

    elif mutation == "denied-policy":
        setup["policies"]["analysis"]["document"]["permissions"] = []

    elif mutation == "different-policy":
        selected["policy"] = "/mock-only/another-policy.json"

    elif mutation == "denied-scope":
        setup["scope"]["authorization"]["state"] = "denied"

    elif mutation == "other-scenario":
        documents["pipeline-plan.json"]["selection"]["scenario"] = "owner-drift"

        for record in (selected, guard, child):
            record["authority_scenario"] = "owner-drift"

    elif mutation == "owner-basis":
        selected["owner_reference"] = "actor:foreign-selection"

    elif mutation == "helper-hash":
        documents["pipeline-helper-sources.json"][evidence.ACTOR_HELPER]["sha256"] = "0" * 64
        child["consumer_sources"][evidence.ACTOR_HELPER]["sha256"] = "0" * 64

    elif mutation == "child-helper":
        child["consumer_sources"][evidence.ACTOR_HELPER]["path"] = "/mock-only/other-helper.py"

    elif mutation == "one-read":
        guard["owner_reads"] = child["owner_reads"] = 1

    elif mutation == "bool-child-read":
        child["owner_reads"] = True

    elif mutation == "child-summary":
        child["summary"]["failure"] = "unrelated"

    elif mutation == "child-guard":
        child["guard"]["audit_probe_seen"] = False

    elif mutation in ("clean-negative", "condition-false", "assessment", "finding", "exception"):
        summary = consumer["summary"]

        if mutation == "clean-negative":
            summary.update(state="completed", failure=None, condition_observed=False)

        elif mutation == "condition-false":
            summary["condition_observed"] = False

        elif mutation == "exception":
            consumer["exception_type"] = "UnexpectedError"

        else:
            summary[mutation + "_reference"] = mutation + ":unexpected"

        child["summary"] = copy.deepcopy(summary)

    elif mutation == "save":
        guard["guard"]["saves"] = child["guard"]["saves"] = [{"owner": "model"}]

    elif mutation == "changed-state":
        documents["process-007-sdk-inspect/stdout.bin"]["summary"]["original_inspection"][
            "model"]["revision"] = 4

    elif mutation == "guard-call":
        guard["guard"]["calls"]["LocalEvidenceStore.Put"] = 1
        child["guard"] = copy.deepcopy(guard["guard"])

    elif mutation == "late-stage":
        documents["physical-relocation.json"] = {"original_root_absent": True}

    elif mutation == "replay":
        documents["process-008-sdk-replay-offline/process.json"] = {"returncode": 0}

    elif mutation == "duplicate-result":
        path = retained / "run-mock-duplicate/approval-denied/pipeline-result.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(documents["pipeline-result.json"]))

    elif mutation == "bool-count":
        documents["pipeline-result.json"]["expected_findings"] = False

    for name, value in documents.items():
        path = case / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    if mutation is None:
        assert evidence.RequireOutcome(junit, retained) == documents["pipeline-result.json"], (
            "Only the exact synthetic approval refusal may satisfy this evidence gate")
        assert evidence.Main([str(junit), str(retained)]) == 0, (
            "The dedicated entrypoint must enforce the same original-evidence contract")

    else:
        with pytest.raises((AssertionError, ValueError)):
            evidence.RequireOutcome(junit, retained)


def test_ApprovalRefusalEntrypointRejectsMissingOriginalPaths():
    """Original JUnit and evidence roots must both be explicitly supplied before reading files."""

    with pytest.raises(ValueError, match="Expected original approval-refusal"):
        evidence.Main([])


def AssertApprovalCheckpoint(jobs):
    """Require an isolated draft marker, one bounded case and original failure evidence."""

    job = jobs["approval-denied-content-header"]
    marker = "[owned-content-header-approval-denied-checkpoint]"
    assert job["if"] == ("github.event_name == 'pull_request' && "
        "(github.event.pull_request.draft == false || "
        f"contains(github.event.pull_request.body, '{marker}'))"), (
            "Only final ready or the unique approval checkpoint may activate this job")
    assert all(marker not in prior["if"] for name, prior in jobs.items() if name != (
        "approval-denied-content-header")), "The new draft marker must not repeat accepted cohorts"
    assert job["runs-on"] == "ubuntu-24.04" and job["timeout-minutes"] == 6 and job["env"] == {
        "FUZZY1337_RUN_OWNED_CONTENT_HEADER_ACCEPTANCE": "1"}, (
            "Required approval acceptance needs the bounded supported ownership environment")
    steps = job["steps"]
    assert len(steps) == 7 and not job.get("continue-on-error", False), (
        "Only setup, one case, strict admission and original upload may execute without bypasses")
    assert steps[:4] == jobs["body-decoy-content-header"]["steps"][:4], (
        "Only the established pinned clean-head checkout and locked installation may be used")
    executions = [step for step in steps if "pytest" in step.get("run", "")]
    junit = "functional-evidence/owned-content-header-approval-denied.xml"
    assert len(executions) == 1 and executions[0]["timeout-minutes"] == 3 and shlex.split(
        executions[0]["run"]) == ["uv", "run", "--locked", "--extra", "dev", "pytest",
            "tests/functional/test_owned_content_response_sdk_pipeline.py::" + evidence.CASE_NAME,
            "-q", "-x", "-n0", "--no-cov", "--timeout=150", "--timeout-method=thread",
            "--junitxml=" + junit], "Execute only the new serial bounded approval-refusal identity"
    checkers = [step for step in steps if (
        "tests.contract.owned_content_response_ci_approval_evidence" in step.get("run", ""))]
    assert len(checkers) == 1 and "if" not in checkers[0] and shlex.split(checkers[0]["run"]) == [
        "uv", "run", "--locked", "--extra", "dev", "python", "-m",
        "tests.contract.owned_content_response_ci_approval_evidence", junit,
        "functional-evidence/owned-content-sdk"], "Require strict admission of original evidence"
    assert steps.index(checkers[0]) == steps.index(executions[0]) + 1 and not any(
        step.get("continue-on-error", False) or "if" in step for step in steps[:-1]), (
            "Every actual execution and admission failure must fail the required job")
    upload = steps[-1]
    assert upload["if"] == "always()" and upload["with"]["if-no-files-found"] == "error" and (
        upload["with"]["name"] == "owned-content-header-approval-denied-original-evidence" and
        upload["with"]["path"].splitlines() == [junit, "functional-evidence/owned-content-sdk/"] and
        upload["with"]["retention-days"] == 14 and upload["uses"] == jobs[
            "body-decoy-content-header"]["steps"][-1]["uses"]
    ), "Always retain distinct original approval-refusal evidence, including on failure"
    assert all(upload["with"]["name"] != prior["steps"][-1]["with"]["name"]
        for name, prior in jobs.items() if name != "approval-denied-content-header"), (
            "New original evidence must not overwrite any accepted cohort artifact")


@pytest.mark.parametrize("mutation", [None, "old-marker", "accepted-cohort-marker", "draft-only",
    "platform", "missing-prerequisite", "credentials", "wrong-case", "parallel", "wrong-junit",
    "skipped-execution", "skipped-checker", "continue-on-error", "overwrite-artifact",
    "missing-failure-evidence", "job-continue-on-error", "extra-command", "upload-action"])
def test_ApprovalCheckpointRequiresItsOwnSerialCaseAndOriginalEvidence(mutation):
    """Workflow tampering cannot repeat accepted cohorts or bypass original-evidence admission."""

    path = Path(__file__).resolve().parents[2] / (
        ".github/workflows/owned-content-header-acceptance.yml")
    jobs = yaml.safe_load(path.read_text())["jobs"]
    job = jobs["approval-denied-content-header"]
    executions = [step for step in job["steps"] if "pytest" in step.get("run", "")]

    if mutation == "old-marker":
        job["if"] += " || contains(body, '[owned-content-header-checkpoint]')"

    elif mutation == "accepted-cohort-marker":
        jobs["installed-content-header"]["if"] = job["if"]

    elif mutation == "draft-only":
        job["if"] = job["if"].replace("draft == false ||", "draft == true &&")

    elif mutation == "platform":
        job["runs-on"] = "windows-latest"

    elif mutation == "missing-prerequisite":
        job["env"] = {}

    elif mutation == "credentials":
        job["steps"][0]["with"]["persist-credentials"] = True

    elif mutation == "wrong-case":
        executions[0]["run"] = executions[0]["run"].replace(evidence.CASE_NAME, ACTOR_CASE_NAME)

    elif mutation == "parallel":
        executions[0]["run"] = executions[0]["run"].replace("-n0", "-n2")

    elif mutation == "wrong-junit":
        executions[0]["run"] += " --junitxml=another.xml"

    elif mutation == "skipped-execution":
        executions[0]["if"] = "false"

    elif mutation == "skipped-checker":
        job["steps"][-2]["if"] = "false"

    elif mutation == "continue-on-error":
        executions[0]["continue-on-error"] = True

    elif mutation == "overwrite-artifact":
        job["steps"][-1]["with"]["name"] = jobs["installed-content-header"][
            "steps"][-1]["with"]["name"]

    elif mutation == "missing-failure-evidence":
        job["steps"][-1]["if"] = "success()"

    elif mutation == "job-continue-on-error":
        job["continue-on-error"] = True

    elif mutation == "extra-command":
        job["steps"].insert(-1, {"run": "echo unapproved extra command"})

    elif mutation == "upload-action":
        job["steps"][-1]["uses"] = "unapproved/upload@unreviewed"

    if mutation is None:
        AssertApprovalCheckpoint(jobs)

    else:
        with pytest.raises(AssertionError):
            AssertApprovalCheckpoint(jobs)
