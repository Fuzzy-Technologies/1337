# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Protect genuine content CI admission from missing, skipped and incomplete runtime evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from tests.contract import owned_content_response_ci_evidence as evidence


@pytest.mark.parametrize("mutation", [None, "skipped", "error", "hidden-skip", "foreign",
    "two-cases", "missing-result", "two-results", "unrun", "source-incomplete", "no-finding",
    "bool-count"])
def test_RequiredCiOutcomeRejectsSkippedOrIncompleteGenuineEvidence(tmp_path, mutation):
    """A successful process or JUnit alone cannot replace the exact original runtime result."""

    junit = tmp_path / "junit.xml"
    skipped, errors = ("1", "0") if mutation == "skipped" else ("0", "1" if mutation == (
        "error") else "0")
    name = "unrelated" if mutation == "foreign" else evidence.CASE_NAME
    children = "<skipped/>" if mutation == "hidden-skip" else ""
    case = f'<testcase classname="{evidence.CASE_CLASS}" name="{name}">{children}</testcase>'
    cases = case * (2 if mutation == "two-cases" else 1)
    junit.write_text(f'<testsuites><testsuite tests="1" failures="0" errors="{errors}" '
        f'skipped="{skipped}">{cases}</testsuite></testsuites>')
    retained = tmp_path / "retained"
    result = {"runtime_acceptance": "passed", "state": "checked-header-replay",
        "expected_findings": 1, "source_delivery": "normal-eof",
        "identities": {"finding_reference": "finding:mock-ci-evidence-only"}}

    if mutation in ("unrun", "source-incomplete", "bool-count"):
        key, value = {"unrun": ("runtime_acceptance", "unrun"),
            "source-incomplete": ("source_delivery", "refused-source-error"),
            "bool-count": ("expected_findings", True)}[mutation]
        result[key] = value

    if mutation == "no-finding":
        result["identities"]["finding_reference"] = None

    if mutation != "missing-result":
        for run in range(2 if mutation == "two-results" else 1):
            destination = retained / f"run-{run}" / "missing-positive/pipeline-result.json"
            destination.parent.mkdir(parents=True)
            destination.write_text(json.dumps(result))

    if mutation is None:
        assert evidence.RequireOutcome(junit, retained) == result, (
            "The exact passing mock evidence must remain admissible to the CI checker")

    else:
        with pytest.raises(ValueError):
            evidence.RequireOutcome(junit, retained)


def test_ContentCiOwnsOnlyTheRequiredSerialCaseAndOriginalEvidence():
    """The supported Linux lane fails on missing prerequisites and retains failure artifacts."""

    path = Path(__file__).resolve().parents[2] / (
        ".github/workflows/owned-content-header-acceptance.yml")
    workflow = yaml.safe_load(path.read_text())
    job = workflow["jobs"]["installed-content-header"]
    assert job["runs-on"] == "ubuntu-24.04" and job["timeout-minutes"] == 6, (
        "Required genuine acceptance needs its bounded supported Linux runner")
    assert job["env"] == {"FUZZY1337_RUN_OWNED_CONTENT_HEADER_ACCEPTANCE": "1"}, (
        "Missing platform prerequisites must fail required acceptance")
    checkout = job["steps"][0]
    assert checkout["with"] == {"ref": "${{ github.event.pull_request.head.sha }}",
        "persist-credentials": False}, "Actual evidence must bind the reviewed head"
    assert "github.event.pull_request.draft == false" in job["if"], (
        "Final ready revisions must retain genuine acceptance")
    assert "[owned-content-header-checkpoint]" in job["if"], (
        "Only the explicit genuine-case checkpoint may run while this PR is draft")
    executions = [step for step in job["steps"] if "pytest" in step.get("run", "")]
    assert len(executions) == 1 and "::" + evidence.CASE_NAME in executions[0]["run"], (
        "The feature checkpoint must run exactly the new genuine pipeline identity")
    assert all(option in executions[0]["run"] for option in (
        "-n0", "--no-cov", "--timeout=150", "--junitxml=functional-evidence/")), (
            "The shared-resource case requires serial bounded execution and retained JUnit")
    assert not any(step.get("continue-on-error", False) for step in job["steps"]), (
        "Actual runtime or evidence failures must fail the acceptance job")
    check = next(step for step in job["steps"] if (
        "tests.contract.owned_content_response_ci_evidence" in step.get("run", "")))
    assert "if" not in check, "Evidence admission must follow only a successful actual case"
    upload = job["steps"][-1]
    assert upload["if"] == "always()" and upload["with"]["if-no-files-found"] == "error", (
        "Failed and unexecuted attempts must preserve available original evidence")
    assert upload["with"]["path"].splitlines() == [
        "functional-evidence/owned-content-header.xml", "functional-evidence/owned-content-sdk/"], (
            "Upload only original evidence, excluding runtime and product workspace trees")
