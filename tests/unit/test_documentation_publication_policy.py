# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Prove unsafe PR or unprotected-branch publication configurations are rejected."""

import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from tools.documentation_publication_policy import (
    DEPLOY_CONDITION,
    Main,
    ValidatePublicationWorkflow,
)


def SafeWorkflow() -> dict[str, Any]:
    """Construct the minimal publication policy fixture, independent of the real workflow."""

    return {
        "on": {"pull_request": {}, "push": {"branches": ["master", "develop"]}},
        "permissions": {"contents": "read"},
        "jobs": {
            "deterministic-documentation": {"steps": []},
            "deploy-pages": {
                "if": DEPLOY_CONDITION,
                "needs": "deterministic-documentation",
                "permissions": {"contents": "read", "pages": "write", "id-token": "write"},
                "environment": "github-pages",
                "steps": [{"uses": "actions/deploy-pages@v4"}],
            },
        },
    }


def test_ConformingPublicationBoundaryIsAccepted() -> None:
    """Accept deployment only after the gate on a protected master push."""

    assert not ValidatePublicationWorkflow(SafeWorkflow()), "Conforming publication was rejected"


@pytest.mark.parametrize("condition", (
    "github.ref == 'refs/heads/master'",
    "github.event_name == 'push' && github.ref == 'refs/heads/master'",
    "always()",
    "github.event_name == 'pull_request'",
    DEPLOY_CONDITION + " || github.event_name == 'pull_request'",
))
def test_UnsafeDeploymentConditionIsRejected(condition: str) -> None:
    """Reject missing protection, PR publication, or failure-bypassing conditions."""

    workflow = SafeWorkflow()
    workflow["jobs"]["deploy-pages"]["if"] = condition
    assert ValidatePublicationWorkflow(workflow), "Unsafe deployment condition was accepted"


@pytest.mark.parametrize("mutation", (
    "write-defaults", "write-build", "privileged-trigger", "deploy-in-build",
    "skip-gate", "write-deploy-contents", "shell-deploy", "no-environment",
))
def test_AuthorityExpansionIsRejected(mutation: str) -> None:
    """Reject workflow configurations that grant PR authority or bypass artifact provenance."""

    workflow = deepcopy(SafeWorkflow())
    build = workflow["jobs"]["deterministic-documentation"]
    deploy = workflow["jobs"]["deploy-pages"]

    if mutation == "write-defaults":
        workflow["permissions"] = "write-all"

    elif mutation == "write-build":
        build["permissions"] = {"contents": "write"}

    elif mutation == "privileged-trigger":
        workflow["on"] = {"pull_request_target": {}}

    elif mutation == "deploy-in-build":
        build["steps"].append({"uses": "actions/deploy-pages@v4"})

    elif mutation == "skip-gate":
        deploy.pop("needs")

    elif mutation == "write-deploy-contents":
        deploy["permissions"]["contents"] = "write"

    elif mutation == "shell-deploy":
        deploy["steps"].append({"run": "publish"})

    elif mutation == "no-environment":
        deploy.pop("environment")

    assert ValidatePublicationWorkflow(workflow), f"Unsafe authority expansion accepted: {mutation}"


@pytest.mark.parametrize("boundary", ("extra-job", "no-jobs", "build-environment", "no-deploy"))
def test_IncompleteOrExpandedJobBoundariesAreRejected(boundary: str) -> None:
    """Reject extra publication paths and incomplete deployment configurations."""

    workflow = SafeWorkflow()

    if boundary == "extra-job":
        workflow["jobs"]["unreviewed-job"] = {}

    elif boundary == "no-jobs":
        workflow.pop("jobs")

    elif boundary == "build-environment":
        workflow["jobs"]["deterministic-documentation"]["environment"] = "github-pages"

    else:
        workflow["jobs"]["deploy-pages"]["steps"] = []

    assert ValidatePublicationWorkflow(workflow), (
        "Incomplete or expanded publication boundary passed"
    )


@pytest.mark.parametrize("valid", (True, False))
def test_PolicyCliReportsRealWorkflowBoundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid: bool,
) -> None:
    """Check real YAML parsing and CLI status, without evaluating workflow expressions."""

    pytest.importorskip("yaml", reason="Pinned YAML tooling is installed by the documentation gate")
    workflow = SafeWorkflow()

    if not valid:
        workflow["permissions"] = "write-all"

    path = tmp_path / "workflow.yml"
    path.write_text(json.dumps(workflow), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["policy", str(path)])
    assert Main() == int(not valid), "Publication CLI hid a rejected authority boundary"


def test_NonmappingWorkflowCannotPassCli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse a malformed workflow before interpreting deployment authority."""

    pytest.importorskip("yaml", reason="YAML tooling is installed by the documentation gate")
    path = tmp_path / "workflow.yml"
    path.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["policy", str(path)])

    with pytest.raises(ValueError, match="mapping"):
        Main()
