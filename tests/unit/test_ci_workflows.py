# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Protect draft feedback, final integration triggers and required full-job execution."""

from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOWS = {
    "python-quality.yml": {"quality", "container-quality", "synthetic-lab", "external-targets"},
    "documentation.yml": {"deterministic-documentation"},
    "nuclei-acceptance.yml": {"owned-loopback"},
    "trivy-acceptance.yml": {"owned-offline"},
}
INTEGRATION_CONDITION = (
    "github.event_name == 'push' || (github.event_name == 'pull_request' "
    "&& github.event.pull_request.draft == false)"
)


def Workflow(name: str) -> dict[str, Any]:
    """Read the actual workflow configuration without evaluating GitHub expressions."""

    path = Path(__file__).resolve().parents[2] / ".github" / "workflows" / name

    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", WORKFLOWS)
def test_FinalReadinessAndDraftTransitionsTriggerTheSameConcurrencyOwner(name: str) -> None:
    """Readiness starts final checks and returning to draft cancels their existing run."""

    workflow = Workflow(name)
    events = workflow.get("on", workflow.get(True))
    assert set(events) == {"pull_request", "push"}, "Integration acquired an unexpected trigger."
    assert events["pull_request"] == {
        "branches": ["develop", "master"],
        "types": ["opened", "reopened", "synchronize", "ready_for_review", "converted_to_draft"],
    }, "Final readiness, later heads and draft cancellation must remain explicit PR events."
    assert events["push"] == {"branches": ["master"]}, (
        "Integration into develop must not repeat the full gate after merge."
    )
    concurrency = workflow["concurrency"]
    assert concurrency["cancel-in-progress"] is True, "Stale integration runs must be cancelled."
    assert concurrency["group"].endswith("-${{ github.ref }}"), (
        "All lifecycle events for the same PR must share the cancellation owner."
    )


@pytest.mark.parametrize("name", WORKFLOWS)
def test_EveryHeavyJobWaitsForFinalReadinessWithoutWeakeningTheGate(name: str) -> None:
    """Draft work skips heavy jobs while ready PRs and stable pushes retain required checks."""

    workflow = Workflow(name)
    jobs = workflow["jobs"]
    expected = WORKFLOWS[name] | ({"deploy-pages"} if name == "documentation.yml" else set())
    assert set(jobs) == expected, "The integration job inventory changed unexpectedly."
    assert workflow["permissions"] == {"contents": "read"}, "PR authority expanded."

    for job_id in WORKFLOWS[name]:
        job = jobs[job_id]
        condition = " ".join(str(job.get("if", "")).split())
        assert condition == INTEGRATION_CONDITION, (
            f"{name}/{job_id} must wait for a ready PR or the existing stable push."
        )
        assert job.get("continue-on-error", False) is False, "Full gate failures became advisory."
        assert job["steps"], "Required integration work was replaced with an empty job."


def test_DocumentationTestsUseParallelWorkersAndKeepBranchCoverage() -> None:
    """Independent documentation modules must share bounded xdist execution and real coverage."""

    steps = Workflow("documentation.yml")["jobs"]["deterministic-documentation"]["steps"]
    command = next(step["run"] for step in steps
                   if step.get("name") == (
                       "Exercise documentation boundaries and enforce per-tool branch coverage"))
    assert "-n auto --dist=loadscope" in command, "Documentation tests lost process parallelism."
    assert "--cov=tools --cov-branch" in command, "Parallel documentation lost branch measurement."
    assert "fuzzy1337.coverage_gate" in command, "Parallel documentation lost its per-tool gate."
