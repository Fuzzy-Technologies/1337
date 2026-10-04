# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Validate the narrow documentation build and protected-branch deployment boundary."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from pathlib import Path
from typing import Any

DEPLOY_CONDITION = (
    "github.event_name == 'push' && github.ref == 'refs/heads/master' && github.ref_protected"
)
READ_PERMISSIONS = {"contents": "read"}
DEPLOY_PERMISSIONS = {"contents": "read", "pages": "write", "id-token": "write"}


def ValidatePublicationWorkflow(workflow: Mapping[str, Any]) -> list[str]:
    """Reject workflows that expand PR authority or skip the validated Pages build.

    Args:
        workflow: Parsed GitHub Actions configuration; no expressions are evaluated.

    Returns:
        Deterministically ordered violations; an empty list means this policy passes.
        This check does not substitute for GitHub branch protection or human review.
    """

    violations: list[str] = []
    events = workflow.get("on", workflow.get(True, {}))

    if not isinstance(events, dict) or set(events) != {"pull_request", "push"}:
        violations.append("Only pull_request and protected-branch push triggers are allowed")

    if workflow.get("permissions") != READ_PERMISSIONS:
        violations.append("Workflow default permissions must be contents: read only")

    jobs = workflow.get("jobs", {})

    if not isinstance(jobs, dict) or set(jobs) != {"deterministic-documentation", "deploy-pages"}:
        violations.append(
            "Exactly one documentation build and one Pages deployment job are required"
        )

        return violations

    build = jobs["deterministic-documentation"]
    deploy = jobs["deploy-pages"]

    if build.get("permissions", READ_PERMISSIONS) != READ_PERMISSIONS:
        violations.append("PR documentation builds cannot obtain write permissions")

    if "environment" in build:
        violations.append("PR builds cannot enter the publication environment")

    condition = str(deploy.get("if", "")).strip().removeprefix("${{").removesuffix("}}").strip()

    if condition != DEPLOY_CONDITION:
        violations.append("Deployment requires a push to protected master")

    if deploy.get("permissions") != DEPLOY_PERMISSIONS:
        violations.append("Deployment permissions must be limited to Pages and OIDC")

    needs = deploy.get("needs")

    if needs not in ("deterministic-documentation", ["deterministic-documentation"]):
        violations.append("Deployment must depend on the complete documentation gate")

    environment = deploy.get("environment")

    if environment != "github-pages" and not (
        isinstance(environment, dict) and environment.get("name") == "github-pages"
    ):
        violations.append("Deployment requires the github-pages environment")

    for step in deploy.get("steps", []):
        if "run" in step or not str(step.get("uses", "")).startswith("actions/deploy-pages@"):
            violations.append("Deployment can only publish the validated official Pages artifact")

    if not deploy.get("steps"):
        violations.append("Deployment action is missing")

    for step in build.get("steps", []):
        if str(step.get("uses", "")).startswith("actions/deploy-pages@"):
            violations.append("PR documentation build cannot deploy Pages")

    return violations


def Main() -> int:
    """Validate the publication policy using pinned documentation YAML tooling.

    Returns:
        Zero for a conforming workflow, one for rejected publication policy.
    """

    import yaml

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workflow", type=Path)
    arguments = parser.parse_args()
    workflow = yaml.safe_load(arguments.workflow.read_text(encoding="utf-8"))

    if not isinstance(workflow, dict):
        raise ValueError("Documentation workflow must be a mapping")

    violations = ValidatePublicationWorkflow(workflow)

    for violation in violations:
        print(violation)

    return int(bool(violations))


if __name__ == "__main__":
    raise SystemExit(Main())
