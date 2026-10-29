# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Prove unsafe PR or unprotected-branch publication configurations are rejected."""

import json
import os
import shutil
import subprocess
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


def WorkflowSteps() -> list[dict]:
    """Read the actual publication workflow without substituting a synthetic selection policy."""

    import yaml

    path = Path(__file__).resolve().parents[2] / ".github/workflows/documentation.yml"
    return yaml.safe_load(path.read_text(
        encoding="utf-8"))["jobs"]["deterministic-documentation"]["steps"]


def WorkflowRecorder(root: Path) -> dict[str, str]:
    """Provide bounded Git/GitHub observations and record the actual shell's verifier arguments."""

    binary = root / "bin"
    binary.mkdir()
    python = root / ".venv/bin/python"
    python.parent.mkdir(parents=True)
    source = '''#!/usr/bin/env python3
"""Record controlled workflow subprocesses without contacting a remote service."""
import json,os,sys
from pathlib import Path
name=Path(sys.argv[0]).name
args=sys.argv[1:]
with Path(os.environ["API_TEST_CALLS"]).open("a") as stream:
    stream.write(json.dumps([name,*args])+"\\n")
mode=os.environ.get("API_TEST_MODE", "existing")
if name == "python":
    if args and args[0] == "tools/compose_documentation.py":
        if "--select-version-source" in args:
            if mode in {"broken","missing-asset"}:
                sys.exit(7)
            print(json.dumps({"release_version":"0.3.0" if mode == "absent" else "",
                "retained_archive":"retained.tar.gz" if mode == "existing" else "",
                "retained_sha256":"d"*64 if mode == "existing" else ""}))
        else:
            print(json.dumps({"sha256":"d"*64}))
    elif args and args[0] == "-m":
        pass
    else:
        os.execv(sys.executable,[sys.executable,*args])
elif name == "gh":
    if args[0] == "api":
        status={"absent":"404", "broken":"503"}.get(mode,"200")
        print("HTTP/2.0 "+status+" Selected observation")
        sys.exit(0 if status == "200" else 1)
    sys.exit(7 if mode == "missing-asset" else 0)
elif name == "git":
    if args[0] == "rev-parse":
        print(("b" if "tree" in args[-1] else "a")*40)
    elif args[0] == "show":
        print("123")
'''
    for path in (binary / "gh", binary / "git", python):
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    environment = os.environ.copy()
    environment["PATH"] = str(binary) + os.pathsep + environment["PATH"]
    environment["API_TEST_CALLS"] = str(root / "calls.jsonl")
    environment["GITHUB_OUTPUT"] = str(root / "outputs")
    (root / "_build/docs").mkdir(parents=True)
    return environment


@pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None,
                    reason="Documentation workflow executes on its declared Linux Bash runner")
@pytest.mark.parametrize("mode", ["legacy", "absent", "existing", "broken", "missing-asset"])
def test_FiniteVersionWorkflowSelectsOnlyAbsentTagOrVerifiedOriginalAsset(
    tmp_path: Path, mode: str,
) -> None:
    """Execute the exact selection shell and prove query/asset failure cannot regenerate history."""

    step, = [item for item in WorkflowSteps() if item.get("id") == "api-mode"]
    environment = WorkflowRecorder(tmp_path)
    environment["API_TEST_MODE"] = mode
    version = "0.2.1" if mode == "legacy" else "0.3.0"
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nversion = "{version}"\n', encoding="utf-8")
    process = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", step["run"]], cwd=tmp_path,
                             env=environment, text=True, capture_output=True,
                             timeout=10, check=False)
    output = tmp_path / "outputs"
    values = (dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
              if output.exists() else {})
    calls = [json.loads(line) for line in (tmp_path / "calls.jsonl").read_text(
        encoding="utf-8").splitlines()]

    if mode in {"broken", "missing-asset"}:
        assert process.returncode != 0, (
            'Rejected version-source preparation must fail the actual workflow shell'
        )
        assert not values, (
            'Rejected version-source preparation must publish no accepted workflow outputs'
        )
    else:
        assert process.returncode == 0, process.stderr
        assert values["release_version"] == ("0.3.0" if mode == "absent" else ""), (
            'Only the absent-tag mode may select a new immutable release rendering'
        )
        assert bool(values["retained_archive"]) is (mode == "existing"), (
            'Only existing-release mode may supply a retained original release archive'
        )

    if mode == "existing":
        verification, = [call for call in calls if "tools/compose_documentation.py" in call]
        assert verification == ["python", "tools/compose_documentation.py",
                                "--select-version-source", "."], (
            'The workflow must invoke the reviewed version-source selector with its fixed '
            'checkout root'
        )
        assert values["retained_sha256"] == "d" * 64, (
            'Existing-release selection must retain the independently observed original archive '
            'digest'
        )

    assert all(call[0] not in {"gh", "git"} for call in calls), (
        "The workflow must delegate all acquisition to the during-read/deadline-bounded owner"
    )

    if mode == "legacy":
        assert all(call[0] != "gh" for call in calls), "Older branches retain prior behavior"


@pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None,
                    reason="Documentation coverage selection executes on its Linux Bash runner")
@pytest.mark.parametrize("state", ["absent", "present", "missing-tests"])
@pytest.mark.parametrize("tool", ["release_delivery", "release_finalize"])
def test_ReleaseToolCoverageSelectionRequiresItsTestsWhenComposed(
    tmp_path: Path, state: str, tool: str,
) -> None:
    """Execute actual workflow test selection without importing an absent future release tool."""

    step, = [item for item in WorkflowSteps() if item.get("name", "").startswith(
        "Exercise documentation boundaries")]
    environment = WorkflowRecorder(tmp_path)

    if state != "absent":
        (tmp_path / "tools").mkdir()
        (tmp_path / f"tools/{tool}.py").write_text('"""Selected future release tool."""\n')

    if state == "present":
        (tmp_path / "tests/unit").mkdir(parents=True)
        (tmp_path / f"tests/unit/test_{tool}.py").write_text(
            '"""Required tool tests."""\n')

    process = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", step["run"]], cwd=tmp_path,
                             env=environment, text=True, capture_output=True,
                             timeout=10, check=False)

    if state == "missing-tests":
        assert process.returncode != 0 and not (tmp_path / "calls.jsonl").exists(), (
            'An invalid release test owner must fail before any test command is launched'
        )
    else:
        assert process.returncode == 0, process.stderr
        calls = [json.loads(line) for line in (tmp_path / "calls.jsonl").read_text(
            encoding="utf-8").splitlines()]
        assert (f"tests/unit/test_{tool}.py" in calls[0]) is (state == "present"), (
            'The release-delivery unit selection must be enrolled exactly when its source '
            'module exists'
        )
        assert "--cov=tools" in calls[0], "No tool is excluded from per-module branch coverage"
