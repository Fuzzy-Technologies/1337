# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Prove copyable CI shells propagate caller approval without silently granting it."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "docs/examples/ci"


def test_GitHubPlatformWorkflowIsAnExactReadOnlyManualTemplateCopy() -> None:
    """Require the actual platform gate to execute exactly the public example."""

    public = (TEMPLATES / "github-actions.yml").read_bytes()
    actual = (ROOT / ".github/workflows/ci-onboarding-demo.yml").read_bytes()
    assert actual == public, "The real GitHub workflow must preserve every public template byte"
    template = yaml.safe_load(public)
    events = template.get("on", template.get(True))
    assert set(events) == {"workflow_dispatch"}, (
        "The owned platform demonstration must not run automatically on pushes or pull requests"
    )
    assert template["permissions"] == {"contents": "read"}, (
        "The public demonstration must not receive publication or repository write authority"
    )
    steps = template["jobs"]["local-demo"]["steps"]
    verification, = [step for step in steps if step["name"] == (
        "Verify owned container/image teardown")]
    retention, = [step for step in steps if step["name"] == (
        "Retain actual evidence and diagnostics")]
    assert verification["if"] == retention["if"] == "always()", (
        "Denied and failed runs must still verify teardown and retain available originals"
    )


@pytest.mark.skipif(os.name == "nt", reason="The platform template uses the Linux Bash runner")
@pytest.mark.parametrize("mode", ["empty", "container", "image", "query-error"])
def test_GitHubTeardownReadbackRequiresActualAbsenceOfExactOwnedResources(
    tmp_path: Path, mode: str,
) -> None:
    """Execute the copied verification shell against causal owned-resource observations."""

    template = yaml.safe_load((TEMPLATES / "github-actions.yml").read_text(encoding="utf-8"))
    step, = [step for step in template["jobs"]["local-demo"]["steps"] if step["name"] == (
        "Verify owned container/image teardown")]
    recorder = tmp_path / "docker"
    recorder.write_text(
        '#!/bin/bash\nset -eu\nprintf "%s\\n" "$*" >> "$CALLS"\n'
        'if test "$MODE" = query-error; then exit 9; fi\n'
        'if test "$MODE" = container && test "$1" = container; then '
        'printf "%s\\n" 1337-demo-123-2; fi\n'
        'if test "$MODE" = image && test "$1" = image; then printf "%s\\n" image-id; fi\n',
        encoding="utf-8",
    )
    recorder.chmod(0o755)
    environment = os.environ.copy()
    environment.update({"PATH": str(tmp_path) + os.pathsep + environment["PATH"],
        "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "MODE": mode,
        "CALLS": str(tmp_path / "calls")})
    result = subprocess.run(["bash", "-eu", "-c", step["run"]], cwd=tmp_path,
        env=environment, capture_output=True, text=True, timeout=10, check=False)
    assert (result.returncode == 0) is (mode == "empty"), (
        "Teardown may pass only after successful Docker queries observe both owned resources absent"
    )
    calls = (tmp_path / "calls").read_text(encoding="utf-8").splitlines()
    assert calls[0] == "container ls --all --filter name=^/1337-demo-123-2$ --format {{.Names}}", (
        "Container readback must select only the current run and attempt's exact owned name"
    )

    if mode != "query-error":
        assert calls[1] == (
            "image ls --filter reference=1337-local-demo:123-2 --format {{.ID}}"
        ), "Image readback must select only the exact run and attempt's owned image tag"

    proof = tmp_path / "artifacts/owned-teardown.json"
    assert proof.exists() is (mode == "empty"), (
        "Failed readback must not manufacture a successful owned-resource teardown receipt"
    )

    if mode == "empty":
        assert json.loads(proof.read_bytes()) == {
            "schema_version": 1, "owned_resources_removed": True,
            "container": "1337-demo-123-2", "image": "1337-local-demo:123-2",
        }, "Successful teardown must retain the exact original owned-resource selection"


@pytest.mark.skipif(os.name == "nt", reason="The platform template uses the Linux Bash runner")
@pytest.mark.parametrize("status", [0, 3])
def test_GitHubExecutionTrapPreservesOriginalApprovedOrDeniedStatus(
    tmp_path: Path, status: int,
) -> None:
    """Prove cleanup cannot turn an original installed-command denial into workflow success."""

    template = yaml.safe_load((TEMPLATES / "github-actions.yml").read_text(encoding="utf-8"))
    step, = [step for step in template["jobs"]["local-demo"]["steps"] if step["name"] == (
        "Build and run installed wheel in isolated container")]
    recorder = tmp_path / "docker"
    recorder.write_text(
        '#!/bin/bash\nset -eu\nprintf "%s\\n" "$*" >> "$CALLS"\n'
        'if test "$1" = run; then exit "$ORIGINAL_STATUS"; fi\n',
        encoding="utf-8",
    )
    recorder.chmod(0o755)
    environment = os.environ.copy()
    environment.update({"PATH": str(tmp_path) + os.pathsep + environment["PATH"],
        "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "PYTHON_IMAGE": "owned:base",
        "F1337_APPROVED_LOCAL_DEMO": "1" if status == 0 else "0",
        "ORIGINAL_STATUS": str(status), "CALLS": str(tmp_path / "calls")})
    result = subprocess.run(["bash", "-eu", "-c", step["run"]], cwd=tmp_path,
        env=environment, capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == status, (
        "The shell must preserve the original execution status, including expected denial three"
    )
    assert (tmp_path / "calls").read_text(encoding="utf-8").splitlines()[-2:] == [
        "rm --force --volumes 1337-demo-123-2", "image rm 1337-local-demo:123-2",
    ], "Both original execution outcomes must attempt cleanup of only their known owned resources"


@pytest.mark.skipif(os.name == "nt", reason="Templates target the documented Linux shell runners")
@pytest.mark.parametrize("platform", ["github-actions", "gitlab-ci"])
@pytest.mark.parametrize("approval", [None, "0", "1"])
def test_TemplateDockerInvocationPropagatesOnlyExplicitCallerApproval(
    tmp_path: Path, platform: str, approval: str | None,
) -> None:
    """Execute actual template Docker shell lines against an approval argv recorder."""

    template = yaml.safe_load((TEMPLATES / f"{platform}.yml").read_text(encoding="utf-8"))

    if platform == "github-actions":
        dispatch = template.get("on", template.get(True))["workflow_dispatch"]["inputs"]
        assert dispatch["approved_local_demo"] == {
            "description": "Approve only the fixed owned loopback plan documented in docs/DEMO.md",
            "required": True, "type": "boolean", "default": False,
        }, (
            'GitHub dispatch must require an explicit false-by-default approval for only the '
            'fixed local plan'
        )
        step = template["jobs"]["local-demo"]["steps"][1]
        assert step["env"]["F1337_APPROVED_LOCAL_DEMO"] == (
            "${{ inputs.approved_local_demo && '1' || '0' }}"
        ), (
            'The GitHub template must derive demo approval solely from the operator dispatch input'
        )
        shell = step["run"].replace("\\\n", " ")
        command, = [line for line in shell.splitlines() if line.lstrip().startswith("docker run ")]

    else:
        job = template["1337-local-demo"]
        assert "F1337_APPROVED_LOCAL_DEMO" not in job.get("variables", {}), (
            'The GitLab template must not manufacture approval in its job variables'
        )
        assert job["artifacts"]["when"] == "always", (
            'The GitLab template must retain available diagnostics even when its job fails'
        )
        assert job["rules"] == [{
            "if": '$CI_PIPELINE_SOURCE == "web" || $CI_PIPELINE_SOURCE == "api"',
        }], "Only authenticated explicit manual web/API pipeline entry points are enabled"
        command, = [line for line in job["script"] if line.startswith("docker run ")]

    recorder = tmp_path / "docker"
    recorder.write_text(
        '#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n',
        encoding="utf-8",
    )
    recorder.chmod(0o755)
    environment = os.environ.copy()
    environment["PATH"] = str(tmp_path) + os.pathsep + environment["PATH"]
    environment["CI_JOB_ID"] = "123"
    environment["DEMO_IMAGE"] = "1337-local-demo:123-1"
    environment["DEMO_CONTAINER"] = "1337-demo-123-1"
    environment.pop("F1337_APPROVED_LOCAL_DEMO", None)

    if approval is not None:
        environment["F1337_APPROVED_LOCAL_DEMO"] = approval

    result = subprocess.run(["bash", "-eu", "-c", command], env=environment, cwd=tmp_path,
                            capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr
    arguments = json.loads(result.stdout)
    assert arguments[arguments.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}", (
        "Container evidence must remain owned/readable by the real artifact-uploading runner"
    )
    expected_name = "1337-demo-123-1" if platform == "github-actions" else "1337-demo-123"
    assert arguments[arguments.index("--name") + 1] == expected_name, (
        'The container invocation must use exactly the job-owned name needed for scoped cleanup'
    )
    value = arguments[arguments.index("-e") + 1]
    assert value == "F1337_APPROVED_LOCAL_DEMO=" + (approval or ""), (
        'The container must receive only the independently supplied demo approval value'
    )
    assert (value == "F1337_APPROVED_LOCAL_DEMO=1") is (approval == "1"), (
        "An absent or denied caller approval must never become a granted container environment"
    )
