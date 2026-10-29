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


@pytest.mark.skipif(os.name == "nt", reason="Templates target the documented Linux shell runners")
@pytest.mark.parametrize("platform", ["github-actions", "gitlab-ci"])
@pytest.mark.parametrize("approval", [None, "0", "1"])
def test_TemplateDockerInvocationPropagatesOnlyExplicitCallerApproval(
    tmp_path: Path, platform: str, approval: str | None,
) -> None:
    """Execute actual template Docker shell lines against an approval argv recorder."""

    template = yaml.safe_load((TEMPLATES / f"{platform}.yml").read_text())

    if platform == "github-actions":
        dispatch = template.get("on", template.get(True))["workflow_dispatch"]["inputs"]
        assert dispatch["approved_local_demo"] == {
            "description": "Approve only the fixed owned loopback plan documented in docs/DEMO.md",
            "required": True, "type": "boolean", "default": False,
        }
        step = template["jobs"]["local-demo"]["steps"][1]
        assert step["env"]["F1337_APPROVED_LOCAL_DEMO"] == (
            "${{ inputs.approved_local_demo && '1' || '0' }}"
        )
        shell = step["run"].replace("\\\n", " ")
        command, = [line for line in shell.splitlines() if line.lstrip().startswith("docker run ")]

    else:
        job = template["1337-local-demo"]
        assert "F1337_APPROVED_LOCAL_DEMO" not in job.get("variables", {})
        assert job["artifacts"]["when"] == "always"
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
    environment.pop("F1337_APPROVED_LOCAL_DEMO", None)

    if approval is not None:
        environment["F1337_APPROVED_LOCAL_DEMO"] = approval

    result = subprocess.run(["bash", "-eu", "-c", command], env=environment, cwd=tmp_path,
                            capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr
    arguments = json.loads(result.stdout)
    value = arguments[arguments.index("-e") + 1]
    assert value == "F1337_APPROVED_LOCAL_DEMO=" + (approval or "")
    assert (value == "F1337_APPROVED_LOCAL_DEMO=1") is (approval == "1"), (
        "An absent or denied caller approval must never become a granted container environment"
    )
