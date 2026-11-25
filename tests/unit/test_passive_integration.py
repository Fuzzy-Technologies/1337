# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Keep passive CI limited to genuine unit checks and benign isolated lifecycle work."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tools import passive_lab_lifecycle as lifecycle

PROJECT = "passive-health-unit"
CONTAINER = "a" * 64


def DockerReplies(monkeypatch, *, failure=None):
    """Provide deterministic Docker responses while retaining exact attempted operations."""

    calls = []

    def Run(arguments, **options):
        """Model only the commands needed for the benign service and strict cleanup."""

        assert options == {"capture_output": True, "text": True, "timeout": 240, "check": False}, (
            'Passive lifecycle commands must preserve the bounded non-shell subprocess '
            'contract'
        )
        calls.append(arguments)
        output = ""
        status = 0

        if arguments[:2] == ["docker", "inspect"]:
            details = {
                "State": {"Running": True, "Health": {"Status": "healthy"}},
                "Config": {"Labels": {
                    "com.docker.compose.project": PROJECT,
                    "com.docker.compose.service": "lab-web-safe",
                }},
                "HostConfig": {"ReadonlyRootfs": True, "Privileged": False,
                               "CapDrop": ["ALL"], "PortBindings": {}},
                "NetworkSettings": {"Networks": {"safe-network": {}}},
            }

            if failure == "exposed":
                details["HostConfig"]["PortBindings"] = {"8080/tcp": [{"HostPort": "8080"}]}

            if failure == "foreign":
                details["Config"]["Labels"]["com.docker.compose.project"] = "other-project"

            output = json.dumps([details])

        elif arguments[:3] == ["docker", "network", "inspect"]:
            output = json.dumps([{"Internal": failure != "network"}])

        elif "ps" in arguments and "compose" in arguments:
            output = CONTAINER

        elif "exec" in arguments:
            status = 1 if failure == "health" else 0

        elif "up" in arguments and failure == "startup":
            status = 1

        elif "down" in arguments and failure == "cleanup":
            status = 1

        elif arguments[:2] == ["docker", "ps"] and failure == "remaining-container":
            output = CONTAINER

        elif arguments[:3] == ["docker", "network", "ls"] and failure == "remaining-network":
            output = "remaining-network"

        return subprocess.CompletedProcess(arguments, status, output, "")

    monkeypatch.setattr(lifecycle.subprocess, "run", Run)

    return calls


def test_PassiveLifecycleChecksIsolationHealthAndIndependentCleanup(tmp_path, monkeypatch):
    """A pass requires a healthy unexposed service and observed absence after teardown."""

    calls = DockerReplies(monkeypatch)
    receipt = tmp_path / "lifecycle.json"
    lifecycle.VerifyLifecycle(PROJECT, receipt)
    result = json.loads(receipt.read_bytes())

    assert result["status"] == "completed" and result["cleanup_verified"] is True, (
        'A passive lifecycle pass must establish owned isolation, real health and '
        'independent resource absence'
    )
    assert result["container_id"] == CONTAINER and result["isolated"] is True, (
        'A passive lifecycle pass must establish owned isolation, real health and '
        'independent resource absence'
    )
    assert calls[0][-4:] == ["up", "--build", "--wait", "lab-web-safe"], (
        'A passive lifecycle pass must establish owned isolation, real health and '
        'independent resource absence'
    )
    assert any("exec" in call and call[-1] == lifecycle.HEALTH_COMMAND for call in calls), (
        'A passive lifecycle pass must establish owned isolation, real health and '
        'independent resource absence'
    )
    assert all("attack-path" not in " ".join(call) and "validate" not in call for call in calls), (
        'A passive lifecycle pass must establish owned isolation, real health and '
        'independent resource absence'
    )
    assert calls[-2][:2] == ["docker", "ps"], (
        'A passive lifecycle pass must establish owned isolation, real health and '
        'independent resource absence'
    )
    assert calls[-1][:3] == ["docker", "network", "ls"], (
        'A passive lifecycle pass must establish owned isolation, real health and '
        'independent resource absence'
    )


@pytest.mark.parametrize("failure", [
    "startup", "exposed", "foreign", "network", "health", "cleanup",
    "remaining-container", "remaining-network",
])
def test_PassiveLifecycleRefusesFailureAndRetainsActualCleanupResult(
    tmp_path, monkeypatch, failure,
):
    """Health, isolation and teardown errors cannot produce a successful receipt."""

    calls = DockerReplies(monkeypatch, failure=failure)
    receipt = tmp_path / "failure.json"

    with pytest.raises((ValueError, RuntimeError)):
        lifecycle.VerifyLifecycle(PROJECT, receipt)

    result = json.loads(receipt.read_bytes())
    assert result["status"] == "failed", (
        'A lifecycle failure must never produce a completed receipt'
    )
    assert any("down" in call for call in calls), "Startup failure must still clean its own project"


def test_PassiveLifecycleRejectsAmbiguousOwnershipBeforeDocker(tmp_path, monkeypatch):
    """A missing dedicated project owner must never reach Docker or write evidence."""

    calls = DockerReplies(monkeypatch)
    receipt = tmp_path / "absent.json"

    with pytest.raises(ValueError, match="dedicated"):
        lifecycle.VerifyLifecycle("shared-project", receipt)

    assert not calls and not receipt.exists(), (
        'Ambiguous project ownership must reach neither Docker nor evidence '
        'publication'
    )


def WorkflowJobs():
    """Read actual workflow routing without starting any job or service."""

    path = Path(__file__).resolve().parents[2] / ".github/workflows/python-quality.yml"

    return yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"]


def test_PassiveBatchRunsOneCompleteUnitPartitionWithoutProductAcceptanceFlags():
    """The canonical Linux partition must run every unit with coverage through the real runner."""

    jobs = WorkflowJobs()
    quality = jobs["quality"]
    assert quality["needs"] == "saved-report-acceptance", (
        'Passive integration must run one complete measured Linux unit partition '
        'without active acceptance flags'
    )
    selected = next(step for step in quality["steps"]
                    if step["name"] == "Run all passive unit tests with branch coverage")
    condition = " ".join(selected["if"].split())
    assert "matrix.os == 'ubuntu-24.04' && matrix.python == '3.13'" in condition, (
        'Passive integration must run one complete measured Linux unit partition '
        'without active acceptance flags'
    )
    assert "integration_profile == 'passive'" in condition, (
        'Passive integration must run one complete measured Linux unit partition '
        'without active acceptance flags'
    )
    assert "github.base_ref == 'develop'" in condition, (
        'Passive integration must run one complete measured Linux unit partition '
        'without active acceptance flags'
    )
    assert selected["run"].startswith(
        "uv run --locked --extra dev python tools/passive_test_gate.py",
    ), (
        'Passive integration must run one complete measured Linux unit partition '
        'without active acceptance flags'
    )
    assert not any(token in selected["run"] for token in ("--no-cov", " -k ", "tests/")), (
        'Passive integration must run one complete measured Linux unit partition '
        'without active acceptance flags'
    )
    assert selected["env"] == {"PASSIVE_BASE": "${{ github.event.pull_request.base.sha }}"}, (
        'Passive integration must run one complete measured Linux unit partition '
        'without active acceptance flags'
    )
    assert sum("tools/passive_test_gate.py" in step.get("run", "")
               for step in quality["steps"]) == 1, (
        'Passive integration must run one complete measured Linux unit partition '
        'without active acceptance flags'
    )
    full = next(step for step in quality["steps"]
                if step["name"] == "Run repository quality gate")
    assert "integration_profile == 'full'" in full["if"], (
        'Passive integration must run one complete measured Linux unit partition '
        'without active acceptance flags'
    )
    assert "1337-dev check --fail-fast" in full["run"], (
        'Passive integration must run one complete measured Linux unit partition '
        'without active acceptance flags'
    )


def test_PassiveProfileCannotStartBrowserTargetsOrExplicitActiveCheckpoints():
    """Even an old diagnostic marker cannot bypass the independently admitted passive profile."""

    jobs = WorkflowJobs()
    assert jobs["integration-scope"]["uses"] == (
        "./.github/workflows/passive-acceptance-routing.yml"
    ), (
        'Browser, target and active checkpoint jobs must depend on the independently '
        'admitted full profile'
    )
    decision = jobs["saved-report-acceptance"]
    assert decision["needs"] == "integration-scope", (
        'Browser, target and active checkpoint jobs must depend on the independently '
        'admitted full profile'
    )
    assert decision["outputs"]["integration_profile"] == (
        "${{ needs.integration-scope.outputs.profile }}"
    ), (
        'Browser, target and active checkpoint jobs must depend on the independently '
        'admitted full profile'
    )

    for name in ("browser-page-quality", "external-targets"):
        assert jobs[name]["needs"] == "saved-report-acceptance", (
            'Browser, target and active checkpoint jobs must depend on the independently '
            'admitted full profile'
        )
        assert jobs[name]["if"].strip().startswith(
            "needs.saved-report-acceptance.outputs.integration_profile == 'full'"
        ), (
            'Browser, target and active checkpoint jobs must depend on the independently '
            'admitted full profile'
        )

    for name in (
        "nuclei-governed-prerequisite-checkpoint", "nuclei-application-product-checkpoint",
        "nuclei-contract-windows-checkpoint", "owned-traversal-rate-checkpoint",
        "native-crawl-windows-portability", "native-crawl-container-portability",
    ):
        assert jobs[name]["needs"] == "integration-scope", (
            'Browser, target and active checkpoint jobs must depend on the independently '
            'admitted full profile'
        )
        assert jobs[name]["if"].strip().startswith(
            "needs.integration-scope.outputs.profile == 'full' && ("
        ), (
            'Browser, target and active checkpoint jobs must depend on the independently '
            'admitted full profile'
        )


def test_PassiveSyntheticCheckUsesOnlyBenignLifecycleAndRequiresOriginalReceipt():
    """The required lifecycle job must execute useful work without any active path validation."""

    job = WorkflowJobs()["synthetic-lab"]
    assert job["name"] == "Synthetic lab lifecycle", (
        'Required passive lifecycle must perform benign health work and preserve its '
        'original failing-or-successful receipt'
    )
    assert job["needs"] == "saved-report-acceptance", (
        'Required passive lifecycle must perform benign health work and preserve its '
        'original failing-or-successful receipt'
    )
    steps = {step["name"]: step for step in job["steps"]}
    benign = steps["Verify benign isolated startup health and teardown"]
    assert "integration_profile == 'passive'" in benign["if"], (
        'Required passive lifecycle must perform benign health work and preserve its '
        'original failing-or-successful receipt'
    )
    assert "tools/passive_lab_lifecycle.py" in benign["run"], (
        'Required passive lifecycle must perform benign health work and preserve its '
        'original failing-or-successful receipt'
    )
    project = "--project passive-health-${{ github.run_id }}-${{ github.run_attempt }}"
    assert project in benign["run"], (
        'Required passive lifecycle must perform benign health work and preserve its '
        'original failing-or-successful receipt'
    )
    assert not any(word in benign["run"] for word in ("attack-path", "pytest", "client.py")), (
        'Required passive lifecycle must perform benign health work and preserve its '
        'original failing-or-successful receipt'
    )
    original = steps["Verify attack-path mini lifecycle"]
    assert original["if"] == (
        "needs.saved-report-acceptance.outputs.integration_profile == 'full'"
    ), (
        'Required passive lifecycle must perform benign health work and preserve its '
        'original failing-or-successful receipt'
    )
    assert "tests/functional/test_attack_path_lab.py" in original["run"], (
        'Required passive lifecycle must perform benign health work and preserve its '
        'original failing-or-successful receipt'
    )
    receipt = steps["Retain actual passive lifecycle evidence"]
    assert receipt["with"]["if-no-files-found"] == "error", (
        'Required passive lifecycle must perform benign health work and preserve its '
        'original failing-or-successful receipt'
    )
    assert "always()" in receipt["if"] and "integration_profile == 'passive'" in receipt["if"], (
        'Required passive lifecycle must perform benign health work and preserve its '
        'original failing-or-successful receipt'
    )


@pytest.mark.parametrize("identity", ["quality", "container-quality", "synthetic-lab"])
@pytest.mark.parametrize("result", ["success", "failure", "skipped", "cancelled"])
@pytest.mark.parametrize("profile", ["full", "passive", "hold", ""])
def test_RequiredProfilesRefuseMissingOrHeldRoutingBeforeRuntimeWork(identity, result, profile):
    """Execute actual guards to reject unverified scope before Docker or acceptance operations."""

    job = WorkflowJobs()[identity]
    guard = next(step for step in job["steps"] if "ROUTING_RESULT" in step.get("env", {}))
    assert "if" not in guard, "Required route refusal must apply to master and ordinary routes too"
    assert guard["env"] == {
        "ROUTING_RESULT": "${{ needs.saved-report-acceptance.result }}",
        "INTEGRATION_PROFILE": "${{ needs.saved-report-acceptance.outputs.integration_profile }}",
    }, (
        'Required runtime work must reject missing or held routing through the '
        'original guard commands'
    )
    environment = {"PATH": os.defpath, "ROUTING_RESULT": result, "INTEGRATION_PROFILE": profile}

    if identity == "container-quality":
        assert job["steps"][0] is guard, "No container action may precede the required route guard"
        arguments = ["bash", "-e", "-c", guard["run"]]

    else:
        command = shlex.split(guard["run"])
        assert command[0] == "python" and command[1] == "-c", (
            'Required runtime work must reject missing or held routing through the '
            'original guard commands'
        )
        arguments = [sys.executable, *command[1:]]

    checked = subprocess.run(arguments, env=environment, check=False, capture_output=True,
                             text=True, timeout=10)
    assert (checked.returncode == 0) is (result == "success" and profile in {"full", "passive"}), (
        "Failed/skipped routing, a missing output or hold cannot turn a required check green"
    )



def test_LifecycleCliRetainsExplicitProjectAndReceipt(tmp_path, monkeypatch):
    """The entry point cannot infer a project owner or evidence destination."""

    calls = []
    receipt = tmp_path / "cli.json"
    monkeypatch.setattr(lifecycle, "VerifyLifecycle", lambda project, receipt:
                        calls.append((project, receipt)))
    monkeypatch.setattr(sys, "argv", ["passive-lifecycle", "--project", PROJECT,
                                     "--receipt", str(receipt)])
    lifecycle.Main()
    assert calls == [(PROJECT, receipt)], (
        'The lifecycle entry point must pass the exact explicit project owner and '
        'receipt destination'
    )
