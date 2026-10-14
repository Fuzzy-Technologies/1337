# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Isolated configuration command delivery and truthful SDK result/error presentation."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from fuzzy1337 import scan_commands
from fuzzy1337.artifact_inputs import ArtifactProfile
from fuzzy1337.cli import Main
from fuzzy1337.configuration_workflow import ConfigurationScanSummary
from fuzzy1337.evidence import EvidenceError
from fuzzy1337.jobs import JobEvent, JobEventKind, JobSnapshot, JobSpec, JobState
from fuzzy1337.workspace import WorkspaceBusyError, WorkspaceConflictError


@pytest.fixture(scope="module")
def command_loop() -> Iterator[asyncio.Runner]:
    """Own event-loop resources before the unchanged per-test network denial guard."""

    with asyncio.Runner() as runner:
        runner.get_loop()
        yield runner


@pytest.fixture(autouse=True)
def reuse_command_loop(command_loop: asyncio.Runner, monkeypatch: pytest.MonkeyPatch) -> None:
    """Use the initialized loop for dispatch doubles while keeping network denial active."""

    monkeypatch.setattr(scan_commands.asyncio, "run", command_loop.run)


def Arguments(root: Path) -> list[str]:
    """Select inert explicit paths without constructing or reading a workspace."""

    return ["scan", "config", str(root), "--profile", "synthetic", "--type", "dockerfile",
        "--logical-path", "Dockerfile", "--source", str(root / "selected"),
        "--scope", "config-scope", "--owner", "owner:test", "--executable", str(root / "python"),
        "--producer", str(root / "producer.py"), "--material", str(root / "policy.json"),
        "--read-consent-reference", "read:test"]


@pytest.mark.parametrize("source_type,profile", [
    ("dockerfile", ArtifactProfile.SYNTHETIC_DOCKERFILE),
    ("kubernetes", ArtifactProfile.SYNTHETIC_KUBERNETES),
])
@pytest.mark.parametrize("mode", ["human", "json", "events"])
def test_ConfigurationCommandPassesExactExplicitInputsAndCanonicalEvents(
    tmp_path, monkeypatch, capsys, source_type, profile, mode
):
    """The adapter preserves selected inputs and original result; this double proves no scan."""

    event = JobEvent("job:config-test", 0, JobEventKind.STATE, JobState.COMPLETED)
    snapshot = JobSnapshot(JobSpec("job:config-test", "workspace", "scope:config-scope",
        "owner:test", "synthetic.trivy"), JobState.COMPLETED, 0, None, None, (), False)
    summary = ConfigurationScanSummary(snapshot, "2026-10-14T00:00:00+00:00",
        "2026-10-14T00:00:01+00:00", 1.0, None, 7, (), (event,), ())
    calls = []

    async def Run(root, scope, owner, selection, **options):
        """Observe delivery and emit one original canonical event without runtime execution."""

        calls.append((root, scope, owner, selection, options))
        options["on_event"](event)

        return summary

    monkeypatch.setattr(scan_commands, "RunSyntheticConfigurationScan", Run)
    destination = tmp_path / "new.json"
    arguments = [*Arguments(tmp_path), "--type", source_type, "--approve-safe-configuration",
        "--timeout", "9", "--report-format", "json", "--report-output", str(destination)]

    if mode != "human":
        arguments.append("--json" if mode == "json" else "--events-json")

    assert Main(arguments) == 0, "Command must return the workflow's completed exit status"
    root, scope, owner, selection, options = calls[0]
    assert (root, scope, owner) == (tmp_path, "config-scope", "owner:test"), (
        "Workspace and authority cannot be inferred from presentation or shell context"
    )
    assert selection.profile is profile and selection.logical_path == "Dockerfile", (
        "The explicit source type must select only its existing closed synthetic profile"
    )
    assert (selection.source, selection.executable, selection.producer, selection.material) == (
        tmp_path / "selected", tmp_path / "python", tmp_path / "producer.py",
        tmp_path / "policy.json"
    ), "The adapter must preserve explicit physical selections"
    assert selection.read_consent.actor_ref == "owner:test" and (
        selection.read_consent.record_ref == "read:test"
    ), "Selected read consent retains its explicitly executing actor and original reference"
    assert options["approve_safe_configuration"] is True and options["timeout_seconds"] == 9, (
        "SAFE opt-in and the actual SDK deadline remain separate explicit inputs"
    )
    assert options["report_format"] == "json" and options["report_output"] == destination, (
        "Report selections must reach the existing workflow publication owner unchanged"
    )
    lines = capsys.readouterr().out.splitlines()

    if mode == "human":
        assert lines[-1] == (
            "Synthetic Configuration Scan completed; model revision 7; evidence records 0"
        ), "Human presentation must label the actual synthetic configuration workflow"

    elif mode == "json":
        assert [json.loads(line) for line in lines] == [summary.ToDict()], (
            "JSON summary must retain the original canonical workflow facts"
        )

    else:
        messages = [json.loads(line) for line in lines]
        assert messages[0]["event"] == summary.ToDict()["events"][0] and (
            messages[-1]["summary"] == summary.ToDict()
        ), "Event presentation must preserve canonical identity before the original summary"


@pytest.mark.parametrize("error,status,code", [
    (ValueError("synthetic-private-value"), 2, "invalid_configuration"),
    (OSError("synthetic-private-value"), 4, "storage"),
    (EvidenceError("synthetic-private-value"), 4, "storage"),
    (WorkspaceBusyError("synthetic-private-value"), 4, "storage"),
    (WorkspaceConflictError("synthetic-private-value"), 4, "storage"),
], ids=["input", "io", "evidence", "busy", "conflict"])
def test_ConfigurationSetupFailureKeepsExitClassificationAndPrivateDetails(
    tmp_path, monkeypatch, capsys, error, status, code
):
    """Failed setup is a failed machine outcome without reflecting selected private values."""

    async def Run(*_args, **_options):
        """Inject the caller-visible SDK/setup exception without accessing local inputs."""

        raise error

    monkeypatch.setattr(scan_commands, "RunSyntheticConfigurationScan", Run)
    assert Main([*Arguments(tmp_path), "--json"]) == status, (
        "Configuration and storage exceptions must retain their existing product exit classes"
    )
    output = capsys.readouterr().out
    assert json.loads(output)["failure"]["code"] == code and (
        "synthetic-private-value" not in output
    ), (
        "Safe diagnostics retain classification and exclude original source/storage details"
    )
