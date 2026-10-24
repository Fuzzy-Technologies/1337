# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Shared explicit response CLI/shell contract over real canonical owners and controlled wire."""

from __future__ import annotations

import io
import json
import shlex

import pytest

from fuzzy1337 import response_commands as commands
from fuzzy1337.adapters import SerializeContract
from fuzzy1337.cli import Main
from fuzzy1337.command_registry import COMMAND_REGISTRY
from fuzzy1337.model import LocalModelStore
from fuzzy1337.shell import InteractiveShell
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.unit.test_owned_response_parent import AT, URL
from tests.unit.test_owned_response_parent import runner as runner
from tests.unit.test_owned_response_workflow import owned as owned


def Arguments(root):
    """Declare explicit fixed inputs without discovering policy or supplying approval."""

    return ["response", "capture", str(root), "--target", URL, "--scope", "lab", "--owner",
            "operator:execution", "--policy", str(root / "explicit-policy.json")]


@pytest.fixture
def response_cli(owned, runner, monkeypatch):
    """Use the unchanged SDK with the controlled fixture's clock and already initialized loop."""

    (owned.root / "explicit-policy.json").write_text(
        SerializeContract(owned.authority[0].context.policy), encoding="utf-8")
    plan = commands.PlanOwnedResponseCapture
    capture = commands.RunOwnedResponseCapture

    def Plan(*args, **kwargs):
        """Delegate actual planning with the deterministic original decision clock."""

        return plan(*args, **kwargs, clock=lambda: AT)

    async def Capture(*args, **kwargs):
        """Delegate the real owner composition; no successful result is fabricated."""

        return await capture(*args, **kwargs, clock=lambda: AT)

    monkeypatch.setattr(commands, "PlanOwnedResponseCapture", Plan)
    monkeypatch.setattr(commands, "RunOwnedResponseCapture", Capture)
    monkeypatch.setattr(commands.asyncio, "run", runner.run)

    return owned


@pytest.mark.parametrize("flag", ["--target", "--scope", "--owner", "--policy"])
def test_CaptureRequiresAllIndependentInputsBeforeWorkspaceRead(tmp_path, flag):
    """Source scope, owner and policy cannot be replaced by approval or implicit defaults."""

    root = tmp_path / "absent"
    args = Arguments(root)
    index = args.index(flag)
    del args[index:index + 2]

    with pytest.raises(SystemExit) as caught:
        Main([*args, "--approve-safe-response-capture"])

    assert caught.value.code == 2 and not root.exists(), "Argument refusal precedes workspace I/O."


@pytest.mark.parametrize("extra", [["--plan", "--approve-safe-response-capture"],
    ["--plan", "--events-json"], ["--json", "--events-json"], ["--timeout", "30"],
    ["--header", "PRIVATE_SECRET_MARKER"], ["--executable", "other-runtime"]])
def test_AmbiguousPresentationAndRuntimeExtensionsNeverReachSource(tmp_path, capsys, extra):
    """The fixed recipe cannot accept generic flags, dynamic headers or mixed execution intent."""

    with pytest.raises(SystemExit) as caught:
        Main([*Arguments(tmp_path / "absent"), *extra])

    assert caught.value.code == 2 and "PRIVATE_SECRET_MARKER" not in capsys.readouterr().err, (
        "Unsupported input refusal must not echo potentially sensitive supplied values."
    )


@pytest.mark.parametrize("url", ["http://localhost:19008/zap-passive/missing",
    "http://127.0.0.1:019008/zap-passive/missing", "http://127.0.0.1:19008/zap-passive/missing?",
    "http://127.0.0.1:19008/zap-passive/../missing"])
def test_OriginalUrlSpellingRefusesBeforeMissingWorkspace(tmp_path, capsys, url):
    """Selection is validated before canonical target conversion can hide an alternate spelling."""

    assert Main([*Arguments(tmp_path / "absent"), "--target", url, "--plan", "--json"]) == 2, (
        "Invalid original target syntax must remain configuration refusal before workspace read."
    )
    assert json.loads(capsys.readouterr().out)["failure"]["code"] == "invalid_configuration", (
        "Invalid original target must not be relabelled as unrelated state storage failure."
    )


def test_CliPlanAndMissingApprovalNeverPersistOrAcquire(response_cli, capsys):
    """One nonexecuting plan and missing approval preserve the exact canonical source bases."""

    root = response_cli.root
    workspace = LocalWorkspaceStore(root).Open()
    model = LocalModelStore(root).Open()
    assert Main([*Arguments(root), "--plan", "--json"]) == 0, "Descriptive planning must be usable."
    plan = json.loads(capsys.readouterr().out)
    assert plan["state"] == "planned" and not plan["execution_authorized"], (
        "The CLI must never present a plan as a capability or execution grant."
    )
    assert Main([*Arguments(root), "--json"]) == 3, "Policy permission cannot approve the workflow."
    assert json.loads(capsys.readouterr().out)["failure"]["code"] == "authorization", (
        "Explicit approval refusal must remain distinct from storage failure."
    )
    assert LocalWorkspaceStore(root).Open() == workspace and (
        LocalModelStore(root).Open() == model
    ), (
        "Planning and denied workflow approval must not write model or workspace state."
    )
    assert not tuple(root.glob("owned-response-*")), "Neither route creates private capture work."


@pytest.mark.parametrize("presentation", ["json", "events", "human"])
def test_SharedCliCaptureAndShellReplayPreserveOriginalAssociations(
    response_cli, capsys, presentation,
):
    """Actual SDK composition reaches CLI and shell without changing provider attribution."""

    root = response_cli.root
    extra = [] if presentation == "human" else [
        "--events-json" if presentation == "events" else "--json"]
    assert Main([*Arguments(root), "--approve-safe-response-capture", *extra]) == 0, (
        "The explicit product route must acknowledge real original source persistence."
    )
    output = capsys.readouterr().out

    if presentation == "human":
        assert "Response capture: completed" in output, "Human output describes source acquisition."
        source = next(item for item in LocalModelStore(root).Open().observations
                      if item.kind == "owned-response-source")
        receipt_id = source.attributes["original_receipt_id"]

    else:
        rows = [json.loads(line) for line in output.splitlines()]
        summary = rows[-1]["summary"] if presentation == "events" else rows[-1]
        receipt_id = summary["original_receipt_id"]
        assert summary["state"] == "completed" and summary["acquisition_outcome"] == "captured", (
            "Only complete guarded acquisition and persistence may produce completed capture."
        )
        assert len(summary["original_role_ids"]) == 7 and summary["stage_retained"], (
            "The summary preserves all original acknowledged IDs and honest staging state."
        )

    assert "Reviewed non-secret response." not in output, "Raw response cannot become a job event."
    sink = io.StringIO()
    shell = InteractiveShell(stdout=sink)
    shell.onecmd("response " + shlex.join(["replay", str(root), "--receipt", receipt_id, "--json"]))
    replay = json.loads(sink.getvalue())
    assert replay["state"] == "verified" and replay["original_receipt_id"] == receipt_id, (
        "The foreground shell must use the same original offline receipt verification route."
    )
    assert replay["original_job_id"] in LocalWorkspaceStore(root).Open().job_references, (
        "Historical replay must recover the original job, not create a replacement job."
    )


@pytest.mark.parametrize("extra", [["--scope", "lab"], ["--owner", "operator:execution"],
    ["--policy", "current.json"], ["--target", URL], ["--approve-safe-response-capture"]])
def test_HistoricalReplayRejectsCurrentAuthorityOrTargetInputs(tmp_path, extra):
    """Historical integrity verification cannot become an acquisition or renewed grant."""

    with pytest.raises(SystemExit) as caught:
        Main(["response", "replay", str(tmp_path), "--receipt", "sha256:" + "a" * 64, *extra])

    assert caught.value.code == 2, "Replay accepts no current runtime, target or authority."


def test_UnknownReplayAssociationRefusesInsteadOfInventingOriginalJob(response_cli, capsys):
    """A stored or supplied receipt address is not a known durable source association."""

    assert Main(["response", "replay", str(response_cli.root), "--receipt",
                 "sha256:" + "a" * 64, "--json"]) == 4, "Unknown custody fails integrity checks."
    document = json.loads(capsys.readouterr().out)
    assert document["failure"]["code"] == "integrity" and "original_job_id" not in document, (
        "Unknown original job attribution must remain unknown rather than synthesized."
    )


def test_ResponseHelpAndRegistryAdvertiseOnlyAcquisitionCapability(capsys):
    """A separate namespace keeps native web checks and future passive analysis distinct."""

    with pytest.raises(SystemExit) as caught:
        Main(["response", "--help"])

    help_text = capsys.readouterr().out
    descriptor = COMMAND_REGISTRY.Resolve("response")
    assert caught.value.code == 0 and "capture" in help_text and "replay" in help_text, (
        "Both explicit source operations must remain discoverable through the installed interface."
    )
    assert descriptor.capabilities == ("http.synthetic-response-capture",), (
        "Source acquisition must advertise no ZAP or assessed capability."
    )
