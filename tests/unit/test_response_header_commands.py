# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic CLI/shell enrollment over mocked offline header SDK and storage boundaries."""

from __future__ import annotations

import io
import json
import shlex
from types import SimpleNamespace

import pytest

from fuzzy1337 import model, native_response_header_workflow, workspace
from fuzzy1337 import response_commands as commands
from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.cli import Main
from fuzzy1337.jobs import JobEvent, JobEventKind
from fuzzy1337.native_response_headers import NativeResponseHeaderError
from fuzzy1337.policy import ImpactPolicy, PolicyDenialReason, PolicyDeniedError
from fuzzy1337.scope import Target, TargetKind
from fuzzy1337.shell import InteractiveShell

URL = "http://127.0.0.1:19008/zap-passive/missing"
RECEIPT = "sha256:" + "a" * 64
ASSESSMENT = "observation:" + "b" * 64


def Arguments(root):
    """Select every independent interpretation input without supplying the separate opt-in."""

    return ["response", "check-headers", str(root), "--receipt", RECEIPT, "--target", URL,
            "--scope", "original-scope", "--owner", "operator:explicit", "--policy",
            str(root / "current-policy.json"), "--analysis-reference", "analysis:independent"]


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    """Replace SDK/storage boundaries only; never acquire originals or run interpretation."""

    state = SimpleNamespace(root=tmp_path / "absent", calls=[], opens=[], policy_reads=[],
        model_revision=11, workspace_revision=7, outcome="completed", failure=None,
        policy=ImpactPolicy("first-explicit-policy", maximum_impact=ImpactLevel.PASSIVE),
        exception=None, documents=[])

    def WorkspaceStore(root):
        """Expose the current selected workspace revision without creating a real workspace."""

        def Open():
            """Record the one current original workspace read for this command attempt."""

            state.opens.append(("workspace", root))

            return SimpleNamespace(revision=state.workspace_revision)

        return SimpleNamespace(Open=Open)

    def ModelStore(root):
        """Expose the current selected model revision without executing a real model owner."""

        def Open():
            """Record the one current original model read for this command attempt."""

            state.opens.append(("model", root))

            return SimpleNamespace(revision=state.model_revision)

        return SimpleNamespace(Open=Open)

    def ReadPolicy(path):
        """Return the current explicit value on every reader call without an implicit policy."""

        state.policy_reads.append(path)

        return state.policy

    def Apply(*args, **kwargs):
        """Record the exact SDK handoff; the test deliberately performs no interpretation."""

        state.calls.append((args, kwargs))

        if state.exception is not None:
            raise state.exception

        document = {"schema_version": 1, "workflow": "owned-response-header-check",
            "state": state.outcome, "model_revision": state.model_revision,
            "workspace_revision": state.workspace_revision, "model_commit": "observed-committed",
            "workspace_commit": "unconfirmed", "failure": state.failure,
            "original_receipt_id": RECEIPT, "assessment_reference": ASSESSMENT}
        state.documents.append(document)

        return SimpleNamespace(state=state.outcome, ToDict=lambda: document)

    def UnrelatedOperation(*args, **kwargs):
        """Fail closed before any unrelated original SDK or source acquisition can execute."""

        raise AssertionError("Mocked header units must not invoke a source owner or hidden replay.")

    monkeypatch.setattr(workspace, "LocalWorkspaceStore", WorkspaceStore)
    monkeypatch.setattr(model, "LocalModelStore", ModelStore)
    monkeypatch.setattr(commands, "ReadNucleiPolicy", ReadPolicy)
    monkeypatch.setattr(native_response_header_workflow, "ApplyOwnedResponseHeaderCheck", Apply)
    monkeypatch.setattr(native_response_header_workflow, "ReplayOwnedResponseHeaderCheck",
                        UnrelatedOperation)
    monkeypatch.setattr(commands, "PlanOwnedResponseCapture", UnrelatedOperation)
    monkeypatch.setattr(commands, "RunOwnedResponseCapture", UnrelatedOperation)
    monkeypatch.setattr(commands, "ReplayOwnedResponse", UnrelatedOperation)

    return state


@pytest.mark.parametrize("flag", ["--receipt", "--target", "--scope", "--owner", "--policy",
                                  "--analysis-reference"])
def test_EachIndependentHeaderInputIsRequiredBeforeAnyOwnerRead(boundary, flag):
    """Approval and selected shell state cannot supply missing receipt or admission inputs."""

    args = Arguments(boundary.root)
    index = args.index(flag)
    del args[index:index + 2]

    with pytest.raises(SystemExit) as caught:
        Main([*args, "--approve-passive-header-check"])

    assert caught.value.code == 2 and not boundary.calls and not boundary.opens, (
        "Missing explicit header inputs must refuse before SDK or workspace/model access."
    )


@pytest.mark.parametrize("extra", [["--plan"], ["--events-json"], ["--timeout", "30"],
    ["--approve-safe-response-capture"], ["--expected-model-revision", "1"],
    ["--raw-headers", "PRIVATE_REJECTED_MARKER"]])
def test_HeaderRouteHasNoPlanEventsRuntimeOrRawSourceOverrides(boundary, extra, capsys):
    """The offline SDK enrollment cannot acquire originals or accept caller source substitutes."""

    with pytest.raises(SystemExit) as caught:
        Main([*Arguments(boundary.root), "--approve-passive-header-check", *extra])

    assert caught.value.code == 2 and not boundary.calls and not boundary.opens, (
        "Unsupported header workflow extensions must refuse before any owning SDK boundary."
    )
    assert "PRIVATE_REJECTED_MARKER" not in capsys.readouterr().err, (
        "Rejected raw material must never be reflected into diagnostic output."
    )


def test_MissingPassiveOptInRefusesWithoutSdkOrStoreReads(boundary, capsys):
    """A selected policy file cannot supply the separate PASSIVE workflow opt-in."""

    assert Main([*Arguments(boundary.root), "--json"]) == 3, (
        "Missing explicit PASSIVE header approval must be an authorization denial."
    )
    assert json.loads(capsys.readouterr().out)["failure"]["code"] == "authorization", (
        "A denied opt-in must remain distinct from invalid configuration and storage failure."
    )
    assert not boundary.calls and not boundary.opens and not boundary.policy_reads, (
        "Default denial must launch no interpretation and read no state or policy."
    )


@pytest.mark.parametrize("url", ["http://localhost:19008/zap-passive/missing",
    "http://127.0.0.1:019008/zap-passive/missing", "http://127.0.0.1:19008/zap-passive/missing?",
    "http://127.0.0.1:19008/zap-passive/../missing"])
def test_OriginalUrlIsValidatedBeforeTargetNormalizationOrStateReads(boundary, url, capsys):
    """A canonical Target must not hide unsupported original receipt selection spelling."""

    assert Main([*Arguments(boundary.root), "--target", url,
                 "--approve-passive-header-check", "--json"]) == 2, (
        "Invalid original URL spelling must fail before workspace access."
    )
    assert json.loads(capsys.readouterr().out)["failure"]["code"] == "invalid_configuration", (
        "Invalid source selection must not be relabelled as missing workspace storage."
    )
    assert not boundary.calls and not boundary.opens, "Invalid targets must never reach the SDK."


def test_HeaderHandoffUsesCurrentBasesAndFreshExplicitPolicyWithoutRetry(boundary, capsys):
    """Each command selects one pair of original revisions and preserves the SDK result exactly."""

    for model_revision, workspace_revision in ((11, 7), (23, 13)):
        boundary.model_revision, boundary.workspace_revision = model_revision, workspace_revision
        assert Main([*Arguments(boundary.root), "--approve-passive-header-check", "--json"]) == 0, (
            "A mocked completed owner result must preserve its actual CLI success classification."
        )
        assert json.loads(capsys.readouterr().out) == boundary.documents[-1], (
            "Presentation must not rewrite original references or independent ACK fields."
        )
        args, kwargs = boundary.calls[-1]
        assert args[:5] == (boundary.root, "original-scope", RECEIPT,
                            Target(TargetKind.URL, URL), "operator:explicit"), (
            "SDK selection must preserve the exact receipt, source, scope and operator."
        )
        assert kwargs == {"analysis_reference": "analysis:independent",
            "expected_model_revision": model_revision,
            "expected_workspace_revision": workspace_revision,
            "approve_passive_header_check": True}, (
            "The CLI must use its one current original basis, not cached revisions or a retry."
        )

    reader = boundary.calls[-1][0][5]
    first = reader()
    boundary.policy = ImpactPolicy("second-explicit-policy", revision=1)
    assert reader() is boundary.policy and first is not boundary.policy, (
        "The SDK callback must reread the selected policy rather than cache a grant."
    )
    assert boundary.policy_reads == [boundary.root / "current-policy.json"] * 2, (
        "Only the explicitly selected current policy file may be read."
    )
    assert boundary.opens == [(kind, boundary.root) for _ in range(2)
                              for kind in ("workspace", "model")] and len(boundary.calls) == 2, (
        "Each explicit attempt must read each original basis once and call the SDK once."
    )
    assert not boundary.root.exists(), "Mocked CLI units must create no real product workspace."


@pytest.mark.parametrize("state,status", [("already-applied", 0), ("denied", 3),
    ("failed", 4), ("partial", 4), ("unknown", 4)])
def test_HeaderTerminalClassificationPreservesOwnerSummary(boundary, state, status, capsys):
    """Partial or unknown ownership cannot become success or a new hidden Save attempt."""

    boundary.outcome = state
    boundary.failure = None if state == "already-applied" else "revision-conflict"
    actual = Main([*Arguments(boundary.root), "--approve-passive-header-check", "--json"])
    assert actual == status, (
        "The CLI must preserve the owning SDK's closed terminal status classification."
    )
    assert json.loads(capsys.readouterr().out) == boundary.documents[-1], (
        "Failed and partial metadata, original IDs and ACK uncertainty must remain unchanged."
    )
    assert len(boundary.calls) == 1, "A non-success result must never trigger a retry."


@pytest.mark.parametrize("error,code,status", [
    (NativeResponseHeaderError("PRIVATE_REJECTED_MARKER"), "invalid_configuration", 2),
    (PolicyDeniedError(PolicyDenialReason.PROVIDER_DENIED), "authorization", 3),
    (OSError("PRIVATE_REJECTED_MARKER"), "storage", 4)])
def test_OnlySafeFailureClassesReachHeaderPresentation(boundary, error, code, status, capsys):
    """Owner/configuration exceptions cannot expose paths, rejected source bytes or raw messages."""

    boundary.exception = error
    actual = Main([*Arguments(boundary.root), "--approve-passive-header-check", "--json"])
    assert actual == status, (
        "The CLI must distinguish configuration, authorization and storage refusal."
    )
    text = capsys.readouterr().out
    assert json.loads(text)["failure"]["code"] == code and "PRIVATE_REJECTED_MARKER" not in text, (
        "Only fixed safe failure metadata may leave the CLI boundary."
    )
    assert len(boundary.calls) == 1, "A raised owner failure must never repeat the analysis."


@pytest.mark.parametrize("action", ["check-headers", "replay-headers"])
def test_ShellUsesTheSameExplicitHeaderRouteAndProtectsHistory(boundary, action, monkeypatch):
    """Shell context supplies no authority; both routes use the same foreground dispatcher."""

    calls = []
    document = {"state": "verified", "model_revision": 11, "workspace_revision": 7,
                "assessment_reference": ASSESSMENT}

    def Replay(root, reference):
        """Record a historical selection without consulting policy, runtime or writable owners."""

        calls.append((root, reference))

        return SimpleNamespace(ToDict=lambda: document)

    monkeypatch.setattr(native_response_header_workflow, "ReplayOwnedResponseHeaderCheck", Replay)
    args = Arguments(boundary.root)[1:] + ["--approve-passive-header-check"] if (
        action == "check-headers") else [action, str(boundary.root), "--assessment", ASSESSMENT]
    output = io.StringIO()
    shell = InteractiveShell(stdout=output)
    before = shell.State
    shell.onecmd("response " + shlex.join([*args, "--json"]))
    expected = boundary.documents[-1] if action == "check-headers" else document
    assert json.loads(output.getvalue()) == expected, (
        "Foreground shell presentation must preserve the same original safe SDK document."
    )
    assert shell.State == before and shell.lastcmd == "response", (
        "Header commands must not infer authority from shell context or retain selected inputs."
    )
    assert calls == ([] if action == "check-headers" else [(boundary.root, ASSESSMENT)]), (
        "Historical header replay takes only workspace and the actual assessment reference."
    )


@pytest.mark.parametrize("extra", [["--receipt", RECEIPT], ["--scope", "scope"],
    ["--owner", "operator"], ["--policy", "policy.json"], ["--target", URL],
    ["--approve-passive-header-check"], ["--plan"], ["--events-json"]])
def test_HistoricalHeaderReplayRejectsCurrentInputsBeforeAnySdkCall(boundary, extra):
    """An old assessment cannot become a new interpretation or manufacture current admission."""

    with pytest.raises(SystemExit) as caught:
        Main(["response", "replay-headers", str(boundary.root), "--assessment", ASSESSMENT, *extra])

    assert caught.value.code == 2 and not boundary.calls and not boundary.opens, (
        "Historical replay must reject current authority, capture and presentation extensions."
    )


def test_UnknownHeaderReplayIsIntegrityFailureWithoutRawDiagnostics(boundary, monkeypatch, capsys):
    """Replay refusal must not invent an assessment, original job or missing acknowledgement."""

    def Refuse(root, reference):
        """Model a closed historical integrity refusal, without reading any real receipt."""

        raise NativeResponseHeaderError("PRIVATE_REJECTED_MARKER")

    monkeypatch.setattr(native_response_header_workflow, "ReplayOwnedResponseHeaderCheck", Refuse)
    assert Main(["response", "replay-headers", str(boundary.root), "--assessment", ASSESSMENT,
                 "--json"]) == 4, "Unknown original assessment must remain an integrity failure."
    text = capsys.readouterr().out
    assert json.loads(text)["failure"]["code"] == "integrity" and (
        "PRIVATE_REJECTED_MARKER" not in text and "original_job_id" not in text
    ), "Historical refusal exposes no rejected material or invented original attribution."
    assert not boundary.opens, "The CLI itself must open no writable current store during replay."


def test_HumanHeaderPresentationNamesAssessmentWithoutCreatingEvents(boundary, capsys):
    """Human output describes the offline action and actual revisions, never response bytes."""

    assert Main([*Arguments(boundary.root), "--approve-passive-header-check"]) == 0, (
        "The human route must preserve the mocked owning summary status."
    )
    assert capsys.readouterr().out == (
        "Response check-headers: completed; model revision 11; workspace revision 7\n"
    ), "Human presentation must stay bounded and distinguish interpretation from capture."


@pytest.mark.parametrize("action,expected", [("check-headers", "--approve-passive-header-check"),
    ("replay-headers", "--assessment")])
def test_HeaderHelpNeedsNoWorkspaceOrOriginals(boundary, action, expected, capsys):
    """Installed grammar remains discoverable without contacting a target or requiring a receipt."""

    with pytest.raises(SystemExit) as caught:
        Main(["response", action, "--help"])

    text = capsys.readouterr().out
    assert caught.value.code == 0 and expected in text and "--plan" not in text, (
        "Help must describe only the implemented offline header action and its actual inputs."
    )
    assert not boundary.calls and not boundary.opens, "Help must remain entirely nonexecuting."


@pytest.mark.parametrize("mode", ["plan", "json", "events", "human"])
def test_LegacyCapturePresentationStillDelegatesOnlyToItsOwnSdk(
    boundary, mode, monkeypatch, capsys,
):
    """Adding offline actions must preserve original capture policy, event and approval handoffs."""

    calls = []
    document = {"state": "planned" if mode == "plan" else "cancelled",
                "model_revision": 11, "workspace_revision": 7}

    def Plan(*args):
        """Record the unchanged descriptive capture contract without creating an invocation."""

        calls.append((args, {}))
        assert args[4]() is boundary.policy, "Legacy planning retains its fresh policy callback."

        return SimpleNamespace(ToDict=lambda: document)

    async def Capture(*args, **kwargs):
        """Emit one mocked original heartbeat and terminal value without running a real job."""

        calls.append((args, kwargs))
        kwargs["on_event"](JobEvent("job:mocked", 0, JobEventKind.HEARTBEAT, None))
        assert args[4]() is boundary.policy, "Legacy capture retains its selected policy reader."

        return SimpleNamespace(ToDict=lambda: document, ExitCode=lambda: 130)

    monkeypatch.setattr(commands, "PlanOwnedResponseCapture", Plan)
    monkeypatch.setattr(commands, "RunOwnedResponseCapture", Capture)
    args = ["response", "capture", str(boundary.root), "--target", URL, "--scope",
            "original-scope", "--owner", "operator:explicit", "--policy",
            str(boundary.root / "current-policy.json")]
    extra = ["--plan"] if mode == "plan" else ["--approve-safe-response-capture"]

    if mode in ("plan", "json"):
        extra.append("--json")

    elif mode == "events":
        extra.append("--events-json")

    assert Main([*args, *extra]) == (0 if mode == "plan" else 130), (
        "Legacy capture keeps its actual original plan/cancellation exit classification."
    )
    text = capsys.readouterr().out

    if mode == "events":
        rows = [json.loads(line) for line in text.splitlines()]
        assert rows[0]["type"] == "event" and rows[-1] == {
            "schema_version": 1, "type": "summary", "summary": document
        }, "Only original capture retains its existing structured event stream."

    elif mode in ("plan", "json"):
        assert json.loads(text) == document, "Legacy capture summary fields remain unchanged."

    else:
        assert "Response capture: cancelled" in text, "Human capture status remains truthful."

    assert len(calls) == 1 and not boundary.calls and not boundary.opens, (
        "Legacy dispatch must not gain a header SDK call or new state read."
    )


def test_LegacyReceiptReplayStillUsesOnlyItsOriginalReadOnlyOwner(boundary, monkeypatch, capsys):
    """Receipt replay remains distinct from native assessment replay and takes no authority."""

    calls = []
    document = {"state": "verified", "model_revision": 11, "workspace_revision": 7}

    def Replay(root, receipt):
        """Record the original historical handoff without loading actual custody or authority."""

        calls.append((root, receipt))

        return SimpleNamespace(ToDict=lambda: document)

    monkeypatch.setattr(commands, "ReplayOwnedResponse", Replay)
    assert Main(["response", "replay", str(boundary.root), "--receipt", RECEIPT, "--json"]) == 0, (
        "Original receipt replay must keep its acknowledged historical success status."
    )
    assert json.loads(capsys.readouterr().out) == document and calls == [
        (boundary.root, RECEIPT)
    ], (
        "Original receipt replay must not be redirected to an interpretation or replacement owner."
    )
    assert not boundary.opens and not boundary.calls, (
        "Historical replay gains no current state reads."
    )
