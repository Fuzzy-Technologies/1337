# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real owned Workbench demo execution, durable export, interruption and teardown evidence."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
from dataclasses import replace
from io import StringIO
from pathlib import Path
from threading import Event, Thread

import pytest

from fuzzy1337 import demo
from fuzzy1337.cli import Main
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.report_commands import ReportFailure
from fuzzy1337.scope import AuthorizationState, LocalScopeStore, ScopeAuthorization
from fuzzy1337.shell import InteractiveShell
from fuzzy1337.workspace import LocalWorkspaceStore


def Files(root: Path) -> dict[str, bytes]:
    """Capture exact retained material bytes for no-clobber and offline-reopen assertions."""

    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}


def AssertStopped(root: Path) -> None:
    """Independently reject a new connection to the previously bound command-owned port."""

    receipt = json.loads((root / "target.json").read_bytes())
    assert receipt["teardown_completed"] is True, "The owned service must confirm teardown."

    with socket.socket() as probe:
        probe.settimeout(0.1)
        assert probe.connect_ex(("127.0.0.1", receipt["port"])) != 0, (
            "The owned target's listening socket must be closed after the command."
        )


def ValidateSuccess(root: Path, outcome: dict) -> None:
    """Verify actual acquisitions, ordered events and reports from the same saved model."""

    assert outcome["state"] == "completed" and outcome["exit_status"] == 0, (
        "A successful assembled demo must report completion and status zero."
    )
    assert outcome["target_teardown_completed"] is True, (
        "Successful completion requires confirmed owned target cleanup."
    )
    assert json.loads((root / "demo-summary.json").read_bytes()) == outcome, (
        "Retained final summary must match the terminal demo outcome."
    )
    workspace_root = root / "workspace"
    workspace = LocalWorkspaceStore(workspace_root).Open()
    model = LocalModelStore(workspace_root).Open()
    scan = json.loads((root / "scan-summary.json").read_bytes())
    assert scan["state"] == "completed" and scan["model_revision"] == model.revision == 3, (
        "The completed scan must reopen the exact persisted third revision."
    )
    assert len(model.Objects(ObjectKind.HOST)) == 1 and len(model.Objects(ObjectKind.PORT)) == 1, (
        "Actual discovery must retain one host and one listening port."
    )
    assert len(model.Objects(ObjectKind.SERVICE)) == 1, (
        "The three endpoint requests must share one actual service."
    )
    assert len(model.Objects(ObjectKind.ENDPOINT)) == 3, (
        "Each explicitly selected route must produce an actual endpoint."
    )
    assert not model.Objects(ObjectKind.FINDING), "Endpoint discovery must not invent findings."
    assert len(workspace.job_references) == 1 and len(workspace.evidence_record_references) == 3, (
        "The saved workspace must retain one real job and three acquisitions."
    )
    stream = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
    events = [line["event"] for line in stream if line["type"] == "event"]
    assert events == scan["events"] and stream[-1]["summary"] == scan, (
        "The exact journal events and terminal summary must remain unchanged."
    )
    assert [event["sequence"] for event in events] == list(range(len(events))), (
        "Actual job events must retain a contiguous ordered sequence."
    )
    assert any(event["kind"] == "model_delta" for event in events), (
        "The workflow must publish at least one real saved model delta."
    )
    assert scan["first_model_update_seconds"] is not None, (
        "Useful discovery must record an actual first-update measurement."
    )
    index = json.loads((root / "evidence-index.json").read_bytes())
    assert index["verified_acquisitions"] == 3, (
        "The evidence index must independently verify all three acquisitions."
    )
    assert {record["evidence_id"] for record in index["records"]} == set(
        workspace.evidence_record_references
    ), (
        "Index identities must match the actual saved acquisition references."
    )

    for item in index["records"]:
        reference = item["record"]["reference"]
        raw = (root / item["material_path"]).read_bytes()
        assert len(raw) == reference["size_bytes"], (
            "Indexed material must have its exact acquired byte length."
        )
        assert hashlib.sha256(raw).hexdigest() == reference["sha256"], (
            "Indexed material must independently match its acquired digest."
        )
        actual = json.loads(raw)
        assert actual["status"] in {200, 204, 302}, "The index must point at real response status."

    report = json.loads((root / "reports" / "model.json").read_bytes())
    assert report["model"] == model.ToDict(), "Report export must preserve the exact saved model."
    assert report["summary"]["findings"] == 0 and report["scan_completeness"] == "not-assessed", (
        "Status-only export cannot invent findings or a complete-scan claim."
    )
    sarif = json.loads((root / "reports" / "model.sarif").read_bytes())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"] == [], (
        "SARIF must retain its actual version and empty discovery findings."
    )
    receipts = [command["outcome"] for command in outcome["commands"]
                if command["command"] == "report.export"]
    assert len(receipts) == 2 and all(receipt["output_published"] for receipt in receipts), (
        "Both actual export receipts must confirm their complete publication."
    )
    assert receipts[0]["snapshot_sha256"] == receipts[1]["snapshot_sha256"], (
        "JSON and SARIF must project the same exact saved-model snapshot."
    )
    target = json.loads((root / "target.json").read_bytes())
    assert [request["path"] for request in target["requests"]] == list(demo.DEMO_ROUTES), (
        "The owned target must receive only the three explicit selected routes."
    )
    assert [request["status"] for request in target["requests"]] == [200, 204, 302], (
        "Actual synthetic responses must retain the expected status sequence."
    )
    AssertStopped(root)


def test_SdkDemoUsesRealSafeWorkflowAndSavedWorkspaceExports(tmp_path, capsys) -> None:
    """Run the assembled SDK composition and independently reopen after the target is stopped."""

    root = tmp_path / "owned demo"
    output = StringIO()
    assert demo.RunLocalDemo(root, output, approve_safe_http=True, json_output=True) == 0, (
        "The real approved SDK demo must complete its full product workflow."
    )
    outcome = json.loads(output.getvalue())
    ValidateSuccess(root, outcome)
    before = Files(root)
    assert Main(["workspace", "open", str(root / "workspace"), "--json"]) == 0, (
        "Independent workspace reopening must succeed after target teardown."
    )
    reopened = json.loads(capsys.readouterr().out)
    assert reopened["verified_evidence_records"] == 3, (
        "Offline reopening must verify all three retained acquisitions."
    )
    assert reopened["model_revision"] == 3, (
        "Offline reopening must preserve the actual saved third revision."
    )
    assert Files(root) == before, "Offline reopen must preserve every saved material byte."


def test_HumanDemoDisplaysActualLiveUpdatesAndRetainedOutput(tmp_path) -> None:
    """Default presentation exposes real saved-model updates followed by the retained root."""

    root = tmp_path / "human-demo"
    output = StringIO()
    assert demo.RunLocalDemo(root, output, approve_safe_http=True) == 0, (
        "The actual human-output demo must complete successfully."
    )
    assert "model_delta" in output.getvalue() and "Local demo completed" in output.getvalue(), (
        "Human output must show real saved deltas and terminal completion."
    )
    assert str(root) in output.getvalue(), (
        "Human output must identify the actual retained output root."
    )
    AssertStopped(root)


def test_ForegroundShellDemoPreservesContextHistoryAndReopensActualSavedModel(tmp_path) -> None:
    """Run the same product demo in the shell with explicit approval and manual model inspection."""

    root = tmp_path / "shell demo with spaces"
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.onecmd("lens dfir")
    shell.onecmd("view updates")
    shell.onecmd("select object:retained")
    context = shell.State

    def Execute(arguments: list[str]) -> str:
        """Run one actual foreground action and capture its own presentation without replay."""

        output.seek(0)
        output.truncate()
        assert not shell.onecmd(shlex.join(arguments)), "Product demo must keep the shell alive."

        return output.getvalue()

    denied = Execute(["demo", "local", str(root), "--json"])
    assert json.loads(denied.splitlines()[0])["state"] == "denied", (
        "Missing foreground approval must produce an explicit denied outcome."
    )
    assert denied.splitlines()[-1] == "Command exit status: 3", (
        "The shell must retain the actual approval-denial exit status."
    )
    assert not root.exists(), "Shell context never supplies missing explicit SAFE approval."
    approved = Execute(["demo", "local", str(root), "--approve-safe-http", "--json"])
    ValidateSuccess(root, json.loads(approved))
    assert shell.State == context, "Foreground demo must preserve lens, selection and view."
    assert shell.lastcmd == "demo", "Replay must not retain the root or approval arguments."
    assert shell._model is None, "Demo must not implicitly replace the shell's selected model."
    before = Files(root)
    output.seek(0)
    output.truncate()
    assert not shell.onecmd(""), "Empty-line repeat must keep the Workbench running."
    assert "Command exit status: 2" in output.getvalue(), (
        "Sanitized empty-line replay must reject missing demo arguments."
    )
    assert shell.lastcmd == "demo" and Files(root) == before, (
        "Replay must preserve the protected namespace and all retained bytes."
    )
    Execute(["history", "demo"])
    assert output.getvalue().splitlines() == ["demo", "demo", "demo"], (
        "History must retain only demo namespaces for the three dispatches."
    )
    assert not shell.onecmd("model " + str(root / "workspace")), (
        "Explicit model inspection must keep the foreground shell running."
    )
    view = json.loads(Execute(["view", "model", "--json"]))
    assert view["revision"] == 3, "Explicit model reopen must show the actual saved demo revision."
    assert shell.State.lens == "dfir" and shell.State.selected_object == "object:retained", (
        "Explicit inspection must preserve the selected lens and object."
    )
    assert Files(root) == before, "Inspection must preserve saved model/evidence/report bytes."


def test_ModuleSubprocessExposesRealDemoAndRejectsExistingOutput(tmp_path) -> None:
    """Process CLI dispatch executes the current candidate and retains all bytes on replay."""

    root = tmp_path / "process-demo"
    argv = [sys.executable, "-m", "fuzzy1337", "demo", "local", str(root),
            "--approve-safe-http", "--json"]
    completed = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=20)
    assert completed.returncode == 0, completed.stderr + completed.stdout
    ValidateSuccess(root, json.loads(completed.stdout))
    before = Files(root)
    repeated = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=10)
    assert repeated.returncode == 2, "Existing output must fail before acquiring a new target."
    assert json.loads(repeated.stdout)["phase"] == "configuration", (
        "Existing-root replay must fail before resource acquisition."
    )
    assert Files(root) == before, "Replaying the demo command must not overwrite prior results."


def test_ActualPolicyDenialStopsTheOwnedTargetWithoutAcquisition(tmp_path, monkeypatch) -> None:
    """Revoked current consent cannot be replaced by the demo's initial approval."""

    original = demo.RunCommands

    def Revoke(command, arguments, output, **kwargs):
        """Use actual scope persistence to revoke the recorded grant before the real scan begins."""

        if command == "scan":
            store = LocalScopeStore(Path(arguments[1]))
            snapshot = store.Open(demo.DEMO_SCOPE_ID)
            store.Save(replace(snapshot, authorization=ScopeAuthorization(
                AuthorizationState.REVOKED,
            )))

        return original(command, arguments, output, **kwargs)

    monkeypatch.setattr(demo, "RunCommands", Revoke)
    root = tmp_path / "denied-demo"
    output = StringIO()
    assert demo.RunLocalDemo(root, output, approve_safe_http=True, json_output=True) == 3, (
        "Revoked current consent must preserve actual denial status three."
    )
    outcome = json.loads(output.getvalue())
    assert outcome["state"] == "denied" and outcome["phase"] == "scan", (
        "The demo must attribute revoked consent denial to the scan phase."
    )
    scan = json.loads((root / "scan-summary.json").read_bytes())
    assert scan["state"] == "failed" and scan["job"]["failure"]["code"] == "authorization", (
        "The actual owning job must preserve its authorization failure."
    )
    assert not LocalWorkspaceStore(root / "workspace").Open().evidence_record_references, (
        "Denied execution cannot retain fabricated acquisition references."
    )
    assert LocalModelStore(root / "workspace").Open().revision == 0, (
        "Denied execution must leave the authoritative model empty."
    )
    assert json.loads((root / "target.json").read_bytes())["requests"] == [], (
        "Revoked scope must prevent every target HTTP request."
    )
    assert not list((root / "reports").iterdir()), (
        "A denied scan must not publish derived reports."
    )
    AssertStopped(root)


def test_ActualPreflightStorageFailureKeepsItsEnvelopeAndStopsTarget(tmp_path, monkeypatch) -> None:
    """Missing authoritative scope before job startup remains an ordinary product storage error."""

    original = demo.RunCommands

    def RemoveScope(command, arguments, output, **kwargs):
        """Remove only the command-owned synthetic scope before the actual scanner reopens it."""

        if command == "scan":
            (Path(arguments[1]) / "state" / "scopes" / (demo.DEMO_SCOPE_ID + ".json")).unlink()

        return original(command, arguments, output, **kwargs)

    monkeypatch.setattr(demo, "RunCommands", RemoveScope)
    root = tmp_path / "scan-preflight-failure"
    output = StringIO()
    assert demo.RunLocalDemo(root, output, approve_safe_http=True, json_output=True) == 4, (
        "Actual scope-read failure must preserve storage failure status four."
    )
    outcome = json.loads(output.getvalue())
    assert outcome["state"] == "failed" and outcome["phase"] == "scan", (
        "A missing scope must remain a failed scan phase."
    )
    failure = json.loads((root / "scan-failure.json").read_bytes())
    assert failure["failure"]["code"] == "storage" and "job" not in failure, (
        "Preflight storage failure must not fabricate an owning job summary."
    )
    assert not (root / "scan-summary.json").exists(), (
        "Preflight failure cannot publish an invented terminal scan summary."
    )
    assert not list((root / "reports").iterdir()), (
        "Preflight storage failure must prevent every report export."
    )
    AssertStopped(root)


def test_ExportFailurePreservesActualPublishedFileAndFailureReceipt(tmp_path, monkeypatch) -> None:
    """A real published report with a later owner acknowledgement failure prevents demo success."""

    from fuzzy1337 import report_commands

    original = report_commands.PublishReport

    def PublishThenFail(destination, payload) -> None:
        """Commit report bytes before injecting the owner's post-publication failure."""

        original(destination, payload)

        raise ReportFailure("publication", published=True)

    monkeypatch.setattr(report_commands, "PublishReport", PublishThenFail)
    root = tmp_path / "export-failure"
    output = StringIO()
    assert demo.RunLocalDemo(root, output, approve_safe_http=True, json_output=True) == 4, (
        "Post-publication export failure must prevent whole-demo success."
    )
    outcome = json.loads(output.getvalue())
    assert outcome["state"] == "failed" and outcome["phase"] == "export", (
        "A lost report acknowledgement must remain an export failure."
    )
    assert "reports/model.json" in outcome["artifacts"], (
        "Confirmed report publication must retain its material reference."
    )
    receipt = json.loads((root / "reports" / "json-export.json").read_bytes())
    assert receipt["status"] == "failed" and receipt["output_published"] is True, (
        "The report receipt must preserve failed but published truth."
    )
    assert json.loads((root / "reports" / "model.json").read_bytes())["model_revision"] == 3, (
        "The already-published report must retain the actual saved revision."
    )
    assert not (root / "reports" / "model.sarif").exists(), (
        "A failed first export must not start the next format export."
    )
    assert LocalModelStore(root / "workspace").Open().revision == 3, (
        "An export failure must preserve the acquired authoritative model."
    )
    AssertStopped(root)


def test_FailedExportCannotClobberAConcurrentForeignOutput(tmp_path, monkeypatch) -> None:
    """Existing report output remains untouched and the failure retains the acquired workspace."""

    original = demo.RunReportCommands

    def ForeignOutput(arguments, output, **kwargs):
        """Create another writer's output immediately before the actual exporter validates it."""

        Path(arguments[-1]).write_bytes(b"foreign-report-bytes")

        return original(arguments, output, **kwargs)

    monkeypatch.setattr(demo, "RunReportCommands", ForeignOutput)
    root = tmp_path / "report-race"
    output = StringIO()
    assert demo.RunLocalDemo(root, output, approve_safe_http=True, json_output=True) == 2, (
        "A competing report output must retain configuration status two."
    )
    outcome = json.loads(output.getvalue())
    assert outcome["state"] == "failed" and outcome["phase"] == "export", (
        "A competing output must remain an explicit export failure."
    )
    assert (root / "reports" / "model.json").read_bytes() == b"foreign-report-bytes", (
        "Report publication must never overwrite the other writer bytes."
    )
    assert "reports/model.json" not in outcome["artifacts"], (
        "Foreign output must not be claimed as a demo-owned artifact."
    )
    assert LocalModelStore(root / "workspace").Open().revision == 3, (
        "No-clobber export failure must preserve the actual saved model."
    )
    AssertStopped(root)


def test_TargetTeardownClosesAContinuingPartialHeaderBeforeShutdown() -> None:
    """An idle-deadline-renewing local client cannot hold the owning service thread indefinitely."""

    target = demo.OwnedDemoTarget()
    target.Start()
    client = socket.create_connection(("127.0.0.1", target.port), timeout=1)
    client.sendall(b"GET / HTTP/1.0\r\nX-Synthetic: ")
    stop = Event()
    finished = Event()
    errors = []

    def ContinueHeader() -> None:
        """Continue partial framing until lifecycle cleanup closes the peer."""

        while not stop.wait(0.05):
            try:
                client.sendall(b"a")

            except OSError:
                return

    def CloseTarget() -> None:
        """Observe teardown completion before the continuing client stops."""

        try:
            target.Close()

        except Exception as error:
            errors.append(error)

        finally:
            finished.set()

    writer = Thread(target=ContinueHeader, daemon=True)
    closer = Thread(target=CloseTarget, daemon=True)

    try:
        deadline = time.monotonic() + 1

        while not target.connections and time.monotonic() < deadline:
            time.sleep(0.01)

        assert target.connections, "The actual service must accept the owned regression client."
        writer.start()
        closer.start()
        assert finished.wait(timeout=1), "Teardown must close an active partial-header client."
        assert not errors and target.stopped, (
            "Continuing partial framing must still permit successful cleanup."
        )
        assert target.thread is not None and not target.thread.is_alive(), (
            "The target service thread must be completely reaped after cleanup."
        )

    finally:
        stop.set()
        client.close()

        if writer.ident is not None:
            writer.join(timeout=2)

        if closer.ident is not None:
            closer.join(timeout=2)

        target.Close()


def test_LateTeardownFailureCannotBecomeDemoSuccess(tmp_path, monkeypatch) -> None:
    """Completed scanning and published reports do not override an explicit cleanup failure."""

    original = demo.OwnedDemoTarget.Close

    def CloseThenFail(self) -> None:
        """Reap the actual target before injecting a lost successful-cleanup acknowledgement."""

        original(self)

        raise OSError("synthetic-cleanup-failure")

    monkeypatch.setattr(demo.OwnedDemoTarget, "Close", CloseThenFail)
    root = tmp_path / "teardown-failure"
    output = StringIO()
    assert demo.RunLocalDemo(root, output, approve_safe_http=True, json_output=True) == 4, (
        "Late target cleanup failure must prevent demo success."
    )
    outcome = json.loads(output.getvalue())
    assert outcome["state"] == "failed" and outcome["phase"] == "teardown", (
        "Late cleanup failure must retain its actual teardown phase."
    )
    assert outcome["target_teardown_completed"] is False, (
        "Lost cleanup acknowledgement cannot confirm completed teardown."
    )
    assert "reports/model.json" in outcome["artifacts"], (
        "Late cleanup failure must preserve already-published reports."
    )
    assert "synthetic-cleanup-failure" not in output.getvalue(), (
        "Raw cleanup exception text must remain outside terminal output."
    )
    AssertStopped(root)


@pytest.mark.skipif(os.name != "posix", reason="SIGINT subprocess ownership is POSIX-specific")
def test_InterruptAfterActualFirstModelDeltaRetainsPartialStateAndStopsTarget(tmp_path) -> None:
    """Interrupt the real CLI while native discovery is active, preserving useful committed work."""

    root = tmp_path / "interrupted-demo"
    process = subprocess.Popen(
        [sys.executable, "-m", "fuzzy1337", "demo", "local", str(root),
         "--approve-safe-http", "--json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )

    try:
        deadline = time.monotonic() + 10
        observed = False

        while time.monotonic() < deadline and process.poll() is None:
            journal = root / "events.jsonl"

            if journal.exists():
                lines = journal.read_text(encoding="utf-8").splitlines()

                if any('"kind": "model_delta"' in line for line in lines):
                    observed = True

                    break

            time.sleep(0.01)

        assert observed, "The real worker must save its first model delta before interruption."
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 130, stderr + stdout
        outcome = json.loads(stdout)
        assert outcome["state"] == "cancelled" and outcome["phase"] == "scan", (
            "Actual SIGINT must preserve a cancelled scan-phase outcome."
        )
        assert outcome["target_teardown_completed"] is True, (
            "Interrupted execution must still confirm owned target teardown."
        )
        assert LocalModelStore(root / "workspace").Open().revision >= 1, (
            "SIGINT must preserve at least the first actually saved model delta."
        )
        assert LocalWorkspaceStore(root / "workspace").Open().evidence_record_references, (
            "SIGINT must retain the acquisitions supporting saved model state."
        )
        assert not (root / "reports" / "model.json").exists(), (
            "Cancelled discovery must not publish a fabricated successful report."
        )
        AssertStopped(root)

    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
