# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real owned Workbench demo execution, durable export, interruption and teardown evidence."""

from __future__ import annotations

import hashlib
import json
import os
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

    assert outcome["state"] == "completed" and outcome["exit_status"] == 0
    assert outcome["target_teardown_completed"] is True
    assert json.loads((root / "demo-summary.json").read_bytes()) == outcome
    workspace_root = root / "workspace"
    workspace = LocalWorkspaceStore(workspace_root).Open()
    model = LocalModelStore(workspace_root).Open()
    scan = json.loads((root / "scan-summary.json").read_bytes())
    assert scan["state"] == "completed" and scan["model_revision"] == model.revision == 3
    assert len(model.Objects(ObjectKind.HOST)) == 1 and len(model.Objects(ObjectKind.PORT)) == 1
    assert len(model.Objects(ObjectKind.SERVICE)) == 1
    assert len(model.Objects(ObjectKind.ENDPOINT)) == 3
    assert not model.Objects(ObjectKind.FINDING), "Endpoint discovery must not invent findings."
    assert len(workspace.job_references) == 1 and len(workspace.evidence_record_references) == 3
    stream = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
    events = [line["event"] for line in stream if line["type"] == "event"]
    assert events == scan["events"] and stream[-1]["summary"] == scan
    assert [event["sequence"] for event in events] == list(range(len(events)))
    assert any(event["kind"] == "model_delta" for event in events)
    assert scan["first_model_update_seconds"] is not None
    index = json.loads((root / "evidence-index.json").read_bytes())
    assert index["verified_acquisitions"] == 3
    assert {record["evidence_id"] for record in index["records"]} == set(
        workspace.evidence_record_references
    )

    for item in index["records"]:
        reference = item["record"]["reference"]
        raw = (root / item["material_path"]).read_bytes()
        assert len(raw) == reference["size_bytes"]
        assert hashlib.sha256(raw).hexdigest() == reference["sha256"]
        actual = json.loads(raw)
        assert actual["status"] in {200, 204, 302}, "The index must point at real response status."

    report = json.loads((root / "reports" / "model.json").read_bytes())
    assert report["model"] == model.ToDict(), "Report export must preserve the exact saved model."
    assert report["summary"]["findings"] == 0 and report["scan_completeness"] == "not-assessed"
    sarif = json.loads((root / "reports" / "model.sarif").read_bytes())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"] == []
    receipts = [command["outcome"] for command in outcome["commands"]
                if command["command"] == "report.export"]
    assert len(receipts) == 2 and all(receipt["output_published"] for receipt in receipts)
    assert receipts[0]["snapshot_sha256"] == receipts[1]["snapshot_sha256"]
    target = json.loads((root / "target.json").read_bytes())
    assert [request["path"] for request in target["requests"]] == list(demo.DEMO_ROUTES)
    assert [request["status"] for request in target["requests"]] == [200, 204, 302]
    AssertStopped(root)


def test_SdkDemoUsesRealSafeWorkflowAndSavedWorkspaceExports(tmp_path, capsys) -> None:
    """Run the assembled SDK composition and independently reopen after the target is stopped."""

    root = tmp_path / "owned demo"
    output = StringIO()
    assert demo.RunLocalDemo(root, output, approve_safe_http=True, json_output=True) == 0
    outcome = json.loads(output.getvalue())
    ValidateSuccess(root, outcome)
    before = Files(root)
    assert Main(["workspace", "open", str(root / "workspace"), "--json"]) == 0
    reopened = json.loads(capsys.readouterr().out)
    assert reopened["verified_evidence_records"] == 3
    assert reopened["model_revision"] == 3
    assert Files(root) == before, "Offline reopen must preserve every saved material byte."


def test_HumanDemoDisplaysActualLiveUpdatesAndRetainedOutput(tmp_path) -> None:
    """Default presentation exposes real saved-model updates followed by the retained root."""

    root = tmp_path / "human-demo"
    output = StringIO()
    assert demo.RunLocalDemo(root, output, approve_safe_http=True) == 0
    assert "model_delta" in output.getvalue() and "Local demo completed" in output.getvalue()
    assert str(root) in output.getvalue()
    AssertStopped(root)


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
    assert json.loads(repeated.stdout)["phase"] == "configuration"
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
    assert demo.RunLocalDemo(root, output, approve_safe_http=True, json_output=True) == 3
    outcome = json.loads(output.getvalue())
    assert outcome["state"] == "denied" and outcome["phase"] == "scan"
    scan = json.loads((root / "scan-summary.json").read_bytes())
    assert scan["state"] == "failed" and scan["job"]["failure"]["code"] == "authorization"
    assert not LocalWorkspaceStore(root / "workspace").Open().evidence_record_references
    assert LocalModelStore(root / "workspace").Open().revision == 0
    assert json.loads((root / "target.json").read_bytes())["requests"] == []
    assert not list((root / "reports").iterdir())
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
    assert demo.RunLocalDemo(root, output, approve_safe_http=True, json_output=True) == 4
    outcome = json.loads(output.getvalue())
    assert outcome["state"] == "failed" and outcome["phase"] == "scan"
    failure = json.loads((root / "scan-failure.json").read_bytes())
    assert failure["failure"]["code"] == "storage" and "job" not in failure
    assert not (root / "scan-summary.json").exists()
    assert not list((root / "reports").iterdir())
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
    assert demo.RunLocalDemo(root, output, approve_safe_http=True, json_output=True) == 4
    outcome = json.loads(output.getvalue())
    assert outcome["state"] == "failed" and outcome["phase"] == "export"
    assert "reports/model.json" in outcome["artifacts"]
    receipt = json.loads((root / "reports" / "json-export.json").read_bytes())
    assert receipt["status"] == "failed" and receipt["output_published"] is True
    assert json.loads((root / "reports" / "model.json").read_bytes())["model_revision"] == 3
    assert not (root / "reports" / "model.sarif").exists()
    assert LocalModelStore(root / "workspace").Open().revision == 3
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
    assert demo.RunLocalDemo(root, output, approve_safe_http=True, json_output=True) == 2
    outcome = json.loads(output.getvalue())
    assert outcome["state"] == "failed" and outcome["phase"] == "export"
    assert (root / "reports" / "model.json").read_bytes() == b"foreign-report-bytes"
    assert "reports/model.json" not in outcome["artifacts"]
    assert LocalModelStore(root / "workspace").Open().revision == 3
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
        assert not errors and target.stopped
        assert target.thread is not None and not target.thread.is_alive()

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
    assert demo.RunLocalDemo(root, output, approve_safe_http=True, json_output=True) == 4
    outcome = json.loads(output.getvalue())
    assert outcome["state"] == "failed" and outcome["phase"] == "teardown"
    assert outcome["target_teardown_completed"] is False
    assert "reports/model.json" in outcome["artifacts"]
    assert "synthetic-cleanup-failure" not in output.getvalue()
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
        assert outcome["state"] == "cancelled" and outcome["phase"] == "scan"
        assert outcome["target_teardown_completed"] is True
        assert LocalModelStore(root / "workspace").Open().revision >= 1
        assert LocalWorkspaceStore(root / "workspace").Open().evidence_record_references
        assert not (root / "reports" / "model.json").exists()
        AssertStopped(root)

    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
