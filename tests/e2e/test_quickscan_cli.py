# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real product Quick Scan against a pytest-owned local synthetic HTTP service."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path
from threading import Event, Thread

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from fuzzy1337.cli import Main
from fuzzy1337.discovery import DiscoveryLimits
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.jobs import JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.quickscan import RunQuickScan
from fuzzy1337.scan_commands import RunCommands
from fuzzy1337.scope import Target, TargetKind
from fuzzy1337.workspace import LocalWorkspaceStore


def ValidateSummary(summary: dict) -> None:
    """Validate actual product output against the published strict envelope and job cursor truth."""

    path = Path(__file__).parents[2] / "contracts" / "quick-scan-summary.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(summary)
    assert summary["job"]["state"] == summary["state"], (
        "The workflow envelope and owned job must report the same actual terminal state."
    )
    assert summary["job"]["last_sequence"] == len(summary["events"]) - 1, (
        "The terminal snapshot cursor must cover the exact retained event stream."
    )
    assert summary["object_counts"]["finding"] == 0, (
        "SAFE discovery must preserve the accepted Finding kind without inventing findings."
    )


@pytest.fixture
def local_target() -> Iterator[tuple[str, list[str], Event]]:
    """Own localhost-only startup, deterministic service readiness and complete teardown."""

    requests: list[str] = []
    release = Event()

    class TargetHandler(BaseHTTPRequestHandler):
        """Serve bounded synthetic status and a secret-shaped cookie that must not be retained."""

        def do_GET(self) -> None:
            """Record the request and optionally delay headers for controlled cancellation."""

            requests.append(self.path)

            if self.path == "/slow":
                release.wait(timeout=2)

            self.send_response(302 if self.path == "/redirect" else 204)
            self.send_header("Set-Cookie", "synthetic-cookie-token")
            self.send_header("Location", "/never-followed")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            """Keep target diagnostic output silent without retaining request contents."""

    server = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()

    try:
        yield f"http://127.0.0.1:{server.server_port}", requests, release

    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), "The synthetic target's owning service thread must be reaped."


def Setup(root: Path, urls: tuple[str, ...], capsys, *, expired: bool = False,
          excluded: bool = False, grant: bool = True) -> None:
    """Configure only explicit local endpoints through the actual product CLI."""

    arguments = ["workspace", "create", str(root), "--id", "synthetic", "--name", "Synthetic"]
    assert Main(arguments) == 0, (
        'Configure only explicit local endpoints through the actual product CLI invariant '
        'failed.'
    )
    capsys.readouterr()
    arguments = ["scope", "create", str(root), "--id", "local", "--allow-ip", "127.0.0.1"]

    for url in urls:
        arguments.extend(("--allow-url", url))

    if excluded:
        arguments.extend(("--exclude-url", urls[0]))

    if grant:
        now = datetime.now(UTC)
        arguments.extend((
            "--grant-consent", "--owner", "operator:fixture",
            "--consent-reference", "consent:owned",
            "--valid-from", (now - timedelta(minutes=2)).isoformat(),
            "--valid-until", (now + timedelta(minutes=-1 if expired else 2)).isoformat(),
        ))

    assert Main(arguments) == 0, (
        'Configure only explicit local endpoints through the actual product CLI invariant '
        'failed.'
    )
    capsys.readouterr()


def ScanArguments(root: Path, urls: tuple[str, ...], *, approval: bool = True) -> list[str]:
    """Build an explicit finite product command without deriving authorization from target data."""

    arguments = ["quick", str(root), "--scope", "local", "--owner", "operator:fixture"]

    for url in urls:
        arguments.extend(("--target", url))

    if approval:
        arguments.append("--approve-safe-http")

    return arguments


def test_ProductQuickScanStreamsBeforeContactAndReopensVerifiedDurableState(
    tmp_path: Path, local_target, capsys,
) -> None:
    """Prove the real scope → native → governed jobs → evidence → model → reopen path."""

    base, requests, _ = local_target
    url = base + "/redirect"
    root = tmp_path / "workspace"
    Setup(root, (url,), capsys)
    queued_before_contact: list[bool] = []
    saved_deltas: list[int] = []

    class LiveOutput(StringIO):
        """Observe actual machine events as they arrive, before the terminal summary exists."""

        def Write(self, value: str) -> int:
            """Check immediate status and model durability at the product output boundary."""

            record = json.loads(value)

            if record["type"] == "event":
                event = record["event"]

                if event["kind"] == "state" and event["data"] == "queued":
                    queued_before_contact.append(not requests)

                if event["kind"] == "model_delta":
                    saved_deltas.append(LocalModelStore(root).Open().revision)

            return super().write(value)

        # StringIO's external stream callback keeps its required spelling.
        write = Write

    output = LiveOutput()
    assert RunCommands("scan", [*ScanArguments(root, (url,)), "--events-json"], output) == 0, (
        'Prove the real scope → native → governed jobs → evidence → model → reopen path '
        'invariant failed.'
    )
    records = [json.loads(line) for line in output.getvalue().splitlines()]
    summary = records[-1]["summary"]
    ValidateSummary(summary)
    assert queued_before_contact == [True], "Queued status must precede target contact."
    assert saved_deltas == [1], "Model events must describe already persisted changes."
    assert requests == ["/redirect"], "Native discovery must not follow redirect target data."
    assert summary["state"] == "completed", (
        'Prove the real scope → native → governed jobs → evidence → model → reopen path '
        'invariant failed.'
    )
    assert summary["first_model_update_seconds"] <= summary["first_update_budget_seconds"], (
        'Prove the real scope → native → governed jobs → evidence → model → reopen path '
        'invariant failed.'
    )
    assert summary["object_counts"]["host"] == 1, (
        'Prove the real scope → native → governed jobs → evidence → model → reopen path '
        'invariant failed.'
    )
    assert summary["object_counts"]["port"] == 1, (
        'Prove the real scope → native → governed jobs → evidence → model → reopen path '
        'invariant failed.'
    )
    assert summary["object_counts"]["service"] == 1, (
        'Prove the real scope → native → governed jobs → evidence → model → reopen path '
        'invariant failed.'
    )
    assert summary["object_counts"]["endpoint"] == 1, (
        'Prove the real scope → native → governed jobs → evidence → model → reopen path '
        'invariant failed.'
    )
    events = [record["event"] for record in records[:-1]]
    assert events == summary["events"], "Live and final events must be the same ordered stream."
    assert [event["sequence"] for event in events] == list(range(len(events))), (
        'Prove the real scope → native → governed jobs → evidence → model → reopen path '
        'invariant failed.'
    )
    assert Main(["workspace", "open", str(root), "--json"]) == 0, (
        'Prove the real scope → native → governed jobs → evidence → model → reopen path '
        'invariant failed.'
    )
    reopened = json.loads(capsys.readouterr().out)
    assert reopened["verified_evidence_records"] == 1, (
        'Prove the real scope → native → governed jobs → evidence → model → reopen path '
        'invariant failed.'
    )
    assert reopened["object_counts"] == summary["object_counts"], (
        'Prove the real scope → native → governed jobs → evidence → model → reopen path '
        'invariant failed.'
    )
    assert len(requests) == 1, "Reopen and inspection must never contact the target."
    workspace = LocalWorkspaceStore(root).Open()
    assert len(workspace.object_references) == 4, (
        'Prove the real scope → native → governed jobs → evidence → model → reopen path '
        'invariant failed.'
    )
    evidence = LocalEvidenceStore(root / "evidence")
    assert b"synthetic-cookie-token" not in evidence.Read(workspace.evidence_references[0]), (
        'Prove the real scope → native → governed jobs → evidence → model → reopen path '
        'invariant failed.'
    )
    before = tuple(item.Reference() for item in LocalModelStore(root).Open().objects)
    assert RunCommands("scan", ScanArguments(root, (url,)), StringIO(), json_output=True) == 0, (
        'Prove the real scope → native → governed jobs → evidence → model → reopen path '
        'invariant failed.'
    )
    after = tuple(item.Reference() for item in LocalModelStore(root).Open().objects)
    assert before == after, "Clean repeated scans must reuse every logical object identity."
    assert len(LocalWorkspaceStore(root).Open().evidence_record_references) == 2, (
        'Prove the real scope → native → governed jobs → evidence → model → reopen path '
        'invariant failed.'
    )


@pytest.mark.parametrize("condition", ["unknown", "expired", "excluded", "missing_capability"])
def test_ProductDenialsNeverContactTargetAndRemainMachineReadable(
    tmp_path: Path, local_target, capsys, condition: str,
) -> None:
    """Do not launch a native worker when any explicit authorization boundary is unmet."""

    base, requests, _ = local_target
    root = tmp_path / "workspace"
    url = base + "/"
    Setup(root, (url,), capsys, expired=condition == "expired", excluded=condition == "excluded",
          grant=condition != "unknown")
    output = StringIO()
    arguments = ScanArguments(root, (url,), approval=condition != "missing_capability")
    assert RunCommands("scan", arguments,
                       output, json_output=True) == 3, (
        'Do not launch a native worker when any explicit authorization boundary is unmet '
        'invariant failed.'
    )
    summary = json.loads(output.getvalue())
    ValidateSummary(summary)
    assert summary["state"] == "failed", (
        'Do not launch a native worker when any explicit authorization boundary is unmet '
        'invariant failed.'
    )
    assert summary["job"]["failure"]["code"] == "authorization", (
        'Do not launch a native worker when any explicit authorization boundary is unmet '
        'invariant failed.'
    )
    assert summary["first_model_update_seconds"] is None, (
        'Do not launch a native worker when any explicit authorization boundary is unmet '
        'invariant failed.'
    )
    assert not requests, "Authorization denial must happen before any owned target contact."
    assert not LocalWorkspaceStore(root).Open().evidence_references, (
        'Do not launch a native worker when any explicit authorization boundary is unmet '
        'invariant failed.'
    )


def test_ProductRequestTimeoutRetainsFirstModelAndActualFailureEvidence(
    tmp_path: Path, local_target, capsys,
) -> None:
    """A later endpoint timeout must retain earlier saved state and truthful whole-run failure."""

    base, requests, _ = local_target
    root = tmp_path / "workspace"
    urls = (base + "/", base + "/slow")
    Setup(root, urls, capsys)
    output = StringIO()
    assert RunCommands("scan", [*ScanArguments(root, urls), "--request-timeout", "0.2"],
                       output, json_output=True) == 4, (
        'A later endpoint timeout must retain earlier saved state and truthful whole-run '
        'failure invariant failed.'
    )
    summary = json.loads(output.getvalue())
    ValidateSummary(summary)
    assert summary["state"] == "failed", (
        'A later endpoint timeout must retain earlier saved state and truthful whole-run '
        'failure invariant failed.'
    )
    assert summary["job"]["failure"]["code"] == "timeout", (
        'A later endpoint timeout must retain earlier saved state and truthful whole-run '
        'failure invariant failed.'
    )
    assert summary["model_revision"] == 1, (
        'A later endpoint timeout must retain earlier saved state and truthful whole-run '
        'failure invariant failed.'
    )
    assert summary["object_counts"]["endpoint"] == 1, (
        'A later endpoint timeout must retain earlier saved state and truthful whole-run '
        'failure invariant failed.'
    )
    assert requests == ["/", "/slow"], (
        'A later endpoint timeout must retain earlier saved state and truthful whole-run '
        'failure invariant failed.'
    )
    assert len(summary["job"]["artifacts"]) == 2, "Success and timeout acquisitions must remain."
    assert Main(["workspace", "open", str(root), "--json"]) == 0, (
        'A later endpoint timeout must retain earlier saved state and truthful whole-run '
        'failure invariant failed.'
    )
    assert json.loads(capsys.readouterr().out)["verified_evidence_records"] == 2, (
        'A later endpoint timeout must retain earlier saved state and truthful whole-run '
        'failure invariant failed.'
    )


def test_ProductJobDeadlineAndNativeLaunchErrorRemainFailed(tmp_path, local_target, capsys):
    """Preserve actual total-deadline and connection-error truth through the product interface."""

    base, _, _ = local_target
    root = tmp_path / "workspace"
    urls = (base + "/slow", "http://127.0.0.1:1/")
    Setup(root, urls, capsys)

    for url, extra, failure in (
        (urls[0], ["--timeout", "0.05"], "timeout"),
        (urls[1], [], "provider"),
    ):
        output = StringIO()
        assert RunCommands("scan", [*ScanArguments(root, (url,)), *extra], output,
                           json_output=True) == 4, (
            'Preserve actual total-deadline and connection-error truth through the product '
            'interface invariant failed.'
        )
        summary = json.loads(output.getvalue())
        ValidateSummary(summary)
        assert summary["state"] == "failed", (
            'Preserve actual total-deadline and connection-error truth through the product '
            'interface invariant failed.'
        )
        assert summary["job"]["failure"]["code"] == failure, (
            'Preserve actual total-deadline and connection-error truth through the product '
            'interface invariant failed.'
        )
        assert summary["object_counts"]["endpoint"] == 0, (
            'Preserve actual total-deadline and connection-error truth through the product '
            'interface invariant failed.'
        )


def test_ProductCancellationAwaitsNativeProcessCleanupAndReopensPartialState(
    tmp_path: Path, local_target, capsys,
) -> None:
    """Cancel between useful first update and the second endpoint without losing committed state."""

    base, requests, _ = local_target
    root = tmp_path / "workspace"
    urls = (base + "/", base + "/slow")
    Setup(root, urls, capsys)

    async def Scenario() -> None:
        """Cancel the operator task only when the real second localhost request is observed."""

        task = asyncio.create_task(RunQuickScan(
            root, "local", tuple(Target(TargetKind.URL, url) for url in urls), "operator:fixture",
            approve_safe_http=True, limits=DiscoveryLimits(interval_seconds=0.05),
        ))

        async with asyncio.timeout(5):
            while "/slow" not in requests:
                await asyncio.sleep(0.01)

        task.cancel()
        summary = await task
        ValidateSummary(summary.ToDict())
        assert summary.snapshot.state is JobState.CANCELLED, (
            'Cancel the operator task only when the real second localhost request is '
            'observed invariant failed.'
        )
        assert summary.ExitCode() == 130, (
            'Cancel the operator task only when the real second localhost request is '
            'observed invariant failed.'
        )
        assert summary.model_revision == 1, (
            'Cancel the operator task only when the real second localhost request is '
            'observed invariant failed.'
        )
        assert summary.object_counts, (
            'Cancel the operator task only when the real second localhost request is '
            'observed invariant failed.'
        )
        assert summary.snapshot.artifacts, "Already published first acquisition must be retained."

    asyncio.run(Scenario())
    assert Main(["workspace", "open", str(root), "--json"]) == 0, (
        'Cancel between useful first update and the second endpoint without losing '
        'committed state invariant failed.'
    )
    assert json.loads(capsys.readouterr().out)["object_counts"]["endpoint"] == 1, (
        'Cancel between useful first update and the second endpoint without losing '
        'committed state invariant failed.'
    )


def test_InstalledModuleCommandRunsRealQuickScanWithStructuredSummary(
    tmp_path: Path, local_target, capsys,
) -> None:
    """Exercise actual process CLI dispatch through the installed module entry point."""

    base, requests, _ = local_target
    root = tmp_path / "workspace"
    url = base + "/"
    Setup(root, (url,), capsys)
    result = subprocess.run(
        [sys.executable, "-m", "fuzzy1337", "scan", *ScanArguments(root, (url,)), "--json"],
        capture_output=True, text=True, check=False, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    ValidateSummary(json.loads(result.stdout))
    assert json.loads(result.stdout)["state"] == "completed", (
        'Exercise actual process CLI dispatch through the installed module entry point '
        'invariant failed.'
    )
    assert requests == ["/"], (
        'Exercise actual process CLI dispatch through the installed module entry point '
        'invariant failed.'
    )


def ReplaceAuthority(root: Path) -> None:
    """Record an explicit replacement consent actor in the owned synthetic workspace."""

    from dataclasses import replace

    from fuzzy1337.scope import LocalScopeStore

    store = LocalScopeStore(root)
    current = store.Open("local")
    store.Save(replace(current, authorization=replace(
        current.authorization, authority_reference="operator:replacement",
        record_reference="consent:replacement",
    )))


def test_ProductCannotContinueAfterConsentAuthorityChangesBetweenEndpoints(
    tmp_path: Path, local_target, capsys,
) -> None:
    """The previous actor cannot acquire another endpoint under replacement consent."""

    base, requests, _ = local_target
    root = tmp_path / "workspace"
    urls = (base + "/first", base + "/second")
    Setup(root, urls, capsys)

    def OnEvent(event) -> None:
        """Replace actor after the first actually persisted model delta, before the next grant."""

        if event.kind.value == "model_delta":
            ReplaceAuthority(root)

    summary = asyncio.run(RunQuickScan(
        root, "local", tuple(Target(TargetKind.URL, url) for url in urls), "operator:fixture",
        approve_safe_http=True, limits=DiscoveryLimits(interval_seconds=0.05), on_event=OnEvent,
    ))
    assert summary.ExitCode() == 3, "Replacement consent must deny the previous owning operator."
    assert summary.snapshot.failure is not None, "Actor drift must remain an explicit failure."
    assert summary.snapshot.failure.code.value == "authorization", (
        "Changing consent actor must preserve authority denial rather than provider failure."
    )
    assert requests == ["/first"], "A changed actor must prevent the second target contact."
    assert summary.model_revision == 1, "The first approved saved model delta must remain durable."
    ValidateSummary(summary.ToDict())


def test_ProductRechecksConsentActorAtFinalGovernedLaunch(
    tmp_path: Path, local_target, capsys, monkeypatch,
) -> None:
    """A replacement actor between grant and process launch must prevent even the first contact."""

    from fuzzy1337.policy import PolicyEngine

    base, requests, _ = local_target
    root = tmp_path / "workspace"
    url = base + "/"
    Setup(root, (url,), capsys)
    original = PolicyEngine.Authorize

    def Authorize(self, *args, **kwargs):
        """Obtain the exact original grant, then replace its current authoritative consent actor."""

        grant = original(self, *args, **kwargs)
        ReplaceAuthority(root)

        return grant

    monkeypatch.setattr(PolicyEngine, "Authorize", Authorize)
    output = StringIO()
    assert RunCommands("scan", ScanArguments(root, (url,)), output, json_output=True) == 3, (
        "Changed consent at the final governed launch must remain a dedicated denial."
    )
    summary = json.loads(output.getvalue())
    ValidateSummary(summary)
    assert not requests, "Final launch revalidation must prevent all target contact."
    assert not summary["job"]["artifacts"], "Denied process launch must not fabricate acquisition."


@pytest.mark.parametrize("mutation", ["missing", "tampered"])
def test_ProductCannotReportNewSuccessWithBrokenRetainedEvidence(
    tmp_path: Path, local_target, capsys, mutation: str,
) -> None:
    """A second scan must fail before contact when an earlier retained raw acquisition is broken."""

    base, requests, _ = local_target
    root = tmp_path / "workspace"
    urls = (base + "/first", base + "/second")
    Setup(root, urls, capsys)
    assert RunCommands("scan", ScanArguments(root, urls[:1]), StringIO(), json_output=True) == 0, (
        "The first owned acquisition must be real and complete before evidence mutation."
    )
    workspace = LocalWorkspaceStore(root).Open()
    blob = root / "evidence" / workspace.evidence_references[0].locator

    if mutation == "missing":
        blob.unlink()

    else:
        blob.write_bytes(b"tampered-safe-acquisition")

    output = StringIO()
    assert RunCommands("scan", ScanArguments(root, urls[1:]), output, json_output=True) == 4, (
        "Broken retained evidence must block whole-workspace scan success."
    )
    failure = json.loads(output.getvalue())
    assert failure["state"] == "failed" and failure["failure"]["code"] == "storage", (
        "Missing or corrupted prior bytes must remain a truthful storage/integrity failure."
    )
    assert requests == ["/first"], "Invalid retained state must prevent the next contact."
    assert LocalModelStore(root).Open().revision == 1, "Failed runs must not fabricate model data."
    assert Main(["workspace", "open", str(root), "--json"]) == 4, (
        "Reopen must independently detect the same retained integrity failure."
    )
