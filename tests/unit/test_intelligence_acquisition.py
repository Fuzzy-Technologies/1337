# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded explicit selections, immutable acquisition evidence, and owned receiver cleanup."""

from __future__ import annotations

import io
import json
import subprocess
from dataclasses import replace
from types import SimpleNamespace

import pytest

from fuzzy1337 import intelligence_acquisition as acquisition
from fuzzy1337 import intelligence_transport as transport
from fuzzy1337.evidence import EvidenceStorageError, LocalEvidenceStore
from fuzzy1337.intel_references import SourceOrigin
from fuzzy1337.intelligence import IntelligenceFeed
from fuzzy1337.intelligence_acquisition import (
    AcquireIntelligenceSnapshot,
    AcquisitionState,
    CisaKevSource,
    SnapshotRequest,
    SnapshotSource,
    SyncIntelligenceSnapshots,
    SyncState,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

RAW = (b"#model_version:synthetic-1,score_date:2026-10-12T00:00:00Z\n"
       b"cve,epss,percentile\nCVE-1900-9999,0.2,0.8\n")
COMMIT = "a" * 40


def Source():
    """Declare explicitly synthetic offline score data without making an official corpus claim."""

    return SnapshotSource(
        IntelligenceFeed.EPSS, "synthetic-1", SourceOrigin.SYNTHETIC, "1337 synthetic fixture",
        "https://example.invalid/scores.csv", "Apache-2.0 (synthetic fixture only)",
        "https://example.invalid/LICENSE",
    )


def Workspace(tmp_path):
    """Create an owned real workspace, including its physical evidence partition."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Intel acquisition tests"), "owned")

    return root


@pytest.mark.parametrize("changes", [
    {"feed": "epss"}, {"origin": "external"}, {"catalog_version": " "},
    {"publisher": ""}, {"source_url": "http://example.invalid/data"},
    {"license_url": "https://user:secret@example.invalid/LICENSE"},
    {"license_name": "\n"}, {"expected_sha256": "A" * 64},
])
def test_SelectionsRequireExplicitBoundedAttribution(changes):
    """Neither malformed source facts nor byte pins are silently coerced or authenticated."""

    with pytest.raises(ValueError):
        replace(Source(), **changes)


@pytest.mark.parametrize("changes", [
    {"source": {}}, {"payload": "bytes?"}, {"max_bytes": True}, {"max_bytes": 0},
    {"max_bytes": 16 * 1024 * 1024 + 1}, {"timeout_seconds": True},
    {"timeout_seconds": float("nan")}, {"timeout_seconds": float("inf")},
    {"timeout_seconds": 0}, {"timeout_seconds": 61},
])
def test_RequestsRefuseUnboundedOrUntypedInputs(changes):
    """Receiver bounds cannot be bypassed with booleans, nonfinite values, or coercion."""

    with pytest.raises(ValueError):
        replace(SnapshotRequest(Source(), RAW), **changes)


@pytest.mark.parametrize("commit", ["main", "latest", "a" * 39, "A" * 40, None])
def test_RemoteSelectionNeverDiscoversOrAcceptsAMovingRevision(commit):
    """A caller must choose an exact immutable official mirror commit."""

    with pytest.raises(ValueError):
        CisaKevSource(commit, "2026.10.12")


@pytest.mark.parametrize("changes", [
    {"source_url": "https://example.invalid/" + COMMIT},
    {"source_url": "https://raw.githubusercontent.com/cisagov/kev-data/main/"
                   "known_exploited_vulnerabilities.json"},
    {"publisher": "Invented"}, {"origin": SourceOrigin.SYNTHETIC},
    {"license_name": "Invented rights"}, {"feed": IntelligenceFeed.CVE},
])
def test_HttpsAllowlistDoesNotFollowArbitrarySourcesOrMislabelAttribution(changes):
    """The remote boundary cannot turn a caller URL or source label into publisher authority."""

    with pytest.raises(ValueError):
        SnapshotRequest(replace(CisaKevSource(COMMIT, "2026.10.12"), **changes))


@pytest.mark.parametrize("raw,state,complete", [
    (RAW, AcquisitionState.SUCCEEDED, True), (b"invalid CSV", AcquisitionState.PARSE_FAILED, True),
    (RAW * 2, AcquisitionState.SIZE_EXCEEDED, False),
])
def test_LocalImportPublishesExactCompleteOrPartialRawAndTerminalReceipt(
    tmp_path, raw, state, complete,
):
    """Acquired bytes survive parser refusal, and truncated input never supplies a snapshot."""

    root = Workspace(tmp_path)
    outcome = AcquireIntelligenceSnapshot(
        root, SnapshotRequest(Source(), raw, max_bytes=len(RAW)), scope_reference="scope:owned",
    )
    store = LocalEvidenceStore(root / "evidence")

    assert outcome.state is state and outcome.body_complete is complete, (
        "Import outcome misreported acquisition completeness or parsing success"
    )
    assert outcome.raw is not None and store.Read(outcome.raw.reference) == raw[:len(RAW)], (
        "Acquisition normalized, dropped, or fabricated original captured bytes"
    )
    assert outcome.receipt is not None, "Terminal acquisition did not publish its immutable receipt"
    receipt = json.loads(store.Read(outcome.receipt.reference))

    assert receipt == outcome.ToDict(), "Persisted terminal receipt differs from the returned facts"
    assert receipt["publisher_authentication"] == "not-assessed", (
        "Byte acquisition fabricated publisher authentication"
    )
    assert (outcome.snapshot is not None) is (state is AcquisitionState.SUCCEEDED), (
        "Failed or partial import supplied a usable parsed snapshot"
    )


def test_ReceiverObservesItsOwnTimesAndRetainsDigestFailures(tmp_path, monkeypatch):
    """Declared metadata cannot supply acquisition clocks or replace mismatched original bytes."""

    root = Workspace(tmp_path)
    times = iter(("2026-10-13T10:00:00.000000+00:00", "2026-10-13T10:00:01.000000+00:00"))
    monkeypatch.setattr(acquisition, "AcquisitionTime", lambda: next(times))
    outcome = AcquireIntelligenceSnapshot(
        root, SnapshotRequest(replace(Source(), expected_sha256="f" * 64), RAW),
        scope_reference="scope:owned",
    )

    assert outcome.state is AcquisitionState.DIGEST_MISMATCH and outcome.snapshot is None, (
        "A mismatched expected byte pin acquired successful snapshot semantics"
    )
    assert outcome.started_at.endswith("00.000000+00:00") and outcome.finished_at.endswith(
        "01.000000+00:00"
    ), "Receiver observation clocks were replaced by caller source declarations"
    assert outcome.raw is not None and outcome.raw.provenance.finished_at == outcome.finished_at, (
        "Captured raw provenance lost the receiver's observed finish time"
    )


@pytest.mark.parametrize("failed_role", [
    "intelligence-source", "intelligence-snapshot", "intelligence-acquisition",
])
def test_PublicationFailuresRemainExplicitAndDoNotEraseEarlierEvidence(
    tmp_path, monkeypatch, failed_role,
):
    """A failed later immutable publication preserves honestly available earlier records."""

    root = Workspace(tmp_path)
    original = LocalEvidenceStore.Put

    def Put(self, data, role, media_type, provenance):
        """Inject one owned storage failure at a specific publication boundary."""

        if role == failed_role:
            raise EvidenceStorageError("Owned deterministic publication failure")

        return original(self, data, role, media_type, provenance)

    monkeypatch.setattr(LocalEvidenceStore, "Put", Put)
    outcome = AcquireIntelligenceSnapshot(
        root, SnapshotRequest(Source(), RAW), scope_reference="scope:owned",
    )

    assert outcome.state is AcquisitionState.STORAGE_FAILED and outcome.snapshot is None, (
        "Partial publication was reported as a successful acquisition"
    )
    assert (outcome.raw is not None) is (failed_role != "intelligence-source"), (
        "Storage failure lost track of already published original evidence"
    )
    assert (outcome.snapshot_record is not None) is (failed_role == "intelligence-acquisition"), (
        "Storage failure fabricated or hid a completed immutable snapshot publication"
    )


@pytest.mark.parametrize("payloads,state", [
    ((RAW, RAW), SyncState.SUCCEEDED), ((RAW, b"invalid"), SyncState.PARTIAL),
    ((b"invalid", b"invalid"), SyncState.FAILED),
])
def test_SyncRetainsEveryIndependentOutcomeWithoutSilentRetries(tmp_path, payloads, state):
    """Batch status reflects actual per-source publications rather than a fabricated clean sync."""

    outcome = SyncIntelligenceSnapshots(
        Workspace(tmp_path), tuple(SnapshotRequest(Source(), raw) for raw in payloads),
        scope_reference="scope:owned",
    )

    assert outcome.state is state and len(outcome.outcomes) == len(payloads), (
        "Batch summary dropped a failure, reordered work, or invented successful acquisitions"
    )
    assert all(item.receipt is not None for item in outcome.outcomes), (
        "A terminal independent sync result lost its acquisition receipt"
    )


@pytest.mark.parametrize("requests", [(), [], ({},), (None,) * 17])
def test_SyncValidatesTheWholeBatchBeforeAnyAcquisition(tmp_path, requests):
    """An untyped or unbounded batch cannot create partial evidence as a validation side effect."""

    root = Workspace(tmp_path)

    with pytest.raises(ValueError):
        SyncIntelligenceSnapshots(root, requests, scope_reference="scope:owned")

    assert not tuple((root / "evidence").iterdir()), "Rejected sync published unexpected evidence"


class Response:
    """Provide an owned response stream without connecting to an Internet source."""

    def __init__(self, body=RAW, status=200, headers=None, error=None):
        """Keep independent controlled framing, bytes, and terminal read behavior."""

        self.status = status
        self.headers = headers or {}
        self.body = io.BytesIO(body)
        self.error = error
        self.getheader = self.GetHeader
        self.read1 = self.ReadAvailable

    def GetHeader(self, name):
        """Implement the standard-library response callback without guessed defaults."""

        return self.headers.get(name)

    def ReadAvailable(self, size):
        """Deliver available owned bytes or an explicit controlled read failure."""

        if self.error is not None:
            raise self.error

        return self.body.read(size)


class Connection:
    """Observe HTTP client ownership and headers with no network connection."""

    def __init__(self, response):
        """Retain the selected owned response and lifecycle observations."""

        self.response = response
        self.closed = False
        self.headers = None

    def Request(self, method, path, headers):
        """Record the HTTP client callback's explicit no-compression request."""

        self.headers = headers

    def GetResponse(self):
        """Return the controlled response through the standard-library callback."""

        return self.response

    def Close(self):
        """Record unconditional connection cleanup."""

        self.closed = True


@pytest.mark.parametrize("response,limit,state,retained", [
    (Response(), len(RAW), 0, RAW),
    (Response(headers={"Content-Length": str(len(RAW))}), len(RAW), 0, RAW),
    (Response(status=302), len(RAW), transport.REDIRECT_EXIT, b""),
    (Response(status=404), len(RAW), transport.HTTP_EXIT, b""),
    (Response(headers={"Content-Encoding": "gzip"}), len(RAW), transport.FORMAT_EXIT, b""),
    (Response(headers={"Transfer-Encoding": "gzip"}), len(RAW), transport.FORMAT_EXIT, b""),
    (Response(headers={"Content-Length": "-1"}), len(RAW), transport.FORMAT_EXIT, b""),
    (Response(headers={"Content-Length": "9,9"}), len(RAW), transport.FORMAT_EXIT, b""),
    (Response(headers={"Content-Length": "1" * 21}), len(RAW), transport.FORMAT_EXIT, b""),
    (Response(headers={"Content-Length": "１２"}), len(RAW), transport.FORMAT_EXIT, b""),
    (Response(headers={"Transfer-Encoding": "chunked", "Content-Length": "1"}),
     len(RAW), transport.FORMAT_EXIT, b""),
    (Response(headers={"Content-Length": "10000"}), len(RAW), transport.SIZE_EXIT, b""),
    (Response(), 10, transport.SIZE_EXIT, RAW[:10]),
    (Response(headers={"Content-Length": str(len(RAW) + 1)}),
     len(RAW) + 1, transport.TRANSPORT_EXIT, RAW),
    (Response(error=TimeoutError()), len(RAW), transport.TIMEOUT_EXIT, b""),
    (Response(error=OSError()), len(RAW), transport.TRANSPORT_EXIT, b""),
])
def test_ReceiverRejectsRedirectsCompressionFramingAndLimitsWithoutFollowingOrNormalizing(
    monkeypatch, response, limit, state, retained,
):
    """The production worker keeps original bounded bytes and always closes its owned connection."""

    connection = Connection(response)
    client = SimpleNamespace(
        request=connection.Request, getresponse=connection.GetResponse, close=connection.Close,
    )
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", lambda *a, **k: client)
    output = io.BytesIO()
    actual = transport.Receive(CisaKevSource(COMMIT, "synthetic-1").source_url, limit, 1, output)

    assert actual == state and output.getvalue().partition(b"\n")[2] == retained, (
        "Receiver followed a redirect, decompressed bytes, ignored a limit, or changed raw evidence"
    )
    assert connection.closed and connection.headers["Accept-Encoding"] == "identity", (
        "Receiver leaked its connection or implicitly requested a compressed representation"
    )


def Worker(tmp_path, monkeypatch, body):
    """Select an owned static worker process for deterministic real subprocess lifecycle checks."""

    worker = tmp_path / "intelligence_transport.py"
    worker.write_text(
        '# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies\n'
        '# SPDX-License-Identifier: Apache-2.0\n\n'
        '"""Owned controlled receiver fixture; no network requests or product security claims."""\n'
        + body, encoding="utf-8",
    )
    monkeypatch.setattr(acquisition, "__file__", str(tmp_path / "intelligence_acquisition.py"))


@pytest.mark.parametrize("exit_code,state", [
    (0, AcquisitionState.SUCCEEDED), (2, AcquisitionState.REDIRECT_REJECTED),
    (3, AcquisitionState.HTTP_REJECTED), (4, AcquisitionState.FORMAT_REJECTED),
    (5, AcquisitionState.SIZE_EXCEEDED), (6, AcquisitionState.TRANSPORT_FAILED),
    (7, AcquisitionState.TIMED_OUT),
])
def test_ParentInterpretsOwnedWorkerTerminalStatus(tmp_path, monkeypatch, exit_code, state):
    """The real parent API preserves explicit subprocess outcomes without an Internet dependency."""

    Worker(tmp_path, monkeypatch,
           f"import sys\nsys.stdout.buffer.write(b'{{\"status\":200}}\\nraw')\n"
           f"raise SystemExit({exit_code})\n")
    payload, observed, status = acquisition.FetchRemoteBytes(
        SnapshotRequest(CisaKevSource(COMMIT, "synthetic-1")),
    )

    assert (payload, observed, status) == (b"raw", state, 200), (
        "Parent confused process termination with successful acquisition or lost original bytes"
    )


def test_TotalDeadlineRetainsDeliveredPartialBytesAndKillsAndJoinsTheRealWorker(
    tmp_path, monkeypatch,
):
    """A worker hanging after a partial body cannot outlive its parent acquisition deadline."""

    Worker(tmp_path, monkeypatch,
           "import sys, time\nsys.stdout.buffer.write(b'{\"status\":200}\\npartial')\n"
           "sys.stdout.buffer.flush()\ntime.sleep(10)\n")
    original = subprocess.Popen
    processes = []

    def Popen(*args, **kwargs):
        """Retain the actual owned process for cleanup and clean-environment assertions."""

        assert kwargs["env"] == {}, "Worker inherited ambient proxy or credential environment"
        process = original(*args, **kwargs)
        processes.append(process)

        return process

    monkeypatch.setattr(acquisition.subprocess, "Popen", Popen)
    payload, state, status = acquisition.FetchRemoteBytes(
        SnapshotRequest(CisaKevSource(COMMIT, "synthetic-1"), timeout_seconds=1.0),
    )

    assert (payload, state, status) == (b"partial", AcquisitionState.TIMED_OUT, 200), (
        "Deadline fabricated complete bytes or discarded delivered original partial evidence"
    )
    assert len(processes) == 1 and processes[0].poll() is not None, (
        "Timed-out receiver remained alive or was not joined"
    )


def test_CallerInterruptionAlsoKillsAndJoinsTheActualReceiver(tmp_path, monkeypatch):
    """Keyboard interruption cannot leak a DNS or header receiver process."""

    Worker(tmp_path, monkeypatch, "import time\ntime.sleep(10)\n")
    original = subprocess.Popen
    processes = []

    def Popen(*args, **kwargs):
        """Interrupt the first parent communication before its owned worker finishes."""

        process = original(*args, **kwargs)
        communicate = process.communicate
        calls = []

        def Communicate(*a, **k):
            """Interrupt once, then perform the real parent cleanup communication."""

            calls.append(True)

            if len(calls) == 1:
                raise KeyboardInterrupt

            return communicate(*a, **k)

        monkeypatch.setattr(process, "communicate", Communicate)
        processes.append(process)

        return process

    monkeypatch.setattr(acquisition.subprocess, "Popen", Popen)

    with pytest.raises(KeyboardInterrupt):
        acquisition.FetchRemoteBytes(SnapshotRequest(CisaKevSource(COMMIT, "synthetic-1")))

    assert len(processes) == 1 and processes[0].poll() is not None, (
        "Caller cancellation leaked an owned receiver process"
    )


@pytest.mark.parametrize("body", [
    "import sys\nsys.stdout.buffer.write(b'garbage\\nraw')\n",
    "import sys\nsys.stdout.buffer.write(b'{\"status\":true}\\nraw')\n",
    "import sys\nsys.stdout.buffer.write(b'{\"status\":200,\"extra\":1}\\nraw')\n",
    "import sys\nsys.stdout.buffer.write(b'{\"status\":200}\\n' + b'x' * 101)\n",
    "import sys\nsys.stdout.buffer.write(b'{\"status\":404}\\nraw')\n",
])
def test_ParentRejectsMalformedFramingOversizedOutputAndFalseSuccess(tmp_path, monkeypatch, body):
    """Internal worker protocol failure cannot produce accepted source or unbounded evidence."""

    Worker(tmp_path, monkeypatch, body)
    payload, state, _ = acquisition.FetchRemoteBytes(
        SnapshotRequest(CisaKevSource(COMMIT, "synthetic-1"), max_bytes=100),
    )

    assert state is AcquisitionState.TRANSPORT_FAILED and len(payload) <= 100, (
        "Malformed worker framing or oversized output acquired complete-source semantics"
    )


def test_ReceiverStartFailureAndInvalidDirectWorkerInvocationStayControlled(monkeypatch):
    """Unavailable process creation or malformed internal invocation cannot claim acquisition."""

    def Popen(*args, **kwargs):
        """Inject a deterministic owned process-creation failure."""

        raise OSError("Owned process startup failure")

    monkeypatch.setattr(acquisition.subprocess, "Popen", Popen)

    assert acquisition.FetchRemoteBytes(SnapshotRequest(CisaKevSource(COMMIT, "x"))) == (
        b"", AcquisitionState.TRANSPORT_FAILED, None
    ), "Process creation failure was reported as successful or attributed to a response"
    assert transport.Receive("http://example.invalid/x", 10, 1, io.BytesIO()) == (
        transport.FORMAT_EXIT
    ), "Internal worker accepted an invalid direct transport scheme"
    monkeypatch.setattr(transport.sys, "argv", ["worker"])

    assert transport.Main() == transport.FORMAT_EXIT, (
        "Malformed internal worker invocation acquired successful process semantics"
    )
