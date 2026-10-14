# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Own finite plaintext proxy/backend fixtures and actual product evidence checks for #97."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path
from threading import Event, Lock, Thread, current_thread
from typing import Any, cast
from uuid import uuid4

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from fuzzy1337.cli import Main
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore, ObjectKind, RelationKind
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore

ROOT = Path(__file__).parents[1]
ORACLE = ROOT / "labs/targets/proxy-regression/oracle.v1.json"
PRIVATE_MARKER = "synthetic-proxy-private-value"
PRIVATE_BODY = (PRIVATE_MARKER + ":body").encode()


def Oracle() -> dict[str, Any]:
    """Read independently handwritten finite target/configuration expectations."""

    return cast(dict[str, Any], json.loads(ORACLE.read_text(encoding="utf-8")))


def Product(arguments: list[str], *, installed: bool = False) -> tuple[int, dict[str, Any]]:
    """Invoke actual CLI dispatch or the installed executable and decode one JSON outcome."""

    if installed:
        executable = Path(sys.executable).with_name("1337.exe" if os.name == "nt" else "1337")
        result = subprocess.run([str(executable), *arguments, "--json"], capture_output=True,
            text=True, check=False, timeout=20)
        status, stdout, stderr = result.returncode, result.stdout, result.stderr

    else:
        output, error = StringIO(), StringIO()

        with redirect_stdout(output), redirect_stderr(error):
            status = Main([*arguments, "--json"])

        stdout, stderr = output.getvalue(), error.getvalue()

    assert not stderr, "Product proxy regression emitted an unexpected diagnostic"
    assert PRIVATE_MARKER not in stdout, "Product presentation leaked synthetic private input"

    return status, json.loads(stdout)


def Setup(root: Path, urls: tuple[str, ...], *, granted: bool = True,
          excluded: bool = False, installed: bool = False) -> None:
    """Create the actual workspace and explicitly scoped frontend URLs through product commands."""

    status, _ = Product(["workspace", "create", str(root), "--id", "proxy-owned",
        "--name", "Owned proxy regression"], installed=installed)
    assert status == 0, "Product workspace setup failed"
    arguments = ["scope", "create", str(root), "--id", "proxy-local", "--allow-ip", "127.0.0.1"]

    for url in urls:
        arguments.extend(("--allow-url", url))

    if excluded:
        arguments.extend(("--exclude-url", urls[0]))

    if granted:
        now = datetime.now(UTC)
        arguments.extend(("--grant-consent", "--owner", "operator:proxy-owned",
            "--consent-reference", "consent:proxy-owned",
            "--valid-from", (now - timedelta(minutes=2)).isoformat(),
            "--valid-until", (now + timedelta(minutes=2)).isoformat()))

    status, _ = Product(arguments, installed=installed)
    assert status == 0, "Product explicit proxy scope setup failed"


def Scan(root: Path, urls: tuple[str, ...], *, approved: bool = True) -> list[str]:
    """Select exact frontend URLs, ordinary SAFE permission and finite current product budgets."""

    arguments = ["scan", "quick", str(root), "--scope", "proxy-local",
        "--owner", "operator:proxy-owned", "--request-timeout", "0.2",
        "--timeout", "8", "--interval", "0.05"]

    for url in urls:
        arguments.extend(("--target", url))

    if approved:
        arguments.append("--approve-safe-http")

    return arguments


@dataclass
class ProxyLab:
    """Explicit pytest-owned frontend/backend addresses and independent request observations."""

    backend: ThreadingHTTPServer
    frontend: ThreadingHTTPServer
    release: Event
    lock: Any
    frontend_hits: list[str] = field(default_factory=list)
    backend_hits: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    request_threads: list[Thread] = field(default_factory=list)
    stalled: Event = field(default_factory=Event)

    def Url(self, case: dict[str, Any]) -> str:
        """Return one explicitly selected frontend URL without expanding any product target."""

        return f"http://127.0.0.1:{self.frontend.server_port}" + str(case["frontend_route"])

    def Observe(self) -> tuple[list[str], list[str]]:
        """Copy exact test-only request logs independently of scanner output or model facts."""

        with self.lock:
            assert not self.errors, "Owned proxy fixture encountered an unexpected request/failure"

            return list(self.frontend_hits), list(self.backend_hits)


@contextmanager
def OwnedProxy() -> Iterator[ProxyLab]:
    """Own two ephemeral literal-loopback listeners, all request threads and bounded teardown."""

    release, lock = Event(), Lock()
    fixture: ProxyLab

    class Server(ThreadingHTTPServer):
        """Keep accepted request threads owned and joinable rather than abandoning daemons."""

        daemon_threads = False
        block_on_close = True

        def process_request_thread(self, request: socket.socket | tuple[bytes, socket.socket],
                                   client_address: tuple[str, int]) -> None:
            """Track every owned accepted handler and bound waits for unexpected client input."""

            with lock:
                fixture.request_threads.append(current_thread())

            assert isinstance(request, socket.socket), "Owned HTTP fixture requires a TCP socket"
            request.settimeout(2)
            super().process_request_thread(request, client_address)

        def handle_error(self, request: socket.socket | tuple[bytes, socket.socket],
                         client_address: tuple[str, int]) -> None:
            """Keep fixed test-only failure truth without printing transient request contents."""

            with lock:
                fixture.errors.append("handler-failure")

    class Handler(BaseHTTPRequestHandler):
        """Serve only finite reviewed non-secret responses and discard normal access logging."""

        def Reply(self, status: int, *, location: str | None = None) -> None:
            """Emit a controlled response containing markers excluded by status-only discovery."""

            self.send_response(status, PRIVATE_MARKER + ":reason")
            self.send_header("Content-Length", str(len(PRIVATE_BODY)))
            self.send_header("Content-Type", "text/plain")
            self.send_header("Set-Cookie", PRIVATE_MARKER + ":cookie")
            self.send_header("Authorization", PRIVATE_MARKER + ":authorization")
            self.send_header("X-Proxy-Canary", PRIVATE_MARKER + ":header")

            if location is not None:
                self.send_header("Location", location)

            try:
                self.end_headers()
                self.wfile.write(PRIVATE_BODY)

            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, format: str, *args: object) -> None:
            """Suppress incidental target access/error text in deterministic regression output."""

    class Backend(Handler):
        """Observe independently whether the proxy actually contacted its fixed owned backend."""

        def do_GET(self) -> None:
            """Record one fixed route; request data never selects another destination."""

            with lock:
                fixture.backend_hits.append(self.path)

                if "Authorization" in self.headers or "Cookie" in self.headers:
                    fixture.errors.append("credential-forwarded")

            self.Reply(200 if self.path == "/owned-resource" else 404)

    class Frontend(Handler):
        """Expose transparent, deny, redirect, status-rewrite and stalled-header cases only."""

        def do_GET(self) -> None:
            """Apply a closed server-side fixture route without adding scanner proxy transport."""

            with lock:
                fixture.frontend_hits.append(self.path)

                if "Authorization" in self.headers or "Cookie" in self.headers:
                    fixture.errors.append("credential-received")

            if self.path == "/timeout":
                fixture.stalled.set()
                release.wait(timeout=5)

                return

            if self.path in ("/transparent", "/rewritten"):
                connection = http.client.HTTPConnection("127.0.0.1", backend.server_port,
                                                        timeout=1)

                try:
                    connection.request("GET", "/owned-resource")
                    response = connection.getresponse()
                    status = response.status
                    body = response.read(len(PRIVATE_BODY) + 1)
                    assert body == PRIVATE_BODY, "Owned backend response changed"

                finally:
                    connection.close()

                self.Reply(429 if self.path == "/rewritten" else status)

            elif self.path == "/blocked":
                self.Reply(403)

            elif self.path == "/redirect":
                self.Reply(302, location=f"http://127.0.0.1:{backend.server_port}/never-followed")

            else:
                self.Reply(404)

    backend = Server(("127.0.0.1", 0), Backend)

    try:
        frontend = Server(("127.0.0.1", 0), Frontend)

    except BaseException:
        backend.server_close()

        raise

    fixture = ProxyLab(backend, frontend, release, lock)
    threads = [Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=False)
               for server in (backend, frontend)]
    started: list[tuple[ThreadingHTTPServer, Thread]] = []

    try:
        for server, thread in zip((backend, frontend), threads, strict=True):
            thread.start()
            started.append((server, thread))

        yield fixture

    finally:
        release.set()

        for running_server, _ in reversed(started):
            running_server.shutdown()

        for server in (frontend, backend):
            server.server_close()

        for thread in [*(thread for _, thread in started), *fixture.request_threads]:
            thread.join(timeout=3)
            assert not thread.is_alive(), "Owned proxy/backend handler thread was not reaped"


def Verify(root: Path, summary: dict[str, Any], case: dict[str, Any], lab: ProxyLab
           ) -> dict[str, Any]:
    """Compare actual product/store facts with the independent handwritten target oracle."""

    packet = EvidencePacket(root, summary, case, lab)
    PreservePacket(packet)
    schema = json.loads((ROOT / "contracts/quick-scan-summary.schema.json").read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(summary)
    frontend_hits, backend_hits = lab.Observe()
    assert frontend_hits == [case["frontend_route"]] and backend_hits == case["backend_hits"], (
        "Observed frontend/backend requests differ from the handwritten proxy oracle"
    )
    assert summary["state"] == summary["job"]["state"] == case["job_state"], (
        "Product terminal state differs from actual job or independent expected result"
    )
    failure = summary["job"]["failure"]
    assert (None if failure is None else failure["code"]) == case["failure_code"], (
        "Proxy regression hid actual job failure classification"
    )
    assert summary["job"]["last_sequence"] == len(summary["events"]) - 1, (
        "Proxy workflow event cursor does not cover its original ordered stream"
    )
    model = LocalModelStore(root).Open()
    assert model.revision == summary["model_revision"] == case["model_revision"], (
        "Proxy workflow claimed a model revision without an owning saved snapshot"
    )
    assert len(model.objects) == case["objects"] and not model.Objects(ObjectKind.FINDING), (
        "Frontend response fabricated vulnerability Findings or backend object facts"
    )
    assert all(relation.kind is not RelationKind.RELATED_TO for relation in model.relations), (
        "Frontend status became an invented technical reachability/barrier transition"
    )
    workspace = LocalWorkspaceStore(root).Open()
    selected_scope = LocalScopeStore(root).Open("proxy-local")
    assert not any(str(lab.backend.server_port) in target.value
        for target in selected_scope.targets), "Frontend observation registered a backend target"
    store = LocalEvidenceStore(root / "evidence")
    assert len(workspace.evidence_record_references) == case["evidence_records"], (
        "Retained original acquisition count differs from the independent oracle"
    )
    records, raw = [], []

    for identity in workspace.evidence_record_references:
        record = store.Get(identity)
        payload = store.Read(record.reference)
        assert record.provenance.source_id == "native.http" and (
            record.provenance.source_version == "1" and record.provenance.execution is not None
        ), "Retained source identity/version/execution was substituted"
        records.append(json.loads(record.Serialize()))
        raw.append(json.loads(payload))

    if case["frontend_status"] is None:
        assert raw == [{"schema_version": 1, "error": "timeout"}], (
            "Actual timeout bytes were hidden or promoted into successful endpoint observation"
        )

    else:
        expected = {"schema_version": 1, "url": lab.Url(case), "address": "127.0.0.1",
            "port": lab.frontend.server_port, "scheme": "http", "status": case["frontend_status"]}
        assert raw == [expected], "Worker output admitted backend/header/body or substituted status"
        endpoints = model.Objects(ObjectKind.ENDPOINT)
        assert len(endpoints) == 1 and endpoints[0].identity.key == lab.Url(case) and (
            endpoints[0].attributes["status"] == case["frontend_status"]
        ), "Saved endpoint status does not describe the selected frontend"
        assert not any(item.identity.key == f"host:127.0.0.1/tcp/{lab.backend.server_port}"
            for item in model.objects), "Backend access was inferred from frontend status"

    for path in root.rglob("*"):
        if path.is_file():
            assert PRIVATE_MARKER.encode() not in path.read_bytes(), (
                "Raw header/body/reason marker leaked into persisted product state"
            )

    return packet


def EvidencePacket(root: Path, summary: dict[str, Any], case: dict[str, Any], lab: ProxyLab
                   ) -> dict[str, Any]:
    """Capture original safe acquisitions and fixture metadata before checking expected results.

    Args:
        root: Actual isolated product workspace after the owning job has stopped.
        summary: Actual machine outcome, never a computed expected result.
        case: Explicit closed test-case identity selecting the independent source oracle.
        lab: Owning listeners and independent test-only observations.

    Returns:
        Version/configuration/source-digest packet, retained even if later comparisons fail.
    """

    workspace = LocalWorkspaceStore(root).Open()
    store = LocalEvidenceStore(root / "evidence")
    records, raw = [], []

    for identity in workspace.evidence_record_references:
        record = store.Get(identity)
        records.append(json.loads(record.Serialize()))
        raw.append(json.loads(store.Read(record.reference)))

    with lab.lock:
        frontend_hits, backend_hits = list(lab.frontend_hits), list(lab.backend_hits)
        errors = list(lab.errors)

    return {"schema_version": 1, "profile": Oracle(),
        "oracle_sha256": hashlib.sha256(ORACLE.read_bytes()).hexdigest(),
        "python_version": sys.version, "case_id": case["id"],
        "source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in ("tests/proxy_regression_helpers.py", "src/fuzzy1337/quickscan.py",
                "src/fuzzy1337/discovery.py", "src/fuzzy1337/adapters/native_http.py",
                "src/fuzzy1337/native_http_worker.py")},
        "test_only_frontend_hits": frontend_hits, "test_only_backend_hits": backend_hits,
        "test_only_fixture_errors": errors,
        "product_summary": summary, "original_evidence_manifests": records,
        "original_safe_worker_records": raw}


def PreservePacket(packet: dict[str, Any]) -> Path:
    """Retain one uniquely named test evidence packet in the existing CI artifact directory."""

    directory = ROOT / "functional-evidence/proxy-regression"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (str(packet["case_id"]) + "-" + uuid4().hex + ".json")

    with path.open("x", encoding="utf-8") as stream:
        json.dump(packet, stream, sort_keys=True)

    return path
