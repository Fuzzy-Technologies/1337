# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned localhost demo composition over actual product commands and evidence stores."""

from __future__ import annotations

import json
import stat
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import StringIO
from pathlib import Path
from socket import SHUT_RDWR, socket
from threading import Event, Lock, Thread
from typing import TextIO, cast

from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.report_commands import PublishReport, ReportFailure, RunReportCommands
from fuzzy1337.scan_commands import RunCommands
from fuzzy1337.workspace import LocalWorkspaceStore, StoragePathInfo

__all__ = ["DemoPlan", "OwnedDemoTarget", "RunLocalDemo"]

DEMO_WORKSPACE_ID = "demo-local"
DEMO_SCOPE_ID = "owned-local"
DEMO_OWNER = "operator:owned-demo"
DEMO_ROUTES = ("/", "/health", "/redirect")


class DemoFailure(RuntimeError):
    """Retain only a fixed phase and actual exit status for safe failure presentation."""

    def __init__(self, phase: str, status: int = 4) -> None:
        """Bind a trusted local phase without retaining raw exception or argument values."""

        super().__init__(phase)
        self.phase = phase
        self.status = status


def DemoPlan() -> dict[str, object]:
    """Describe the finite plan without reading files, starting a service or granting consent.

    Returns:
        Fixed schema-v1 plan whose approval applies solely to the command-owned service.
    """

    return {
        "schema_version": 1,
        "command": "demo.local",
        "bind_host": "127.0.0.1",
        "port_selection": "ephemeral",
        "routes": list(DEMO_ROUTES),
        "capabilities": ["http.endpoint-discovery"],
        "impact": "safe",
        "max_requests": 3,
        "request_timeout_seconds": 2,
        "scan_timeout_seconds": 15,
        "consent_validity_seconds": 120,
        "outputs": ["workspace", "events.jsonl", "scan-summary.json", "workspace-open.json",
                    "reports/model.json", "reports/model.sarif", "evidence-index.json",
                    "target.json", "demo-summary.json"],
        "limitations": ["status-only discovery", "no vulnerability checks", "no attack paths",
                        "no external scanners", "no response bodies or redirect following"],
    }


def RequireNewDemoRoot(path: Path) -> Path:
    """Reject existing or unsafe output paths before acquiring any demo resource.

    Args:
        path: New root beneath an existing physical parent, without traversal or controls.

    Returns:
        Validated absolute path; no entry is created.

    Raises:
        DemoFailure: The root exists, the path is ambiguous, or a parent is not physical.
    """

    text = str(path)

    if ".." in path.parts or len(text.encode("utf-8")) > 4096 or any(
        ord(character) < 32 or ord(character) == 127 for character in text
    ):
        raise DemoFailure("configuration", 2)

    root = path.absolute()

    for parent in (*reversed(root.parent.parents), root.parent):
        metadata = StoragePathInfo(parent)

        if metadata is None or not stat.S_ISDIR(metadata.st_mode):
            raise DemoFailure("configuration", 2)

    if StoragePathInfo(root) is not None:
        raise DemoFailure("configuration", 2)

    return root


class OwnedDemoTarget:
    """Own one finite non-secret service, listening thread and exact request receipt."""

    def __init__(self) -> None:
        """Initialize ownership bookkeeping without opening a socket or starting a thread."""

        self.server: HTTPServer | None = None
        self.thread: Thread | None = None
        self.ready = Event()
        self.closing = Event()
        self.lock = Lock()
        self.connections: set[socket] = set()
        self.requests: list[dict[str, object]] = []
        self.port: int | None = None
        self.stopped = False

    def Start(self) -> None:
        """Bind only localhost, start the owned thread and await finite readiness.

        Raises:
            OSError: Binding, thread startup or readiness fails; caller still owns Close().
        """

        if self.server is not None or self.stopped:
            raise OSError("demo target lifecycle cannot be restarted")

        owner = self

        class Server(HTTPServer):
            """Bound accepted socket reads so teardown cannot wait for an idle local client."""

            def GetRequest(self) -> tuple[socket, tuple[str, int]]:
                """Bound each accepted socket without outbound readiness probes."""

                connection, address = super().get_request()
                connection.settimeout(1)

                with owner.lock:
                    if owner.closing.is_set():
                        connection.close()

                        raise OSError("demo target is closing")

                    owner.connections.add(connection)

                return connection, address

            get_request = GetRequest

            def CloseRequest(self, request: socket | tuple[bytes, socket]) -> None:
                """Release the exact accepted socket from lifecycle ownership after handling."""

                try:
                    super().close_request(request)

                finally:
                    with owner.lock:
                        owner.connections.discard(cast(socket, request))

            close_request = CloseRequest

            def HandleError(
                self, request: socket | tuple[bytes, socket], client_address: object,
            ) -> None:
                """Keep interrupted/invalid local client diagnostics outside retained evidence."""

            handle_error = HandleError

        class Handler(BaseHTTPRequestHandler):
            """Serve three bounded synthetic routes without exposing filesystem contents."""

            def do_GET(self) -> None:
                """Record an actually received request and return an empty synthetic response."""

                status = {"/": 200, "/health": 204, "/redirect": 302}.get(self.path, 404)

                with owner.lock:
                    if len(owner.requests) < 16:
                        owner.requests.append({"method": "GET",
                                               "path": self.path if self.path in DEMO_ROUTES else (
                                                   "<unselected>"), "status": status})

                self.send_response(status)
                self.send_header("Content-Length", "0")

                if self.path == "/redirect":
                    self.send_header("Location", "/not-selected")

                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                """Suppress framework diagnostics; exact bounded requests remain in the receipt."""

        self.server = Server(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port

        def Serve() -> None:
            """Signal owned thread readiness and enter the finite-polling service loop."""

            self.ready.set()
            assert self.server is not None
            self.server.serve_forever(poll_interval=0.05)

        self.thread = Thread(target=Serve, name="1337-demo-target", daemon=True)
        self.thread.start()

        if not self.ready.wait(timeout=2) or not self.thread.is_alive():
            raise OSError("demo target did not become ready")

    def Urls(self) -> tuple[str, ...]:
        """Return only the fixed explicit endpoints of the started command-owned service.

        Returns:
            Three exact literal-IP URLs; never discovered or externally supplied targets.

        Raises:
            DemoFailure: The service was not started or has already stopped.
        """

        if self.port is None or self.stopped:
            raise DemoFailure("target")

        return tuple(f"http://127.0.0.1:{self.port}{route}" for route in DEMO_ROUTES)

    def Close(self) -> None:
        """Attempt service shutdown/socket close and verify the owning thread was reaped.

        Raises:
            OSError: Shutdown/socket cleanup fails or a service thread remains alive.
        """

        self.closing.set()

        with self.lock:
            connections = tuple(self.connections)

        close_failed = False

        for connection in connections:
            try:
                connection.shutdown(SHUT_RDWR)

            except OSError:
                # A peer or framework may already have closed this same owned socket.
                pass

            finally:
                try:
                    connection.close()

                except OSError:
                    close_failed = True

        try:
            if self.server is not None and self.thread is not None and self.thread.is_alive():
                self.server.shutdown()

        finally:
            try:
                if self.server is not None:
                    self.server.server_close()

            finally:
                if self.thread is not None and self.thread.ident is not None:
                    self.thread.join(timeout=3)

                with self.lock:
                    self.stopped = (self.thread is None or not self.thread.is_alive()) and (
                        all(connection.fileno() == -1 for connection in self.connections)
                    )

        if close_failed or not self.stopped:
            raise OSError("demo target thread was not reaped")

    def Receipt(self) -> dict[str, object]:
        """Return measured service identity/request truth without claiming scanner success.

        Returns:
            Detached target metadata after startup or cleanup, including actual request order.
        """

        with self.lock:
            requests = [dict(request) for request in self.requests]

        return {"schema_version": 1, "bind_host": "127.0.0.1", "port": self.port,
                "requests": requests, "teardown_completed": self.stopped}


class DemoEventOutput(StringIO):
    """Record unchanged product events while optionally displaying concise actual job updates."""

    def __init__(self, journal: TextIO, output: TextIO, *, live: bool) -> None:
        """Retain caller-owned streams; lifetime/cleanup belongs to the orchestration context."""

        super().__init__()
        self.journal = journal
        self.output = output
        self.live = live
        self.pending = ""

    def write(self, text: str) -> int:
        """Tee the exact product text into its owned journal without altering its grammar."""

        self.journal.write(text)
        self.pending += text

        return super().write(text)

    def flush(self) -> None:
        """Flush real journal lines and render selected actual state/model/progress events."""

        self.journal.flush()

        while "\n" in self.pending:
            line, self.pending = self.pending.split("\n", 1)
            document = json.loads(line)

            if self.live and document.get("type") == "event":
                event = document["event"]

                if event["kind"] in {"state", "model_delta", "progress"}:
                    self.output.write(f"{event['sequence']} {event['kind']}: "
                                      f"{json.dumps(event['data'], sort_keys=True)}\n")
                    self.output.flush()

        super().flush()


def SaveDemoArtifact(root: Path, name: str, document: object, artifacts: list[str]) -> None:
    """Publish one fixed derived artifact using the report owner's no-clobber boundary.

    Args:
        root: Newly owned physical output directory.
        name: Fixed first-party relative filename, not operator-supplied content.
        document: Detached strict JSON metadata from actual commands or owning stores.
        artifacts: Invocation-local list of confirmed published material paths.

    Raises:
        ReportFailure: Publication fails, retaining its actual confirmed publication status.
    """

    payload = (json.dumps(document, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")

    try:
        PublishReport(root / name, payload)

    except ReportFailure as error:
        if error.published:
            artifacts.append(name)

        raise

    artifacts.append(name)


def EvidenceIndex(workspace_root: Path) -> dict[str, object]:
    """Index actual owner-read acquisition manifests and verified material bytes.

    Args:
        workspace_root: Existing saved demo workspace independently reopened after scanning.

    Returns:
        Root-relative raw material paths/digests; no invented findings or acquired contents.
    """

    workspace = LocalWorkspaceStore(workspace_root).Open()
    evidence = LocalEvidenceStore(workspace_root / "evidence")
    records = []

    for identity in workspace.evidence_record_references:
        record = evidence.Get(identity)
        evidence.Read(record.reference)

        if record.provenance.workspace_id != workspace.workspace_id:
            raise EvidenceError("demo evidence belongs to another workspace")

        records.append({"evidence_id": identity,
                        "material_path": "workspace/evidence/" + record.reference.locator,
                        "record": record.ToDict()})

    return {"schema_version": 1, "workspace_id": workspace.workspace_id,
            "verified_acquisitions": len(records), "records": records}


def RunLocalDemo(
    path: Path, output: TextIO, *, approve_safe_http: bool = False, json_output: bool = False,
) -> int:
    """Run the real bounded product workflow and retain partial outputs after any failure.

    Args:
        path: New output root beneath an existing physical parent; existing roots reject.
        output: Caller-owned terminal stream; raw acquired bytes are never presented.
        approve_safe_http: Explicit opt-in to only this command-owned localhost service.
        json_output: Emit one schema-v1 outcome instead of concise live job presentation.

    Returns:
        Zero for completed demo, two for configuration, three for denial, four for failure,
        or 130 for interruption. Any export or teardown failure prevents demo success.
    """

    outcome: dict[str, object] = {
        "schema_version": 1, "command": "demo.local", "state": "denied", "exit_status": 3,
        "plan": DemoPlan(), "phase": "approval", "failure": "approval_required",
        "artifacts": [], "commands": [], "target_teardown_completed": None,
        "duration_seconds": 0.0,
    }
    artifacts: list[str] = []
    commands: list[dict[str, object]] = []
    outcome.update({"artifacts": artifacts, "commands": commands})
    started = time.monotonic()
    root: Path | None = None
    target: OwnedDemoTarget | None = None
    phase = "configuration"

    def Invoke(namespace: str, arguments: list[str], filename: str) -> dict[str, object]:
        """Run and retain an actual product receipt, failing on its original exit status."""

        assert root is not None
        captured = StringIO()
        status = RunCommands(namespace, arguments, captured, json_output=True)
        document = json.loads(captured.getvalue())

        if not isinstance(document, dict):
            raise DemoFailure("receipt")

        commands.append({"command": namespace + "." + arguments[0], "exit_status": status,
                         "outcome": document})
        SaveDemoArtifact(root, filename, document, artifacts)

        if status:
            raise DemoFailure(namespace, status)

        return document

    try:
        if type(approve_safe_http) is not bool:
            raise DemoFailure("configuration", 2)

        if approve_safe_http:
            selected = RequireNewDemoRoot(path)
            selected.mkdir(mode=0o700)
            root = selected
            (root / "reports").mkdir(mode=0o700)
            target = OwnedDemoTarget()
            phase = "target"
            target.Start()
            urls = target.Urls()
            workspace = root / "workspace"
            phase = "workspace"
            Invoke("workspace", ["create", str(workspace), "--id", DEMO_WORKSPACE_ID,
                                 "--name", "Owned local Workbench demo"], "workspace-create.json")
            now = datetime.now(UTC)
            scope = ["create", str(workspace), "--id", DEMO_SCOPE_ID,
                     "--allow-ip", "127.0.0.1", "--grant-consent", "--owner", DEMO_OWNER,
                     "--consent-reference", "consent:command-owned-local-demo",
                     "--valid-from", (now - timedelta(seconds=1)).isoformat(),
                     "--valid-until", (now + timedelta(seconds=120)).isoformat()]

            for url in urls:
                scope.extend(("--allow-url", url))

            phase = "scope"
            Invoke("scope", scope, "scope-create.json")
            scan = ["quick", str(workspace), "--scope", DEMO_SCOPE_ID, "--owner", DEMO_OWNER,
                    "--approve-safe-http", "--max-endpoints", "3", "--request-timeout", "2",
                    "--interval", "0.1", "--timeout", "15", "--events-json"]

            for url in urls:
                scan.extend(("--target", url))

            phase = "scan"

            with (root / "events.jsonl").open("x", encoding="utf-8") as journal:
                artifacts.append("events.jsonl")
                events = DemoEventOutput(journal, output, live=not json_output)
                status = RunCommands("scan", scan, events)
                lines = [json.loads(line) for line in events.getvalue().splitlines()]

            summary = lines[-1].get("summary", lines[-1])
            commands.append({"command": "scan.quick", "exit_status": status,
                             "outcome": {key: value for key, value in summary.items()
                                         if key not in {"job", "events"}}})
            SaveDemoArtifact(root, "scan-summary.json" if "job" in summary else (
                "scan-failure.json"), summary, artifacts)

            if status:
                raise DemoFailure("scan", status)

            phase = "reopen"
            Invoke("workspace", ["open", str(workspace)], "workspace-open.json")
            phase = "export"

            for format_name, name in (("json", "model.json"), ("sarif", "model.sarif")):
                captured = StringIO()
                status = RunReportCommands(
                    ["export", str(workspace), "--format", format_name,
                     "--output", str(root / "reports" / name)], captured, json_output=True,
                )
                receipt = json.loads(captured.getvalue())
                commands.append({"command": "report.export", "exit_status": status,
                                 "outcome": receipt})

                if receipt["output_published"]:
                    artifacts.append("reports/" + name)

                SaveDemoArtifact(root, f"reports/{format_name}-export.json", receipt, artifacts)

                if status:
                    raise DemoFailure("export", status)

            phase = "index"
            SaveDemoArtifact(root, "evidence-index.json", EvidenceIndex(workspace), artifacts)
            outcome.update({"state": "completed", "exit_status": 0,
                            "phase": "completed", "failure": None})

    except DemoFailure as error:
        outcome.update({"state": "cancelled" if error.status == 130 else (
            "denied" if error.status == 3 else "failed"), "exit_status": error.status,
            "phase": error.phase, "failure": error.phase})

    except ReportFailure as error:
        outcome.update({"state": "cancelled" if error.status == 130 else "failed",
                        "exit_status": error.status, "phase": phase,
                        "failure": error.kind, "artifact_output_published": error.published})

    except KeyboardInterrupt:
        outcome.update({"state": "cancelled", "exit_status": 130,
                        "phase": phase, "failure": "interrupted"})

    except (OSError, ValueError, EvidenceError):
        outcome.update({"state": "failed", "exit_status": 2 if root is None else 4,
                        "phase": phase, "failure": "configuration" if root is None else "storage"})

    except Exception:
        outcome.update({"state": "failed", "exit_status": 4,
                        "phase": phase, "failure": "internal"})

    finally:
        if target is not None:
            try:
                target.Close()
                outcome["target_teardown_completed"] = target.stopped

            except (Exception, KeyboardInterrupt):
                outcome.update({"state": "failed", "exit_status": 4, "phase": "teardown",
                                "failure": "teardown", "target_teardown_completed": False})

            if root is not None:
                try:
                    SaveDemoArtifact(root, "target.json", target.Receipt(), artifacts)

                except (Exception, KeyboardInterrupt):
                    outcome.update({"state": "failed", "exit_status": 4,
                                    "phase": "target-receipt", "failure": "publication"})

    outcome["duration_seconds"] = time.monotonic() - started

    if root is not None:
        try:
            SaveDemoArtifact(root, "demo-summary.json", outcome, [])

        except ReportFailure as error:
            outcome.update({"state": "cancelled" if error.status == 130 else "failed",
                            "exit_status": error.status, "phase": "summary",
                            "failure": error.kind, "summary_output_published": error.published})

        except (Exception, KeyboardInterrupt):
            outcome.update({"state": "failed", "exit_status": 4,
                            "phase": "summary", "failure": "publication"})

    if json_output:
        output.write(json.dumps(outcome, sort_keys=True, allow_nan=False) + "\n")

    elif not approve_safe_http:
        output.write("Local demo plan: own 127.0.0.1 on an ephemeral port; GET only /, /health "
                     "and /redirect with native SAFE discovery; retain workspace/events/evidence "
                     "and saved-model JSON/SARIF; stop the service.\n"
                     "Explicit --approve-safe-http is required. No resources were started.\n")

    else:
        output.write(f"Local demo {outcome['state']} (exit {outcome['exit_status']}); "
                     f"phase {outcome['phase']}; target teardown "
                     f"{outcome['target_teardown_completed']}.\n")

        if root is not None:
            output.write(f"Retained output: {root}\n")

    output.flush()

    return int(str(outcome["exit_status"]))
