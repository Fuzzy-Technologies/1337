# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite loopback target with real owned-file, SQLite and HTML reflection behavior."""

from __future__ import annotations

import hashlib
import html
import json
import socket
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Event, Lock
from typing import Any, cast
from urllib.parse import quote, unquote

HEAD_BYTES = b"ref: refs/heads/owned-fixture\n"
SQL_TRUE = "' OR is_hidden=1 --"
SQL_FALSE = "' OR is_hidden=2 --"
SQL_INPUTS = frozenset(("public", SQL_TRUE, SQL_FALSE))
REFLECTION_INPUT = "<fuzzy1337-probe>owned</fuzzy1337-probe>"
GIT_ROUTES = {
    "/git/vulnerable/.git/HEAD": "vulnerable",
    "/git/fixed/.git/HEAD": "fixed",
    "/git/decoy/.git/HEAD": "decoy",
}
SQL_ROUTES = {
    "/sql/vulnerable/public": "vulnerable",
    "/sql/vulnerable/" + quote(SQL_TRUE, safe="="): "vulnerable",
    "/sql/vulnerable/" + quote(SQL_FALSE, safe="="): "vulnerable",
    "/sql/fixed/" + quote(SQL_TRUE, safe="="): "fixed",
    "/sql/decoy/" + quote(SQL_TRUE, safe="="): "decoy",
}
REFLECTION_ROUTES = {
    f"/reflect/{mode}/" + quote(REFLECTION_INPUT, safe="/"): mode
    for mode in ("vulnerable", "fixed", "decoy")
}
KNOWN_ROUTES = frozenset((*GIT_ROUTES, *SQL_ROUTES, *REFLECTION_ROUTES, "/redirect"))
MAX_PATH_BYTES = 1024
MAX_FILE_BYTES = 256


@contextmanager
def OwnedReadonlyDatabase() -> Iterator[sqlite3.Connection]:
    """Seed non-secret memory rows, then deny every SQL action except reading those rows."""

    with closing(sqlite3.connect(":memory:")) as database:
        database.execute("CREATE TABLE records (label TEXT, is_hidden INTEGER, marker TEXT)")
        database.executemany("INSERT INTO records VALUES (?, ?, ?)", (
            ("public", 0, "owned-public-row"), ("private", 1, "owned-private-row"),
        ))
        database.commit()
        database.execute("PRAGMA query_only = ON")
        remaining_callbacks = 100

        def Authorize(action: int, first: str | None, second: str | None,
                      database_name: str | None, trigger: str | None) -> int:
            """Confine query execution to SELECT and the three fixture-owned columns."""

            allowed_read = (action == sqlite3.SQLITE_READ and first == "records"
                            and second in ("label", "is_hidden", "marker")
                            and database_name == "main")

            return sqlite3.SQLITE_OK if action == sqlite3.SQLITE_SELECT or allowed_read else (
                sqlite3.SQLITE_DENY)

        def BoundInstructions() -> int:
            """Interrupt unexpected query work after a finite virtual-machine budget."""

            nonlocal remaining_callbacks
            remaining_callbacks -= 1

            return int(remaining_callbacks <= 0)

        database.set_authorizer(Authorize)
        database.set_progress_handler(BoundInstructions, 100)

        yield database


def SelectRows(value: str, *, parameterized: bool) -> list[str]:
    """Execute one finite input through genuine interpolated or parameterized SQL."""

    if value not in SQL_INPUTS:
        raise ValueError("Only the finite reviewed SQLite inputs are accepted")

    with OwnedReadonlyDatabase() as database:
        if parameterized:
            cursor = database.execute(
                "SELECT marker FROM records WHERE label = ? AND is_hidden = 0", (value,))

        else:
            cursor = database.execute(
                f"SELECT marker FROM records WHERE label = '{value}' AND is_hidden = 0")

        return [str(row[0]) for row in cursor.fetchall()]


class TargetState:
    """Keep independent mechanism observations; response and oracle labels are not evidence."""

    def __init__(self, root: Path) -> None:
        """Use only the explicitly supplied temporary root and synchronized non-secret records."""

        self.root = root
        self.lock = Lock()
        self.records: dict[str, list[Any]] = {
            "requests": [], "file_reads": [], "queries": [], "reflections": [], "errors": [],
        }

    def Observe(self) -> dict[str, list[Any]]:
        """Copy target-side truth independently of a scanner's output and expected matches."""

        with self.lock:
            return deepcopy(self.records)

    def Record(self, kind: str, value: Any) -> None:
        """Append one finite mechanism fact without retaining arbitrary headers or request input."""

        with self.lock:
            self.records[kind].append(value)

    def ReadHead(self) -> bytes:
        """Read the actual bounded owned HEAD file, rejecting missing files and symbolic links."""

        public = self.root / "public"
        git = public / ".git"
        head = git / "HEAD"

        if any(path.is_symlink() for path in (self.root, public, git, head)):
            raise OSError("Owned HEAD cannot be a symbolic link")

        if not head.is_file():
            raise OSError("Owned HEAD must be a regular file")

        head.resolve(strict=True).relative_to(self.root.resolve(strict=True))

        with head.open("rb") as stream:
            body = stream.read(MAX_FILE_BYTES + 1)

        if len(body) > MAX_FILE_BYTES:
            raise OSError("Owned HEAD exceeds the finite fixture budget")

        self.Record("file_reads", {
            "path": "public/.git/HEAD", "sha256": hashlib.sha256(body).hexdigest(),
        })

        return body


class WebVulnerabilityHandler(BaseHTTPRequestHandler):
    """Serve only the reviewed paths; inputs never select general files, SQL or destinations."""

    server_version = "1337OwnedWebTarget/1"
    sys_version = ""

    def do_GET(self) -> None:
        """Dispatch a finite GET with no credentials, body, query or expansion of supplied input."""

        server = cast(WebVulnerabilityServer, self.server)

        if server.closing.is_set():
            return

        state = server.state
        rejected = (
            len(self.path.encode("utf-8")) > MAX_PATH_BYTES or self.path not in KNOWN_ROUTES
            or "Authorization" in self.headers or "Cookie" in self.headers
            or "Transfer-Encoding" in self.headers
            or self.headers.get_all("Content-Length", ["0"]) != ["0"]
        )

        if rejected:
            state.Record("requests", "<rejected>")
            self.Reply(404, b"unknown-owned-route", "text/plain")

            return

        state.Record("requests", self.path)

        if self.path == "/redirect":
            self.Reply(302, b"owned-redirect", "text/plain",
                       location="/git/vulnerable/.git/HEAD")

        elif self.path in GIT_ROUTES:
            self.GitHead(state, GIT_ROUTES[self.path])

        elif self.path in SQL_ROUTES:
            mode = SQL_ROUTES[self.path]
            value = unquote(self.path.removeprefix(f"/sql/{mode}/"), errors="strict")
            rows = SelectRows(value, parameterized=mode != "vulnerable")
            state.Record("queries", {
                "input": value, "parameterized": mode != "vulnerable", "rows": rows,
            })
            payload: dict[str, object] = {"rows": rows}

            if mode == "decoy":
                payload["documentation"] = "Example hidden canary: owned-private-row"

            self.Reply(200, json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
                       "application/json")

        else:
            mode = REFLECTION_ROUTES[self.path]
            value = unquote(self.path.removeprefix(f"/reflect/{mode}/"), errors="strict")
            insertion = value
            context = "raw"

            if mode == "fixed":
                insertion, context = html.escape(value, quote=True), "escaped"

            elif mode == "decoy":
                insertion, context = "<!-- " + value + " -->", "comment"

            state.Record("reflections", {"input": value, "mode": context})
            body = ('<!doctype html><html><body><main id="reflection">' + insertion
                    + "</main></body></html>")
            self.Reply(200, body.encode(), "text/html; charset=utf-8")

    def GitHead(self, state: TargetState, mode: str) -> None:
        """Expose a real owned file, deny before reading, or serve an unrelated HTML example."""

        if mode == "fixed":
            self.Reply(403, b"dotfile-access-denied", "text/plain")

        elif mode == "decoy":
            self.Reply(200, b"<html><body>HEAD example: <code>ref: refs/heads/owned-fixture\n"
                       b"</code></body></html>", "text/html; charset=utf-8")

        else:
            try:
                body = state.ReadHead()

            except (OSError, ValueError):
                state.Record("errors", "owned-head-unavailable")
                self.Reply(500, b"owned-file-unavailable", "text/plain")

                return

            self.Reply(200, body, "text/plain")

    def Reply(self, status: int, body: bytes, content_type: str,
              *, location: str | None = None) -> None:
        """Write a finite response and close each connection without incidental access logs."""

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")

        if location is not None:
            self.send_header("Location", location)

        try:
            self.end_headers()
            self.wfile.write(body)

        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format: str, *arguments: object) -> None:
        """Discard incidental request text instead of retaining potentially private input."""


class WebVulnerabilityServer(HTTPServer):
    """Own a single ephemeral loopback listener and every currently accepted request socket."""

    def __init__(self, root: Path) -> None:
        """Bind only literal loopback after initializing cleanup and independent observations."""

        self.state = TargetState(root)
        self.closing = Event()
        self.accepted = Event()
        self.lock = Lock()
        self.active: set[socket.socket] = set()
        super().__init__(("127.0.0.1", 0), WebVulnerabilityHandler)
        self.timeout = 0.05

    def GetRequest(self) -> tuple[socket.socket, tuple[str, int]]:
        """Track accepted sockets so teardown interrupts even a dribbled partial HTTP header."""

        request, address = super().get_request()
        request.settimeout(2)

        with self.lock:
            if self.closing.is_set():
                request.close()

                raise OSError("Owned target is closing")

            self.active.add(request)
            self.accepted.set()

        return request, address

    get_request = GetRequest

    def ShutdownRequest(self, request: socket.socket) -> None:
        """Release the socket and remove it from the fixture-owned active set."""

        try:
            super().shutdown_request(request)

        finally:
            with self.lock:
                self.active.discard(request)

    shutdown_request = ShutdownRequest

    def CloseActiveRequests(self) -> None:
        """Stop accepts and interrupt all owned input reads before waiting for the service loop."""

        self.closing.set()

        with self.lock:
            for request in self.active:
                try:
                    request.shutdown(socket.SHUT_RDWR)

                except OSError:
                    pass

                request.close()

    def HandleError(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        """Record unexpected handler failure without printing request contents or shutdown races."""

        if not self.closing.is_set():
            self.state.Record("errors", "handler-failure")

    handle_error = HandleError
