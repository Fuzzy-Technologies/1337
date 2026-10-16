# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite loopback file-access target with actual owned traversal and containment controls."""

from __future__ import annotations

import hashlib
import json
import posixpath
import socket
import stat
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path, PurePosixPath
from threading import Event, Lock
from typing import Any, cast
from urllib.parse import parse_qs, quote

PUBLIC_BYTES = b"owned-public-file\n"
PRIVATE_BYTES = b"owned-private-file-canary\n"
MAX_REQUEST_BYTES = 1024
MAX_FILE_BYTES = 256
PUBLIC_INPUT = "hello.txt"
PRIVATE_INPUT = "../private/canary.txt"
MISSING_INPUT = "../private/missing.txt"
INPUTS = frozenset((PUBLIC_INPUT, PRIVATE_INPUT, MISSING_INPUT))
ROUTES = {
    "/files/vulnerable?name=" + quote(PUBLIC_INPUT, safe=""): "vulnerable",
    "/files/vulnerable?name=" + quote(PRIVATE_INPUT, safe=""): "vulnerable",
    "/files/fixed?name=" + quote(PRIVATE_INPUT, safe=""): "fixed",
    "/files/fixed?name=" + quote(PUBLIC_INPUT, safe=""): "fixed",
    "/files/vulnerable?name=" + quote(MISSING_INPUT, safe=""): "vulnerable",
    "/files/decoy?name=" + quote(PRIVATE_INPUT, safe=""): "decoy",
}
OWNED_PATHS = frozenset(("public/hello.txt", "private/canary.txt", "private/missing.txt"))


class PublicContainmentError(PermissionError):
    """The fixed variant refused a declared path before inspecting private filesystem state."""


class FileAccessState:
    """Retain actual non-secret request and filesystem observations independently of the oracle."""

    def __init__(self, root: Path) -> None:
        """Bind a helper-created temporary root and synchronized detached observation records."""

        self.root = root
        self.lock = Lock()
        self.records: dict[str, list[Any]] = {
            "requests": [], "file_reads": [], "denials": [], "errors": [],
        }

    def Record(self, kind: str, value: Any) -> None:
        """Retain only fixed codes, declared inputs and actual owned-file read metadata."""

        with self.lock:
            self.records[kind].append(value)

    def Observe(self) -> dict[str, list[Any]]:
        """Return detached facts without consulting expected matches or source metadata."""

        with self.lock:
            return deepcopy(self.records)

    def ReadFile(self, value: str, *, fixed: bool) -> bytes:
        """Join one declared input to public while keeping every read inside owned root."""

        if not isinstance(value, str) or value not in INPUTS or not isinstance(fixed, bool):
            raise ValueError("Only reviewed owned file inputs are supported")

        relative = PurePosixPath(posixpath.normpath("public/" + value))

        if relative.as_posix() not in OWNED_PATHS:
            raise ValueError("File input is outside the declared owned tree")

        if fixed and not relative.is_relative_to("public"):
            raise PublicContainmentError("File input leaves the public subtree")

        public = self.root / "public"
        candidate = public / value
        guarded = [self.root, public]
        current = self.root

        for part in relative.parts:
            current /= part
            guarded.append(current)

        if any(path.is_symlink() for path in guarded):
            raise OSError("Owned file paths cannot contain symbolic links")

        canonical_root = self.root.resolve(strict=True)
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(canonical_root)

        if fixed:
            resolved.relative_to(public.resolve(strict=True))

        information = candidate.stat()

        if not stat.S_ISREG(information.st_mode) or information.st_size > MAX_FILE_BYTES:
            raise OSError("Owned input must be a bounded regular file")

        with candidate.open("rb") as stream:
            body = stream.read(MAX_FILE_BYTES + 1)

        if len(body) > MAX_FILE_BYTES:
            raise OSError("Owned file changed beyond its byte budget")

        self.Record("file_reads", {
            "input": value, "path": relative.as_posix(), "size_bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        })

        return body


class FileAccessHandler(BaseHTTPRequestHandler):
    """Expose exactly six explicit query cases without providing a general file-serving endpoint."""

    server_version = "1337OwnedFileAccess/1"
    sys_version = ""

    def do_GET(self) -> None:
        """Reject unknown raw requests before decoding, filesystem inspection or mechanism work."""

        server = cast(FileAccessServer, self.server)

        if server.closing.is_set():
            return

        state = server.state
        rejected = (
            len(self.path.encode("utf-8")) > MAX_REQUEST_BYTES or self.path not in ROUTES
            or any(name in self.headers for name in (
                "Authorization", "Proxy-Authorization", "Cookie", "Transfer-Encoding"))
            or self.headers.get_all("Content-Length", ["0"]) != ["0"]
        )

        if rejected:
            state.Record("requests", "<rejected>")
            self.Reply(404, b"unknown-owned-route", "text/plain")

            return

        state.Record("requests", self.path)
        mode = ROUTES[self.path]
        value = parse_qs(self.path.partition("?")[2], strict_parsing=True)["name"][0]

        if mode == "decoy":
            body = json.dumps({"documentation": "Example: owned-private-file-canary"},
                              separators=(",", ":"), sort_keys=True).encode()
            self.Reply(200, body, "application/json")

            return

        try:
            body = state.ReadFile(value, fixed=mode == "fixed")

        except PublicContainmentError:
            state.Record("denials", "public-containment")
            self.Reply(403, b"public-path-required", "text/plain")

        except FileNotFoundError:
            state.Record("errors", "owned-file-missing")
            self.Reply(404, b"owned-file-missing", "text/plain")

        except (OSError, ValueError):
            state.Record("errors", "owned-file-unavailable")
            self.Reply(500, b"owned-file-unavailable", "text/plain")

        else:
            self.Reply(200, body, "text/plain")

    def Reply(self, status: int, body: bytes, content_type: str) -> None:
        """Send a finite response and close the connection without incidental request logging."""

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")

        try:
            self.end_headers()
            self.wfile.write(body)

        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format: str, *arguments: object) -> None:
        """Suppress arbitrary request/error text instead of retaining untrusted values."""


class FileAccessServer(HTTPServer):
    """Own an ephemeral loopback listener and every accepted socket for bounded fixture cleanup."""

    def __init__(self, root: Path) -> None:
        """Initialize ownership before binding the sole literal-loopback HTTP listener."""

        self.state = FileAccessState(root)
        self.closing = Event()
        self.accepted = Event()
        self.lock = Lock()
        self.active: set[socket.socket] = set()
        super().__init__(("127.0.0.1", 0), FileAccessHandler)
        self.timeout = 0.05

    def GetRequest(self) -> tuple[socket.socket, tuple[str, int]]:
        """Track bounded accepted sockets before a handler can wait for incomplete HTTP input."""

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
        """Close accepted input and release its owned active-socket record on every exit."""

        try:
            super().shutdown_request(request)

        finally:
            with self.lock:
                self.active.discard(request)

    shutdown_request = ShutdownRequest

    def CloseActiveRequests(self) -> None:
        """Interrupt pending input before the context owner joins the service thread."""

        self.closing.set()

        with self.lock:
            for request in self.active:
                try:
                    request.shutdown(socket.SHUT_RDWR)

                except OSError:
                    pass

                request.close()

    def HandleError(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        """Retain fixed failure evidence without printing untrusted requests or cleanup races."""

        if not self.closing.is_set():
            self.state.Record("errors", "handler-failure")

    handle_error = HandleError
