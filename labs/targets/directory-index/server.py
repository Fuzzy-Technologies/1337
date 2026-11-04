# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Own a finite filesystem-backed directory-index target for 1337Scope (Litoscope) tests."""

from __future__ import annotations

import hashlib
import html
import socketserver
from copy import deepcopy
from pathlib import Path
from threading import Lock
from typing import Any, cast
from urllib.parse import quote

_CASES = frozenset({"listed", "fixed", "tutorial", "comment", "hidden", "wrong-media",
    "redirect", "unfinished-html", "truncated", "overrun", "oversized", "ambiguous-framing"})


def IndexDocument(path: str, entries: tuple[str, ...], *, hidden: bool = False) -> bytes:
    """Render exact owned names as inert relative anchors without consulting scanner predicates."""

    links = "\n".join('<a href="' + quote(name, safe="/") + '">'
                      + html.escape(name) + "</a>" for name in entries)
    bodyAttributes = ' hidden="hidden"' if hidden else ""

    return ('<!DOCTYPE html><html><head><title>Index of ' + path + '</title></head><body'
            + bodyAttributes + '><h1>Index of ' + path + '</h1><hr><pre>'
            + '<a href="../">Parent Directory</a>\n' + links + '</pre><hr></body></html>').encode()


class DirectoryTarget(socketserver.TCPServer):
    """Bind only the test's ephemeral loopback socket and explicitly supplied owned directory."""

    def __init__(self, root: Path) -> None:
        """Keep finite non-secret acquisition facts independently of detector output and oracles."""

        self.root = root
        self.lock = Lock()
        self.records: dict[str, list[Any]] = {
            "requests": [], "directory_reads": [], "responses": [], "errors": [],
        }
        super().__init__(("127.0.0.1", 0), DirectoryRequest)

    def Record(self, kind: str, value: Any) -> None:
        """Append one bounded target-side observation under the fixture-owned lock."""

        with self.lock:
            self.records[kind].append(value)

    def Observe(self) -> dict[str, list[Any]]:
        """Detach target facts without deriving any expected scanner matches."""

        with self.lock:
            return deepcopy(self.records)

    def Entries(self) -> tuple[str, ...]:
        """Actually enumerate the owned directory without opening or serving any file contents."""

        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError("Owned directory root is unavailable")

        entries = []

        for entry in sorted(self.root.iterdir(), key=lambda item: item.name):
            if entry.is_symlink() or not entry.is_file() and not entry.is_dir():
                raise ValueError("Owned directory entries must be ordinary files or directories")

            entries.append(entry.name + ("/" if entry.is_dir() else ""))

        if not 1 <= len(entries) <= 64:
            raise ValueError("Owned directory entry budget differs")

        result = tuple(entries)
        self.Record("directory_reads", list(result))

        return result


class DirectoryRequest(socketserver.StreamRequestHandler):
    """Serve only finite reviewed routes and raw-wire failure controls on the owned listener."""

    def handle(self) -> None:
        """Read one bounded request, record it and never implement a followed file destination."""

        server = cast(DirectoryTarget, self.server)
        self.connection.settimeout(2)
        request = self.rfile.readline(2048)

        try:
            method, route, protocol = request.decode("ascii").rstrip("\r\n").split(" ")

        except (UnicodeError, ValueError):
            server.Record("errors", "request-shape")

            return

        server.Record("requests", route)
        case = route.removeprefix("/listing/").removesuffix("/")

        if method != "GET" or protocol != "HTTP/1.1" or case not in _CASES or (
            route != "/listing/" + case + "/"
        ):
            self.wfile.write(b"HTTP/1.1 404 Owned\r\nContent-Length: 0\r\n"
                             b"Connection: close\r\n\r\n")

            return

        for _ in range(64):
            line = self.rfile.readline(4096)

            if line == b"\r\n":
                break

            if not line or len(line) >= 4096 or line.lower().startswith((
                b"authorization:", b"cookie:", b"transfer-encoding:",
            )):
                server.Record("errors", "request-headers")

                return

        else:
            server.Record("errors", "request-headers")

            return

        status, media, body = 200, "text/html; charset=utf-8", b""

        if case == "listed":
            body = IndexDocument(route, server.Entries())

        elif case == "fixed":
            status, media, body = 403, "text/plain", b"owned-directory-enumeration-denied"

        elif case == "tutorial":
            body = (b"<!DOCTYPE html><html><head><title>Directory tutorial</title></head>"
                    b"<body><h1>Directory tutorial</h1><p>Index of /listing/listed/</p>"
                    b'<pre>&lt;a href="example.txt"&gt;example.txt&lt;/a&gt;</pre></body></html>')

        elif case == "comment":
            body = IndexDocument(route, ()).replace(b"</pre>",
                b'<!-- <a href="owned-comment.txt">owned-comment.txt</a> --></pre>')

        elif case == "hidden":
            body = IndexDocument(route, ("owned-hidden.txt",), hidden=True)

        elif case == "redirect":
            status, media, body = 302, "text/plain", b"owned-redirect-unfollowed"

        else:
            body = IndexDocument(route, ("owned-wire-control.txt",))

            if case == "wrong-media":
                media = "text/plain"

            elif case == "unfinished-html":
                body += b"<!--unfinished"

            elif case == "oversized":
                body = b"x" * 4097

        header = (f"HTTP/1.1 {status} Owned\r\nContent-Type: {media}\r\n"
                  f"Content-Length: {len(body)}\r\nConnection: close\r\n").encode()

        if case == "redirect":
            header += b"Location: /listing/listed/\r\n"

        if case == "ambiguous-framing":
            header += b"Content-Length: 1\r\n"

        transmitted = body[:-10] if case == "truncated" else body

        if case == "overrun":
            transmitted += b"unexpected-unframed-tail"

        server.Record("responses", {"status": status, "body_size": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest()})

        try:
            self.wfile.write(header + b"\r\n" + transmitted)

        except (BrokenPipeError, ConnectionResetError):
            pass
