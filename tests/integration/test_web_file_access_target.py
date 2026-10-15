# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise actual owned file reads, containment controls and bounded target lifecycle."""

from __future__ import annotations

import hashlib
import http.client
import os
import socket
from pathlib import Path
from threading import Event
from unittest.mock import patch
from urllib.parse import urlsplit

import pytest

from tests import web_file_access_helpers as helpers
from tests.web_file_access_helpers import Oracle, OwnedWebFileAccessTarget, TargetModule


def Request(url: str, *, headers: dict[str, str] | None = None) -> tuple[int, str, bytes]:
    """Send one literal-loopback request with its explicit query and no automatic redirects."""

    parsed = urlsplit(url)
    assert parsed.hostname == "127.0.0.1", "Target probes must use the owned loopback listener"
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=2)

    try:
        connection.request("GET", parsed.path + "?" + parsed.query, headers=headers or {})
        response = connection.getresponse()

        return response.status, str(response.getheader("Content-Type")), response.read()

    finally:
        connection.close()


@pytest.mark.parametrize("case", Oracle()["cases"], ids=lambda case: case["id"])
def test_ActualFileBehaviorMatchesIndependentOracle(tmp_path, case):
    """Every expected outcome must result from real owned filesystem or explicit no-read control."""

    with OwnedWebFileAccessTarget(tmp_path) as target:
        assert not target.Observe()["requests"], "Readiness must not hide an extra target request"
        status, content_type, body = Request(target.Url(case))
        expected = case["expected_behavior"]
        assert (status, content_type, body.decode()) == (
            case["expected_status"], expected["content_type"], expected["body"],
        ), "Actual HTTP response must agree with the independently authored mechanism oracle"
        observed = target.Observe()
        assert observed["requests"] == [case["route"]], "Only the selected query may be requested"
        assert [record["path"] for record in observed["file_reads"]] == expected["file_reads"], (
            "Actual file read paths must distinguish disclosure from a denied or decoy response"
        )
        assert observed["denials"] == expected["denials"], "Policy denials must remain explicit"
        assert observed["errors"] == expected["errors"], "Filesystem failure state must be truthful"

        for record in observed["file_reads"]:
            assert record == {
                "input": expected["input"], "path": expected["file_reads"][0],
                "size_bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
            }, "Read metadata must bind actual input, owned path and disclosed bytes"

    assert not target.root.exists() and not target.thread.is_alive(), (
        "Every scenario must remove its synthetic tree and join its owned service thread"
    )


def test_PrivateDisclosureChangesWithOwnedFileAndFixedDenialPrecedesFilesystem(tmp_path):
    """Changing fixture bytes changes the vulnerable response; fixed input never opens a file."""

    with OwnedWebFileAccessTarget(tmp_path) as target:
        changed = b"independent-owned-file-revision\n"
        (target.root / "private/canary.txt").write_bytes(changed)
        assert Request(target.Url("private-traversal"))[2] == changed, (
            "The vulnerability must read actual file bytes instead of returning a canary branch"
        )
        assert target.Observe()["file_reads"][0]["sha256"] == hashlib.sha256(changed).hexdigest(), (
            "Independent read metadata must describe the actual changed file"
        )
        fixed_url = target.Url("fixed-traversal")

        with patch.object(Path, "open", side_effect=AssertionError("unexpected file open")):
            with patch.object(Path, "stat", side_effect=AssertionError("unexpected file stat")):
                assert Request(fixed_url)[0] == 403, "Fixed containment must precede filesystem IO"

        assert len(target.Observe()["file_reads"]) == 1, "A fixed refusal must add no file read"


def test_DeclaredMissingFileReflectsRealFilesystemState(tmp_path):
    """The missing control becomes readable only when its explicitly owned file actually exists."""

    with OwnedWebFileAccessTarget(tmp_path) as target:
        url = target.Url("missing-control")
        assert Request(url)[0] == 404, "The absent owned file must produce a genuine missing state"
        created = b"newly-created-owned-control\n"
        (target.root / "private/missing.txt").write_bytes(created)
        assert Request(url)[2] == created, "The declared missing route must consult actual storage"
        assert target.Observe()["file_reads"][0]["path"] == "private/missing.txt", (
            "A later actual read must identify the previously absent owned file"
        )


@pytest.mark.parametrize("failure", ["oversized", "directory", "symlink", "fifo"])
def test_InvalidOwnedFileIsRejectedBeforeAnyContentRead(tmp_path, failure):
    """Reject excessive, linked and nonregular targets without opening candidate file content."""

    with OwnedWebFileAccessTarget(tmp_path) as target:
        candidate = target.root / "private/canary.txt"
        candidate.unlink()

        if failure == "oversized":
            candidate.write_bytes(b"x" * 257)

        elif failure == "directory":
            candidate.mkdir()

        elif failure == "symlink":
            other = tmp_path / "separate-owned-canary.txt"
            other.write_bytes(b"separate-owned-content-must-not-be-read")

            try:
                candidate.symlink_to(other)

            except (OSError, NotImplementedError):
                pytest.skip("This platform cannot create a fixture-owned symbolic link")

        else:
            if not hasattr(os, "mkfifo"):
                pytest.skip("This platform does not support fixture-owned FIFOs")

            os.mkfifo(candidate)

        url = target.Url("private-traversal")

        with patch.object(Path, "open", side_effect=AssertionError("unexpected file open")):
            assert Request(url) == (500, "text/plain", b"owned-file-unavailable"), (
                "Invalid file metadata must fail before opening any bytes"
            )

        assert target.Observe()["file_reads"] == [], "Rejected file kinds must not become reads"
        assert target.Observe()["errors"] == ["owned-file-unavailable"], (
            "A filesystem refusal must not be mislabeled as public-containment policy"
        )


@pytest.mark.parametrize("directory", ["public", "private"])
def test_SymbolicDirectoryLinksAreRejectedBeforeContentRead(tmp_path, directory):
    """Reject linked path components even when their destinations contain owned regular files."""

    with OwnedWebFileAccessTarget(tmp_path) as target:
        component = target.root / directory
        separate = tmp_path / (directory + "-separate-owned-directory")
        component.rename(separate)

        try:
            component.symlink_to(separate, target_is_directory=True)

        except (OSError, NotImplementedError):
            pytest.skip("This platform cannot create a fixture-owned directory symbolic link")

        url = target.Url("private-traversal")

        with patch.object(Path, "open", side_effect=AssertionError("unexpected file open")):
            assert Request(url) == (500, "text/plain", b"owned-file-unavailable"), (
                "A symbolic link in either joined directory must fail before opening bytes"
            )

        observed = target.Observe()
        assert observed["file_reads"] == [], "Linked directories must not become read evidence"
        assert observed["errors"] == ["owned-file-unavailable"], (
            "Directory symbolic-link refusal must preserve truthful filesystem failure state"
        )


@pytest.mark.parametrize("raw,headers", [
    ("/files/vulnerable?name=../../separate-owned-canary.txt", {}),
    ("/files/vulnerable?name=%2Fprivate%2Fcanary.txt", {}),
    ("/files/vulnerable?name=..%252Fprivate%252Fcanary.txt", {}),
    ("/files/vulnerable?name=..%2fprivate%2fcanary.txt", {}),
    ("/files/vulnerable?name=hello.txt&name=../private/canary.txt", {}),
    ("/files/vulnerable?name=hello.txt&extra=private-value", {}),
    ("/files/vulnerable?name=hello.txt#private-value", {}),
    ("/files/vulnerable?name=" + "x" * 1024, {}),
    ("/files/vulnerable?name=hello.txt", {"Authorization": "owned-private-authorization"}),
    ("/files/vulnerable?name=hello.txt", {"Proxy-Authorization": "owned-private-proxy"}),
    ("/files/vulnerable?name=hello.txt", {"Cookie": "owned-private-cookie"}),
    ("/files/vulnerable?name=hello.txt", {"Content-Length": "1"}),
    ("/files/vulnerable?name=hello.txt", {"Transfer-Encoding": "chunked"}),
])
def test_UnknownRawInputHasNoFilesystemEffectsAndIsRedacted(tmp_path, raw, headers):
    """Reject arbitrary spelling, query expansion and credentials before any filesystem lookup."""

    with OwnedWebFileAccessTarget(tmp_path) as target:
        connection = http.client.HTTPConnection("127.0.0.1", target.server.server_port, timeout=2)

        try:
            with patch.object(Path, "open", side_effect=AssertionError("unexpected file open")):
                with patch.object(Path, "stat", side_effect=AssertionError("unexpected file stat")):
                    connection.request("GET", raw, headers=headers)
                    response = connection.getresponse()
                    assert response.status == 404, "Unknown input must fail before filesystem IO"
                    assert response.read() == b"unknown-owned-route", "Refusal body must stay fixed"

        finally:
            connection.close()

        assert target.Observe() == {
            "requests": ["<rejected>"], "file_reads": [], "denials": [], "errors": [],
        }, "Rejected request values must not leak into target observations or execute a file read"


@pytest.mark.parametrize("lengths", [("0", "10"), ("10", "0"), ("0", "0")])
def test_DuplicateContentLengthIsRejectedBeforeFilesystem(tmp_path, lengths):
    """Refuse duplicate body framing before any file lookup regardless of header ordering."""

    with OwnedWebFileAccessTarget(tmp_path) as target:
        connection = http.client.HTTPConnection("127.0.0.1", target.server.server_port, timeout=2)

        try:
            with patch.object(Path, "open", side_effect=AssertionError("unexpected file open")):
                with patch.object(Path, "stat", side_effect=AssertionError("unexpected file stat")):
                    connection.putrequest("GET", "/files/vulnerable?name=hello.txt")

                    for length in lengths:
                        connection.putheader("Content-Length", length)

                    connection.endheaders()
                    response = connection.getresponse()
                    assert response.status == 404, "Duplicate body framing must precede file IO"
                    assert response.read() == b"unknown-owned-route", "Refusal body must stay fixed"

        finally:
            connection.close()

        assert target.Observe() == {
            "requests": ["<rejected>"], "file_reads": [], "denials": [], "errors": [],
        }, "Duplicate body framing must be redacted and must not cause filesystem effects"


@pytest.mark.parametrize("value", ["../../outside", "/absolute", "hello.txt\x00", None, []])
def test_DirectUnknownFileInputIsRejectedBeforeFilesystem(tmp_path, value):
    """The mechanism boundary also refuses direct calls outside its finite owned-input contract."""

    module = TargetModule()
    state = module.FileAccessState(tmp_path)

    with patch.object(Path, "stat", side_effect=AssertionError("unexpected file stat")):
        with pytest.raises(ValueError, match="reviewed owned file"):
            state.ReadFile(value, fixed=False)

    assert state.Observe()["file_reads"] == [], "Invalid direct input must not create read evidence"


def test_PartialHeaderCleanupDoesNotExecuteTheApparentFileRequest(tmp_path):
    """Owned shutdown interrupts actual reads before their deliberately longer deadline."""

    connection = None
    target = None
    reading = Event()
    accepted: list[socket.socket] = []
    interruptions: list[bool] = []
    read_count = 0
    read_into = socket.SocketIO.readinto
    shutdown = socket.socket.shutdown

    def ReadInto(reader, buffer):
        """Observe real owned socket reads with a deadline longer than the unchanged join bound."""

        nonlocal read_count

        if target is not None:
            with target.server.lock:
                owned = next((request for request in target.server.active
                              if request.fileno() == reader.fileno()), None)

            if owned is not None and not target.server.closing.is_set():
                if not accepted:
                    owned.settimeout(10)
                    accepted.append(owned)

                read_count += 1

                if read_count >= 2:
                    reading.set()

        return read_into(reader, buffer)

    def Shutdown(request, how):
        """Record successful kernel interruption without changing its behavior or taking a lock."""

        if request not in accepted or how != socket.SHUT_RDWR:
            return shutdown(request, how)

        interruptions.append(False)
        shutdown(request, how)
        interruptions[-1] = True

    try:
        with patch.object(socket.SocketIO, "readinto", ReadInto):
            with patch.object(socket.socket, "shutdown", Shutdown):
                with OwnedWebFileAccessTarget(tmp_path) as target:
                    connection = socket.create_connection(
                        ("127.0.0.1", target.server.server_port), timeout=2)
                    connection.sendall(
                        b"GET /files/vulnerable?name=..%2Fprivate%2Fcanary.txt HTTP/1.1\r\n"
                        b"Host: partial")
                    assert reading.wait(2), "The owned handler must read the incomplete header"
                    assert accepted[0].gettimeout() == 10, (
                        "Natural read expiry must exceed the unchanged three-second join bound"
                    )

        assert interruptions == [True], "Cleanup must successfully interrupt the owned read"

        try:
            remaining = connection.recv(1)

        except ConnectionResetError:
            remaining = b""

        assert remaining == b"", "The owned accepted socket must be closed on exit"
        assert target.Observe() == {
            "requests": [], "file_reads": [], "denials": [], "errors": [],
        }, "Closing a partial header must not execute its apparent file read"
        assert not target.server.active and target.server.socket.fileno() == -1, (
            "Cleanup must release every accepted socket and the listener"
        )
        assert not target.thread.is_alive() and not target.root.exists(), (
            "Cleanup must join the service thread before deleting its owned tree"
        )

    finally:
        if connection is not None:
            connection.close()

        if target is not None:
            target.thread.join(timeout=3)
            assert not target.thread.is_alive(), "A failed interruption probe must also be reaped"


def test_BodyFailureAndObservationMutationPreserveOwnership(tmp_path):
    """Context failure still cleans resources and detached observations cannot change read facts."""

    with pytest.raises(RuntimeError, match="owned-body-failure"):
        with OwnedWebFileAccessTarget(tmp_path) as target:
            Request(target.Url("private-traversal"))
            observed = target.Observe()
            observed["file_reads"][0]["path"] = "changed-observation"
            assert target.Observe()["file_reads"][0]["path"] == "private/canary.txt", (
                "Returned observations must not mutate actual mechanism truth"
            )

            raise RuntimeError("owned-body-failure")

    assert not target.thread.is_alive() and not target.root.exists(), (
        "The owner must release thread and synthetic files after test-body failure"
    )


def test_PreDispatchServiceFailureCannotHangCleanup(tmp_path):
    """A failed request loop retains fixed failure evidence and releases all owned resources."""

    module = TargetModule()
    entered, release = Event(), Event()

    class FailingServer(module.FileAccessServer):
        """Fail before HTTP dispatch after deterministic test synchronization."""

        def HandleRequest(self) -> None:
            """Expose startup, then fail without entering BaseServer private shutdown code."""

            entered.set()
            release.wait(timeout=2)

            raise RuntimeError("owned-file-service-failure")

        handle_request = HandleRequest

    module.FileAccessServer = FailingServer

    with patch.object(helpers, "TargetModule", return_value=module):
        with OwnedWebFileAccessTarget(tmp_path) as target:
            assert entered.wait(2), "The failing owned loop must expose its start"
            release.set()
            target.thread.join(timeout=2)
            assert target.Observe()["errors"] == ["listener-failure"], (
                "Unexpected service failure must not disappear from target evidence"
            )

    assert not target.thread.is_alive() and not target.root.exists(), "Failed startup must clean up"
    assert target.server.socket.fileno() == -1, "Failed startup must close its bound listener"
