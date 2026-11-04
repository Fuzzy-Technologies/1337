# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Shared isolated receiver admission and original resource representation checks."""

from __future__ import annotations

import gzip
import http.client
import io
import subprocess
from types import SimpleNamespace

import pytest

from fuzzy1337 import intelligence_receiver as receiver
from fuzzy1337 import intelligence_transport as transport
from tests.unit.test_intelligence_acquisition import Connection, Response, Worker


@pytest.mark.parametrize("field,value", [
    ("url", "http://example.invalid/x"), ("url", "https://u:p@example.invalid/x"),
    ("url", "https://example.invalid/x?q=1"), ("url", "https://example.invalid/x#f"),
    ("max_bytes", 0), ("max_bytes", True), ("max_bytes", 16 * 1024 * 1024 + 1),
    ("timeout_seconds", True), ("timeout_seconds", 0.049), ("timeout_seconds", 60.01),
    ("timeout_seconds", float("nan")), ("timeout_seconds", float("inf")),
    ("accept_kind", "html"), ("accept_kind", True), ("accept_kind", b"gzip"),
])
def test_InvalidInternalBoundsRefuseBeforeAnyProcess(monkeypatch, field, value):
    """Profile-independent structure never launches a child on malformed finite input."""

    def Refuse(*args, **kwargs):
        """Make any premature process creation an explicit regression failure."""

        raise AssertionError("Invalid internal receiver input launched a child")

    monkeypatch.setattr(receiver.subprocess, "Popen", Refuse)
    arguments = {"url": "https://example.invalid/x", "max_bytes": 100,
                 "timeout_seconds": 1.0, "accept_kind": "gzip"}
    arguments[field] = value

    with pytest.raises(ValueError):
        receiver.ReceiveIsolatedHttps(**arguments)


@pytest.mark.parametrize("kind,accept", [("json", "application/json"),
                                         ("gzip", "application/gzip")])
def test_ResourcePreferenceNeverDecompressesHttpOrOriginalGzip(monkeypatch, kind, accept):
    """Explicit gzip resource negotiation retains exact bytes and HTTP identity encoding."""

    body = gzip.compress(b"owned synthetic corpus", mtime=0)
    connection = Connection(Response(body=body, headers={"Content-Length": str(len(body))}))
    client = SimpleNamespace(request=connection.Request, getresponse=connection.GetResponse,
                             close=connection.Close)
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", lambda *a, **k: client)
    output = io.BytesIO()
    status = transport.Receive("https://example.invalid/x.gz", len(body), 1.0,
                               output, accept_kind=kind)
    assert status == 0 and output.getvalue().partition(b"\n")[2] == body, (
        "Resource preference changed, decompressed or dropped original gzip bytes"
    )
    assert connection.headers["Accept"] == accept and (
        connection.headers["Accept-Encoding"] == "identity" and connection.closed
    ), "Explicit resource kind altered HTTP framing or leaked its owned connection"


@pytest.mark.parametrize("kind", ["json", "gzip", "zip"])
def test_RealIsolatedWorkerReceivesOnlyTheFixedOptionalArgument(tmp_path, monkeypatch, kind):
    """The real isolated process preserves JSON argv and passes only admitted optional modes."""

    expected = [] if kind == "json" else [kind]
    Worker(tmp_path, monkeypatch,
           f'import sys\nassert sys.argv[4:] == {expected!r}\n'
           'assert sys.flags.isolated and sys.flags.no_site\n'
           'sys.stdout.buffer.write(b\'{"status":200}\\noriginal-gzip-body\')\n')
    body, state, http_status = receiver.ReceiveIsolatedHttps(
        "https://example.invalid/owned.gz", 100, 2.0, accept_kind=kind,
    )
    assert (body, state, http_status) == (b"original-gzip-body", "succeeded", 200), (
        "The actual isolated process lost the explicit gzip selection or original bytes"
    )


@pytest.mark.parametrize("arguments,kind", [(["worker", "https://example.invalid/x", "1", "1"],
                                           "json"),
    (["worker", "https://example.invalid/x", "1", "1", "gzip"], "gzip"),
    (["worker", "https://example.invalid/x", "1", "1", "zip"], "zip")])
def test_InternalWorkerOptionalModePreservesDefaultInvocation(monkeypatch, arguments, kind):
    """The compatibility four-argument invocation and explicit resource profiles remain distinct."""

    observed = []

    def Receive(url, maximum, timeout, output, *, accept_kind):
        """Record only parsed first-party invocation facts without opening a socket."""

        observed.append((url, maximum, timeout, accept_kind))

        return 0

    monkeypatch.setattr(transport.sys, "argv", arguments)
    monkeypatch.setattr(transport, "Receive", Receive)
    assert transport.Main() == 0 and observed == [(
        "https://example.invalid/x", 1, 1.0, kind,
    )], "Worker mode silently changed its original invocation contract"


def test_UnknownWorkerResourceKindRefusesBeforeAnyConnection(monkeypatch):
    """Neither the direct function nor the internal argv profile accepts arbitrary headers."""

    def Refuse(*args, **kwargs):
        """Reject any transport construction before fixed resource admission."""

        raise AssertionError("Unknown resource kind reached the network constructor")

    monkeypatch.setattr(transport.http.client, "HTTPSConnection", Refuse)
    assert transport.Receive("https://example.invalid/x", 10, 1, io.BytesIO(),
                             accept_kind="other") == transport.FORMAT_EXIT, (
        "Unknown resource representation was admitted"
    )
    monkeypatch.setattr(transport.sys, "argv", ["worker", "https://example.invalid/x",
                                               "10", "1", "other"])
    assert transport.Main() == transport.FORMAT_EXIT, "Unknown internal worker argv mode ran"


class ParsedConnection(Connection):
    """Feed owned raw wire bytes through the actual standard-library response parser."""

    def __init__(self, raw):
        """Retain controlled wire bytes and count attempted body reads."""

        super().__init__(None)
        self.raw = raw
        self.read_calls = 0

    def GetResponse(self):
        """Parse the wire fixture at the production connection response boundary."""

        response = http.client.HTTPResponse(
            SimpleNamespace(makefile=lambda *a: io.BytesIO(self.raw)),
        )
        response.begin()
        read = response.read1

        def Read(size):
            """Observe body access separately from standard-library header parsing."""

            self.read_calls += 1

            return read(size)

        response.read1 = Read

        return response


def ReceiveWire(monkeypatch, raw, maximum=64, kind="zip"):
    """Run the actual receiver over controlled parsed wire data without opening a socket."""

    connection = ParsedConnection(raw)
    client = SimpleNamespace(request=connection.Request, getresponse=connection.GetResponse,
                             close=connection.Close)
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", lambda *a, **k: client)
    output = io.BytesIO()
    result = transport.Receive("https://example.invalid/owned.zip", maximum, 1.0,
                               output, accept_kind=kind)
    assert connection.closed, "Owned response connection leaked on a terminal path"

    return result, output.getvalue(), connection


@pytest.mark.parametrize("media", [
    b"application/zip", b"APPLICATION/ZIP", b"application/octet-stream",
    b"\tApplication/Octet-Stream \t", b"application/zip" + b" " * 113,
    b"application/zip" + b"\t" * 113,
])
def test_ZipMediaGatePreservesOriginalBytesAndExactNegotiation(monkeypatch, media):
    """One parsed ASCII ZIP media value admits original bytes without decompression."""

    body = b"PK\x03\x04\x00owned-original\xff"
    raw = b"HTTP/1.1 200 OK\r\nContent-Type: " + media + b"\r\n\r\n" + body
    result, output, connection = ReceiveWire(monkeypatch, raw)
    assert (result, output) == (0, b'{"status": 200}\n' + body)
    assert connection.headers == {
        "Accept": "application/zip, application/octet-stream", "Accept-Encoding": "identity",
        "Connection": "close", "User-Agent": "1337-intelligence-acquisition/1",
    }, "ZIP preference changed unrelated legacy headers"
    assert connection.read_calls > 0, "Admitted ZIP body was never consumed"


@pytest.mark.parametrize("fields", [
    b"", b"Content-Type:\r\n", b"Content-Type: application/json\r\n",
    b"Content-Type: application/zip; charset=utf-8\r\n",
    b"Content-Type: application/zip, application/octet-stream\r\n",
    b"Content-Type: application/zip\r\nContent-Type: application/zip\r\n",
    b"Content-Type: application/zip\r\ncontent-type: application/octet-stream\r\n",
    b"Content-Type: application/zip\r\n \t\r\n",
    b"Content-Type: application/zip\x00\r\n", b"Content-Type: application/zip\x7f\r\n",
    b"Content-Type: application/zip\x0b\r\n", b"Content-Type: application/zip\x0c\r\n",
    b"Content-Type: application/zip\x80\r\n", b"Content-Type: application/ zip\r\n",
    b"Content-Type: application/\tzip\r\n",
    b"Content-Type: application/zip" + b" " * 114 + b"\r\n",
])
def test_ZipMediaRefusesBeforeAnyBodyReadAfterActualHeaderParsing(monkeypatch, fields):
    """Missing, ambiguous, folded or noncanonical media cannot release any original body."""

    result, output, connection = ReceiveWire(
        monkeypatch, b"HTTP/1.1 200 OK\r\n" + fields + b"\r\nprivate-body",
    )
    assert (result, output, connection.read_calls) == (
        transport.FORMAT_EXIT, b'{"status": 200}\n', 0,
    ), "Invalid ZIP media reached read1 or lost status-only framing"


@pytest.mark.parametrize("values", [[b"application/zip"], [None], [1]])
def test_ZipMediaRejectsNonStringParsedValues(monkeypatch, values):
    """Even a faulty internal parsed-header seam cannot coerce its values into valid media."""

    response = Response()
    response.headers = SimpleNamespace(get_all=lambda *a: values, get=lambda *a: None)
    connection = Connection(response)
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", lambda *a, **k: SimpleNamespace(
        request=connection.Request, getresponse=connection.GetResponse, close=connection.Close,
    ))
    output = io.BytesIO()
    assert transport.Receive("https://example.invalid/x", 100, 1, output,
                             accept_kind="zip") == transport.FORMAT_EXIT
    assert output.getvalue() == b'{"status": 200}\n'


@pytest.mark.parametrize("wire,maximum,state,body,reads", [
    (b"broken-status\r\n\r\n", 64, transport.TRANSPORT_EXIT, b"", False),
    (b"HTTP/1.1 302 Redirect\r\n\r\nbody", 64, transport.REDIRECT_EXIT, b"", False),
    (b"HTTP/1.1 404 Missing\r\n\r\nbody", 64, transport.HTTP_EXIT, b"", False),
    (b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nbody",
     64, transport.FORMAT_EXIT, b"", False),
    (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
     64, transport.FORMAT_EXIT, b"", False),
    (b"HTTP/1.1 200 OK\r\nContent-Length: 65\r\n\r\nbody",
     64, transport.SIZE_EXIT, b"", False),
    (b"HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: 5\r\n\r\nx",
     64, transport.TRANSPORT_EXIT, b"x", True),
    (b"HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\n\r\n1234",
     3, transport.SIZE_EXIT, b"123", True),
    (b"HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nTransfer-Encoding: chunked\r\n"
     b"\r\n3\r\nZIP\r\n0\r\n\r\n", 3, 0, b"ZIP", True),
    (b"HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nTransfer-Encoding: chunked\r\n"
     b"\r\nbad-chunk\r\n", 64, transport.TRANSPORT_EXIT, b"", True),
])
def test_ZipModePreservesStatusFramingAndFiniteBodyLimits(
    monkeypatch, wire, maximum, state, body, reads,
):
    """ZIP admission cannot weaken earlier status/framing gates or bounded streaming failures."""

    result, output, connection = ReceiveWire(monkeypatch, wire, maximum)
    assert result == state and output.partition(b"\n")[2] == body
    assert bool(connection.read_calls) is reads


@pytest.mark.parametrize("kind,accept", [("json", "application/json"),
                                         ("gzip", "application/gzip")])
def test_LegacyModesStillIgnoreMissingOrMalformedMedia(monkeypatch, kind, accept):
    """The opt-in ZIP gate does not migrate older typed sources to a new media contract."""

    for fields in (b"", b"Content-Type: bad\r\nContent-Type: worse\r\n"):
        result, output, connection = ReceiveWire(
            monkeypatch, b"HTTP/1.1 200 OK\r\n" + fields + b"\r\noriginal", kind=kind,
        )
        assert (result, output) == (0, b'{"status": 200}\noriginal')
        assert connection.headers["Accept"] == accept


@pytest.mark.parametrize("payload,exit_code,expected", [
    (b'{"status":200}\npartial', 7, (b"partial", "timed-out", 200)),
    (b'{"status":200}\n', 4, (b"", "format-rejected", 200)),
    (b'{"status":true}\nbody', 0, (b"", "transport-failed", None)),
    (b'{"status":200,"extra":1}\nbody', 0, (b"", "transport-failed", None)),
    (b' ' * 129 + b'\nbody', 0, (b"", "transport-failed", None)),
    (b'{"status":404}\nbody', 0, (b"body", "transport-failed", 404)),
])
def test_ZipParentPreservesBoundedStatusOnlyProtocol(
    tmp_path, monkeypatch, payload, exit_code, expected,
):
    """ZIP mode retains exact tuple, partial-timeout and malformed worker protocol semantics."""

    Worker(tmp_path, monkeypatch,
           f"import sys\nsys.stdout.buffer.write({payload!r})\nraise SystemExit({exit_code})\n")
    assert receiver.ReceiveIsolatedHttps(
        "https://example.invalid/owned.zip", 64, 2.0, accept_kind="zip",
    ) == expected


def test_ZipSocketTimeoutPreservesObservedStatusAndNoBody(monkeypatch):
    """A valid ZIP media gate cannot turn a failed body read into a successful transfer."""

    response = Response(error=TimeoutError())
    response.headers = SimpleNamespace(
        get_all=lambda *a: ["application/zip"], get=lambda *a: None,
    )
    connection = Connection(response)
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", lambda *a, **k: SimpleNamespace(
        request=connection.Request, getresponse=connection.GetResponse, close=connection.Close,
    ))
    output = io.BytesIO()
    assert transport.Receive("https://example.invalid/x", 100, 1, output,
                             accept_kind="zip") == transport.TIMEOUT_EXIT
    assert output.getvalue() == b'{"status": 200}\n' and connection.closed


def test_ZipTotalDeadlineKillsAndDrainsTheRealWorker(tmp_path, monkeypatch):
    """An admitted ZIP child retains partial bytes and cannot outlive its total deadline."""

    Worker(tmp_path, monkeypatch,
           "import sys, time\nassert sys.argv[4] == 'zip'\n"
           "sys.stdout.buffer.write(b'{\"status\":200}\\npartial')\n"
           "sys.stdout.buffer.flush()\ntime.sleep(10)\n")
    original = subprocess.Popen
    processes = []

    def Popen(*args, **kwargs):
        """Capture the actual child for termination and isolation assertions."""

        assert kwargs["env"] == {} and args[0][1:3] == ["-I", "-S"]
        process = original(*args, **kwargs)
        processes.append(process)

        return process

    monkeypatch.setattr(receiver.subprocess, "Popen", Popen)
    assert receiver.ReceiveIsolatedHttps(
        "https://example.invalid/owned.zip", 64, 1.0, accept_kind="zip",
    ) == (b"partial", "timed-out", 200)
    assert len(processes) == 1 and processes[0].poll() is not None
