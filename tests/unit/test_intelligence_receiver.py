# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Shared isolated receiver admission and explicit gzip resource representation checks."""

from __future__ import annotations

import gzip
import io
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


def test_RealIsolatedGzipWorkerReceivesOnlyTheFixedOptionalArgument(tmp_path, monkeypatch):
    """The real process boundary passes gzip explicitly without changing original JSON argv."""

    Worker(tmp_path, monkeypatch,
           'import sys\nassert len(sys.argv) == 5 and sys.argv[4] == "gzip"\n'
           'assert sys.flags.isolated and sys.flags.no_site\n'
           'sys.stdout.buffer.write(b\'{"status":200}\\noriginal-gzip-body\')\n')
    body, state, http_status = receiver.ReceiveIsolatedHttps(
        "https://example.invalid/owned.gz", 100, 2.0, accept_kind="gzip",
    )
    assert (body, state, http_status) == (b"original-gzip-body", "succeeded", 200), (
        "The actual isolated process lost the explicit gzip selection or original bytes"
    )


@pytest.mark.parametrize("arguments,kind", [(["worker", "https://example.invalid/x", "1", "1"],
                                           "json"),
    (["worker", "https://example.invalid/x", "1", "1", "gzip"], "gzip")])
def test_InternalWorkerOptionalModePreservesDefaultInvocation(monkeypatch, arguments, kind):
    """The compatibility four-argument invocation and explicit gzip profile are disjoint."""

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
