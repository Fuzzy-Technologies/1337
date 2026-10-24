# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual installed acquisition worker and closed original wire; no ZAP/provider acceptance."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CATALOG = REPOSITORY_ROOT / "tests/contract/fixtures/zap-passive.oracle.v1.json"
CATALOG_SHA256 = "fb57a1e31904e9904ef5501a6dc7721c9263e12ab55672405c5a70fb2c3798d7"


def Canonical(value) -> bytes:
    """Encode handwritten expectations with only standard-library JSON.

    Args:
        value: Explicit original-byte or closed-refusal expectation.

    Returns:
        Sorted compact UTF-8 JSON without a newline or BOM.
    """

    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def CatalogCase(case_id: str) -> dict:
    """Select approved original bytes without reading semantic alert-count expectations.

    Args:
        case_id: One of the three literal approved acquisition cases.

    Returns:
        Independently frozen path and original header/body/response byte identities only.
    """

    raw = CATALOG.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == CATALOG_SHA256, (
        "The independent original-wire catalog differs from its approved frozen identity"
    )
    selected = next(item for item in json.loads(raw)["cases"] if item["case_id"] == case_id)
    result = {key: selected[key] for key in (
        "case_id", "path", "header_section", "body", "response")}

    for key in ("header_section", "body", "response"):
        part = result[key]
        wire = base64.b64decode(part["base64"], validate=True)
        assert len(wire) == part["size_bytes"] and hashlib.sha256(wire).hexdigest() == (
            part["sha256"]), (
            "Approved original wire bytes must agree with their independent lengths and SHA-256"
        )

    assert base64.b64decode(result["response"]["base64"]) == (
        base64.b64decode(result["header_section"]["base64"])
        + base64.b64decode(result["body"]["base64"])
    ), "Original response must be exactly the frozen headers followed immediately by frozen body"

    return result


@pytest.fixture(scope="module")
def installed_worker(tmp_path_factory):
    """Build and install the actual current wheel offline into a clean isolated interpreter."""

    root = tmp_path_factory.mktemp("installed-owned-response")
    wheel_directory = root / "wheel"
    wheel_directory.mkdir()
    built = subprocess.run((sys.executable, "-m", "build", "--wheel", "--no-isolation",
        "--outdir", str(wheel_directory)), cwd=REPOSITORY_ROOT, capture_output=True,
        timeout=30, check=False)
    assert built.returncode == 0, "Offline worker wheel build failed: " + repr(built.stderr)
    wheels = tuple(wheel_directory.glob("*.whl"))
    assert len(wheels) == 1, "The actual isolated worker needs exactly one freshly built wheel"
    environment = root / "environment"
    created = subprocess.run((sys.executable, "-m", "venv", str(environment)),
        capture_output=True, timeout=30, check=False)
    assert created.returncode == 0, (
        "Isolated worker environment creation failed: " + repr(created.stderr)
    )
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    installed = subprocess.run((str(python), "-I", "-B", "-m", "pip", "--isolated", "install",
        "--no-index", "--no-deps", "--no-compile", "--disable-pip-version-check", str(wheels[0])),
        cwd=root, capture_output=True, timeout=30, check=False)
    assert installed.returncode == 0, "Offline wheel installation failed: " + repr(installed.stderr)

    return python


class OwnedResponseListener:
    """Own one exact loopback wire listener and drain only its accepted current-case connections."""

    def __init__(self, wire: bytes, address: str = "127.0.0.1") -> None:
        """Bind before launch and start no probes, redirects or secondary targets.

        Args:
            wire: Exact approved or explicitly rejected safe synthetic response bytes.
            address: Explicit IPv4 or IPv6 loopback literal for this case.
        """

        family = socket.AF_INET6 if address == "::1" else socket.AF_INET
        self.listener = socket.socket(family, socket.SOCK_STREAM)

        try:
            self.listener.bind((address, 0))
            self.listener.listen(4)
            self.listener.settimeout(0.05)

        except BaseException:
            self.listener.close()

            raise

        self.address = address
        self.port = self.listener.getsockname()[1]
        self.authority = f"[{address}]:{self.port}" if address == "::1" else (
            f"{address}:{self.port}")
        self.origin = "http://" + self.authority
        self.wire = wire
        self.requests = []
        self.accepted = 0
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.Serve, daemon=True)
        self.thread.start()

    def Serve(self) -> None:
        """Send only this selected synthetic wire and retain a finite complete original request."""

        while True:
            try:
                connection, _ = self.listener.accept()

            except socket.timeout:
                if self.stopping.is_set():
                    return

                continue

            except OSError:
                return

            self.accepted += 1

            with connection:
                connection.settimeout(0.5)
                request = bytearray()

                try:
                    while b"\r\n\r\n" not in request and len(request) <= 1024:
                        chunk = connection.recv(1025 - len(request))

                        if not chunk:
                            break

                        request.extend(chunk)

                    connection.sendall(self.wire)
                    connection.shutdown(socket.SHUT_WR)

                    while len(request) <= 1024:
                        chunk = connection.recv(1025 - len(request))

                        if not chunk:
                            break

                        request.extend(chunk)

                except (OSError, TimeoutError):
                    pass

                finally:
                    self.requests.append(bytes(request))

    def Close(self) -> None:
        """Drain already queued connections, then join and close the exact owned listener."""

        self.stopping.set()

        try:
            self.thread.join(timeout=2)

        finally:
            self.listener.close()
            self.thread.join(timeout=1)

        assert not self.thread.is_alive(), "Owned loopback listener did not finish bounded cleanup"


def ExpectedRequest(listener: OwnedResponseListener, case_id: str) -> bytes:
    """Write the independent exact original GET grammar without a production request builder.

    Args:
        listener: This case's explicit bound authority.
        case_id: Approved literal selected path suffix.

    Returns:
        Exact sent ASCII request, with no extra body or CR/LF.
    """

    return (f"GET /zap-passive/{case_id} HTTP/1.1\r\nHost: {listener.authority}\r\n"
        "Connection: close\r\nAccept: text/html\r\nAccept-Encoding: identity\r\n"
        "User-Agent: 1337-owned-response/1\r\n\r\n").encode("ascii")


def RunWorker(python: Path, cwd: Path, listener: OwnedResponseListener, suffix: str):
    """Run the actual installed isolated module with only this explicit owned URL.

    Args:
        python: Clean wheel-installed interpreter, outside the checkout import path.
        cwd: Fresh current-case directory containing an inert shadow package.
        listener: Current owned literal server; proxy variables also point only here.
        suffix: Exact selected case path or one explicitly rejected safe URL suffix.

    Returns:
        Actual original process return code and captured byte streams.
    """

    shadow = cwd / "fuzzy1337"
    shadow.mkdir()
    (shadow / "__init__.py").write_text(
        '"""Owned import shadow must never execute."""\n'
        'from pathlib import Path\n'
        'Path("shadow-executed.marker").write_text("owned shadow")\n'
        'raise SystemExit(73)\n', encoding="utf-8")
    environment = {key: os.environ[key] for key in
        ("SYSTEMROOT", "WINDIR", "PATH", "TMP", "TEMP", "TMPDIR") if key in os.environ}
    environment.update({"HTTP_PROXY": listener.origin, "http_proxy": listener.origin,
        "HTTPS_PROXY": listener.origin, "https_proxy": listener.origin,
        "NO_PROXY": "", "no_proxy": ""})
    result = subprocess.run((str(python), "-I", "-B", "-m",
        "fuzzy1337.owned_response_capture_worker", listener.origin + suffix),
        cwd=cwd, env=environment, capture_output=True, timeout=10, check=False)
    assert not (cwd / "shadow-executed.marker").exists(), (
        "The isolated worker must load its actual installed wheel despite a same-named cwd package"
    )

    return result


@pytest.mark.parametrize("address", ["127.0.0.1", "::1"])
@pytest.mark.parametrize("case_id", ["missing", "fixed", "body-decoy"])
def test_InstalledWorkerCapturesExactFrozenOriginalsWithOneGet(
    installed_worker, tmp_path, address, case_id,
):
    """Acquire original bytes through real isolated installed Python, without any ZAP analysis."""

    case = CatalogCase(case_id)

    try:
        listener = OwnedResponseListener(base64.b64decode(case["response"]["base64"]), address)

    except OSError as error:
        if address == "::1" and error.errno in {49, 97, 99, 10047, 10049}:
            pytest.skip("This host lacks IPv6 loopback; IPv6 acceptance is unexecuted")

        raise

    try:
        result = RunWorker(installed_worker, tmp_path, listener, case["path"])

    finally:
        listener.Close()

    request = ExpectedRequest(listener, case_id)
    expected = {"schema_version": 1, "profile": "owned-response-capture.v1", "outcome": "captured",
        "catalog_sha256": CATALOG_SHA256, "case_id": case_id,
        "url": listener.origin + case["path"], "address": address, "port": listener.port,
        "request": {"base64": base64.b64encode(request).decode("ascii"), "size_bytes": len(request),
            "sha256": hashlib.sha256(request).hexdigest()},
        "response_headers": {key: case["header_section"][key]
            for key in ("base64", "size_bytes", "sha256")},
        "response_body": {key: case["body"][key] for key in ("base64", "size_bytes", "sha256")},
        "response": {key: case["response"][key] for key in ("size_bytes", "sha256")}}
    assert result.returncode == 0 and result.stderr == b"" and result.stdout == (
        Canonical(expected)), (
        "Installed worker must emit only the exact canonical original capture and exit zero"
    )
    assert listener.accepted == 1 and listener.requests == [request], (
        "Acquisition must send exactly one original GET without proxy rewriting, follow-up or retry"
    )


@pytest.mark.parametrize("change,error", [("header", "response-policy"), ("body", "body-policy"),
    ("trailing", "protocol"), ("truncated", "protocol"), ("redirect", "response-policy")])
def test_InstalledWorkerRefusesRejectedWireWithoutPublishingItsBytesOrHashes(
    installed_worker, tmp_path, change, error,
):
    """Real safe rejected responses produce only the closed refusal, with no retry or redirect."""

    case = CatalogCase("missing")
    header = base64.b64decode(case["header_section"]["base64"])
    body = base64.b64decode(case["body"]["base64"])
    wire = header + body

    if change == "header":
        wire = header[:-2] + b"X-Owned-Refusal: rejected-header-canary\r\n\r\n" + body

    elif change == "body":
        wire = header + b"owned-rejected-body-marker".ljust(170, b"x")

    elif change == "trailing":
        wire += b"owned-rejected-trailing-marker"

    elif change == "truncated":
        wire = wire[:-1]

    listener = OwnedResponseListener(wire)

    if change == "redirect":
        listener.wire = ("HTTP/1.1 302 Found\r\nLocation: " + listener.origin
            + "/zap-passive/fixed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ).encode("ascii")

    try:
        result = RunWorker(installed_worker, tmp_path, listener, case["path"])

    finally:
        listener.Close()

    expected = Canonical({"schema_version": 1, "profile": "owned-response-capture.v1",
        "outcome": "refused", "error": error})
    no_rejected_material = result.stdout == expected and result.stderr == b""
    assert result.returncode == 2 and no_rejected_material, (
        "Refusal must expose only the exact closed error, without raw bytes, hashes or diagnostics"
    )
    assert listener.accepted == 1 and listener.requests == [ExpectedRequest(listener, "missing")], (
        "A rejected response must cause exactly one GET without retry or redirect"
    )


def test_InstalledWorkerRejectsUnselectedQueryBeforeAnyConnection(installed_worker, tmp_path):
    """Invalid safe selection neither contacts its owned listener nor appears in refusal stdout."""

    listener = OwnedResponseListener(b"")

    try:
        result = RunWorker(installed_worker, tmp_path, listener,
            "/zap-passive/missing?owned-rejected-query-marker")

    finally:
        listener.Close()

    expected = Canonical({"schema_version": 1, "profile": "owned-response-capture.v1",
        "outcome": "refused", "error": "input"})
    no_rejected_material = result.stdout == expected and result.stderr == b""
    assert result.returncode == 2 and no_rejected_material, (
        "Invalid selection must emit only canonical input refusal without rejected URL diagnostics"
    )
    assert listener.accepted == 0 and listener.requests == [], (
        "Invalid URL selection must refuse before any connection or original request is sent"
    )
