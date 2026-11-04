# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise native Git exposure against independent local response calibration controls.

Each scenario allows one exact anonymous loopback GET under the existing STANDARD
Git profile. The fixture provides controls for future calibration; it does not
implement baseline sampling, response similarity or resource discovery.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import socketserver
from pathlib import Path
from threading import Thread

import pytest

from fuzzy1337.findings import Findings
from fuzzy1337.jobs import JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_web import PlanNativeWebScan, RunNativeWebScan
from fuzzy1337.policy import PolicyConfirmation
from fuzzy1337.scan_commands import OpenWorkspace
from tests.functional.test_native_web_checks import NativePolicy, NativeRunEvidence, NativeWorkspace

ORACLE = json.loads((Path(__file__).resolve().parents[1] / "fixtures" / "response_calibration" /
                     "oracle.v1.json").read_text(encoding="utf-8"))
HEAD_PATH = b"/repository/.git/HEAD"
HEAD_BODY = b"ref: refs/heads/owned-control\n"
ABSENT_PATHS = {b"/absent/nonce-a/.git/HEAD": b"nonce-a", b"/absent/nonce-b/.git/HEAD": b"nonce-b"}


def Response(path: bytes) -> tuple[int, bytes, bytes]:
    """Serve only the finite fixture routes without consulting the expected-result oracle."""

    if path == HEAD_PATH:
        return 200, b"", HEAD_BODY

    if path in ABSENT_PATHS:
        body = b"Resource unavailable (" + ABSENT_PATHS[path] + b")\nExample only: " + HEAD_BODY

        return 200, b"", body

    if path == b"/private/.git/HEAD":
        return 200, b"", b"Sign in to continue\n"

    if path == b"/missing/.git/HEAD":
        return 404, b"", HEAD_BODY

    if path == b"/redirect/.git/HEAD":
        return 302, b"Location: " + HEAD_PATH + b"\r\n", HEAD_BODY

    return 404, b"", b"Unrecognized fixture route\n"


@pytest.fixture(name="responseCalibrationTarget")
def ResponseCalibrationTarget():
    """Own one ephemeral loopback listener and retain exact target-side request lines."""

    requests: list[bytes] = []

    class Handler(socketserver.StreamRequestHandler):
        """Serve bounded plain text responses, including deliberate false HTTP 200 pages."""

        def Handle(self) -> None:
            """Read one bounded request, send its fixture response, and close the connection."""

            self.connection.settimeout(2)
            requestLine = self.rfile.readline(1024)
            requests.append(requestLine)
            parts = requestLine.split()

            if len(parts) != 3 or parts[0] != b"GET":
                return

            for _ in range(16):
                header = self.rfile.readline(1024)

                if header == b"\r\n":
                    break

                if not header.endswith(b"\r\n"):
                    return

            else:
                return

            status, extraHeader, body = Response(parts[1])
            headers = (f"HTTP/1.1 {status} Fixture\r\nContent-Type: text/plain\r\n"
                       f"Content-Length: {len(body)}\r\nConnection: close\r\n").encode("ascii")
            self.wfile.write(headers + extraHeader + b"\r\n" + body)

        handle = Handle

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()

        try:
            yield f"http://127.0.0.1:{server.server_address[1]}", requests

        finally:
            server.shutdown()
            thread.join(timeout=3)
            assert not thread.is_alive(), "The owned response calibration target leaked."


@pytest.mark.parametrize("case", ORACLE["cases"], ids=lambda case: case["id"])
def test_ActualNativeGitCheckDistinguishesCalibrationControls(
    tmp_path, responseCalibrationTarget, case,
):
    """Require one approved request and persist only the independently expected finding."""

    baseUrl, requests = responseCalibrationTarget
    root = tmp_path / "workspace"
    target = NativeWorkspace(root, baseUrl + case["path"])
    plan = PlanNativeWebScan(root, "local", target, "operator:owned", NativePolicy)
    assert requests == [], "Read-only planning contacted the fixture."
    summary = asyncio.run(RunNativeWebScan(root, "local", target, "operator:owned", NativePolicy,
        confirmation=PolicyConfirmation(plan.policy_plan.intent_sha256, "approval:owned-control")))
    assert summary.ExitCode() == 0 and summary.snapshot.state is JobState.COMPLETED
    assert requests == [f"GET {case['path']} HTTP/1.1\r\n".encode("ascii")], (
        "The check retried, expanded scope, or followed an unapproved redirect."
    )
    findings = Findings(LocalModelStore(root).Open())
    assert [finding.check_id for finding in findings] == (
        [ORACLE["check_id"]] if case["finding"] else []
    ), "Persisted native findings disagreed with the independent controls."
    evidence = NativeRunEvidence(root, plan, summary)
    report = json.loads(next(item.content for item in evidence if item.role == "stdout"))
    expectedBody = case["body"].encode("ascii")
    assert report["url"] == target.value and report["check_id"] == ORACLE["check_id"]
    assert report["status"] == case["status"] and report["matched"] is case["finding"]
    assert report["body_bytes"] == len(expectedBody)
    assert report["body_sha256"] == hashlib.sha256(expectedBody).hexdigest()
    assert OpenWorkspace(root)["verified_evidence_records"] == 2
