# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual governed installed-worker acceptance on independently authored local metrics wires."""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import socketserver
from io import StringIO
from pathlib import Path
from threading import Event, Thread

import pytest

from fuzzy1337.adapters import ImpactLevel, SerializeContract
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.findings import Findings, FindingSeverity, FindingStatus
from fuzzy1337.jobs import JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_web import (
    NATIVE_PROMETHEUS_CAPABILITY,
    NATIVE_PROMETHEUS_CHECK_ID,
    NATIVE_WEB_PROVIDER_ID,
    PlanNativeWebScan,
    RunNativeWebScan,
)
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, PolicyConfirmation
from fuzzy1337.reporting import ReportSnapshot, VerifyReportEvidence
from fuzzy1337.scan_commands import OpenWorkspace, RunCommands
from tests.functional.test_native_web_checks import NativeWorkspace

EXPOSITION = (b"# HELP accepted_requests_total Number of accepted requests\n"
              b"# TYPE accepted_requests_total counter\n"
              b'accepted_requests_total{component="owned-fixture"} 7\n')
PADDED_EXPOSITION = EXPOSITION + b"# bounded padding\n" * 400
NAN_EXPOSITION = (b"# HELP observed_accuracy Current diagnostic ratio\n"
                  b"# TYPE observed_accuracy gauge\n"
                  b'observed_accuracy{phase="find it"} Nan\n'
                  b'observed_accuracy{phase="fix it"} Nan\n'
                  + b"# bounded padding\n" * 400)
OUTPUT = Path("_build/native-prometheus/acceptance")


def Response(body=PADDED_EXPOSITION, *, framing="chunked", status=200, media="text/plain"):
    """Freeze synthetic transport truth independently of detector parsing and metric names."""

    header = f"HTTP/1.1 {status} Owned\r\nContent-Type: {media}\r\n".encode()

    if status == 302:
        header += b"Location: /unselected\r\n"

    if framing == "chunked":
        split = len(body) // 2

        return (header + b"Transfer-Encoding: chunked\r\n\r\n"
                + f"{split:x}\r\n".encode() + body[:split] + b"\r\n"
                + f"{len(body) - split:x}\r\n".encode() + body[split:] + b"\r\n0\r\n\r\n")

    if framing == "length":
        return header + f"Content-Length: {len(body)}\r\n\r\n".encode() + body

    return header + b"\r\n" + body


CASES = {
    "length-positive": (Response(framing="length"), True, True),
    "chunked-positive": (Response(), True, True),
    "eof-positive": (Response(framing="eof"), True, True),
    "nan-spelling-positive": (Response(NAN_EXPOSITION), True, True),
    "plain-prose-decoy": (Response(b"This page describes Prometheus metrics\n"), False, True),
    "html-decoy": (Response(b"<html>\n" + EXPOSITION + b"</html>\n", media="text/html"),
                   False, True),
    "denied": (Response(status=403), False, True),
    "redirect": (Response(status=302), False, True),
    "truncated-chunk": (Response()[:-2], False, False),
    "oversized-eof": (Response(b"x" * 262145, framing="eof"), False, False),
    "ambiguous-framing": (Response().replace(b"Transfer-Encoding: chunked\r\n",
        b"Transfer-Encoding: chunked\r\nContent-Length: 1\r\n"), False, False),
}


@pytest.fixture
def prometheus_target(request):
    """Own a single loopback response service and bounded unconditional listener teardown."""

    case = getattr(request, "param", "chunked-positive")
    wire, _, _ = CASES[case]
    hits = []

    class Handler(socketserver.StreamRequestHandler):
        """Serve one frozen response without deriving expectations from scanner behavior."""

        def handle(self):
            """Read the one bounded request, then close after transmitting the selected wire."""

            self.connection.settimeout(2)
            line = self.rfile.readline(2048)
            hits.append(line.decode("ascii"))

            for _ in range(64):
                if self.rfile.readline(4096) == b"\r\n":
                    break

            try:
                self.wfile.write(wire)

            except (BrokenPipeError, ConnectionResetError):
                pass

    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    ready = Event()

    def Serve():
        """Expose readiness after the selected ephemeral listener is already bound."""

        ready.set()
        server.serve_forever(poll_interval=0.01)

    thread = Thread(target=Serve, name="owned-prometheus-target", daemon=False)

    try:
        thread.start()
        assert ready.wait(2), "Owned metrics listener did not become ready."

        yield case, f"http://127.0.0.1:{server.server_address[1]}/selected", hits

    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive(), "Owned metrics service thread leaked."


def MetricsPolicy():
    """Allow only the exact new STANDARD check under existing separate plan confirmation."""

    return ImpactPolicy("owned-prometheus", maximum_impact=ImpactLevel.STANDARD,
        permissions=(CapabilityPermission(NATIVE_PROMETHEUS_CAPABILITY, NATIVE_WEB_PROVIDER_ID,
                                          ImpactLevel.STANDARD),))


@pytest.mark.parametrize("prometheus_target", list(CASES), indirect=True)
def test_ActualInstalledWorkerPersistsOnlyCorrectMetricsFindings(tmp_path, prometheus_target):
    """Real SDK jobs distinguish exposure, negatives and failed unassessed transport end to end."""

    case, url, hits = prometheus_target
    _, expected_match, assessed = CASES[case]
    root = tmp_path / "workspace"
    target = NativeWorkspace(root, url)
    plan = PlanNativeWebScan(root, "local", target, "operator:owned", MetricsPolicy,
                             check_id=NATIVE_PROMETHEUS_CHECK_ID)
    assert hits == [], "Planning contacted the target."
    assert plan.invocation.argv[1:4] == ("-I", "-m", "fuzzy1337.native_web_worker"), (
        "Acceptance did not select the actual isolated installed worker."
    )
    summary = asyncio.run(RunNativeWebScan(root, "local", target, "operator:owned", MetricsPolicy,
        check_id=NATIVE_PROMETHEUS_CHECK_ID, confirmation=PolicyConfirmation(
            plan.policy_plan.intent_sha256, "approval:owned-metrics")))
    assert hits == ["GET /selected HTTP/1.1\r\n"], "Request was expanded, retried or redirected."
    assert (summary.snapshot.state is JobState.COMPLETED) is assessed, "Assessment state drifted."
    assert summary.ExitCode() == (0 if assessed else 4), "A failed acquisition became clean."
    model = LocalModelStore(root).Open()
    findings = Findings(model)
    assert len(findings) == int(expected_match), "Saved Findings differ from case truth."

    for finding in findings:
        assert (finding.check_id, finding.severity, finding.status, finding.confidence) == (
            NATIVE_PROMETHEUS_CHECK_ID, FindingSeverity.LOW, FindingStatus.OPEN, 0.0,
        ), "Metrics observation claimed unsupported risk or confidence."

    store = LocalEvidenceStore(root / "evidence")
    streams = {item.evidence.reference.role: store.Read(item.evidence.reference)
               for item in summary.snapshot.artifacts}
    assert streams["stderr"] == b"", "Worker emitted unexpected private error material."
    assert b"accepted_requests_total" not in streams["stdout"], "Metric names were retained."
    assert b"observed_accuracy" not in streams["stdout"], "Diagnostic metric names were retained."
    worker = json.loads(streams["stdout"])

    if assessed:
        assert worker["matched"] is expected_match, "Original worker predicate differs from model."
        assert worker["check_id"] == NATIVE_PROMETHEUS_CHECK_ID, "Wrong worker code ran."

        if expected_match:
            expected_body = NAN_EXPOSITION if case == "nan-spelling-positive" else PADDED_EXPOSITION
            assert worker["body_bytes"] == len(expected_body) > 4096, "New cap was not used."
            assert worker["body_sha256"] == hashlib.sha256(expected_body).hexdigest(), (
                "Actual decoded response hash differs from the independent fixture."
            )

        verified = VerifyReportEvidence(ReportSnapshot(model), root)
        assert len(verified.EvidenceReferences()) == 2, "Saved report lost original worker custody."

    else:
        assert set(worker) == {"schema_version", "error"}, "Failed acquisition invented assessment."

    assert OpenWorkspace(root)["verified_evidence_records"] == 2, "Durable reopen lost evidence."
    output = OUTPUT / case
    output.mkdir(parents=True, exist_ok=True)
    shutil.copytree(root / "evidence", output / "evidence", dirs_exist_ok=True)
    (output / "plan.json").write_text(json.dumps(plan.ToDict(), indent=2), encoding="utf-8")
    (output / "summary.json").write_text(json.dumps(summary.ToDict(), indent=2), encoding="utf-8")
    (output / "requests.json").write_text(json.dumps(hits), encoding="utf-8")


def test_MetricsCliRequiresTheSameExactPlanAndCurrentAuthority(tmp_path, prometheus_target):
    """The actual CLI refuses unconfirmed work, runs its new selection and reopens the Finding."""

    _, url, hits = prometheus_target
    root = tmp_path / "workspace"
    NativeWorkspace(root, url)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(SerializeContract(MetricsPolicy()), encoding="utf-8")
    arguments = ["web", str(root), "--check", "prometheus-exposition", "--scope", "local",
        "--owner", "operator:owned", "--target", url, "--policy", str(policy_path)]
    output = StringIO()
    assert RunCommands("scan", [*arguments, "--plan"], output) == 0, "CLI planning failed."
    plan = json.loads(output.getvalue())
    assert plan["check_id"] == NATIVE_PROMETHEUS_CHECK_ID and hits == [], "CLI intent drifted."
    assert RunCommands("scan", arguments, StringIO()) == 3, "Unconfirmed STANDARD work ran."
    assert hits == [], "Missing confirmation allowed network contact."
    result = StringIO()
    assert RunCommands("scan", [*arguments, "--confirm-plan", plan["intent_sha256"],
        "--confirmation-reference", "approval:owned-metrics-cli"], result, json_output=True) == 0, (
        "Confirmed CLI metrics execution failed."
    )
    assert json.loads(result.getvalue())["state"] == "completed", "CLI lost terminal truth."
    assert len(Findings(LocalModelStore(root).Open())) == 1, "CLI did not persist the real Finding."
    assert OpenWorkspace(root)["verified_evidence_records"] == 2, "CLI evidence did not reopen."
    assert hits == ["GET /selected HTTP/1.1\r\n"], "CLI expanded its selected request."
