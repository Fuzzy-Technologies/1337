# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Opt-in genuine installed Nuclei acceptance exclusively against pytest-owned loopback HTTP."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from test_nuclei_workflow import Policy, Setup

from fuzzy1337.findings import Findings
from fuzzy1337.model import LocalModelStore
from fuzzy1337.nucleiscan import PlanNucleiScan, RunNucleiScan
from fuzzy1337.policy import PolicyConfirmation
from fuzzy1337.reporting import ReportSnapshot, VerifyReportEvidence
from fuzzy1337.scan_commands import OpenWorkspace
from fuzzy1337.scope import Target, TargetKind


@pytest.fixture
def native_marker_service() -> Iterator[tuple[str, list[str]]]:
    """Own a loopback marker/negative service and reap its lifecycle after each test."""

    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        """Expose deterministic one-GET positive/negative template oracles without credentials."""

        def do_GET(self) -> None:
            """Record actual provider contacts and return the selected non-sensitive marker."""

            requests.append(self.path)
            body = (b"1337-owned-synthetic-marker" if self.path == "/match"
                    else b"owned-negative-no-template-marker")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            """Keep the local oracle's untrusted request text outside test diagnostic output."""

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()

    try:
        yield f"http://127.0.0.1:{server.server_port}", requests

    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), "The owning pytest fixture must reap its service thread."


@pytest.mark.integration
@pytest.mark.parametrize("route,expected_matches", [("/match", 1), ("/negative", 0)])
def test_GenuineInstalledNucleiReviewedExactGetAndDurableFindings(
    tmp_path: Path, native_marker_service: tuple[str, list[str]], route: str, expected_matches: int,
) -> None:
    """Run the actual selected binary with unchanged finite flags and retain raw evidence."""

    supplied_binary = os.environ.get("FUZZY1337_NUCLEI_BINARY")

    if supplied_binary is None:
        pytest.skip("Genuine provider acceptance requires explicit FUZZY1337_NUCLEI_BINARY")

    executable = Path(supplied_binary).absolute()
    assert executable.is_file(), "Opt-in native acceptance requires an actual installed binary."
    base_url, requests = native_marker_service
    target = Target(TargetKind.URL, base_url + route)
    root = tmp_path / "workspace"
    _, profile, _ = Setup(root, target)
    plan = PlanNucleiScan(root, "local", target, "operator:owned", profile, str(executable), Policy)
    assert "synthetic" not in plan.invocation.provider_version, (
        "A synthetic format producer must never count as genuinely installed scanner acceptance."
    )
    assert requests == [], "Planning's bounded version probe must not contact the target."
    approval = PolicyConfirmation(plan.policy_plan.intent_sha256, "approval:pytest-native-get")
    summary = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
                                       str(executable), Policy, confirmation=approval))
    output = Path("functional-evidence/nuclei-native") / route.lstrip("/")
    output.mkdir(parents=True, exist_ok=True)
    shutil.copytree(root / "evidence", output / "evidence", dirs_exist_ok=True)
    (output / "plan.json").write_text(json.dumps(plan.ToDict(), indent=2), encoding="utf-8")
    (output / "summary.json").write_text(json.dumps({
        "provider_version": plan.invocation.provider_version,
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "requests": requests, "expected_matches": expected_matches,
        "summary": summary.ToDict(),
    }, indent=2), encoding="utf-8")
    assert summary.ExitCode() == 0, (
        "Genuine incompatible/provider failure must remain an actual failure."
    )
    assert requests == [route], (
        "The finite reviewed profile must issue exactly one GET at the exact URL."
    )
    model = LocalModelStore(root).Open()
    assert len(Findings(model)) == expected_matches, (
        "The owned positive/negative marker oracle is exact."
    )
    assert OpenWorkspace(root)["verified_evidence_records"] == 2, (
        "Native raw acquisitions must reopen."
    )
    verified_report = VerifyReportEvidence(ReportSnapshot(model), root)
    assert len(verified_report.EvidenceReferences()) == 2, (
        "Reports verify actual native terminal streams."
    )
    assert all(record.evidence.provenance.tool_version == plan.invocation.provider_version
               for record in summary.snapshot.artifacts), (
        "Actual native version must attribute raw evidence."
    )
