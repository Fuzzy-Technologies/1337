# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Optional genuine Nmap discovery against two fixture-owned loopback TCP ports."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
from datetime import datetime, timezone

import pytest

from fuzzy1337.adapters import (
    AdapterHealthState,
    AdapterReport,
    AdapterRequest,
    ExecutionState,
    ImpactLevel,
    SerializeContract,
)
from fuzzy1337.adapters.nmap import NmapAdapter
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptors,
    ExecutionAuthorization,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutor,
)

NMAP_LOOPBACK_ORACLE = {
    "scenario": "nmap.owned-loopback-tcp",
    "target_provenance": "first-party:tests/functional/test_nmap_loopback.py",
    "target_version": "1",
    "required_capabilities": ["nmap", "network.tcp-connect"],
    "assessment_profile": "STANDARD",
    "timeout_seconds": 15,
    "expected_observations": {"listening": "open", "bound_without_listening": "closed"},
    "expected_findings": [],
    "cleanup": "close both fixture-owned sockets",
}
NMAP_TEST_EXECUTABLE = os.environ.get("F1337_NMAP_TEST_EXECUTABLE", "nmap")


@pytest.mark.skipif(shutil.which(NMAP_TEST_EXECUTABLE) is None,
                    reason="optional system Nmap is not installed")
def test_SystemNmapPreservesLoopbackOracleAndRawEvidence(tmp_path):
    """Retain real tool provenance and raw XML for a two-port known-answer oracle.

    Args:
        tmp_path: Owned temporary executor workspace and attributable evidence directory.
    """

    root = tmp_path.resolve()
    evidence_root = root / "evidence"
    evidence_root.mkdir()
    store = LocalEvidenceStore(evidence_root)
    health = NmapAdapter(store.Read, NMAP_TEST_EXECUTABLE).CheckHealth()

    assert health.state is AdapterHealthState.AVAILABLE, (
        "An installed tool whose health probe fails cannot be treated as functional availability."
    )
    adapter = NmapAdapter(store.Read, NMAP_TEST_EXECUTABLE, health.provider_version)
    tool_environment = {key: os.environ[key] for key in ("LD_LIBRARY_PATH", "NMAPDIR")
                        if key in os.environ}

    with socket.socket() as listening, socket.socket() as closed:
        listening.bind(("127.0.0.1", 0))
        listening.listen(8)
        closed.bind(("127.0.0.1", 0))
        open_port = listening.getsockname()[1]
        closed_port = closed.getsockname()[1]
        request = AdapterRequest("network.tcp-connect", "target:owned-loopback",
            ImpactLevel.STANDARD, {"address": "127.0.0.1", "ports": [open_port, closed_port],
                                   "timeout_seconds": NMAP_LOOPBACK_ORACLE["timeout_seconds"]})
        invocation = adapter.PrepareInvocation(request)
        digest = InvocationDigest(invocation)
        authorization = ExecutionAuthorization(
            "authorization:owned-loopback", "scope:loopback-only",
            "policy:test-owned-ports", digest,
        )
        governed = LocalExecutionRequest(invocation, CapabilityDescriptors(adapter.Descriptor)[0],
                                          authorization, environment=tool_environment)
        started_at = datetime.now(timezone.utc).isoformat()
        captured = asyncio.run(LocalExecutor(root).Execute(governed))
        finished_at = datetime.now(timezone.utc).isoformat()

    provenance = EvidenceProvenance("workspace:nmap-loopback", authorization.scope_reference,
        adapter.Descriptor.adapter_id, adapter.Descriptor.version, health.provider_version,
        started_at, finished_at, digest, captured.execution)
    stdout = store.Put(captured.stdout, "stdout", "application/xml", provenance)
    stderr = store.Put(captured.stderr, "stderr", "text/plain", provenance)
    report = AdapterReport(invocation, captured.execution, (stdout.reference, stderr.reference))
    normalized = adapter.NormalizeReport(report)
    oracle = {**NMAP_LOOPBACK_ORACLE, "open_port": open_port, "closed_port": closed_port,
              "tool_version": health.provider_version, "invocation_sha256": digest}
    (root / "oracle.json").write_text(json.dumps(oracle, sort_keys=True), encoding="utf-8")
    (root / "normalized.json").write_text(SerializeContract(normalized), encoding="utf-8")
    observations = {item.attributes["number"]: item.attributes["state"]
                    for item in normalized.observations if item.kind == "network.port"}

    assert captured.execution.state is ExecutionState.SUCCEEDED, (
        "A failed real tool must not pass the loopback discovery oracle."
    )
    assert observations.get(open_port) == "open", "The fixture-owned listening port must be open."
    assert observations.get(closed_port) == "closed", (
        "The fixture-owned bound but non-listening port must remain closed."
    )
    assert normalized.findings == (), "The port oracle cannot make vulnerability accuracy claims."
    assert store.Read(stdout.reference) == captured.stdout, (
        "Genuine XML must remain exact evidence."
    )
