# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exact prepared fixture argv crosses executor, evidence storage, and normalization."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fuzzy1337.adapters import (
    AdapterHealthState,
    AdapterReport,
    AdapterRequest,
    ExecutionState,
    ImpactLevel,
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


@pytest.mark.skipif(os.name == "nt", reason="owned executable fixture uses a POSIX shebang")
def test_PreparedFixtureExecutionEvidenceAndNormalization(tmp_path):
    """Use actual bounded subprocess output without pretending the fixture is live Nmap.

    Args:
        tmp_path: Pytest owned temporary directory, selected physically for the executor.
    """

    root = tmp_path.resolve()
    fixture = Path(__file__).parents[1] / "fixtures/nmap/synthetic_nmap.py"
    executable = root / "owned-nmap-fixture"
    executable.write_text(f"#!{sys.executable}\n" + fixture.read_text(encoding="utf-8"),
                          encoding="utf-8")
    executable.chmod(0o700)
    evidence_root = root / "evidence"
    evidence_root.mkdir()
    store = LocalEvidenceStore(evidence_root)
    adapter = NmapAdapter(store.Read, str(executable), "7.95-synthetic")
    health = adapter.CheckHealth()

    assert health.state is AdapterHealthState.AVAILABLE, (
        "Actual owned --version output must pass the bounded health observation."
    )
    assert health.provider_version == "7.95-synthetic", (
        "Synthetic health must keep its explicit fixture version."
    )
    request = AdapterRequest("network.tcp-connect", "target:owned-synthetic", ImpactLevel.STANDARD,
                             {"address": "127.0.0.1", "ports": [443, 80], "timeout_seconds": 10})
    invocation = adapter.PrepareInvocation(request)
    digest = InvocationDigest(invocation)
    authorization = ExecutionAuthorization("authorization:owned-fixture", "scope:owned-fixture",
                                           "policy:synthetic-only", digest)
    execution_request = LocalExecutionRequest(invocation,
        CapabilityDescriptors(adapter.Descriptor)[0], authorization)
    started_at = datetime.now(timezone.utc).isoformat()
    captured = asyncio.run(LocalExecutor(root).Execute(execution_request))
    finished_at = datetime.now(timezone.utc).isoformat()
    provenance = EvidenceProvenance("workspace:synthetic", authorization.scope_reference,
        adapter.Descriptor.adapter_id, adapter.Descriptor.version, "7.95-synthetic",
        started_at, finished_at, digest, captured.execution)
    stdout = store.Put(captured.stdout, "stdout", "application/xml", provenance)
    stderr = store.Put(captured.stderr, "stderr", "text/plain", provenance)
    report = AdapterReport(invocation, captured.execution, (stdout.reference, stderr.reference))
    normalized = adapter.NormalizeReport(report)

    assert captured.execution.state is ExecutionState.SUCCEEDED, (
        "The owned producer must accept the exact prepared finite profile."
    )
    assert normalized.report is report, "Original executor facts and evidence must remain intact."
    assert store.Read(stdout.reference) == captured.stdout, (
        "XML bytes must survive storage exactly."
    )
    assert store.Get(stdout.evidence_id).provenance.invocation_sha256 == digest, (
        "Evidence must attribute the actual prepared and executed fixture command."
    )
    assert store.Get(stdout.evidence_id).provenance.tool_version == "7.95-synthetic", (
        "Fixture provenance must not claim a genuine installed Nmap tool."
    )
    assert b"no network activity" in store.Read(stderr.reference), (
        "The raw fixture diagnostic must remain independently inspectable."
    )
    assert tuple(item.attributes["state"] for item in normalized.observations
                 if item.kind == "network.port") == ("open", "closed"), (
        "The real captured producer bytes must reach the existing normalized envelopes."
    )
    assert len(normalized.object_enrichments) == 4, (
        "Fixture XML must yield one host, two ports, and one service proposal."
    )
