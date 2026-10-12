# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned Trivy-compatible producer crosses the actual executor/evidence SDK boundary."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fuzzy1337.adapters import AdapterReport, AdapterRequest, ExecutionState, ImpactLevel
from fuzzy1337.adapters.trivy import TrivyAdapter
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
    """Preserve synthetic version/DB metadata and scan bytes through real components."""

    root = tmp_path.resolve()
    fixture = Path(__file__).parents[1] / "fixtures/trivy/synthetic_trivy.py"
    executable = root / "owned-trivy-fixture"
    executable.write_text(f"#!{sys.executable}\n" + fixture.read_text(), encoding="utf-8")
    executable.chmod(0o700)
    (root / "owned.tar").write_bytes(b"owned synthetic archive marker")
    (root / "trivy-cache").mkdir()
    (root / "evidence").mkdir()
    store = LocalEvidenceStore(root / "evidence")
    adapter = TrivyAdapter(store.Read, root, str(executable), "0.75.0-synthetic")
    probe_started = datetime.now(timezone.utc).isoformat()
    probe = adapter.ProbeHealth()
    probe_finished = datetime.now(timezone.utc).isoformat()
    request = AdapterRequest("image.archive-vulnerabilities", "target:owned-synthetic",
                             ImpactLevel.SAFE, {"archive": "owned.tar", "timeout_seconds": 10})
    invocation = adapter.PrepareInvocation(request)
    digest = InvocationDigest(invocation)
    authorization = ExecutionAuthorization("authorization:owned", "scope:owned",
                                           "policy:synthetic-only", digest)
    execution_request = LocalExecutionRequest(invocation,
        CapabilityDescriptors(adapter.Descriptor)[0], authorization)
    started = datetime.now(timezone.utc).isoformat()
    captured = asyncio.run(LocalExecutor(root).Execute(execution_request))
    finished = datetime.now(timezone.utc).isoformat()
    provenance = EvidenceProvenance("workspace:synthetic", authorization.scope_reference,
        adapter.Descriptor.adapter_id, adapter.Descriptor.version, probe.health.provider_version,
        started, finished, digest, captured.execution)
    stdout = store.Put(captured.stdout, "stdout", "application/json", provenance)
    stderr = store.Put(captured.stderr, "stderr", "text/plain", provenance)
    version_provenance = EvidenceProvenance("workspace:synthetic", authorization.scope_reference,
        adapter.Descriptor.adapter_id, adapter.Descriptor.version, probe.health.provider_version,
        probe_started, probe_finished)
    version = store.Put(probe.stdout, "provider-version", "application/json", version_provenance)
    report = AdapterReport(invocation, captured.execution,
                           (stdout.reference, stderr.reference, version.reference))
    result = adapter.NormalizeReport(report)

    assert (
        captured.execution.state is ExecutionState.SUCCEEDED
    ), (
        "Preserve synthetic version/DB metadata and scan bytes through real components."
    )
    assert (
        result.report is report and len(result.findings) == 1
    ), (
        "Preserve synthetic version/DB metadata and scan bytes through real components."
    )
    assert (
        store.Read(stdout.reference) == captured.stdout
    ), (
        "Preserve synthetic version/DB metadata and scan bytes through real components."
    )
    assert (
        store.Get(stdout.evidence_id).provenance.invocation_sha256 == digest
    ), (
        "Preserve synthetic version/DB metadata and scan bytes through real components."
    )
    assert (
        store.Get(version.evidence_id).provenance.tool_version == "0.75.0-synthetic"
    ), (
        "Preserve synthetic version/DB metadata and scan bytes through real components."
    )
    assert (
        result.observations[0].attributes["database_metadata"]["Version"] == 2
    ), (
        "Preserve synthetic version/DB metadata and scan bytes through real components."
    )
    assert (
        result.observations[0].attributes["provider_version"] == "0.75.0-synthetic"
    ), (
        "Preserve synthetic version/DB metadata and scan bytes through real components."
    )
    assert (
        b"no image decode or network activity" in store.Read(stderr.reference)
    ), (
        "Preserve synthetic version/DB metadata and scan bytes through real components."
    )


@pytest.mark.skipif(os.name == "nt", reason="owned executable fixture uses a POSIX shebang")
@pytest.mark.parametrize("mode", ["invalid", "nonzero", "oversized", "timeout"])
def test_HealthProbeFailureBudgets(tmp_path, monkeypatch, mode):
    """Actual owned version subprocess cannot hide invalid, failed or over-budget output."""

    from fuzzy1337.adapters import AdapterHealthState, trivy

    root = tmp_path.resolve()
    (root / "trivy-cache").mkdir()
    executable = root / "owned-health-fixture"
    header = ('# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies\n'
              '# SPDX-License-Identifier: Apache-2.0\n'
              '"""Owned health failure fixture with no scanning."""\n')
    bodies = {"invalid": 'print("not JSON")\n', "nonzero": 'raise SystemExit(7)\n',
              "oversized": 'print("X" * 20000)\n',
              "timeout": 'import time\ntime.sleep(10)\n'}
    executable.write_text(f"#!{sys.executable}\n" + header + bodies[mode], encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setattr(trivy, "TRIVY_HEALTH_TIMEOUT_SECONDS", 0.05)
    adapter = TrivyAdapter(lambda item: b"", root, str(executable))
    probe = adapter.ProbeHealth()

    assert (
        probe.health.state is AdapterHealthState.DEGRADED
    ), (
        "Actual owned version subprocess cannot hide invalid, failed or over-budget output."
    )
    assert (
        len(probe.stdout) <= trivy.TRIVY_HEALTH_MAX_BYTES
    ), (
        "Actual owned version subprocess cannot hide invalid, failed or over-budget output."
    )
