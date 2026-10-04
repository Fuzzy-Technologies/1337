# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual local-executor output persists through unchanged adapter references."""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone

import pytest

from fuzzy1337.adapters import (
    AdapterInvocation,
    AdapterReport,
    AdapterRequest,
    ExecutionState,
    ImpactLevel,
)
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutor,
)

FIXTURE_SCRIPT = '''# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Emit bounded synthetic stdout/stderr from an owned fixture process."""

import sys


def Main():
    """Write exact non-secret fixture bytes and use the requested terminal code."""

    sys.stdout.buffer.write(b"owned-output\\x00\\xff\\n")
    sys.stderr.buffer.write(b"owned-diagnostic\\r\\n")

    return int(sys.argv[1])


if __name__ == "__main__":
    raise SystemExit(Main())
'''


@pytest.fixture(name="tmp_path")
def PhysicalTmpPath(tmp_path):
    """Select the known physical temporary root across platform path aliases."""

    return tmp_path.resolve()


@pytest.mark.parametrize("exit_code", [0, 7])
def test_LocalExecutorRawOutputRoundTripsWithFailureAttribution(tmp_path, exit_code):
    """Persist real captured bytes and keep failed execution separate from storage success."""

    script_path = tmp_path / "owned_evidence_fixture.py"
    script_path.write_text(FIXTURE_SCRIPT, encoding="utf-8")
    invocation = AdapterInvocation(
        adapter_id="native.evidence-fixture",
        request=AdapterRequest("test.evidence", "target:owned-local-process", ImpactLevel.PASSIVE),
        argv=(sys.executable, str(script_path), str(exit_code)),
        timeout_seconds=5,
        provider_version=f"{sys.version_info.major}.{sys.version_info.minor}",
    )
    digest = InvocationDigest(invocation)
    authorization = ExecutionAuthorization(
        "authorization:owned-test", "scope:owned-local-process", "policy:test-only", digest,
    )
    request = LocalExecutionRequest(
        invocation=invocation,
        capability=CapabilityDescriptor(
            "test.evidence", "native.evidence-fixture", ImpactLevel.PASSIVE,
        ),
        authorization=authorization,
    )
    started_at = datetime.now(timezone.utc).isoformat()
    result = asyncio.run(LocalExecutor(tmp_path).Execute(request))
    finished_at = datetime.now(timezone.utc).isoformat()
    root = tmp_path / "evidence"
    root.mkdir()
    store = LocalEvidenceStore(root)
    provenance = EvidenceProvenance(
        workspace_id="workspace:owned-fixture",
        scope_reference=authorization.scope_reference,
        source_id=invocation.adapter_id,
        source_version="1",
        tool_version=invocation.provider_version,
        started_at=started_at,
        finished_at=finished_at,
        invocation_sha256=digest,
        execution=result.execution,
    )
    stdout = store.Put(result.stdout, "stdout", "application/octet-stream", provenance)
    stderr = store.Put(result.stderr, "stderr", "application/octet-stream", provenance)
    report = AdapterReport(invocation, result.execution, (stdout.reference, stderr.reference))
    reopened = LocalEvidenceStore(root)

    assert reopened.Get(stdout.evidence_id) == stdout, (
        'Evidence invariant failed: reopened.Get(stdout.evidence_id) == stdout'
    )
    assert reopened.Get(stderr.evidence_id) == stderr, (
        'Evidence invariant failed: reopened.Get(stderr.evidence_id) == stderr'
    )
    assert reopened.Read(report.evidence[0]) == b"owned-output\x00\xff\n", (
        "Persisted stdout must preserve the exact binary fixture output."
    )
    assert reopened.Read(report.evidence[1]) == b"owned-diagnostic\r\n", (
        'Evidence invariant failed: reopened.Read(report.evidence[1]) == b"owned-diagnostic\\r\\n"'
    )
    assert stdout.provenance.invocation_sha256 == InvocationDigest(report.invocation), (
        'Evidence artifacts must retain verified original bytes and metadata.'
    )
    assert stdout.provenance.execution.exit_code == exit_code, (
        'Evidence invariant failed: stdout.provenance.execution.exit_code == exit_code'
    )
    expected_state = ExecutionState.SUCCEEDED if exit_code == 0 else ExecutionState.FAILED

    assert stdout.provenance.execution.state is expected_state, (
        "Successful evidence storage must not turn a failed tool execution into success."
    )
