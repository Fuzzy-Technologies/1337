# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned Nuclei-format argv crosses the existing executor, evidence, and adapter boundaries."""

from __future__ import annotations

import asyncio
import hashlib
import os
import sys
from dataclasses import replace
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
from fuzzy1337.adapters.nuclei import NucleiAdapter, NucleiProfile, NucleiTemplate
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptors,
    ExecutionAuthorization,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutor,
)


@pytest.mark.skipif(os.name == "nt", reason="owned executable fixture uses a POSIX shebang")
def test_PreparedOwnedProducerExecutionEvidenceAndNormalization(tmp_path):
    """Execute actual exact prepared argv without pretending the fixture performs a real scan."""

    root = tmp_path.resolve()
    fixtures = Path(__file__).parents[1] / "fixtures/nuclei"
    executable = root / "owned-nuclei-fixture"
    executable.write_text(f"#!{sys.executable}\n"
                          + (fixtures / "synthetic_nuclei.py").read_text(encoding="utf-8"),
                          encoding="utf-8")
    executable.chmod(0o700)
    template_path = root / "reviewed-get.yaml"
    raw_template = (fixtures / "reviewed-get.yaml").read_bytes()
    template_path.write_bytes(raw_template)
    configuration_path = root / "nuclei-empty.yaml"
    configuration_path.write_bytes(b"{}\n")
    template = NucleiTemplate("owned-http-marker", str(template_path),
        hashlib.sha256(raw_template).hexdigest(), len(raw_template), "fixture:owned-nuclei", "1",
        "review:exact-source-controlled-synthetic", "single-get-exact-url")
    profile = NucleiProfile("owned-synthetic", (template,), str(configuration_path))
    evidence_root = root / "evidence"
    evidence_root.mkdir()
    store = LocalEvidenceStore(evidence_root)
    adapter = NucleiAdapter(store.Read, profile, str(executable), "3.4.10-synthetic")
    health = adapter.CheckHealth()

    assert health.state is AdapterHealthState.AVAILABLE, "Owned version-only producer must run."
    assert health.provider_version == "3.4.10-synthetic", "Fixture provenance must remain explicit."

    request = AdapterRequest("web.http-template-check", "target:owned", ImpactLevel.STANDARD,
        {"url": "http://127.0.0.1:8080/", "profile_sha256": profile.Digest,
         "timeout_seconds": 10, "rate_limit": 2})
    invocation = adapter.PrepareInvocation(request)
    digest = InvocationDigest(invocation)
    authorization = ExecutionAuthorization("authorization:owned", "scope:owned-synthetic",
                                           "policy:owned-fixture-only", digest)
    execution_request = LocalExecutionRequest(invocation,
        CapabilityDescriptors(adapter.Descriptor)[0], authorization)
    executor = LocalExecutor(root)

    with pytest.raises(ValueError, match="authorization"):
        asyncio.run(executor.Execute(replace(execution_request,
            authorization=replace(authorization, invocation_sha256="0" * 64))))

    started_at = datetime.now(timezone.utc).isoformat()
    captured = asyncio.run(executor.Execute(execution_request))
    finished_at = datetime.now(timezone.utc).isoformat()
    provenance = EvidenceProvenance("workspace:owned", authorization.scope_reference,
        adapter.Descriptor.adapter_id, adapter.Descriptor.version, health.provider_version,
        started_at, finished_at, digest, captured.execution)
    stdout = store.Put(captured.stdout, "stdout", "application/x-ndjson", provenance)
    stderr = store.Put(captured.stderr, "stderr", "text/plain", provenance)
    report = AdapterReport(invocation, captured.execution, (stdout.reference, stderr.reference))
    normalized = adapter.NormalizeReport(report)

    assert captured.execution.state is ExecutionState.SUCCEEDED, (
        "The owned producer must accept exact deterministic genuine Nuclei-format flags."
    )
    assert normalized.report is report, "Original execution and evidence cannot be replaced."
    assert store.Read(stdout.reference) == captured.stdout, "Actual stdout must survive storage."
    assert store.Get(stdout.evidence_id).provenance.invocation_sha256 == digest, (
        "Evidence must attribute exact authorized invocation metadata."
    )
    assert store.Get(stdout.evidence_id).provenance.tool_version == "3.4.10-synthetic", (
        "Owned format fixtures must not claim an installed genuine scanner execution."
    )
    assert b"no network activity" in store.Read(stderr.reference), (
        "Independent raw diagnostics preserve the producer's actual scope."
    )
    assert normalized.findings[0].attributes["template_sha256"] == template.sha256, (
        "Real captured JSONL must retain the exact selected review-bound artifact."
    )
    assert normalized.findings[0].subject_reference == "target:owned", (
        "Actual producer output reaches existing provider-neutral SDK envelopes."
    )
