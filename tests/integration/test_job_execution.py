# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned job integration with real bounded local execution, evidence and model state."""

from __future__ import annotations

import asyncio
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.adapters import (
    AdapterInvocation,
    AdapterReport,
    AdapterRequest,
    ExecutionState,
    ImpactLevel,
    NormalizedObservation,
)
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    ExecutionResources,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutor,
)
from fuzzy1337.jobs import (
    JobContext,
    JobError,
    JobEventKind,
    JobFailure,
    JobFailureCode,
    JobSpec,
    JobState,
    LocalExecutionJob,
    ScanJob,
)
from fuzzy1337.model import ModelProvenance, ModelState, ObjectIdentity, ObjectKind, SecurityObject


def Request(script: str, *, timeout_seconds: int = 2) -> LocalExecutionRequest:
    """Bind one synthetic local Python process to the unchanged executor contract."""

    invocation = AdapterInvocation(
        "test.provider", AdapterRequest("test.local", "target:synthetic", ImpactLevel.SAFE),
        (sys.executable, "-c", script), timeout_seconds=timeout_seconds, provider_version="1",
    )

    return LocalExecutionRequest(
        invocation,
        CapabilityDescriptor("test.local", "test.provider", ImpactLevel.SAFE),
        ExecutionAuthorization(
            "authorization:test", "scope:local", "policy:synthetic", InvocationDigest(invocation),
        ),
        resources=ExecutionResources(
            max_stdout_bytes=1024, max_stderr_bytes=1024, terminate_grace_seconds=0.1,
        ),
    )


def Spec() -> JobSpec:
    """Return the synthetic workspace, provider and cancellation owner."""

    return JobSpec(
        "job:integration", "workspace-test", "scope:local", "owner:test", "test.provider",
    )


def test_RealLocalExecutionPreservesEvidenceBeforeSharedModelUpdates(tmp_path: Path) -> None:
    """Drive the real executor, evidence store and existing model through one owned job."""

    async def Scenario() -> None:
        """Normalize bounded stdout and emit the delta returned by actual model application."""

        store = LocalEvidenceStore(tmp_path)
        model = ModelState("workspace-test")

        async def Normalize(context: JobContext, report: AdapterReport) -> None:
            """Consume retained raw content and apply a typed model fact."""

            nonlocal model
            stdout = next(item for item in report.evidence if item.role == "stdout")
            assert store.Read(stdout) == b"synthetic-host\n", (
                "Normalization must read stored evidence."
            )
            provenance = ModelProvenance(
                source_id="test.provider", provider_version="1", run_reference="job:integration",
                observed_at="2026-10-11T00:00:00Z", target_reference="target:synthetic",
                scope_reference="scope:local", execution=report.execution,
                evidence_references=report.evidence,
            )
            host = SecurityObject(
                ObjectIdentity("workspace-test", ObjectKind.HOST, "127.0.0.1"),
                {"alive": True}, (provenance,),
            )
            model, delta = model.Apply(objects=(host,))
            context.Observe(NormalizedObservation("host", host.Reference(), {"alive": True}))
            context.ModelChanged(delta)

        job = ScanJob(
            Spec(), LocalExecutionJob(
                Request("print('synthetic-host')"), LocalExecutor(tmp_path).Execute, Normalize,
            ), evidence_store=store,
        )
        job.Start()

        result = await job.Wait()

        assert result.state is JobState.COMPLETED, (
            "Real bounded execution must complete successfully."
        )
        assert len(result.artifacts) == 2, "Both stdout and stderr must be durably attached."
        assert len(model.Objects(ObjectKind.HOST)) == 1, (
            "The shared model must contain the host fact."
        )
        events = job.EventsSince()
        artifact_sequence = max(
            event.sequence for event in events if event.kind is JobEventKind.ARTIFACT
        )
        delta_sequence = next(
            event.sequence for event in events if event.kind is JobEventKind.MODEL_DELTA
        )
        assert artifact_sequence < delta_sequence, (
            "Raw evidence must precede interpreted model deltas."
        )

        for artifact in result.artifacts:
            assert artifact.evidence.provenance.execution is not None, (
                "Evidence must retain exit truth."
            )
            assert store.Get(artifact.evidence.evidence_id) == artifact.evidence, (
                "Attachments must resolve through the unchanged evidence record store."
            )

    asyncio.run(Scenario())


@pytest.mark.parametrize(("script", "timeout", "expected"), [
    ("import sys; print('partial', flush=True); sys.exit(3)", 2, JobFailureCode.PROVIDER),
    ("import time; print('partial', flush=True); time.sleep(30)", 1, JobFailureCode.TIMEOUT),
    ("print('x' * 4096)", 2, JobFailureCode.OUTPUT_LIMIT),
])
def test_RealExecutorFailuresRetainRawEvidence(
    tmp_path: Path, script: str, timeout: int, expected: JobFailureCode,
) -> None:
    """Preserve bounded process output without converting failed execution into job success."""

    async def Scenario() -> None:
        """Execute one isolated synthetic process and inspect its exact retained exit state."""

        store = LocalEvidenceStore(tmp_path)
        job = ScanJob(
            Spec(), LocalExecutionJob(Request(script, timeout_seconds=timeout),
                                      LocalExecutor(tmp_path).Execute), evidence_store=store,
        )
        job.Start()

        result = await job.Wait()

        assert result.state is JobState.FAILED, (
            "Failed executor outcomes must never become success."
        )
        assert result.failure is not None and result.failure.code is expected, (
            "Executor terminal reason must retain its job failure classification."
        )
        assert len(result.artifacts) == 2, "Failure must preserve both bounded raw streams."
        stdout = next(item.evidence for item in result.artifacts if item.evidence.reference.role
                      == "stdout")
        assert store.Read(stdout.reference), "Partial or truncated stdout must remain readable."
        assert stdout.provenance.execution is not None, "Raw evidence must retain terminal truth."
        assert stdout.provenance.execution.state is not ExecutionState.SUCCEEDED, (
            "Stored failed execution must never claim successful exit."
        )

    asyncio.run(Scenario())


def test_RealExecutorCancellationReapsProcessAndPreservesPartialStreams(tmp_path: Path) -> None:
    """Request owned cancellation only after the executor has emitted real output."""

    async def Scenario() -> None:
        """Use the live heartbeat stream instead of process timing to request cancellation."""

        store = LocalEvidenceStore(tmp_path)
        job = ScanJob(
            Spec(), LocalExecutionJob(
                Request("import time; print('partial', flush=True); time.sleep(30)"),
                LocalExecutor(tmp_path).Execute,
            ), evidence_store=store,
        )
        job.Start()
        heartbeats = 0

        async for event in job.Events():
            if event.kind is JobEventKind.HEARTBEAT:
                heartbeats += 1

                if heartbeats == 2:
                    job.Cancel("owner:test")

        result = await job.Wait()

        assert result.state is JobState.CANCELLED, (
            "Cooperative executor cancellation must stay explicit."
        )
        assert len(result.artifacts) == 2, (
            "Cancelled processes must retain completed stream capture."
        )
        stdout = next(item.evidence for item in result.artifacts if item.evidence.reference.role
                      == "stdout")
        assert store.Read(stdout.reference) == b"partial\n", (
            "Cancellation must retain partial stdout."
        )
        assert stdout.provenance.execution is not None, (
            "Cancellation evidence needs terminal truth."
        )
        assert stdout.provenance.execution.state is ExecutionState.CANCELLED, (
            "Executor evidence must confirm cancellation after cleanup."
        )

    asyncio.run(Scenario())


@pytest.mark.parametrize("change", [{"scope_reference": "scope:other"},
                                     {"provider_id": "other.provider"}])
def test_LocalBridgeRejectsCrossScopeOrProviderBeforeLaunch(tmp_path: Path, change) -> None:
    """Fail closed when the job and exact authorized execution belong to different contexts."""

    async def Scenario() -> None:
        """Use a launch marker to prove the ownership rejection precedes process execution."""

        marker = tmp_path / "launched"
        request = Request("from pathlib import Path; Path('launched').touch()")
        job = ScanJob(
            replace(Spec(), **change), LocalExecutionJob(request, LocalExecutor(tmp_path).Execute),
            evidence_store=LocalEvidenceStore(tmp_path),
        )
        job.Start()

        result = await job.Wait()

        assert result.failure is not None, "Ownership mismatch must be an explicit failure."
        assert result.failure.code is JobFailureCode.AUTHORIZATION, (
            "Context mismatch must deny launch."
        )
        assert not marker.exists(), "A denied job must not execute its prepared local process."

    asyncio.run(Scenario())


def test_ProcessLaunchAndNormalizationFailuresRemainClassified(tmp_path: Path) -> None:
    """Keep launch failure and post-evidence normalization errors distinct."""

    async def Scenario() -> None:
        """Exercise both classified paths without optional tools or network dependencies."""

        request = Request("print('synthetic')")
        invalid_invocation = replace(request.invocation, argv=(str(tmp_path / "absent-tool"),))
        invalid_request = replace(
            request, invocation=invalid_invocation,
            authorization=replace(request.authorization,
                                  invocation_sha256=InvocationDigest(invalid_invocation)),
        )
        invalid = ScanJob(
            Spec(), LocalExecutionJob(invalid_request, LocalExecutor(tmp_path).Execute),
            evidence_store=LocalEvidenceStore(tmp_path),
        )
        invalid.Start()

        launch = await invalid.Wait()

        assert launch.failure is not None and launch.failure.code is JobFailureCode.PROVIDER, (
            "Unavailable executable must remain a classified launch failure."
        )

        async def BrokenHandler(context: JobContext, report: AdapterReport) -> None:
            """Reject interpretation while keeping the already preserved evidence intact."""

            raise ValueError("synthetic-parser-detail")

        parser = ScanJob(
            Spec(), LocalExecutionJob(request, LocalExecutor(tmp_path).Execute, BrokenHandler),
            evidence_store=LocalEvidenceStore(tmp_path),
        )
        parser.Start()

        normalized = await parser.Wait()

        assert normalized.failure is not None, "Rejected normalization must block job completion."
        assert normalized.failure.code is JobFailureCode.NORMALIZATION, (
            "Parser failure must be typed."
        )
        assert len(normalized.artifacts) == 2, "Parser failure must preserve raw process evidence."

        async def ClassifiedHandler(context: JobContext, report: AdapterReport) -> None:
            """Retain a handler's deliberate user-safe storage failure classification."""

            raise JobError(JobFailure(
                JobFailureCode.STORAGE, "Synthetic model persistence failure",
            ))

        classified = ScanJob(
            Spec(), LocalExecutionJob(request, LocalExecutor(tmp_path).Execute, ClassifiedHandler),
            evidence_store=LocalEvidenceStore(tmp_path),
        )
        classified.Start()

        stored = await classified.Wait()

        assert stored.failure is not None and stored.failure.code is JobFailureCode.STORAGE, (
            "Deliberate downstream classifications must survive normalization."
        )

    asyncio.run(Scenario())


def test_GovernedDenialAndHandlerCancellationRetainExactLifecycle(tmp_path: Path) -> None:
    """Accept governed callables while preserving approval denial and cleanup ownership."""

    async def Scenario() -> None:
        """Use the existing callable boundary without importing another task's policy code."""

        async def Denied(request, *, on_event=None, cancellation=None):
            """Represent a governed executor's safe PermissionError boundary."""

            raise PermissionError("synthetic-private-policy-detail")

        denied = ScanJob(
            Spec(), LocalExecutionJob(Request("print('synthetic')"), Denied),
            evidence_store=LocalEvidenceStore(tmp_path),
        )
        denied.Start()

        rejected = await denied.Wait()

        assert rejected.failure is not None, "A governed denial must block execution success."
        assert rejected.failure.code is JobFailureCode.AUTHORIZATION, (
            "Denied grant must stay typed."
        )
        assert rejected.artifacts == (), "Denied execution must not fabricate collected artifacts."
        assert "synthetic-private" not in repr(denied.EventsSince()), (
            "Denial detail must stay private."
        )
        entered = asyncio.Event()
        cleaned = asyncio.Event()

        async def Handler(context: JobContext, report: AdapterReport) -> None:
            """Keep normalization active until the owned task is explicitly cancelled."""

            entered.set()

            try:
                await asyncio.Event().wait()

            finally:
                cleaned.set()

        job = ScanJob(
            Spec(), LocalExecutionJob(
                Request("print('synthetic')"), LocalExecutor(tmp_path).Execute, Handler,
            ), evidence_store=LocalEvidenceStore(tmp_path),
        )
        job.Start()

        await entered.wait()

        cancelled = await job.CancelAndWait("owner:test", grace_seconds=0.01)

        assert cancelled.state is JobState.CANCELLED, (
            "Handler task cancellation must not be a parse error."
        )
        assert cleaned.is_set(), (
            "Handler cleanup must finish before terminal ownership is released."
        )
        assert len(cancelled.artifacts) == 2, (
            "Already published process evidence must survive cancellation."
        )

    asyncio.run(Scenario())
