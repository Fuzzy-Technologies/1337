# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned job integration with real bounded local execution, evidence and model state."""

from __future__ import annotations

import asyncio
import errno
import os
import signal
import sys
import time
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
    local,
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


@pytest.mark.skipif(os.name != "posix", reason="owned POSIX process-group race contract")
@pytest.mark.parametrize("outcome", ["output_limit", "timeout", "cancellation"])
def test_ExitSignalRaceRetainsActualJobReasonAndRawEvidence(
    tmp_path: Path, monkeypatch, outcome: str,
) -> None:
    """Reap a real child after injected EPERM without inventing authorization failure or success."""

    async def Scenario() -> None:
        """Release only the owned child at the signal boundary and inspect durable job truth."""

        marker = tmp_path / "owned-child-release"
        evidence_root = tmp_path / "evidence"
        evidence_root.mkdir()
        store = LocalEvidenceStore(evidence_root)
        executor = LocalExecutor(tmp_path)
        processes = []
        signals = []
        start = executor.StartProcess
        original_signal = local.KillProcessGroup

        async def Start(request, workspace, environment):
            """Capture the actual owned process without changing launch or policy parameters."""

            process = await start(request, workspace, environment)
            processes.append(process)

            return process

        def Signal(process_id: int, selected: int) -> None:
            """Force a kernel-exit handoff before its event-loop returncode callback runs."""

            assert processes and process_id == processes[0].pid, (
                "Fault injection must address only this fixture's actual owned child."
            )
            signals.append(selected)

            if selected == signal.SIGTERM:
                assert processes[0].returncode is None, "The regression requires a late-exit race."
                marker.touch()
                time.sleep(0.05)

                raise PermissionError(errno.EPERM, "synthetic exited-group race")

            assert selected == 0 and processes[0].returncode is not None, (
                "The only further group operation must be non-mutating proof after observed exit."
            )
            original_signal(process_id, selected)

        monkeypatch.setattr(executor, "StartProcess", Start)
        monkeypatch.setattr(local, "KillProcessGroup", Signal)
        output = "x" * 4096 if outcome == "output_limit" else "partial"
        script = (
            f"import pathlib,time; print({output!r}, flush=True); "
            "marker=pathlib.Path('owned-child-release'); "
            "exec('while not marker.exists(): time.sleep(0.001)')"
        )
        job = ScanJob(
            Spec(), LocalExecutionJob(Request(script, timeout_seconds=1), executor.Execute),
            evidence_store=store,
        )

        try:
            job.Start()

            if outcome == "cancellation":
                heartbeats = 0

                async for event in job.Events():
                    if event.kind is JobEventKind.HEARTBEAT:
                        heartbeats += 1

                        if heartbeats == 2:
                            job.Cancel("owner:test")

            result = await asyncio.wait_for(job.Wait(), 3)
            expected_state = JobState.CANCELLED if outcome == "cancellation" else JobState.FAILED
            assert result.state is expected_state, (
                "An exit race must preserve actual terminal truth."
            )

            if outcome != "cancellation":
                expected = JobFailureCode.OUTPUT_LIMIT if outcome == "output_limit" else (
                    JobFailureCode.TIMEOUT
                )
                assert result.failure is not None and result.failure.code is expected, (
                    "A post-launch exit race cannot become a false authorization denial."
                )

            assert len(result.artifacts) == 2, "Both actually captured raw streams must remain."
            stdout = next(item.evidence for item in result.artifacts if (
                item.evidence.reference.role == "stdout"
            ))
            expected_output = b"x" * 1024 if outcome == "output_limit" else b"partial\n"
            assert store.Read(stdout.reference) == expected_output, (
                "Recovered cleanup must preserve exact bounded or partial stdout evidence."
            )
            assert stdout.provenance.execution is not None and (
                stdout.provenance.execution.state is not ExecutionState.SUCCEEDED
            ), "A raced zero exit cannot turn stopped execution evidence into success."
            assert signals == [signal.SIGTERM, 0], (
                "Reaped child identifiers must not be re-signaled."
            )
            assert processes[0].returncode == 0, (
                "The real owned child must be independently reaped."
            )
            assert asyncio.all_tasks() == {asyncio.current_task()}, (
                "Executor waiters must be reaped."
            )

        finally:
            marker.touch()
            monkeypatch.setattr(local, "KillProcessGroup", original_signal)

            for process in processes:
                drains = [asyncio.create_task(reader.read()) for reader in (
                    process.stdout, process.stderr,
                ) if reader is not None]
                await executor.Terminate(process, 0.1)
                await asyncio.wait_for(asyncio.gather(*drains), 1)

    asyncio.run(Scenario())


@pytest.mark.skipif(os.name != "posix", reason="owned POSIX signal-denial fault injection")
@pytest.mark.parametrize("before_launch", [False, True])
def test_JobSeparatesLaunchAuthorityFromLiveChildCleanupDenial(
    tmp_path: Path, monkeypatch, before_launch: bool,
) -> None:
    """Keep real pre-launch denial separate from unrecovered live-child provider failure."""

    async def Scenario() -> None:
        """Never suppress live signaling denial and restore ownership before fixture teardown."""

        executor = LocalExecutor(tmp_path)
        processes = []
        start = executor.StartProcess
        original_signal = local.KillProcessGroup

        async def Start(request, workspace, environment):
            """Capture only the actual child launched by this isolated fixture."""

            child = await start(request, workspace, environment)
            processes.append(child)

            return child

        def Signal(process_id: int, selected: int) -> None:
            """Deny cleanup without exiting or signaling the real live owned child."""

            assert processes and process_id == processes[0].pid, "Only the owned child may be used."
            assert selected == signal.SIGTERM, "A live denied child must not get false exit proof."

            raise PermissionError(errno.EPERM, "synthetic genuine live-child denial")

        def Deny(request) -> None:
            """Reject authority before any subprocess can be started."""

            raise PermissionError("synthetic pre-launch authority denial")

        async def Execute(request, **kwargs):
            """Bind the existing pre-launch boundary only for the authorization case."""

            return await executor.Execute(
                request, **kwargs, pre_launch=Deny if before_launch else None,
            )

        monkeypatch.setattr(executor, "StartProcess", Start)
        monkeypatch.setattr(local, "KillProcessGroup", Signal)
        job = ScanJob(Spec(), LocalExecutionJob(
            Request("import time; print('x'*4096, flush=True); time.sleep(30)"), Execute,
        ), evidence_store=LocalEvidenceStore(tmp_path))

        try:
            job.Start()
            result = await asyncio.wait_for(job.Wait(), 3)
            expected = JobFailureCode.AUTHORIZATION if before_launch else JobFailureCode.PROVIDER
            assert result.state is JobState.FAILED and result.failure is not None, (
                "Unresolved authorization or owned cleanup must remain explicit failure."
            )
            assert result.failure.code is expected, "Post-launch denial cannot be a policy denial."
            assert not result.artifacts, "Unconfirmed terminal cleanup must not fabricate evidence."

            if before_launch:
                assert not processes, "True policy denial must prevent process launch."

            else:
                assert result.failure.message == (
                    "The approved local execution could not complete"
                ), (
                    "The provider message must accurately cover both launch and cleanup failure."
                )
                assert processes[0].returncode is None, (
                    "The live-denial fixture must not pretend the child was cleaned successfully."
                )

            assert asyncio.all_tasks() == {asyncio.current_task()}, "No owned waiter may remain."

        finally:
            monkeypatch.setattr(local, "KillProcessGroup", original_signal)

            for process in processes:
                drains = [asyncio.create_task(reader.read()) for reader in (
                    process.stdout, process.stderr,
                ) if reader is not None]
                await executor.Terminate(process, 0.1)
                await asyncio.wait_for(asyncio.gather(*drains), 1)
                assert process.returncode is not None, (
                    "The fixture must finally reap its own child."
                )

    asyncio.run(Scenario())


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
                Request("import sys; sys.stdout.buffer.write(b'synthetic-host\\n')"),
                LocalExecutor(tmp_path).Execute, Normalize,
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
    (
        "import sys; sys.stdout.buffer.write(b'partial\\n'); sys.stdout.flush(); sys.exit(3)",
        2, JobFailureCode.PROVIDER,
    ),
    (
        "import sys,time; sys.stdout.buffer.write(b'partial\\n'); "
        "sys.stdout.flush(); time.sleep(30)",
        1, JobFailureCode.TIMEOUT,
    ),
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
                Request(
                    "import sys,time; sys.stdout.buffer.write(b'partial\\n'); "
                    "sys.stdout.flush(); time.sleep(30)"
                ),
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
