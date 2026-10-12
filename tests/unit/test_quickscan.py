# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic Quick Scan ownership, persistence, consumer and summary boundaries."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from fuzzy1337 import quickscan
from fuzzy1337.discovery import NATIVE_HTTP_PROVIDER_ID
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.jobs import (
    JobContext,
    JobError,
    JobFailure,
    JobFailureCode,
    JobSnapshot,
    JobSpec,
    JobState,
)
from fuzzy1337.quickscan import QuickScanSummary, RunQuickScan
from fuzzy1337.scan_commands import CreateWorkspace
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore


@pytest.fixture(scope="module")
def runner() -> Iterator[asyncio.Runner]:
    """Initialize loop resources before the unit network guard, then own their teardown."""

    with asyncio.Runner() as owned_runner:
        yield owned_runner


def Workspace(root: Path) -> tuple[Target, ...]:
    """Create an isolated authoritative model and explicit non-secret synthetic consent."""

    CreateWorkspace(root, "synthetic", "Synthetic")
    targets = (Target(TargetKind.URL, "http://127.0.0.1:1/"), Target(TargetKind.IP, "127.0.0.1"))
    now = datetime.now(UTC)
    authorization = ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:fixture", "consent:fixture",
        (now - timedelta(minutes=1)).isoformat(), (now + timedelta(minutes=1)).isoformat(),
    )
    LocalScopeStore(root).Create(ScopeSnapshot(
        "local", "synthetic", authorization, targets=targets, allow=targets,
    ))

    return targets[:1]


class EvidenceProvider:
    """Produce deterministic owned evidence while exercising the real coordinator stores."""

    def __init__(self, *args, **kwargs) -> None:
        """Retain the same constructor boundary without touching any network or subprocess."""

        self.policy = args[3]

    async def Run(self, context: JobContext) -> None:
        """Publish safe bytes only when the explicit capability policy is populated."""

        if not self.policy.permissions:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION, "Synthetic capability denial"))

        now = datetime.now(UTC).isoformat()
        context.CaptureEvidence(b"raw-safe-marker", "stdout", "text/plain", EvidenceProvenance(
            context.Spec.workspace_id, context.Spec.scope_reference,
            NATIVE_HTTP_PROVIDER_ID, "1", "1", now, now,
        ))
        context.Progress(1, 1)


def test_QuickScanPersistsOnlyVerifiedJobEvidenceAndReturnsDetachedSummary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: asyncio.Runner,
) -> None:
    """Use real CAS and evidence records to prove the coordinator's durable metadata contract."""

    root = tmp_path / "workspace"
    targets = Workspace(root)
    monkeypatch.setattr(quickscan, "NativeDiscoveryProvider", EvidenceProvider)
    result = runner.run(RunQuickScan(root, "local", targets, "operator:fixture",
                                    approve_safe_http=True))
    workspace = LocalWorkspaceStore(root).Open()
    assert result.snapshot.state is JobState.COMPLETED, "Verified provider completion must survive."
    assert result.ExitCode() == 0, "Successful execution is distinct from findings thresholds."
    assert workspace.job_references == (result.snapshot.spec.job_id,), (
        "Durable metadata must identify the actual completed owned job."
    )
    assert workspace.scope_references == ("scope:local",), "Scope attribution must survive reopen."
    assert len(workspace.evidence_record_references) == 1, "Records must remain discoverable."
    raw = LocalEvidenceStore(root / "evidence").Read(workspace.evidence_references[0])
    assert raw == b"raw-safe-marker", (
        "Use real CAS and evidence records to prove the coordinator's durable metadata "
        'contract invariant failed.'
    )
    document = result.ToDict()
    assert document["first_model_update_seconds"] is None, "Evidence alone is not a model delta."
    assert "raw-safe-marker" not in json.dumps(document), (
        "Raw content must not be copied into event or summary payloads."
    )
    document["object_counts"] = {}
    assert result.ToDict()["object_counts"], "Machine output must detach from summary state."


@pytest.mark.parametrize("owner, approved", [("operator:other", True), ("operator:fixture", False)])
def test_QuickScanOwnerAndMissingCapabilityDenialRemainTruthful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: asyncio.Runner,
    owner: str, approved: bool,
) -> None:
    """Fail before useful acquisition when owner or capability approval is absent."""

    root = tmp_path / "workspace"
    targets = Workspace(root)
    monkeypatch.setattr(quickscan, "NativeDiscoveryProvider", EvidenceProvider)
    result = runner.run(RunQuickScan(root, "local", targets, owner, approve_safe_http=approved))
    assert result.snapshot.state is JobState.FAILED, "Denied actions must never claim scan success."
    assert result.ExitCode() == 3, "Authority denial must retain its dedicated exit status."
    assert result.snapshot.failure is not None, (
        'Fail before useful acquisition when owner or capability approval is absent '
        'invariant failed.'
    )
    assert result.snapshot.failure.code is JobFailureCode.AUTHORIZATION, (
        'Fail before useful acquisition when owner or capability approval is absent '
        'invariant failed.'
    )
    assert result.snapshot.artifacts == (), "Denied acquisition must not fabricate evidence."


def test_QuickScanMetadataStorageFailureBlocksTerminalSuccess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: asyncio.Runner,
) -> None:
    """A completed provider cannot claim a completed job after the workspace CAS fails."""

    root = tmp_path / "workspace"
    targets = Workspace(root)
    monkeypatch.setattr(quickscan, "NativeDiscoveryProvider", EvidenceProvider)

    def FailSave(self, state):
        """Inject a real storage failure after evidence publication without leaking details."""

        raise OSError("synthetic-private-storage-detail")

    monkeypatch.setattr(LocalWorkspaceStore, "Save", FailSave)
    result = runner.run(RunQuickScan(root, "local", targets, "operator:fixture",
                                    approve_safe_http=True))
    assert result.snapshot.state is JobState.FAILED, "Failed durable metadata must block success."
    assert result.ExitCode() == 4, "Storage is an execution error, not a scope denial."
    assert result.snapshot.failure is not None, (
        'A completed provider cannot claim a completed job after the workspace CAS fails '
        'invariant failed.'
    )
    assert result.snapshot.failure.code is JobFailureCode.STORAGE, (
        'A completed provider cannot claim a completed job after the workspace CAS fails '
        'invariant failed.'
    )
    assert "private" not in json.dumps(result.ToDict()), "Exception text must not be exposed."
    assert len(result.snapshot.artifacts) == 1, "Published evidence must survive CAS failure."
    record = result.snapshot.artifacts[0].evidence
    assert LocalEvidenceStore(root / "evidence").Get(record.evidence_id) == record, (
        'A completed provider cannot claim a completed job after the workspace CAS fails '
        'invariant failed.'
    )


def test_QuickScanCancelledConsumerAwaitsOwnedCleanupAndPersistsReferences(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: asyncio.Runner,
) -> None:
    """Turn operator interruption into a truthful cancelled summary after owned cleanup."""

    root = tmp_path / "workspace"
    targets = Workspace(root)

    async def Scenario() -> None:
        """Cancel the presentation caller only after the provider owns a running job."""

        entered = asyncio.Event()
        cleaned = asyncio.Event()

        class WaitingProvider(EvidenceProvider):
            """Yield to cooperative cancellation and complete cleanup before leaving Run."""

            async def Run(self, context: JobContext) -> None:
                """Block indefinitely until the owning operator's explicit cancellation signal."""

                entered.set()

                try:
                    await context.Cancellation.wait()
                    context.CheckCancellation()

                finally:
                    cleaned.set()

        monkeypatch.setattr(quickscan, "NativeDiscoveryProvider", WaitingProvider)
        task = asyncio.create_task(RunQuickScan(root, "local", targets, "operator:fixture",
                                               approve_safe_http=True))

        await entered.wait()

        task.cancel()
        result = await task
        assert cleaned.is_set(), "Summary must follow actual provider cleanup."
        assert result.ExitCode() == 130, "Cancelled scans must retain their terminal exit status."
        assert result.snapshot.state is JobState.CANCELLED, (
            'Turn operator interruption into a truthful cancelled summary after owned '
            'cleanup invariant failed.'
        )
        assert result.snapshot.spec.job_id in LocalWorkspaceStore(root).Open().job_references, (
            'Turn operator interruption into a truthful cancelled summary after owned '
            'cleanup invariant failed.'
        )

    runner.run(Scenario())


def test_QuickScanPresentationFailureDetachesOnlyAfterJobCleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: asyncio.Runner,
) -> None:
    """Never abandon an owned running job after an event presentation sink fails."""

    root = tmp_path / "workspace"
    targets = Workspace(root)
    monkeypatch.setattr(quickscan, "NativeDiscoveryProvider", EvidenceProvider)

    def BrokenSink(event):
        """Represent a deterministic caller presentation failure with private details."""

        raise ValueError("synthetic-presentation-failure")

    with pytest.raises(ValueError, match="presentation"):
        runner.run(RunQuickScan(root, "local", targets, "operator:fixture",
                               approve_safe_http=True, on_event=BrokenSink))

    async def Remaining() -> int:
        """Count jobs that escaped cleanup while ignoring the current observer task."""

        return len(asyncio.all_tasks()) - 1

    assert runner.run(Remaining()) == 0, "Presentation failure must leave no owned background task."


@pytest.mark.parametrize("approved", [None, 1, "yes"])
def test_QuickScanRejectsImplicitApprovalBeforeReadingLocalState(
    tmp_path: Path, runner: asyncio.Runner, approved: object,
) -> None:
    """Require an actual boolean capability flag rather than coercing arbitrary caller data."""

    with pytest.raises(ValueError, match="boolean"):
        runner.run(RunQuickScan(tmp_path / "absent", "local", (), "operator:fixture",
                               approve_safe_http=approved))  # type: ignore[arg-type]


@pytest.mark.parametrize("state, code, expected", [
    (JobState.COMPLETED, None, 0), (JobState.CANCELLED, None, 130),
    (JobState.FAILED, JobFailureCode.AUTHORIZATION, 3),
    (JobState.FAILED, JobFailureCode.TIMEOUT, 4),
])
def test_QuickScanMachineExitCodesSeparateExecutionFromFindingThresholds(state, code, expected):
    """Freeze terminal status semantics independently from any vulnerability finding count."""

    spec = JobSpec("job:fixture", "fixture", "scope:fixture", "operator:fixture", "native.http")
    failure = JobFailure(code, "Synthetic failure") if code is not None else None
    snapshot = JobSnapshot(spec, state, 0, None, failure, (), False)
    summary = QuickScanSummary(snapshot, "start", "finish", 1, None, 4, 0, (("host", 0),), ())
    assert summary.ExitCode() == expected, (
        'Freeze terminal status semantics independently from any vulnerability finding '
        'count invariant failed.'
    )
    assert summary.ToDict()["state"] == state.value, (
        'Freeze terminal status semantics independently from any vulnerability finding '
        'count invariant failed.'
    )
