# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real owned portable producer execution, raw-evidence truth and fresh acceptance lifecycle."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import replace
from datetime import timedelta

import pytest
from artifact_helpers import AT, OwnedArtifact

from fuzzy1337.adapters import ExecutionState
from fuzzy1337.artifact_inputs import ArtifactProfile
from fuzzy1337.artifact_policy import (
    ArtifactDenialReason,
    ArtifactDeniedError,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
    GovernedArtifactExecutor,
    PrepareArtifact,
    VerifyArtifactReplay,
)
from fuzzy1337.executors import ExecutionEventKind, ExecutionResources, ExecutionTermination
from fuzzy1337.scope import AuthorizationState, LocalScopeStore


@pytest.mark.parametrize(
    "profile",
    [
        ArtifactProfile.SYNTHETIC_IMAGE,
        ArtifactProfile.SYNTHETIC_DOCKERFILE,
        ArtifactProfile.SYNTHETIC_KUBERNETES,
    ],
)
def test_ReviewedOwnedProfileReturnsRawAndFreshReceipt(tmp_path, profile):
    """All three closed synthetic profiles traverse the actual portable subprocess boundary."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path, profile=profile)
    executor = GovernedArtifactExecutor(root, clock=lambda: AT)
    outcome = asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))
    executor.ValidateAcceptance(outcome, prepared, stage, context, at=AT)
    payload = json.loads(outcome.raw_result.stdout)

    assert payload["fixture_id"] == "owned-artifact-lifecycle-v1", "Unowned producer ran"
    assert outcome.raw_result.execution.state == ExecutionState.SUCCEEDED, "Owned child failed"
    assert outcome.acceptance.refusal is None, "Fresh approved owned raw result was refused"
    assert outcome.Metadata()["grant"]["plan"]["profile"] == profile.value, (
        "Original fixed profile provenance was lost"
    )

    with pytest.raises(ArtifactDeniedError):
        asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))


@pytest.mark.parametrize(
    "mode,termination",
    [
        ("failure", ExecutionTermination.PROCESS_EXIT),
        ("overflow", ExecutionTermination.OUTPUT_LIMIT),
        ("wait", ExecutionTermination.TIMEOUT),
    ],
)
def test_RealFailureKeepsExactRawFactsBeforeRefusal(tmp_path, mode, termination):
    """Timeout, output limit and child failure never become a successful acceptance."""

    root, stage, _, context, _ = OwnedArtifact(tmp_path, mode=mode)
    prepared = PrepareArtifact(
        stage, root, timeout_seconds=1, resources=ExecutionResources(max_stdout_bytes=1024)
    )
    grant = ArtifactPolicyEngine().Authorize(prepared, stage, context, at=AT)
    outcome = asyncio.run(
        GovernedArtifactExecutor(root, clock=lambda: AT).Execute(
            prepared,
            stage,
            grant,
            lambda: context,
        )
    )

    assert outcome.raw_result.termination == termination, "Real executor stop reason changed"
    assert outcome.acceptance.refusal == ArtifactDenialReason.EXECUTION_FAILED, (
        "Non-successful raw result was accepted"
    )
    assert outcome.raw_result.stdout, "Partial raw stdout was discarded before capture"

    if mode == "overflow":
        assert outcome.raw_result.stdout == b"x" * 1024, "Exact bounded partial stdout changed"

    if mode == "failure":
        assert outcome.raw_result.stderr == b"owned-failure\n", "Raw stderr was discarded"


def test_CooperativeCancellationReturnsRawBeforeAcceptanceDenial(tmp_path):
    """Cancellation after owned readiness returns actual partial bytes and cancelled facts."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path, mode="wait")

    async def Run():
        """Cancel only the actual owned worker after its explicit readiness bytes."""

        cancelled = asyncio.Event()

        def OnEvent(event):
            """Use only this owned worker's stdout event as deterministic cancellation readiness."""

            if event.data == b"owned-ready\n":
                cancelled.set()

        return await GovernedArtifactExecutor(root, clock=lambda: AT).Execute(
            prepared,
            stage,
            grant,
            lambda: context,
            on_event=OnEvent,
            cancellation=cancelled,
        )

    outcome = asyncio.run(Run())

    assert outcome.raw_result.termination == ExecutionTermination.CANCELLATION, "Cancellation lost"
    assert outcome.raw_result.stdout == b"owned-ready\n", "Cancelled partial evidence was lost"
    assert outcome.acceptance.refusal == ArtifactDenialReason.EXECUTION_FAILED, "Cancel accepted"


def test_PostRunMutationPreservesRawSuccessButRefusesNormalization(tmp_path):
    """A child exit zero does not authorize results from changed input bytes."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path, mode="mutate")
    executor = GovernedArtifactExecutor(root, clock=lambda: AT)
    outcome = asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))

    assert outcome.raw_result.execution.state == ExecutionState.SUCCEEDED, (
        "Actual exit was relabeled"
    )
    assert outcome.raw_result.stdout, "Changed-material refusal discarded raw evidence"
    assert outcome.acceptance.refusal == ArtifactDenialReason.MATERIAL_CHANGED, "Mutation accepted"

    with pytest.raises(ArtifactDeniedError):
        executor.ValidateAcceptance(outcome, prepared, stage, context, at=AT)


@pytest.mark.parametrize("change", ["revoke", "expire", "owner", "policy", "context-error"])
def test_ChangedAuthorityAfterLaunchNeverLosesRawEvidence(tmp_path, change):
    """Fresh post-run refusal is per run and preserves original process/provenance facts."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    completed = False

    def Current():
        """Switch authority only after the actual owned child completed."""

        if not completed:
            return context

        if change == "revoke":
            scope = LocalScopeStore(root).Save(
                replace(
                    context.scope,
                    authorization=replace(
                        context.scope.authorization,
                        state=AuthorizationState.REVOKED,
                    ),
                )
            )

            return replace(context, scope=scope)

        if change == "owner":
            return replace(context, owner_ref="owner:changed")

        if change == "policy":
            return replace(context, policy=replace(context.policy, permissions=()))

        if change == "context-error":
            raise RuntimeError("owned synthetic lookup failure")

        return context

    def Clock():
        """Expire the issued grant only at the actual post-run check."""

        return AT + timedelta(hours=1) if change == "expire" and completed else AT

    def OnEvent(event):
        """Use the actual owned executor terminal event to change later authority."""

        nonlocal completed

        if event.kind == ExecutionEventKind.COMPLETED:
            completed = True

    outcome = asyncio.run(
        GovernedArtifactExecutor(root, clock=Clock).Execute(
            prepared,
            stage,
            grant,
            Current,
            on_event=OnEvent,
        )
    )

    assert outcome.raw_result.stdout, "Post-run authority failure discarded raw result"
    assert outcome.acceptance.refusal is not None, "Changed authority preserved acceptance"
    assert outcome.grant == grant, "Historical provenance was relabeled with later authority"


def test_ReceiptCannotBeSwappedOntoAlteredRawResultOrRun(tmp_path):
    """Raw bytes and original run identity remain independently bound by the immutable receipt."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    outcome = asyncio.run(
        GovernedArtifactExecutor(root, clock=lambda: AT).Execute(
            prepared,
            stage,
            grant,
            lambda: context,
        )
    )

    with pytest.raises(ValueError):
        replace(outcome, raw_result=replace(outcome.raw_result, stdout=b"owned-replacement"))

    with pytest.raises(ValueError):
        replace(outcome, run_id="artifact-run:other")


def test_FreshAcceptanceRejectsLaterRevocationAndResultReplayCannotLaunch(tmp_path):
    """A prior good receipt is provenance, never permanent model or launch authority."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    executor = GovernedArtifactExecutor(root, clock=lambda: AT)
    outcome = asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))
    original_metadata = outcome.Metadata()
    scope = LocalScopeStore(root).Save(
        replace(
            context.scope,
            authorization=replace(
                context.scope.authorization,
                state=AuthorizationState.REVOKED,
            ),
        )
    )

    with pytest.raises(ArtifactDeniedError):
        executor.ValidateAcceptance(
            outcome,
            prepared,
            stage,
            ArtifactPolicyContext(scope, context.policy, context.owner_ref),
            at=AT,
        )

    assert outcome.Metadata() == original_metadata, "Historical receipt changed during replay"


def test_DurableRawCapturePrecedesPostRunAcceptanceFailure(tmp_path):
    """The existing job/evidence bridge captures actual streams before rejecting model use."""

    from fuzzy1337.evidence import LocalEvidenceStore
    from fuzzy1337.jobs import (
        JobError,
        JobFailure,
        JobFailureCode,
        JobSpec,
        JobState,
        LocalExecutionJob,
        ScanJob,
    )

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path, mode="mutate")
    executor = GovernedArtifactExecutor(root, clock=lambda: AT)
    store = LocalEvidenceStore(root / "evidence")
    outcome = None

    async def Execute(request, **options):
        """Keep this one job's immutable outcome and return its actual raw executor facts."""

        nonlocal outcome
        assert request == prepared.Request(grant), "Job substituted the fixed request"

        outcome = await executor.Execute(prepared, stage, grant, lambda: context, **options)

        return outcome.raw_result

    async def Normalize(job_context, report):
        """Require raw store capture before any model-acceptance decision."""

        assert len(report.evidence) == 2, "Raw streams were not attached before normalization"
        assert outcome is not None, "Per-job original execution outcome is absent"
        stdout = next(item for item in report.evidence if item.role == "stdout")
        assert store.Read(stdout) == outcome.raw_result.stdout, "Captured stdout bytes changed"

        try:
            executor.ValidateAcceptance(outcome, prepared, stage, context, at=AT)

        except ArtifactDeniedError as error:
            raise JobError(
                JobFailure(JobFailureCode.AUTHORIZATION, "Artifact result acceptance denied")
            ) from error

    async def Run():
        """Own the assembled existing job and await its terminal evidence state."""

        job = ScanJob(
            JobSpec(
                "job:artifact",
                "owned-artifact",
                context.scope.Reference(),
                "owner:test",
                "synthetic.trivy",
            ),
            LocalExecutionJob(prepared.Request(grant), Execute, Normalize),
            evidence_store=store,
        )
        job.Start()

        return await job.Wait()

    terminal = asyncio.run(Run())

    assert terminal.state == JobState.FAILED, "Changed material invented a completed scan"
    assert len(terminal.artifacts) == 2, "Post-run refusal lost captured raw streams"

    for artifact in terminal.artifacts:
        assert (
            LocalEvidenceStore(root / "evidence").Get(artifact.evidence.evidence_id)
            == artifact.evidence
        ), "Reopened raw evidence lost original provenance"


@pytest.mark.parametrize("mutation", ["stream", "manifest", "plan", "facts", "version", "extra"])
def test_ReadOnlyReplayVerifiesOriginalBindingsAndRejectsTamper(tmp_path, mutation):
    """Historical receipts verify captured facts without granting current launch authority."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    outcome = asyncio.run(
        GovernedArtifactExecutor(root, clock=lambda: AT).Execute(
            prepared,
            stage,
            grant,
            lambda: context,
        )
    )
    metadata = json.loads(json.dumps(outcome.Metadata()))
    stdout = outcome.raw_result.stdout
    stderr = outcome.raw_result.stderr
    original = VerifyArtifactReplay(metadata, stdout, stderr)

    assert original == outcome.acceptance, "Historical receipt was relabeled during replay"

    if mutation == "stream":
        stdout += b"owned-tamper"

    elif mutation == "manifest":
        metadata["manifests"][0]["files"][0]["sha256"] = "0" * 64

    elif mutation == "plan":
        metadata["grant"]["plan"]["owner_ref"] = "owner:tampered"

    elif mutation == "facts":
        metadata["raw_facts"]["execution"]["exit_code"] = 7

    elif mutation == "version":
        metadata["schema_version"] = True

    else:
        metadata["extra"] = "owned"

    with pytest.raises(ValueError):
        VerifyArtifactReplay(metadata, stdout, stderr)


@pytest.mark.parametrize("mutation", ["missing", "bytes", "replacement", "hardlink", "run"])
def test_FreshAcceptanceRequiresActualPhysicalRunMarker(tmp_path, mutation):
    """A coherent forged receipt or same-byte marker replacement cannot relabel the actual run."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    executor = GovernedArtifactExecutor(root, clock=lambda: AT)
    outcome = asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))
    marker = stage.root / "scratch/run-lease.json"

    if mutation == "missing":
        marker.unlink()

    elif mutation == "bytes":
        marker.write_text("artifact-run:owned-replacement")

    elif mutation == "replacement":
        actual = marker.read_bytes()
        marker.unlink()
        marker.write_bytes(actual)

    elif mutation == "hardlink":
        os.link(marker, stage.root / "scratch/relinked-marker")

    else:
        fake = "artifact-run:" + "0" * 32
        outcome = replace(outcome, run_id=fake, acceptance=replace(outcome.acceptance, run_id=fake))

    with pytest.raises(ArtifactDeniedError):
        executor.ValidateAcceptance(outcome, prepared, stage, context, at=AT)


@pytest.mark.parametrize("checked_at", ["1900-01-01T00:00:00+00:00", "2099-01-01T00:00:00+00:00"])
def test_AcceptedReceiptClockCannotContradictOriginalGrant(tmp_path, checked_at):
    """Original receipt chronology is validated independently of the current fresh grant check."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    executor = GovernedArtifactExecutor(root, clock=lambda: AT)
    outcome = asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))

    with pytest.raises(ValueError):
        replace(outcome, acceptance=replace(outcome.acceptance, checked_at=checked_at))

    metadata = outcome.Metadata()
    metadata["acceptance"]["checked_at"] = checked_at

    with pytest.raises(ValueError):
        VerifyArtifactReplay(metadata, outcome.raw_result.stdout, outcome.raw_result.stderr)


def test_ReceiptCannotClaimAcceptanceAfterSuppliedCurrentTime(tmp_path):
    """A still-valid grant cannot make a future receipt chronology acceptable now."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    executor = GovernedArtifactExecutor(root, clock=lambda: AT)
    outcome = asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))
    future = replace(
        outcome,
        acceptance=replace(outcome.acceptance, checked_at=(AT + timedelta(seconds=1)).isoformat()),
    )

    with pytest.raises(ArtifactDeniedError):
        executor.ValidateAcceptance(future, prepared, stage, context, at=AT)


def test_PrelaunchCooperativeCancellationHasNoMarkerAndNoSuccessClaim(tmp_path):
    """Cancellation before a process exists preserves raw facts without marker invention."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)

    async def Run():
        """Cancel only this owned operation before entering the accepted executor launch phase."""

        cancellation = asyncio.Event()
        cancellation.set()

        return await GovernedArtifactExecutor(root, clock=lambda: AT).Execute(
            prepared,
            stage,
            grant,
            lambda: context,
            cancellation=cancellation,
        )

    outcome = asyncio.run(Run())

    assert outcome.acceptance.marker_identity is None, "A cancelled pre-launch process was invented"
    assert outcome.acceptance.refusal == ArtifactDenialReason.EXECUTION_FAILED, (
        "Cancellation accepted"
    )
    assert outcome.raw_result.termination == ExecutionTermination.CANCELLATION, "Raw reason changed"
    assert not tuple((stage.root / "scratch").iterdir()), "Pre-launch cancellation touched a marker"


def test_OutcomeFreezesCallerManifestListBeforeRetainingProvenance(tmp_path):
    """Mutable caller aliases cannot change original manifest metadata after receipt validation."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    executor = GovernedArtifactExecutor(root, clock=lambda: AT)
    outcome = asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))
    caller_list = list(outcome.manifests)
    frozen = replace(outcome, manifests=caller_list)
    before = frozen.Metadata()
    caller_list[0] = replace(caller_list[0], profile=ArtifactProfile.SYNTHETIC_DOCKERFILE)

    assert isinstance(frozen.manifests, tuple), "Frozen outcome retained a caller's mutable list"
    assert frozen.Metadata() == before, "Caller alias changed accepted original provenance"
    executor.ValidateAcceptance(frozen, prepared, stage, context, at=AT)
