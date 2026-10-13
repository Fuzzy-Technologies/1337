# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real owned portable producer execution, raw-evidence truth and fresh acceptance lifecycle."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from artifact_helpers import AT, OwnedArtifact, OwnedImageArtifact

from fuzzy1337 import artifact_fixture_worker, artifact_policy
from fuzzy1337.adapters import ExecutionState, SerializeContract
from fuzzy1337.artifact_inputs import ArtifactOperation, ArtifactProfile, ArtifactStage
from fuzzy1337.artifact_policy import (
    ArtifactDenialReason,
    ArtifactDeniedError,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
    ArtifactStagePayload,
    ArtifactVersionProof,
    GovernedArtifactExecutor,
    PrepareArtifact,
    VerifyArtifactReplay,
    VerifySyntheticImagePayloadReplay,
)
from fuzzy1337.executors import ExecutionEventKind, ExecutionResources, ExecutionTermination
from fuzzy1337.policy import Digest
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
    "retired_hash",
    [
        "6cec015e044f290f2f5f48d04156fe1430ba679ee629505100e192459d10ec7a",
        "48626d65b8e4d092859ed948507b8162a5e276b70599469e65fe8abc179a6bb1",
    ],
    ids=["retired-parser", "retired-text-wire"],
)
def test_RetiredExactWorkerCannotLaunchButOriginalEvidenceStillReplays(
    tmp_path, monkeypatch, retired_hash
):
    """An actual historical reviewed producer keeps provenance after its live catalog retires."""

    current_source = Path(artifact_fixture_worker.__file__).read_bytes()
    retired_source = current_source.replace(
        b"Exercise bounded synthetic lifecycle modes with exact LF byte streams.",
        b"Exercise bounded synthetic lifecycle modes through the fixed profile wire.",
    )

    for byte_wire, text_wire in (
        (
            b'sys.stdout.buffer.write(b"owned-ready\\n")\n        sys.stdout.buffer.flush()',
            b'print("owned-ready", flush=True)',
        ),
        (
            b'sys.stdout.buffer.write(b"x" * 65536 + b"\\n")\n        sys.stdout.buffer.flush()',
            b'print("x" * 65536, flush=True)',
        ),
        (
            b'sys.stdout.buffer.write(b"owned-partial-output\\n")'
            b'\n        sys.stdout.buffer.flush()',
            b'print("owned-partial-output", flush=True)',
        ),
        (
            b'sys.stderr.buffer.write(b"owned-failure\\n")\n        sys.stderr.buffer.flush()',
            b'print("owned-failure", file=sys.stderr, flush=True)',
        ),
        (
            b'sys.stdout.buffer.write(json.dumps(payload, sort_keys=True).encode("utf-8") + b"\\n")'
            b'\n    sys.stdout.buffer.flush()',
            b'print(json.dumps(payload, sort_keys=True), flush=True)',
        ),
    ):
        retired_source = retired_source.replace(byte_wire, text_wire)

    if retired_hash.startswith("6cec"):
        retired_source = retired_source.replace(
            b"argparse.ArgumentParser(allow_abbrev=False)", b"argparse.ArgumentParser()"
        ).replace(b"parser.parse_intermixed_args()", b"parser.parse_args()")

    assert hashlib.sha256(retired_source).hexdigest() == retired_hash, (
        "The historical fixture no longer equals the exact source-reviewed retired producer"
    )

    historical_producer = tmp_path.resolve() / "historical-producer.py"
    historical_producer.write_bytes(retired_source)

    with monkeypatch.context() as historical_catalog:
        historical_catalog.setattr(
            artifact_policy, "_REVIEWED_PRODUCERS", frozenset({retired_hash})
        )
        historical_catalog.setattr(artifact_fixture_worker, "__file__", str(historical_producer))
        root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
        executor = GovernedArtifactExecutor(root, clock=lambda: AT)
        outcome = asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))
        executor.ValidateAcceptance(outcome, prepared, stage, context, at=AT)

    assert retired_hash not in artifact_policy._REVIEWED_PRODUCERS, (
        "Retired producer remained in the live launch catalog"
    )
    assert outcome.raw_result.execution.state == ExecutionState.SUCCEEDED, (
        "Historical execution evidence was fabricated without running the reviewed source"
    )
    assert outcome.acceptance.refusal is None, "The original historical run was not accepted"

    with pytest.raises(ArtifactDeniedError):
        PrepareArtifact(stage, root)

    with pytest.raises(ArtifactDeniedError):
        executor.ValidateAcceptance(outcome, prepared, stage, context, at=AT)

    replayed = VerifyArtifactReplay(
        outcome.Metadata(), outcome.raw_result.stdout, outcome.raw_result.stderr
    )

    assert replayed == outcome.acceptance, "Retired-source evidence lost its original receipt"
    assert stage.scanner.manifest.files[1].sha256 == retired_hash, (
        "Historical scanner identity was relabeled as the current producer"
    )


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


@pytest.mark.parametrize("fragmented", [False, True], ids=["native-chunks", "fragmented-readiness"])
def test_CooperativeCancellationReturnsRawBeforeAcceptanceDenial(tmp_path, fragmented):
    """Cancellation after owned readiness returns actual partial bytes and cancelled facts."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path, mode="wait")

    async def Run():
        """Cancel only the actual owned worker after its explicit readiness bytes."""

        cancelled = asyncio.Event()
        readiness = bytearray()
        ready_marker = b"owned-ready\n"

        def OnEvent(event):
            """Use only this owned worker's stdout event as deterministic cancellation readiness."""

            if event.kind != ExecutionEventKind.STDOUT:
                return

            readiness.extend(event.data[: len(ready_marker) - len(readiness)])

            if readiness == ready_marker:
                cancelled.set()

        def ObservedEvent(event):
            """Exercise fragmented readiness without rewriting retained raw events or bytes."""

            if fragmented and event.kind == ExecutionEventKind.STDOUT:
                for byte in event.data:
                    OnEvent(replace(event, data=bytes([byte])))

            else:
                OnEvent(event)

        return await GovernedArtifactExecutor(root, clock=lambda: AT).Execute(
            prepared,
            stage,
            grant,
            lambda: context,
            on_event=ObservedEvent,
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


def test_RebuiltExpiredOutcomeEnvelopeCannotExtendOriginalPolicyLifetime(tmp_path):
    """A coherent changed grant/receipt still cannot normalize beyond the bound policy limit."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    executor = GovernedArtifactExecutor(root, clock=lambda: AT)
    outcome = asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))
    later = AT + timedelta(seconds=301)

    with pytest.raises(ArtifactDeniedError):
        executor.ValidateAcceptance(outcome, prepared, stage, context, at=later)

    valid_until = (AT + timedelta(hours=1)).isoformat()
    changed_grant = replace(
        grant,
        valid_until=valid_until,
        authorization=ArtifactPolicyEngine().Envelope(grant.plan, grant.issued_at, valid_until),
    )
    changed = replace(
        outcome,
        grant=changed_grant,
        acceptance=replace(
            outcome.acceptance, grant_id=changed_grant.authorization.authorization_id
        ),
    )

    with pytest.raises(ArtifactDeniedError):
        executor.ValidateAcceptance(changed, prepared, stage, context, at=later)

    assert changed.raw_result == outcome.raw_result, "Lifetime denial rewrote actual raw evidence"


def test_CompletedRunCannotBeRelabeledWithAnotherCanonicalGrantWindow(tmp_path):
    """The physical marker witnesses original authorization as well as original run identity."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    executor = GovernedArtifactExecutor(root, clock=lambda: AT)
    outcome = asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))
    later = AT + timedelta(seconds=301)
    issued_at = later.isoformat()
    valid_until = (later + timedelta(seconds=context.policy.max_authorization_seconds)).isoformat()
    changed_grant = replace(
        grant,
        issued_at=issued_at,
        valid_until=valid_until,
        authorization=ArtifactPolicyEngine().Envelope(grant.plan, issued_at, valid_until),
    )
    changed = replace(
        outcome,
        grant=changed_grant,
        acceptance=replace(
            outcome.acceptance,
            grant_id=changed_grant.authorization.authorization_id,
            checked_at=issued_at,
        ),
    )
    marker = json.loads((stage.root / "scratch/run-lease.json").read_bytes())

    assert marker == {
        "schema_version": 1,
        "run_id": outcome.run_id,
        "grant_id": grant.authorization.authorization_id,
    }, "Launch marker failed to preserve the original run and grant"

    with pytest.raises(ArtifactDeniedError):
        executor.ValidateAcceptance(changed, prepared, stage, context, at=later)

    executor.ValidateAcceptance(outcome, prepared, stage, context, at=AT)
    replayed = VerifyArtifactReplay(
        outcome.Metadata(), outcome.raw_result.stdout, outcome.raw_result.stderr
    )

    assert replayed.grant_id == grant.authorization.authorization_id, (
        "Read-only original replay lost its actual recorded authorization"
    )


@pytest.mark.parametrize("mutation", ["owner", "permission", "expiry"])
def test_AuthorityChangedDuringPostRunHashingRefusesReceiptAndKeepsRaw(
    tmp_path, monkeypatch, mutation
):
    """The final result decision refreshes owner/policy/time after expensive after-run hashing."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    actual_verify = ArtifactStage.Verify
    current = context
    now = AT

    def Verify(selected, **options):
        """Change only owned operator state after actual final immutable material checking."""

        nonlocal current, now
        actual_verify(selected, **options)

        if not options.get("after_run"):
            return

        if mutation == "owner":
            current = replace(context, owner_ref="owner:changed")

        elif mutation == "permission":
            current = replace(context, policy=replace(context.policy, permissions=()))

        else:
            now = AT + timedelta(seconds=301)

    monkeypatch.setattr(ArtifactStage, "Verify", Verify)
    outcome = asyncio.run(
        GovernedArtifactExecutor(root, clock=lambda: now).Execute(
            prepared, stage, grant, lambda: current
        )
    )

    assert outcome.raw_result.execution.state == ExecutionState.SUCCEEDED, (
        "Actual child did not run"
    )
    assert outcome.raw_result.stdout, "Fresh post-run refusal discarded actual raw output"
    assert outcome.acceptance.refusal is not None, (
        "Stale post-hash authority became accepted receipt"
    )


def ImageVersion(tmp_path, *, scenario="success"):
    """Collect and freshly accept actual VERSION before preparing any richer image SCAN."""

    root, stage, prepared, context, grant = OwnedImageArtifact(tmp_path, scenario=scenario)
    executor = GovernedArtifactExecutor(root, clock=lambda: AT)
    outcome = asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))
    executor.ValidateAcceptanceFresh(outcome, prepared, stage, lambda: context)
    proof = ArtifactVersionProof(outcome, prepared, stage)

    return root, context, executor, proof


def ImageScan(tmp_path, root, context, executor, proof, *, scenario="success"):
    """Use a separate fresh stage and exact original VERSION prerequisite for SCAN."""

    _, stage, prepared, scan_context, grant = OwnedImageArtifact(
        tmp_path, scenario=scenario, workspace=root, stage_name="scan-stage",
        operation=ArtifactOperation.SCAN, version_proof=proof,
    )
    assert scan_context == context, "Pair must retain complete current original authority"
    outcome = asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))

    return outcome, prepared, stage


def DetachedImageRun(outcome, prepared, stage):
    """Capture exact original detached SDK payloads alongside actual retained raw streams."""

    original = json.loads(SerializeContract((outcome.Metadata(), prepared.Payload(),
                                           ArtifactStagePayload(stage))))

    return (*original, outcome.raw_result.stdout, outcome.raw_result.stderr)


@pytest.fixture(scope="module")
def detached_original_image_runs(tmp_path_factory):
    """Execute both actual reviewed operations once before pure historical mutation probes."""

    selected = tmp_path_factory.mktemp("original-image-runs")
    root, context, executor, proof = ImageVersion(selected)
    scan = ImageScan(selected, root, context, executor, proof)
    executor.ValidatePairAcceptanceFresh(
        (proof.outcome, proof.prepared, proof.stage), scan, lambda: context,
    )

    return (DetachedImageRun(proof.outcome, proof.prepared, proof.stage), DetachedImageRun(*scan))


@pytest.mark.parametrize("index", [0, 1], ids=["version", "scan"])
def test_ActualDetachedImagePayloadReplayUsesOriginalOnly(
    detached_original_image_runs, monkeypatch, index,
):
    """Actual original factory/output captures replay after current physical authority is absent."""

    from fuzzy1337.workspace import LocalWorkspaceStore

    metadata, prepared, stage, stdout, stderr = copy.deepcopy(detached_original_image_runs[index])

    def Forbidden(*_args, **_kwargs):
        """Trip any accidental current filesystem, launch, policy or workspace lookup."""

        raise AssertionError("Detached historical replay consulted current execution authority")

    monkeypatch.setattr(Path, "open", Forbidden)
    monkeypatch.setattr(Path, "stat", Forbidden)
    monkeypatch.setattr(Path, "resolve", Forbidden)
    monkeypatch.setattr(ArtifactStage, "Verify", Forbidden)
    monkeypatch.setattr(LocalWorkspaceStore, "Open", Forbidden)
    monkeypatch.setattr(ArtifactPolicyEngine, "Authorize", Forbidden)
    monkeypatch.setattr(GovernedArtifactExecutor, "Execute", Forbidden)
    before = copy.deepcopy((metadata, prepared, stage, stdout, stderr))
    VerifyArtifactReplay(metadata, stdout, stderr)
    VerifySyntheticImagePayloadReplay(metadata, prepared, stage)
    assert (metadata, prepared, stage, stdout, stderr) == before, (
        "Historical payload verification must preserve all original facts and raw bytes"
    )


@pytest.mark.parametrize("index", [0, 1], ids=["version", "scan"])
@pytest.mark.parametrize("mutation", [
    "argv", "cwd", "environment", "resources", "cleanup", "operation",
    "partition-alias", "file-alias",
])
def test_ActualDetachedImageRehashedFactoryMutationsDeny(
    detached_original_image_runs, index, mutation,
):
    """Self-consistent recorded hashes remain insufficient to pass the closed SDK grammar."""

    metadata, prepared, stage, stdout, stderr = copy.deepcopy(detached_original_image_runs[index])
    grant = metadata["grant"]
    plan = grant["plan"]

    if mutation == "argv":
        prepared["invocation"]["argv"] = ["unsupported-synthetic-command"]

    elif mutation == "cwd":
        prepared["workspace"] = "unsupported/scratch"

    elif mutation == "environment":
        prepared["environment"]["PYTHONPATH"] = "unsupported-overlay"

    elif mutation == "resources":
        prepared["resources"]["max_stdout_bytes"] = 16 * 1024 * 1024

    elif mutation == "cleanup":
        prepared["resources"]["terminate_grace_seconds"] = 6

    elif mutation == "operation":
        plan["operation"] = prepared["operation"] = "scan" if index == 0 else "version"

        for name, value in (("version_run_id", "artifact-run:other"),
                            ("version_grant_id", "artifact-authorization:other"),
                            ("version_prerequisite_sha256", "0" * 64)):
            plan[name] = prepared[name] = value if index == 0 else None

    elif mutation == "partition-alias":
        stage["partitions"][2]["directory_identity"] = stage["partitions"][0]["directory_identity"]

    else:
        input_identity = stage["partitions"][0]["identities"][0][1]
        stage["partitions"][2]["identities"][0][1][:2] = input_identity[:2]

    plan["stage_sha256"] = Digest(stage)
    plan["request_sha256"] = Digest(prepared)
    plan["invocation_sha256"] = Digest(prepared["invocation"])
    plan["intent_sha256"] = Digest({key: value for key, value in plan.items()
                                   if key != "intent_sha256"})
    authorization = grant["authorization"]
    authorization["invocation_sha256"] = plan["invocation_sha256"]
    authorization["authorization_id"] = "artifact-authorization:" + Digest(
        (plan, grant["issued_at"], grant["valid_until"])
    )
    metadata["acceptance"]["grant_id"] = authorization["authorization_id"]
    VerifyArtifactReplay(metadata, stdout, stderr)

    with pytest.raises(ValueError):
        VerifySyntheticImagePayloadReplay(metadata, prepared, stage)

    assert (stdout, stderr) == detached_original_image_runs[index][-2:], (
        "Factory refusal must not rewrite the actual original process bytes"
    )


@pytest.mark.parametrize("scenario", ["success", "no_findings"])
def test_RealImageVersionScanPairHasSeparateRunsAndBoundOriginalPrerequisite(tmp_path, scenario):
    """Actual richer operations retain independent raw results and one exact original pairing."""

    root, context, executor, proof = ImageVersion(tmp_path, scenario=scenario)
    scan = ImageScan(tmp_path, root, context, executor, proof, scenario=scenario)
    executor.ValidatePairAcceptanceFresh(
        (proof.outcome, proof.prepared, proof.stage), scan, lambda: context
    )
    outcome, prepared, stage = scan
    assert proof.stage.root != stage.root and proof.stage.lease_id != stage.lease_id, (
        "VERSION and SCAN must retain separate original physical stages and single-run leases"
    )
    assert proof.outcome.run_id != outcome.run_id, "SCAN borrowed VERSION's actual run"
    assert proof.outcome.grant.authorization != outcome.grant.authorization, (
        "SCAN must receive its own operation-bound authorization instead of borrowing VERSION"
    )
    assert proof.outcome.manifests == outcome.manifests, "Selected content pair changed"
    assert outcome.grant.plan.version_run_id == proof.outcome.run_id, (
        "SCAN intent must bind the actual original VERSION run"
    )
    assert (
        outcome.grant.plan.version_grant_id == proof.outcome.grant.authorization.authorization_id
    ), (
        "SCAN intent must bind the actual original VERSION authorization"
    )
    assert outcome.grant.plan.version_prerequisite_sha256 == proof.Digest(), (
        "SCAN intent must bind the complete original VERSION prerequisite digest"
    )
    assert prepared.VersionBindings()["version_prerequisite_sha256"] == proof.Digest(), (
        "The prepared SCAN request must retain the same original prerequisite as its grant"
    )
    assert (
        outcome.Metadata()["schema_version"] == proof.outcome.Metadata()["schema_version"] == 2
    ), (
        "Both actual operation outcomes must preserve schema-2 provenance"
    )
    assert json.loads(proof.outcome.raw_result.stdout)["Version"] == "0.75.0-synthetic", (
        "Actual VERSION stdout must retain the reviewed synthetic provider version"
    )
    assert json.loads(outcome.raw_result.stdout)["Results"][0]["Vulnerabilities"] == (
        [] if scenario == "no_findings" else [{
            "VulnerabilityID": "CVE-2099-0001", "PkgID": "owned-1", "PkgName": "Owned_Lib",
            "InstalledVersion": "1.0", "FixedVersion": "2.0", "Severity": "HIGH",
        }]
    ), "Exact owned raw wire changed before interpretation"
    assert prepared.invocation.timeout_seconds == 30, "Richer SCAN default changed"
    assert prepared.resources.max_stdout_bytes == 4 * 1024 * 1024, (
        "Richer SCAN must retain its reviewed 4 MiB stdout capture ceiling"
    )
    assert prepared.resources.max_stderr_bytes == 1024 * 1024, (
        "Richer SCAN must retain its reviewed 1 MiB stderr capture ceiling"
    )
    assert prepared.invocation.argv[9:] == (
        "image", "--cache-backend", "memory", "--input", str(stage.root / "input/image.tar"),
        "--format", "json", "--scanners", "vuln", "--disable-telemetry", "--offline-scan",
        "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
        "--skip-version-check", "--skip-vex-repo-update", "--ignorefile=", "--list-all-pkgs",
        "--exit-code", "0", "--no-progress", "--timeout", "30s",
    ), "Reviewed richer SCAN flag ordering drifted"


def test_RicherScanCannotPrepareWithoutActualVersionPrerequisite(tmp_path):
    """A stage version string or policy bytes never substitute for a collected VERSION."""

    with pytest.raises(ValueError):
        OwnedImageArtifact(tmp_path, operation=ArtifactOperation.SCAN)

    scratch = tmp_path.resolve() / "workspace/image-stage/scratch"
    assert not tuple(scratch.iterdir()), "Missing VERSION began a SCAN physical run"


@pytest.mark.parametrize("failed", ["output-limit", "cancelled"])
def test_RealRejectedVersionKeepsRawTruthAndCannotBecomeScanProof(tmp_path, failed):
    """Failed/cancelled actual VERSION has no original accepted proof or subsequent SCAN grant."""

    root, stage, prepared, context, _ = OwnedImageArtifact(tmp_path)
    cancellation = None

    if failed == "output-limit":
        prepared = PrepareArtifact(
            stage, root, operation=ArtifactOperation.VERSION,
            resources=ExecutionResources(max_stdout_bytes=1, max_stderr_bytes=16 * 1024),
        )

    else:
        cancellation = asyncio.Event()
        cancellation.set()

    grant = ArtifactPolicyEngine().Authorize(prepared, stage, context, at=AT)
    outcome = asyncio.run(GovernedArtifactExecutor(root, clock=lambda: AT).Execute(
        prepared, stage, grant, lambda: context, cancellation=cancellation,
    ))
    assert outcome.acceptance.refusal is not None, "Rejected VERSION became accepted metadata"
    assert outcome.raw_result.termination == (
        ExecutionTermination.OUTPUT_LIMIT if failed == "output-limit"
        else ExecutionTermination.CANCELLATION
    ), "Actual VERSION termination was rewritten"

    with pytest.raises(ArtifactDeniedError):
        ArtifactVersionProof(outcome, prepared, stage)

    assert VerifyArtifactReplay(outcome.Metadata(), outcome.raw_result.stdout,
                                outcome.raw_result.stderr) == outcome.acceptance, (
        "Rejected VERSION replay must retain the actual original refusal receipt"
    )


@pytest.mark.parametrize("scenario,termination", [
    ("provider_error", ExecutionTermination.PROCESS_EXIT),
    ("output_limit", ExecutionTermination.OUTPUT_LIMIT),
    ("hold", ExecutionTermination.TIMEOUT),
])
def test_RealRicherScanFailuresRetainOriginalVersionAndBothRawOutcomes(
    tmp_path, scenario, termination
):
    """Provider/output/time failures keep process truth and never yield accepted normalization."""

    root, context, executor, proof = ImageVersion(tmp_path, scenario=scenario)
    _, stage, prepared, _, _ = OwnedImageArtifact(
        tmp_path, scenario=scenario, workspace=root, stage_name="scan-stage",
        operation=ArtifactOperation.SCAN, version_proof=proof,
    )
    prepared = PrepareArtifact(stage, root, timeout_seconds=1, version_proof=proof)
    grant = ArtifactPolicyEngine().Authorize(prepared, stage, context, at=AT)
    outcome = asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))
    assert outcome.raw_result.termination == termination, "SCAN termination was hidden"
    assert outcome.acceptance.refusal == ArtifactDenialReason.EXECUTION_FAILED, (
        "Actual SCAN provider or capture failure must refuse successful acceptance"
    )
    assert outcome.raw_result.stdout, "SCAN failure discarded bounded original bytes"
    assert proof.outcome.raw_result.execution.state == ExecutionState.SUCCEEDED, (
        "A failed SCAN must preserve the independently successful original VERSION result"
    )

    with pytest.raises(ArtifactDeniedError):
        executor.ValidatePairAcceptanceFresh(
            (proof.outcome, proof.prepared, proof.stage), (outcome, prepared, stage),
            lambda: context,
        )

    assert VerifyArtifactReplay(outcome.Metadata(), outcome.raw_result.stdout,
                                outcome.raw_result.stderr) == outcome.acceptance, (
        "Failed SCAN replay must retain the actual original refusal receipt"
    )


def test_SameMaterialAlternateVersionCannotReplaceIssuedScanPrerequisite(tmp_path):
    """A second valid same-content VERSION cannot be swapped into an already issued SCAN."""

    root, context, executor, proof = ImageVersion(tmp_path)
    scan = ImageScan(tmp_path, root, context, executor, proof)
    _, version_stage, version_prepared, _, version_grant = OwnedImageArtifact(
        tmp_path, workspace=root, stage_name="alternate-version"
    )
    alternate_outcome = asyncio.run(executor.Execute(
        version_prepared, version_stage, version_grant, lambda: context
    ))
    alternate = ArtifactVersionProof(alternate_outcome, version_prepared, version_stage)
    assert alternate.outcome.manifests == proof.outcome.manifests, "Test changed selected content"

    with pytest.raises(ArtifactDeniedError):
        executor.ValidatePairAcceptanceFresh(
            (alternate.outcome, alternate.prepared, alternate.stage), scan, lambda: context
        )

    outcome, prepared, stage = scan
    substituted = replace(prepared, version_proof=alternate)

    with pytest.raises(ArtifactDeniedError):
        substituted.Request(outcome.grant)

    with pytest.raises(ArtifactDeniedError):
        ArtifactPolicyEngine().Validate(
            outcome.grant, substituted, stage, context, at=AT, after_run=True
        )


@pytest.mark.parametrize("change", ["expiry", "owner", "marker", "material"])
def test_VersionPrerequisiteIsFreshAtScanIssuanceAndLaunch(tmp_path, change):
    """An accepted earlier VERSION cannot grant SCAN after its affected boundary changes."""

    root, context, executor, proof = ImageVersion(tmp_path)
    _, stage, prepared, _, grant = OwnedImageArtifact(
        tmp_path, workspace=root, stage_name="scan-stage", operation=ArtifactOperation.SCAN,
        version_proof=proof,
    )
    now = AT
    current = context

    if change == "expiry":
        now = AT + timedelta(seconds=301)

    elif change == "owner":
        current = replace(context, owner_ref="owner:changed")

    else:
        path = proof.stage.root / (
            "scratch/run-lease.json" if change == "marker" else "material/policy.json"
        )
        path.chmod(0o600)
        path.write_bytes(b"owned-changed-original-version")

    with pytest.raises(ArtifactDeniedError):
        ArtifactPolicyEngine().Authorize(prepared, stage, current, at=now)

    events = []

    with pytest.raises(ArtifactDeniedError):
        asyncio.run(GovernedArtifactExecutor(root, clock=lambda: now).Execute(
            prepared, stage, grant, lambda: current, on_event=events.append
        ))

    assert not any(event.kind == ExecutionEventKind.STARTED for event in events), (
        "A stale VERSION prerequisite must prevent the SCAN process from starting"
    )
    assert not tuple((stage.root / "scratch").iterdir()), "Stale VERSION began SCAN"
    assert proof.outcome.raw_result.stdout, "Refusal erased original VERSION capture"


@pytest.mark.parametrize("mutation", ["expiry", "owner", "policy"])
def test_FinalPairBarrierRefreshesVersionAfterAllScanHashing(tmp_path, monkeypatch, mutation):
    """The pair's final guard covers VERSION when authority changes during expensive SCAN work."""

    root, context, executor, proof = ImageVersion(tmp_path)
    scan = ImageScan(tmp_path, root, context, executor, proof)
    outcome, prepared, stage = scan
    current = context
    now = AT
    original_verify = ArtifactStage.Verify

    def Verify(selected, **options):
        """Change only the owned current authority after original scan physical hashing."""

        nonlocal current, now
        original_verify(selected, **options)

        if selected is not stage or not options.get("after_run"):
            return

        if mutation == "expiry":
            now = AT + timedelta(seconds=301)

        elif mutation == "owner":
            current = replace(context, owner_ref="owner:changed")

        else:
            current = replace(context, policy=replace(context.policy, permissions=()))

    monkeypatch.setattr(ArtifactStage, "Verify", Verify)

    with pytest.raises(ArtifactDeniedError):
        GovernedArtifactExecutor(root, clock=lambda: now).ValidatePairAcceptanceFresh(
            (proof.outcome, proof.prepared, proof.stage), scan, lambda: current
        )

    assert outcome.raw_result.stdout and proof.outcome.raw_result.stdout, (
        "Fresh pair refusal must preserve both actual original stdout captures"
    )
    assert prepared.version_proof == proof, "Refusal swapped the actual prerequisite"


def test_RicherScanPostRunVersionExpiryKeepsBothActualResults(tmp_path):
    """Expiry only after successful SCAN returns raw truth while refusing new acceptance."""

    root, context, _, proof = ImageVersion(tmp_path)
    _, stage, prepared, _, _ = OwnedImageArtifact(
        tmp_path, workspace=root, stage_name="scan-stage", operation=ArtifactOperation.SCAN,
        version_proof=proof,
    )
    issued = AT + timedelta(seconds=120)
    grant = ArtifactPolicyEngine().Authorize(prepared, stage, context, at=issued)
    finished = False

    def OnEvent(event):
        """Move the controlled clock only after actual child completion."""

        nonlocal finished

        if event.kind == ExecutionEventKind.COMPLETED:
            finished = True

    executor = GovernedArtifactExecutor(
        root, clock=lambda: AT + timedelta(seconds=301) if finished else issued
    )
    outcome = asyncio.run(executor.Execute(
        prepared, stage, grant, lambda: context, on_event=OnEvent
    ))
    assert outcome.raw_result.execution.state == ExecutionState.SUCCEEDED, (
        "Post-run VERSION expiry must preserve the actual successful SCAN process state"
    )
    assert outcome.acceptance.refusal == ArtifactDenialReason.GRANT_EXPIRED, (
        "Expired original VERSION must refuse new SCAN acceptance through the grant boundary"
    )
    assert outcome.raw_result.stdout and proof.outcome.raw_result.stdout, (
        "Post-run VERSION expiry must retain both original operation stdout captures"
    )
    assert outcome.grant.valid_until > proof.outcome.grant.valid_until, (
        "The test must expire VERSION while SCAN's own grant still remains current"
    )


def test_OperationAwareReplayDoesNotInspectCurrentPhysicalStages(tmp_path, monkeypatch):
    """Saved schema2 VERSION and SCAN retain original facts without regranting relocated files."""

    root, context, executor, proof = ImageVersion(tmp_path)
    scan = ImageScan(tmp_path, root, context, executor, proof)

    def ForbiddenVerify(*args, **kwargs):
        """Reject a physical lookup if historical verification attempts live authority."""

        raise AssertionError("Historical replay inspected current physical material")

    monkeypatch.setattr(ArtifactStage, "Verify", ForbiddenVerify)

    for outcome in (proof.outcome, scan[0]):
        assert VerifyArtifactReplay(
            outcome.Metadata(), outcome.raw_result.stdout, outcome.raw_result.stderr
        ) == outcome.acceptance, "Historical operation facts were upgraded or relabeled"

    with pytest.raises(ValueError):
        PrepareArtifact(scan[2], root, version_proof=proof.outcome.acceptance)


def test_VersionGrantNeverLaunchesScanAndVersionNeverTakesAnotherPrerequisite(tmp_path):
    """Actual separate operation requests cannot borrow each other's original approval."""

    root, context, executor, proof = ImageVersion(tmp_path)
    _, stage, prepared, _, grant = OwnedImageArtifact(
        tmp_path, workspace=root, stage_name="scan-stage", operation=ArtifactOperation.SCAN,
        version_proof=proof,
    )
    events = []

    with pytest.raises(ArtifactDeniedError):
        asyncio.run(executor.Execute(
            prepared, stage, proof.outcome.grant, lambda: context, on_event=events.append
        ))

    assert not any(event.kind == ExecutionEventKind.STARTED for event in events), (
        "A VERSION authorization must never start the distinct SCAN process"
    )
    assert not tuple((stage.root / "scratch").iterdir()), "VERSION grant initialized SCAN"

    with pytest.raises(ValueError):
        PrepareArtifact(proof.stage, root, operation=ArtifactOperation.VERSION, version_proof=proof)

    for field in ("version_run_id", "version_grant_id", "version_prerequisite_sha256"):
        with pytest.raises(ValueError):
            replace(grant.plan, **{field: None})
