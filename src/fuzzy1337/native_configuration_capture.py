# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned original native configuration execution with bounded durable stream custody."""

from __future__ import annotations

import asyncio
import hashlib
import shutil
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from fuzzy1337.adapters import ExecutionState
from fuzzy1337.adapters.trivy import ParseJson
from fuzzy1337.artifact_policy import ArtifactPolicyContext, ArtifactPolicyEngine
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutionResult,
    LocalExecutor,
)
from fuzzy1337.native_configuration_material import (
    NativeConfigurationMaterialObserver,
    NativeConfigurationMaterialProof,
    Settle,
)
from fuzzy1337.native_configuration_policy import (
    BoundedControl,
    ConfigurationEnvironment,
    NativeConfigurationExecutionClaim,
    NativeConfigurationOperationGrant,
    OriginalClaim,
    PreparedNativeConfigurationOperation,
    PrivateDirectory,
    WriteControl,
)
from fuzzy1337.native_configuration_report import (
    NATIVE_CONFIGURATION_FAMILY,
    NATIVE_CONFIGURATION_ROLES,
)
from fuzzy1337.native_image_bounded_capture import Finalization
from fuzzy1337.native_image_observation import NativeImageObservationBudget
from fuzzy1337.policy import Digest


class NativeConfigurationCaptureError(RuntimeError):
    """Refuse unconfirmed terminal custody while retaining original private event controls."""


def RawFacts(result: LocalExecutionResult) -> dict[str, object]:
    """Project bounded original execution and stream/event identities without embedding bodies.

    Args:
        result: Exact original local executor result after owned cleanup.

    Returns:
        Original execution, termination and complete ordered event size/digest metadata.
    """

    return {"execution": result.execution, "termination": result.termination,
        "stdout_size_bytes": len(result.stdout), "stdout_sha256": hashlib.sha256(
            result.stdout).hexdigest(), "stderr_size_bytes": len(result.stderr),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "events": [{"sequence": item.sequence, "kind": item.kind,
            "size_bytes": len(item.data), "sha256": hashlib.sha256(item.data).hexdigest(),
            "termination": item.termination} for item in result.events]}


@dataclass(frozen=True, slots=True)
class NativeConfigurationOperationCapture:
    """Original SDK operation, immutable raw result and custody facts; possession grants nothing."""

    prepared: PreparedNativeConfigurationOperation
    grant: NativeConfigurationOperationGrant
    request: LocalExecutionRequest
    outcome: LocalExecutionResult
    started_at: str
    finished_at: str
    observed_version: str | None
    refusal: str | None
    cleanup_confirmed: bool
    records: tuple[EvidenceRecord, ...] = ()

    @property
    def Operation(self) -> str:
        """Return the exact closed operation name from the original prepared recipe.

        Returns:
            ``version`` or ``scan``.
        """

        return self.prepared.operation

    def Envelope(self) -> dict[str, object]:
        """Project original complete recipe, authority, request and terminal collection facts.

        Returns:
            Bounded schema-one receipt; stream bodies remain in distinct immutable roles.
        """

        return {"schema_version": 1, "family": NATIVE_CONFIGURATION_FAMILY,
            "prepared": self.prepared.Payload(), "grant": self.grant, "request": self.request,
            "raw_facts": RawFacts(self.outcome), "started_at": self.started_at,
            "finished_at": self.finished_at, "observed_version": self.observed_version,
            "refusal": self.refusal, "cleanup_confirmed": self.cleanup_confirmed}

    def Digest(self) -> str:
        """Bind the complete finite receipt without recursive evidence-record inclusion.

        Returns:
            Canonical SHA256 of original operation facts.
        """

        return Digest(self.Envelope())

    def Provenance(self) -> EvidenceProvenance:
        """Attribute exact original raw acquisitions to the actual executed invocation.

        Returns:
            Canonical source, scope, times, version and actual execution facts.
        """

        return EvidenceProvenance(self.prepared.workspace_id, self.grant.plan.scope_reference,
            "native.trivy", "1", self.observed_version, self.started_at, self.finished_at,
            InvocationDigest(self.prepared.invocation), self.outcome.execution)


def PublishCapture(capture: NativeConfigurationOperationCapture,
                   store: LocalEvidenceStore) -> NativeConfigurationOperationCapture:
    """Publish original stdout, stderr and receipt only through the canonical evidence owner.

    Args:
        capture: Original complete successful or refused terminal capture.
        store: Exact owning evidence store or job bridge.

    Returns:
        Original frozen capture with its three confirmed immutable owning acquisitions.
    """

    provenance = capture.Provenance()
    prefix = "native-configuration-" + capture.Operation
    records = []

    for suffix, raw in (("stdout", capture.outcome.stdout), ("stderr", capture.outcome.stderr),
                         ("receipt", BoundedControl(capture.Envelope()))):
        role = prefix + "-" + suffix
        maximum, media = NATIVE_CONFIGURATION_ROLES[role]

        if len(raw) > maximum:
            raise ValueError("Native configuration acquisition exceeds its role bound")

        record = store.Put(raw, role, media, provenance)

        if store.Get(record.evidence_id) != record or store.Read(record.reference) != raw:
            raise ValueError("Native configuration acquisition acknowledgement differs")

        records.append(record)

    return replace(capture, records=tuple(records))


async def CaptureNativeConfigurationOperation(
    engine: ArtifactPolicyEngine, prepared: PreparedNativeConfigurationOperation,
    grant: NativeConfigurationOperationGrant, claim: NativeConfigurationExecutionClaim,
    store: LocalEvidenceStore, context_provider: Callable[[], ArtifactPolicyContext], *,
    observer: NativeConfigurationMaterialObserver, material_proof: NativeConfigurationMaterialProof,
    budget: NativeImageObservationBudget, cancellation: asyncio.Event,
    clock: Callable[[], datetime],
) -> tuple[NativeConfigurationOperationCapture, NativeConfigurationMaterialProof | None]:
    """Run one original granted process, preserve event custody and verify post-run material.

    Args:
        engine: Exact original issuing engine.
        prepared: Original fixed recipe with new private scratch path.
        grant: Original separately issued configuration grant.
        claim: Original unbound one-use operation/observation claim.
        store: Exact owning canonical evidence store or job bridge.
        context_provider: Fresh synchronous factual policy source.
        observer: Original material owner.
        material_proof: Original consumed pre-operation proof.
        budget: Single whole-pair observation/finalization ledger.
        cancellation: Owning cooperative cancellation signal.
        clock: Trusted aware authority clock.

    Returns:
        Original confirmed terminal capture and optional fresh same-stage proof.

    Raises:
        NativeConfigurationCaptureError: Terminal cleanup/custody is unknown; private controls stay.
        asyncio.CancelledError: Direct cancellation propagates only after owned task settlement.
    """

    state = OriginalClaim(engine, claim)

    if state.prepared is not prepared or state.grant is not grant or state.launched:
        raise ValueError("Native configuration collector requires its original unused claim")

    with Finalization(budget):
        prepared.scratch.mkdir(mode=0o700)
        scratch_identity = PrivateDirectory(prepared.scratch)
        (prepared.scratch / "cache").mkdir(mode=0o700)
        request = LocalExecutionRequest(prepared.invocation,
            CapabilityDescriptor(prepared.selection.Capability(), "native.trivy",
                                  prepared.invocation.request.impact),
            grant.authorization, prepared.scratch.relative_to(prepared.workspace_root).as_posix(),
            ConfigurationEnvironment(prepared.scratch), prepared.resources)
        engine.BindNativeConfigurationRequest(claim, request, context_provider(),
            observer=observer, material_proof=material_proof, at=clock())
        directory = state.directories[-2][0]

    events: list[ExecutionEvent] = []
    sizes = {ExecutionEventKind.STDOUT: 0, ExecutionEventKind.STDERR: 0}

    def Validate(actual: LocalExecutionRequest) -> None:
        """Recheck the original request at both initial and owned READY-to-worker checkpoints."""

        with Finalization(budget):
            engine.ValidateNativeConfigurationClaim(claim, actual, context_provider(),
                observer=observer, material_proof=material_proof, at=clock())

    def Observe(event: ExecutionEvent) -> None:
        """Durably retain each bounded original event before continuing process observation."""

        with Finalization(budget):
            if event.sequence != len(events) or len(events) >= 512:
                raise ValueError("Native configuration event custody exceeds its finite bound")

            if event.kind in sizes:
                maximum = (prepared.resources.max_stdout_bytes
                    if event.kind is ExecutionEventKind.STDOUT
                    else prepared.resources.max_stderr_bytes)

                if len(event.data) > maximum - sizes[event.kind]:
                    raise ValueError("Native configuration original stream exceeds its bound")

                sizes[event.kind] += len(event.data)

            control = WriteControl(directory / ("event-" + str(event.sequence) + ".json"),
                {"sequence": event.sequence, "kind": event.kind, "data_hex": event.data.hex(),
                 "termination": event.termination})
            state.controls = (*state.controls, control)
            events.append(event)

    started = datetime.now(UTC).isoformat()
    state.launched = True
    task = asyncio.create_task(LocalExecutor(prepared.workspace_root).Execute(request,
        cancellation=cancellation, pre_launch=Validate, on_event=Observe, own_descendants=True))

    try:
        outcome, interrupted = await Settle(task, cancellation)

    except BaseException as error:
        raise NativeConfigurationCaptureError(
            "Native configuration terminal custody is unconfirmed; original controls retained"
        ) from error

    finished = datetime.now(UTC).isoformat()

    if outcome.events != tuple(events) or outcome.stdout != b"".join(
        item.data for item in events if item.kind is ExecutionEventKind.STDOUT
    ) or outcome.stderr != b"".join(
        item.data for item in events if item.kind is ExecutionEventKind.STDERR
    ):
        raise NativeConfigurationCaptureError(
            "Native configuration original terminal events differ")

    with Finalization(budget):
        terminal = WriteControl(directory / "terminal.json", RawFacts(outcome))
        state.controls = (*state.controls, terminal)

        if PrivateDirectory(prepared.scratch) != scratch_identity:
            raise NativeConfigurationCaptureError("Native configuration execution scratch changed")

        shutil.rmtree(prepared.scratch)
        state.directories = state.directories[:-1]
        state.cleaned_scratch = prepared.scratch

    refusal = None
    observed = None if prepared.operation == "version" else "0.75.0"

    if outcome.execution.state is not ExecutionState.SUCCEEDED or (
        outcome.termination is not ExecutionTermination.PROCESS_EXIT
        or outcome.execution.exit_code != 0
    ):
        refusal = "execution-not-successful"

    elif prepared.operation == "version":
        try:
            payload = ParseJson(outcome.stdout, max_bytes=16 * 1024)

            if payload.get("Version") != "0.75.0":
                raise ValueError("Native configuration provider version differs")

            observed = "0.75.0"

        except (ValueError, TypeError, UnicodeError):
            refusal = "provider-version-unverified"

    proof = None

    try:
        proof = await observer.Verify(material_proof, budget,
            operation_reference=prepared.operation_reference, cancellation=cancellation)

        with Finalization(budget):
            engine.ValidateNativeConfigurationClaim(claim, request, context_provider(),
                observer=observer, material_proof=proof, at=clock())

    except (OSError, ValueError):
        refusal = "material-or-authority-unverified"

    except asyncio.CancelledError:
        refusal = "cancelled"
        interrupted = True

    capture = NativeConfigurationOperationCapture(prepared, grant, request, outcome, started,
                                                  finished, observed, refusal, True)

    with Finalization(budget):
        capture = PublishCapture(capture, store)
        state.capture = capture

    if interrupted:
        raise asyncio.CancelledError

    return capture, proof
