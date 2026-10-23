# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Additive bounded original Trivy custody using only owned material observations."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar, cast

from fuzzy1337.adapters import (
    AdapterInvocation,
    EvidenceReference,
    ExecutionState,
)
from fuzzy1337.adapters.contracts import JsonValue, RequireText
from fuzzy1337.adapters.trivy import ParseJson
from fuzzy1337.artifact_inputs import ArtifactHandleInfo, ArtifactPathInfo
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptors,
    ExecutionAuthorization,
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionResources,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutionResult,
    LocalExecutor,
)
from fuzzy1337.executors.owned_process import RequireLinuxOwnership
from fuzzy1337.native_image_capture import (
    CheckVersion,
    NativeTrivyOperation,
    NativeTrivyOperationCapture,
    NativeTrivySelection,
)
from fuzzy1337.native_image_observation import (
    NativeImageMaterialObserver,
    NativeImageMaterialProof,
    NativeImageObservationBudget,
    NativeImageObservationError,
)

CONTROL_BYTES = 64 * 1024
VERSION_RECEIPT_BYTES = 256 * 1024
SCAN_RECEIPT_BYTES = 16 * 1024 * 1024
JOURNAL_BYTES = 32 * 1024 * 1024
VERSION_EVENTS = 512
SCAN_EVENTS = 16384
TERMINAL_EVENT_BYTES = 256
JOURNAL_MAGIC = b"1337-native-outcome-v1\n"
_Result = TypeVar("_Result")


@dataclass(frozen=True, slots=True)
class BoundedNativeTrivyOperationCapture:
    """Original unchanged capture plus the optional reusable same-pair post-observation proof."""

    capture: NativeTrivyOperationCapture
    material_proof: NativeImageMaterialProof | None


class NativeImageBoundedCaptureError(RuntimeError):
    """Incomplete original custody or uncertain publication with retained private recovery bytes."""

    def __init__(self, reason: str, journal_path: Path | None,
                 *, outcome_retained: bool = False) -> None:
        """Expose a fixed failure category and an explicit owner-only recovery location.

        Args:
            reason: Internal fixed failure category, without provider or filesystem diagnostics.
            journal_path: Private bounded journal retained when available.
            outcome_retained: Whether a complete original terminal outcome was durably verified.
        """

        super().__init__(f"Bounded native capture refused: {reason}")
        self.reason = reason
        self.journal_path = journal_path
        self.outcome_retained = outcome_retained


def EncodeBounded(value: object, maximum: int) -> bytes:
    """Encode exact existing canonical contract bytes while enforcing an inclusive ceiling.

    Args:
        value: Finite typed control or an already bounded collection of original events.
        maximum: Inclusive canonical UTF-8 byte ceiling.

    Returns:
        Complete canonical bytes; no truncated encoding can be returned.
    """

    encoded = bytearray()
    encoder = json.JSONEncoder(allow_nan=False, separators=(",", ":"), sort_keys=True)

    for fragment in encoder.iterencode(JsonValue(value)):
        raw = fragment.encode("utf-8")

        if len(raw) > maximum - len(encoded):
            raise ValueError("bounded native control exceeds its byte ceiling")

        encoded.extend(raw)

    return bytes(encoded)


@contextmanager
def Finalization(budget: NativeImageObservationBudget) -> Iterator[None]:
    """Charge one synchronous slice against the pair's shared nine-second reserve.

    Args:
        budget: Original cumulative ledger; observations never overlap this slice.

    Yields:
        Owned synchronous work charged to the original shared finalization reserve.
    """

    window = budget.BeginFinalization()

    try:
        yield

    finally:
        budget.FinishFinalization(window)


def EventValue(event: ExecutionEvent) -> dict[str, object]:
    """Preserve exactly the historical receipt representation of one original event.

    Args:
        event: Original executor event, without trimming or stream rechunking.

    Returns:
        The unchanged four original event fields.
    """

    return {"sequence": event.sequence, "kind": event.kind,
            "data_hex": event.data.hex(), "termination": event.termination}


class OriginalEvents:
    """Bound count, exact encoded event bytes and raw fragments during executor observation."""

    def __init__(self, operation: NativeTrivyOperation, resources: ExecutionResources) -> None:
        """Reserve one original completion event and fixed terminal serialization overhead.

        Args:
            operation: Closed VERSION or SCAN profile with independent historical limits.
            resources: Original finite stdout/stderr ceilings.
        """

        self.maximum = VERSION_EVENTS if operation is NativeTrivyOperation.VERSION else SCAN_EVENTS
        self.receipt_maximum = (
            VERSION_RECEIPT_BYTES if operation is NativeTrivyOperation.VERSION
            else SCAN_RECEIPT_BYTES)
        self.maximum_bytes = self.receipt_maximum - CONTROL_BYTES
        self.events: list[ExecutionEvent] = []
        self.encoded_bytes = 2
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.resources = resources

    def Observe(self, event: ExecutionEvent) -> None:
        """Admit a complete exact event only if every incremental bound still holds.

        Args:
            event: Executor-owned next original event, already appended by its owner.

        Raises:
            ValueError: Count, sequence, raw streams or exact serialization exceeds admission.
        """

        if type(event) is not ExecutionEvent or event.sequence != len(self.events) or (
            self.events and self.events[-1].kind is ExecutionEventKind.COMPLETED
        ):
            raise ValueError("native event identity differs")

        terminal = event.kind is ExecutionEventKind.COMPLETED
        maximum_count = self.maximum if terminal else self.maximum - 1
        maximum_bytes = self.maximum_bytes if terminal else (
            self.maximum_bytes - TERMINAL_EVENT_BYTES)
        destination = self.stdout if event.kind is ExecutionEventKind.STDOUT else self.stderr
        limit = (self.resources.max_stdout_bytes if event.kind is ExecutionEventKind.STDOUT
                 else self.resources.max_stderr_bytes)

        if len(self.events) >= maximum_count or len(event.data) > limit - len(destination):
            raise ValueError("native event count or stream ceiling exceeded")

        raw = EncodeBounded(EventValue(event), maximum_bytes)
        added = len(raw) + bool(self.events)

        if added > maximum_bytes - self.encoded_bytes:
            raise ValueError("native event serialization ceiling exceeded")

        self.events.append(event)
        self.encoded_bytes += added

        if event.kind in {ExecutionEventKind.STDOUT, ExecutionEventKind.STDERR}:
            destination.extend(event.data)

    def Confirm(self, outcome: LocalExecutionResult) -> None:
        """Require the actual terminal outcome to agree with every original observed fragment.

        Args:
            outcome: Actual executor result after its owned cleanup.
        """

        if type(outcome) is not LocalExecutionResult or outcome.events != tuple(self.events) or (
            outcome.stdout != self.stdout or outcome.stderr != self.stderr
        ):
            raise ValueError("native original outcome differs from observed events")


class OutcomeJournal:
    """Own one exclusive finite integrity-framed private outcome journal and execution scratch."""

    def __init__(self, workspace: Path) -> None:
        """Create only a fresh private collector directory, distinct from observation controls.

        Args:
            workspace: Verified explicitly owned existing physical workspace.
        """

        self.directory = Path(tempfile.mkdtemp(prefix="native-image-bounded-", dir=workspace))
        os.chmod(self.directory, 0o700)
        self.scratch = self.directory / "work"
        self.scratch.mkdir(mode=0o700)
        self.path = self.directory / "outcome.journal"
        self.descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_NOFOLLOW", 0), 0o600)

        try:
            cast(Callable[[int, int], None], getattr(os, "fchmod"))(self.descriptor, 0o600)
            info = ArtifactPathInfo(self.directory, directory=True)
            self.directory_identity = (info.st_dev, info.st_ino)
            opened = ArtifactHandleInfo(self.descriptor)
            self.file_identity = (opened.st_dev, opened.st_ino)
            self.size = 0
            self.outcome_retained = False
            self.fragments_retained = False
            self.removed = False
            self.Write(JOURNAL_MAGIC)

        except BaseException:
            self.Close()
            shutil.rmtree(self.directory)

            raise

    def Check(self) -> None:
        """Require original private path/handle identities and exact private permissions."""

        directory = ArtifactPathInfo(self.directory, directory=True)
        path = ArtifactPathInfo(self.path)
        opened = ArtifactHandleInfo(self.descriptor)

        if (directory.st_dev, directory.st_ino) != self.directory_identity or (
            (path.st_dev, path.st_ino) != self.file_identity
            or (opened.st_dev, opened.st_ino) != self.file_identity
            or stat.S_IMODE(directory.st_mode) != 0o700
            or stat.S_IMODE(path.st_mode) != 0o600
            or path.st_size != self.size or opened.st_size != self.size
        ):
            raise ValueError("native private journal identity differs")

    def Write(self, raw: bytes) -> None:
        """Write complete finite private bytes without accepting a short write as custody.

        Args:
            raw: Original frame bytes within the remaining total journal ceiling.
        """

        if len(raw) > JOURNAL_BYTES - self.size:
            raise ValueError("native private journal exceeds its ceiling")

        offset = 0

        while offset < len(raw):
            written = os.write(self.descriptor, raw[offset:])

            if written <= 0:
                raise OSError("native private journal write was incomplete")

            offset += written
            self.size += written

    def Append(self, value: object, *, complete: bool = False, fragments: bool = False) -> None:
        """Durably retain an exact length/SHA-256 frame before any following asynchronous work.

        Args:
            value: Bounded original control, complete outcome or explicitly incomplete fragments.
            complete: Mark complete original custody only after durable readback verification.
            fragments: Mark an explicitly incomplete exact prefix as already retained.
        """

        self.Check()
        raw = EncodeBounded(value, JOURNAL_BYTES - self.size - 40)
        self.Write(len(raw).to_bytes(8, "big") + hashlib.sha256(raw).digest() + raw)
        os.fsync(self.descriptor)
        self.SyncDirectory()
        self.Verify()
        self.outcome_retained = self.outcome_retained or complete
        self.fragments_retained = self.fragments_retained or fragments

    def SyncDirectory(self) -> None:
        """Durably acknowledge the private journal's original owning directory entry."""

        directory_fd = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                               getattr(os, "O_NOFOLLOW", 0))

        try:
            os.fsync(directory_fd)

        finally:
            os.close(directory_fd)

    def Verify(self) -> None:
        """Verify exact finite journal length, private identities and every original frame hash."""

        self.Check()
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        raw = bytearray()

        while len(raw) <= self.size:
            chunk = os.read(self.descriptor, min(1024 * 1024, self.size + 1 - len(raw)))

            if not chunk:
                break

            raw.extend(chunk)

        if len(raw) != self.size or not raw.startswith(JOURNAL_MAGIC):
            raise ValueError("native private journal framing differs")

        offset = len(JOURNAL_MAGIC)

        while offset < len(raw):
            if len(raw) - offset < 40:
                raise ValueError("native private journal frame is incomplete")

            size = int.from_bytes(raw[offset:offset + 8], "big")
            digest = raw[offset + 8:offset + 40]
            offset += 40
            value = raw[offset:offset + size]

            if len(value) != size or hashlib.sha256(value).digest() != digest:
                raise ValueError("native private journal integrity differs")

            offset += size

        os.lseek(self.descriptor, 0, os.SEEK_END)

    def Close(self) -> None:
        """Close only the private owned handle, retaining recovery bytes on every refusal."""

        if self.descriptor >= 0:
            descriptor, self.descriptor = self.descriptor, -1
            os.close(descriptor)

    def RemoveConfirmed(self) -> None:
        """Remove staging only after all original canonical roles were independently confirmed."""

        self.Check()
        shutil.rmtree(self.scratch)
        self.Close()
        self.path.unlink()
        self.removed = True
        self.directory.rmdir()


async def AwaitOwned(task: asyncio.Task[_Result], cancellation: asyncio.Event,
                     interrupted: list[asyncio.CancelledError]) -> _Result:
    """Bridge caller cancellation cooperatively and await the original owned task to completion.

    Args:
        task: Sole tracked executor or observation task; never abandoned after shielding.
        cancellation: Cooperative signal consumed by that exact owner.
        interrupted: Preserve the original caller cancellation until custody finalizes.

    Returns:
        Actual owner result, after its cleanup; caller cancellation is propagated later.
    """

    while True:
        try:
            return await asyncio.shield(task)

        except asyncio.CancelledError as error:
            if task.cancelled():
                raise

            cancellation.set()

            if not interrupted:
                interrupted.append(error)


def PureVersion(raw: bytes, proof: NativeImageMaterialProof) -> str:
    """Compare bounded original VERSION JSON with helper-verified metadata without file reads.

    Args:
        raw: Original successful VERSION stdout within its historical wire ceiling.
        proof: Original observer-issued selected database/metadata observation.

    Returns:
        The actual supported native version after strict schema-two metadata agreement.
    """

    document = ParseJson(raw, 16 * 1024)
    version = document.get("Version")
    metadata = proof.Metadata()
    observed = document.get("VulnerabilityDB")

    if not isinstance(version, str) or not re.fullmatch(r"0\.75\.[0-9]+", version) or (
        proof.facts[-2].sha256 is None or proof.facts[-1].sha256 is None
        or not isinstance(metadata, dict) or not isinstance(observed, dict)
        or type(metadata.get("Version")) is not int
        or metadata["Version"] != 2 or not isinstance(metadata.get("UpdatedAt"), str)
        or any(observed.get(key) != value for key, value in metadata.items())
    ):
        raise ValueError("native VERSION or selected metadata is unverified")

    updated = datetime.fromisoformat(cast(str, metadata["UpdatedAt"]))

    if updated.tzinfo is None or updated.utcoffset() is None:
        raise ValueError("native selected metadata timezone is unverified")

    return version


def FinitePrerequisite(version: NativeTrivyOperationCapture) -> None:
    """Bound an original VERSION before invoking its unchanged historical association checks.

    Args:
        version: Original prerequisite, never a fabricated health or success receipt.
    """

    if not isinstance(version, NativeTrivyOperationCapture) or (
        len(version.outcome.stdout) > 16 * 1024 or len(version.outcome.stderr) > 16 * 1024
        or len(version.outcome.events) > VERSION_EVENTS or len(version.records) != 3
    ):
        raise ValueError("native VERSION prerequisite exceeds bounded admission")

    for event in version.outcome.events:
        if len(event.data) > 16 * 1024:
            raise ValueError("native VERSION prerequisite event exceeds its bound")

    EncodeBounded(version.Envelope(), VERSION_RECEIPT_BYTES)

    for record in version.records:
        maximum = VERSION_RECEIPT_BYTES if record.reference.role.endswith("-receipt") else (
            16 * 1024)

        if record.reference.size_bytes is None or record.reference.size_bytes > maximum:
            raise ValueError("native VERSION original record exceeds its bound")


def PreparedRecord(raw: bytes, role: str, media: str,
                   provenance: EvidenceProvenance) -> EvidenceRecord:
    """Prepare exact existing content-addressed metadata before any canonical publication.

    Args:
        raw: Complete original bytes, without interpretation or transformation.
        role: One of the unchanged six historical custody roles.
        media: Original role media type.
        provenance: Exact original native operation provenance.

    Returns:
        The expected unchanged evidence record, independently confirmed after Put.
    """

    digest = hashlib.sha256(raw).hexdigest()

    return EvidenceRecord(EvidenceReference(role, f"blobs/sha256/{digest}", digest,
                                            media, len(raw)), provenance)


async def CaptureBoundedNativeTrivyOperation(
    operation: NativeTrivyOperation, selection: NativeTrivySelection,
    invocation: AdapterInvocation, authorization: ExecutionAuthorization,
    store: LocalEvidenceStore, workspace_id: str, owner_reference: str,
    *, observer: NativeImageMaterialObserver, budget: NativeImageObservationBudget,
    material_proof: NativeImageMaterialProof, operation_reference: str,
    version_prerequisite: NativeTrivyOperationCapture | None = None,
    cancellation: asyncio.Event | None = None,
    validate_authority: Callable[[LocalExecutionRequest], None] | None = None,
) -> BoundedNativeTrivyOperationCapture:
    """Own one bounded original native operation without changing legacy capture or receipt wire.

    Args:
        operation: Exact independent VERSION or prerequisite-bound SCAN.
        selection: Explicit original typed native selection and read consent.
        invocation: Exact original fixed factory invocation; VERSION retains its three seconds.
        authorization: Independently issued exact-invocation execution decision.
        store: Existing canonical evidence owner under the selected physical workspace.
        workspace_id: Exact owning workspace identity.
        owner_reference: Exact selected read-consent actor.
        observer: Original fixed first-party material observation owner.
        budget: Whole-pair cumulative 45-second overhead ledger and shared nine-second reserve.
        material_proof: Original same-instance same-pair pre-launch observation proof.
        operation_reference: Whole VERSION/SCAN pair reference, never execution permission.
        version_prerequisite: Original bounded accepted VERSION for SCAN only.
        cancellation: Cooperative signal also set when the outer task is cancelled.
        validate_authority: Existing synchronous upstream policy check; never material hashing.

    Returns:
        Original unchanged three-role capture and optional reusable post-observation proof.

    Raises:
        ValueError: Typed setup, exact profile, current proof or original authority is invalid.
        NativeImageBoundedCaptureError: Original outcome is incomplete or publication uncertain.
        asyncio.CancelledError: Original caller cancellation, after owned cleanup and finalization.
    """

    if not isinstance(operation, NativeTrivyOperation) or not isinstance(
        selection, NativeTrivySelection
    ) or not isinstance(invocation, AdapterInvocation) or not isinstance(
        authorization, ExecutionAuthorization
    ) or not isinstance(store, LocalEvidenceStore) or not isinstance(
        observer, NativeImageMaterialObserver
    ) or not isinstance(budget, NativeImageObservationBudget) or not isinstance(
        material_proof, NativeImageMaterialProof
    ):
        raise ValueError("bounded native capture requires original typed owners and proof")

    for value in (workspace_id, owner_reference, operation_reference):
        RequireText(value, "bounded native identity")

        if len(value) > CONTROL_BYTES:
            raise ValueError("bounded native identity exceeds its control ceiling")

    signal = cancellation if cancellation is not None else asyncio.Event()

    if signal.is_set():
        raise asyncio.CancelledError

    RequireLinuxOwnership()

    if owner_reference != selection.read_consent.actor_ref or (
        store.root != selection.workspace_root / "evidence"
        or material_proof.workspace_id != workspace_id
        or material_proof.owner_reference != owner_reference
        or invocation.request.parameters.get("archive") != selection.archive
    ):
        raise ValueError("bounded native selection or proof owner differs")

    journal: OutcomeJournal | None = None
    interrupted: list[asyncio.CancelledError] = []

    try:
        with Finalization(budget):
            ArtifactPathInfo(store.root, directory=True)
            observer.CheckCurrent(material_proof, operation_reference=operation_reference)
            material = material_proof.facts

            if material[-2].sha256 is None or material[-1].sha256 is None or (
                material_proof.Metadata() is None
            ):
                raise ValueError("bounded native execution requires selected database material")

            prerequisite = None

            if operation is NativeTrivyOperation.VERSION:
                if version_prerequisite is not None:
                    raise ValueError("native VERSION cannot borrow a previous execution")

                expected = selection.Adapter(store).PrepareVersionInvocation(invocation.request)

            else:
                if not isinstance(version_prerequisite, NativeTrivyOperationCapture) or (
                    version_prerequisite.request.invocation.request.target_reference !=
                    invocation.request.target_reference
                ):
                    raise ValueError("native SCAN requires its exact original VERSION target")

                FinitePrerequisite(version_prerequisite)
                CheckVersion(version_prerequisite, selection, store, authorization,
                             workspace_id, owner_reference, material)
                prerequisite = version_prerequisite.Digest()
                adapter = selection.Adapter(store, version_prerequisite.observed_version)
                expected = adapter.PrepareInvocation(invocation.request)

            if invocation != expected:
                raise ValueError("native invocation differs from the original finite factory")

            journal = OutcomeJournal(selection.workspace_root)
            scratch = str(journal.scratch)
            resources = (
                ExecutionResources(max_stdout_bytes=16 * 1024, max_stderr_bytes=16 * 1024)
                if operation is NativeTrivyOperation.VERSION else ExecutionResources(
                    max_stdout_bytes=4 * 1024 * 1024, max_stderr_bytes=1024 * 1024))
            environment = {"HOME": scratch, "XDG_CONFIG_HOME": scratch,
                "XDG_CACHE_HOME": scratch, "TMPDIR": scratch, "TEMP": scratch, "TMP": scratch,
                "PATH": "", "PATHEXT": "", "LANG": "C", "LC_ALL": "C"}
            request = LocalExecutionRequest(invocation,
                CapabilityDescriptors(selection.Adapter(store).Descriptor)[0], authorization,
                workspace=journal.scratch.relative_to(selection.workspace_root).as_posix(),
                environment=environment, resources=resources)
            events = OriginalEvents(operation, resources)
            started_at = datetime.now(UTC).isoformat()
            header = {"schema_version": 1, "pair_reference": operation_reference,
                "operation": operation, "workspace_id": workspace_id,
                "owner_reference": owner_reference, "request": request,
                "selection": selection, "proof_sha256": material_proof.Digest(),
                "observation_id": material_proof.observation_id,
                "workspace_identity": material_proof.workspace_identity,
                "operation_directory_identity": journal.directory_identity,
                "journal_identity": journal.file_identity,
                "material_before": material, "started_at": started_at}
            # Paths are explicit JSON strings, never a serializer extension or selected-file read.
            header["selection"] = {"workspace_root": str(selection.workspace_root),
                "executable": str(selection.executable), "archive": selection.archive,
                "cache_directory": selection.cache_directory,
                "read_consent": selection.read_consent}
            EncodeBounded({"state": "prepared", "control": header}, CONTROL_BYTES)
            journal.Append({"state": "prepared", "control": header})

        def Validate(actual: LocalExecutionRequest) -> None:
            """Perform only fresh bounded identities, cancellation and original upstream checks."""

            with Finalization(budget):
                if actual != request or signal.is_set():
                    raise ValueError("bounded native launch request or cancellation differs")

                observer.CheckCurrent(material_proof, operation_reference=operation_reference)
                Authority(actual)

        def Authority(actual: LocalExecutionRequest) -> None:
            """Require the current upstream decision to stay synchronous at every boundary.

            Args:
                actual: Exact original operation request, never a replacement permission.
            """

            if validate_authority is not None:
                check = cast(Callable[[LocalExecutionRequest], object], validate_authority)
                response = check(actual)

                if response is not None:
                    if inspect.iscoroutine(response):
                        response.close()

                    raise ValueError("native authority validation must return None")

        def Observe(event: ExecutionEvent) -> None:
            """Charge exact incremental event/control handling without an unbounded event list."""

            with Finalization(budget):
                try:
                    events.Observe(event)

                except ValueError:
                    assert journal is not None, "Private original journal must already be owned."
                    journal.Append({"state": "incomplete", "reason": "event-control-overflow",
                        "stdout_hex": events.stdout.hex(), "stderr_hex": events.stderr.hex(),
                        "events": tuple(EventValue(value) for value in events.events)},
                        fragments=True)

                    raise

        execution_task = asyncio.create_task(LocalExecutor(selection.workspace_root).Execute(
            request, cancellation=signal, pre_launch=Validate, on_event=Observe,
            own_descendants=True))

        try:
            outcome = await AwaitOwned(execution_task, signal, interrupted)

        except BaseException:
            with Finalization(budget):
                if not journal.fragments_retained:
                    journal.Append({"state": "incomplete", "reason": "terminal-outcome-unconfirmed",
                        "stdout_hex": events.stdout.hex(), "stderr_hex": events.stderr.hex(),
                        "events": tuple(EventValue(value) for value in events.events)},
                        fragments=True)

            raise NativeImageBoundedCaptureError("terminal-outcome-unconfirmed", journal.path) \
                from None

        # No await may precede this complete synchronous durable original-outcome transfer.
        with Finalization(budget):
            finished_at = datetime.now(UTC).isoformat()
            events.Confirm(outcome)
            journal.Append({"state": "complete", "finished_at": finished_at,
                "execution": outcome.execution, "termination": outcome.termination,
                "stdout_hex": outcome.stdout.hex(), "stderr_hex": outcome.stderr.hex(),
                "events": tuple(EventValue(value) for value in outcome.events)}, complete=True)

        after_proof = None
        after = None
        observed_version = None
        refusal = None

        try:
            Validate(request)
            observation_task = asyncio.create_task(observer.Observe(budget,
                operation_reference=operation_reference, cancellation=signal))
            after_proof = await AwaitOwned(observation_task, signal, interrupted)

            with Finalization(budget):
                observer.CheckCurrent(after_proof, operation_reference=operation_reference)
                after = after_proof.facts

                if after != material:
                    refusal = "material-changed"

                elif outcome.execution.state is not ExecutionState.SUCCEEDED or (
                    outcome.termination is not ExecutionTermination.PROCESS_EXIT
                ):
                    refusal = "execution-not-successful"

                elif operation is NativeTrivyOperation.VERSION:
                    observed_version = PureVersion(outcome.stdout, after_proof)

        except (Exception, asyncio.CancelledError):
            refusal = "material-or-version-unverified"
            after_proof = None
            after = None

        with Finalization(budget):
            try:
                Authority(request)

            except Exception:
                refusal = "authority-unverified"

            if signal.is_set():
                refusal = "authority-unverified"

            version = observed_version if operation is NativeTrivyOperation.VERSION else (
                invocation.provider_version)
            provenance = EvidenceProvenance(workspace_id, authorization.scope_reference,
                "native.trivy", "1", version, started_at, finished_at,
                InvocationDigest(invocation), outcome.execution)
            roles = (
                ("provider-version", "provider-version-stderr", "native-version-receipt")
                if operation is NativeTrivyOperation.VERSION else (
                    "stdout", "stderr", "native-scan-receipt"))
            originals = ((outcome.stdout, roles[0], "application/json"),
                         (outcome.stderr, roles[1], "text/plain"))
            records = tuple(PreparedRecord(raw, role, media, provenance)
                            for raw, role, media in originals)
            capture = NativeTrivyOperationCapture(operation, request, outcome, workspace_id,
                owner_reference, selection, material, after, started_at, finished_at,
                prerequisite, version, refusal, records)
            envelope = capture.Envelope()
            control = {key: value for key, value in envelope.items() if key != "events"}
            EncodeBounded(control, CONTROL_BYTES)
            receipt_bytes = EncodeBounded(envelope, events.receipt_maximum)
            receipt_record = PreparedRecord(receipt_bytes, roles[2], "application/json", provenance)

            try:
                for raw, role, media in (*originals,
                    (receipt_bytes, roles[2], "application/json")):
                    actual = store.Put(raw, role, media, provenance)
                    expected_record = receipt_record if role == roles[2] else (
                        records[0] if role == roles[0] else records[1])

                    if actual != expected_record or store.Get(actual.evidence_id) != actual or (
                        store.Read(actual.reference) != raw
                    ):
                        raise ValueError("native original publication acknowledgement differs")

            except Exception:
                raise NativeImageBoundedCaptureError("publication-unconfirmed", journal.path,
                    outcome_retained=journal.outcome_retained) from None

            complete = NativeTrivyOperationCapture(operation, request, outcome, workspace_id,
                owner_reference, selection, material, after, started_at, finished_at,
                prerequisite, version, refusal, (*records, receipt_record))
            journal.RemoveConfirmed()

        if interrupted:
            raise interrupted[0]

        return BoundedNativeTrivyOperationCapture(complete, after_proof)

    except NativeImageObservationError:
        if journal is not None:
            raise NativeImageBoundedCaptureError("overhead-budget-unconfirmed",
                None if journal.removed else journal.path,
                outcome_retained=journal.outcome_retained) from None

        raise

    except (OSError, ValueError):
        if journal is not None:
            raise NativeImageBoundedCaptureError("original-custody-unconfirmed",
                None if journal.removed else journal.path,
                outcome_retained=journal.outcome_retained) from None

        raise

    finally:
        if journal is not None:
            journal.Close()
