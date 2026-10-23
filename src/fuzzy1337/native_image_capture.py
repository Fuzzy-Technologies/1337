# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Original native image VERSION/SCAN custody; no artifact grants or model interpretation."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from fuzzy1337.native_image_bounded_capture import BoundedNativeTrivyOperationCapture
    from fuzzy1337.native_image_observation import (
        NativeImageMaterialObserver,
        NativeImageMaterialProof,
        NativeImageObservationBudget,
    )

from fuzzy1337.adapters import AdapterInvocation, ExecutionState, SerializeContract
from fuzzy1337.adapters.contracts import RequireText
from fuzzy1337.adapters.trivy import ParseJson, TrivyAdapter
from fuzzy1337.artifact_inputs import (
    ArtifactHandleInfo,
    ArtifactPathInfo,
    ArtifactReadConsent,
    MatchesArtifactReadIdentity,
    PhysicalIdentity,
)
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptors,
    ExecutionAuthorization,
    ExecutionResources,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutionResult,
    LocalExecutor,
)


class NativeTrivyOperation(StrEnum):
    """Closed descriptive native operations, independent of artifact-profile authorization."""

    VERSION = "version"
    SCAN = "scan"


@dataclass(frozen=True, slots=True)
class NativeFileFact:
    """Observed selected bytes and physical identity; never publisher authentication."""

    role: str
    path: str
    size_bytes: int | None
    sha256: str | None
    physical_identity: tuple[int, int, int, int, int] | None


def SelectedFile(path: Path, role: str, maximum: int, *, optional: bool = False) -> NativeFileFact:
    """Hash an explicit read-authorized physical file without buffering a database.

    Args:
        path: Explicit physical selected file whose read consent belongs to the caller.
        role: Descriptive fixed material role, never execution authority.
        maximum: Inclusive byte limit enforced while reading.
        optional: Retain an absent leaf as an explicit missing-material fact.

    Returns:
        Selected SHA-256, length and device/inode/size/mtime/ctime identity.

    Raises:
        ValueError: A selected file uses links, exceeds bounds or changes during observation.
        OSError: Selected material cannot be safely opened or inspected.
    """

    if optional:
        try:
            path.lstat()

        except FileNotFoundError:
            return NativeFileFact(role, str(path), None, None, None)

    before = ArtifactPathInfo(path)

    if before.st_size > maximum or before.st_ino == 0:
        raise ValueError("native selected file exceeds its bound or lacks physical identity")

    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)

    with os.fdopen(os.open(path, flags), "rb") as source:
        opened = ArtifactHandleInfo(source.fileno())

        if not MatchesArtifactReadIdentity(before, opened):
            raise ValueError("native selected file changed before hashing")

        while chunk := source.read(1024 * 1024):
            size += len(chunk)

            if size > maximum:
                raise ValueError("native selected file grew beyond its byte bound")

            digest.update(chunk)

        if PhysicalIdentity(ArtifactHandleInfo(source.fileno())) != PhysicalIdentity(opened):
            raise ValueError("native selected file changed during hashing")

    if PhysicalIdentity(ArtifactPathInfo(path)) != PhysicalIdentity(before) or (
        size != before.st_size
    ):
        raise ValueError("native selected file changed after hashing")

    return NativeFileFact(role, str(path), size, digest.hexdigest(), PhysicalIdentity(before))


@dataclass(frozen=True, slots=True)
class NativeTrivySelection:
    """Explicit trusted native files and read consent; selection itself starts no process."""

    workspace_root: Path
    executable: Path
    archive: str
    cache_directory: str
    read_consent: ArtifactReadConsent

    def __post_init__(self) -> None:
        """Require absolute typed physical selections and explicit non-secret read consent."""

        if not isinstance(self.read_consent, ArtifactReadConsent) or any(
            not isinstance(path, Path) or not path.is_absolute()
            for path in (self.workspace_root, self.executable)
        ):
            raise ValueError("native capture requires absolute selections and explicit consent")

    def Adapter(self, store: LocalEvidenceStore, version: str | None = None) -> TrivyAdapter:
        """Bind the optional adapter to exactly the selected workspace/cache/binary.

        Args:
            store: Existing verified raw-evidence reader without discovery.
            version: Actual previously accepted version for SCAN, absent for original VERSION.

        Returns:
            Selected optional Trivy adapter without execution authority.
        """

        return TrivyAdapter(store.Read, self.workspace_root, str(self.executable), version,
                            self.cache_directory)

    def Material(self) -> tuple[NativeFileFact, ...]:
        """Observe fixed archive/binary/DB selections with distinct identities.

        Returns:
            Ordered archive, executable, database and metadata file facts, including absences.

        Raises:
            ValueError: Material is outside the physical selected boundary or exceeds bounds.
            OSError: Selected material cannot be safely observed.
        """

        from fuzzy1337.adapters.trivy import WorkspacePath

        root = self.workspace_root
        ArtifactPathInfo(root, directory=True)
        archive = WorkspacePath(root, self.archive)
        cache = WorkspacePath(root, self.cache_directory, directory=True)
        database = cache / "db"

        if database.exists() or database.is_symlink():
            ArtifactPathInfo(database, directory=True)

        return (
            SelectedFile(archive, "archive", 512 * 1024 * 1024),
            SelectedFile(self.executable, "executable", 256 * 1024 * 1024),
            SelectedFile(database / "trivy.db", "database", 2 * 1024**3, optional=True),
            SelectedFile(database / "metadata.json", "database-metadata", 16 * 1024, optional=True),
        )


@dataclass(frozen=True, slots=True)
class NativeTrivyOperationCapture:
    """Immutable original execution and retained records, with descriptive association refusal."""

    operation: NativeTrivyOperation
    request: LocalExecutionRequest
    outcome: LocalExecutionResult
    workspace_id: str
    owner_reference: str
    selection: NativeTrivySelection
    material_before: tuple[NativeFileFact, ...]
    material_after: tuple[NativeFileFact, ...] | None
    started_at: str
    finished_at: str
    version_prerequisite_sha256: str | None
    observed_version: str | None
    refusal: str | None
    records: tuple[EvidenceRecord, ...]

    def Envelope(self) -> dict[str, object]:
        """Detach exact original facts without granting execution authority.

        Returns:
            Canonical schema-1 custody document with independently retained stream references.
        """

        return cast(dict[str, object], json.loads(SerializeContract({
            "schema_version": 1, "operation": self.operation,
            "request": self.request, "execution": self.outcome.execution,
            "termination": self.outcome.termination,
            "events": tuple({"sequence": event.sequence, "kind": event.kind,
                "data_hex": event.data.hex(), "termination": event.termination}
                for event in self.outcome.events),
            "selection": {"workspace_root": str(self.selection.workspace_root),
                "executable": str(self.selection.executable), "archive": self.selection.archive,
                "cache_directory": self.selection.cache_directory},
            "workspace_id": self.workspace_id,
            "owner_reference": self.owner_reference, "read_consent": self.selection.read_consent,
            "material_before": self.material_before, "material_after": self.material_after,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "version_prerequisite_sha256": self.version_prerequisite_sha256,
            "observed_version": self.observed_version, "refusal": self.refusal,
            "streams": tuple(record for record in self.records
                             if not record.reference.role.endswith("-receipt")),
        })))

    def Digest(self) -> str:
        """Identify this exact original capture without granting authority.

        Returns:
            SHA-256 of the canonical detached original custody document.
        """

        return hashlib.sha256(SerializeContract(self.Envelope()).encode()).hexdigest()


def CheckVersion(version: NativeTrivyOperationCapture, selection: NativeTrivySelection,
                 store: LocalEvidenceStore, authority: ExecutionAuthorization,
                 workspace_id: str, owner_reference: str,
                 material: tuple[NativeFileFact, ...]) -> None:
    """Reject refused, substituted, cross-owner or changed-material VERSION association.

    Args:
        version: Original executed VERSION capture with its immutable records.
        selection: Current explicit physical material selection and read consent.
        store: Canonical selected evidence store that must reopen every original record.
        authority: Independently issued SCAN authorization with matching scope and policy.
        workspace_id: Current explicit owning workspace identity.
        owner_reference: Current explicit owner, unchanged from VERSION.
        material: Current selected byte and physical facts.

    Raises:
        ValueError: Original VERSION facts or same-owner/material association are unverified.
        OSError: An immutable original record cannot be reopened.
    """

    if not isinstance(version, NativeTrivyOperationCapture) or (
        version.operation is not NativeTrivyOperation.VERSION or version.refusal is not None
    ) or (
        version.outcome.execution.state is not ExecutionState.SUCCEEDED
        or version.outcome.termination is not ExecutionTermination.PROCESS_EXIT
        or version.observed_version is None or version.selection != selection
        or version.material_before != material or version.material_after != material
        or version.workspace_id != workspace_id or version.owner_reference != owner_reference
        or version.request.authorization.scope_reference != authority.scope_reference
        or version.request.authorization.policy_reference != authority.policy_reference
        or version.request.authorization.authorization_id == authority.authorization_id
    ):
        raise ValueError("native SCAN requires the original accepted same-owner/material VERSION")

    if len(version.records) != 3 or {record.reference.role for record in version.records} != {
        "provider-version", "provider-version-stderr", "native-version-receipt"
    }:
        raise ValueError("native VERSION association requires its exact three original records")

    expected = EvidenceProvenance(workspace_id,
        version.request.authorization.scope_reference, "native.trivy", "1",
        version.observed_version, version.started_at, version.finished_at,
        InvocationDigest(version.request.invocation), version.outcome.execution)

    for record in version.records:
        media = "text/plain" if record.reference.role == "provider-version-stderr" else (
            "application/json")

        if record.provenance != expected or record.reference.media_type != media:
            raise ValueError("native VERSION record differs from original operation provenance")

        if store.Get(record.evidence_id) != record:
            raise ValueError("native VERSION differs from its immutable record")

        raw = store.Read(record.reference)

        if record.reference.role in {"provider-version", "provider-version-stderr"} and raw != (
            version.outcome.stdout if record.reference.role == "provider-version"
            else version.outcome.stderr
        ):
            raise ValueError("native VERSION streams differ from original executor bytes")

        if record.reference.role == "native-version-receipt" and raw != (
            SerializeContract(version.Envelope()).encode()
        ):
            raise ValueError("native VERSION facts differ from the original receipt bytes")


def ObserveVersion(raw: bytes, material: tuple[NativeFileFact, ...]) -> str:
    """Verify successful version wire against its selected offline database metadata.

    Args:
        raw: Original bounded successful VERSION stdout, never fixture acceptance authority.
        material: Ordered originally selected archive/binary/database/metadata facts.

    Returns:
        Actual supported native version matching the selected schema-2 database metadata.

    Raises:
        ValueError: Wire, selected database metadata or timezone is unverified.
        OSError: The explicitly selected metadata cannot be safely reread.
    """

    document = ParseJson(raw, 16 * 1024)
    version = document.get("Version")

    if not isinstance(version, str) or not re.fullmatch(r"0\.75\.[0-9]+", version):
        raise ValueError("native VERSION wire requires the supported genuine release envelope")

    metadata_fact = material[-1]

    if metadata_fact.sha256 is None or material[-2].sha256 is None:
        raise ValueError("native VERSION requires selected offline database material")

    metadata_path = Path(metadata_fact.path)
    before = ArtifactPathInfo(metadata_path)

    if PhysicalIdentity(before) != metadata_fact.physical_identity:
        raise ValueError("native database metadata changed before bounded verification")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)

    with os.fdopen(os.open(metadata_fact.path, flags), "rb") as source:
        opened = ArtifactHandleInfo(source.fileno())

        if not MatchesArtifactReadIdentity(before, opened):
            raise ValueError("native database metadata changed before bounded verification")

        metadata_raw = source.read(16 * 1024 + 1)

        if PhysicalIdentity(ArtifactHandleInfo(source.fileno())) != (
            PhysicalIdentity(opened)
        ):
            raise ValueError("native database metadata changed during bounded verification")

    if PhysicalIdentity(ArtifactPathInfo(metadata_path)) != PhysicalIdentity(before):
        raise ValueError("native database metadata changed after bounded verification")

    if len(metadata_raw) > 16 * 1024 or hashlib.sha256(metadata_raw).hexdigest() != (
        metadata_fact.sha256
    ):
        raise ValueError("native database metadata changed after material observation")

    metadata = ParseJson(metadata_raw, 16 * 1024)
    observed = document.get("VulnerabilityDB")

    if not isinstance(observed, dict) or type(metadata.get("Version")) is not int or (
        metadata.get("Version") != 2
    ) or not isinstance(
        metadata.get("UpdatedAt"), str
    ) or any(observed.get(key) != value for key, value in metadata.items()):
        raise ValueError("native observed database metadata differs from selected material")

    updated = datetime.fromisoformat(cast(str, metadata["UpdatedAt"]))

    if updated.tzinfo is None or updated.utcoffset() is None:
        raise ValueError("native selected DB update time must have an explicit timezone")

    return version


async def CaptureNativeTrivyOperation(
    operation: NativeTrivyOperation, selection: NativeTrivySelection,
    invocation: AdapterInvocation, authorization: ExecutionAuthorization,
    store: LocalEvidenceStore, workspace_id: str, owner_reference: str,
    *, version_prerequisite: NativeTrivyOperationCapture | None = None,
    cancellation: asyncio.Event | None = None,
    validate_authority: Callable[[LocalExecutionRequest], None] | None = None,
) -> NativeTrivyOperationCapture:
    """Execute one exact explicitly authorized native operation and preserve original custody facts.

    Args:
        operation: Explicit independent VERSION or prerequisite-bound SCAN.
        selection: Trusted read-authorized native files in an existing owned workspace.
        invocation: Exact selected adapter factory invocation, never caller-injected argv.
        authorization: Caller-issued typed decision bound to this invocation; never issued here.
        store: Existing canonical evidence root at selected workspace/evidence.
        workspace_id: Explicit owning workspace identity without creating persisted model state.
        owner_reference: Explicit owner matching selected read-consent actor.
        version_prerequisite: Original same-material accepted VERSION for SCAN only.
        cancellation: Optional cooperative signal; owned executor retains cancelled raw facts.
        validate_authority: Optional upstream fresh policy callback at actual launch.

    Returns:
        Original execution, raw stream/receipt records and explicit post-run association refusal.

    Raises:
        ValueError: Unsupported setup, invocation, authority or VERSION association before launch.
        OSError: Selected files or raw evidence cannot be safely read/published.
        asyncio.CancelledError: Direct task cancellation propagates after executor cleanup.
    """

    if not isinstance(operation, NativeTrivyOperation) or not isinstance(
        selection, NativeTrivySelection
    ) or not isinstance(invocation, AdapterInvocation) or not isinstance(
        authorization, ExecutionAuthorization
    ) or not isinstance(store, LocalEvidenceStore):
        raise ValueError("native capture requires original typed selection/invocation/authority")

    RequireText(workspace_id, "native workspace identity")
    RequireText(owner_reference, "native owner reference")

    if owner_reference != (
        selection.read_consent.actor_ref
    ) or store.root != selection.workspace_root / "evidence":
        raise ValueError("native capture requires the exact owning selection and evidence root")

    if invocation.request.parameters.get("archive") != selection.archive:
        raise ValueError("native invocation archive differs from the exact selected material")

    ArtifactPathInfo(store.root, directory=True)
    material = selection.Material()
    prerequisite = None

    if operation is NativeTrivyOperation.VERSION:
        if version_prerequisite is not None:
            raise ValueError("native VERSION cannot borrow a previous execution")

        expected = selection.Adapter(store).PrepareVersionInvocation(invocation.request)

    else:
        if version_prerequisite is None:
            raise ValueError("native SCAN requires an original VERSION prerequisite")

        if version_prerequisite.request.invocation.request.target_reference != (
            invocation.request.target_reference
        ):
            raise ValueError("native SCAN requires the original VERSION target")

        CheckVersion(version_prerequisite, selection, store, authorization,
                     workspace_id, owner_reference, material)
        prerequisite = version_prerequisite.Digest()
        adapter = selection.Adapter(store, version_prerequisite.observed_version)
        expected = adapter.PrepareInvocation(invocation.request)

    if invocation != expected:
        raise ValueError("native invocation differs from the exact selected factory profile")

    descriptor = CapabilityDescriptors(selection.Adapter(store).Descriptor)[0]
    resources = ExecutionResources(max_stdout_bytes=16 * 1024, max_stderr_bytes=16 * 1024) if (
        operation is NativeTrivyOperation.VERSION
    ) else ExecutionResources(max_stdout_bytes=4 * 1024 * 1024, max_stderr_bytes=1024 * 1024)
    started_at = ""
    finished_at = ""

    with tempfile.TemporaryDirectory(
        prefix="native-image-", dir=selection.workspace_root
    ) as scratch:
        relative = Path(scratch).relative_to(selection.workspace_root).as_posix()
        environment = {"HOME": scratch, "XDG_CONFIG_HOME": scratch, "XDG_CACHE_HOME": scratch,
            "TMPDIR": scratch, "TEMP": scratch, "TMP": scratch, "PATH": "", "PATHEXT": "",
            "LANG": "C", "LC_ALL": "C"}
        request = LocalExecutionRequest(invocation, descriptor, authorization,
            workspace=relative, environment=environment, resources=resources)

        def Validate(actual: LocalExecutionRequest) -> None:
            """Recheck selected material and upstream authority before process creation.

            Args:
                actual: Exact request presented by the bounded executor before process launch.
            """

            if actual != request or selection.Material() != material:
                raise ValueError("native material changed before the exact owned launch")

            if validate_authority is not None:
                validate_authority(actual)

        started_at = datetime.now(UTC).isoformat()

        outcome = await LocalExecutor(selection.workspace_root).Execute(
            request, cancellation=cancellation, pre_launch=Validate)

    finished_at = datetime.now(UTC).isoformat()
    after = None
    observed_version = None
    refusal = None

    try:
        after = selection.Material()

        if after != material:
            refusal = "material-changed"

        elif outcome.execution.state is not ExecutionState.SUCCEEDED or (
            outcome.termination is not ExecutionTermination.PROCESS_EXIT
        ):
            refusal = "execution-not-successful"

        elif operation is NativeTrivyOperation.VERSION:
            observed_version = ObserveVersion(outcome.stdout, material)

    except (OSError, ValueError):
        refusal = "material-or-version-unverified"

    if validate_authority is not None:
        try:
            validate_authority(request)

        except Exception:
            refusal = "authority-unverified"

    version = observed_version if operation is NativeTrivyOperation.VERSION else (
        invocation.provider_version)
    provenance = EvidenceProvenance(workspace_id, authorization.scope_reference,
        "native.trivy", "1", version, started_at, finished_at,
        InvocationDigest(invocation), outcome.execution)
    roles = ("provider-version", "provider-version-stderr", "native-version-receipt") if (
        operation is NativeTrivyOperation.VERSION
    ) else ("stdout", "stderr", "native-scan-receipt")
    records = tuple(store.Put(raw, role, media, provenance) for raw, role, media in (
        (outcome.stdout, roles[0], "application/json"), (outcome.stderr, roles[1], "text/plain")))
    capture = NativeTrivyOperationCapture(operation, request, outcome,
        workspace_id, owner_reference, selection, material, after, started_at, finished_at,
        prerequisite, version, refusal, records)
    receipt = store.Put(SerializeContract(capture.Envelope()).encode(), roles[2],
                        "application/json", provenance)

    return NativeTrivyOperationCapture(operation, request, outcome,
        workspace_id, owner_reference, selection, material, after, started_at, finished_at,
        prerequisite, version, refusal, (*records, receipt))


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
    """Select additive bounded custody explicitly without importing its owners during replay.

    Args:
        operation: Original explicit VERSION or prerequisite-bound SCAN.
        selection: Original typed native files and independent read consent.
        invocation: Original exact finite adapter invocation.
        authorization: Independent original exact-invocation authority.
        store: Existing canonical evidence owner.
        workspace_id: Exact original workspace identity.
        owner_reference: Exact read-consent actor.
        observer: Fixed first-party owned material observer.
        budget: Whole-pair cumulative observation/finalization ledger.
        material_proof: Original same-observer same-pair current material proof.
        operation_reference: Whole VERSION/SCAN owner-pair reference.
        version_prerequisite: Original accepted VERSION required by SCAN.
        cancellation: Cooperative signal; outer cancellation also signals the owned executor.
        validate_authority: Fresh synchronous upstream authority check, never a material callback.

    Returns:
        Unchanged historical capture plus optional reusable post-observation proof.
    """

    from fuzzy1337.native_image_bounded_capture import (
        CaptureBoundedNativeTrivyOperation as CaptureBounded,
    )

    return await CaptureBounded(operation, selection, invocation, authorization, store,
        workspace_id, owner_reference, observer=observer, budget=budget,
        material_proof=material_proof, operation_reference=operation_reference,
        version_prerequisite=version_prerequisite, cancellation=cancellation,
        validate_authority=validate_authority)
