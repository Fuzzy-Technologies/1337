# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned finite native-material observation and instance-associated private proof."""

from __future__ import annotations

import asyncio
import hashlib
import math
import os
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import cast

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ExecutionState, ImpactLevel
from fuzzy1337.adapters.trivy import WorkspacePath
from fuzzy1337.artifact_inputs import ArtifactPathInfo, PhysicalIdentity
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    ExecutionEvent,
    ExecutionResources,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutor,
)
from fuzzy1337.executors.local import LocalExecutionError
from fuzzy1337.executors.owned_process import RequireLinuxOwnership
from fuzzy1337.native_image_capture import NativeFileFact, NativeTrivySelection
from fuzzy1337.native_image_material_worker import (
    CONTROL_MAX_BYTES,
    ROLE_BOUNDS,
    CanonicalControl,
    ControlIdentity,
    ParseControl,
    ReadControl,
    RequireText,
    StrictMetadata,
)


class NativeImageObservationError(ValueError):
    """Refuse unverified material, exhausted ownership or incomplete private control."""


@dataclass(frozen=True, slots=True)
class NativeImageObservationWindow:
    """One issued absolute monotonic allowance, including reserved owned cleanup."""

    started_at: float
    deadline: float
    working_deadline: float

    def WorkerSeconds(self) -> float:
        """Return the live worker ceiling without borrowing its cleanup reserve.

        Returns:
            At most six actual seconds before the working deadline.

        Raises:
            NativeImageObservationError: No positive working allowance remains.
        """

        remaining = min(6.0, self.working_deadline - monotonic())

        if remaining <= 0:
            raise NativeImageObservationError("native material working allowance is exhausted")

        return remaining


class NativeImageObservationBudget:
    """Single-owner cumulative 12/12/12/9 ledger, or one 12-second planning call."""

    def __init__(self, *, planning: bool = False, overall_deadline: float | None = None) -> None:
        """Create a fixed ledger without file reads or process work.

        Args:
            planning: Limit this separate call to one observation and no finalization.
            overall_deadline: Optional finite absolute monotonic owning-job deadline.

        Raises:
            NativeImageObservationError: A mode/deadline has an incompatible type.
        """

        if type(planning) is not bool or overall_deadline is not None and (
            isinstance(overall_deadline, bool) or not isinstance(overall_deadline, (int, float))
        ):
            raise NativeImageObservationError("native material budget requires finite deadlines")

        if overall_deadline is not None:
            try:
                finite = math.isfinite(overall_deadline)

            except OverflowError:
                finite = False

            if not finite:
                raise NativeImageObservationError("native material deadline must be finite")

        self._planning = planning
        self._overall_deadline = overall_deadline
        self._spent = 0.0
        self._observations = 0
        self._finalization = 0.0
        self._failed = False
        self._active: NativeImageObservationWindow | None = None
        self._finalizing = False

    @property
    def SpentSeconds(self) -> float:
        """Return actual overhead already charged to completed windows."""

        return self._spent

    @property
    def ObservationCount(self) -> int:
        """Return observations claimed, including a failed consumed allowance."""

        return self._observations

    @property
    def FinalizationSeconds(self) -> float:
        """Return actual finalization charged across all nonoverlapping slices."""

        return self._finalization

    @property
    def Failed(self) -> bool:
        """Return whether further observation has been irrevocably refused."""

        return self._failed

    def BeginObservation(self) -> NativeImageObservationWindow:
        """Claim one of the fixed observation slots without spending the final reserve.

        Returns:
            Exact issued window accepted once by FinishObservation.
        """

        if self._failed or self._observations >= (1 if self._planning else 3):
            raise NativeImageObservationError("native material observation cannot be retried")

        reserve = 0.0 if self._planning else 9.0 - self._finalization
        window = self.BeginWindow(12.0, reserve, finalizing=False)
        self._observations += 1

        return window

    def FinishObservation(self, window: NativeImageObservationWindow, *, successful: bool) -> None:
        """Charge actual elapsed observation and permanently latch a failed read.

        Args:
            window: Exact single active issued observation object.
            successful: Actual proof completion, never a caller material digest.
        """

        if type(successful) is not bool:
            raise NativeImageObservationError("native material completion requires a boolean")

        self.FinishWindow(window, finalizing=False)
        self._failed = self._failed or not successful

    def BeginFinalization(self) -> NativeImageObservationWindow:
        """Claim a slice from the shared nine-second finalization reserve.

        Returns:
            Exact nonoverlapping issued window, available after failed observation too.
        """

        if self._planning:
            raise NativeImageObservationError("planning has no capture finalization allowance")

        return self.BeginWindow(9.0 - self._finalization, 0.0, finalizing=True)

    def FinishFinalization(self, window: NativeImageObservationWindow) -> None:
        """Charge one exact finalization slice without resetting the shared reserve.

        Args:
            window: Exact currently active finalization object.
        """

        self.FinishWindow(window, finalizing=True)

    def BeginWindow(self, maximum: float, reserve: float, *, finalizing: bool
               ) -> NativeImageObservationWindow:
        """Issue a single finite window from the current cumulative ledger.

        Args:
            maximum: Fixed observation or remaining finalization phase ceiling.
            reserve: Unused finalization time unavailable to observations.
            finalizing: Select the existing finalization allowance.

        Returns:
            Exact issued active window, never a caller-created replacement.
        """

        if self._active is not None:
            raise NativeImageObservationError("native material windows cannot overlap")

        now = monotonic()
        remaining = (12.0 if self._planning else 45.0) - self._spent - reserve
        deadline = now + min(maximum, remaining)

        if self._overall_deadline is not None:
            deadline = min(deadline, self._overall_deadline)

        if deadline <= now or not finalizing and deadline - now <= 3.0:
            raise NativeImageObservationError("native material cumulative allowance is exhausted")

        window = NativeImageObservationWindow(now, deadline,
            deadline if finalizing else deadline - 3.0)
        self._active = window
        self._finalizing = finalizing

        return window

    def FinishWindow(self, window: NativeImageObservationWindow, *, finalizing: bool) -> None:
        """Consume exactly one issued window and reject excess elapsed time.

        Args:
            window: Exact currently active issued allowance.
            finalizing: Match the kind selected when issuing this window.
        """

        if window is not self._active or self._finalizing is not finalizing:
            raise NativeImageObservationError("native material window is not the active object")

        now = monotonic()
        elapsed = now - window.started_at
        self._active = None
        self._spent += max(0.0, elapsed)

        if finalizing:
            self._finalization += max(0.0, elapsed)

        if elapsed < 0 or now > window.deadline:
            self._failed = True

            raise NativeImageObservationError("native material phase exceeded its allowance")


@dataclass(frozen=True, slots=True)
class NativeImageMaterialProof:
    """Immutable observation facts; only its exact issuer accepts this original object."""

    facts: tuple[NativeFileFact, ...]
    metadata_json: bytes
    observation_id: str
    operation_reference: str
    workspace_id: str
    owner_reference: str
    selection_sha256: str
    control_sha256: str
    request_identity: tuple[int, ...]
    operation_directory_identity: tuple[int, ...]
    workspace_identity: tuple[int, ...]
    finished_at: float

    def Metadata(self) -> dict[str, object] | None:
        """Detach strict metadata without reopening selected file content.

        Returns:
            Fresh parsed metadata, or None for observed absence; mutation cannot change proof.
        """

        if self.metadata_json == b"null":
            return None

        return StrictMetadata(self.metadata_json)

    def Digest(self) -> str:
        """Correlate immutable observed facts without granting read or scan authority.

        Returns:
            SHA256 of the finite canonical issued proof fields.
        """

        value = {"facts": self.facts, "metadata": self.Metadata(),
            "observation_id": self.observation_id, "operation_reference": self.operation_reference,
            "workspace_id": self.workspace_id, "owner_reference": self.owner_reference,
            "selection_sha256": self.selection_sha256, "control_sha256": self.control_sha256,
            "request_identity": self.request_identity,
            "operation_directory_identity": self.operation_directory_identity,
            "workspace_identity": self.workspace_identity, "finished_at": self.finished_at}

        return hashlib.sha256(CanonicalControl(value)).hexdigest()


class NativeImageMaterialObserver:
    """Own fixed installed read workers and strongly retain exact issued proofs."""

    def __init__(self, selection: NativeTrivySelection, workspace_id: str,
                 owner_reference: str) -> None:
        """Bind explicit read consent and pair owner without selected content reads.

        Args:
            selection: Original typed four-file native selection and read consent.
            workspace_id: Explicit owning product workspace reference.
            owner_reference: Actor matching that selected read consent.
        """

        if not isinstance(selection, NativeTrivySelection) or (
            selection.read_consent.actor_ref != owner_reference
        ):
            raise NativeImageObservationError("native material requires selected-owner consent")

        self.selection = selection
        self.workspace_id = RequireText(workspace_id)
        self.owner_reference = RequireText(owner_reference)
        self._selection_fields = {"workspace_root": str(selection.workspace_root),
            "executable": str(selection.executable), "archive": selection.archive,
            "cache_directory": selection.cache_directory}
        self._selection_sha256 = hashlib.sha256(CanonicalControl({
            "selection": self._selection_fields, "read_consent": selection.read_consent,
            "workspace_id": workspace_id, "owner_reference": owner_reference})).hexdigest()
        self._proofs: dict[str, NativeImageMaterialProof] = {}
        self._busy = False

    def CheckCurrent(self, proof: NativeImageMaterialProof, *, operation_reference: str) -> None:
        """Check exact issuance and cheap no-follow identities, never selected contents.

        Args:
            proof: Exact original strongly retained proof from this observer.
            operation_reference: Same whole VERSION/SCAN owner-pair correlation.

        Raises:
            NativeImageObservationError: Issuer, association or current physical metadata differs.
        """

        if not isinstance(proof, NativeImageMaterialProof) or (
            self._proofs.get(proof.observation_id) is not proof or
            proof.operation_reference != operation_reference or
            proof.selection_sha256 != self.CurrentSelectionDigest() or
            proof.workspace_id != self.workspace_id or
            proof.owner_reference != self.owner_reference or
            self.selection.read_consent.actor_ref != self.owner_reference
        ):
            raise NativeImageObservationError("native material requires its exact issued proof")

        try:
            paths = self.Paths()
            root = ArtifactPathInfo(self.selection.workspace_root, directory=True)

            if (root.st_dev, root.st_ino) != proof.workspace_identity:
                raise NativeImageObservationError("native material workspace identity changed")

            for fact, path in zip(proof.facts, paths, strict=True):
                if fact.physical_identity is None:
                    try:
                        path.lstat()

                    except FileNotFoundError:
                        continue

                    raise NativeImageObservationError("native material missing selection appeared")

                if fact.path != str(path) or PhysicalIdentity(ArtifactPathInfo(path)) != (
                    fact.physical_identity
                ):
                    raise NativeImageObservationError("native material physical identity changed")

        except (OSError, ValueError) as error:
            raise NativeImageObservationError("native material identity is unverified") from error

    async def Observe(self, budget: NativeImageObservationBudget, *, operation_reference: str,
                      cancellation: asyncio.Event | None = None) -> NativeImageMaterialProof:
        """Observe the fixed selections through an installed owned finite worker.

        Args:
            budget: Owning cumulative ledger, never reset between VERSION/SCAN operations.
            operation_reference: Whole VERSION/SCAN owner-pair correlation, not authority.
            cancellation: Cooperative cancellation checked before any worker startup.

        Returns:
            Exact instance-issued proof only after successful bounded wire and cleanup.

        Raises:
            NativeImageObservationError: Permission, deadline, control or cleanup is unverified.
            asyncio.CancelledError: Outer cancellation after owned cooperative cleanup.
        """

        RequireText(operation_reference)

        if self._busy or not isinstance(budget, NativeImageObservationBudget) or (
            cancellation is not None and cancellation.is_set()
        ):
            raise NativeImageObservationError("native material is busy, cancelled or unbudgeted")

        if self.selection.read_consent.actor_ref != self.owner_reference or (
            self.CurrentSelectionDigest() != self._selection_sha256
        ):
            raise NativeImageObservationError("native material read consent changed")

        try:
            RequireLinuxOwnership()

        except LocalExecutionError as error:
            raise NativeImageObservationError("native material ownership is unsupported") from error

        window = budget.BeginObservation()
        self._busy = True
        successful = False

        try:
            proof = await self.ObserveOwned(window, operation_reference, cancellation)
            successful = True

        except (OSError, ValueError, LocalExecutionError) as error:
            raise NativeImageObservationError("native material is unverified") from error

        finally:
            self._busy = False
            budget.FinishObservation(window, successful=successful)

        self._proofs[proof.observation_id] = proof

        return proof

    def CurrentSelectionDigest(self) -> str:
        """Bind all current in-memory selection/consent fields without file reads.

        Returns:
            Canonical SHA256 of exact current typed owner/read selection fields.
        """

        selection = self.selection

        return hashlib.sha256(CanonicalControl({"selection": {
            "workspace_root": str(selection.workspace_root),
            "executable": str(selection.executable), "archive": selection.archive,
            "cache_directory": selection.cache_directory}, "read_consent": selection.read_consent,
            "workspace_id": self.workspace_id,
            "owner_reference": self.owner_reference})).hexdigest()

    def Paths(self) -> tuple[Path, ...]:
        """Resolve only fixed paths and current directory metadata without reading content.

        Returns:
            Four exact selected paths in the original native fact role order.
        """

        selection = self.selection
        ArtifactPathInfo(selection.workspace_root, directory=True)
        archive = WorkspacePath(selection.workspace_root, selection.archive)
        cache = WorkspacePath(selection.workspace_root, selection.cache_directory, directory=True)
        database = cache / "db"

        if database.exists() or database.is_symlink():
            ArtifactPathInfo(database, directory=True)

        return archive, selection.executable, database / "trivy.db", database / "metadata.json"

    async def ObserveOwned(self, window: NativeImageObservationWindow, pair: str,
                       cancellation: asyncio.Event | None) -> NativeImageMaterialProof:
        """Own one private request directory until an actual verified terminal result.

        Args:
            window: The active observer-owned finite allowance.
            pair: Exact whole VERSION/SCAN pair correlation.
            cancellation: Optional cooperative caller signal.

        Returns:
            Validated candidate proof, still unusable until its issuer registers it.
        """

        paths = self.Paths()
        directory = Path(tempfile.mkdtemp(
            prefix="native-material-", dir=self.selection.workspace_root))
        os.chmod(directory, 0o700)
        info = ArtifactPathInfo(directory, directory=True)
        directory_identity = info.st_dev, info.st_ino
        root = ArtifactPathInfo(self.selection.workspace_root, directory=True)
        workspace_identity = root.st_dev, root.st_ino
        nonce = uuid.uuid4().hex
        fields: dict[str, object] = {"schema_version": 1, "nonce": nonce,
            "operation_reference": pair, "workspace_id": self.workspace_id,
            "owner_reference": self.owner_reference, "read_consent": {
                "actor_ref": self.selection.read_consent.actor_ref,
                "record_ref": self.selection.read_consent.record_ref},
            "selection": self._selection_fields, "directory_identity": directory_identity,
            "workspace_identity": workspace_identity,
            "roles": ROLE_BOUNDS}
        raw = CanonicalControl(fields)
        request_path = directory / "request.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)

        with os.fdopen(os.open(request_path, flags, 0o600), "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

        request_identity = PhysicalIdentity(ArtifactPathInfo(request_path))
        digest = hashlib.sha256(raw).hexdigest()
        invocation_request = AdapterRequest("image.material-observation", "material:" + nonce,
            ImpactLevel.SAFE, {"profile": "native-image-four-files-v1"})
        invocation = AdapterInvocation("native.material-observer", invocation_request,
            (sys.executable, "-I", "-m", "fuzzy1337.native_image_material_worker",
             str(request_path), digest, ",".join(str(item) for item in request_identity)), 6)
        authority = ExecutionAuthorization("read:" + nonce,
            self.selection.read_consent.record_ref, "read-consent:" + self.owner_reference,
            InvocationDigest(invocation))
        environment = {name: str(directory) for name in (
            "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMPDIR", "TEMP", "TMP")}
        environment.update({"PATH": "", "PATHEXT": "", "LANG": "C", "LC_ALL": "C"})
        request = LocalExecutionRequest(invocation,
            CapabilityDescriptor("image.material-observation", "native.material-observer",
                                 ImpactLevel.SAFE), authority,
            workspace=directory.relative_to(self.selection.workspace_root).as_posix(),
            environment=environment,
            resources=ExecutionResources(CONTROL_MAX_BYTES, 4096, 3.0))
        stop = asyncio.Event()

        def Check(actual: LocalExecutionRequest) -> None:
            """Recheck only bounded control/consent/time at both actual launch boundaries."""

            if actual != request or stop.is_set() or (
                cancellation is not None and cancellation.is_set()
            ) or self.CurrentSelectionDigest() != self._selection_sha256:
                raise NativeImageObservationError("native material launch is cancelled or changed")

            window.WorkerSeconds()
            ReadControl(request_path, digest, request_identity)

        event_count = 0
        event_bytes = 0

        def Event(event: ExecutionEvent) -> None:
            """Bound private original event/control overhead while it is acquired."""

            nonlocal event_count, event_bytes
            event_count += 1
            event_bytes += len(event.data) * 2 + 256

            if event_count > 1024 or event_bytes > 256 * 1024:
                raise NativeImageObservationError("native material events exceed their bound")

        async def Deadline() -> None:
            """Stop at the working end while preserving the inclusive cleanup reserve."""

            await asyncio.sleep(max(0.0, window.working_deadline - monotonic()))
            stop.set()

        async def Cancel() -> None:
            """Bridge a caller event without transferring ownership of executor tasks."""

            assert cancellation is not None, "Only an explicit caller event has a bridge."

            await cancellation.wait()
            stop.set()

        timer = asyncio.create_task(Deadline())
        bridge = asyncio.create_task(Cancel()) if cancellation is not None else None
        execution = asyncio.create_task(LocalExecutor(self.selection.workspace_root).Execute(
            request, cancellation=stop, pre_launch=Check, on_event=Event, own_descendants=True))
        cancelled = False

        try:
            # Unknown executor cleanup must retain its potentially live private request.
            while True:
                try:
                    outcome = await asyncio.shield(execution)

                    break

                except asyncio.CancelledError:
                    cancelled = True
                    stop.set()

                    if execution.cancelled():
                        raise

        finally:
            timer.cancel()

            if bridge is not None:
                bridge.cancel()

            await asyncio.gather(timer, *(() if bridge is None else (bridge,)),
                                 return_exceptions=True)

        try:
            if cancelled:
                raise asyncio.CancelledError

            if cancellation is not None and cancellation.is_set() or stop.is_set() or (
                outcome.execution.state is not ExecutionState.SUCCEEDED or
                outcome.execution.exit_code != 0 or
                outcome.termination is not ExecutionTermination.PROCESS_EXIT or outcome.stderr
            ):
                raise NativeImageObservationError("native material worker did not succeed")

            value = ParseControl(outcome.stdout)
            proof = self.ParseProof(value, fields, digest, request_identity,
                directory_identity, workspace_identity, paths)
            ReadControl(request_path, digest, request_identity)

        finally:
            current = ArtifactPathInfo(directory, directory=True)

            if (current.st_dev, current.st_ino) != directory_identity:
                raise NativeImageObservationError("native material private directory changed")

            request_path.unlink()
            directory.rmdir()

        return proof

    def ParseProof(self, value: dict[str, object], fields: dict[str, object], digest: str,
               request_identity: tuple[int, ...], directory_identity: tuple[int, ...],
               workspace_identity: tuple[int, ...], paths: tuple[Path, ...]
               ) -> NativeImageMaterialProof:
        """Validate exact private wire facts before creating an unissued opaque proof.

        Args:
            value: Actual bounded private worker response.
            fields: Original selected private request fields.
            digest: Exact request SHA256.
            request_identity: Original private request physical identity.
            directory_identity: Original private observation directory identity.
            workspace_identity: Original workspace parent identity.
            paths: Four fixed current selected paths.

        Returns:
            Complete immutable candidate; only Observe can register its exact issuance.
        """

        expected = {key: item for key, item in fields.items() if key not in {"roles"}}
        expected.update({"request_sha256": digest, "request_identity": list(request_identity)})

        if type(value.get("schema_version")) is not int or (
            set(value) != set(expected) | {"facts", "metadata"}
        ) or any(
            value[key] != ParseControl(CanonicalControl({"value": item}))["value"]
            for key, item in expected.items()
        ):
            raise NativeImageObservationError("native material result association differs")

        ControlIdentity(value["request_identity"])
        ControlIdentity(value["directory_identity"], 2)
        ControlIdentity(value["workspace_identity"], 2)
        raw_facts = value["facts"]

        if not isinstance(raw_facts, list) or len(raw_facts) != 4:
            raise NativeImageObservationError("native material result requires exactly four facts")

        facts: list[NativeFileFact] = []

        for raw_fact, path, (role, maximum) in zip(raw_facts, paths, ROLE_BOUNDS, strict=True):
            if not isinstance(raw_fact, dict) or set(raw_fact) != {
                "role", "path", "size_bytes", "sha256", "physical_identity"
            } or raw_fact["role"] != role or raw_fact["path"] != str(path):
                raise NativeImageObservationError("native material result roles or paths differ")

            size = raw_fact["size_bytes"]
            sha256 = raw_fact["sha256"]

            if role in {"database", "database-metadata"} and all(
                raw_fact[key] is None for key in ("size_bytes", "sha256", "physical_identity")
            ):
                try:
                    path.lstat()

                except FileNotFoundError:
                    facts.append(NativeFileFact(role, str(path), None, None, None))

                    continue

                raise NativeImageObservationError("native material absence no longer matches")

            identity = ControlIdentity(raw_fact["physical_identity"])

            if type(size) is not int or not 0 <= size <= maximum or (
                not isinstance(sha256, str) or len(sha256) != 64 or
                any(character not in "0123456789abcdef" for character in sha256) or
                identity[2] != size or PhysicalIdentity(ArtifactPathInfo(path)) != identity
            ):
                raise NativeImageObservationError("native material facts are incomplete or changed")

            facts.append(NativeFileFact(role, str(path), size, sha256, identity))

        metadata = value["metadata"]

        if facts[-1].physical_identity is None:
            if metadata is not None:
                raise NativeImageObservationError("absent metadata cannot supply parsed content")

            metadata_json = b"null"

        else:
            metadata_json = CanonicalControl(StrictMetadata(CanonicalControl(metadata)))

        return NativeImageMaterialProof(tuple(facts), metadata_json,
            cast(str, value["nonce"]), cast(str, value["operation_reference"]),
            self.workspace_id, self.owner_reference, self._selection_sha256, digest,
            request_identity, directory_identity, workspace_identity, monotonic())
