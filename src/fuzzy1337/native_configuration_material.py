# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Own fixed configuration read helpers and exact instance-issued, nonauthority material proof."""

from __future__ import annotations

import asyncio
import hashlib
import os
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import TypeVar

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ExecutionState, ImpactLevel
from fuzzy1337.artifact_inputs import ArtifactPathInfo, ArtifactStage, PhysicalIdentity
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
from fuzzy1337.native_configuration import ConfigurationPath, NativeConfigurationSelection
from fuzzy1337.native_configuration_material_worker import (
    CONTROL_BYTES,
    CanonicalControl,
    CheckStageMetadata,
    ExactChildren,
    Identity,
    ParseControl,
    ReadControl,
    RequirePlatform,
    SelectionPayload,
    StageFromPayload,
    StagePayload,
    Text,
)
from fuzzy1337.native_image_observation import (
    NativeImageObservationBudget,
    NativeImageObservationWindow,
)

_RESULT = TypeVar("_RESULT")


class NativeConfigurationMaterialError(ValueError):
    """Refuse unissued material, changed association or unconfirmed owned cleanup."""


@dataclass(frozen=True, slots=True)
class NativeConfigurationMaterialProof:
    """Descriptive immutable facts; only the issuing observer accepts this exact original object."""

    stage: ArtifactStage
    observation_id: str
    operation_reference: str
    workspace_id: str
    owner_reference: str
    selection_sha256: str
    control_sha256: str
    request_identity: tuple[int, ...]
    directory_identity: tuple[int, ...]
    workspace_identity: tuple[int, ...]
    scratch_identity: tuple[int, ...]
    finished_at: float


async def Settle(task: asyncio.Future[_RESULT], stop: asyncio.Event) -> tuple[_RESULT, bool]:
    """Retain ownership across repeated cancellation until the original task settles."""

    cancelled = False

    while True:
        try:
            result = await asyncio.shield(task)

            return result, cancelled

        except asyncio.CancelledError:
            cancelled = True
            stop.set()

            if task.cancelled():
                raise


class NativeConfigurationMaterialObserver:
    """Own one generated stage, fixed installed create/verify helpers and their private control."""

    def __init__(self, selection: NativeConfigurationSelection, workspace_root: Path,
                 workspace_id: str, owner_reference: str) -> None:
        """Bind syntax-only selected read consent and owner without touching selected paths."""

        if type(selection) is not NativeConfigurationSelection or (
            selection.read_consent.actor_ref != owner_reference
        ):
            raise NativeConfigurationMaterialError("configuration material requires owner consent")

        ConfigurationPath(workspace_root)
        self.selection = selection
        self.workspace_root = workspace_root
        self.workspace_id = Text(workspace_id)
        self.owner_reference = Text(owner_reference)
        self._selection_sha256 = self.SelectionDigest()
        self._proofs: dict[str, NativeConfigurationMaterialProof] = {}
        self._stage: ArtifactStage | None = None
        self._stage_root: Path | None = None
        self._scratch_identity: tuple[int, ...] | None = None
        self._private: dict[Path, tuple[str, tuple[int, ...]]] = {}
        self._busy = False
        self._terminal = True
        self._closed = False

    def SelectionDigest(self) -> str:
        """Bind exact current selection, read consent and owning context without file reads."""

        return hashlib.sha256(CanonicalControl({"selection": SelectionPayload(self.selection),
            "workspace_root": str(self.workspace_root), "workspace_id": self.workspace_id,
            "owner_reference": self.owner_reference})).hexdigest()

    def CheckCurrent(self, proof: NativeConfigurationMaterialProof, *,
                     operation_reference: str) -> None:
        """Check exact issuer/object/stage and finite physical metadata without content reads."""

        if self._closed or not self._terminal or type(proof) is not (
            NativeConfigurationMaterialProof
        ) or (
            self._proofs.get(proof.observation_id) is not proof or proof.stage is not self._stage
            or proof.operation_reference != operation_reference
            or proof.workspace_id != self.workspace_id
            or proof.owner_reference != self.owner_reference
            or proof.selection_sha256 != self._selection_sha256
            or proof.scratch_identity != self._scratch_identity
            or self.SelectionDigest() != self._selection_sha256
        ):
            raise NativeConfigurationMaterialError("configuration material proof is not original")

        RequirePlatform()
        workspace = ArtifactPathInfo(self.workspace_root, directory=True)

        if (workspace.st_dev, workspace.st_ino) != proof.workspace_identity:
            raise NativeConfigurationMaterialError("configuration material workspace changed")

        CheckStageMetadata(proof.stage, self.selection)
        scratch = ArtifactPathInfo(proof.stage.root / "scratch", directory=True)

        if (scratch.st_dev, scratch.st_ino) != proof.scratch_identity:
            raise NativeConfigurationMaterialError("configuration scratch identity changed")

    async def Create(self, budget: NativeImageObservationBudget, *, operation_reference: str,
                     cancellation: asyncio.Event | None = None) -> NativeConfigurationMaterialProof:
        """Capture one stage through the installed helper using the existing caller ledger."""

        return await self.Observe(budget, operation_reference, None, cancellation)

    async def Verify(self, proof: NativeConfigurationMaterialProof,
                     budget: NativeImageObservationBudget, *, operation_reference: str,
                     cancellation: asyncio.Event | None = None) -> NativeConfigurationMaterialProof:
        """Reobserve only the exact issued stage; no original source is opened after capture."""

        if type(proof) is not NativeConfigurationMaterialProof:
            raise NativeConfigurationMaterialError("configuration verification requires proof")

        return await self.Observe(budget, operation_reference, proof, cancellation)

    async def Observe(self, budget: NativeImageObservationBudget, operation_reference: str,
                      prior: NativeConfigurationMaterialProof | None,
                      cancellation: asyncio.Event | None) -> NativeConfigurationMaterialProof:
        """Issue proof within one observation slot only after terminal private cleanup."""

        Text(operation_reference)

        if self._closed or self._busy or not self._terminal or (
            type(budget) is not NativeImageObservationBudget
            or cancellation is not None and cancellation.is_set()
            or self.SelectionDigest() != self._selection_sha256
            or prior is None and self._stage_root is not None
        ):
            raise NativeConfigurationMaterialError("configuration material is unavailable")

        RequirePlatform()
        window = budget.BeginObservation()
        self._busy = True
        successful = False

        try:
            if prior is not None:
                self.CheckCurrent(prior, operation_reference=operation_reference)
                self._proofs.clear()

            else:
                self._stage_root = self.workspace_root / (
                    "native-configuration-stage-" + uuid.uuid4().hex)

            proof = await self.ObserveOwned(window, operation_reference, prior, cancellation)
            successful = True

        except (OSError, ValueError, LocalExecutionError) as error:
            raise NativeConfigurationMaterialError(
                "configuration material is unverified") from error

        finally:
            self._busy = False
            budget.FinishObservation(window, successful=successful)

        self._stage = proof.stage
        self._proofs[proof.observation_id] = proof

        return proof

    async def ObserveOwned(self, window: NativeImageObservationWindow, operation_reference: str,
                           prior: NativeConfigurationMaterialProof | None,
                           cancellation: asyncio.Event | None) -> NativeConfigurationMaterialProof:
        """Own exact control and tasks; retain state on unknown child cleanup."""

        workspace = ArtifactPathInfo(self.workspace_root, directory=True)
        workspace_identity = workspace.st_dev, workspace.st_ino
        nonce = uuid.uuid4().hex
        directory = self.workspace_root / ("native-configuration-read-" + nonce)
        directory.mkdir(mode=0o700)
        info = ArtifactPathInfo(directory, directory=True)
        fields = {"schema_version": 1, "action": "create" if prior is None else "verify",
            "nonce": nonce, "operation_reference": operation_reference,
            "workspace_id": self.workspace_id, "owner_reference": self.owner_reference,
            "workspace_root": str(self.workspace_root), "workspace_identity": workspace_identity,
            "directory_identity": (info.st_dev, info.st_ino),
            "selection": SelectionPayload(self.selection), "stage_root": str(self._stage_root),
            "stage": None}

        if prior is not None:
            fields["stage"] = StagePayload(prior.stage, scratch_identity=prior.scratch_identity)

        raw = CanonicalControl(fields)
        path = directory / "request.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)

        with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

        identity = PhysicalIdentity(ArtifactPathInfo(path))
        digest = hashlib.sha256(raw).hexdigest()
        self._private[path] = digest, identity
        request = self.Request(directory, path, digest, identity, nonce)
        stop = asyncio.Event()
        event_count = 0
        event_bytes = 0

        def Check(actual: LocalExecutionRequest) -> None:
            """Recheck control, selection and live allowance at both real launch boundaries."""

            if actual is not request or stop.is_set() or (
                cancellation is not None and cancellation.is_set()
                or self.SelectionDigest() != self._selection_sha256
            ):
                raise NativeConfigurationMaterialError("configuration material launch changed")

            window.WorkerSeconds()
            ReadControl(path, digest, identity)

        def Event(event: ExecutionEvent) -> None:
            """Bound acquired event count and envelope without retaining another event history."""

            nonlocal event_count, event_bytes
            event_count += 1
            event_bytes += len(event.data) * 2 + 256

            if event_count > 1024 or event_bytes > 256 * 1024:
                raise NativeConfigurationMaterialError("configuration material event overflow")

        async def Deadline() -> None:
            """Stop worker time at the shared window's working end, preserving cleanup reserve."""

            await asyncio.sleep(max(0.0, window.working_deadline - monotonic()))
            stop.set()

        async def Cancel() -> None:
            """Bridge only the explicit cooperative caller signal to the owned executor."""

            assert cancellation is not None, "A cancellation bridge needs an explicit signal"

            await cancellation.wait()
            stop.set()

        executor = LocalExecutor(self.workspace_root)
        timer = asyncio.create_task(Deadline())
        bridge = asyncio.create_task(Cancel()) if cancellation is not None else None
        self._terminal = False
        execution = asyncio.create_task(executor.Execute(request,
            cancellation=stop, pre_launch=Check, on_event=Event, own_descendants=True))
        cancelled = False

        try:
            outcome, cancelled = await Settle(execution, stop)
            self._terminal = True

        finally:
            timer.cancel()

            if bridge is not None:
                bridge.cancel()

            _, interrupted = await Settle(asyncio.gather(timer,
                *(() if bridge is None else (bridge,)), return_exceptions=True), stop)
            cancelled = cancelled or interrupted

        try:
            if cancelled:
                raise asyncio.CancelledError

            if stop.is_set() or cancellation is not None and cancellation.is_set() or (
                outcome.execution.state is not ExecutionState.SUCCEEDED
                or outcome.execution.exit_code != 0
                or outcome.termination is not ExecutionTermination.PROCESS_EXIT or outcome.stderr
            ):
                raise NativeConfigurationMaterialError("configuration material worker refused")

            value = ParseControl(outcome.stdout)

            if set(value) != {"schema_version", "control", "request_sha256", "request_identity",
                              "stage"} or type(value["schema_version"]) is not int or (
                value["schema_version"] != 1 or value["request_sha256"] != digest
                or CanonicalControl(value["request_identity"]) != CanonicalControl(identity)
                or CanonicalControl(value["control"]) != raw
            ):
                raise NativeConfigurationMaterialError("configuration material response differs")

            assert self._stage_root is not None, "Only an owned generated stage can be observed"
            stage = StageFromPayload(value["stage"], self.selection, self._stage_root)
            scratch_identity = Identity(value["stage"]["scratch_identity"], 2)

            if prior is not None and (
                stage != prior.stage or scratch_identity != prior.scratch_identity
            ):
                raise NativeConfigurationMaterialError("configuration material stage changed")

            CheckStageMetadata(stage, self.selection)
            self._stage = stage if prior is None else prior.stage
            self._scratch_identity = scratch_identity if prior is None else prior.scratch_identity
            ReadControl(path, digest, identity)

        finally:
            self.CleanPrivate(path)

        assert self._stage is not None and self._scratch_identity is not None, (
            "Validated configuration response must retain stage and scratch facts")

        return NativeConfigurationMaterialProof(self._stage, nonce, operation_reference,
            self.workspace_id, self.owner_reference, self._selection_sha256, digest,
            identity, (info.st_dev, info.st_ino), workspace_identity,
            self._scratch_identity, monotonic())

    def Request(self, directory: Path, path: Path, digest: str, identity: tuple[int, ...],
                nonce: str) -> LocalExecutionRequest:
        """Build the fixed isolated read worker with bounded streams and empty host paths."""

        invocation = AdapterInvocation("native.configuration-material", AdapterRequest(
            "config.material-observation", "material:" + nonce, ImpactLevel.SAFE,
            {"profile": "native-configuration-read-v1"}),
            (sys.executable, "-I", "-m", "fuzzy1337.native_configuration_material_worker",
             str(path), digest, ",".join(str(item) for item in identity)), 6)
        authority = ExecutionAuthorization("read:" + nonce, self.selection.read_consent.record_ref,
            "read-consent:" + self.owner_reference, InvocationDigest(invocation))
        environment = {name: str(directory) for name in (
            "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMPDIR", "TEMP", "TMP")}
        environment.update({name: "" for name in (
            "PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR")})
        environment.update({"LANG": "C", "LC_ALL": "C"})

        return LocalExecutionRequest(invocation, CapabilityDescriptor("config.material-observation",
            "native.configuration-material", ImpactLevel.SAFE), authority,
            workspace=directory.relative_to(self.workspace_root).as_posix(),
            environment=environment, resources=ExecutionResources(CONTROL_BYTES, 4096, 3.0))

    def CleanPrivate(self, path: Path) -> None:
        """Unlink exact unchanged control only after confirmed terminal ownership."""

        if not self._terminal:
            raise NativeConfigurationMaterialError("configuration child cleanup is unknown")

        digest, identity = self._private[path]
        ReadControl(path, digest, identity)
        ExactChildren(path.parent, {"request.json"})
        path.unlink()
        path.parent.rmdir()
        del self._private[path]

    def Close(self) -> None:
        """Revoke proof and unlink only exact known stage children after terminal owned cleanup."""

        if self._busy or not self._terminal:
            raise NativeConfigurationMaterialError("configuration material helper is not terminal")

        self._proofs.clear()

        if self._closed:
            return

        for path in tuple(self._private):
            self.CleanPrivate(path)

        if self._stage is not None:
            stage = self._stage
            root = ArtifactPathInfo(stage.root, directory=True)

            if (root.st_dev, root.st_ino) != stage.root_identity:
                raise NativeConfigurationMaterialError("configuration material stage root changed")

            ExactChildren(stage.root, {"input", "scanner", "material", "scratch"})

            for snapshot in (stage.input, stage.scanner, stage.material):
                info = ArtifactPathInfo(snapshot.directory, directory=True)

                if (info.st_dev, info.st_ino) != snapshot.directory_identity:
                    raise NativeConfigurationMaterialError("configuration partition changed")

                ExactChildren(snapshot.directory, {name for name, _ in snapshot.identities})

                for name, identity in snapshot.identities:
                    if PhysicalIdentity(ArtifactPathInfo(snapshot.directory / name)) != identity:
                        raise NativeConfigurationMaterialError("configuration staged file changed")

            scratch = ArtifactPathInfo(stage.root / "scratch", directory=True)

            if (scratch.st_dev, scratch.st_ino) != self._scratch_identity:
                raise NativeConfigurationMaterialError("configuration scratch identity changed")

            ExactChildren(stage.root / "scratch", set())

            for snapshot in (stage.input, stage.scanner, stage.material):
                for name, identity in snapshot.identities:
                    path = snapshot.directory / name

                    if PhysicalIdentity(ArtifactPathInfo(path)) != identity:
                        raise NativeConfigurationMaterialError("configuration staged file changed")

                    path.unlink()

                snapshot.directory.rmdir()

            (stage.root / "scratch").rmdir()
            stage.root.rmdir()

        elif self._stage_root is not None:
            try:
                self._stage_root.lstat()

            except FileNotFoundError:
                pass

            else:
                raise NativeConfigurationMaterialError("configuration partial stage is retained")

        self._closed = True
