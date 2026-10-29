# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Configuration material mechanics with tiny deterministic files, not native product proof."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from fuzzy1337 import artifact_inputs
from fuzzy1337 import native_configuration_material as material
from fuzzy1337 import native_configuration_material_worker as worker
from fuzzy1337 import native_image_observation as budget_module
from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.artifact_inputs import (
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactRole,
    ArtifactSnapshot,
    ArtifactStage,
    PhysicalIdentity,
)
from fuzzy1337.executors import (
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    LocalExecutionError,
    LocalExecutionResult,
    LocalExecutor,
)
from fuzzy1337.native_configuration import NativeConfigurationSelection
from fuzzy1337.native_image_observation import NativeImageObservationBudget


@pytest.fixture
def owned_material(tmp_path, monkeypatch):
    """Use a tiny explicit pin double for worker mechanics, never native admission."""

    source = tmp_path / "source"
    source.write_bytes(b"FROM scratch\nUSER 12345\n# independent ordinary source\n")
    executable = tmp_path / "selected-tool"
    executable.write_bytes(b"inert test bytes; this file must never execute\n")
    monkeypatch.setattr(worker, "NATIVE_CONFIGURATION_EXECUTABLE_SHA256",
                        hashlib.sha256(executable.read_bytes()).hexdigest())

    return NativeConfigurationSelection(ArtifactProfile.DOCKERFILE, "Dockerfile", source,
        executable, ArtifactReadConsent("owner:mechanics", "read:tiny-files"))


def StageRoot(tmp_path):
    """Return an absent fixed-shape test stage beneath the explicit owned workspace."""

    return tmp_path / ("native-configuration-stage-" + "a" * 32)


def Control(tmp_path, selection, action="create", stage=None):
    """Create exact private metadata without issuing observer material proof."""

    directory = tmp_path / ("native-configuration-read-" + "b" * 32)
    directory.mkdir(mode=0o700)
    directory_identity = directory.stat()
    workspace_identity = tmp_path.stat()

    return directory, {"schema_version": 1, "action": action, "nonce": "c" * 32,
        "operation_reference": "operation:material", "workspace_id": "workspace:material",
        "owner_reference": selection.read_consent.actor_ref, "workspace_root": str(tmp_path),
        "workspace_identity": [workspace_identity.st_dev, workspace_identity.st_ino],
        "directory_identity": [directory_identity.st_dev, directory_identity.st_ino],
        "selection": worker.SelectionPayload(selection), "stage_root": str(StageRoot(tmp_path)),
        "stage": stage}


def test_SnapshotCompositionPassesActualRoleAdmissionLimits(tmp_path, owned_material, monkeypatch):
    """The limits reach streaming Capture rather than depending on a prior metadata check."""

    captures = []
    original_capture = ArtifactSnapshot.Capture

    def Capture(*args, **kwargs):
        """Observe the real bounded capture API while preserving actual guarded file copying."""

        captures.append((args[2], kwargs.get("max_total_bytes")))

        return original_capture(*args, **kwargs)

    def Forbidden(*args, **kwargs):
        """Reject accidental calls to the globally bounded stage or snapshot verifier."""

        pytest.fail("Configuration material must compose only explicitly bounded primitive reads")

    monkeypatch.setattr(ArtifactSnapshot, "Capture", Capture)
    monkeypatch.setattr(ArtifactStage, "Create", Forbidden)
    monkeypatch.setattr(ArtifactStage, "Verify", Forbidden)
    monkeypatch.setattr(ArtifactSnapshot, "Verify", Forbidden)
    stage = worker.CreateStage(StageRoot(tmp_path), owned_material)
    assert captures == [(ArtifactRole.INPUT, 4096), (ArtifactRole.SCANNER, 256 * 1024**2),
                        (ArtifactRole.MATERIAL, 0)], (
        "Every copied role must receive its actual configuration streaming admission budget"
    )
    assert stage.input.manifest.files[0].sha256 == hashlib.sha256(
        owned_material.source.read_bytes()).hexdigest(), (
        "The manifest must describe the exact chunks copied into the staged source"
    )


def test_VerificationNeverReopensOriginalSource(tmp_path, owned_material, monkeypatch):
    """After snapshot capture only staged source bytes and both executable locations are read."""

    stage = worker.CreateStage(StageRoot(tmp_path), owned_material)
    owned_material.source.unlink()
    reads = []
    original_read = worker.ReadArtifactFile

    def Read(path, name, destination=None, *, max_bytes):
        """Retain each real bounded read and reject any original-source reopen."""

        assert path != owned_material.source, "Captured original source must never be reopened"
        reads.append((path, max_bytes))

        return original_read(path, name, destination, max_bytes=max_bytes)

    monkeypatch.setattr(worker, "ReadArtifactFile", Read)
    worker.VerifyStage(stage, owned_material)
    assert reads == [(stage.input.directory / "Dockerfile", 4096),
        (stage.scanner.directory / "executable", 256 * 1024**2),
        (owned_material.executable, 256 * 1024**2)], (
        "Verification must preserve explicit source/scanner admission limits at every read"
    )


def test_SourceUtf8ComesFromTheSameVerifiedCappedBytes(tmp_path, owned_material, monkeypatch):
    """Malformed copied UTF-8 refuses without a second source read after hash verification."""

    owned_material.source.write_bytes(b"\xff")

    def Forbidden(*args, **kwargs):
        """Refuse a convenience read that would bypass bounded guarded verifier bytes."""

        pytest.fail("UTF-8 must decode only the exact bounded verifier-returned bytes")

    monkeypatch.setattr(Path, "read_bytes", Forbidden)

    with pytest.raises(UnicodeDecodeError):
        worker.CreateStage(StageRoot(tmp_path), owned_material)


@pytest.mark.parametrize("mutation", ["source", "copy", "executable", "extra", "scratch"])
def test_ChangedOrExpandedMaterialRefuses(tmp_path, owned_material, mutation):
    """Physical replacement, changed selected bytes and unselected files cannot retain proof."""

    stage = worker.CreateStage(StageRoot(tmp_path), owned_material)

    if mutation == "source":
        target = stage.input.directory / "Dockerfile"

    elif mutation == "copy":
        target = stage.scanner.directory / "executable"

    elif mutation == "executable":
        target = owned_material.executable

    else:
        target = stage.root / ("scratch" if mutation == "scratch" else "material") / "unknown"

    if target.exists():
        target.chmod(0o600)

    target.write_bytes(b"different")

    with pytest.raises(ValueError):
        worker.VerifyStage(stage, owned_material)


def test_InitialSourceCapAndSupportedScannerPinAreEnforced(tmp_path, owned_material):
    """Oversized source and a different candidate both refuse before a usable stage exists."""

    owned_material.source.write_bytes(b"x" * 4097)

    with pytest.raises(ValueError):
        worker.CreateStage(StageRoot(tmp_path), owned_material)

    owned_material.source.write_bytes(b"FROM scratch\n")
    owned_material.executable.write_bytes(b"not the admitted candidate")

    with pytest.raises(ValueError):
        worker.CreateStage(tmp_path / ("native-configuration-stage-" + "d" * 32), owned_material)


def test_StageWireRoundtripPreservesExactPhysicalAndManifestFacts(tmp_path, owned_material):
    """Detached stage syntax reconstructs descriptive facts without issuing observer proof."""

    stage = worker.CreateStage(StageRoot(tmp_path), owned_material)
    detached = json.loads(worker.CanonicalControl(worker.StagePayload(stage)))
    restored = worker.StageFromPayload(detached, owned_material, stage.root)
    assert restored == stage, "The private stage roundtrip must retain exact original associations"
    worker.VerifyStage(restored, owned_material)

    with pytest.raises(ValueError):
        worker.StageFromPayload({**detached, "unexpected": True}, owned_material, stage.root)

    detached["partitions"]["input"]["manifest"]["role"] = "scanner"

    with pytest.raises(ValueError):
        worker.StageFromPayload(detached, owned_material, stage.root)


@pytest.mark.parametrize("role", ["input", "scanner", "original"])
def test_VerifierRejectsChangedBytesDespiteRefreshedDescriptiveIdentity(
    tmp_path, owned_material, role,
):
    """Detached physical metadata cannot replace exact captured source or executable hashes."""

    stage = worker.CreateStage(StageRoot(tmp_path), owned_material)

    if role == "original":
        target = owned_material.executable

    else:
        snapshot = getattr(stage, role)
        target = snapshot.directory / snapshot.manifest.files[0].name

    target.chmod(0o600)
    target.write_bytes(b"x" * target.stat().st_size)
    identity = PhysicalIdentity(target.stat())

    if role == "original":
        detached = replace(stage, executable_identity=identity)

    else:
        changed = replace(snapshot, identities=((snapshot.manifest.files[0].name, identity),))
        detached = replace(stage, **{role: changed})

    worker.CheckStageMetadata(detached, owned_material)

    with pytest.raises(ValueError, match="copied bytes"):
        worker.VerifyStage(detached, owned_material)


@pytest.mark.parametrize("field", ["schema", "nonce", "stage", "selection", "consent"])
def test_PrivateSelectionCannotBroadenItsClosedSchemaOrReadOwner(
    tmp_path, owned_material, field,
):
    """Malformed request associations reject before a private child can read selected bytes."""

    _, control = Control(tmp_path, owned_material)

    if field == "schema":
        control["schema_version"] = True

    elif field == "nonce":
        control["nonce"] = "not-an-original-nonce"

    elif field == "stage":
        control["stage"] = {}

    elif field == "selection":
        control["selection"]["extra"] = "caller-extension"

    else:
        control["selection"]["read_consent"]["actor_ref"] = "owner:foreign"

    with pytest.raises(ValueError):
        worker.SelectionFromControl(control)


def test_StageWireRejectsExpandedPartitionFields(tmp_path, owned_material):
    """A detached stage cannot smuggle an extra partition field past fixed wire decoding."""

    stage = worker.CreateStage(StageRoot(tmp_path), owned_material)
    detached = json.loads(worker.CanonicalControl(worker.StagePayload(stage)))
    detached["partitions"]["input"]["extra"] = "caller-extension"

    with pytest.raises(ValueError, match="partition fields"):
        worker.StageFromPayload(detached, owned_material, stage.root)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1} ',
                                 b" " * 65537, b"[]", b"\xff"],
                         ids=["duplicate-key", "nonfinite", "noncanonical", "oversized",
                              "non-object", "invalid-utf8"])
def test_PrivateControlRequiresStrictBoundedCanonicalJson(raw):
    """Duplicate, nonfinite, malformed or noncanonical control cannot describe selected reads."""

    with pytest.raises(ValueError):
        worker.ParseControl(raw)


def test_PrivateRequestBindsOriginalPathDigestIdentityAndParents(
    tmp_path, owned_material, monkeypatch,
):
    """The child reads only the original exclusive owner request beneath its exact workspace."""

    directory, control = Control(tmp_path, owned_material)
    raw = worker.CanonicalControl(control)
    path = directory / "request.json"
    path.write_bytes(raw)
    path.chmod(0o600)
    digest = hashlib.sha256(raw).hexdigest()
    identity = PhysicalIdentity(path.stat())

    if os.name == "nt":
        read = MagicMock(side_effect=AssertionError("Unsupported private modes must refuse reads"))
        monkeypatch.setattr(worker, "ReadArtifactFile", read)

        with pytest.raises(ValueError, match="private ownership differs"):
            worker.ReadControl(path, digest, identity)

        assert not read.called, (
            "Windows private modes must refuse before any control bytes are read")

        return

    assert worker.ReadControl(path, digest, identity) == control, (
        "The exact private request must retain its original hash and physical parent binding"
    )

    with pytest.raises(ValueError):
        worker.ReadControl(path, "0" * 64, identity)

    path.chmod(0o644)

    with pytest.raises(ValueError):
        worker.ReadControl(path, digest, PhysicalIdentity(path.stat()))


@pytest.mark.parametrize("association", ["filename", "digest", "directory", "workspace"])
def test_PrivateRequestRejectsRehashedForeignParentAssociations(
    tmp_path, owned_material, association,
):
    """A new valid content hash cannot rebind control to a different physical owner context."""

    directory, control = Control(tmp_path, owned_material)

    if association in {"directory", "workspace"}:
        control[association + "_identity"][1] += 1

    raw = worker.CanonicalControl(control)
    path = directory / ("foreign.json" if association == "filename" else "request.json")
    path.write_bytes(raw)
    path.chmod(0o600)
    digest = "not-a-sha256" if association == "digest" else hashlib.sha256(raw).hexdigest()

    with pytest.raises(ValueError):
        worker.ReadControl(path, digest, PhysicalIdentity(path.stat()))


@pytest.mark.parametrize("maximum", [4096, 256 * 1024**2])
def test_ActualOverlimitReadChunkIsRefusedBeforeHashOrCopy(tmp_path, monkeypatch, maximum):
    """Growth may read one extra bounded buffer, but no overlimit buffer is hashed or copied."""

    source = tmp_path / "growing"
    source.write_bytes(b"x")
    original_fdopen = os.fdopen
    opened = 0
    requested = []
    chunk = b"x" * (64 * 1024)

    def Read(read_maximum):
        """Supply one bounded overlimit buffer after real descriptor metadata checks."""

        requested.append(read_maximum)

        return chunk

    def Open(*args, **kwargs):
        """Replace only the selected read stream, retaining the independent witness handle."""

        nonlocal opened
        stream = original_fdopen(*args, **kwargs)
        opened += 1

        if opened != 1:
            return stream

        simulated = MagicMock()
        simulated.__enter__.return_value = simulated
        simulated.__exit__.side_effect = lambda *unused: stream.close()
        simulated.fileno.side_effect = stream.fileno
        simulated.read.side_effect = Read

        return simulated

    monkeypatch.setattr(artifact_inputs.os, "fdopen", Open)
    destination = MagicMock()
    digest = MagicMock()
    monkeypatch.setattr(artifact_inputs.hashlib, "sha256", lambda: digest)

    with pytest.raises(ValueError, match="grew beyond"):
        artifact_inputs.ReadArtifactFile(source, "source", destination, max_bytes=maximum)

    admitted_chunks = maximum // len(chunk)
    assert requested == [64 * 1024] * (admitted_chunks + 1), (
        "Growth may read at most one extra fixed 64-KiB buffer before refusing the selected file")
    assert digest.update.call_count == admitted_chunks and (
        destination.write.call_count == admitted_chunks
    ), "The overlimit chunk must never be hashed, copied or admitted to either role budget"


def test_StagePayloadCannotBroadenManifestSizeWithoutPhysicalAgreement(tmp_path, owned_material):
    """A typed descriptive stage cannot bypass the admitted input and scanner bounds."""

    stage = worker.CreateStage(StageRoot(tmp_path), owned_material)
    file = replace(stage.input.manifest.files[0], size_bytes=4097)
    snapshot = replace(stage.input, manifest=replace(stage.input.manifest, files=(file,)))

    with pytest.raises(ValueError):
        worker.CheckStageMetadata(replace(stage, input=snapshot), owned_material)


def InstallPrivatePosixModel(observer, monkeypatch):
    """Model declared private modes and owned snapshot unlink for protocol units only."""

    original_info = worker.ArtifactPathInfo
    original_mkdir, original_chmod, original_unlink = Path.mkdir, Path.chmod, Path.unlink
    original_open = os.open
    model = SimpleNamespace(modes={}, declarations=[], views=[], unlinked=[])

    def Remember(path, mode, *, directory):
        """Retain declared permissions alongside the original guarded physical entry identity."""

        info = original_info(path, directory=directory)
        model.modes[path] = ((info.st_dev, info.st_ino), mode, directory)
        model.declarations.append((path, mode))

    def Mkdir(path, mode=0o777, parents=False, exist_ok=False):
        """Observe only successful generated private directories inside the active workspace."""

        original_mkdir(path, mode=mode, parents=parents, exist_ok=exist_ok)
        prefix = "native-configuration-read-"
        suffix = path.name.removeprefix(prefix)

        if observer._busy and path.parent == observer.workspace_root and (
            path.name.startswith(prefix) and len(suffix) == 32
            and set(suffix) <= set("0123456789abcdef")
        ):
            Remember(path, mode, directory=True)

    def Open(path, flags, mode=0o777, *, dir_fd=None):
        """Delegate actual exclusive creation and record only an owned private request's mode."""

        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        path = Path(path)

        if path.parent in model.modes and path.name == "request.json" and observer._busy:
            Remember(path, mode, directory=False)

        return descriptor

    def Chmod(path, mode, *, follow_symlinks=True):
        """Keep deliberate permission changes visible instead of normalizing them away."""

        entry = model.modes.get(path)
        info = original_info(path, directory=entry[2]) if entry is not None else None
        original_chmod(path, mode, follow_symlinks=follow_symlinks)

        if entry is not None and (info.st_dev, info.st_ino) == entry[0]:
            Remember(path, mode, directory=entry[2])

    def Info(path, *, directory=False):
        """Run physical guards first; change only modes of exact registered private entries."""

        info = original_info(path, directory=directory)
        entry = model.modes.get(path)
        registered = path in observer._private or any(
            path == request.parent for request in observer._private)

        if entry is None or not registered or (info.st_dev, info.st_ino) != entry[0]:
            return info

        fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        fields["st_mode"] = stat.S_IFMT(info.st_mode) | entry[1]
        model.views.append((path, entry[1], PhysicalIdentity(info)))

        return SimpleNamespace(**fields)

    def Unlink(path, missing_ok=False):
        """Model POSIX unlink only after guards reach an original known snapshot file."""

        stage = observer._stage
        known = {} if stage is None else {snapshot.directory / name: identity
            for snapshot in (stage.input, stage.scanner, stage.material)
            for name, identity in snapshot.identities}

        if path in known:
            info = original_info(path)
            assert PhysicalIdentity(info) == known[path] and (
                stage.root == observer._stage_root and observer._terminal and not observer._busy
            ), "Only unchanged terminal observer snapshots may use modeled POSIX unlink"

            if not info.st_mode & stat.S_IWUSR:
                original_chmod(path, stat.S_IMODE(info.st_mode) | stat.S_IWUSR)

            model.unlinked.append(path)

        return original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "mkdir", Mkdir)
    monkeypatch.setattr(Path, "chmod", Chmod)
    monkeypatch.setattr(Path, "unlink", Unlink)
    monkeypatch.setattr(material, "os", SimpleNamespace(**{**vars(os), "open": Open}))
    monkeypatch.setattr(worker, "ArtifactPathInfo", Info)

    return model


@pytest.fixture
def simulated_observer(tmp_path, owned_material, monkeypatch, request):
    """Simulate terminal helpers; optional declared POSIX mechanics are never OS admission proof."""

    monkeypatch.setattr(material, "RequirePlatform", lambda: None)
    monkeypatch.setattr(worker, "RequirePlatform", lambda: None)
    observer = material.NativeConfigurationMaterialObserver(owned_material, tmp_path,
        "workspace:material", "owner:mechanics")
    controls = {"calls": [], "mode": "success", "stdout": None, "after_worker": None,
                "event": None, "started": asyncio.Event(), "released": asyncio.Event()}

    if os.name == "nt" or getattr(request, "param", False):
        controls["posix_model"] = InstallPrivatePosixModel(observer, monkeypatch)

    async def Execute(executor, request, **options):
        """Exercise exact closed wire under an explicitly simulated terminal executor boundary."""

        argv = request.invocation.argv
        assert argv[:4] == (os.sys.executable, "-I", "-m",
            "fuzzy1337.native_configuration_material_worker") and len(argv) == 7, (
            "The observer may launch only the fixed installed isolated read helper")
        assert options["own_descendants"] is True, "Read helpers need actual descendant ownership"
        assert request.invocation.timeout_seconds == 6 and (
            request.resources.max_stdout_bytes == 65536
            and request.resources.max_stderr_bytes == 4096
            and request.resources.terminate_grace_seconds == 3.0
        ), "The fixed worker and output/cleanup budgets must remain explicit"
        assert all(request.environment[name] == "" for name in (
            "PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR")), (
            "Caller executable paths and host shell locations cannot enter the helper environment")
        path = Path(argv[4])
        identity = tuple(int(item) for item in argv[6].split(","))
        control = worker.ReadControl(path, argv[5], identity)
        controls["calls"].append((request, path, control))
        controls["started"].set()
        options["pre_launch"](request)

        if controls.get("before_second") is not None:
            controls["before_second"](path)

        options["pre_launch"](request)

        if controls["event"] is not None:
            options["on_event"](controls["event"])

        if controls["mode"] == "unknown":
            raise LocalExecutionError("simulated unconfirmed terminal cleanup")

        if controls["mode"] in {"cancel", "hold"}:
            await options["cancellation"].wait()

            if controls["mode"] == "hold":
                await controls["released"].wait()

            return LocalExecutionResult(AdapterExecution(ExecutionState.CANCELLED, None, 0.01),
                ExecutionTermination.CANCELLATION, b"", b"", (ExecutionEvent(0,
                    ExecutionEventKind.COMPLETED, termination=ExecutionTermination.CANCELLATION),))

        raw = worker.ObserveControl(control, argv[5], identity)

        if controls["after_worker"] is not None:
            controls["after_worker"](path, control)

        if controls["stdout"] is not None:
            raw = controls["stdout"](raw)

        termination = ExecutionTermination.OUTPUT_LIMIT if controls["mode"] == "overflow" else (
            ExecutionTermination.PROCESS_EXIT)
        events = (ExecutionEvent(0, ExecutionEventKind.STARTED),
            ExecutionEvent(1, ExecutionEventKind.STDOUT, raw),
            ExecutionEvent(2, ExecutionEventKind.COMPLETED,
                termination=termination))

        for event in events:
            options["on_event"](event)

        state = ExecutionState.FAILED if controls["mode"] == "nonzero" else ExecutionState.SUCCEEDED

        return LocalExecutionResult(AdapterExecution(state, 2 if state is ExecutionState.FAILED
            else 0, 0.01), termination, raw, b"refused" if controls["mode"] == "stderr" else b"",
            events)

    monkeypatch.setattr(LocalExecutor, "Execute", Execute)

    return observer, controls


@pytest.mark.parametrize("simulated_observer", [True], indirect=True, ids=["posix-model"])
def test_PortablePrivateModeModelRetainsOriginalReadsAndKnownSnapshotCleanup(simulated_observer):
    """Forced portable mechanics retain real control guards through create, verify and close."""

    observer, controls = simulated_observer
    model = controls["posix_model"]
    budget = NativeImageObservationBudget()
    proof = asyncio.run(observer.Create(budget, operation_reference="operation:material"))
    proof = asyncio.run(observer.Verify(proof, budget, operation_reference="operation:material"))
    known = {snapshot.directory / name for snapshot in (
        proof.stage.input, proof.stage.scanner, proof.stage.material)
        for name, _ in snapshot.identities}
    assert [mode for _, mode in model.declarations] == [0o700, 0o600] * 2, (
        "Private logical modes must come from each actual mkdir and exclusive open declaration")
    assert {mode for _, mode, _ in model.views} == {0o600, 0o700} and (
        material.ReadControl is worker.ReadControl and len(controls["calls"]) == 2
        and budget.ObservationCount == 2 and not budget.Failed
        and not observer._private
    ), "Portable mechanics must keep original guarded request reads and terminal cleanup active"
    observer.Close()
    assert set(model.unlinked) == known and len(model.unlinked) == 2 and (
        not proof.stage.root.exists() and observer.selection.source.exists()
        and observer.selection.executable.exists()
    ), "Modeled unlink may remove only the exact original owned snapshots after their guards"


@pytest.mark.parametrize("simulated_observer", [True], indirect=True, ids=["posix-model"])
@pytest.mark.parametrize(("target", "mode"), [("request", 0o644), ("directory", 0o755)])
def test_PortablePrivateModeModelCannotHideDeclaredPermissionMutation(
    simulated_observer, target, mode,
):
    """Refreshed physical identity cannot hide deliberately broadened private logical modes."""

    observer, controls = simulated_observer
    denied = []

    def Change(path):
        """Broaden exactly one private mode between the actual original launch checks."""

        selected = path if target == "request" else path.parent
        selected.chmod(mode)
        digest, _ = observer._private[path]
        refreshed = PhysicalIdentity(path.stat())
        assert controls["posix_model"].modes[selected][1] == mode, (
            "Mode tracking must retain the deliberate chmod instead of restoring private defaults")

        with pytest.raises(ValueError, match="private ownership differs"):
            worker.ReadControl(path, digest, refreshed)

        denied.append(path)

    controls["before_second"] = Change
    budget = NativeImageObservationBudget()

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Create(budget, operation_reference="operation:material"))

    assert denied and denied[0].exists() and observer._private and not observer._proofs and (
        budget.Failed and budget.ObservationCount == 1 and not observer._terminal
        and not observer._stage_root.exists()
    ), "Changed private modes must refuse launch, retain uncertain control and withhold every proof"


def test_SimulatedOriginalProofBindsStageOwnerAndLedgerAndCloseRevokes(
    tmp_path, owned_material, simulated_observer,
):
    """Simulated terminal cleanup precedes exact issuance; clones and other issuers refuse."""

    observer, controls = simulated_observer
    budget = NativeImageObservationBudget()
    proof = asyncio.run(observer.Create(budget, operation_reference="operation:material"))
    request, path, control = controls["calls"][0]
    assert not path.exists() and not path.parent.exists(), (
        "Proof issuance must follow removal of the exact terminal private request")
    assert proof.observation_id == control["nonce"] and (
        proof.control_sha256 == request.invocation.argv[5]
        and proof.operation_reference == "operation:material"
        and proof.workspace_id == "workspace:material"
        and proof.owner_reference == "owner:mechanics"
    ), "Proof must retain the original nonce, control, operation, workspace and read owner"
    assert budget.ObservationCount == 1 and not budget.Failed, (
        "The existing caller ledger must charge one actual successful observation")
    observer.CheckCurrent(proof, operation_reference="operation:material")

    with pytest.raises(material.NativeConfigurationMaterialError):
        observer.CheckCurrent(replace(proof), operation_reference="operation:material")

    with pytest.raises(material.NativeConfigurationMaterialError):
        observer.CheckCurrent(proof, operation_reference="operation:foreign")

    other = material.NativeConfigurationMaterialObserver(owned_material, tmp_path,
        "workspace:material", "owner:mechanics")

    with pytest.raises(material.NativeConfigurationMaterialError):
        other.CheckCurrent(proof, operation_reference="operation:material")

    owned_material.source.unlink()
    verified = asyncio.run(observer.Verify(proof, budget, operation_reference="operation:material"))
    assert verified.stage is proof.stage and budget.ObservationCount == 2, (
        "Verify must reobserve the same original stage with the same caller budget")
    assert controls["calls"][1][2]["action"] == "verify", "Verification is a fixed distinct action"
    observer.Close()
    observer.Close()
    assert not proof.stage.root.exists() and not owned_material.source.exists(), (
        "Close must remove only known generated material without reopening the original source")

    with pytest.raises(material.NativeConfigurationMaterialError):
        observer.CheckCurrent(verified, operation_reference="operation:material")


def test_SimulatedEmptyScratchReplacementRevokesOriginalProof(simulated_observer):
    """An empty scratch replacement cannot keep the original config-owned partition identity."""

    observer, _ = simulated_observer
    budget = NativeImageObservationBudget()
    proof = asyncio.run(observer.Create(budget, operation_reference="operation:material"))
    scratch = proof.stage.root / "scratch"
    scratch.rename(proof.stage.root.parent / "retained-original-scratch")
    scratch.mkdir()

    with pytest.raises(material.NativeConfigurationMaterialError):
        observer.CheckCurrent(proof, operation_reference="operation:material")

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Verify(proof, budget, operation_reference="operation:material"))

    with pytest.raises(ValueError):
        observer.Close()

    assert scratch.exists(), "A replaced or unknown tree must be retained without recursive cleanup"


@pytest.mark.parametrize("mode", ["nonzero", "stderr", "overflow"])
def test_SimulatedTerminalFailureCannotIssueProof(simulated_observer, mode):
    """Nonzero, diagnostic or output-limit results consume and fail the one observation slot."""

    observer, controls = simulated_observer
    controls["mode"] = mode
    budget = NativeImageObservationBudget()

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Create(budget, operation_reference="operation:material"))

    assert not observer._proofs and budget.Failed and budget.ObservationCount == 1, (
        "A failed terminal result must not leave any usable original material proof")
    assert not controls["calls"][0][1].exists(), "Confirmed terminal control must be cleaned"

    with pytest.raises(material.NativeConfigurationMaterialError):
        observer.Close()


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{} ', b'[]',
                                 b"x" * 65537],
                         ids=["duplicate-key", "nonfinite", "noncanonical", "non-object",
                              "oversized"])
def test_SimulatedMalformedOrOverflowWireCannotIssueProof(simulated_observer, raw):
    """Bounded strict canonical response validation precedes any original proof registration."""

    observer, controls = simulated_observer
    controls["stdout"] = lambda original: raw
    budget = NativeImageObservationBudget()

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Create(budget, operation_reference="operation:material"))

    assert budget.Failed and not observer._proofs, "Malformed private wire cannot prove material"


@pytest.mark.parametrize("field", ["nonce", "operation_reference", "workspace_id",
    "owner_reference", "workspace_identity", "directory_identity", "selection", "stage_root"])
def test_SimulatedCrossAssociatedResponseRefuses(simulated_observer, field):
    """No detached child response may substitute another request's control associations."""

    observer, controls = simulated_observer

    def Change(raw):
        """Change a single association while retaining syntactically canonical private wire."""

        value = worker.ParseControl(raw)
        value["control"][field] = "foreign"

        return worker.CanonicalControl(value)

    controls["stdout"] = Change
    budget = NativeImageObservationBudget()

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Create(budget, operation_reference="operation:material"))

    assert budget.Failed and not observer._proofs, "Substituted association cannot issue proof"


@pytest.mark.parametrize("change", ["request", "private-extra", "source", "scanner", "scratch"])
def test_SimulatedPostWorkerMutationRefusesAndRetainsUnverifiedState(
    simulated_observer, change,
):
    """Result validation and terminal cleanup cannot accept changed control or staged identities."""

    observer, controls = simulated_observer

    def Change(path, control):
        """Alter only one selected owned test file after the simulated worker terminates."""

        root = Path(control["stage_root"])

        if change == "request":
            path.write_bytes(b"{}")

        elif change == "private-extra":
            (path.parent / "unknown").write_bytes(b"unselected")

        elif change == "scratch":
            (root / "scratch").rename(root.parent / "original-scratch")
            (root / "scratch").mkdir()

        else:
            target = root / ("input/Dockerfile" if change == "source" else "scanner/executable")
            target.chmod(0o600)
            target.write_bytes(b"changed")

    controls["after_worker"] = Change
    budget = NativeImageObservationBudget()

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Create(budget, operation_reference="operation:material"))

    assert budget.Failed and not observer._proofs, "Post-worker mutation must refuse issuance"

    if change in {"request", "private-extra"}:
        assert controls["calls"][0][1].exists(), "Unverified private state must remain available"


@pytest.mark.parametrize("event", [ExecutionEvent(0, ExecutionEventKind.STDOUT, b"x" * 131073),
                                   ExecutionEvent(0, ExecutionEventKind.STARTED)])
def test_SimulatedEventEnvelopeOrCountFailureRetainsUnknownCleanup(
    simulated_observer, monkeypatch, event,
):
    """Acquisition overflow propagates through the owner without inventing terminal cleanup."""

    observer, controls = simulated_observer

    if not event.data:
        original = LocalExecutor.Execute

        async def TooMany(executor, request, **options):
            """Exhaust the exact fixed event-count ceiling before any result is delivered."""

            for _ in range(1025):
                options["on_event"](event)

            return await original(executor, request, **options)

        monkeypatch.setattr(LocalExecutor, "Execute", TooMany)

    else:
        controls["event"] = event

    budget = NativeImageObservationBudget()

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Create(budget, operation_reference="operation:material"))

    assert budget.Failed and not observer._terminal and not observer._proofs, (
        "An exception without the original owned terminal result must retain unknown cleanup")

    with pytest.raises(material.NativeConfigurationMaterialError):
        observer.Close()

    assert observer._private, "Unknown cleanup must retain its private control identity"


def test_SimulatedUnknownCleanupRetainsPrivateStateAndBlocksRetry(simulated_observer):
    """An executor exception never substitutes for the required original owned cleanup result."""

    observer, controls = simulated_observer
    controls["mode"] = "unknown"
    budget = NativeImageObservationBudget()

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Create(budget, operation_reference="operation:material"))

    path = controls["calls"][0][1]
    assert path.exists() and not observer._terminal and not observer._proofs, (
        "Unknown child cleanup must preserve exact private controls and withhold proof")

    with pytest.raises(material.NativeConfigurationMaterialError):
        observer.Close()

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Create(budget, operation_reference="operation:material"))

    assert budget.ObservationCount == 1, "An unconfirmed helper cannot consume a replacement slot"


def test_UnknownTerminalOwnershipCannotCleanExactPrivateRequest(simulated_observer):
    """Even an unchanged known control remains retained while helper termination is unknown."""

    observer, controls = simulated_observer
    controls["mode"] = "unknown"

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Create(NativeImageObservationBudget(),
            operation_reference="operation:material"))

    path = controls["calls"][0][1]

    with pytest.raises(material.NativeConfigurationMaterialError, match="cleanup is unknown"):
        observer.CleanPrivate(path)

    assert path in observer._private and path.is_file(), (
        "Unknown terminal ownership must retain exact private state without any unlink")


def test_SettlingAnAlreadyCancelledOriginalTaskPropagatesCancellation():
    """A terminal cancelled original task cannot trap the ownership settlement loop."""

    async def Scenario():
        """Cancel the original owned future and require prompt cancellation propagation."""

        task = asyncio.get_running_loop().create_future()
        task.cancel()
        stop = asyncio.Event()

        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(material.Settle(task, stop), timeout=1)

        assert task.cancelled() and stop.is_set(), (
            "Original terminal cancellation must signal stop without replacing owned work")

    asyncio.run(Scenario())


def test_SimulatedRepeatedOuterCancellationSettlesOriginalHelperAndMonitors(simulated_observer):
    """Repeated cancellation waits for the original terminal owner and never abandons monitors."""

    observer, controls = simulated_observer
    controls["mode"] = "hold"
    budget = NativeImageObservationBudget()

    async def Scenario():
        """Hold terminal cleanup after cooperative stop to inspect ownership before releasing it."""

        task = asyncio.create_task(observer.Create(
            budget, operation_reference="operation:material"))

        await controls["started"].wait()
        task.cancel()

        await asyncio.sleep(0)
        task.cancel()

        await asyncio.sleep(0)
        assert not task.done() and observer._busy and not observer._terminal, (
            "Outer cancellation cannot finish while the original helper still owns cleanup")
        assert controls["calls"][0][1].exists(), "Live helper private controls must be retained"
        controls["released"].set()

        with pytest.raises(asyncio.CancelledError):
            await task

        assert not [active for active in asyncio.all_tasks()
            if active is not asyncio.current_task()], (
            "Original executor, deadline and cancellation tasks must all be settled")

    asyncio.run(Scenario())
    assert observer._terminal and not observer._busy and budget.Failed and not observer._proofs, (
        "Cancellation can confirm cleanup but can never issue material proof")
    assert not controls["calls"][0][1].exists(), "Confirmed cancelled control must be removed"
    observer.Close()


def test_SimulatedCallerCancellationBridgeSettlesOwnedHelper(simulated_observer):
    """A cooperative event stops the owned executor and its bridge without replacing its task."""

    observer, controls = simulated_observer
    controls["mode"] = "cancel"
    budget = NativeImageObservationBudget()

    async def Scenario():
        """Deliver the caller event only after actual simulated launch checks have completed."""

        cancellation = asyncio.Event()
        task = asyncio.create_task(observer.Create(budget, operation_reference="operation:material",
            cancellation=cancellation))

        await controls["started"].wait()
        cancellation.set()

        with pytest.raises(material.NativeConfigurationMaterialError):
            await task

        assert not [active for active in asyncio.all_tasks()
            if active is not asyncio.current_task()], (
            "Cooperative cancellation must settle both the helper and the bridge")

    asyncio.run(Scenario())
    assert budget.Failed and observer._terminal and not observer._proofs, (
        "Caller cancellation must consume a failed observation after confirmed cleanup")


def test_SimulatedWorkingDeadlineStopsBeforeCleanupReserve(simulated_observer, monkeypatch):
    """A shortened issued test window exercises the real watchdog without waiting twelve seconds."""

    observer, controls = simulated_observer
    controls["mode"] = "cancel"
    budget = NativeImageObservationBudget()
    original = budget.BeginObservation

    def Begin():
        """Shorten the same active ledger window solely for deterministic timeout mechanics."""

        issued = original()
        issued = replace(issued, deadline=issued.started_at + 0.2,
            working_deadline=issued.started_at + 0.02)
        budget._active = issued

        return issued

    monkeypatch.setattr(budget, "BeginObservation", Begin)

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Create(budget, operation_reference="operation:material"))

    assert budget.Failed and observer._terminal and not observer._proofs, (
        "Working deadline must stop the helper while preserving terminal cleanup ownership")


def test_SimulatedResultAndCleanupTimeRemainChargedToSameWindow(simulated_observer, monkeypatch):
    """Even successful worker bytes cannot issue proof after result/cleanup exceeds the slot."""

    observer, controls = simulated_observer
    budget = NativeImageObservationBudget()

    def Exhaust(path, control):
        """Move only the existing ledger clock past its issued inclusive deadline."""

        deadline = budget._active.deadline
        monkeypatch.setattr(budget_module, "monotonic", lambda: deadline + 0.01)

    controls["after_worker"] = Exhaust

    with pytest.raises(ValueError, match="exceeded"):
        asyncio.run(observer.Create(budget, operation_reference="operation:material"))

    assert budget.Failed and not observer._proofs and budget.ObservationCount == 1, (
        "Control, response and cleanup overhead cannot escape the original inclusive slot")
    observer.Close()


def test_ReadConsentPlatformAndCancelledPreflightDoNotStartHelpers(
    tmp_path, owned_material, simulated_observer, monkeypatch,
):
    """Missing owner consent, unsupported ownership or prior cancellation refuses before reads."""

    observer, controls = simulated_observer

    with pytest.raises(material.NativeConfigurationMaterialError):
        material.NativeConfigurationMaterialObserver(owned_material, tmp_path,
            "workspace:material", "owner:foreign")

    budget = NativeImageObservationBudget()
    cancellation = asyncio.Event()
    cancellation.set()

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Create(budget, operation_reference="operation:material",
            cancellation=cancellation))

    def Unsupported():
        """Represent absent platform ownership before any selected material is opened."""

        raise ValueError("unsupported owned-child interface")

    monkeypatch.setattr(material, "RequirePlatform", Unsupported)

    with pytest.raises(ValueError):
        asyncio.run(observer.Create(budget, operation_reference="operation:material"))

    assert not controls["calls"] and budget.ObservationCount == 0, (
        "Preflight refusals must not launch helpers or claim an observation slot")


def test_SameLedgerHasExactlyThreeObservationsAndNoImplicitFinalization(simulated_observer):
    """Create and both verifications share the original three slots; no fresh ledger is created."""

    observer, _ = simulated_observer
    budget = NativeImageObservationBudget()
    proof = asyncio.run(observer.Create(budget, operation_reference="operation:material"))

    for _ in range(2):
        proof = asyncio.run(observer.Verify(
            proof, budget, operation_reference="operation:material"))

    with pytest.raises(ValueError, match="retried"):
        asyncio.run(observer.Verify(proof, budget, operation_reference="operation:material"))

    assert budget.ObservationCount == 3 and budget.FinalizationSeconds == 0, (
        "Read helpers cannot reset the caller ledger or spend its finalization reserve")
    observer.Close()


def test_WorkerWireRetainsOriginalEmptyScratchPhysicalIdentity(tmp_path, owned_material):
    """A detached original stage wire cannot accept a different newly empty scratch directory."""

    stage = worker.CreateStage(StageRoot(tmp_path), owned_material)
    payload = worker.StagePayload(stage)
    scratch = stage.root / "scratch"
    scratch.rename(stage.root.parent / "retained-original-scratch")
    scratch.mkdir()

    with pytest.raises(ValueError, match="scratch identity"):
        worker.StageFromPayload(payload, owned_material, stage.root)


def test_SnapshotConsentAssociationCannotBeReplaced(tmp_path, owned_material):
    """Typed snapshot construction does not allow a stage to substitute another read consent."""

    stage = worker.CreateStage(StageRoot(tmp_path), owned_material)
    snapshot = replace(stage.input, consent=ArtifactReadConsent("owner:other", "read:other"))

    with pytest.raises(ValueError):
        worker.CheckStageMetadata(replace(stage, input=snapshot), owned_material)


@pytest.mark.parametrize("proof", [None, object()])
def test_MissingVerificationProofCannotBecomeCreate(simulated_observer, proof):
    """Verify requires an original proof even when no stage has yet been created."""

    observer, controls = simulated_observer
    budget = NativeImageObservationBudget()

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Verify(proof, budget, operation_reference="operation:material"))

    assert not controls["calls"] and budget.ObservationCount == 0, (
        "Missing proof cannot select create action or acquire any selected source bytes")


def test_FailedReverificationRevokesPreviouslyIssuedProof(simulated_observer):
    """An original earlier receipt cannot survive an unknown active reobservation owner."""

    observer, controls = simulated_observer
    budget = NativeImageObservationBudget()
    proof = asyncio.run(observer.Create(budget, operation_reference="operation:material"))
    controls["mode"] = "unknown"

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Verify(proof, budget, operation_reference="operation:material"))

    with pytest.raises(material.NativeConfigurationMaterialError):
        observer.CheckCurrent(proof, operation_reference="operation:material")

    assert not observer._proofs and not observer._terminal, (
        "An unconfirmed verification owner must withhold every previous original proof")


@pytest.mark.parametrize("change", ["consent", "control"])
def test_LaunchRechecksSelectedConsentAndExactControlAfterReadiness(
    simulated_observer, monkeypatch, change,
):
    """A mutation between real launch checks refuses before the worker reads selected material."""

    observer, controls = simulated_observer

    def Change(path):
        """Change the original owner association or exclusive request after the first check."""

        if change == "consent":
            observer.selection = replace(observer.selection,
                read_consent=ArtifactReadConsent("owner:mechanics", "read:changed"))

        else:
            path.write_bytes(b"{}")

    def Forbidden(*args, **kwargs):
        """Refuse any selected capture after the second launch boundary must have denied it."""

        pytest.fail("Changed selected consent/control must refuse before selected worker reads")

    controls["before_second"] = Change
    monkeypatch.setattr(worker, "CreateStage", Forbidden)
    budget = NativeImageObservationBudget()

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Create(budget, operation_reference="operation:material"))

    assert budget.Failed and not observer._proofs and controls["calls"][0][1].exists(), (
        "A refused final launch cannot issue proof or discard unconfirmed control")


@pytest.mark.parametrize("change", ["root", "partition", "file", "unknown"])
def test_CloseRefusesChangedKnownStageBeforeAnyUnlink(simulated_observer, change):
    """Close validates finite original metadata and known names before unlinking owned children."""

    observer, _ = simulated_observer
    proof = asyncio.run(observer.Create(NativeImageObservationBudget(),
        operation_reference="operation:material"))
    root = proof.stage.root

    if change == "root":
        root.rename(root.parent / "original-stage")
        root.mkdir()

    elif change == "partition":
        (root / "material").rename(root.parent / "original-material")
        (root / "material").mkdir()

    elif change == "file":
        selected = root / "input" / "Dockerfile"
        selected.chmod(0o600)
        selected.write_bytes(b"changed")

    else:
        (root / "material" / "unknown").write_bytes(b"unselected")

    with pytest.raises(ValueError):
        observer.Close()

    assert root.exists() and not observer._proofs, (
        "Changed stage must retain its tree and revoke proof without recursive or partial deletion")


def test_ChangedStageLeaseInVerificationResponseRefuses(simulated_observer):
    """A response cannot keep physical paths while swapping the original stage association."""

    observer, controls = simulated_observer
    budget = NativeImageObservationBudget()
    proof = asyncio.run(observer.Create(budget, operation_reference="operation:material"))

    def Change(raw):
        """Substitute a syntactically valid lease in the reobserved descriptive stage wire."""

        value = worker.ParseControl(raw)
        value["stage"]["lease_id"] = "0" * 32

        return worker.CanonicalControl(value)

    controls["stdout"] = Change

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Verify(proof, budget, operation_reference="operation:material"))

    assert budget.Failed and not observer._proofs, "Reverification must retain original stage facts"


def test_WorkerPlatformRefusesBeforeAnySelectedRead(monkeypatch):
    """Unsupported machine or Linux ownership cannot enter either child read action."""

    monkeypatch.setattr(worker.platform, "machine", lambda: "unsupported")

    with pytest.raises(ValueError, match="platform"):
        worker.RequirePlatform()

    monkeypatch.setattr(worker.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(worker.sys, "platform", "linux")

    def Unsupported():
        """Represent unavailable owned Linux primitives without probing unrelated process state."""

        raise LocalExecutionError("unsupported ownership")

    monkeypatch.setattr(worker, "RequireLinuxOwnership", Unsupported)

    with pytest.raises(ValueError, match="ownership"):
        worker.RequirePlatform()


@pytest.mark.parametrize(("system", "machine"), [
    ("win32", "x86_64"), ("darwin", "x86_64"), ("linux", "aarch64"),
])
def test_UnsupportedPlatformRefusesWorkerAndParentBeforeReadsOrHelperAdmission(
    tmp_path, owned_material, monkeypatch, capsys, system, machine,
):
    """Actual unsupported entry paths refuse without reads, helper launch or ledger admission."""

    observer = material.NativeConfigurationMaterialObserver(owned_material, tmp_path,
        "workspace:material", "owner:mechanics")
    budget = NativeImageObservationBudget()
    original_children = set(tmp_path.iterdir())
    forbidden = MagicMock(side_effect=AssertionError("Unsupported platforms must refuse admission"))
    monkeypatch.setattr(worker, "sys", SimpleNamespace(platform=system, stderr=worker.sys.stderr))
    monkeypatch.setattr(worker.platform, "machine", lambda: machine)
    monkeypatch.setattr(worker, "RequireLinuxOwnership", forbidden)
    monkeypatch.setattr(worker, "ReadControl", forbidden)
    monkeypatch.setattr(worker, "SelectionFromControl", forbidden)
    monkeypatch.setattr(worker, "ReadArtifactFile", forbidden)
    monkeypatch.setattr(worker, "CreateStage", forbidden)
    monkeypatch.setattr(worker, "VerifyStage", forbidden)
    monkeypatch.setattr(material, "ArtifactPathInfo", forbidden)
    monkeypatch.setattr(material, "ReadControl", forbidden)
    monkeypatch.setattr(LocalExecutor, "Execute", forbidden)

    with pytest.raises(ValueError, match="platform is unsupported"):
        worker.ObserveControl({}, "0" * 64, (0,) * 5)

    assert worker.Main([str(tmp_path / "request.json"), "0" * 64, "0,0,0,0,0"]) == 2, (
        "Unsupported installed entry paths must return only the fixed refusal status")
    output = capsys.readouterr()
    assert not output.out and output.err == "native-configuration-material-refused\n", (
        "Unsupported platforms must emit no material metadata or selected path diagnostics")

    with pytest.raises(ValueError, match="platform is unsupported"):
        asyncio.run(observer.Create(budget, operation_reference="operation:material"))

    assert not forbidden.called and set(tmp_path.iterdir()) == original_children, (
        "Unsupported platform refusal must precede reads, helper launch and workspace mutation")
    assert budget.ObservationCount == 0 and not budget.Failed, (
        "Platform preflight must refuse before the caller ledger admits an observation")
    assert not observer._private and not observer._proofs and observer._stage_root is None and (
        observer._stage is None and observer._terminal and not observer._busy
    ), "Unsupported entry paths cannot create private control, stage or material proof"


def test_WorkerMainUsesOnlyFixedArgumentsAndSanitizedRefusal(monkeypatch, capsys):
    """The installed child entry point rejects invalid control without leaking selected paths."""

    monkeypatch.setattr(worker, "RequirePlatform", lambda: None)
    assert worker.Main([]) == 2, "The fixed installed helper requires exact private arguments"
    assert capsys.readouterr().err == "native-configuration-material-refused\n", (
        "A private request refusal must expose only a bounded fixed diagnostic")


def test_InProcessWorkerEntryPointRechecksOriginalControlBeforeMetadataOutput(
    tmp_path, owned_material, monkeypatch, capsysbinary,
):
    """Tiny in-process entry mechanics revalidate control twice and emit bounded metadata only."""

    directory, control = Control(tmp_path, owned_material)
    raw = worker.CanonicalControl(control)
    path = directory / "request.json"
    path.write_bytes(raw)
    path.chmod(0o600)
    digest = hashlib.sha256(raw).hexdigest()
    identity = PhysicalIdentity(path.stat())

    if os.name == "nt":
        read = MagicMock(side_effect=AssertionError(
            "Unsupported workers must refuse control reads"))
        monkeypatch.setattr(worker, "ReadControl", read)
        assert worker.Main([str(path), digest, ",".join(str(item) for item in identity)]) == 2, (
            "The actual Windows entry path must refuse unsupported platform ownership")
        output = capsysbinary.readouterr()
        assert not read.called and not StageRoot(tmp_path).exists(), (
            "Unsupported Windows workers must refuse before control reads or selected capture")
        assert not output.out and output.err == b"native-configuration-material-refused\n", (
            "Unsupported worker refusal must retain its fixed bounded diagnostic")

        return

    original_read = worker.ReadControl
    reads = []

    def Read(path, digest, identity):
        """Observe both actual guarded reads without substituting request or stage bytes."""

        reads.append((path, digest, identity))

        return original_read(path, digest, identity)

    monkeypatch.setattr(worker, "RequirePlatform", lambda: None)
    monkeypatch.setattr(worker, "ReadControl", Read)
    monkeypatch.setattr(worker.sys, "argv", ["in-process-worker", str(path), digest,
        ",".join(str(item) for item in identity)])
    assert worker.Main() == 0, "In-process mechanics must complete the fixed metadata response"
    output = capsysbinary.readouterr()
    response = worker.ParseControl(output.out)
    assert reads == [(path, digest, identity)] * 2, (
        "The entry point must recheck original control after selected stage observation")
    assert not output.err and response["control"] == control and (
        response["request_sha256"] == digest
        and response["request_identity"] == list(identity)
        and owned_material.source.read_bytes() not in output.out
        and owned_material.executable.read_bytes() not in output.out
    ), "Bounded successful output must preserve private associations without selected contents"


def test_ScratchReplacementDuringWorkerVerificationRefusesAndRetainsStage(
    simulated_observer, monkeypatch,
):
    """Replacing empty scratch after request decoding cannot issue a renewed original proof."""

    observer, controls = simulated_observer
    budget = NativeImageObservationBudget()
    proof = asyncio.run(observer.Create(budget, operation_reference="operation:material"))
    original_read = worker.ReadArtifactFile
    original_execute = LocalExecutor.Execute
    replaced = False
    refusal = []

    def Read(path, name, destination=None, *, max_bytes):
        """Replace scratch during the first bounded source read after original wire admission."""

        nonlocal replaced

        if path == proof.stage.input.directory / "Dockerfile" and not replaced:
            scratch = proof.stage.root / "scratch"
            scratch.rename(proof.stage.root.parent / "scratch-replaced-during-verification")
            scratch.mkdir()
            replaced = True

        return original_read(path, name, destination, max_bytes=max_bytes)

    async def Execute(executor, request, **options):
        """Represent sanitized child refusal with a confirmed simulated terminal result."""

        try:
            return await original_execute(executor, request, **options)

        except ValueError as error:
            if "scratch identity" not in str(error):
                raise

            refusal.append(error)

            return LocalExecutionResult(AdapterExecution(ExecutionState.FAILED, 2, 0.01),
                ExecutionTermination.PROCESS_EXIT, b"", b"native-configuration-material-refused\n",
                (ExecutionEvent(0, ExecutionEventKind.COMPLETED,
                    termination=ExecutionTermination.PROCESS_EXIT),))

    monkeypatch.setattr(worker, "ReadArtifactFile", Read)
    monkeypatch.setattr(LocalExecutor, "Execute", Execute)

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Verify(proof, budget, operation_reference="operation:material"))

    assert replaced and refusal, "The worker must refuse the replacement detected after decoding"
    assert budget.Failed and not observer._proofs and observer._scratch_identity == (
        proof.scratch_identity
    ), "Failed reobservation must revoke prior proof and retain only its original scratch identity"
    assert observer._terminal and not controls["calls"][-1][1].exists(), (
        "Confirmed simulated child refusal permits cleanup of exact private control only")

    with pytest.raises(material.NativeConfigurationMaterialError):
        observer.CheckCurrent(proof, operation_reference="operation:material")

    with pytest.raises(material.NativeConfigurationMaterialError, match="scratch identity"):
        observer.Close()

    assert (proof.stage.root / "scratch").exists(), (
        "Changed staged material must remain retained without being rebound or recursively removed")


def test_ChangedReturnedScratchIdentityCannotRebindOriginalProof(simulated_observer):
    """Parent refusal preserves the original identity even if child wire describes a replacement."""

    observer, controls = simulated_observer
    budget = NativeImageObservationBudget()
    proof = asyncio.run(observer.Create(budget, operation_reference="operation:material"))
    returned = []

    def Change(raw):
        """Provide otherwise valid same-stage wire matching newly replaced actual empty scratch."""

        value = worker.ParseControl(raw)
        scratch = proof.stage.root / "scratch"
        scratch.rename(proof.stage.root.parent / "scratch-replaced-before-response")
        scratch.mkdir()
        info = scratch.stat()
        returned.append((info.st_dev, info.st_ino))
        value["stage"]["scratch_identity"] = returned[-1]

        return worker.CanonicalControl(value)

    controls["stdout"] = Change

    with pytest.raises(material.NativeConfigurationMaterialError):
        asyncio.run(observer.Verify(proof, budget, operation_reference="operation:material"))

    assert returned and returned[-1] != proof.scratch_identity, (
        "The causal response must match actual replacement while differing from the original proof")
    assert observer._scratch_identity == proof.scratch_identity and not observer._proofs, (
        "Parent must refuse to renew or rebind proof even without a child-side late identity check")
    assert budget.Failed and observer._terminal and not controls["calls"][-1][1].exists(), (
        "Known terminal response permits exact private cleanup while changed staged facts refuse")

    with pytest.raises(material.NativeConfigurationMaterialError):
        observer.CheckCurrent(proof, operation_reference="operation:material")

    with pytest.raises(material.NativeConfigurationMaterialError, match="scratch identity"):
        observer.Close()

    assert (proof.stage.root / "scratch").exists(), "Unverified replacement must remain retained"
