# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Four real installed configuration read-helper cases; pinned provider bytes never execute."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import importlib.metadata
import json
import os
import platform
import socket
import stat
import sys
from pathlib import Path

import pytest

from fuzzy1337.adapters import ExecutionState, SerializeContract
from fuzzy1337.artifact_inputs import ArtifactProfile, ArtifactReadConsent, PhysicalIdentity
from fuzzy1337.executors import ExecutionEventKind, ExecutionTermination, LocalExecutor
from fuzzy1337.executors.owned_process import RequireLinuxOwnership
from fuzzy1337.native_configuration import (
    NATIVE_CONFIGURATION_EXECUTABLE_SHA256,
    NativeConfigurationSelection,
)
from fuzzy1337.native_configuration_material import (
    NativeConfigurationMaterialError,
    NativeConfigurationMaterialObserver,
)
from fuzzy1337.native_configuration_material_worker import CONTROL_BYTES, StagePayload
from fuzzy1337.native_image_observation import NativeImageObservationBudget

pytestmark = pytest.mark.integration
CASE_IDS = (
    "installed-create-verify-close",
    "installed-invalid-utf8-child-refusal",
    "installed-original-scratch-replacement-refusal",
    "installed-caller-cancellation-settlement",
)
CONTEXT_ENVIRONMENT = "FUZZY1337_CONFIGURATION_MATERIAL_CONTEXT"
OWNER = "owner:installed-configuration-material"
OPERATION = "operation:installed-configuration-material"
SOURCE = b"FROM scratch\nUSER 41731\n# independently authored inert snapshot source\n"
RECEIPT_BYTES = 512 * 1024


def Digest(path: Path) -> str:
    """Hash selected regular bytes in constant memory without executing them."""

    assert path.is_file() and not path.is_symlink(), "Selected hash input must be a physical file"
    assert path.stat().st_size <= 256 * 1024**2, "Selected hash input exceeded its byte budget"
    digest = hashlib.sha256()
    received = 0

    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            received += len(chunk)
            assert received <= 256 * 1024**2, "Selected hash input grew beyond its byte budget"
            digest.update(chunk)

    return digest.hexdigest()


def ReadJson(path: Path, maximum: int = 1024 * 1024) -> dict:
    """Read only the explicitly selected bounded synthetic acceptance metadata."""

    assert path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum, (
        'Acceptance metadata must be a bounded physical regular file'
    )

    with path.open("rb") as source:
        raw = source.read(maximum + 1)

    assert len(raw) <= maximum, "Acceptance metadata grew beyond its fixed envelope"

    return json.loads(raw)


def WriteJson(path: Path, value: object) -> None:
    """Preserve bounded original metadata exclusively without executable or archive bodies."""

    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    assert len(raw) <= RECEIPT_BYTES, "Original helper metadata exceeded its retention bound"

    with path.open("xb") as output:
        output.write(raw)


def ModuleHashes(context: dict) -> dict[str, str]:
    """Associate every loaded first-party module with its exact installed wheel source member."""

    prefix = Path(context["environment"])
    hashes = {}

    for name, module in tuple(sys.modules.items()):
        if name != "fuzzy1337" and not name.startswith("fuzzy1337."):
            continue

        path = Path(module.__file__).resolve()
        assert path.is_relative_to(prefix), "First-party module escaped the wheel installation"
        relative = "fuzzy1337/" + path.relative_to(
            Path(sys.modules["fuzzy1337"].__file__).parent).as_posix()
        digest = Digest(path)
        assert digest == context["source_hashes"][relative], (
            "Installed module differs from the exact clean revision's wheel member"
        )
        hashes[name] = digest

    required = {"fuzzy1337.native_configuration_material_worker",
        "fuzzy1337.native_configuration_material", "fuzzy1337.executors.local",
        "fuzzy1337.executors.owned_process", "fuzzy1337.executors.descendant_supervisor"}
    assert required <= set(hashes), "Launch and terminal provenance must include all owners"

    return hashes


@pytest.fixture(scope="module")
def installed_context():
    """Fail required lane prerequisites; absent context is explicitly unexecuted locally."""

    selected = os.environ.get(CONTEXT_ENVIRONMENT)

    if selected is None:
        pytest.skip("Installed material helper acceptance is UNRUN without its dedicated context")

    context = ReadJson(Path(selected))
    assert sys.platform == "linux" and platform.machine() == "x86_64" and os.geteuid() != 0, (
        "Required installed material proof needs the ordinary Linux x86_64 owner"
    )
    assert sys.version_info[:2] == (3, 14), "Required helper lane must use the selected Python 3.14"
    RequireLinuxOwnership()
    assert Path(sys.executable).absolute() == Path(context["interpreter"]), (
        "Parent and fixed helper must share the fresh installed interpreter"
    )
    assert sys.flags.isolated, "Every actual pytest worker must use isolated installed Python"
    prefix = Path(context["environment"])
    repository = Path(context["repository"])
    assert Path(sys.prefix) == prefix and not prefix.is_relative_to(repository), (
        'Installed prefix must be the fresh outside-checkout environment'
    )
    assert Path.cwd() == Path(context["run_directory"]), (
        'Cases must execute from the prepared outside-checkout directory'
    )
    assert not Path.cwd().is_relative_to(repository), (
        'Case working directory must remain outside the source checkout'
    )
    assert "PYTHONPATH" not in os.environ and all(
        not Path(item).absolute().is_relative_to(repository) for item in sys.path if item
    ), "Installed acceptance must not expose checkout source on its import path"
    distribution = importlib.metadata.distribution("1337")
    assert Path(distribution.locate_file("")).is_relative_to(prefix), (
        'Distribution metadata must resolve beneath the installed environment'
    )
    direct = json.loads(distribution.read_text("direct_url.json"))
    assert "dir_info" not in direct and direct["url"].endswith(context["wheel"]["name"]), (
        "Installed product must originate from the built wheel, never an editable source"
    )
    assert Digest(Path(__file__)) == context["test_sha256"], (
        'Copied case source must match the exact reviewed revision'
    )
    namespace = os.readlink("/proc/self/ns/net")
    host_namespace = os.environ["FUZZY1337_CONFIGURATION_MATERIAL_HOST_NETNS"]
    assert namespace != host_namespace, "Required helper lane reused its provisioning namespace"
    interfaces = socket.if_nameindex()
    assert interfaces == [(1, "lo")], "Required helper namespace permits only loopback"
    routes = Path("/proc/net/route").read_text().splitlines()[1:]
    assert all(int(line.split()[1], 16) == int(line.split()[2], 16) == 0 for line in routes), (
        'Required helper namespace must have no external IPv4 route'
    )
    assert all(line.split()[0] == "0" * 32 for line in
               Path("/proc/net/ipv6_route").read_text().splitlines()), (
        'Required helper namespace must have no external IPv6 route'
    )
    provisioning = context["provisioning"]
    executable = Path(provisioning["executable"])
    assert stat.S_IMODE(executable.stat().st_mode) == 0o400, (
        'Selected genuine scanner must retain mode 0400'
    )
    assert not os.access(executable, os.X_OK), (
        'Selected scanner data must have no execution permission'
    )
    assert Digest(executable) == provisioning["executable_sha256"] == (
        NATIVE_CONFIGURATION_EXECUTABLE_SHA256
    ), "Required helper input must retain the genuine existing executable pin"
    assert provisioning["provider_executed"] is False, (
        'Provisioning must never execute the selected scanner'
    )
    assert provisioning["database_provisioned"] is False, (
        'Installed read-helper acceptance must provision no database'
    )

    # Importing the fixed supervisor records source provenance without running its entry point.
    from fuzzy1337.executors import descendant_supervisor

    assert descendant_supervisor.__name__ == "fuzzy1337.executors.descendant_supervisor", (
        'Ownership provenance must import the fixed installed supervisor'
    )
    context["module_hashes"] = ModuleHashes(context)
    context["network"] = {"host": host_namespace, "helper": namespace, "interfaces": interfaces,
                          "no_external_ipv4_routes": True, "no_external_ipv6_routes": True}
    context["parent_isolated"] = bool(sys.flags.isolated)

    return context


class OriginalRecorder:
    """Delegate the actual executor unchanged and retain original bounded process observations."""

    def __init__(self, context: dict, directory: Path, cancellation: asyncio.Event | None) -> None:
        """Bind one case's isolated evidence destination and optional caller cancellation."""

        self.context = context
        self.directory = directory
        self.cancellation = cancellation
        self.results = []
        self.controls = []
        self.requests = []
        self.receipt_hashes = []
        self.started = False
        self.execute = LocalExecutor.Execute

    async def Execute(self, executor, request, **options):
        """Record exact originals while preserving launch checks, events, outcomes and ownership."""

        argv = request.invocation.argv
        assert len(argv) == 7 and argv[:4] == (sys.executable, "-I", "-m",
            "fuzzy1337.native_configuration_material_worker"), "Provider commands are excluded"
        assert options["own_descendants"] is True, (
            'Actual executor must retain stronger Linux descendant ownership'
        )
        assert request.invocation.timeout_seconds == 6, (
            'Fixed helper worker timeout must remain six seconds'
        )
        assert request.resources.max_stdout_bytes == CONTROL_BYTES == 64 * 1024, (
            'Actual helper stdout must retain the fixed 64 KiB ceiling'
        )
        assert request.resources.max_stderr_bytes == 4096, (
            'Actual helper stderr must retain the fixed 4 KiB ceiling'
        )
        assert request.resources.terminate_grace_seconds == 3, (
            'Actual helper cleanup grace must remain three seconds'
        )
        control_path = Path(argv[4])

        with control_path.open("rb") as source:
            raw = source.read(CONTROL_BYTES + 1)

        assert len(raw) <= CONTROL_BYTES, "Original private control must retain its 64 KiB bound"
        control = json.loads(raw)
        assert hashlib.sha256(raw).hexdigest() == argv[5], (
            'Original private control bytes must match the fixed request digest'
        )
        assert ",".join(str(item) for item in PhysicalIdentity(control_path.stat())) == argv[6], (
            'Original private control identity must match the fixed request arguments'
        )
        self.controls.append(control)
        self.requests.append(request)
        callback = options["on_event"]
        events = []

        def Event(event):
            """Retain original events and signal cancellation at the original STARTED event."""

            events.append(event)
            callback(event)

            if event.kind is ExecutionEventKind.STARTED:
                self.started = True

                if self.cancellation is not None:
                    self.cancellation.set()

        result = await self.execute(executor, request, **{**options, "on_event": Event})
        self.results.append(result)
        assert tuple(events) == result.events, "Recorder must preserve the original events"
        assert events[0].kind is ExecutionEventKind.STARTED and (
            events[-1].kind is ExecutionEventKind.COMPLETED
        ), "Unstarted or unknown terminal outcomes cannot establish helper acceptance"
        assert len(events) <= 1024, (
            'Original helper event count must remain within its production ceiling'
        )
        assert sum(len(event.data) * 2 + 256 for event in events) <= 256 * 1024, (
            'Original helper event envelope must remain within 256 KiB'
        )
        assert len(result.stdout) <= CONTROL_BYTES and len(result.stderr) <= 4096, (
            'Original result streams must remain within fixed production bounds'
        )
        index = len(self.results)

        for stream in ("stdout", "stderr"):
            with (self.directory / f"observation-{index}-{stream}.bin").open("xb") as output:
                output.write(getattr(result, stream))

        receipt_path = self.directory / f"observation-{index}.json"
        WriteJson(receipt_path, {
            "schema_version": 1, "commit": self.context["commit"],
            "request": json.loads(SerializeContract(request)), "control": control,
            "original_result_returned": True, "own_descendants": options["own_descendants"],
            "terminal_ownership": "original-owned-executor-returned-after-verified-cleanup",
            "launch_evidence": "original-worker-status-and-owned-cleanup-with-installed-source",
            "worker_body_execution": "not-asserted-for-cancellation",
            "execution": json.loads(SerializeContract(result.execution)),
            "termination": result.termination.value, "module_hashes": self.context["module_hashes"],
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
            "events": [{"sequence": event.sequence, "kind": event.kind.value,
                "data_hex": event.data.hex(), "termination": None if event.termination is None
                else event.termination.value} for event in events]})
        self.receipt_hashes.append(Digest(receipt_path))

        return result


def Ledger(budget: NativeImageObservationBudget, count: int, failed: bool) -> dict:
    """Require the original consumed ledger and untouched finalization reserve."""

    assert budget.ObservationCount == count and budget.Failed is failed, (
        'Original ledger must retain the exact consumed count and failure state'
    )
    assert budget.FinalizationSeconds == 0 and 0 <= budget.SpentSeconds <= count * 12, (
        'Observations must respect inclusive slots without spending finalization'
    )
    assert budget._active is None and budget._finalizing is False, (
        'The original ledger must have no active observation or finalization'
    )

    return {"observations": budget.ObservationCount, "failed": budget.Failed,
            "spent_seconds": budget.SpentSeconds,
            "finalization_seconds": budget.FinalizationSeconds}


def Settled(observer: NativeConfigurationMaterialObserver, recorder: OriginalRecorder) -> None:
    """Require returned actual ownership, removed private controls and no live observer monitor."""

    assert recorder.results and observer._terminal and not (
        observer._busy or observer._private
    ), (
        'Actual returned ownership must precede private cleanup and settlement'
    )
    assert all(not Path(request.invocation.argv[4]).parent.exists()
               for request in recorder.requests), (
        'Every original private request directory must be removed before proof use'
    )
    assert not [task for task in asyncio.all_tasks() if task is not asyncio.current_task()
                and not task.done()], "Helper and observer tasks must settle"


def StageInventory(root: Path | None) -> list[dict]:
    """Retain metadata for exact known generated locations without reopening any file contents."""

    if root is None:
        return []

    inventory = []

    for relative in (".", "input", "input/Dockerfile", "scanner", "scanner/executable",
                     "material", "scratch"):
        path = root / relative

        try:
            info = path.lstat()

        except FileNotFoundError:
            continue

        inventory.append({"path": relative, "physical_identity": PhysicalIdentity(info),
            "mode": stat.S_IMODE(info.st_mode), "directory": stat.S_ISDIR(info.st_mode)})

    return inventory


async def Exercise(case_id: str, context: dict, monkeypatch, facts: dict) -> None:
    """Exercise one reviewed lifecycle against genuine pinned data and the installed worker."""

    root = Path(context["root"]) / case_id
    root.mkdir(mode=0o700)
    source = root / "selected-source"
    source.write_bytes(b"\xff" if case_id == CASE_IDS[1] else SOURCE)
    source_hash = Digest(source)
    executable = Path(context["provisioning"]["executable"])
    original_executable_identity = PhysicalIdentity(executable.stat())
    selection = NativeConfigurationSelection(ArtifactProfile.DOCKERFILE, "Dockerfile", source,
        executable, ArtifactReadConsent(OWNER, "read:installed-configuration-material"))
    observer = NativeConfigurationMaterialObserver(selection, root, "installed-helper", OWNER)
    budget = NativeImageObservationBudget()
    cancellation = asyncio.Event() if case_id == CASE_IDS[3] else None
    recorder = OriginalRecorder(context, Path(facts["evidence"]), cancellation)

    async def Execute(executor, request, **options):
        """Install only a transparent recorder around the unchanged original executor."""

        return await recorder.Execute(executor, request, **options)

    monkeypatch.setattr(LocalExecutor, "Execute", Execute)

    try:
        if case_id == CASE_IDS[0]:
            first = await observer.Create(budget, operation_reference=OPERATION)
            Settled(observer, recorder)
            observer.CheckCurrent(first, operation_reference=OPERATION)

            with pytest.raises(NativeConfigurationMaterialError):
                observer.CheckCurrent(copy.copy(first), operation_reference=OPERATION)

            other = NativeConfigurationMaterialObserver(selection, root, "installed-helper", OWNER)

            with pytest.raises(NativeConfigurationMaterialError):
                other.CheckCurrent(first, operation_reference=OPERATION)

            stage = StagePayload(first.stage, scratch_identity=first.scratch_identity)
            staged_scanner = first.stage.scanner.directory / "executable"
            assert stat.S_IMODE(staged_scanner.stat().st_mode) == 0o400, (
                "Staged genuine scanner bytes must retain a read-only nonexecutable snapshot"
            )
            source.unlink()
            second = await observer.Verify(first, budget, operation_reference=OPERATION)
            Settled(observer, recorder)
            assert not source.exists() and second.stage is first.stage, (
                'Verify must reuse the exact original stage after the source is removed'
            )
            assert second.scratch_identity == first.scratch_identity, (
                'Verify must retain the original scratch identity'
            )
            assert second.observation_id != first.observation_id, (
                'Separate original observations must have distinct nonces'
            )
            assert second.control_sha256 != first.control_sha256, (
                'Verify must bind a new exact private control digest'
            )
            assert StagePayload(second.stage, scratch_identity=second.scratch_identity) == stage, (
                'Verify must preserve every original stage and manifest association'
            )
            assert stage["partitions"]["input"]["manifest"]["files"][0]["sha256"] == source_hash, (
                'Staged input must bind the exact independently authored source bytes'
            )
            assert first.stage.scanner.manifest.files[0].sha256 == (
                NATIVE_CONFIGURATION_EXECUTABLE_SHA256), (
                'Staged scanner must match the genuine production executable pin'
            )
            assert all(result.execution.state is ExecutionState.SUCCEEDED and (
                result.execution.exit_code == 0
                and result.termination is ExecutionTermination.PROCESS_EXIT
                and not result.stderr) for result in recorder.results), (
                'Both original helpers must actually exit successfully with owned cleanup'
            )
            assert [control["action"] for control in recorder.controls] == ["create", "verify"], (
                'Create and Verify must be separate fixed original helper actions'
            )
            observer.CheckCurrent(second, operation_reference=OPERATION)

            with pytest.raises(NativeConfigurationMaterialError):
                observer.CheckCurrent(first, operation_reference=OPERATION)

            observer.Close()
            assert not first.stage.root.exists(), (
                'Close must remove only the exact known generated stage'
            )

            with pytest.raises(NativeConfigurationMaterialError):
                observer.CheckCurrent(second, operation_reference=OPERATION)

            facts.update(stage=stage, cleanup="exact-known-stage-removed-and-proofs-revoked",
                         ledger=Ledger(budget, 2, False))

        elif case_id == CASE_IDS[1]:
            with pytest.raises(NativeConfigurationMaterialError):
                await observer.Create(budget, operation_reference=OPERATION)

            Settled(observer, recorder)
            result = recorder.results[0]
            assert result.execution.state is ExecutionState.FAILED, (
                'Malformed UTF-8 must remain an actual child failure'
            )
            assert result.execution.exit_code == 2, (
                'Original invalid UTF-8 child must exit with its sanitized status 2'
            )
            assert result.termination is ExecutionTermination.PROCESS_EXIT and (
                result.stdout == b""
            ), (
                'Invalid UTF-8 must retain natural child exit and empty stdout'
            )
            assert result.stderr == b"native-configuration-material-refused\n", (
                'Original child refusal must retain the exact sanitized diagnostic'
            )
            assert not observer._proofs and observer._stage is None, (
                'Invalid UTF-8 must issue neither a material proof nor an accepted stage'
            )
            assert observer._stage_root.is_dir(), (
                'Partial unverified stage must remain available for diagnosis'
            )

            with pytest.raises(NativeConfigurationMaterialError, match="partial stage is retained"):
                observer.Close()

            assert observer._stage_root.is_dir() and Digest(source) == source_hash, (
                'Close refusal must retain partial stage and unchanged original source'
            )
            facts.update(cleanup="partial-stage-retained-close-refused",
                         ledger=Ledger(budget, 1, True))

        elif case_id == CASE_IDS[2]:
            proof = await observer.Create(budget, operation_reference=OPERATION)
            Settled(observer, recorder)
            scratch = proof.stage.root / "scratch"
            original = root / "original-scratch"
            scratch.rename(original)
            scratch.mkdir(mode=0o700)
            original_identity = original.stat().st_dev, original.stat().st_ino
            replacement_identity = scratch.stat().st_dev, scratch.stat().st_ino
            assert original_identity == proof.scratch_identity, (
                'Renamed original scratch must retain its issued physical identity'
            )
            assert replacement_identity != original_identity, (
                'Replacement scratch must have a distinct actual physical identity'
            )

            with pytest.raises(NativeConfigurationMaterialError):
                observer.CheckCurrent(proof, operation_reference=OPERATION)

            with pytest.raises(NativeConfigurationMaterialError):
                await observer.Verify(proof, budget, operation_reference=OPERATION)

            assert len(recorder.results) == 1, "Changed scratch must refuse before a second helper"

            with pytest.raises(NativeConfigurationMaterialError):
                observer.Close()

            assert original.is_dir() and scratch.is_dir() and proof.stage.root.is_dir(), (
                'Changed original and replacement scratch state must remain retained'
            )
            assert not observer._proofs and Digest(source) == source_hash, (
                'Changed scratch must revoke proof without changing selected source'
            )
            facts.update(original_scratch_identity=original_identity,
                replacement_scratch_identity=replacement_identity, cleanup="changed-stage-retained",
                ledger=Ledger(budget, 2, True))

        else:
            with pytest.raises(NativeConfigurationMaterialError):
                await observer.Create(budget, operation_reference=OPERATION,
                                      cancellation=cancellation)

            Settled(observer, recorder)
            assert recorder.started and cancellation.is_set() and not observer._proofs, (
                'Actual launched cancellation must issue no proof after caller signaling'
            )
            result = recorder.results[0]
            assert result.termination in {
                ExecutionTermination.CANCELLATION, ExecutionTermination.PROCESS_EXIT}, (
                'Cancellation races must preserve original cancellation or natural exit'
            )

            if result.termination is ExecutionTermination.CANCELLATION:
                assert result.execution.state is ExecutionState.CANCELLED, (
                    'Actual cancellation termination must retain the original cancelled state'
                )

            else:
                assert result.execution.exit_code in {0, 2}, (
                    'Natural-exit race must preserve the original worker exit status'
                )
                assert result.execution.state is (
                    ExecutionState.SUCCEEDED if result.execution.exit_code == 0
                    else ExecutionState.FAILED), (
                    'Natural-exit race must retain the actual success or failure classification'
                )

            assert Digest(source) == source_hash, (
                'Cancellation must leave the original inert selected source unchanged'
            )
            facts.update(cleanup="terminal-private-cleanup-stage-retained-if-present",
                actual_termination=result.termination.value,
                actual_exit_code=result.execution.exit_code,
                ledger=Ledger(budget, 1, True), worker_body_execution="not-asserted")

        assert PhysicalIdentity(executable.stat()) == original_executable_identity, (
            'Original selected executable physical identity must remain unchanged'
        )
        assert stat.S_IMODE(executable.stat().st_mode) == 0o400, (
            'Selected genuine scanner must remain read-only mode 0400'
        )
        assert not os.access(executable, os.X_OK), (
            'Snapshot acceptance must never grant scanner execution permission'
        )
        assert Digest(executable) == NATIVE_CONFIGURATION_EXECUTABLE_SHA256, (
            'Selected scanner must still match the unmodified production pin'
        )
        Settled(observer, recorder)
        facts["outcome"] = "installed-helper-assertions-passed"

    finally:
        facts["helper_count"] = len(recorder.results)
        facts["receipt_sha256"] = recorder.receipt_hashes
        facts["pending_tasks"] = [task.get_coro().__qualname__ for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()]
        facts["private_controls_retained"] = [str(path) for path in observer._private]
        facts["terminal"] = observer._terminal
        facts["stage_retained"] = observer._stage_root is not None and observer._stage_root.exists()
        facts["stage_inventory"] = (
            StageInventory(observer._stage_root) if observer._terminal else [])


@pytest.mark.parametrize("case_id", CASE_IDS, ids=CASE_IDS)
def test_InstalledMaterialLifecycle(installed_context, monkeypatch, case_id):
    """Require real installed snapshot, refusal, preflight and cancellation ownership evidence."""

    context = installed_context
    directory = Path(context["evidence"]) / case_id
    directory.mkdir(mode=0o700)
    facts = {"schema_version": 1, "case_id": case_id, "commit": context["commit"],
        "tree": context["tree"], "wheel_sha256": context["wheel"]["sha256"],
        "module_hashes": context["module_hashes"], "network": context["network"],
        "parent_isolated": context["parent_isolated"], "evidence": str(directory),
        "python_version": sys.version, "environment_prefix": sys.prefix,
        "native_product_acceptance": False, "provider_executed": False, "quota": "UNKNOWN",
        "outcome": "unassessed"}

    try:
        asyncio.run(Exercise(case_id, context, monkeypatch, facts))

    finally:
        WriteJson(directory / "case.json", facts)
