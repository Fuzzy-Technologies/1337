# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent closed native-material owner and cumulative-budget contracts, without Trivy."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337 import native_image_observation as observation
from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.executors import (
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    LocalExecutionError,
    LocalExecutionResult,
    LocalExecutor,
)
from fuzzy1337.native_image_capture import NativeTrivySelection

OPERATION = "operation:owned-native-pair"
METADATA = {"NextUpdate": "2026-06-22T20:30:14Z", "UpdatedAt": "2026-06-22T14:30:14Z", "Version": 2}
MATERIAL = (
    ("archive", "owned.tar", b"owned material archive\n", 23,
     "ccb9d5de5d6ae89167b3d061c2565158b00d46edfd4232e61d6b99674431731e"),
    ("executable", "trivy-never-executed", b"owned material executable never run\n", 36,
     "ec57df03224cd11b422fc2a0999bdd73b8a16036bbe5d8cac7152f42ebf553e8"),
    ("database", "cache/db/trivy.db", b"owned material database\n", 24,
     "55a501658c8c44b7d460cfeca38912a094053206384d2e7f2514584240d8dcdd"),
    ("database-metadata", "cache/db/metadata.json",
     b'{"NextUpdate":"2026-06-22T20:30:14Z","UpdatedAt":"2026-06-22T14:30:14Z","Version":2}',
     84, "9191e1f0e5b052ffd2867aee380b6a2a0ea4d17745d4ee467cf84fbfa9289e78"),
)
ROLE_BOUNDS = [["archive", 536870912], ["executable", 268435456],
               ["database", 2147483648], ["database-metadata", 16384]]


@pytest.fixture
def owned_selection(tmp_path) -> NativeTrivySelection:
    """Write only four tiny selected regular files; the selected executable is never runnable."""

    for _, name, raw, size, digest in MATERIAL:
        assert len(raw) == size and hashlib.sha256(raw).hexdigest() == digest, (
            "Independent closed material fixture drifted from its handwritten byte identities"
        )
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    return NativeTrivySelection(tmp_path.resolve(), tmp_path / "trivy-never-executed",
        "owned.tar", "cache", ArtifactReadConsent("owner:contract", "read:closed-material"))


def Identity(path: Path) -> tuple[int, int, int, int, int]:
    """Measure only an explicit owned fixture path independently of observation implementation.

    Args:
        path: Exact selected regular file or private control file from this test.

    Returns:
        Device, inode, size and nanosecond modification/change times in the fixed original order.
    """

    info = path.stat(follow_symlinks=False)

    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


@pytest.fixture
def synthetic_wire(owned_selection, monkeypatch):
    """Use explicit offline executor doubles; this does not establish genuine helper acceptance."""

    if sys.platform != "linux":
        pytest.skip("The synthetic private Linux control contract needs POSIX file permissions")

    calls = []
    monkeypatch.setattr(observation, "RequireLinuxOwnership", lambda: None)

    async def Execute(executor, request, **options):
        """Return handwritten fixture facts through the real observer's closed wire validator."""

        argv = request.invocation.argv
        assert argv[:4] == (sys.executable, "-I", "-m",
                            "fuzzy1337.native_image_material_worker") and len(argv) == 7, (
            "Only the fixed installed material reader may receive private control arguments"
        )
        assert options.get("own_descendants") is True, "Material reads require descendant ownership"
        assert request.resources.max_stdout_bytes == 65536, "Private result bytes must stay bounded"
        path = Path(argv[4])
        assert path.name == "request.json" and (
            path.parent.parent == owned_selection.workspace_root
        ), (
            "Private control must belong to this selected workspace's own observation directory"
        )
        assert stat.S_IMODE(path.stat().st_mode) == 0o600 and (
            stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        ), "Private request and its operation directory must have exact 0600/0700 permissions"
        raw = path.read_bytes()
        control = json.loads(raw)
        assert len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == argv[5], (
            "The exact finite private request bytes must match the fixed command's digest"
        )
        assert tuple(int(value) for value in argv[6].split(",")) == Identity(path), (
            "The fixed command must retain the exact private request physical identity"
        )
        assert set(control) == {"schema_version", "nonce", "operation_reference", "workspace_id",
            "owner_reference", "read_consent", "selection", "directory_identity",
            "workspace_identity", "roles"}, "Private requests must have only the closed fields"
        assert control["schema_version"] == 1 and control["roles"] == ROLE_BOUNDS, (
            "The observer must preserve the exact ordered four roles and original byte ceilings"
        )
        assert control["operation_reference"] == OPERATION and (
            control["workspace_id"] == "workspace:contract"
            and control["owner_reference"] == "owner:contract"
            and control["read_consent"] == {"actor_ref": "owner:contract",
                                            "record_ref": "read:closed-material"}
        ), "The private request must bind its pair, workspace, owner and explicit read consent"
        assert control["selection"] == {
            "workspace_root": str(owned_selection.workspace_root),
            "executable": str(owned_selection.executable), "archive": "owned.tar",
            "cache_directory": "cache",
        }, "The private request must not replace or expand the original four selected paths"
        options["pre_launch"](request)
        options["pre_launch"](request)
        facts = []

        for role, name, _, size, digest in MATERIAL:
            selected = owned_selection.workspace_root / name
            missing = role in {"database", "database-metadata"} and not selected.exists()
            facts.append({"role": role, "path": str(selected),
                "size_bytes": None if missing else size, "sha256": None if missing else digest,
                "physical_identity": None if missing else Identity(selected)})

        result = {key: value for key, value in control.items() if key != "roles"}
        result.update({"request_sha256": argv[5], "request_identity": Identity(path),
                       "facts": facts,
                       "metadata": None if facts[-1]["sha256"] is None else METADATA})
        stdout = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        events = (ExecutionEvent(0, ExecutionEventKind.STARTED),
            ExecutionEvent(1, ExecutionEventKind.STDOUT, stdout),
            ExecutionEvent(2, ExecutionEventKind.COMPLETED,
                           termination=ExecutionTermination.PROCESS_EXIT))

        for event in events:
            options["on_event"](event)

        calls.append((request, path, control))

        return LocalExecutionResult(AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.01),
            ExecutionTermination.PROCESS_EXIT, stdout, b"", events)

    monkeypatch.setattr(LocalExecutor, "Execute", Execute)

    return calls


def AssertOriginalFacts(proof, selection: NativeTrivySelection) -> None:
    """Compare measured fields with independent tiny-file bytes and actual owned physical metadata.

    Args:
        proof: Issued observation proof from the production owner under the declared test boundary.
        selection: Current test's original explicit four-file selection.
    """

    assert len(proof.facts) == 4, "An observation must retain exactly four original material roles"

    for fact, (role, name, _, size, digest) in zip(proof.facts, MATERIAL, strict=True):
        path = selection.workspace_root / name
        assert (fact.role, fact.path, fact.size_bytes, fact.sha256, fact.physical_identity) == (
            role, str(path), size, digest, Identity(path)
        ), "Observed role/order/path/hash/length/physical metadata differs from the closed oracle"

    assert proof.Metadata() == METADATA, "The proof must retain exact selected schema-two metadata"
    detached = proof.Metadata()
    detached["Version"] = 99
    assert proof.Metadata() == METADATA, "A detached metadata consumer must not mutate the proof"
    assert hashlib.sha256(proof.metadata_json).hexdigest() == MATERIAL[-1][4], (
        "The canonical closed metadata must retain its original selected-file digest"
    )


def test_SimulatedWireProofBindsFourFactsToTheOriginalObserverAndPair(
    owned_selection, synthetic_wire,
):
    """Validate an explicitly simulated successful wire without claiming an actual helper run."""

    observer = observation.NativeImageMaterialObserver(owned_selection,
        "workspace:contract", "owner:contract")
    budget = observation.NativeImageObservationBudget()
    proof = asyncio.run(observer.Observe(budget, operation_reference=OPERATION))
    AssertOriginalFacts(proof, owned_selection)
    assert budget.ObservationCount == 1 and not budget.Failed, (
        "One successfully admitted simulated result must consume exactly one observation slot"
    )
    request, path, control = synthetic_wire[0]
    assert proof.operation_reference == OPERATION and (
        proof.workspace_id == "workspace:contract" and proof.owner_reference == "owner:contract"
        and proof.observation_id == control["nonce"]
        and proof.control_sha256 == request.invocation.argv[5]
    ), "The issued proof must bind its original private control, nonce, pair and owning context"
    assert not path.exists() and not path.parent.exists(), (
        "Confirmed successful private control cleanup belongs to its observation owner"
    )
    assert len(proof.Digest()) == 64 and proof.Digest() == proof.Digest(), (
        "The finite proof digest must stay stable after detached metadata mutation"
    )
    observer.CheckCurrent(proof, operation_reference=OPERATION)

    for substituted in (proof.facts, replace(proof)):
        with pytest.raises(observation.NativeImageObservationError):
            observer.CheckCurrent(substituted, operation_reference=OPERATION)

    other = observation.NativeImageMaterialObserver(owned_selection,
        "workspace:contract", "owner:contract")

    with pytest.raises(observation.NativeImageObservationError):
        other.CheckCurrent(proof, operation_reference=OPERATION)

    with pytest.raises(observation.NativeImageObservationError):
        observer.CheckCurrent(proof, operation_reference="operation:another-pair")

    observer.selection = replace(owned_selection,
        read_consent=ArtifactReadConsent("owner:contract", "read:changed-consent"))

    with pytest.raises(observation.NativeImageObservationError):
        observer.CheckCurrent(proof, operation_reference=OPERATION)


@pytest.mark.parametrize("missing_roles", [
    ("database-metadata",), ("database", "database-metadata"),
])
def test_SimulatedOptionalAbsenceStaysExplicitUntilTheSelectedLeafAppears(
    owned_selection, synthetic_wire, missing_roles,
):
    """Describe missing optional material without inventing metadata or a VERSION proof."""

    del synthetic_wire

    for role, name, _, _, _ in MATERIAL:
        if role in missing_roles:
            (owned_selection.workspace_root / name).unlink()

    observer = observation.NativeImageMaterialObserver(owned_selection,
        "workspace:contract", "owner:contract")
    proof = asyncio.run(observer.Observe(observation.NativeImageObservationBudget(),
        operation_reference=OPERATION))
    assert len(proof.facts) == 4, "Optional absence must preserve all four original ordered roles"

    for fact, (role, name, _, size, digest) in zip(proof.facts, MATERIAL, strict=True):
        path = owned_selection.workspace_root / name
        expected = (None, None, None) if role in missing_roles else (size, digest, Identity(path))
        assert (fact.role, fact.path) == (role, str(path)) and (
            fact.size_bytes, fact.sha256, fact.physical_identity
        ) == expected, "Optional absence must retain its exact role/path and three null facts"

    assert proof.Metadata() is None and proof.metadata_json == b"null", (
        "Absent selected metadata must remain absent instead of an invented empty metadata object"
    )
    assert len(proof.Digest()) == 64, "Descriptive absence proof must retain bounded identity"
    observer.CheckCurrent(proof, operation_reference=OPERATION)
    appeared = next(item for item in MATERIAL if item[0] == missing_roles[0])
    (owned_selection.workspace_root / appeared[1]).write_bytes(appeared[2])

    with pytest.raises(observation.NativeImageObservationError):
        observer.CheckCurrent(proof, operation_reference=OPERATION)


def test_SimulatedUnknownCleanupRetainsOnlyPrivateControlAndIssuesNoProof(
    owned_selection, synthetic_wire, monkeypatch,
):
    """Simulated unknown cleanup retains private association instead of deleting it."""

    del synthetic_wire
    requests = []

    async def UnknownCleanup(executor, request, **options):
        """Represent unknown cleanup without starting any fixture process or selected-file read."""

        options["pre_launch"](request)
        requests.append(request)
        raise LocalExecutionError("owned synthetic cleanup is deliberately unconfirmed")

    monkeypatch.setattr(LocalExecutor, "Execute", UnknownCleanup)
    observer = observation.NativeImageMaterialObserver(owned_selection,
        "workspace:contract", "owner:contract")
    budget = observation.NativeImageObservationBudget()

    with pytest.raises(observation.NativeImageObservationError):
        asyncio.run(observer.Observe(budget, operation_reference=OPERATION))

    path = Path(requests[0].invocation.argv[4])
    assert path.is_file() and stat.S_IMODE(path.stat().st_mode) == 0o600 and (
        stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    ), "Unconfirmed helper cleanup must preserve its finite private 0600/0700 control association"
    assert budget.Failed and budget.ObservationCount == 1, (
        "Unknown cleanup cannot issue a proof, erase the charged slot or permit a fresh observation"
    )

    with pytest.raises(observation.NativeImageObservationError):
        budget.BeginObservation()


def test_ActualInstalledHelperReadsTheClosedSelectionWithoutExecutingTrivy(owned_selection):
    """Run the real isolated Python reader on capable Linux; this is not Trivy acceptance."""

    if sys.platform != "linux":
        pytest.skip("Actual installed material observation requires Linux descendant ownership")

    try:
        observation.RequireLinuxOwnership()

    except LocalExecutionError:
        if os.environ.get("FUZZY1337_RUN_DESCENDANT_ACCEPTANCE") == "1":
            pytest.fail("Required actual Linux material helper lacks descendant ownership")

        pytest.skip("Actual material-helper ownership is unavailable; not acceptance")

    observer = observation.NativeImageMaterialObserver(owned_selection,
        "workspace:contract", "owner:contract")
    budget = observation.NativeImageObservationBudget()
    proof = asyncio.run(observer.Observe(budget, operation_reference=OPERATION))
    AssertOriginalFacts(proof, owned_selection)
    observer.CheckCurrent(proof, operation_reference=OPERATION)
    assert proof.workspace_identity == Identity(owned_selection.workspace_root)[:2], (
        "The actual helper proof must bind the original physical workspace parent"
    )
    assert budget.ObservationCount == 1 and not budget.Failed, (
        "The actual installed read-only helper must complete exactly one bounded observation"
    )


def test_ThreeInclusiveSlotsAndOneReserveChargeActualElapsedWithoutReset(monkeypatch):
    """One operation retains three twelve-second caps and a separate nine-second reserve."""

    clock = [100.0]
    monkeypatch.setattr(observation, "monotonic", lambda: clock[0])
    budget = observation.NativeImageObservationBudget(overall_deadline=300)

    for index in range(3):
        window = budget.BeginObservation()
        assert window.started_at == clock[0] and window.deadline == clock[0] + 12, (
            "Each of the three observation phases must include readiness, work and cleanup"
        )
        assert window.working_deadline == window.deadline - 3 and window.WorkerSeconds() == 6, (
            "A worker may use six seconds only while reserving cleanup inside its phase"
        )
        clock[0] += 6
        assert window.WorkerSeconds() == 3, "Elapsed observation time cannot renew worker allowance"
        clock[0] += 3
        budget.FinishObservation(window, successful=True)
        assert budget.SpentSeconds == 9 * (index + 1), (
            "Actual inclusive observation overhead must accumulate across the entire operation"
        )
        assert budget.ObservationCount == index + 1, "One operation must retain each consumed slot"

    finalization = budget.BeginFinalization()
    assert finalization.deadline == clock[0] + 9, (
        "Three observations must leave the independent finalization reserve available"
    )
    clock[0] += 8
    budget.FinishFinalization(finalization)
    assert budget.SpentSeconds == 35 and budget.FinalizationSeconds == 8, (
        "Actual finalization time must debit the same ledger without resetting its observation cost"
    )

    with pytest.raises(observation.NativeImageObservationError):
        budget.BeginObservation()


def test_FailedSlotKeepsReservedFinalizationWithinTheOverallDeadline(monkeypatch):
    """A failed observation prevents another hash while preserving bounded custody finalization."""

    clock = [100.0]
    monkeypatch.setattr(observation, "monotonic", lambda: clock[0])
    budget = observation.NativeImageObservationBudget(overall_deadline=105)
    window = budget.BeginObservation()
    assert window.deadline == 105 and window.working_deadline == 102, (
        "The overall absolute deadline must cap the phase and its internal cleanup reservation"
    )
    assert window.WorkerSeconds() == 2, "A short overall deadline cannot grant a fresh six seconds"
    clock[0] = 101
    budget.FinishObservation(window, successful=False)
    assert budget.Failed and budget.SpentSeconds == 1, "A failed observation must debit and latch"

    with pytest.raises(observation.NativeImageObservationError):
        budget.BeginObservation()

    finalization = budget.BeginFinalization()
    assert finalization.deadline == 105, "Reserved finalization must obey the absolute deadline"
    clock[0] = 104
    budget.FinishFinalization(finalization)
    assert budget.SpentSeconds == 4 and budget.FinalizationSeconds == 3, (
        "Failed observation and finalization must share actual cumulative elapsed overhead"
    )


def test_PreCancelledObservationCannotLaunchAnyMaterialWorker(owned_selection, monkeypatch):
    """A preset cancellation refuses before helper launch; bounded metadata preflight is allowed."""

    calls = []

    async def RejectUnexpectedExecution(executor, request, **options):
        """Record a forbidden helper attempt without starting a subprocess or reading material."""

        calls.append((request, options))
        raise AssertionError("Pre-cancelled material observation attempted a worker launch")

    monkeypatch.setattr(LocalExecutor, "Execute", RejectUnexpectedExecution)
    observer = observation.NativeImageMaterialObserver(owned_selection,
        "workspace:contract", "owner:contract")
    cancellation = asyncio.Event()
    cancellation.set()

    with pytest.raises(observation.NativeImageObservationError):
        asyncio.run(observer.Observe(observation.NativeImageObservationBudget(),
            operation_reference=OPERATION, cancellation=cancellation))

    assert calls == [], "A pre-cancelled read observation must not enter the executor"


def test_ActuallyUnsupportedOwnershipCannotLaunchAnyMaterialWorker(owned_selection, monkeypatch):
    """An actually unsupported kernel refuses before selected content reads or helper launch."""

    if sys.platform == "linux":
        try:
            with Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children").open("rb"):
                pass

        except OSError:
            pass

        else:
            pytest.skip("The negative contract requires an actually unavailable child interface")

    calls = []

    async def RejectUnexpectedExecution(executor, request, **options):
        """Record a forbidden helper attempt while leaving every selected file unread."""

        calls.append((request, options))
        raise AssertionError("Unsupported material ownership attempted a worker launch")

    monkeypatch.setattr(LocalExecutor, "Execute", RejectUnexpectedExecution)
    observer = observation.NativeImageMaterialObserver(owned_selection,
        "workspace:contract", "owner:contract")

    with pytest.raises(observation.NativeImageObservationError):
        asyncio.run(observer.Observe(observation.NativeImageObservationBudget(),
            operation_reference=OPERATION))

    assert calls == [], "Unsupported ownership must refuse before material-worker execution"
