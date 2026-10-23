# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded collector units use explicit offline executor doubles, never actual Trivy acceptance."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import stat
from dataclasses import fields, replace
from types import SimpleNamespace

import pytest

from fuzzy1337 import native_image_bounded_capture as bounded
from fuzzy1337 import native_image_capture as legacy
from fuzzy1337.adapters import AdapterExecution, AdapterRequest, ExecutionState, ImpactLevel
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import (
    ExecutionAuthorization,
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionResources,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionError,
    LocalExecutionResult,
    LocalExecutor,
)
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.native_image_admission import (
    ApplyVerifiedNativeTrivyImages,
    VerifyNativeTrivyImageReplay,
)
from fuzzy1337.native_image_observation import NativeImageObservationError
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration
from tests.unit.test_native_image_admission import REPORT
from tests.unit.test_native_image_material_worker import material_control as material_control
from tests.unit.test_native_image_observation import (
    observation_runner as observation_runner,
)
from tests.unit.test_native_image_observation import (
    simulated_observer as simulated_observer,
)

PAIR = "pair:collector-unit"


def Frames(path):
    """Independently verify the private finite framing and decode only owned unit journal bytes."""

    raw = path.read_bytes()
    assert len(raw) <= 32 * 1024 * 1024 and raw.startswith(b"1337-native-outcome-v1\n"), (
        "The collector journal must retain finite original framing"
    )
    cursor = len(b"1337-native-outcome-v1\n")
    values = []

    while cursor < len(raw):
        length = int.from_bytes(raw[cursor:cursor + 8], "big")
        digest = raw[cursor + 8:cursor + 40]
        value = raw[cursor + 40:cursor + 40 + length]
        assert len(value) == length and hashlib.sha256(value).digest() == digest, (
            "Each exact private original frame must independently retain its integrity"
        )
        values.append(json.loads(value))
        cursor += 40 + length

    assert cursor == len(raw), "Private framing cannot have an accepted partial suffix"

    return values


@pytest.fixture
def collector(simulated_observer, observation_runner, monkeypatch):
    """Reuse the actual opaque-proof issuer with a separate explicit provider executor double."""

    original_observer, wire = simulated_observer
    original_selection = original_observer.selection
    root = original_selection.workspace_root / "collector"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned bounded collector"),
                                     "collector-unit")
    shutil.copyfile(original_selection.executable, root / "trivy")
    shutil.copyfile(original_selection.workspace_root / original_selection.archive,
                    root / "image.tar")
    shutil.copytree(original_selection.workspace_root / original_selection.cache_directory,
                    root / "cache", dirs_exist_ok=True)
    selection = replace(original_selection, workspace_root=root, executable=root / "trivy")
    observer = bounded.NativeImageMaterialObserver(selection, "collector-unit", "actor:unit")
    store = LocalEvidenceStore(selection.workspace_root / "evidence")
    budget = bounded.NativeImageObservationBudget()
    wire_execute = LocalExecutor.Execute
    state = SimpleNamespace(mode="success", calls=[], started=asyncio.Event(),
        cleanup=False, revoked=False, checks=[], after=None, reading=False, raw=None)
    monkeypatch.setattr(bounded, "RequireLinuxOwnership", lambda: None)

    if os.name == "nt":
        # These are portable protocol units, not Windows permission/directory-fsync acceptance.
        selected_os = SimpleNamespace(**vars(os))
        selected_os.fchmod = lambda descriptor, mode: None
        monkeypatch.setattr(bounded, "os", selected_os)
        monkeypatch.setattr(bounded, "stat", SimpleNamespace(S_IMODE=lambda mode:
            0o700 if stat.S_ISDIR(mode) else 0o600))
        monkeypatch.setattr(bounded.OutcomeJournal, "SyncDirectory", lambda owner: None)

    async def Execute(executor, request, **options):
        """Report original events and await only the explicit cooperative owner signal."""

        if request.invocation.adapter_id == "native.material-observer":
            state.reading = True

            try:
                return await wire_execute(executor, request, **options)

            finally:
                state.reading = False

        state.calls.append((request, options))

        try:
            assert options["own_descendants"] is True, "Every provider requires owned descendants."
            options["pre_launch"](request)
            options["pre_launch"](request)
            state.started.set()
            raw = json.dumps({"Version": "0.75.0", "VulnerabilityDB": initial.Metadata()}).encode()

            if request.invocation.provider_version is not None:
                raw = json.dumps(REPORT).encode()

            if state.raw is not None:
                raw = state.raw

            events = [ExecutionEvent(0, ExecutionEventKind.STARTED)]
            options["on_event"](events[0])

            if state.mode == "overflow":
                for index in range(1, 514):
                    options["on_event"](ExecutionEvent(index, ExecutionEventKind.STDOUT, b"x"))

                pytest.fail("An excessive original event count was accepted.")

            for kind, data in ((ExecutionEventKind.STDOUT, raw),
                               (ExecutionEventKind.STDERR, b"owned original stderr")):
                event = ExecutionEvent(len(events), kind, data)
                events.append(event)
                options["on_event"](event)

            if state.mode == "unknown":
                raise LocalExecutionError("controlled unknown cleanup")

            stop = ExecutionTermination.PROCESS_EXIT
            execution = (AdapterExecution(ExecutionState.FAILED, 7, 0.001)
                         if state.mode == "failed" else
                         AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.001))

            if state.mode == "pending":
                await options["cancellation"].wait()
                await asyncio.sleep(0)
                stop = ExecutionTermination.CANCELLATION
                execution = AdapterExecution(ExecutionState.CANCELLED, -9, 0.001)

            event = ExecutionEvent(len(events), ExecutionEventKind.COMPLETED, termination=stop)
            events.append(event)
            options["on_event"](event)

            if state.mode == "post-pending":
                wire.mode = "pending"

            if state.after is not None:
                state.after()

            return LocalExecutionResult(execution, stop,
                b"substituted" if state.mode == "mismatch" else raw,
                b"owned original stderr", tuple(events))

        finally:
            state.cleanup = True

    monkeypatch.setattr(LocalExecutor, "Execute", Execute)
    initial = observation_runner.run(observer.Observe(budget, operation_reference=PAIR))

    def Authority(request):
        """Model only a fresh synchronous upstream decision, never selected material reads."""

        state.checks.append(request)

        if state.revoked:
            raise RuntimeError("controlled authority revocation")

    def Invocation(operation, version=None):
        """Prepare the unchanged existing finite provider invocation and caller decision."""

        request = AdapterRequest("image.archive-vulnerabilities", "target:collector-unit",
            ImpactLevel.SAFE, {"archive": selection.archive,
                              "timeout_seconds": 3 if operation is (
                                  legacy.NativeTrivyOperation.VERSION) else 30})
        adapter = selection.Adapter(store, version)
        invocation = adapter.PrepareVersionInvocation(request) if operation is (
            legacy.NativeTrivyOperation.VERSION) else adapter.PrepareInvocation(request)
        authorization = ExecutionAuthorization("authorization:" + operation.value,
            "scope:collector-unit", "policy:collector-unit", InvocationDigest(invocation))

        return invocation, authorization

    def Capture(operation=legacy.NativeTrivyOperation.VERSION, *, prerequisite=None,
                proof=None, **options):
        """Construct one additive call; the test owns every selected byte and execution double."""

        invocation, authorization = Invocation(operation,
            None if prerequisite is None else prerequisite.observed_version)

        return bounded.CaptureBoundedNativeTrivyOperation(operation,
            options.pop("selection", selection), invocation, authorization, store,
            observer.workspace_id, observer.owner_reference,
            observer=options.pop("observer", observer), budget=options.pop("budget", budget),
            material_proof=initial if proof is None else proof,
            operation_reference=PAIR, version_prerequisite=prerequisite,
            validate_authority=options.pop("validate_authority", Authority), **options)

    return SimpleNamespace(observer=observer, wire=wire, selection=selection, store=store,
        budget=budget, initial=initial, state=state, Capture=Capture, Invocation=Invocation,
        run=observation_runner.run)


def test_BoundedPairUsesThreeProofsAndPreservesSixOriginalRolesWithoutLegacyHashing(
    collector, monkeypatch,
):
    """Post-VERSION reuse preserves original identities without a fourth observation."""

    original_material = legacy.NativeTrivySelection.Material

    def WorkerMaterial(owner):
        """Permit hashing only inside this explicit synthetic owned-worker double."""

        assert collector.state.reading, "The bounded collector called legacy Material on its loop."

        return original_material(owner)

    monkeypatch.setattr(legacy.NativeTrivySelection, "Material", WorkerMaterial)
    monkeypatch.setattr(legacy, "ObserveVersion",
        lambda *args: pytest.fail("The bounded collector must never reread selected metadata."))
    version = collector.run(collector.Capture())
    scan = collector.run(collector.Capture(legacy.NativeTrivyOperation.SCAN,
        prerequisite=version.capture, proof=version.material_proof))
    assert collector.budget.ObservationCount == 3, "A pair has only three full observations."
    assert 0 < collector.budget.FinalizationSeconds < 9, "Both operations share one reserve."
    assert version.capture.observed_version == "0.75.0" and version.capture.refusal is None, (
        "Original VERSION wire and verified selected metadata must agree"
    )
    assert scan.capture.refusal is None and scan.capture.version_prerequisite_sha256 == (
        version.capture.Digest()), "SCAN binds the actual original VERSION capture."
    assert version.capture.request.invocation.timeout_seconds == 3, "VERSION changed its deadline."
    assert scan.capture.request.invocation.timeout_seconds == 30, "Selected SCAN deadline changed."
    roles = [record.reference.role for item in (version, scan) for record in item.capture.records]
    assert roles == [
        "provider-version", "provider-version-stderr", "native-version-receipt",
        "stdout", "stderr", "native-scan-receipt"], "All six historical roles remain exact."

    for item in (version, scan):
        capture = item.capture
        assert collector.store.Read(capture.records[0].reference) == (
            capture.outcome.stdout), "Original stdout bytes changed during custody."
        assert collector.store.Read(capture.records[1].reference) == (
            capture.outcome.stderr), "Original stderr bytes changed during custody."
        assert collector.store.Read(capture.records[2].reference) == (
            legacy.SerializeContract(capture.Envelope()).encode()), "Receipt serialization changed."

    assert not tuple(collector.selection.workspace_root.glob("native-image-bounded-*")), (
        "Confirmed canonical custody releases its private journal and scratch"
    )


@pytest.mark.parametrize("failure", ["observer", "material", "authority"])
def test_PostRunRefusalPreservesActualRawOutcomeAndNeverAcceptsUnverifiedMaterial(
    collector, failure,
):
    """Post-run failures preserve original bytes with an explicit refused association."""

    if failure == "observer":
        collector.state.after = lambda: setattr(collector.wire, "mode", "timeout")

    elif failure == "material":
        collector.state.after = lambda: (collector.selection.workspace_root /
            collector.selection.archive).write_bytes(b"changed owned archive")

    else:
        collector.state.after = lambda: setattr(collector.state, "revoked", True)

    result = collector.run(collector.Capture())
    assert result.capture.outcome.execution.state is ExecutionState.SUCCEEDED, (
        "Post-run refusal must preserve the actual original process status"
    )
    assert result.capture.material_after is None and result.material_proof is None, (
        "A failed post-run check cannot supply usable selected material"
    )
    expected = ("authority-unverified" if failure == "authority"
                else "material-or-version-unverified")
    assert result.capture.refusal == expected and len(result.capture.records) == 3, (
        "A refused association must retain its exact three original roles"
    )
    assert collector.store.Read(result.capture.records[0].reference) == (
        result.capture.outcome.stdout), "Post-run refusal changed original stdout."


@pytest.mark.parametrize("failure", ["failed", "wire"])
def test_FailedOrUnverifiedOriginalVersionNeverBecomesAcceptedInventory(collector, failure):
    """A failed process or unverified wire cannot establish an accepted original VERSION."""

    if failure == "failed":
        collector.state.mode = "failed"

    else:
        collector.state.raw = b"owned non-JSON original version output"

    result = collector.run(collector.Capture())
    expected = ("execution-not-successful" if failure == "failed"
                else "material-or-version-unverified")
    assert result.capture.refusal == expected and result.capture.observed_version is None, (
        "A failed or unverified original VERSION supplied successful association"
    )
    assert collector.store.Read(result.capture.records[0].reference) == (
        result.capture.outcome.stdout), "Refused VERSION lost its actual original bytes."

    with pytest.raises(ValueError):
        collector.run(collector.Capture(legacy.NativeTrivyOperation.SCAN,
            prerequisite=result.capture, proof=result.material_proof or collector.initial))

    assert len(collector.state.calls) == 1, "A refused VERSION started SCAN."


@pytest.mark.parametrize("mode", ["unknown", "overflow", "mismatch"])
def test_NoOriginalTerminalOutcomeOrOverflowRetainsOnlyBoundedIncompletePrivateCustody(
    collector, mode,
):
    """Unknown cleanup and oversized event histories cannot become trimmed accepted receipts."""

    collector.state.mode = mode

    with pytest.raises(bounded.NativeImageBoundedCaptureError) as error:
        collector.run(collector.Capture())

    assert collector.state.cleanup, "The capture owner abandoned its provider execution task."
    path = error.value.journal_path
    assert path is not None and path.exists(), "Available private original custody was discarded."
    frames = Frames(path)
    assert not error.value.outcome_retained, "An unverified result became complete custody."
    assert len(frames) >= 1 and not tuple(collector.store.root.glob("records/*.json")), (
        "Incomplete fragments must not create an accepted canonical receipt"
    )

    if mode != "mismatch":
        incomplete = frames[-1]
        assert incomplete["state"] == "incomplete" and len(incomplete["events"]) < 512, (
            "Overflow cannot create a trimmed complete original event history"
        )
        assert len(bytes.fromhex(incomplete["stdout_hex"])) <= 16 * 1024, (
            "Incomplete original VERSION bytes still require their exact finite ceiling"
        )


def test_PublicationUncertaintyRetainsVerifiedPrivateOriginalOutcome(collector, monkeypatch):
    """A storage exception after acquisition cannot erase original bytes or claim full custody."""

    def Refuse(*args):
        """Simulate unavailable canonical storage without altering the private journal owner."""

        raise OSError("controlled publication failure")

    monkeypatch.setattr(collector.store, "Put", Refuse)

    with pytest.raises(bounded.NativeImageBoundedCaptureError,
                       match="publication-unconfirmed") as error:
        collector.run(collector.Capture())

    assert error.value.outcome_retained and error.value.journal_path is not None, (
        "Uncertain publication must retain the actual complete private original"
    )
    complete = Frames(error.value.journal_path)[-1]
    control = Frames(error.value.journal_path)[0]["control"]
    assert control["observation_id"] == collector.initial.observation_id and (
        control["proof_sha256"] == collector.initial.Digest()
        and control["workspace_identity"] == list(collector.initial.workspace_identity)
        and control["pair_reference"] == PAIR
    ), "Private journal custody must retain its exact proof, nonce and parent association."
    assert complete["state"] == "complete" and bytes.fromhex(complete["stderr_hex"]) == (
        b"owned original stderr"), "Original terminal bytes must survive publication uncertainty."


@pytest.mark.parametrize("phase", ["provider", "post-observation"])
def test_OuterCancellationAwaitsOwnedCleanupAndDurableOriginalFinalization(collector, phase):
    """Cancellation cannot abandon a shielded task or erase already acquired original streams."""

    collector.state.mode = "pending" if phase == "provider" else "post-pending"

    async def Run():
        """Cancel only after the controlled provider or post-run read is actually active."""

        task = asyncio.create_task(collector.Capture())
        barrier = collector.state.started if phase == "provider" else collector.wire.started
        await asyncio.wait_for(barrier.wait(), 1)

        if phase == "post-observation":
            paths = tuple(collector.selection.workspace_root.glob(
                "native-image-bounded-*/outcome.journal"))
            assert len(paths) == 1 and Frames(paths[0])[-1]["state"] == "complete", (
                "Complete original custody must precede the first post-observation await"
            )

        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

        assert task.done() and collector.state.cleanup, "An owned task outlived its capture owner."

    collector.run(Run())
    manifests = tuple(collector.store.root.glob("records/*.json"))
    assert len(manifests) == 3, "Both original streams and refusal must finalize on cancellation."
    assert not tuple(collector.selection.workspace_root.glob("native-image-bounded-*")), (
        "Confirmed cancelled custody still owns unnecessary recovery staging"
    )


def test_PreCancelledOrForeignProofNeverStartsProviderOrCreatesCustody(collector):
    """A previous digest or an already cancelled operation cannot become execution authority."""

    event = asyncio.Event()
    event.set()

    with pytest.raises(asyncio.CancelledError):
        collector.run(collector.Capture(cancellation=event))

    with pytest.raises(NativeImageObservationError):
        collector.run(collector.Capture(proof=replace(collector.initial)))

    assert collector.state.calls == [], "Refused proof/cancellation reached the provider."
    assert not tuple(collector.selection.workspace_root.glob("native-image-bounded-*")), (
        "A pre-cancelled or foreign proof cannot create collector custody"
    )


def test_ExactIncrementalBytesAndTerminalReserveDoNotRechunkOriginalEvents():
    """Even enlarged portable stream resources cannot bypass the fixed event encoding ceiling."""

    events = bounded.OriginalEvents(legacy.NativeTrivyOperation.VERSION,
        ExecutionResources(max_stdout_bytes=1024 * 1024))
    event = ExecutionEvent(0, ExecutionEventKind.STDOUT, b"x" * (96 * 1024))

    with pytest.raises(ValueError, match="ceiling"):
        events.Observe(event)

    assert events.events == [] and events.stdout == b"", "An oversized event was trimmed/admitted."


@pytest.mark.parametrize("role", ["trivy.db", "metadata.json"])
def test_DescriptiveMissingMaterialProofCannotStartBoundedNativeProvider(collector, role):
    """An exact observation of absence stays descriptive rather than become execution permission."""

    selected = (collector.selection.workspace_root / collector.selection.cache_directory /
                "db" / role)
    selected.unlink()
    proof = collector.run(collector.observer.Observe(collector.budget, operation_reference=PAIR))

    with pytest.raises(ValueError, match="selected database material"):
        collector.run(collector.Capture(proof=proof))

    assert collector.state.calls == [], "Descriptive missing material started the provider."


def test_UnsupportedOwnershipRefusesBeforeAnyCollectorJournalOrProvider(collector, monkeypatch):
    """An old proof cannot bypass the currently unavailable Linux ownership prerequisite."""

    def Refuse():
        """Model only the explicit current unsupported-kernel admission refusal."""

        raise LocalExecutionError("controlled unsupported ownership")

    monkeypatch.setattr(bounded, "RequireLinuxOwnership", Refuse)

    with pytest.raises(LocalExecutionError, match="unsupported ownership"):
        collector.run(collector.Capture())

    assert collector.state.calls == [], "Unsupported ownership reached the provider."
    assert not tuple(collector.selection.workspace_root.glob("native-image-bounded-*")), (
        "Unsupported ownership must refuse before collector control creation"
    )


def test_RevocationAtTheSecondFreshLaunchHookNeverStartsProvider(collector):
    """The same original request must remain authorized at the actual post-READY hook."""

    checks = []

    def Authority(request):
        """Revoke only after the initial check, before the second exact launch hook."""

        checks.append(request)

        if len(checks) == 2:
            raise PermissionError("controlled fresh revocation")

    with pytest.raises(bounded.NativeImageBoundedCaptureError):
        collector.run(collector.Capture(validate_authority=Authority))

    assert len(checks) == 2 and checks[0] is checks[1], "The exact fresh request was substituted."
    assert not collector.state.started.is_set() and collector.state.cleanup, (
        "Revoked current launch authority started or abandoned the provider"
    )
    assert len(collector.wire.calls) == 1, "Refused execution started another material helper."


def test_AwaitableFinalAuthorityIsClosedAndRefusesAssociation(collector):
    """A later asynchronous validator cannot create an unowned task or accepted association."""

    checks = []
    coroutines = []

    async def InvalidAuthority():
        """Represent a callback that must never actually be awaited or scheduled."""

        pytest.fail("The collector executed an asynchronous policy callback.")

    def Authority(request):
        """Return an invalid coroutine only at the final original-publication boundary."""

        checks.append(request)

        if len(checks) == 4:
            coroutine = InvalidAuthority()
            coroutines.append(coroutine)

            return coroutine

        return None

    result = collector.run(collector.Capture(validate_authority=Authority))
    assert result.capture.refusal == "authority-unverified", "Awaitable authority was accepted."
    assert len(coroutines) == 1 and coroutines[0].cr_frame is None, (
        "An invalid authority coroutine remained live after capture"
    )


def test_SubstitutedOriginalVersionCannotLaunchBoundedScan(collector):
    """Finite historical validation still binds original VERSION bytes and immutable custody."""

    version = collector.run(collector.Capture())
    changed = replace(version.capture,
        outcome=replace(version.capture.outcome, stdout=b"substituted original stdout"))

    with pytest.raises(ValueError, match="original executor bytes"):
        collector.run(collector.Capture(legacy.NativeTrivyOperation.SCAN,
            prerequisite=changed, proof=version.material_proof))

    assert len(collector.state.calls) == 1, "A substituted VERSION started SCAN."


def test_AdditiveHistoricalFacadeForwardsExactTypedOwnersAndFreshAuthority(collector):
    """The lazy facade retains request, proof and authority without an import cycle."""

    operation = legacy.NativeTrivyOperation.VERSION
    invocation, authorization = collector.Invocation(operation)
    checks = []
    result = collector.run(legacy.CaptureBoundedNativeTrivyOperation(operation,
        collector.selection, invocation, authorization, collector.store,
        collector.observer.workspace_id,
        collector.observer.owner_reference, observer=collector.observer, budget=collector.budget,
        material_proof=collector.initial, operation_reference=PAIR,
        validate_authority=checks.append))
    assert result.capture.refusal is None and result.material_proof is not None, (
        "The additive facade lost its exact original successful capture or post-proof"
    )
    assert len(checks) == 4 and all(item is result.capture.request for item in checks), (
        "The lazy facade must retain every original fresh authority boundary"
    )


def test_CanonicalAcknowledgementSubstitutionRetainsPrivateOriginal(collector, monkeypatch):
    """A foreign manifest acknowledgement cannot replace an original native operation owner."""

    put = collector.store.Put

    def Substitute(*args):
        """Publish actual bytes, then report a contradictory provenance acknowledgement."""

        record = put(*args)

        return replace(record, provenance=replace(record.provenance,
            scope_reference="scope:foreign-ack"))

    monkeypatch.setattr(collector.store, "Put", Substitute)

    with pytest.raises(bounded.NativeImageBoundedCaptureError,
                       match="publication-unconfirmed") as error:
        collector.run(collector.Capture())

    assert error.value.outcome_retained and error.value.journal_path is not None, (
        "Contradictory storage acknowledgement erased private original custody"
    )
    assert Frames(error.value.journal_path)[-1]["state"] == "complete", (
        "Acknowledgement uncertainty replaced the original terminal outcome"
    )


def test_JournalRejectsExactTotalOverflowAndCorruptOriginalFrame(tmp_path, monkeypatch):
    """Finite journal framing cannot grow beyond its ceiling or accept changed original bytes."""

    if os.name == "nt":
        pytest.skip("Actual private permission/fsync requires POSIX; portable doubles are separate")

    journal = bounded.OutcomeJournal(tmp_path)

    try:
        journal.Append({"state": "owned", "raw": "unchanged"})
        assert stat.S_IMODE(journal.directory.stat().st_mode) == 0o700, (
            "Actual private collector directories require exact owner-only mode"
        )
        assert stat.S_IMODE(journal.path.stat().st_mode) == 0o600, (
            "Actual private journal files require exact owner-only mode"
        )
        before = journal.path.read_bytes()
        monkeypatch.setattr(bounded, "JOURNAL_BYTES", len(before) + 40)

        with pytest.raises(ValueError, match="ceiling"):
            journal.Append({"raw": "x" * 100})

        assert journal.path.read_bytes() == before, "Overflow altered an existing original frame."
        os.lseek(journal.descriptor, len(bounded.JOURNAL_MAGIC) + 40, os.SEEK_SET)
        os.write(journal.descriptor, b"!")

        with pytest.raises(ValueError, match="integrity"):
            journal.Verify()

    finally:
        journal.Close()


def test_BoundedPairPassesUnchangedHistoricalReplayAndCanonicalAdmission(collector):
    """Original bounded roles compose with actual historical owners and a pure model proposal."""

    root = collector.selection.workspace_root
    workspace = LocalWorkspaceStore(root).Open()
    model = LocalModelStore(root).Create()
    version = collector.run(collector.Capture())
    scan = collector.run(collector.Capture(legacy.NativeTrivyOperation.SCAN,
        prerequisite=version.capture, proof=version.material_proof))
    replay = VerifyNativeTrivyImageReplay((*version.capture.records, *scan.capture.records), root)
    proposed, delta = ApplyVerifiedNativeTrivyImages(model, version.capture, scan.capture, root)
    assert replay.version_request == version.capture.request and replay.scan_request == (
        scan.capture.request), "Bounded originals must pass historical request admission."
    assert proposed.revision == 1 and delta.created, "The pair must admit one canonical batch."
    assets = [item for item in proposed.objects if item.identity.kind is ObjectKind.ASSET]
    assert {item.attributes["asset_type"] for item in assets} == {"image", "package"}, (
        "Bounded successful originals must admit both original image and installed package"
    )
    assert any(item.identity.kind is ObjectKind.FINDING for item in proposed.objects), (
        "The actual historical admission owner must preserve the controlled package finding"
    )
    assert LocalWorkspaceStore(root).Open() == workspace and (
        LocalModelStore(root).Open() == model
    ), (
        "Pure bounded admission must preserve both independently persisted authoritative snapshots"
    )
    assert not tuple(root.glob("native-image-*")), "Confirmed original staging must be removed."


@pytest.mark.parametrize("replacement", ["observer", "budget", "proof", "selection"])
def test_ReplacementOwnerSubclassesRefuseBeforeAnyOverrideOrProvider(collector, replacement):
    """The additive closed path never accepts caller replacements for material or ledger owners."""

    called = []

    class ReplacementObserver(bounded.NativeImageMaterialObserver):
        """Model a caller replacement whose material callbacks must remain unreachable."""

        async def Observe(self, *args, **kwargs):
            """Record an impermissible replacement callback if reached."""

            called.append("observer-observe")
            raise AssertionError("Replacement observer was invoked")

        def CheckCurrent(self, *args, **kwargs):
            """Record an impermissible replacement check if reached."""

            called.append("observer-check")
            raise AssertionError("Replacement observer was invoked")

    class ReplacementBudget(bounded.NativeImageObservationBudget):
        """Model a caller replacement for the original cumulative reserve."""

        def BeginFinalization(self):
            """Record an impermissible replacement reserve callback if reached."""

            called.append("budget")
            raise AssertionError("Replacement budget was invoked")

    class ReplacementProof(bounded.NativeImageMaterialProof):
        """Model a caller replacement for fixed immutable material facts."""

        def Metadata(self):
            """Record an impermissible replacement proof callback if reached."""

            called.append("proof")
            raise AssertionError("Replacement proof was invoked")

    class ReplacementSelection(legacy.NativeTrivySelection):
        """Model a caller replacement for the original finite provider factory."""

        def Adapter(self, *args, **kwargs):
            """Record an impermissible replacement factory callback if reached."""

            called.append("selection")
            raise AssertionError("Replacement selection was invoked")

    options = {}

    if replacement == "observer":
        options[replacement] = ReplacementObserver(collector.selection,
            collector.observer.workspace_id, collector.observer.owner_reference)

    elif replacement == "budget":
        options[replacement] = ReplacementBudget()

    elif replacement == "proof":
        options[replacement] = ReplacementProof(**{
            field.name: getattr(collector.initial, field.name)
            for field in fields(bounded.NativeImageMaterialProof)})

    else:
        options[replacement] = ReplacementSelection(**{
            field.name: getattr(collector.selection, field.name)
            for field in fields(legacy.NativeTrivySelection)})

    with pytest.raises(ValueError, match="original typed owners"):
        collector.run(collector.Capture(**options))

    assert called == [] and collector.state.calls == [], (
        "A replacement material owner, ledger, proof or factory must remain wholly uninvoked"
    )
    assert not tuple(collector.selection.workspace_root.glob("native-image-*")), (
        "Refused replacement owners must not create collector journal or execution scratch"
    )


@pytest.mark.parametrize("schema", [2.0, True])
def test_NonIntegerObservedDatabaseSchemaNeverEstablishesScanPrerequisite(collector, schema):
    """Python numeric equality cannot weaken historical exact-integer schema admission."""

    metadata = collector.initial.Metadata()
    metadata["Version"] = schema
    collector.state.raw = json.dumps({"Version": "0.75.0", "VulnerabilityDB": metadata}).encode()
    version = collector.run(collector.Capture())
    assert version.capture.refusal == "material-or-version-unverified" and (
        version.capture.observed_version is None
    ), "Only an exact observed integer schema two may establish a supported VERSION."

    with pytest.raises(ValueError):
        collector.run(collector.Capture(legacy.NativeTrivyOperation.SCAN,
            prerequisite=version.capture, proof=version.material_proof or collector.initial))

    assert len(collector.state.calls) == 1, "An invalid observed database schema launched SCAN."


@pytest.mark.parametrize("selected_field", ["executable", "cache_directory", "read_consent"])
def test_ProofForDifferentSelectedMaterialNeverStartsProvider(collector, selected_field):
    """A same-workspace proof cannot cover a different executable, cache or consent."""

    changes = {"executable": collector.selection.workspace_root / "different-executable",
        "cache_directory": "different-cache",
        "read_consent": replace(collector.selection.read_consent, record_ref="read:different")}
    selected = replace(collector.selection, **{selected_field: changes[selected_field]})

    with pytest.raises(ValueError, match="selected material differ"):
        collector.run(collector.Capture(selection=selected))

    assert collector.state.calls == [], "A proof for material A reached selected provider B."
    assert not tuple(collector.selection.workspace_root.glob("native-image-*")), (
        "An unassociated selection cannot create private custody or execution scratch"
    )


def test_ObserverSelectionChangeAtReadyRefusesBeforeProviderStart(collector):
    """The final owned READY hook repeats full selected-material association after fresh policy."""

    checks = []

    def Revalidate(request):
        """Mutate only at the synthetic second owned launch hook, after initial process setup."""

        checks.append(request)

        if len(checks) == 2:
            collector.observer.selection = replace(collector.selection,
                cache_directory="different-cache")

    with pytest.raises(bounded.NativeImageBoundedCaptureError):
        collector.run(collector.Capture(validate_authority=Revalidate))

    assert len(checks) == 2 and not collector.state.started.is_set(), (
        "A READY-time observer selection change must refuse before any provider-start event"
    )
    assert len(collector.wire.calls) == 1, "Changed association cannot start a post-read helper."


def test_ReplacedSiblingScratchCannotBeRemovedAsOwnedJournalCleanup(tmp_path):
    """The journal cleanup owner independently binds the original sibling scratch inode."""

    if os.name == "nt":
        pytest.skip("Actual private permissions require POSIX; portable doubles are separate")

    journal = bounded.OutcomeJournal(tmp_path)
    original = tmp_path / "original-scratch"

    try:
        journal.scratch.rename(original)
        journal.scratch.mkdir(mode=0o700)

        with pytest.raises(ValueError, match="identity differs"):
            journal.RemoveConfirmed()

        assert original.is_dir() and journal.scratch.is_dir() and journal.path.is_file(), (
            "Refused scratch substitution must preserve replacement and original recovery bytes"
        )

    finally:
        journal.Close()
