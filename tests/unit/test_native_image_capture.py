# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Descriptive native custody and refusal invariants using explicitly simulated executor results."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.adapters import AdapterExecution, AdapterRequest, ExecutionState, ImpactLevel
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import (
    ExecutionAuthorization,
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionResult,
    LocalExecutor,
)
from fuzzy1337.native_image_capture import (
    CaptureNativeTrivyOperation,
    NativeTrivyOperation,
    NativeTrivySelection,
    SelectedFile,
)

METADATA = {"Version": 2, "UpdatedAt": "2026-06-22T14:30:14Z",
            "NextUpdate": "2026-06-22T20:30:14Z"}
VERSION = {"Version": "0.75.0", "VulnerabilityDB": METADATA}


@pytest.fixture(scope="module")
def capture_runner():
    """Initialize owned Windows loop resources before the unchanged unit network guard."""

    with asyncio.Runner() as runner:
        runner.get_loop()

        yield runner


@pytest.fixture
def owned(tmp_path):
    """Create tiny explicit physical selections and canonical evidence without native acceptance."""

    root = tmp_path.resolve()
    (root / "evidence").mkdir()
    database = root / "trivy-cache" / "db"
    database.mkdir(parents=True)
    (database / "trivy.db").write_bytes(b"owned simulated database bytes")
    (database / "metadata.json").write_text(json.dumps(METADATA))
    (root / "owned.tar").write_bytes(b"owned simulated archive bytes")
    executable = root / "trivy"
    executable.write_bytes(b"owned non-executed fixture binary")
    selection = NativeTrivySelection(root, executable, "owned.tar", "trivy-cache",
        ArtifactReadConsent("owner:unit", "read:explicit-unit-files"))

    return selection, LocalEvidenceStore(root / "evidence")


def Invocation(selection, store, *, operation=NativeTrivyOperation.VERSION, version=None):
    """Prepare exact existing adapter metadata while granting no execution or model authority."""

    request = AdapterRequest("image.archive-vulnerabilities", "target:owned-unit", ImpactLevel.SAFE,
        {"archive": "owned.tar", "timeout_seconds": 3 if operation is NativeTrivyOperation.VERSION
         else 30})
    adapter = selection.Adapter(store, version)

    if operation is NativeTrivyOperation.VERSION:
        return adapter.PrepareVersionInvocation(request)

    return adapter.PrepareInvocation(request)


def Authority(invocation, identifier):
    """Declare explicit caller-owned simulated authorization, not factory-created permission."""

    return ExecutionAuthorization(identifier, "scope:owned-unit", "policy:unit",
                                  InvocationDigest(invocation))


def Result(raw, *, state=ExecutionState.SUCCEEDED, termination=ExecutionTermination.PROCESS_EXIT):
    """Represent simulated original executor outcomes; this is never genuine scanner evidence."""

    exit_code = 0 if state is ExecutionState.SUCCEEDED else (
        7 if state is ExecutionState.FAILED else None)

    return LocalExecutionResult(AdapterExecution(state, exit_code, 0.01),
        termination, raw, b"owned-stderr",
        (ExecutionEvent(0, ExecutionEventKind.STARTED),
         ExecutionEvent(1, ExecutionEventKind.COMPLETED, termination=termination)))


@pytest.fixture
def executor(monkeypatch):
    """Simulate the existing executor boundary and still call its exact final launch validation."""

    calls = []
    result = [Result(json.dumps(VERSION).encode())]
    mutate = [None]

    async def Execute(self, request, **options):
        """Return controlled raw facts after the real producer's pre-launch callback."""

        calls.append(request)
        options["pre_launch"](request)

        if mutate[0] is not None:
            mutate[0]()

        return result[0]

    monkeypatch.setattr(LocalExecutor, "Execute", Execute)

    return calls, result, mutate


def Capture(capture_runner, owned, executor, *, operation=NativeTrivyOperation.VERSION,
            version=None, owner="owner:unit", authority=None, invocation=None, **options):
    """Drive the actual production producer with simulated executor facts and owned tiny files."""

    selection, store = owned
    prepared = invocation or Invocation(selection, store, operation=operation,
        version=None if version is None else version.observed_version)
    grant = authority or Authority(prepared, "authorization:" + operation.value)

    return capture_runner.run(CaptureNativeTrivyOperation(operation, selection, prepared, grant,
        store, "workspace:unit", owner, version_prerequisite=version, **options))


def test_IndependentVersionAndScanRetainOriginalExecutionAndSeparateCustody(
    capture_runner, owned, executor
):
    """Both producer paths retain simulated facts and independent invocation bounds."""

    selection, store = owned
    calls, result, _ = executor
    version = Capture(capture_runner, owned, executor)
    result[0] = Result(b'{"SchemaVersion":2,"ArtifactType":"container_image"}')
    scan = Capture(capture_runner, owned, executor, operation=NativeTrivyOperation.SCAN,
                   version=version)
    assert version.refusal is None and scan.refusal is None, "Stable custody is accepted"
    assert version.request.invocation.provider_version is None and (
        version.observed_version == "0.75.0"
    ), (
        "Observed version must not rewrite its original unknown-version invocation"
    )
    assert scan.version_prerequisite_sha256 == version.Digest(), "SCAN binds original VERSION"
    assert calls[0].workspace != calls[1].workspace, "Operations use fresh scratch"
    assert version.request.resources.max_stdout_bytes == 16 * 1024, "VERSION output is bounded"
    assert not tuple(selection.workspace_root.glob("native-image-*")), "Owned scratch is cleaned up"
    assert {record.reference.role for record in (*version.records, *scan.records)} == {
        "provider-version", "provider-version-stderr", "native-version-receipt",
        "stdout", "stderr", "native-scan-receipt",
    }, "Independent original operations retain all six roles"

    for capture in (version, scan):
        for record in capture.records:
            assert store.Get(record.evidence_id) == record, "Original record must reopen unchanged"
            assert record.provenance.execution == capture.outcome.execution, (
                "VERSION and SCAN keep their own actual original terminal execution"
            )
            assert record.provenance.invocation_sha256 == (
                InvocationDigest(capture.request.invocation)
            ), (
                "Every stream/receipt binds its own exact original invocation"
            )


@pytest.mark.parametrize("state,termination", [
    (ExecutionState.FAILED, ExecutionTermination.PROCESS_EXIT),
    (ExecutionState.FAILED, ExecutionTermination.OUTPUT_LIMIT),
    (ExecutionState.SUCCEEDED, ExecutionTermination.OUTPUT_LIMIT),
    (ExecutionState.TIMED_OUT, ExecutionTermination.TIMEOUT),
    (ExecutionState.CANCELLED, ExecutionTermination.CANCELLATION),
])
def test_FailedOriginalVersionNeverAssociatesScanAndKeepsRawFacts(
    capture_runner, owned, executor, state, termination
):
    """A success-shaped stdout cannot erase nonzero, truncation, timeout or cancellation."""

    calls, result, _ = executor
    result[0] = Result(json.dumps(VERSION).encode(), state=state, termination=termination)
    version = Capture(capture_runner, owned, executor)
    assert version.refusal == "execution-not-successful", "Failed execution is not a VERSION proof"
    assert version.outcome.execution.state is state and (
        version.outcome.termination is termination
    ), (
        "The collector must preserve unchanged actual terminal facts"
    )
    assert version.records[0].reference.sha256 == hashlib.sha256(result[0].stdout).hexdigest(), (
        "Actual raw stdout remains retained even when VERSION cannot authorize association"
    )
    selection, store = owned
    invocation = Invocation(selection, store, operation=NativeTrivyOperation.SCAN, version="0.75.0")

    with pytest.raises(ValueError, match="original accepted"):
        Capture(capture_runner, owned, executor, operation=NativeTrivyOperation.SCAN,
                version=version, invocation=invocation)

    assert len(calls) == 1, "Rejected association cannot launch a SCAN"


@pytest.mark.parametrize("raw", [b"broken-json", b'{"Version":"0.75.0-synthetic"}',
    b'{"Version":"0.75.0"}', json.dumps({**VERSION, "VulnerabilityDB": {"Version": 2}}).encode()])
def test_UnverifiedVersionWireRetainsSuccessfulProcessWithoutAcceptedAssociation(
    capture_runner, owned, executor, raw
):
    """Parser or DB mismatch refuses association while preserving process success."""

    executor[1][0] = Result(raw)
    capture = Capture(capture_runner, owned, executor)
    assert capture.outcome.execution.state is ExecutionState.SUCCEEDED and (
        capture.refusal is not None
    ), (
        "Interpretation refusal must not rewrite actual process execution"
    )
    assert owned[1].Read(capture.records[0].reference) == raw, "Uninterpreted wire stays exact"


@pytest.mark.parametrize("field,value", [
    ("observed_version", "0.75.999"), ("started_at", "2000-01-01T00:00:00Z"),
    ("records", ()), ("owner_reference", "owner:other"),
])
def test_ChangedOriginalVersionFactsCannotBeAssociated(
    capture_runner, owned, executor, field, value
):
    """Object replacement cannot bypass original receipt and owner bindings."""

    version = replace(Capture(capture_runner, owned, executor), **{field: value})
    selection, store = owned
    invocation = Invocation(selection, store, operation=NativeTrivyOperation.SCAN, version="0.75.0")

    with pytest.raises(ValueError):
        Capture(capture_runner, owned, executor, operation=NativeTrivyOperation.SCAN,
                version=version, invocation=invocation)

    assert len(executor[0]) == 1, "Changed VERSION facts never launch a SCAN"


@pytest.mark.parametrize("relative", ["trivy", "owned.tar", "trivy-cache/db/trivy.db",
                                     "trivy-cache/db/metadata.json"])
def test_ChangedSelectedMaterialRefusesAssociationAndRetainsOriginalRaw(
    capture_runner, owned, executor, relative
):
    """Every selected binary/archive/database member participates in post-run acceptance."""

    path = owned[0].workspace_root / relative
    executor[2][0] = lambda: path.write_bytes(path.read_bytes() + b"changed")
    capture = Capture(capture_runner, owned, executor)
    assert capture.refusal == "material-changed" and capture.outcome.execution.state is (
        ExecutionState.SUCCEEDED
    ), "Changed selected bytes refuse interpretation without erasing actual process success"
    assert len(capture.records) == 3, "Raw output and refused custody receipt remain available"


def test_RevokedPostRunAuthorityRefusesAssociationWithoutChangingExecution(
    capture_runner, owned, executor
):
    """The optional upstream callback rereads authority after cleanup as well as before launch."""

    calls = []

    def Validate(request):
        """Accept the initial launch, then refuse final same-request authority."""

        calls.append(request)

        if len(calls) == 2:
            raise PermissionError("owned revoked authority")

    capture = Capture(capture_runner, owned, executor, validate_authority=Validate)
    assert capture.refusal == "authority-unverified" and len(calls) == 2, (
        "Fresh post-run denial must be explicit in original retained custody"
    )
    assert capture.outcome.execution.state is ExecutionState.SUCCEEDED, "Execution stays unchanged"


def test_InvocationSubstitutionAndMissingPrerequisiteNeverReachExecutor(
    capture_runner, owned, executor
):
    """Caller-supplied extra flags or a missing original VERSION cannot enter a native process."""

    selection, store = owned
    invocation = Invocation(selection, store)
    changed = replace(invocation, argv=(*invocation.argv, "--arbitrary"))

    with pytest.raises(ValueError, match="exact selected"):
        Capture(capture_runner, owned, executor, invocation=changed)

    scan = Invocation(selection, store, operation=NativeTrivyOperation.SCAN, version="0.75.0")

    with pytest.raises(ValueError, match="original VERSION"):
        Capture(capture_runner, owned, executor, operation=NativeTrivyOperation.SCAN,
                invocation=scan)

    assert not executor[0], "Invalid profiles or missing prerequisites must fail before launch"


def test_SelectedFileRejectsLinksOversizeAndRetainsPhysicalByteIdentity(tmp_path):
    """File receipts distinguish selected byte hash from physical inode/time observations."""

    path = tmp_path / "selected"
    path.write_bytes(b"owned")
    fact = SelectedFile(path, "archive", 5)
    assert fact.size_bytes == 5 and fact.physical_identity[2] == 5, "Length binds physical fact"

    with pytest.raises(ValueError, match="exceeds"):
        SelectedFile(path, "archive", 4)

    missing = SelectedFile(tmp_path / "absent", "database", 10, optional=True)
    assert missing.sha256 is None and missing.physical_identity is None, "Absent DB is not invented"


def test_NativeSelectionRejectsImplicitSourcesAndMissingReadConsent(tmp_path):
    """Construction never turns caller-relative file discovery into a native selection."""

    with pytest.raises(ValueError, match="absolute selections"):
        NativeTrivySelection(tmp_path, Path("relative"), "owned.tar", "cache",
            ArtifactReadConsent("owner:unit", "read:owned"))

    with pytest.raises(ValueError, match="explicit consent"):
        NativeTrivySelection(tmp_path, tmp_path / "binary", "owned.tar", "cache", None)


@pytest.mark.parametrize("field,value", [
    ("scope_reference", "scope:other"), ("policy_reference", "policy:other"),
    ("authorization_id", "authorization:version"),
])
def test_ScanAssociationRequiresIndependentSameScopePolicyAuthorization(
    capture_runner, owned, executor, field, value
):
    """Separate exact grants cannot move an original VERSION across policy or scope."""

    version = Capture(capture_runner, owned, executor)
    invocation = Invocation(*owned, operation=NativeTrivyOperation.SCAN, version="0.75.0")
    authority = replace(Authority(invocation, "authorization:scan"), **{field: value})

    with pytest.raises(ValueError, match="same-owner/material"):
        Capture(capture_runner, owned, executor, operation=NativeTrivyOperation.SCAN,
                version=version, invocation=invocation, authority=authority)

    assert len(executor[0]) == 1, "Changed association authority never reaches SCAN"


def test_ScanCannotReuseOriginalVersionForAnotherTarget(capture_runner, owned, executor):
    """The selected archive alone cannot silently move custody to another target identity."""

    version = Capture(capture_runner, owned, executor)
    invocation = Invocation(*owned, operation=NativeTrivyOperation.SCAN, version="0.75.0")
    invocation = replace(invocation, request=replace(invocation.request,
                                                   target_reference="target:other"))

    with pytest.raises(ValueError, match="VERSION target"):
        Capture(capture_runner, owned, executor, operation=NativeTrivyOperation.SCAN,
                version=version, invocation=invocation)

    assert len(executor[0]) == 1, "Cross-target association fails before SCAN"


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_OriginalVersionCannotSubstituteExecutorRawBuffer(
    capture_runner, owned, executor, stream
):
    """Retained raw records must also equal the supplied original executor buffers."""

    version = Capture(capture_runner, owned, executor)
    version = replace(version, outcome=replace(version.outcome, **{stream: b"substituted"}))

    with pytest.raises(ValueError, match="original executor bytes"):
        Capture(capture_runner, owned, executor, operation=NativeTrivyOperation.SCAN,
                version=version)

    assert len(executor[0]) == 1, "Raw substitution cannot launch a second process"


@pytest.mark.parametrize("metadata", [
    {"Version": True, "UpdatedAt": METADATA["UpdatedAt"]},
    {"Version": 1, "UpdatedAt": METADATA["UpdatedAt"]},
    {"Version": 2}, {"Version": 2, "UpdatedAt": "2026-06-22T14:30:14"},
])
def test_MalformedSelectedDatabaseCannotEstablishVersion(
    capture_runner, owned, executor, metadata
):
    """Actual matching-looking wire cannot rescue missing schema or timezone-aware update facts."""

    path = owned[0].workspace_root / "trivy-cache/db/metadata.json"
    path.write_text(json.dumps(metadata))
    executor[1][0] = Result(json.dumps({"Version": "0.75.0", "VulnerabilityDB": metadata}).encode())
    version = Capture(capture_runner, owned, executor)
    assert version.refusal == "material-or-version-unverified", "Malformed selected DB is refused"
    assert len(version.records) == 3, "Unaccepted actual VERSION still retains all original roles"


def test_MissingDatabaseVersionKeepsOriginalButCannotLaunchScan(capture_runner, owned, executor):
    """No selected DB is manufactured from successful native version stdout."""

    (owned[0].workspace_root / "trivy-cache/db/trivy.db").unlink()
    version = Capture(capture_runner, owned, executor)
    assert version.refusal == "material-or-version-unverified", "Missing DB denies association"
    assert version.material_before[-2].sha256 is None, "Missing DB remains an explicit absence"


def test_ExactLaunchCallbackRejectsMaterialChangedBeforeProcess(
    capture_runner, owned, executor, monkeypatch
):
    """Material is rechecked at executor launch rather than only at invocation selection."""

    async def Execute(self, request, **options):
        """Mutate only owned input immediately before the real producer callback."""

        (owned[0].workspace_root / "owned.tar").write_bytes(b"changed before launch")
        options["pre_launch"](request)
        raise AssertionError("Changed material must prevent process creation")

    monkeypatch.setattr(LocalExecutor, "Execute", Execute)

    with pytest.raises(ValueError, match="changed before"):
        Capture(capture_runner, owned, executor)

    assert not tuple(owned[0].workspace_root.glob("native-image-*")), "Refusal cleans owned scratch"


def test_SelectedFileRejectsSymlinksWithoutFollowingSource(tmp_path):
    """Only explicit regular physical selections are hashable native material."""

    source = tmp_path / "source"
    source.write_bytes(b"owned")
    link = tmp_path / "link"

    try:
        link.symlink_to(source)

    except OSError:
        pytest.skip("Symlink creation is unavailable for this owned test identity")

    with pytest.raises(ValueError):
        SelectedFile(link, "archive", 10)


def test_OriginalCaptureRequiresExactInvocationBoundCallerAuthority(
    capture_runner, owned, executor
):
    """No descriptive selection or receipt can replace the caller's exact execution decision."""

    invocation = Invocation(*owned)
    authority = replace(Authority(invocation, "authorization:version"), invocation_sha256="0" * 64)

    with pytest.raises(ValueError, match="authorization does not match"):
        Capture(capture_runner, owned, executor, invocation=invocation, authority=authority)

    with pytest.raises(ValueError, match="owning selection"):
        Capture(capture_runner, owned, executor, owner="owner:other")

    assert not executor[0], "Invalid caller authority or owner cannot start a native operation"


def test_ScanKeepsActualFailureWithoutForgingSuccessfulInterpretation(
    capture_runner, owned, executor
):
    """Accepted original VERSION does not erase a later genuine-shaped SCAN failure."""

    version = Capture(capture_runner, owned, executor)
    executor[1][0] = Result(b"original failed scan", state=ExecutionState.FAILED)
    scan = Capture(capture_runner, owned, executor, operation=NativeTrivyOperation.SCAN,
                   version=version)
    assert scan.refusal == "execution-not-successful", "Failed SCAN retains explicit refusal"
    assert scan.version_prerequisite_sha256 == version.Digest(), "Original association stays exact"
    assert owned[1].Read(scan.records[0].reference) == b"original failed scan", "Raw stays exact"


def test_AnotherFactoryValidArchiveCannotBorrowSelectedMaterialFacts(
    capture_runner, owned, executor
):
    """Factory-valid argv must also select the archive named by original material custody."""

    selection, store = owned
    (selection.workspace_root / "other.tar").write_bytes(b"different explicit archive")
    invocation = Invocation(selection, store)
    request = replace(invocation.request, parameters={"archive": "other.tar", "timeout_seconds": 3})
    invocation = selection.Adapter(store).PrepareVersionInvocation(request)

    with pytest.raises(ValueError, match="archive differs"):
        Capture(capture_runner, owned, executor, invocation=invocation)

    assert not executor[0], "Unselected archive cannot borrow another material's custody"
