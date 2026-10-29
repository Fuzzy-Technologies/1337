# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Original native-pair admission guards using explicitly simulated owned executor results."""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
from dataclasses import replace

import pytest

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterRequest,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
    SerializeContract,
)
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.executors import (
    ExecutionAuthorization,
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionResult,
    LocalExecutor,
)
from fuzzy1337.findings import Finding, FindingStatus
from fuzzy1337.images import ImageIdentity
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.native_image_admission import (
    ApplyVerifiedNativeTrivyImages,
    NativeEvidenceStore,
    OriginalPath,
    VerifyNativeTrivyImageReplay,
)
from fuzzy1337.native_image_capture import (
    CaptureNativeTrivyOperation,
    NativeTrivyOperation,
    NativeTrivySelection,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

METADATA = {"Version": 2, "UpdatedAt": "2026-06-22T14:30:14Z"}
VERSION = {"Version": "0.75.0", "VulnerabilityDB": METADATA}
REPORT = {"SchemaVersion": 2, "ArtifactType": "container_image", "Trivy": {"Version": "0.75.0"},
    "Metadata": {"ImageID": "sha256:" + "a" * 64}, "Results": [{"Type": "python-pkg",
        "Packages": [{"ID": "requests@2.30.0", "Name": "requests", "Version": "2.30.0",
                      "Identifier": {"PURL": "pkg:pypi/requests@2.30.0"}}],
        "Vulnerabilities": [{"VulnerabilityID": "CVE-2023-32681", "PkgName": "requests",
            "InstalledVersion": "2.30.0", "PkgID": "requests@2.30.0", "Severity": "HIGH",
            "FixedVersion": "2.31.0"}]}]}


@pytest.fixture(scope="module")
def admission_runner():
    """Initialize Windows loop resources before the unchanged unit network guard."""

    with asyncio.Runner() as runner:
        runner.get_loop()

        yield runner


@pytest.fixture
def paired(tmp_path, monkeypatch, admission_runner):
    """Drive the real custody producer with simulated executor outcomes and explicit tiny files."""

    root = tmp_path / "owned"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned admission"), "native-admission")
    state = LocalModelStore(root).Create()
    database = root / "trivy-cache" / "db"
    database.mkdir(parents=True)
    (database / "trivy.db").write_bytes(b"owned simulated database")
    (database / "metadata.json").write_text(json.dumps(METADATA))
    (root / "owned.tar").write_bytes(b"owned simulated archive")
    binary = root / "owned-trivy"
    binary.write_bytes(b"owned simulated binary; never executed")
    store = LocalEvidenceStore(root / "evidence")
    selection = NativeTrivySelection(root, binary, "owned.tar", "trivy-cache",
        ArtifactReadConsent("owner:unit", "read:explicit-fixture"))
    outcomes = []

    async def Execute(self, request, **options):
        """Simulate only subprocess outcomes while exercising real pre-launch validation."""

        options["pre_launch"](request)
        raw = json.dumps(VERSION if "--version" in request.invocation.argv else REPORT).encode()
        stderr = b"owned simulated stderr"
        result = LocalExecutionResult(AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.01),
            ExecutionTermination.PROCESS_EXIT, raw, stderr,
            (ExecutionEvent(0, ExecutionEventKind.STARTED),
             ExecutionEvent(1, ExecutionEventKind.STDOUT, raw),
             ExecutionEvent(2, ExecutionEventKind.STDERR, stderr),
             ExecutionEvent(3, ExecutionEventKind.COMPLETED,
                            termination=ExecutionTermination.PROCESS_EXIT)))
        outcomes.append(result)

        return result

    monkeypatch.setattr(LocalExecutor, "Execute", Execute)
    captures = []

    for operation in (NativeTrivyOperation.VERSION, NativeTrivyOperation.SCAN):
        adapter = selection.Adapter(store, None if not captures else captures[0].observed_version)
        request = AdapterRequest("image.archive-vulnerabilities", "target:owned-unit",
            ImpactLevel.SAFE, {"archive": "owned.tar", "timeout_seconds":
                              3 if not captures else 30})
        invocation = adapter.PrepareVersionInvocation(request) if not captures else (
            adapter.PrepareInvocation(request))
        authority = ExecutionAuthorization("authorization:" + operation.value, "scope:owned-unit",
            "policy:owned-unit", InvocationDigest(invocation))
        capture = admission_runner.run(CaptureNativeTrivyOperation(operation, selection,
            invocation, authority, store, state.workspace_id, "owner:unit",
            version_prerequisite=None if not captures else captures[0]))
        captures.append(capture)

    return root, state, store, captures[0], captures[1]


def Receipt(capture, store, envelope, *, provenance=None):
    """Retain a changed receipt as a separate acquisition without overwriting source."""

    old = capture.records[-1]
    changed = store.Put(SerializeContract(envelope).encode(), old.reference.role,
                        old.reference.media_type, provenance or old.provenance)

    return replace(capture, records=(*capture.records[:2], changed))


def test_OriginalExecutedPairAdmitsCanonicalAssetsAndStableFindingTriage(paired):
    """Successful canonical projection uses six roles and preserves independently set triage."""

    root, state, _, version, scan = paired
    replay = VerifyNativeTrivyImageReplay((*version.records, *scan.records), root)
    updated, delta = ApplyVerifiedNativeTrivyImages(state, version, scan, root)
    assert replay.version_request.invocation.provider_version is None, (
        "Original VERSION must retain its unknown provider version"
    )
    assert replay.version_execution == version.outcome.execution and (
        replay.scan_execution == scan.outcome.execution
    ), "Both original executed operations must preserve separate terminal facts"
    assert replay.version_prerequisite_sha256 == version.Digest(), (
        "SCAN attribution must bind the exact original VERSION receipt"
    )
    assert updated.revision == 1 and delta.created, "Admission must create one model batch"
    assets = [item for item in updated.objects if item.identity.kind is ObjectKind.ASSET]
    assert {item.attributes["asset_type"] for item in assets} == {"image", "package"}, (
        "Canonical inventory must include the exact image and installed package"
    )
    finding = next(item for item in updated.objects if item.identity.kind is ObjectKind.FINDING)
    parsed = Finding.FromObject(finding)
    assert parsed.location_key == "CVE-2023-32681" and (
        len(parsed.provenance[0].evidence_references) == 6
    ), (
        "The exact installed package finding must retain the full original executed pair"
    )
    triaged = replace(parsed, status=FindingStatus.CONFIRMED, status_reason="owned reason")
    current, _ = updated.Apply(objects=(triaged.ToObject(state.workspace_id),))
    repeated, repeated_delta = ApplyVerifiedNativeTrivyImages(current, version, scan, root)
    assert repeated == current and not repeated_delta.created and not repeated_delta.updated, (
        "Reapplying the exact original pair must preserve existing owner triage and revision"
    )


def test_ReplayRetainsOriginalPathsAfterWorkspaceMoveAndMaterialRemoval(paired, tmp_path):
    """Historical replay never opens the recorded binary/archive/cache or reissues authority."""

    root, state, _, version, scan = paired
    records = (*version.records, *scan.records)
    expected = VerifyNativeTrivyImageReplay(records, root)
    moved = tmp_path / "moved"
    shutil.copytree(root, moved)
    shutil.rmtree(root)
    actual = VerifyNativeTrivyImageReplay(records, moved)
    assert actual == expected, "Relocated replay must retain exact original custody facts"
    assert actual.scan_request.invocation.argv[0].startswith(str(root)), (
        "Relocation must preserve historical invocation paths"
    )
    updated, _ = ApplyVerifiedNativeTrivyImages(state, version, scan, moved)
    assert updated.objects, "Retained captures must use their owning relocated evidence store"


@pytest.mark.parametrize("field,changed", [
    ("schema_version", True), ("operation", "version"), ("owner_reference", "owner:foreign"),
    ("workspace_id", "foreign"), ("started_at", "2026-01-01T00:00:00+00:00"),
    ("finished_at", "2020-01-01T00:00:00+00:00"), ("observed_version", "0.75.1"),
    ("version_prerequisite_sha256", "0" * 64), ("refusal", "invented-refusal"),
    ("streams", []), ("material_before", []), ("material_after", None),
    ("events", []), ("termination", "invented"),
])
def test_ChangedReceiptFactsCannotReplaceOriginalPair(paired, field, changed):
    """A separately rehashed receipt cannot borrow original stream/provenance/pair bindings."""

    root, _, store, version, scan = paired
    envelope = scan.Envelope()
    envelope[field] = changed
    changed_scan = Receipt(scan, store, envelope)

    with pytest.raises(ValueError, match="inconsistent"):
        VerifyNativeTrivyImageReplay((*version.records, *changed_scan.records), root)


@pytest.mark.parametrize("path,changed", [
    (("request", "invocation", "argv"), ["foreign-binary"]),
    (("request", "invocation", "request", "parameters", "timeout_seconds"), True),
    (("request", "invocation", "request", "credential_references"), ["credential:foreign"]),
    (("request", "invocation", "request", "impact"), "ACTIVE"),
    (("request", "authorization", "invocation_sha256"), "f" * 64),
    (("request", "authorization", "granted_privileges"), ["root"]),
    (("request", "capability", "required_privileges"), ["root"]),
    (("request", "resources", "max_stdout_bytes"), 9 * 1024 * 1024),
    (("request", "resources", "terminate_grace_seconds"), 2.0),
    (("request", "environment", "PATH"), "/foreign/bin"),
    (("request", "workspace"), "../foreign"),
    (("selection", "archive"), "../foreign.tar"),
    (("selection", "workspace_root"), "/foreign/../owned"),
    (("read_consent", "record_ref"), ""),
    (("execution", "duration_seconds"), True),
    (("execution", "exit_code"), 7),
])
def test_ChangedExactRequestCannotExpandOrSubstituteOriginalProfile(paired, path, changed):
    """Finite-profile checks reject request substitution and resource expansion."""

    root, _, store, version, scan = paired
    envelope = scan.Envelope()
    value = envelope

    for part in path[:-1]:
        value = value[part]

    value[path[-1]] = changed
    changed_scan = Receipt(scan, store, envelope)

    with pytest.raises(ValueError, match="inconsistent"):
        VerifyNativeTrivyImageReplay((*version.records, *changed_scan.records), root)


@pytest.mark.parametrize("field,changed", [
    ("path", "/foreign/archive"), ("role", "executable"), ("size_bytes", True),
    ("sha256", "not-a-digest"), ("physical_identity", [0, 0, 0, 0, 0]),
    ("physical_identity", [0, 1, 500, 0, 0]), ("physical_identity", [0, 1, 0]),
])
def test_MaterialFactShapeCannotBorrowOriginalByteIdentity(paired, field, changed):
    """Hash/length/physical-role facts form one original selected-file observation."""

    root, _, store, version, scan = paired
    envelope = scan.Envelope()
    envelope["material_before"][0][field] = changed
    changed_scan = Receipt(scan, store, envelope)

    with pytest.raises(ValueError, match="inconsistent"):
        VerifyNativeTrivyImageReplay((*version.records, *changed_scan.records), root)


@pytest.mark.parametrize("field,changed", [
    ("data_hex", "FF"), ("data_hex", "00"), ("sequence", 42),
    ("kind", "foreign"), ("termination", "timeout"),
])
def test_OriginalEventHistoryCannotSubstituteRetainedStream(paired, field, changed):
    """Retained event chunks must reproduce the original streams and lifecycle sequence exactly."""

    root, _, store, version, scan = paired
    envelope = scan.Envelope()
    envelope["events"][1][field] = changed
    changed_scan = Receipt(scan, store, envelope)

    with pytest.raises(ValueError, match="inconsistent"):
        VerifyNativeTrivyImageReplay((*version.records, *changed_scan.records), root)


@pytest.mark.parametrize("role", ["stdout", "stderr", "native-scan-receipt",
                                 "provider-version", "native-version-receipt"])
def test_ForeignReceiptOrStreamProvenanceCannotBorrowOriginalBytes(paired, role):
    """Identical raw bytes under another context cannot replace original custody."""

    root, _, store, version, scan = paired
    records = list((*version.records, *scan.records))
    index = next(index for index, record in enumerate(records) if record.reference.role == role)
    old = records[index]
    records[index] = store.Put(store.Read(old.reference), role, old.reference.media_type,
        replace(old.provenance, scope_reference="scope:foreign"))

    with pytest.raises(ValueError, match="inconsistent"):
        VerifyNativeTrivyImageReplay(tuple(records), root)


def test_MissingOriginalManifestCannotBeReplacedByUnchangedContentBlob(paired):
    """Existing stream bytes cannot substitute for the original manifest."""

    root, _, store, version, scan = paired
    record = scan.records[0]
    (store.root / "records" / (record.evidence_id[7:] + ".json")).unlink()
    assert store.Read(record.reference), "Original blob remains present"

    with pytest.raises(EvidenceError):
        VerifyNativeTrivyImageReplay((*version.records, *scan.records), root)


@pytest.mark.parametrize("mode", ["missing", "duplicate", "list", "untyped"])
def test_RecordFamilyRequiresSixDistinctOriginalManifests(paired, mode):
    """Legacy health/synthetic/partial role sets cannot masquerade as the new native pair family."""

    root, _, _, version, scan = paired
    records = (*version.records, *scan.records)
    candidates = {"missing": records[:-1], "duplicate": (*records[:-1], records[0]),
                  "list": list(records), "untyped": (*records[:-1], None)}

    with pytest.raises(ValueError, match="native admission"):
        VerifyNativeTrivyImageReplay(candidates[mode], root)


def test_RoleBudgetIsCheckedBeforeAnyOriginalRawAllocation(paired, monkeypatch):
    """Caller and actual owning manifests cannot enlarge this consumer's raw budgets."""

    root, _, _, version, scan = paired
    record = scan.records[0]
    oversized = replace(record, reference=replace(record.reference, size_bytes=4 * 1024**2 + 1))

    def Read(self, reference):
        """Fail if the role guard delegates an oversized reference to raw storage."""

        pytest.fail("Oversized native role must fail before reading original bytes")

    monkeypatch.setattr(LocalEvidenceStore, "Read", Read)

    with pytest.raises(ValueError, match="budget"):
        VerifyNativeTrivyImageReplay((*version.records, oversized, *scan.records[1:]), root)


@pytest.mark.parametrize("role,media,size", [("foreign", "application/json", 0),
    ("stdout", "text/plain", 0), ("stderr", "text/plain", 1024**2 + 1)])
def test_StoreEnforcesExactRoleMediaAndFiniteSizes(paired, role, media, size):
    """Consumer role validation cannot rely only on the caller's receipt shape."""

    root, _, _, _, _ = paired
    reference = EvidenceReference(role, "blobs/sha256/" + "f" * 64, "f" * 64, media, size)

    with pytest.raises(ValueError):
        NativeEvidenceStore(root / "evidence").Read(reference)


@pytest.mark.parametrize("value", ["relative", "/original/../foreign", "C:relative"])
def test_ReplayPathRequiresOriginalCanonicalAbsoluteSyntax(value):
    """Historical paths have syntax ownership while replay performs no filesystem access."""

    with pytest.raises(ValueError):
        OriginalPath(value)


def test_WindowsOriginalPathUsesItsOwnPlatformSyntax():
    """Cross-platform replay never interprets a Windows original invocation as a POSIX path."""

    assert str(OriginalPath("C:\\owned\\workspace")) == "C:\\owned\\workspace", (
        "Windows paths must retain exact original separators and absolute drive"
    )


@pytest.mark.parametrize("mode", ["state", "version", "scan", "workspace", "outcome"])
def test_AdmissionRequiresUnchangedOriginalTypedCapturesAndWorkspace(paired, mode):
    """Typed original-memory equality is separate from detached historical replay consistency."""

    root, state, _, version, scan = paired
    values = {
        "state": (None, version, scan), "version": (state, None, scan),
        "scan": (state, version, None),
        "workspace": (replace(state, workspace_id="foreign"), version, scan),
        "outcome": (state, version, replace(scan,
            outcome=replace(scan.outcome, stdout=scan.outcome.stdout + b" "))),
    }

    with pytest.raises(ValueError):
        ApplyVerifiedNativeTrivyImages(*values[mode], root)


def test_RefusedScanReplayKeepsRawFactsButCannotAdmitModel(paired):
    """Recorded post-run refusal is descriptive and cannot become successful empty findings."""

    root, state, store, version, scan = paired
    refused = replace(scan, refusal="authority-unverified")
    refused = Receipt(refused, store, refused.Envelope())
    replay = VerifyNativeTrivyImageReplay((*version.records, *refused.records), root)
    assert replay.scan_refusal == "authority-unverified", "Replay must preserve refusal"

    with pytest.raises(ValueError, match="successful"):
        ApplyVerifiedNativeTrivyImages(state, version, refused, root)

    assert LocalModelStore(root).Open() == state, "Refusal must leave saved model intact"
    assert store.Read(scan.records[0].reference) == scan.outcome.stdout, (
        "Refused model admission must retain the original raw scan facts"
    )


def test_RehashedVersionReceiptCannotBeBorrowedByOriginalScan(paired):
    """SCAN pins the original VERSION envelope and terminal facts."""

    root, _, store, version, scan = paired
    envelope = version.Envelope()
    envelope["read_consent"]["record_ref"] = "read:another-record"
    changed_version = Receipt(version, store, envelope)

    with pytest.raises(ValueError, match="inconsistent"):
        VerifyNativeTrivyImageReplay((*changed_version.records, *scan.records), root)

    assert changed_version.records[-1].reference.sha256 != hashlib.sha256(
        store.Read(version.records[-1].reference)).hexdigest(), "Changed VERSION is separate"


@pytest.mark.parametrize("mode", ["remove-started", "insert-completed", "insert-started"])
def test_RehashedReceiptCannotInventExecutorLifecycle(paired, mode):
    """Exact source-produced event grammar rejects plausible but impossible reordered histories."""

    root, _, store, version, scan = paired
    envelope = scan.Envelope()
    events = envelope["events"]

    if mode == "remove-started":
        events.pop(0)

    else:
        events.insert(1, dict(events[-1] if mode == "insert-completed" else events[0]))

    for index, event in enumerate(events):
        event["sequence"] = index

    changed = Receipt(scan, store, envelope)

    with pytest.raises(ValueError, match="inconsistent"):
        VerifyNativeTrivyImageReplay((*version.records, *changed.records), root)


@pytest.mark.parametrize("state,termination,exit_code", [
    (ExecutionState.FAILED, ExecutionTermination.PROCESS_EXIT, 7),
    (ExecutionState.TIMED_OUT, ExecutionTermination.TIMEOUT, None),
    (ExecutionState.CANCELLED, ExecutionTermination.CANCELLATION, None),
    (ExecutionState.CANCELLED, ExecutionTermination.OUTPUT_LIMIT, None),
])
def test_FailedTerminalFactsReplayWithoutParsingPartialScanOrApplyingModel(
    paired, state, termination, exit_code
):
    """Failure replay verifies original custody without converting partial stdout into inventory."""

    root, model, store, version, scan = paired
    raw = b'{"partial":'
    execution = AdapterExecution(state, exit_code, 0.01)
    outcome = LocalExecutionResult(execution, termination, raw, b"partial owned stderr",
        (ExecutionEvent(0, ExecutionEventKind.STARTED),
         ExecutionEvent(1, ExecutionEventKind.STDOUT, raw),
         ExecutionEvent(2, ExecutionEventKind.STDERR, b"partial owned stderr"),
         ExecutionEvent(3, ExecutionEventKind.COMPLETED, termination=termination)))
    source = replace(scan.records[0].provenance, execution=execution)
    stdout = store.Put(raw, "stdout", "application/json", source)
    stderr = store.Put(outcome.stderr, "stderr", "text/plain", source)
    failed = replace(scan, outcome=outcome, refusal="execution-not-successful",
                     records=(stdout, stderr))
    receipt = store.Put(SerializeContract(failed.Envelope()).encode(), "native-scan-receipt",
                        "application/json", source)
    failed = replace(failed, records=(*failed.records, receipt))
    replay = VerifyNativeTrivyImageReplay((*version.records, *failed.records), root)
    assert replay.scan_execution == execution and replay.scan_termination is termination, (
        "Replay must retain independent actual non-success terminal facts"
    )

    with pytest.raises(ValueError, match="successful"):
        ApplyVerifiedNativeTrivyImages(model, version, failed, root)

    assert store.Read(stdout.reference) == raw, "Partial raw must survive refused admission"


def test_PreLaunchCancellationKeepsOnlyItsOriginalTerminalEvent(paired):
    """A never-started cancelled SCAN legitimately has one COMPLETED event and no raw output."""

    root, _, store, version, scan = paired
    execution = AdapterExecution(ExecutionState.CANCELLED, None, 0.0)
    termination = ExecutionTermination.CANCELLATION
    outcome = LocalExecutionResult(execution, termination, b"", b"",
        (ExecutionEvent(0, ExecutionEventKind.COMPLETED, termination=termination),))
    source = replace(scan.records[0].provenance, execution=execution)
    records = (store.Put(b"", "stdout", "application/json", source),
               store.Put(b"", "stderr", "text/plain", source))
    cancelled = replace(scan, outcome=outcome, refusal="execution-not-successful", records=records)
    receipt = store.Put(SerializeContract(cancelled.Envelope()).encode(), "native-scan-receipt",
                        "application/json", source)
    replay = VerifyNativeTrivyImageReplay((*version.records, *records, receipt), root)
    assert replay.scan_termination is termination and replay.scan_execution == execution, (
        "Pre-launch cancellation must remain truthful without inventing a STARTED event"
    )


def test_ExecutedNativeAdmissionSharesCanonicalLegacyIdentityWithoutRewritingHealth(paired):
    """Both native consumers share canonical identities with distinct original custody."""

    from fuzzy1337.adapters import AdapterReport
    from fuzzy1337.images import ApplyVerifiedTrivyImages
    from fuzzy1337.model import ModelProvenance

    root, state, store, version, scan = paired
    health_source = replace(version.records[0].provenance, execution=None, invocation_sha256=None)
    health = store.Put(version.outcome.stdout, "provider-version", "application/json",
                       health_source)
    records = (*scan.records[:2], health)
    report = AdapterReport(scan.request.invocation, scan.outcome.execution,
                           tuple(record.reference for record in records))
    provenance = ModelProvenance("native.trivy", "legacy:owned-health", scan.finished_at,
        scan.request.authorization.scope_reference,
        scan.request.invocation.request.target_reference, scan.observed_version,
        tuple(record.reference for record in records), scan.outcome.execution)
    legacy, _ = ApplyVerifiedTrivyImages(state, report, provenance, records, root)
    current, _ = ApplyVerifiedNativeTrivyImages(legacy, version, scan, root)
    assert {item.Reference() for item in current.objects} == (
        {item.Reference() for item in legacy.objects}
    ), "Executed native admission must reuse canonical native image/package/Finding identities"
    assert store.Get(health.evidence_id).provenance.execution is None and (
        store.Get(version.records[0].evidence_id).provenance.execution == version.outcome.execution
    ), "Independent legacy health and original executed VERSION provenance must remain unchanged"
    finding = next(item for item in current.objects if item.identity.kind is ObjectKind.FINDING)
    assert {len(source.evidence_references) for source in finding.provenance} == {3, 6}, (
        "Finding must retain separate legacy and executed-pair source attribution"
    )


def test_AmbiguousInstalledPackageCollisionCannotCreateFinding(paired):
    """A vulnerability cannot choose between different installed architectures."""

    root, state, store, version, scan = paired
    report = json.loads(scan.outcome.stdout)
    packages = report["Results"][0]["Packages"]
    package = packages[0]
    package["Identifier"]["PURL"] += "?arch=x86_64"
    package["Arch"] = "x86_64"
    second = json.loads(json.dumps(package))
    second["Identifier"]["PURL"] = "pkg:pypi/requests@2.30.0?arch=aarch64"
    second["Arch"] = "aarch64"
    packages.append(second)
    raw = json.dumps(report).encode()
    events = list(scan.outcome.events)
    events[1] = replace(events[1], data=raw)
    outcome = replace(scan.outcome, stdout=raw, events=tuple(events))
    stdout = store.Put(raw, "stdout", "application/json", scan.records[0].provenance)
    changed = replace(scan, outcome=outcome, records=(stdout, scan.records[1]))
    receipt = store.Put(SerializeContract(changed.Envelope()).encode(), "native-scan-receipt",
                        "application/json", scan.records[0].provenance)
    changed = replace(changed, records=(*changed.records, receipt))

    with pytest.raises(ValueError, match="exactly one installed"):
        ApplyVerifiedNativeTrivyImages(state, version, changed, root)

    assert LocalModelStore(root).Open() == state, "Ambiguous finding must leave saved model intact"


@pytest.mark.parametrize("matches", (True, False))
def test_SelectedConfigPinChecksFreshReportBeforeCandidates(paired, monkeypatch, matches):
    """Old assets cannot satisfy the new report pin, and a mismatch never reaches projection."""

    from fuzzy1337 import native_image_admission as admission

    root, state, _, version, scan = paired
    prior, _ = ApplyVerifiedNativeTrivyImages(state, version, scan, root)
    observed = REPORT["Metadata"]["ImageID"]
    expected = ImageIdentity(observed if matches else "sha256:" + "f" * 64)
    calls = []
    original = admission.TrivyCandidates

    def Candidates(*args):
        """Observe the actual projection boundary without changing its interpretation."""

        calls.append(args)
        return original(*args)

    monkeypatch.setattr(admission, "TrivyCandidates", Candidates)
    if matches:
        updated, _ = ApplyVerifiedNativeTrivyImages(prior, version, scan, root,
                                                   expected_image_identity=expected)
        assert len(calls) == 1 and updated == prior, (
            "A matching fresh report must preserve the existing idempotent model transition."
        )
    else:
        with pytest.raises(ValueError, match="selected image config identity"):
            ApplyVerifiedNativeTrivyImages(prior, version, scan, root,
                                          expected_image_identity=expected)
        assert calls == [], "A mismatch must stop before candidates and any model save."
