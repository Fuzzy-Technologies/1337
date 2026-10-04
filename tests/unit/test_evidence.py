# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Local raw-evidence integrity and immutable collection-contract boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from fuzzy1337.adapters import AdapterExecution, EvidenceReference, ExecutionState
from fuzzy1337.evidence import (
    EVIDENCE_MANIFEST_MAX_BYTES,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    EvidenceProvenance,
    EvidenceRecord,
    EvidenceStorageError,
    LocalEvidenceStore,
    ParseEvidenceManifest,
)


@pytest.fixture(name="tmp_path")
def PhysicalTmpPath(tmp_path):
    """Select the known physical temporary root across platform path aliases."""

    return tmp_path.resolve()


def Provenance(**overrides) -> EvidenceProvenance:
    """Construct explicit non-secret synthetic collection attribution."""

    values = {
        "workspace_id": "workspace:fixture",
        "scope_reference": "scope:owned-fixture",
        "source_id": "native.fixture",
        "source_version": "1.0",
        "tool_version": "fixture-tool-2",
        "started_at": "2026-10-04T12:00:00+02:00",
        "finished_at": "2026-10-04T10:00:02Z",
    }
    values.update(overrides)

    return EvidenceProvenance(**values)


def Record(data: bytes = b"synthetic raw evidence") -> EvidenceRecord:
    """Construct the canonical reference for a synthetic byte payload."""

    digest = hashlib.sha256(data).hexdigest()

    return EvidenceRecord(
        EvidenceReference("stdout", f"blobs/sha256/{digest}", digest, "text/plain", len(data)),
        Provenance(),
    )


@pytest.mark.parametrize("data", [b"", b"marker\x00\xff\r\n", "fixture: 数据".encode()])
def test_RawEvidenceRoundTripIsExactAndIdempotent(tmp_path, data):
    """Preserve arbitrary bytes without normalization and deduplicate identical writes."""

    store = LocalEvidenceStore(tmp_path)
    first = store.Put(data, "stdout", "application/octet-stream", Provenance())
    second = store.Put(data, "stdout", "application/octet-stream", Provenance())

    assert first == second, "Idempotent writes must retain the same immutable record."
    assert store.Read(first.reference) == data, "Raw evidence must survive byte-for-byte."
    assert store.Get(first.evidence_id) == first, "The manifest must retain collection attribution."
    assert len(list((tmp_path / "blobs" / "sha256").iterdir())) == 1, (
        'Evidence invariant failed: len(list((tmp_path / "blobs" / "sha256").iterdir())) == 1'
    )
    assert len(list((tmp_path / "records").iterdir())) == 1, (
        'Evidence invariant failed: len(list((tmp_path / "records").iterdir())) == 1'
    )
    assert first.reference.sha256 == hashlib.sha256(data).hexdigest(), (
        'Evidence invariant failed: first.reference.sha256 == hashlib.sha256(data).hexdigest()'
    )
    assert first.provenance.started_at == "2026-10-04T10:00:00.000000+00:00", (
        'Evidence artifacts must retain verified original bytes and metadata.'
    )


def test_ContentIdentityAndCollectionIdentityRemainDistinct(tmp_path):
    """Share one blob while preserving distinct immutable collection records."""

    store = LocalEvidenceStore(tmp_path)
    first = store.Put(b"marker", "stdout", "text/plain", Provenance())
    second = store.Put(
        b"marker", "stdout", "text/plain", Provenance(scope_reference="scope:another-fixture"),
    )

    assert first.reference == second.reference, "Provenance must not change the raw content hash."
    assert first.evidence_id != second.evidence_id, "Distinct collections need distinct identities."
    assert len(list((tmp_path / "blobs" / "sha256").iterdir())) == 1, (
        'Evidence invariant failed: len(list((tmp_path / "blobs" / "sha256").iterdir())) == 1'
    )
    assert len(list((tmp_path / "records").iterdir())) == 2, (
        'Evidence invariant failed: len(list((tmp_path / "records").iterdir())) == 2'
    )


def test_RecordsAreFrozenAndSerializationReturnsDetachedData():
    """Prevent caller-side mutation of records and nested execution facts."""

    execution = AdapterExecution(ExecutionState.FAILED, 7, 0.5)
    provenance = Provenance(execution=execution, invocation_sha256="a" * 64)
    record = replace(Record(), provenance=provenance)
    original = record.Serialize()
    detached = record.ToDict()
    detached["provenance"]["execution"]["state"] = "succeeded"

    assert record.Serialize() == original, "Exported JSON mutation must not change attribution."
    assert ParseEvidenceManifest(original) == record, (
        'Evidence invariant failed: ParseEvidenceManifest(original) == record'
    )

    with pytest.raises(FrozenInstanceError):
        record.provenance.execution.exit_code = 0

    with pytest.raises(FrozenInstanceError):
        record.reference.size_bytes = 1


@pytest.mark.parametrize("overrides", [
    {"workspace_id": ""}, {"scope_reference": "a\nb"}, {"source_id": "Invalid"},
    {"source_version": None}, {"tool_version": "a\x00b"}, {"invocation_sha256": "../blob"},
    {"started_at": "2026-10-04T10:00:00"}, {"started_at": "not-a-time"},
    {"finished_at": "2026-10-04T09:00:00Z"}, {"execution": {}},
    {"execution": AdapterExecution(ExecutionState.SUCCEEDED, 0, True)},
])
def test_InvalidProvenanceFailsBeforeFilesystemAccess(overrides):
    """Reject ambiguous attribution, invalid timing, and bool-as-duration coercion."""

    with pytest.raises(ValueError):
        Provenance(**overrides)


def test_PureConstructionDoesNotTouchFilesystem(tmp_path):
    """Defer all storage access and reject traversal during pure construction."""

    root = tmp_path / "absent"
    store = LocalEvidenceStore(root)

    assert not root.exists(), "Store construction must not create an evidence directory."

    with pytest.raises(EvidenceStorageError):
        store.Put(b"marker", "stdout", "text/plain", Provenance())

    with pytest.raises(ValueError, match="parent traversal"):
        LocalEvidenceStore(tmp_path / ".." / "other")

    with pytest.raises(ValueError, match="filesystem root"):
        LocalEvidenceStore(Path(tmp_path.anchor))


@pytest.mark.parametrize("field,value", [
    ("schema_version", 2), ("schema_version", True), ("reference", {}), ("provenance", {}),
])
def test_RecordValidationRejectsUnsupportedContracts(field, value):
    """Refuse unsupported schema and unvalidated nested contract substitutes."""

    with pytest.raises(ValueError):
        replace(Record(), **{field: value})


def test_ReferenceMustUseExactContentAddress():
    """Reject safe-looking aliases as well as traversal in evidence locators."""

    reference = replace(Record().reference, locator="other/blob")

    with pytest.raises(ValueError, match="canonical content address"):
        replace(Record(), reference=reference)


@pytest.mark.parametrize("mutation", [
    "unknown", "missing", "duplicate", "noncanonical", "nan", "infinity", "bool-size",
    "bad-execution", "bad-provenance", "bad-reference", "invalid-utf8", "overflow", "schema",
])
def test_ManifestParserRejectsMalformedOrNoncanonicalData(mutation):
    """Validate schema, canonical bytes, duplicate fields, and non-JSON numbers."""

    record = Record()
    value = record.ToDict()

    if mutation == "unknown":
        value["undeclared"] = "cannot be ignored"

    elif mutation == "missing":
        del value["provenance"]["scope_reference"]

    elif mutation == "duplicate":
        data = record.Serialize().replace(b'{"provenance":', b'{"schema_version":1,"provenance":')

    elif mutation == "noncanonical":
        data = json.dumps(value).encode()

    elif mutation == "nan":
        value["reference"]["size_bytes"] = float("nan")

    elif mutation == "infinity":
        value["reference"]["size_bytes"] = float("inf")

    elif mutation == "bool-size":
        value["reference"]["size_bytes"] = True

    elif mutation == "bad-execution":
        value["provenance"]["execution"] = {
            "state": "succeeded", "exit_code": 0, "duration_seconds": "invalid",
        }

    elif mutation == "bad-provenance":
        value["provenance"]["started_at"] = 42

    elif mutation == "bad-reference":
        value["reference"]["sha256"] = 42

    elif mutation == "invalid-utf8":
        data = b"\xff"

    elif mutation == "overflow":
        value["provenance"]["started_at"] = "0001-01-01T00:00:00+14:00"

    else:
        value["schema_version"] = 2

    if mutation not in {"duplicate", "noncanonical", "invalid-utf8"}:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

    with pytest.raises(ValueError):
        ParseEvidenceManifest(data)


def test_ParserRequiresBytes():
    """Keep explicit raw/canonical encoding at the parser boundary."""

    with pytest.raises(ValueError, match="must be bytes"):
        ParseEvidenceManifest("{}")


@pytest.mark.parametrize("evidence_id", [None, "", "sha512:" + "a" * 64, "sha256:../manifest"])
def test_InvalidManifestIdentitiesCannotSelectPaths(tmp_path, evidence_id):
    """Reject malformed addresses before reading any path."""

    with pytest.raises(ValueError):
        LocalEvidenceStore(tmp_path).Get(evidence_id)


def test_ReadRequiresValidatedCanonicalReference(tmp_path):
    """Reject aliases and unvalidated reference objects before filesystem access."""

    store = LocalEvidenceStore(tmp_path)

    with pytest.raises(ValueError, match="EvidenceReference"):
        store.Read({})

    with pytest.raises(ValueError, match="canonical content address"):
        store.Read(replace(Record().reference, locator="blobs/sha256/./" + "a" * 64))

    with pytest.raises(ValueError, match="must be bytes"):
        store.Put(bytearray(b"marker"), "stdout", "text/plain", Provenance())


def test_MissingManifestAndRawBytesRemainFailures(tmp_path):
    """Never reinterpret missing evidence as an empty successful artifact."""

    store = LocalEvidenceStore(tmp_path)

    with pytest.raises(EvidenceNotFoundError, match="manifest"):
        store.Get("sha256:" + "a" * 64)

    with pytest.raises(EvidenceNotFoundError, match="raw evidence"):
        store.Read(Record().reference)

    record = store.Put(b"marker", "stdout", "text/plain", Provenance())
    (tmp_path / record.reference.locator).unlink()

    with pytest.raises(EvidenceNotFoundError, match="raw evidence"):
        store.Get(record.evidence_id)


@pytest.mark.parametrize("replacement", [b"changed", b"short"])
def test_CorruptRawBytesCannotBeReadOrOverwritten(tmp_path, replacement):
    """Detect digest and length corruption and retain evidence of the failure."""

    store = LocalEvidenceStore(tmp_path)
    record = store.Put(b"original", "stdout", "text/plain", Provenance())
    blob_path = tmp_path / record.reference.locator
    blob_path.write_bytes(replacement)

    with pytest.raises(EvidenceIntegrityError, match="digest or length"):
        store.Get(record.evidence_id)

    with pytest.raises(EvidenceIntegrityError):
        store.Put(b"original", "stdout", "text/plain", Provenance())

    assert blob_path.read_bytes() == replacement, "Put must not erase existing corrupt evidence."
    assert not list(tmp_path.rglob("*.pending")), "Failed publication must clean temporary bytes."


def test_CorruptManifestCannotBeReplacedOrSilentlyAccepted(tmp_path):
    """Reject broken schema and preserve its bytes when an identical collection is retried."""

    store = LocalEvidenceStore(tmp_path)
    record = store.Put(b"marker", "stdout", "text/plain", Provenance())
    manifest = tmp_path / "records" / f"{record.evidence_id[7:]}.json"
    manifest.write_bytes(b"{}")

    with pytest.raises(EvidenceIntegrityError, match="schema"):
        store.Get(record.evidence_id)

    with pytest.raises(EvidenceIntegrityError, match="different bytes"):
        store.Put(b"marker", "stdout", "text/plain", Provenance())

    assert manifest.read_bytes() == b"{}", "A retry must preserve existing corrupt bytes."


def test_CanonicalButSubstitutedManifestFailsIdentityVerification(tmp_path):
    """Detect valid canonical metadata placed beneath another manifest identity."""

    store = LocalEvidenceStore(tmp_path)
    record = store.Put(b"marker", "stdout", "text/plain", Provenance())
    other = replace(record, provenance=Provenance(workspace_id="workspace:other"))
    manifest = tmp_path / "records" / f"{record.evidence_id[7:]}.json"
    manifest.write_bytes(other.Serialize())

    with pytest.raises(EvidenceIntegrityError, match="manifest digest"):
        store.Get(record.evidence_id)


def test_ConcurrentCooperativeWritersPublishOneCompleteIdentity(tmp_path):
    """Use real filesystem races to verify complete no-overwrite publication."""

    store = LocalEvidenceStore(tmp_path)

    def Publish(_index):
        """Publish one identical collection from a cooperating writer."""

        return store.Put(b"same marker" * 8192, "stdout", "text/plain", Provenance())

    with ThreadPoolExecutor(max_workers=8) as pool:
        records = list(pool.map(Publish, range(24)))

    assert len({record.evidence_id for record in records}) == 1, (
        'Evidence invariant failed: len({record.evidence_id for record in records}) == 1'
    )
    assert store.Get(records[0].evidence_id) == records[0], (
        'Evidence invariant failed: store.Get(records[0].evidence_id) == records[0]'
    )
    assert len(list((tmp_path / "records").iterdir())) == 1, (
        'Evidence invariant failed: len(list((tmp_path / "records").iterdir())) == 1'
    )
    assert len(list((tmp_path / "blobs" / "sha256").iterdir())) == 1, (
        'Evidence invariant failed: len(list((tmp_path / "blobs" / "sha256").iterdir())) == 1'
    )


@pytest.mark.parametrize("partition", ["blobs", "records"])
def test_DirectoriesCannotBeReplacedByRegularFiles(tmp_path, partition):
    """Reject unexpected partition object types before publication."""

    (tmp_path / partition).write_bytes(b"not a directory")

    with pytest.raises((EvidenceIntegrityError, EvidenceStorageError)):
        LocalEvidenceStore(tmp_path).Put(b"marker", "stdout", "text/plain", Provenance())


def test_RawArtifactCannotBeReplacedByDirectory(tmp_path):
    """Refuse non-regular artifacts rather than treating them as usable evidence."""

    store = LocalEvidenceStore(tmp_path)
    record = store.Put(b"marker", "stdout", "text/plain", Provenance())
    path = tmp_path / record.reference.locator
    path.unlink()
    path.mkdir()

    with pytest.raises(EvidenceIntegrityError, match="object kind"):
        store.Read(record.reference)


@pytest.mark.parametrize("location", ["root", "partition", "blob", "manifest"])
def test_ObservedSymlinksCannotEscapeEvidenceRoot(tmp_path, location):
    """Reject actual filesystem symlinks while leaving the owned sentinel untouched."""

    root = tmp_path / "evidence"
    root.mkdir()
    outside = tmp_path / "owned-sentinel"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"unrelated owned fixture")
    store = LocalEvidenceStore(root)
    record = store.Put(b"marker", "stdout", "text/plain", Provenance())

    if location == "root":
        path = tmp_path / "linked-root"
        target = root
        store = LocalEvidenceStore(path)

    elif location == "partition":
        path = root / "records"
        path.rename(root / "original-records")
        target = outside

    elif location == "blob":
        path = root / record.reference.locator
        path.unlink()
        target = sentinel

    else:
        path = root / "records" / f"{record.evidence_id[7:]}.json"
        path.unlink()
        target = sentinel

    try:
        path.symlink_to(target, target_is_directory=target.is_dir())

    except OSError:
        pytest.skip("The runner cannot create symlinks; reparse rejection is tested separately.")

    with pytest.raises(EvidenceIntegrityError, match="links or reparse"):
        store.Get(record.evidence_id)

    assert sentinel.read_bytes() == b"unrelated owned fixture", (
        'Evidence invariant failed: sentinel.read_bytes() == b"unrelated owned fixture"'
    )


def test_WindowsReparseAttributeIsRejectedOnEveryPlatform(tmp_path, monkeypatch):
    """Exercise Windows junction/reparse detection without privileged link creation."""

    original_lstat = Path.lstat

    def ReparseStat(path):
        """Return a reparse attribute only for the owned evidence root."""

        if path == tmp_path:
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)

        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", ReparseStat)

    with pytest.raises(EvidenceIntegrityError, match="links or reparse"):
        LocalEvidenceStore(tmp_path).Put(b"marker", "stdout", "text/plain", Provenance())


def test_ManifestPublicationFailureLeavesOnlyValidOrphanBlob(tmp_path, monkeypatch):
    """Preserve a valid raw blob but never report success after manifest publication failure."""

    original_link = os.link

    def FailManifestLink(source, destination):
        """Deny only the manifest's actual no-overwrite publication operation."""

        if Path(destination).parent.name == "records":
            raise OSError("synthetic manifest publication failure")

        return original_link(source, destination)

    monkeypatch.setattr(os, "link", FailManifestLink)
    store = LocalEvidenceStore(tmp_path)

    with pytest.raises(EvidenceStorageError, match="publish"):
        store.Put(b"marker", "stdout", "text/plain", Provenance())

    assert len(list((tmp_path / "blobs" / "sha256").iterdir())) == 1, (
        'Evidence invariant failed: len(list((tmp_path / "blobs" / "sha256").iterdir())) == 1'
    )
    assert not list((tmp_path / "records").iterdir()), (
        'Evidence invariant failed: not list((tmp_path / "records").iterdir())'
    )
    assert not list(tmp_path.rglob("*.pending")), (
        'Evidence invariant failed: not list(tmp_path.rglob("*.pending"))'
    )
    expected = Record(b"marker").reference

    assert store.Read(expected) == b"marker", "Manifest failure must preserve the raw blob."


def test_FsyncFailurePublishesNoPartialArtifact(tmp_path, monkeypatch):
    """Clean incomplete temporary files when flush durability cannot be established."""

    def FailFsync(_descriptor):
        """Raise at the real fsync boundary before publication."""

        raise OSError("synthetic fsync failure")

    monkeypatch.setattr(os, "fsync", FailFsync)

    with pytest.raises(EvidenceStorageError, match="publish"):
        LocalEvidenceStore(tmp_path).Put(b"marker", "stdout", "text/plain", Provenance())

    assert not list((tmp_path / "blobs" / "sha256").iterdir()), (
        'Evidence invariant failed: not list((tmp_path / "blobs" / "sha256").iterdir())'
    )
    assert not list(tmp_path.rglob("*.pending")), (
        'Evidence invariant failed: not list(tmp_path.rglob("*.pending"))'
    )


@pytest.mark.parametrize("artifact", ["blob", "manifest"])
def test_UnreadableEvidenceIsAnExplicitStorageFailure(tmp_path, monkeypatch, artifact):
    """Keep filesystem read errors distinct from missing or corrupt content."""

    store = LocalEvidenceStore(tmp_path)
    record = store.Put(b"marker", "stdout", "text/plain", Provenance())
    original_open = Path.open

    def DenySelectedRead(path, *args, **kwargs):
        """Deny one owned artifact without changing other filesystem observations."""

        if (path.parent.name == "records") == (artifact == "manifest"):
            raise PermissionError("synthetic read failure")

        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", DenySelectedRead)

    with pytest.raises(EvidenceStorageError, match="could not read"):
        store.Get(record.evidence_id)


@pytest.mark.parametrize("artifact", ["blob", "manifest"])
def test_OversizedCorruptArtifactIsRejectedBeforeOpening(tmp_path, monkeypatch, artifact):
    """Bound corrupt-file ingestion by expected raw size and the manifest size ceiling."""

    store = LocalEvidenceStore(tmp_path)
    record = store.Put(b"marker", "stdout", "text/plain", Provenance())
    path = (
        tmp_path / record.reference.locator if artifact == "blob"
        else tmp_path / "records" / f"{record.evidence_id[7:]}.json"
    )
    path.write_bytes(b"x" * (EVIDENCE_MANIFEST_MAX_BYTES + 1))
    original_open = Path.open

    def ForbidCorruptRead(candidate, *args, **kwargs):
        """Fail the test if oversized corrupt bytes reach the open boundary."""

        if candidate == path:
            pytest.fail("Oversized corrupt evidence must be rejected before reading bytes.")

        return original_open(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "open", ForbidCorruptRead)

    with pytest.raises(EvidenceIntegrityError, match="size bound"):
        store.Get(record.evidence_id)


def test_ManifestSizeLimitIsEnforcedBeforeAnyPublication(tmp_path):
    """Reject caller metadata over the explicit manifest ceiling without leaving raw bytes."""

    provenance = Provenance(workspace_id="x" * EVIDENCE_MANIFEST_MAX_BYTES)

    with pytest.raises(ValueError, match="1 MiB"):
        LocalEvidenceStore(tmp_path).Put(b"marker", "stdout", "text/plain", provenance)

    with pytest.raises(ValueError, match="1 MiB"):
        ParseEvidenceManifest(b"x" * (EVIDENCE_MANIFEST_MAX_BYTES + 1))

    assert not list(tmp_path.iterdir()), "Oversized metadata must not publish raw artifacts."
