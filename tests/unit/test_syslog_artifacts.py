# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real original/receipt ownership, independent anchors and truthful partial publication."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace

import pytest

from fuzzy1337 import syslog_artifacts as artifacts
from fuzzy1337.adapters.contracts import EvidenceReference
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.syslog_records import SyslogJson
from tests.syslog_helpers import CONSENT, ORIGINAL, Files, Owned, Source


def Acquire(root, path, payload=ORIGINAL, framing="lines"):
    """Use the genuine original file operation with fixed descriptive read references."""

    return artifacts.ImportSavedSyslogFile(root, path, Source(payload, framing),
        scopeReference="collection:fixture", consent=CONSENT)


def test_ActualOwnerReopensCopiedOriginalWithExactProvenanceAndNoFileOrModel(tmp_path, monkeypatch):
    """Copy the complete store, remove both inputs and reparse solely through original pins."""

    root, path = Owned(tmp_path)
    before = Files(root)
    result = Acquire(root, path)
    assert result.state == "succeeded" and result.rawAck == result.receiptAck == "confirmed", (
        "A genuine syslog file import must verify both independent original publications"
    )
    store = LocalEvidenceStore(root / "evidence")
    assert store.Read(result.raw.reference) == ORIGINAL, "Acquisition changed original file bytes"
    receipt = json.loads(store.Read(result.receipt.reference))
    assert receipt["read"] == {"actor_reference": CONSENT.actor_ref,
                               "consent_reference": CONSENT.record_ref}, (
        "The profile receipt lost the original descriptive selected-file read references"
    )
    assert receipt["parser_id"] == "syslog-rfc5424" and receipt["source"] == (
        Source().ToDict()
    ), "Parser identity and original source attribution must remain separate"
    assert result.raw.provenance.source_id == "fixture.syslog" and (
        result.raw.provenance.tool_version is None
        and result.raw.provenance.execution is None
        and result.raw.provenance.invocation_sha256 is None
    ), "Acquisition invented producer version, execution or Core semantics"
    assert all(Files(root)[key] == value for key, value in before.items()), (
        "The source-only importer changed existing workspace bytes"
    )
    moved = tmp_path / "copied"
    shutil.copytree(root, moved)
    shutil.rmtree(root)
    path.unlink()
    retained = Files(moved)

    def Denied(*arguments, **keywords):
        """Tripwire any new read acquisition or owning publication during retained replay."""

        raise AssertionError("Replay attempted acquisition or publication")

    monkeypatch.setattr(artifacts, "ReadArtifactFile", Denied)
    monkeypatch.setattr(LocalEvidenceStore, "Put", Denied)
    replay = artifacts.LoadSavedSyslog(moved, result.receipt.evidence_id, Source().expectedSha256)
    assert replay.document == result.document and replay.source == result.source and (
        replay.raw == result.raw and replay.receipt == result.receipt
        and replay.readConsent == CONSENT and replay.ackBasis == "verified-present"
    ), "Relocated retained replay changed original records, source or read attribution"
    repeated = artifacts.LoadSavedSyslog(
        moved, result.receipt.evidence_id, Source().expectedSha256)
    assert repeated == replay, (
        "Repeated retained syslog verification must be deterministic without a new clock"
    )
    assert Files(moved) == retained, "Retained replay changed persisted workspace bytes"


def test_DigestRefusalPublishesNothingAndParserRefusalRetainsOnlyVerifiedOriginals(tmp_path):
    """A wrong pin never publishes; correct malformed bytes retain original raw and refusal."""

    root, path = Owned(tmp_path)
    before = Files(root)
    wrong = replace(Source(), expectedSha256="0" * 64)
    result = artifacts.ImportSavedSyslogFile(root, path, wrong,
        scopeReference="collection:fixture", consent=CONSENT)
    assert result.state == "digest-rejected" and result.raw is result.receipt is None and (
        result.document is None and result.rawAck == result.receiptAck == "not-attempted"
        and result.sourceSha256 == hashlib.sha256(ORIGINAL).hexdigest()
    ), "Independent source-pin refusal must not imply a verified original publication"
    assert Files(root) == before, "Wrong independent source checksum wrote evidence"
    malformed = b"<0>1 - - - - - [broken"
    path.write_bytes(malformed)
    rejected = Acquire(root, path, malformed, "single")
    assert rejected.state == "parse-rejected" and rejected.document is None and (
        rejected.rawAck == rejected.receiptAck == "confirmed"
    ), "Parser refusal must retain its complete verified original without usable records"
    assert artifacts.LoadSavedSyslog(root, rejected.receipt.evidence_id,
        hashlib.sha256(malformed).hexdigest()).state == "parse-rejected", (
        "Retained refusal must reproduce the original parser result"
    )


@pytest.mark.parametrize("role,after,interrupt", [
    (artifacts.RAW_ROLE, False, False), (artifacts.RAW_ROLE, True, False),
    (artifacts.RECEIPT_ROLE, False, False), (artifacts.RECEIPT_ROLE, True, False),
    (artifacts.RAW_ROLE, True, True), (artifacts.RECEIPT_ROLE, True, True),
])
def test_PublicationFailuresPreserveIndependentAcknowledgementsAndRecoverActualReceipt(
    tmp_path, monkeypatch, role, after, interrupt,
):
    """Loss before/after each real owner publication never turns uncertainty into rollback."""

    root, path = Owned(tmp_path)
    original = LocalEvidenceStore.Put
    observed = []

    def Publish(self, data, selectedRole, media, provenance):
        """Inject failure at one independent owner boundary around its actual publication."""

        if selectedRole == role and not after:
            raise OSError("inert injected publication failure")

        record = original(self, data, selectedRole, media, provenance)
        observed.append(record)

        if selectedRole == role:
            if interrupt:
                raise KeyboardInterrupt

            raise OSError("inert lost publication acknowledgement")

        return record

    monkeypatch.setattr(LocalEvidenceStore, "Put", Publish)
    result = Acquire(root, path)
    assert result.state == ("interrupted" if interrupt else "storage-failed") and (
        result.document is None and result.receipt is None
        and result.receiptAck == ("not-attempted" if role == artifacts.RAW_ROLE else "unknown")
        and result.rawAck == ("unknown" if role == artifacts.RAW_ROLE else "confirmed")
    ), "A storage fault falsely exposed records, rollback or confirmed an unreturned owner ACK"
    assert (result.raw is None) == (role == artifacts.RAW_ROLE), (
        "Earlier independently verified raw publication must survive a later receipt failure"
    )
    originalReceipts = [record for record in observed if record.reference.role == (
        artifacts.RECEIPT_ROLE)]

    if originalReceipts:
        before = Files(root)
        replay = artifacts.LoadSavedSyslog(root, originalReceipts[0].evidence_id,
                                           Source().expectedSha256)
        assert replay.state == "succeeded" and replay.ackBasis == "verified-present", (
            "An actually saved receipt whose reply was lost must be recoverable by original pins"
        )
        assert Files(root) == before, "Lost-ACK recovery wrote or refreshed original custody"


@pytest.mark.parametrize("selection", ["raw", "receipt", "foreign", "pin", "manifest"])
def test_CorruptMixedOrForeignSelectionsRefuseBeforeReturningRecords(tmp_path, selection):
    """Receipt role, byte pin, workspace identity, manifests and complete originals are checked."""

    root, path = Owned(tmp_path)
    result = Acquire(root, path)
    receiptId = result.receipt.evidence_id
    digest = Source().expectedSha256
    selected = root

    if selection in ("raw", "receipt"):
        record = result.raw if selection == "raw" else result.receipt
        (root / "evidence" / record.reference.locator).write_bytes(b"corrupt")

    elif selection == "manifest":
        (root / "evidence/records" / (receiptId[7:] + ".json")).write_bytes(b"{}")

    elif selection == "foreign":
        selected = tmp_path / "foreign"
        from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

        LocalWorkspaceStore(selected).Create(WorkspaceConfiguration("Other"), "foreign")
        shutil.copytree(root / "evidence", selected / "evidence", dirs_exist_ok=True)

    else:
        digest = "0" * 64

    before = Files(selected)

    with pytest.raises((ValueError, EvidenceError)):
        artifacts.LoadSavedSyslog(selected, receiptId, digest)

    assert Files(selected) == before, "Refused retained selection changed persisted bytes"


def test_ReceiptAndRawCannotSelectEachOtherAndUnrelatedCorruptionIsIgnored(tmp_path):
    """Select exactly one original receipt chain rather than all workspace evidence."""

    root, path = Owned(tmp_path)
    result = Acquire(root, path)

    with pytest.raises(ValueError):
        artifacts.LoadSavedSyslog(root, result.raw.evidence_id, Source().expectedSha256)

    other = LocalEvidenceStore(root / "evidence").Put(b"unrelated", "unrelated",
                                                    "text/plain", result.raw.provenance)
    (root / "evidence" / other.reference.locator).write_bytes(b"corrupt")
    assert artifacts.LoadSavedSyslog(root, result.receipt.evidence_id,
        Source().expectedSha256).document == result.document, (
        "Unselected unrelated evidence must not become an artificial replay dependency"
    )


@pytest.mark.parametrize("role,media,size", [
    ("other", "application/octet-stream", 1),
    (artifacts.RAW_ROLE, "text/plain", 1),
    (artifacts.RAW_ROLE, "application/octet-stream", 0),
    (artifacts.RAW_ROLE, "application/octet-stream", 1024 * 1024 + 1),
])
def test_RoleAndSizePreflightHappensBeforeTheOwnersEagerBlobRead(
    tmp_path, monkeypatch, role, media, size,
):
    """An untrusted manifest cannot allocate its declared blob size through owner Get."""

    store = artifacts.SyslogEvidenceStore(tmp_path, artifacts.RAW_ROLE)

    def Denied(*arguments, **keywords):
        """Prove rejected role/media/size metadata never reaches the owner's raw read."""

        raise AssertionError("Unbounded original owner read occurred")

    monkeypatch.setattr(LocalEvidenceStore, "Read", Denied)

    with pytest.raises(ValueError):
        store.Read(EvidenceReference(role, "blobs/sha256/" + "0" * 64, "0" * 64, media, size))


@pytest.mark.parametrize("field,value", [
    ("sourceId", ""), ("sourceVersion", ""), ("sourceLocator", "secret\nmarker"),
    ("expectedSha256", "A" * 64), ("framing", "auto"), ("sourceToolVersion", ""),
])
def test_SourceDeclarationsRequireClosedBoundedMetadata(field, value):
    """Source metadata is bounded independently from permitted RFC control-bearing SD values."""

    with pytest.raises(ValueError):
        replace(Source(), **{field: value})


@pytest.mark.parametrize("change", [
    {"state": "invented"}, {"ackBasis": "authenticated"}, {"rawAck": "confirmed"},
    {"receiptAck": "unknown", "state": "succeeded"}, {"document": b"{}"},
])
def test_OutcomeCannotInventCompletionOrMutableAuthority(change):
    """Only internally consistent original ACKs may accompany an immutable source result."""

    with pytest.raises(ValueError):
        values = {"state": "storage-failed", "source": Source(),
                  "sourceSha256": Source().expectedSha256, **change}
        artifacts.SyslogAcquisition(**values)


def test_ReceiptClosedCanonicalGrammarAndReplayProfileAreEnforced(tmp_path):
    """Candidate metadata cannot change framing, source, parser, limits or canonical syntax."""

    root, path = Owned(tmp_path)
    result = Acquire(root, path)
    store = LocalEvidenceStore(root / "evidence")
    payload = store.Read(result.receipt.reference)
    document = json.loads(payload)
    assert artifacts.SyslogReceipt(payload) == document, (
        "The original canonical receipt was refused"
    )

    for key, value in (
        ("schema_version", True), ("profile", "other"), ("parser_id", "other"),
        ("parser_version", "2"), ("limits", {}), ("method", "network"),
        ("state", "invented"), ("parse_error", {}), ("document_sha256", "A" * 64),
    ):
        changed = {**document, key: value}

        with pytest.raises(ValueError):
            artifacts.SyslogReceipt(SyslogJson(changed))

    for invalid in (b"", payload + b" ", b'{"duplicate":1,"duplicate":2}', b'{"x":NaN}',
                    b"\xff", b"[" * 1100, b"x" * (artifacts.MAX_SYSLOG_RECEIPT_BYTES + 1)):
        with pytest.raises(ValueError):
            artifacts.SyslogReceipt(invalid)

    substituted = json.loads(payload)
    substituted["source"]["source_version"] = "substituted"
    forged = store.Put(SyslogJson(substituted), artifacts.RECEIPT_ROLE,
                       "application/json", result.receipt.provenance)

    with pytest.raises(ValueError):
        artifacts.LoadSavedSyslog(root, forged.evidence_id, Source().expectedSha256)


def test_ReadSelectionsRejectEmptySourcesAndInvalidMetadataBeforePublication(tmp_path):
    """No model, inferred source path, unsupported facade role or missing pin is accepted."""

    root, path = Owned(tmp_path, b"")
    before = Files(root)

    with pytest.raises(ValueError):
        Acquire(root, path, b"", "single")

    with pytest.raises(ValueError):
        artifacts.LoadSavedSyslog(root, "0" * 64, Source().expectedSha256)

    with pytest.raises(ValueError):
        artifacts.SyslogEvidenceStore(root, "other")

    with pytest.raises(ValueError):
        artifacts.ImportSavedSyslogFile(root, path, Source(), scopeReference="",
                                         consent=CONSENT)

    with pytest.raises(ValueError):
        artifacts.SourceFromDict({**Source().ToDict(), "extra": True})

    assert Files(root) == before, "Invalid local selections published evidence"


@pytest.mark.parametrize("field,value", [
    ("raw_id", "sha256:" + "0" * 64),
    ("document_sha256", "0" * 64),
    ("state", "parse-rejected"),
    ("read", {"actor_reference": "", "consent_reference": "read:fixture"}),
])
def test_SelectedReceiptMustMatchOriginalReparseAndClosedReadMetadata(tmp_path, field, value):
    """A newly pinned candidate receipt still cannot lie about selected source results."""

    root, path = Owned(tmp_path)
    result = Acquire(root, path)
    store = LocalEvidenceStore(root / "evidence")
    data = json.loads(store.Read(result.receipt.reference))
    data[field] = value
    forged = store.Put(SyslogJson(data), artifacts.RECEIPT_ROLE,
                       "application/json", result.receipt.provenance)
    before = Files(root)

    with pytest.raises(ValueError):
        artifacts.LoadSavedSyslog(root, forged.evidence_id, Source().expectedSha256)

    assert Files(root) == before, "Invalid selected receipt verification changed owning files"


def test_DeclaredProducerVersionAndReceiptBudgetRemainSeparateFromParser(tmp_path, monkeypatch):
    """Known producer versions are explicit and receipt oversize fails before any publication."""

    root, path = Owned(tmp_path)
    source = replace(Source(), sourceToolVersion="producer-9")
    result = artifacts.ImportSavedSyslogFile(root, path, source,
        scopeReference="collection:fixture", consent=CONSENT)
    assert result.raw.provenance.tool_version == "producer-9", (
        "An explicitly declared original producer version was replaced by parser version"
    )
    assert artifacts.LoadSavedSyslog(root, result.receipt.evidence_id,
        source.expectedSha256).source == source, "Retained replay lost the producer declaration"
    monkeypatch.setattr(artifacts, "MAX_SYSLOG_RECEIPT_BYTES", 1)
    before = Files(root)

    with pytest.raises(ValueError):
        Acquire(root, path)

    assert Files(root) == before, "Receipt budget refusal published a raw orphan before preflight"


@pytest.mark.parametrize("change", [
    {"source": "not-a-source"}, {"readConsent": "not-a-declaration"},
    {"rawAck": "invented"}, {"document": bytearray(b"{}"), "state": "storage-failed"},
])
def test_ResultTypesAndAcknowledgementDomainsAreClosed(change):
    """Mutable or foreign source/result payloads cannot substitute for original typed facts."""

    values = {"state": "storage-failed", "source": Source(),
              "sourceSha256": Source().expectedSha256, **change}

    with pytest.raises(ValueError):
        artifacts.SyslogAcquisition(**values)


@pytest.mark.parametrize("role", [artifacts.RAW_ROLE, artifacts.RECEIPT_ROLE])
def test_SubstitutedPublicationContextCannotBecomeVerifiedCompletion(tmp_path, monkeypatch, role):
    """Even an actual saved different record must match this operation's exact expected manifest."""

    root, path = Owned(tmp_path)
    original = LocalEvidenceStore.Put

    def Substitute(self, data, selectedRole, media, provenance):
        """Publish genuine bytes under a different source acquisition context."""

        selected = replace(provenance, scope_reference="collection:substituted") if (
            selectedRole == role) else provenance

        return original(self, data, selectedRole, media, selected)

    monkeypatch.setattr(LocalEvidenceStore, "Put", Substitute)
    result = Acquire(root, path)
    assert result.state == "storage-failed" and result.document is None and (
        result.rawAck == ("unknown" if role == artifacts.RAW_ROLE else "confirmed")
        and result.receiptAck == ("not-attempted" if role == artifacts.RAW_ROLE else "unknown")
    ), "A different real publication context must not impersonate this operation's original"


def test_ReceiptNestedStructureAndCanonicalRefusalMetadataAreBounded(tmp_path):
    """Closed root fields do not grant unlimited nested receipt allocation or invented errors."""

    root, path = Owned(tmp_path)
    result = Acquire(root, path)
    store = LocalEvidenceStore(root / "evidence")
    original = json.loads(store.Read(result.receipt.reference))
    nested = None

    for _ in range(10):
        nested = [nested]

    for field, value in (("raw", nested), ("raw", [None] * 4100)):
        with pytest.raises(ValueError):
            artifacts.SyslogReceipt(SyslogJson({**original, field: value}))

    for refusal in (
        {"code": "header", "record_index": -1, "byte_offset": 0},
        {"code": "header", "record_index": 1, "byte_offset": True},
        {"code": False, "record_index": 1, "byte_offset": 0},
    ):
        changed = {**original, "state": "parse-rejected", "parse_error": refusal,
                   "document_sha256": None}

        with pytest.raises(ValueError):
            artifacts.SyslogReceipt(SyslogJson(changed))


def test_SelectedFileMutationDuringActualGuardedReadNeverPublishes(tmp_path, monkeypatch):
    """An observed changing selected file is refused by the reused owner before any custody."""

    root, path = Owned(tmp_path)
    originalBuffer = artifacts.BytesIO
    before = Files(root)

    class MutatingBuffer(originalBuffer):
        """Mutate only the test-owned input while the genuine file reader is consuming it."""

        def Write(self, chunk):
            """Accept the first original chunk then change the selected physical file."""

            written = super().write(chunk)
            path.write_bytes(ORIGINAL + b"changed")

            return written

        write = Write

    monkeypatch.setattr(artifacts, "BytesIO", MutatingBuffer)

    with pytest.raises(ValueError):
        Acquire(root, path)

    assert Files(root) == before, "Unstable selected file published source or receipt evidence"
