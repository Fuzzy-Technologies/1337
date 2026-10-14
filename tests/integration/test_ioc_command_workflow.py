# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual IOC command acquisition, immutable evidence, anchored replay and partial truth."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import subprocess
from dataclasses import replace

import pytest

from fuzzy1337 import ioc_commands as commands
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.ioc_artifacts import LoadIocArtifact
from tests.ioc_cli_helpers import RAW, Files, ImportArguments, InspectArguments, Owned, Run


def Denied(*args, **kwargs):
    """Expose any accidental acquisition/replay network, process or source discovery side effect."""

    raise AssertionError("IOC command attempted network or process activity")


def test_ActualImportAndRelocatedReadOnlyInspectRetainOriginals(tmp_path, monkeypatch):
    """Run real SDK/store boundaries and independently check the source occurrence oracle."""

    root, source = Owned(tmp_path)
    core_before = {name: Files(root)[name] for name in (
        "workspace.json", "state/model/model.json")}
    monkeypatch.setattr(socket, "socket", Denied)
    monkeypatch.setattr(socket, "getaddrinfo", Denied)
    monkeypatch.setattr(subprocess, "Popen", Denied)
    status, result = Run(ImportArguments(root, source))
    assert status == 0 and result["evidence_commit"] == "confirmed", (
        "Actual IOC command did not confirm all original immutable acquisition records"
    )
    store = LocalEvidenceStore(root / "evidence")
    raw = store.Get(result["raw_id"])
    receipt = store.Get(result["receipt_id"])
    snapshot = store.Get(result["snapshot_id"])
    assert store.Read(raw.reference) == RAW and raw.provenance == receipt.provenance == (
        snapshot.provenance
    ), "Product acquisition changed original bytes or common acquisition attribution"
    parsed = LoadIocArtifact(root, snapshot.evidence_id, receipt.evidence_id)
    assert [candidate.normalized_token for candidate in parsed.candidates] == [
        "192.0.2.7", "2001:db8::1", "example.invalid", "a" * 64, "example.invalid"
    ], "Product import differs from its independent supplied-candidate oracle"
    assert parsed.candidates[-1].observed_at_utc == "2099-01-01T06:30:00.000000+00:00", (
        "Source-declared future observation was replaced by the receiver acquisition clock"
    )
    moved = tmp_path / "relocated workspace"
    shutil.move(root, moved)
    source.unlink()
    before = Files(moved)
    monkeypatch.setattr(commands, "ReadOwnedIoc", Denied)
    monkeypatch.setattr(commands, "AcquireIocArtifact", Denied)
    status, inspected = Run(InspectArguments(moved, result))
    assert status == 0 and inspected["raw_id"] == result["raw_id"] and inspected[
        "evidence_commit"
    ] == "not-attempted", "Inspection rediscovered input or attempted evidence publication"
    assert Files(moved) == before and all(before[name] == content
        for name, content in core_before.items()), "IOC product workflow wrote Core/owning state"


@pytest.mark.parametrize("raw,pin,state", [(b"bad-source", None, "parse-rejected"),
    (RAW, "b" * 64, "digest-rejected"), (b"", None, "parse-rejected")],
    ids=("parse", "digest", "empty"))
def test_RefusalRetainsActualRawAndTerminalReceiptWithoutSnapshot(tmp_path, raw, pin, state):
    """Malformed or mismatching selected bytes retain truthful, usable refusal evidence."""

    root, source = Owned(tmp_path, raw)
    arguments = ImportArguments(root, source, raw)

    if pin is not None:
        arguments[arguments.index("--expected-sha256") + 1] = pin

    status, result = Run(arguments)
    assert status == 4 and result["acquisition_state"] == state and result["snapshot_id"] is None, (
        "Refused IOC input supplied a success snapshot or incorrect terminal state"
    )
    assert result["evidence_commit"] == "confirmed", "Refusal lost confirmed original records"
    store = LocalEvidenceStore(root / "evidence")
    assert store.Read(store.Get(result["raw_id"]).reference) == raw, (
        "Refusal rewrote or discarded original selected bytes"
    )
    receipt = json.loads(store.Read(store.Get(result["receipt_id"]).reference))
    assert receipt["state"] == state and receipt["raw_evidence_id"] == result["raw_id"], (
        "Refusal receipt does not describe its original source acquisition"
    )


def test_CoherentAlternativeReceiptAndSnapshotCannotReplaceIndependentAnchor(tmp_path):
    """Rehashed metadata sharing raw bytes must not borrow a separately retained receipt pin."""

    root, source = Owned(tmp_path)
    status, result = Run(ImportArguments(root, source))
    assert status == 0, "Owned IOC fixture acquisition failed"
    store = LocalEvidenceStore(root / "evidence")
    receipt = store.Get(result["receipt_id"])
    original = LoadIocArtifact(root, result["snapshot_id"], result["receipt_id"])
    forged_source = replace(original.source, license_name="forged-license")
    document = json.loads(store.Read(receipt.reference))
    document["source"] = forged_source.ToDict()
    document["request_sha256"] = commands.RequestPin(forged_source, original.limits)
    forged_receipt = store.Put(json.dumps(document, sort_keys=True, separators=(",", ":")).encode(),
                              "ioc-acquisition", "application/json", receipt.provenance)
    forged = replace(original, source=forged_source,
                     acquisition_evidence_id=forged_receipt.evidence_id)
    forged_snapshot = store.Put(forged.Serialize(), "ioc-snapshot", "application/json",
                                receipt.provenance)
    before = Files(root)
    status, rejected = Run(["ioc", "inspect", str(root), "--snapshot",
        forged_snapshot.evidence_id, "--receipt", result["receipt_id"]])
    assert status == 4 and rejected["failure"] == "integrity" and Files(root) == before, (
        "Product inspect inferred its trusted receipt from coherently replaced candidate metadata"
    )


@pytest.mark.parametrize("record_key", ["raw_id", "receipt_id", "snapshot_id"])
def test_OriginalChainCorruptionFailsReadOnlyInspection(tmp_path, record_key):
    """Every original raw/receipt/snapshot byte role remains required by product inspection."""

    root, source = Owned(tmp_path)
    status, result = Run(ImportArguments(root, source))
    assert status == 0, "Owned IOC fixture acquisition failed"
    record = LocalEvidenceStore(root / "evidence").Get(result[record_key])
    (root / "evidence" / record.reference.locator).write_bytes(b"corrupt")
    before = Files(root)
    status, rejected = Run(InspectArguments(root, result))
    assert status == 4 and rejected["failure"] == "integrity" and Files(root) == before, (
        "Product inspection ignored corrupt original chain bytes or rewrote evidence"
    )


@pytest.mark.parametrize("phase", ["raw", "receipt", "snapshot"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt], ids=("storage", "interrupt"))
def test_LostPublicationAcknowledgementRetainsOrphansAndReportsUncertainty(
    tmp_path, monkeypatch, phase, error,
):
    """Lost acknowledgement must not claim rollback, success or invented confirmed identities."""

    root, source = Owned(tmp_path)
    original = commands.IocEvidenceStore.Put
    role = {"raw": "ioc-source", "receipt": "ioc-acquisition", "snapshot": "ioc-snapshot"}[phase]

    def Put(store, payload, selected_role, media_type, provenance):
        """Publish real immutable bytes then simulate the missing acknowledgement of one role."""

        record = original(store, payload, selected_role, media_type, provenance)

        if selected_role == role:
            raise error("secret-sentinel")

        return record

    monkeypatch.setattr(commands.IocEvidenceStore, "Put", Put)
    status, result = Run(ImportArguments(root, source))
    assert status == (130 if error is KeyboardInterrupt else 4) and result["evidence_commit"] == (
        "unknown"
    ), "Lost IOC publication acknowledgement became confirmed success or rollback"
    assert result["raw_id"] is None and "secret-sentinel" not in str(result), (
        "Unacknowledged acquisition invented retained identities or leaked storage exceptions"
    )
    assert any(path.is_file() for path in (root / "evidence").rglob("*")), (
        "Error handler silently rolled back immutable original evidence"
    )


def test_ImportCallerByteQuotaRejectsBeforeAcquisition(tmp_path):
    """A selected file exceeding the finite byte budget is refused without a truncated receipt."""

    raw = b"x" * 65537
    root, source = Owned(tmp_path, raw)
    before = Files(root)
    status, result = Run(ImportArguments(root, source, raw))
    assert status == 2 and result["evidence_commit"] == "not-attempted" and Files(root) == before, (
        "Oversize selected IOC bytes were read, truncated or acquired"
    )
    assert result["source_sha256"] is None, "Unacquired selected bytes received a source proof"


def test_ReportedSourceHashIsObservedOriginalBytes(tmp_path):
    """A digest refusal must report its actual retained hash separately from the rejected pin."""

    root, source = Owned(tmp_path)
    arguments = ImportArguments(root, source)
    arguments[arguments.index("--expected-sha256") + 1] = "b" * 64
    status, result = Run(arguments)
    assert status == 4 and result["source_sha256"] == hashlib.sha256(RAW).hexdigest(), (
        "IOC refusal repaired the expected pin or replaced the actual observed original digest"
    )
