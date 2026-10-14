# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exact typed IOC boundaries and pure-phase file/process/network mutation tripwires."""

from __future__ import annotations

import builtins
import hashlib
import socket
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337 import ioc_artifacts as ioc
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord
from fuzzy1337.ioc_artifacts import (
    AcquireIocArtifact,
    IocCandidate,
    IocLimits,
    IocRequest,
    IocSnapshot,
    IocSource,
    ParseIocArtifact,
    ReplayIocArtifact,
)
from fuzzy1337.workspace import LocalWorkspaceStore

RAW = b"dns\tEXAMPLE.Invalid.\n"


def Selection():
    """Return one explicit synthetic byte selection without external-source access."""

    return IocSource("owned.synthetic", "fixture-1", "owned:case.tsv", "Apache-2.0",
                     "owned:LICENSE", hashlib.sha256(RAW).hexdigest())


def Denied(*args, **kwargs):
    """Fail immediately if a pure parser or serializer attempts any ambient side effect."""

    raise AssertionError("Pure IOC transformation attempted filesystem, process or network I/O")


def test_ContractPureParsingAndSerializationHaveNoIoOrCoreWrites(monkeypatch):
    """Candidate normalization and strict interchange require only explicit caller-owned bytes."""

    source = Selection()

    with monkeypatch.context() as isolated:
        isolated.setattr(builtins, "open", Denied)
        isolated.setattr(Path, "open", Denied)
        isolated.setattr(socket, "socket", Denied)
        isolated.setattr(socket, "getaddrinfo", Denied)
        isolated.setattr(subprocess, "Popen", Denied)
        isolated.setattr(LocalWorkspaceStore, "Open", Denied)
        candidates = ParseIocArtifact(RAW, source)
        selection_pin = ioc.RequestPin(source, IocLimits())
        snapshot = IocSnapshot("sha256:" + "a" * 64, "sha256:" + "b" * 64, source,
                               IocLimits(), candidates)
        serialized = snapshot.Serialize()
        decoded = ioc.Metadata(serialized, 512 * 1024)

    assert decoded["candidates"][0]["normalized_token"] == "example.invalid", (
        "Pure parser/serializer failed its explicit synthetic candidate oracle"
    )
    assert len(selection_pin) == 64, "Pure selection description lost its canonical digest shape"
    assert set(decoded) == {"schema_version", "family", "profile", "parser_id", "parser_version",
                           "raw_evidence_id", "acquisition_evidence_id", "source", "limits",
                           "candidates"}, "IOC interchange gained inferred incident/model semantics"


class ForeignSource(IocSource):
    """Synthetic subclass representing a foreign typed replacement at the API boundary."""


class ForeignLimits(IocLimits):
    """Synthetic subclass representing an unreviewed resource profile replacement."""


class ForeignRequest(IocRequest):
    """Synthetic request subclass that must not borrow the closed acquisition family."""


class ForeignCandidate(IocCandidate):
    """Synthetic derived candidate subclass that must not change serialized semantics."""


class ForeignSnapshot(IocSnapshot):
    """Synthetic derived snapshot subclass that cannot borrow original serialization."""


class ForeignRecord(EvidenceRecord):
    """Synthetic manifest subclass that must not borrow the original evidence owner."""


@pytest.mark.parametrize("replacement", ["source", "limits", "source-frozen", "limits-frozen"])
def test_ContractForeignAndFrozenSourceBudgetsFailBeforeAnyIo(monkeypatch, replacement):
    """Pure/acquisition boundaries revalidate frozen fields and require exact runtime types."""

    source = Selection()
    limits = IocLimits()

    if replacement == "source":
        source = ForeignSource(**source.ToDict())

    elif replacement == "limits":
        limits = ForeignLimits()

    elif replacement == "source-frozen":
        object.__setattr__(source, "source_version", "bad\nversion")

    else:
        object.__setattr__(limits, "max_bytes", 65537)

    monkeypatch.setattr(LocalWorkspaceStore, "Open", Denied)

    with pytest.raises(ValueError):
        ParseIocArtifact(RAW, source, limits)

    with pytest.raises(ValueError):
        IocRequest(RAW, source, limits)


@pytest.mark.parametrize("replacement", ["foreign", "untyped", "payload-frozen", "source-frozen"])
def test_ContractAcquisitionRevalidatesRequestBeforeOpeningOwner(monkeypatch, replacement):
    """A foreign or mutated frozen request cannot publish artifacts through original acquisition."""

    request = IocRequest(RAW, Selection())

    if replacement == "foreign":
        request = ForeignRequest(request.payload, request.source)

    elif replacement == "untyped":
        request = object()

    elif replacement == "payload-frozen":
        object.__setattr__(request, "payload", bytearray(RAW))

    else:
        object.__setattr__(request.source, "expected_sha256", "A" * 64)

    monkeypatch.setattr(LocalWorkspaceStore, "Open", Denied)

    with pytest.raises(ValueError):
        AcquireIocArtifact(Path("owned"), request, scope_reference="scope:owned")


@pytest.mark.parametrize("replacement", ["foreign", "normalized-frozen", "coordinate-frozen"])
def test_ContractSnapshotRevalidatesExactCandidateFacts(replacement):
    """Frozen-field mutation cannot serialize invalid normalization or coordinate types."""

    source = Selection()
    candidate = ParseIocArtifact(RAW, source)[0]

    if replacement == "foreign":
        candidate = ForeignCandidate(**candidate.ToDict())

    elif replacement == "normalized-frozen":
        object.__setattr__(candidate, "normalized_token", "else.invalid")

    else:
        object.__setattr__(candidate, "line_number", True)

    snapshot = IocSnapshot("sha256:" + "a" * 64, "sha256:" + "b" * 64, source,
                           IocLimits(), (candidate,))

    with pytest.raises(ValueError):
        snapshot.Serialize()


def test_ContractForeignSnapshotCannotBorrowOriginalSerializer():
    """Serialization itself is an exact typed boundary without foreign snapshot replacements."""

    source = Selection()
    snapshot = ForeignSnapshot("sha256:" + "a" * 64, "sha256:" + "b" * 64, source,
                               IocLimits(), ParseIocArtifact(RAW, source))

    with pytest.raises(ValueError):
        snapshot.Serialize()


@pytest.mark.parametrize("record", [object(), None])
def test_ContractReplayRejectsUntypedManifestBeforeOpeningOwner(monkeypatch, record):
    """Replay accepts exact first-party immutable evidence records only."""

    monkeypatch.setattr(LocalWorkspaceStore, "Open", Denied)

    with pytest.raises(ValueError):
        ReplayIocArtifact(Path("owned"), record, record)


@pytest.mark.parametrize("role,media,size", [
    ("stdout", "text/plain", 1), ("ioc-source", "application/json", 1),
    ("ioc-source", "text/tab-separated-values", 65537),
    ("ioc-snapshot", "application/json", 524289),
    ("ioc-acquisition", "application/json", 8193),
])
def test_ContractOwningConsumerRejectsBudgetBeforeReadingAnyBlob(monkeypatch, role, media, size):
    """Closed evidence roles/media/size are checked before eager owner blob verification."""

    reference = ioc.EvidenceReference(role, "blobs/sha256/" + "a" * 64, "a" * 64, media, size)
    store = ioc.IocEvidenceStore(Path("owned/evidence"))
    monkeypatch.setattr(store, "ReadStoredBytes", Denied)

    with pytest.raises(ValueError):
        store.Read(reference)


def test_ContractDeclaredSourceBudgetAppliesBeforeTheEagerBlobRead(monkeypatch):
    """Replay's original receipt budget constrains reads beneath the global source ceiling."""

    store = ioc.IocEvidenceStore(Path("owned/evidence"), source_max_bytes=1)
    reference = ioc.EvidenceReference("ioc-source", "blobs/sha256/" + "a" * 64,
                                     "a" * 64, "text/tab-separated-values", 2)
    monkeypatch.setattr(store, "ReadStoredBytes", Denied)

    with pytest.raises(ValueError, match="budget"):
        store.Read(reference)


def test_ContractForeignManifestCannotBorrowOriginalReplay(monkeypatch):
    """Evidence record subclasses fail before workspace or blob access."""

    provenance = EvidenceProvenance("owned", "scope:owned", "ioc-artifacts", "1", "1",
                                    "2026-10-14T10:00:00Z", "2026-10-14T10:00:01Z")
    reference = ioc.EvidenceReference("ioc-snapshot", "blobs/sha256/" + "a" * 64,
                                     "a" * 64, "application/json", 0)
    record = ForeignRecord(reference, provenance)
    monkeypatch.setattr(LocalWorkspaceStore, "Open", Denied)

    with pytest.raises(ValueError):
        ReplayIocArtifact(Path("owned"), record, record)


@pytest.mark.parametrize("acquisition_record", [None, object()], ids=("missing", "foreign"))
def test_ContractReplayRequiresIndependentExactAcquisitionRecord(monkeypatch, acquisition_record):
    """The second original receipt anchor is mandatory and independently typed before any I/O."""

    provenance = EvidenceProvenance("owned", "scope:owned", "ioc-artifacts", "1", "1",
                                    "2026-10-14T10:00:00Z", "2026-10-14T10:00:01Z")
    reference = ioc.EvidenceReference("ioc-snapshot", "blobs/sha256/" + "a" * 64,
                                     "a" * 64, "application/json", 0)
    record = EvidenceRecord(reference, provenance)
    monkeypatch.setattr(LocalWorkspaceStore, "Open", Denied)

    with pytest.raises(ValueError):
        ReplayIocArtifact(Path("owned"), record, acquisition_record)


def test_ContractFrozenNestedRecordCannotReplaceOriginalOwnerFacts():
    """Canonical reconstruction detects altered frozen evidence identities and nested provenance."""

    provenance = EvidenceProvenance("owned", "scope:owned", "ioc-artifacts", "1", "1",
                                    "2026-10-14T10:00:00Z", "2026-10-14T10:00:01Z")
    reference = ioc.EvidenceReference("ioc-snapshot", "blobs/sha256/" + "a" * 64,
                                     "a" * 64, "application/json", 0)
    record = EvidenceRecord(reference, provenance)
    object.__setattr__(record, "evidence_id", "sha256:" + "b" * 64)

    with pytest.raises(ValueError):
        ioc.OriginalRecord(record, "owned", ioc.IocEvidenceStore(Path("owned/evidence")),
                           "ioc-snapshot")

    original = replace(record)
    object.__setattr__(original, "provenance", object())

    with pytest.raises(ValueError):
        ioc.OriginalRecord(original, "owned", ioc.IocEvidenceStore(Path("owned/evidence")),
                           "ioc-snapshot")
