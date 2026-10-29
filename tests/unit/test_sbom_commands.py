# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded source descriptors, explicit grammar and early original-custody refusals."""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

import fuzzy1337.sbom_commands as commands
from fuzzy1337 import artifact_inputs
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import EvidenceError, EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.images import IMAGE_IMPORT_MAX_BYTES
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.sbom_helpers import Arguments, Context, Run, Value

AT = datetime(2026, 10, 14, 10, 0, tzinfo=UTC)


@pytest.mark.parametrize("flag", ["--owner", "--read-consent-reference", "--source-id",
                                  "--source-version", "--image-digest-kind"])
def test_FileModeRequiresEveryExplicitFieldBeforeSelectedRead(tmp_path, monkeypatch, flag):
    """Source identity, image semantics and read description have no workspace-derived defaults."""

    owned = Context(tmp_path)
    arguments = Arguments(owned)
    position = arguments.index(flag)
    del arguments[position:position + 2]

    def Forbidden(*_args, **_kwargs):
        """Trip any selected-file read after invalid explicit configuration."""

        raise AssertionError("Invalid source selection reached its raw reader")

    monkeypatch.setattr(commands, "ReadOwnedSbom", Forbidden)
    status, outcome = Run(arguments)
    assert status == 2 and outcome["acquisition_commit"] == "not-attempted", (
        "Missing explicit inputs must fail before original acquisition or model work"
    )


@pytest.mark.parametrize("flag,value", [("--expected-revision", 1),
    ("--expected-workspace-revision", 1), ("--scope", "missing")])
def test_CurrentBasesAndScopeRefuseBeforeFileOrGenericEvidenceReads(
    tmp_path, monkeypatch, flag, value
):
    """Stale revisions and unknown attribution cannot read selected or retained raw bytes."""

    owned = Context(tmp_path)
    arguments = Value(Arguments(owned), flag, value)
    calls = []

    def Forbidden(*_args, **_kwargs):
        """Record a forbidden raw-reading boundary for rejected metadata bases."""

        calls.append("read")

        raise AssertionError("Stale metadata basis reached raw bytes")

    monkeypatch.setattr(commands, "ReadOwnedSbom", Forbidden)
    monkeypatch.setattr(commands, "OpenReportInput", Forbidden)
    monkeypatch.setattr(LocalEvidenceStore, "Read", Forbidden)
    status, outcome = Run(arguments)
    assert status == 4 and not calls and outcome["model_commit"] == "not-attempted", (
        "Current basis/scope refusal must happen before every selected or generic raw reader"
    )


@pytest.mark.parametrize("kind", ["missing", "empty", "oversize", "hardlink", "symlink"])
def test_SelectedFileSizeAndPhysicalOwnershipRefuseBeforeOpening(tmp_path, monkeypatch, kind):
    """Original source metadata is bounded and non-following before any descriptor is opened."""

    source = tmp_path / "source.json"
    source.write_bytes(b"{}")

    if kind == "missing":
        source.unlink()

    elif kind == "empty":
        source.write_bytes(b"")

    elif kind == "oversize":
        with source.open("wb") as stream:
            stream.truncate(IMAGE_IMPORT_MAX_BYTES + 1)

    elif kind == "hardlink":
        os.link(source, tmp_path / "alias.json")

    else:
        target = tmp_path / "actual.json"
        source.rename(target)

        try:
            source.symlink_to(target)

        except OSError:
            pytest.skip("Controlled source symlink requires filesystem support")

    def Forbidden(*_args, **_kwargs):
        """Trip raw descriptor creation after selected metadata should already refuse."""

        raise AssertionError("Invalid source metadata reached descriptor open")

    monkeypatch.setattr(commands.os, "open", Forbidden)

    with pytest.raises((commands.SbomFailure, EvidenceError, OSError, ValueError)):
        commands.ReadOwnedSbom(source, ArtifactReadConsent("owner:test", "read:test"), lambda: AT)


def test_DescriptorIsClosedWhenStreamWrappingFails(tmp_path, monkeypatch):
    """Descriptor ownership transfers only after successful stream construction."""

    source = tmp_path / "source.json"
    source.write_bytes(b"{}")
    opened = []
    original_open = os.open

    def Open(*args, **kwargs):
        """Retain the actual private descriptor solely for independent closed-state inspection."""

        descriptor = original_open(*args, **kwargs)
        opened.append(descriptor)

        return descriptor

    def Fdopen(*_args, **_kwargs):
        """Fail before transferring descriptor ownership to a buffered stream."""

        raise OSError("Owned stream wrapper failure")

    monkeypatch.setattr(commands.os, "open", Open)
    monkeypatch.setattr(commands.os, "fdopen", Fdopen)

    with pytest.raises(OSError):
        commands.ReadOwnedSbom(source, ArtifactReadConsent("owner:test", "read:test"), lambda: AT)

    assert len(opened) == 1, "The controlled wrapper failure must follow one actual descriptor open"

    with pytest.raises(OSError):
        os.fstat(opened[0])


@pytest.mark.parametrize("kind", ["descriptor-ctime", "path-ctime", "link-count"])
def test_SameViewIdentityChangesCannotBorrowWindowsCrossViewTolerance(tmp_path, monkeypatch, kind):
    """Only cross-view ctime differences are tolerated; each same-view identity stays stable."""

    source = tmp_path / "source.json"
    source.write_bytes(b"{}")
    original_stat = commands.os.fstat
    original_check = commands.CheckStorageEntry
    count = {"descriptor": 0, "path": 0}

    def Alter(metadata, changes):
        """Retain all observed physical fields except the one independently controlled change."""

        values = {name: getattr(metadata, name) for name in (
            "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink", "st_mode")}
        values.update(changes)

        return SimpleNamespace(**values)

    def Fstat(descriptor):
        """Change only the final same-handle ctime or observed private link count."""

        metadata = original_stat(descriptor)
        count["descriptor"] += 1

        if count["descriptor"] == 2 and kind == "descriptor-ctime":
            return Alter(metadata, {"st_ctime_ns": metadata.st_ctime_ns + 1})

        if count["descriptor"] == 2 and kind == "link-count":
            return Alter(metadata, {"st_nlink": 2})

        return metadata

    def Check(path, *, directory):
        """Change only the second same-path observation after original bytes have been read."""

        metadata = original_check(path, directory=directory)

        if path == source:
            count["path"] += 1

            if count["path"] == 2 and kind == "path-ctime":
                return Alter(metadata, {"st_ctime_ns": metadata.st_ctime_ns + 1})

        return metadata

    monkeypatch.setattr(commands.os, "fstat", Fstat)
    monkeypatch.setattr(commands, "CheckStorageEntry", Check)

    with pytest.raises(commands.SbomFailure, match="source-changed"):
        commands.ReadOwnedSbom(source, ArtifactReadConsent("owner:test", "read:test"), lambda: AT)


def test_UnknownRetainedSdkAcquisitionRefusesBeforeAnySelectedRawRead(tmp_path, monkeypatch):
    """An original SDK manifest alone does not declare absent product image/run/read custody."""

    owned = Context(tmp_path)
    record = LocalEvidenceStore(owned.root / "evidence").Put(owned.source.read_bytes(), "sbom",
        "application/json", EvidenceProvenance("owned-sbom", "scope:owned", "inventory.external",
            "declared-version", None, AT.isoformat(), AT.isoformat()))
    arguments = Arguments(owned, evidence_id=record.evidence_id)
    calls = []

    def Forbidden(*_args, **_kwargs):
        """Trip generic report opening or owning raw verification for unknown initial custody."""

        calls.append("raw")

        raise AssertionError("Unknown original product custody reached raw bytes")

    monkeypatch.setattr(LocalEvidenceStore, "Read", Forbidden)
    monkeypatch.setattr(commands, "OpenReportInput", Forbidden)
    status, outcome = Run(arguments)
    assert status == 4 and outcome["failure"] == "source-context" and not calls, (
        "Unknown first-time SDK manifest must not invent product custody or read selected bytes"
    )


def test_HelpAndHumanOutputNeedNoImplicitSourceOrScope(tmp_path):
    """Static help and successful human summaries retain explicit selections and safe facts."""

    status, help_text = Run(["--help"], json_output=False)
    assert status == 0 and "--image-digest-kind" in help_text and "known original" in help_text, (
        "Read-only help describes explicit image semantics and conservative retained admission"
    )
    owned = Context(tmp_path)
    status, text = Run(Arguments(owned), json_output=False)
    assert status == 0 and "model_commit: confirmed" in text and str(owned.source) not in text, (
        "Human output reports actual acknowledgement without reflecting selected paths or raw bytes"
    )


def test_MissingWorkspaceObjectReferenceRefusesBeforeAnySelectedRawRead(tmp_path, monkeypatch):
    """A current revision cannot legitimize a dangling retained workspace object reference."""

    owned = Context(tmp_path)
    store = LocalWorkspaceStore(owned.root)
    store.Save(replace(store.Open(), object_references=("object:" + "a" * 64,)))
    arguments = Arguments(owned)
    calls = []

    def Forbidden(*_args, **_kwargs):
        """Trip a selected or generic raw reader for logically invalid current references."""

        calls.append("raw")

        raise AssertionError("Dangling workspace reference reached source bytes")

    monkeypatch.setattr(commands, "ReadOwnedSbom", Forbidden)
    monkeypatch.setattr(commands, "OpenReportInput", Forbidden)
    status, outcome = Run(arguments)
    assert status == 4 and outcome["failure"] == "integrity" and not calls, (
        "Actual current workspace references must validate before selected raw bytes are read"
    )


def test_StableWindowsPathHandleCtimeDifferencePreservesOriginalBytes(tmp_path, monkeypatch):
    """Windows cross-view ctime differences do not erase full stable same-view checks."""

    source = tmp_path / "source.json"
    original = b'{"owned":"original"}'
    source.write_bytes(original)
    original_stat = commands.os.fstat

    def Fstat(descriptor):
        """Return a stable handle view with only a different Windows API ctime value."""

        metadata = original_stat(descriptor)
        values = {name: getattr(metadata, name) for name in (
            "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink", "st_mode")}
        values["st_ctime_ns"] += 1

        return SimpleNamespace(**values)

    monkeypatch.setattr(artifact_inputs, "_WINDOWS_STAT_VIEWS", True)
    monkeypatch.setattr(commands.os, "fstat", Fstat)
    raw, started, finished = commands.ReadOwnedSbom(source,
        ArtifactReadConsent("owner:test", "read:test"), lambda: AT)
    assert raw == original and started == finished == AT.isoformat(), (
        "Stable Windows path/handle differences must retain complete original bytes and clock facts"
    )
