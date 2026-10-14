# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""IOC selected-file identity, typed consumer and safe diagnostic failure boundaries."""

from __future__ import annotations

import hashlib
import os
from io import StringIO
from types import SimpleNamespace

import pytest

from fuzzy1337 import artifact_inputs
from fuzzy1337 import ioc_commands as commands
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.ioc_artifacts import AcquireIocArtifact, IocRequest, IocSource
from tests.ioc_cli_helpers import RAW, ImportArguments, Owned, Run


def Info(info, **changes):
    """Copy the exact physical identity fields for deterministic native stat-view mutations."""

    values = {name: getattr(info, name) for name in (
        "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink", "st_mode")}
    values.update(changes)

    return SimpleNamespace(**values)


def Consent():
    """Declare only selected-file read references without granting any target operation."""

    return ArtifactReadConsent("owner:fixture", "read:fixture")


def test_FileGuardAcceptsWindowsCrossViewCtimeWhileCheckingEachView(tmp_path, monkeypatch):
    """Windows path and handle ctime may differ, while stable same-view identities remain exact."""

    _, source = Owned(tmp_path)
    original = commands.ArtifactHandleInfo

    def Handle(descriptor):
        """Simulate the stable Windows handle-specific ctime without weakening other fields."""

        info = original(descriptor)

        return Info(info, st_ctime_ns=info.st_ctime_ns + 200)

    monkeypatch.setattr(artifact_inputs, "_WINDOWS_STAT_VIEWS", True)
    monkeypatch.setattr(commands, "ArtifactHandleInfo", Handle)
    assert commands.ReadOwnedIoc(source, Consent(), len(RAW)) == RAW, (
        "Stable Windows path/handle ctime differences rejected original guarded bytes"
    )


@pytest.mark.parametrize("view", ["path", "handle"])
@pytest.mark.parametrize("field_name", ["st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"])
def test_FullSameViewIdentityChangesAreRefused(tmp_path, monkeypatch, view, field_name):
    """Restored mtime or allowed Windows cross-view ctime cannot hide same-view changes."""

    _, source = Owned(tmp_path)
    name = "ArtifactPathInfo" if view == "path" else "ArtifactHandleInfo"
    original = getattr(commands, name)
    calls = 0

    def Observe(*args, **kwargs):
        """Alter exactly the second observation in one owned native metadata view."""

        nonlocal calls
        info = original(*args, **kwargs)
        calls += 1

        return Info(info, **{field_name: getattr(info, field_name) + 1}) if calls == 2 else info

    monkeypatch.setattr(artifact_inputs, "_WINDOWS_STAT_VIEWS", True)
    monkeypatch.setattr(commands, name, Observe)

    with pytest.raises(commands.IocFailure, match="selected-file"):
        commands.ReadOwnedIoc(source, Consent(), len(RAW))


def test_HardlinkedSelectedFileIsRefusedBeforeOpen(tmp_path, monkeypatch):
    """An observed additional link never enters the file read or acquisition boundary."""

    _, source = Owned(tmp_path)
    os.link(source, tmp_path / "second link.tsv")

    def Open(*args, **kwargs):
        """Expose a premature open of the observed multiply linked source."""

        raise AssertionError("IOC hardlinked source was opened")

    monkeypatch.setattr(commands.os, "open", Open)

    with pytest.raises(ValueError, match="singly linked"):
        commands.ReadOwnedIoc(source, Consent(), len(RAW))


def test_SelectedFileReplacementBetweenPathObservationAndOpenIsRefused(tmp_path, monkeypatch):
    """Opening another same-length file cannot borrow the original selected path identity."""

    _, source = Owned(tmp_path)
    other = tmp_path / "other.tsv"
    other.write_bytes(RAW)
    original = commands.os.open

    def Open(path, flags):
        """Return a real different file descriptor with identical bytes and length."""

        return original(other, flags)

    monkeypatch.setattr(commands.os, "open", Open)

    with pytest.raises(commands.IocFailure, match="selected-file"):
        commands.ReadOwnedIoc(source, Consent(), len(RAW))


@pytest.mark.parametrize("consent", [None, object(), SimpleNamespace(
    actor_ref="owner:fixture", record_ref="read:fixture")], ids=("missing", "foreign", "duck"))
def test_ExactReadConsentIsRequiredBeforeMetadataOrBytes(tmp_path, monkeypatch, consent):
    """Foreign read declarations cannot trigger caller-controlled properties or file reads."""

    def Observe(*args, **kwargs):
        """Expose filesystem access before exact selected-file consent validation."""

        raise AssertionError("IOC source observed before read consent validation")

    monkeypatch.setattr(commands, "ArtifactPathInfo", Observe)

    with pytest.raises(commands.IocFailure, match="configuration"):
        commands.ReadOwnedIoc(tmp_path / "source", consent, 1024)


@pytest.mark.parametrize("path", ["relative.tsv", "/owned/../source.tsv", "/owned/\nsource.tsv"])
def test_NoncanonicalOrControlBearingPathsFailBeforeAccess(path):
    """Physical selections never resolve traversal, hidden controls or implicit working paths."""

    with pytest.raises(commands.IocFailure, match="configuration"):
        commands.SelectedPath(commands.Path(path))


@pytest.mark.parametrize("target", ["result", "raw", "receipt", "snapshot", "snapshot_record"])
def test_ForeignAcquisitionTypesAreRefusedBeforeCallingTheirMethods(tmp_path, monkeypatch, target):
    """Exact outer and nested source/acquisition/record types guard terminal presentation."""

    root, source = Owned(tmp_path)
    original = commands.AcquireIocArtifact

    def Acquire(*args, **kwargs):
        """Obtain real accepted records, then substitute one foreign boundary result."""

        acquired = original(*args, **kwargs)

        if target == "result":
            return object()

        object.__setattr__(acquired, target, object())

        return acquired

    monkeypatch.setattr(commands, "AcquireIocArtifact", Acquire)
    status, result = Run(ImportArguments(root, source))
    assert status == 4 and result["evidence_commit"] == "unknown" and result[
        "snapshot_id"
    ] is None, (
        "Foreign original acquisition types entered presentation or confirmed usable evidence"
    )


@pytest.mark.parametrize("target", ["source", "limits", "candidates"])
def test_FrozenNestedSnapshotSubstitutionsCannotReachSummary(tmp_path, monkeypatch, target):
    """Exact snapshot serialization reconstructs nested facts before counts or hashes are used."""

    root, source = Owned(tmp_path)
    original = commands.AcquireIocArtifact

    def Acquire(*args, **kwargs):
        """Substitute one foreign nested fact after real original immutable acquisition."""

        acquired = original(*args, **kwargs)
        object.__setattr__(acquired.snapshot, target, object())

        return acquired

    monkeypatch.setattr(commands, "AcquireIocArtifact", Acquire)
    status, result = Run(ImportArguments(root, source))
    assert status == 4 and result["candidate_count"] is None, (
        "A frozen nested snapshot substitution reached a success count or summary"
    )


@pytest.mark.parametrize("pin", [None, "b" * 64], ids=("valid-original", "wrong-digest"))
def test_RefusalReceiptContradictingActualParserIsRejected(tmp_path, pin):
    """A manufactured refused original record chain cannot override independent valid bytes."""

    root, _ = Owned(tmp_path)
    source = IocSource("owned", "1", "owned:source", "Apache-2.0", "owned:LICENSE",
                       hashlib.sha256(RAW).hexdigest() if pin is None else pin)
    request = IocRequest(RAW, source)
    acquired = AcquireIocArtifact(root, request, scope_reference="scope:owned")
    store = commands.IocEvidenceStore(root / "evidence")
    document = commands.json.loads(store.Read(acquired.receipt.reference))
    document["state"] = "parse-rejected"
    forged_receipt = store.Put(commands.json.dumps(document, sort_keys=True,
        separators=(",", ":")).encode(), "ioc-acquisition", "application/json",
        acquired.receipt.provenance)
    forged = commands.IocAcquisition("parse-rejected", acquired.raw, forged_receipt, None, None)

    with pytest.raises(ValueError, match="contradict"):
        commands.VerifiedAcquisition(root, forged, request, "scope:owned")


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt], ids=("failed", "interrupted"))
def test_FailedReadWrapperConstructionClosesTheOwnedDescriptor(tmp_path, monkeypatch, error):
    """File-wrapper failures and interruption leave no leaked owned read descriptor."""

    _, source = Owned(tmp_path)
    descriptor = None

    def Wrap(opened, *args, **kwargs):
        """Retain only the test-owned descriptor and simulate wrapper construction failure."""

        nonlocal descriptor
        descriptor = opened

        raise error("secret-marker")

    monkeypatch.setattr(commands.os, "fdopen", Wrap)

    with pytest.raises(error):
        commands.ReadOwnedIoc(source, Consent(), len(RAW))

    assert descriptor is not None, "Read guard did not own an actual source descriptor"

    with pytest.raises(OSError):
        os.fstat(descriptor)


@pytest.mark.parametrize("action", [None, "import", "inspect"])
def test_HelpReturnsWithoutOpeningAnySourceOrWorkspace(monkeypatch, action):
    """Root or known-action help remains deterministic and free of source discovery."""

    def Open(*args, **kwargs):
        """Expose any physical source or workspace access from help presentation."""

        raise AssertionError("IOC help accessed storage")

    monkeypatch.setattr(commands, "ArtifactPathInfo", Open)
    output = StringIO()
    arguments = [] if action is None else ["ioc", action]
    status = commands.RunIocCommands([*arguments, "--help"], output)
    assert status == 0 and "usage:" in output.getvalue(), "IOC help failed without inputs"


def test_HumanSuccessDescribesCandidatesWithoutRawTokens(tmp_path):
    """Human summary exposes only supplied candidate count and assessed-boundary limits."""

    root, source = Owned(tmp_path)
    output = StringIO()
    status = commands.RunIocCommands(ImportArguments(root, source), output)
    assert status == 0 and "5 supplied candidates" in output.getvalue() and "192.0.2.7" not in (
        output.getvalue()
    ), "Human IOC output failed or exposed original source tokens"
