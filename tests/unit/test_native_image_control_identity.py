# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned journal byte/view regressions; portable protocol doubles do not enroll Windows engines."""

from __future__ import annotations

import os
import stat
from types import SimpleNamespace

import pytest

from fuzzy1337 import artifact_inputs
from fuzzy1337 import native_image_bounded_capture as bounded


def JournalIdentityView(info, **changes):
    """Retain an actual owned metadata observation except for explicit unit-view changes."""

    fields = {name: getattr(info, name) for name in (
        "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink",
    )}
    fields.update(changes)

    return SimpleNamespace(**fields)


@pytest.fixture
def journal(tmp_path, monkeypatch):
    """Create a real tiny journal before isolated matching seams; Windows modes are unit views."""

    if os.name == "nt":
        selectedOs = SimpleNamespace(**vars(os))
        selectedOs.fchmod = lambda descriptor, mode: None
        monkeypatch.setattr(bounded, "os", selectedOs)
        monkeypatch.setattr(bounded, "stat", SimpleNamespace(S_IMODE=lambda mode:
            0o700 if stat.S_ISDIR(mode) else 0o600))
        monkeypatch.setattr(bounded.OutcomeJournal, "SyncDirectory", lambda owner: None)

    owned = bounded.OutcomeJournal(tmp_path)

    try:
        yield owned

    finally:
        owned.Close()


def JournalMatcher(monkeypatch, windows):
    """Scope canonical cross-view compatibility to this journal's matching operation only."""

    original = bounded.MatchesArtifactReadIdentity

    def Match(path_info, handle_info):
        """Keep preparatory filesystem observations outside the simulated platform seam."""

        with monkeypatch.context() as selected:
            selected.setattr(artifact_inputs, "_WINDOWS_STAT_VIEWS", windows)

            return original(path_info, handle_info)

    monkeypatch.setattr(bounded, "MatchesArtifactReadIdentity", Match)


@pytest.mark.parametrize("windows", [False, True], ids=["strict-posix", "windows-views"])
def test_JournalAcceptsSeparateStableCtimeViewsOnlyUnderTheCanonicalWindowsRule(
    journal, monkeypatch, windows,
):
    """A stable cross-API ctime difference never changes the original journal or Linux guard."""

    original = bounded.ArtifactHandleInfo
    handleCtime = journal.path.stat().st_ctime_ns + 1

    def Handle(descriptor):
        """Expose a distinct stable handle ctime while retaining real owned common fields."""

        return JournalIdentityView(original(descriptor), st_ctime_ns=handleCtime)

    monkeypatch.setattr(bounded, "ArtifactHandleInfo", Handle)
    JournalMatcher(monkeypatch, windows)

    if not windows:
        with pytest.raises(ValueError, match="identity differs"):
            journal.Verify()

        return

    journal.Verify()
    pathView, handleView = journal.Check()
    assert pathView.st_ctime_ns != handleView.st_ctime_ns and (
        journal.path.read_bytes() == b"1337-native-outcome-v1\n"
    ), "Canonical compatibility must retain separate complete views and exact journal bytes"


@pytest.mark.parametrize("phase", ["association", "readback"])
@pytest.mark.parametrize("view", ["path", "handle"])
@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"])
def test_JournalRejectsEverySameApiMutationAtAssociationAndDuringReadback(
    journal, monkeypatch, phase, view, field,
):
    """Every full same-API field remains strict even when cross-API Windows ctime differs."""

    originalPath = bounded.ArtifactPathInfo
    originalHandle = bounded.ArtifactHandleInfo
    originalRead = bounded.os.read
    handleCtime = journal.path.stat().st_ctime_ns + 1
    calls = {"path": 0, "handle": 0}
    reading = False

    def Change(info, selected):
        """Mutate one observed field only at the declared association or readback boundary."""

        calls[selected] += 1

        if selected == view and (
            phase == "association" and calls[selected] == 2 or phase == "readback" and reading
        ):
            return JournalIdentityView(info, **{field: getattr(info, field) + 1})

        return info

    def PathInfo(path, **options):
        """Leave original private directory observations untouched."""

        info = originalPath(path, **options)

        return Change(info, "path") if path == journal.path else info

    def Handle(descriptor):
        """Expose a full stable handle view before the declared unit mutation boundary."""

        info = JournalIdentityView(originalHandle(descriptor), st_ctime_ns=handleCtime)

        return Change(info, "handle")

    def Read(descriptor, size):
        """Mark actual owned journal I/O so readback mutations cannot poison preparatory reads."""

        nonlocal reading
        raw = originalRead(descriptor, size)

        if descriptor == journal.descriptor:
            reading = True

        return raw

    selectedOs = SimpleNamespace(**vars(bounded.os))
    selectedOs.read = Read
    monkeypatch.setattr(bounded, "os", selectedOs)
    monkeypatch.setattr(bounded, "ArtifactPathInfo", PathInfo)
    monkeypatch.setattr(bounded, "ArtifactHandleInfo", Handle)
    JournalMatcher(monkeypatch, True)

    with pytest.raises(ValueError, match="journal (identity differs|changed during readback)"):
        journal.Verify()

    assert calls[view] >= 2 and journal.path.read_bytes() == b"1337-native-outcome-v1\n", (
        "Same-API mutation must refuse custody while preserving all original recovery bytes"
    )


def test_JournalPreservesExactRawLfAndControlZFrameBytes(journal):
    """Binary framing retains literal LF and SHA bytes containing control-Z on every host."""

    value = {"index": 0, "owned": "line\n\x1a"}
    payload = b'{"index":0,"owned":"line\\n\\u001a"}'
    digest = bytes.fromhex("c9f1f9fa497153916334f2bf1adc2c94d16154a5afaad6a7ceb1c52bb8ccca97")
    expected = b"1337-native-outcome-v1\n" + len(payload).to_bytes(8, "big") + digest + payload
    journal.Append(value, complete=True)
    journal.Verify()
    assert b"\n" in expected and b"\x1a" in expected and journal.path.read_bytes() == expected, (
        "Original journal LF/control-Z bytes must survive exact binary write and full readback"
    )
    assert journal.size == len(expected) and journal.outcome_retained, (
        "Complete original custody requires exact physical byte length and verified framing"
    )


def test_JournalCreationExplicitlyRequestsThePlatformBinaryFlag(journal, monkeypatch):
    """Require binary mode at descriptor creation even on a host without a native O_BINARY flag."""

    originalOpen = bounded.os.open
    binaryFlag = getattr(os, "O_BINARY", 1 << 28)
    flagsSeen = []

    def Open(path, flags, *args, **options):
        """Observe the second journal's exact descriptor creation and retain real local I/O."""

        if getattr(path, "name", None) == "outcome.journal":
            flagsSeen.append(flags)

        actual = flags if hasattr(os, "O_BINARY") else flags & ~binaryFlag

        return originalOpen(path, actual, *args, **options)

    selectedOs = SimpleNamespace(**vars(bounded.os))
    selectedOs.O_BINARY = binaryFlag
    selectedOs.open = Open
    monkeypatch.setattr(bounded, "os", selectedOs)
    second = bounded.OutcomeJournal(journal.directory.parent)

    try:
        assert len(flagsSeen) == 1 and flagsSeen[0] & binaryFlag, (
            "The exact original journal descriptor must explicitly disable text translation"
        )
        second.Verify()

    finally:
        second.Close()
