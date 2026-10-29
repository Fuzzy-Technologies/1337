# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Causal process-identity cleanup controls without launching a daemon or signaling any process."""

import io
import signal
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.fixtures.local_image import owned_product_lane as lane


def test_ProcessParserRetainsSelectedPidStartTimeAndGroup(monkeypatch):
    """Inert Linux stat bytes include spaces and parentheses without shifting identity fields."""

    fields = ["S", "100", "123", *(["0"] * 16), "456", "0", "0"]
    raw = ("123 (owned ) fixture) " + " ".join(fields)).encode()
    original = Path.open

    def Open(path, *args, **kwargs):
        """Substitute only the explicitly selected inert proc-stat response."""

        if path == Path("/proc/123/stat"):
            return io.BytesIO(raw)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", Open)
    observed = lane.Process(123)
    assert observed == lane.ProcessFact(123, 100, 123, 456, "S"), (
        "Controlled stat bytes must preserve the selected PID, parent, group and start time."
    )


@pytest.mark.parametrize("change", ("original", "gone", "zombie", "reused"))
def test_CleanupSignalsOnlyTheOriginalLiveStartTime(monkeypatch, change):
    """A reused PID is a causal refusal, while exited/zombie original children receive no signal."""

    original = lane.ProcessFact(123, 100, 123, 456, "S")
    current = {original.pid: original}
    observed = {"original": original, "gone": None, "zombie": replace(original, state="Z"),
                "reused": replace(original, started=789)}[change]
    calls = []
    closed = []
    monkeypatch.setattr(lane, "Process", lambda pid: observed)
    monkeypatch.setattr(lane, "os", SimpleNamespace(
        pidfd_open=lambda pid, flags: 17, close=closed.append))
    monkeypatch.setattr(lane, "signal", SimpleNamespace(
        pidfd_send_signal=lambda descriptor, selected: calls.append((descriptor, selected))))
    if change == "reused":
        with pytest.raises(ValueError, match="identity changed"):
            lane.SignalOriginalChildren(current, signal.SIGTERM)
    else:
        lane.SignalOriginalChildren(current, signal.SIGTERM)
    assert calls == ([(17, signal.SIGTERM)] if change == "original" else []), (
        "Only the pinned descriptor for a freshly verified original identity may receive a signal."
    )
    assert closed == [17], "Every opened identity handle must close even after refusal."


@pytest.mark.parametrize("gone", (True, False))
def test_SignalRaceRequiresConfirmedDisappearance(monkeypatch, gone):
    """A signal race cannot upgrade a still-observed original child to confirmed cleanup."""

    original = lane.ProcessFact(123, 100, 123, 456, "S")
    monkeypatch.setattr(lane, "Process", lambda pid: None if gone else original)

    def Open(*args):
        """Simulate disappearance before any kernel identity handle could be obtained."""

        raise ProcessLookupError("Explicit inert disappearance race")

    monkeypatch.setattr(lane, "os", SimpleNamespace(pidfd_open=Open))
    if gone:
        lane.SignalOriginalChildren({123: original}, signal.SIGTERM)
    else:
        with pytest.raises(ValueError, match="disappearance is unconfirmed"):
            lane.SignalOriginalChildren({123: original}, signal.SIGTERM)


def test_PinnedSignalCannotReachAReusedNumericPidAfterObservation(monkeypatch):
    """Changing the numeric target after observation cannot retarget an already pinned pidfd."""

    original = lane.ProcessFact(123, 100, 123, 456, "S")
    state = {"started": 456}
    descriptors = {}
    delivered = []

    def Open(pid, flags):
        """Pin the explicitly inert original identity before its numeric spelling is reused."""

        descriptors[17] = state["started"]
        return 17

    def Observe(pid):
        """Return original facts, then model the reviewed check-to-delivery reuse window."""

        state["started"] = 789
        return original

    monkeypatch.setattr(lane, "Process", Observe)
    monkeypatch.setattr(lane, "os", SimpleNamespace(pidfd_open=Open, close=lambda fd: None,
        kill=lambda *args: pytest.fail("Reusable numeric PID signaling must never be reached")))
    monkeypatch.setattr(lane, "signal", SimpleNamespace(pidfd_send_signal=lambda fd, selected:
        delivered.append((descriptors[fd], selected))))
    lane.SignalOriginalChildren({123: original}, signal.SIGTERM)
    assert state["started"] == 789 and delivered == [(456, signal.SIGTERM)], (
        "Delivery must remain bound to the original handle across the reproduced reuse race."
    )


@pytest.mark.parametrize("ancestor", (False, True))
def test_ActorWritableParentOrAncestorRefusesBeforeTemporaryRootCreation(tmp_path, ancestor):
    """An actor-writable directory entry cannot become the parent of root cleanup authority."""

    parent = tmp_path / "parent"
    parent.mkdir()
    (tmp_path if ancestor else parent).chmod(0o777)
    with pytest.raises(ValueError, match="actor-writable or non-root"):
        lane.ProtectedParent(parent)
    assert not list(parent.iterdir()), "Parent admission must precede creating any daemon state."


def test_AdoptedReapingPreservesDirectPopenWaitOwnership(monkeypatch):
    """The manager must never reap a direct Popen child through an unscoped waitpid(-1)."""

    direct = lane.ProcessFact(123, 100, 123, 456, "Z")
    adopted = lane.ProcessFact(124, 100, 124, 457, "Z")
    nested = lane.ProcessFact(125, 124, 124, 458, "Z")
    facts = {item.pid: item for item in (direct, adopted, nested)}
    waited = []
    monkeypatch.setattr(lane, "Process", facts.get)
    monkeypatch.setattr(lane, "os", SimpleNamespace(getpid=lambda: 100, WNOHANG=1,
        waitpid=lambda pid, flags: (waited.append(pid) or pid, 7 << 8)))
    assert lane.ReapAdoptedChildren(facts, {123}) == [(124, 7 << 8)]
    assert waited == [124], "Only the original adopted zombie may yield its original wait status."



@pytest.mark.skipif(sys.platform != "linux", reason="Explicit Linux POSIX fixture material")
def test_ExplicitFixtureExecutableHashesOriginalBytesAndRejectsHardlinks(tmp_path):
    """The lifecycle fixture selects physical bytes without executing its inert test material."""

    import hashlib
    import os

    selected = tmp_path / "inert-tool"
    selected.write_bytes(b"Explicit inert fixture executable identity; never executed")
    selected.chmod(0o700)
    path, digest = lane.ExactExecutable(selected)
    assert path == selected and digest == hashlib.sha256(selected.read_bytes()).hexdigest(), (
        "The original selected fixture tool hash must describe actual bounded bytes."
    )
    link = tmp_path / "hardlink"
    os.link(selected, link)
    with pytest.raises(ValueError, match="bounded physical executable"):
        lane.ExactExecutable(selected)
