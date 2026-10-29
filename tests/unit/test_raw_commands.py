# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exact raw argument presentation and truthful wrapper failure diagnostics."""

from __future__ import annotations

from io import BytesIO, StringIO, TextIOWrapper
from types import SimpleNamespace

import pytest

from fuzzy1337 import raw_commands as commands
from fuzzy1337.portscan import PortScanUnavailableError
from tests.unit.test_raw_cli import TCP

PREFIX = ["run", "/owned/workspace", "--tool", "nmap", "--scope", "local",
    "--owner", "operator:owned", "--policy", "/owned/policy.json", "--executable", "/nmap"]


def test_ActualOriginalTailAndSeparateStreamsRemainExact(monkeypatch):
    """Native stdout/stderr remain byte-exact and native seven survives complete wrapper custody."""

    seen = []

    async def Run(*arguments, **keywords):
        """Capture exact native selection without launching a synthetic process."""

        seen.append((arguments[4].arguments, keywords["confirmation"]))

        return SimpleNamespace(result=SimpleNamespace(stdout=b"\xff\nxml", stderr=b"\x80error\n"),
            ExitCode=lambda: 7, ToDict=lambda: {"native_exit_code": 7})

    monkeypatch.setattr(commands, "RunRawCli", Run)
    output, error = StringIO(), StringIO()
    status = commands.RunRawCommands([*PREFIX, "--", *TCP], output, error=error)
    assert status == 7 and seen == [(TCP, None)], (
        "Exact native order and missing separate confirmation must reach the governed owner")
    assert output.getvalue().encode("utf-8", "surrogateescape") == b"\xff\nxml", (
        "Original stdout must not gain wrapper framing or replacement characters")
    assert error.getvalue().encode("utf-8", "surrogateescape") == b"\x80error\n", (
        "Original stderr must remain separate and reversible")
    output.seek(0)
    output.truncate()
    assert commands.RunRawCommands([*PREFIX, "--json", "--", *TCP], output, error=error) == 7, (
        "Explicit JSON presentation must retain the same actual native status")
    assert output.getvalue() == '{"native_exit_code": 7}\n', (
        "JSON presentation must not mix original native stream bytes into its document")


def test_BinaryTerminalWritesOriginalBytesWithoutTextTranscoding():
    """A real binary terminal buffer receives exact bytes regardless of its text encoding."""

    raw = BytesIO()
    text = TextIOWrapper(raw, encoding="ascii")
    commands.WriteNative(text, b"\xff\x00\r\n")
    assert raw.getvalue() == b"\xff\x00\r\n", "Binary terminal output was transcoded or framed"


@pytest.mark.parametrize("tail", [["--version"], ["--json"], ["--help"], ["--script", "secret"]])
def test_NativeTailNeverBecomesWrapperFlags(tail):
    """Outer command flags after the native separator are rejected without reflecting values."""

    output, error = StringIO(), StringIO()
    assert commands.RunRawCommands([*PREFIX, "--", *tail], output, error=error) == 2, (
        "Unsupported native tokens must fail before any health probe or process launch")
    assert "secret" not in output.getvalue() + error.getvalue(), (
        "Rejected argument values must remain absent from safe wrapper diagnostics")


@pytest.mark.parametrize("arguments", [PREFIX, [*PREFIX, "--"],
    [*PREFIX, "--confirm-plan", "0" * 64, "--", *TCP],
    ["replay", "/owned/workspace", "--receipt", "sha256:" + "0" * 64, "--", *TCP]])
def test_MissingSeparatorAndPartialConfirmationAreUsageErrors(arguments):
    """The wrapper requires explicit native separation and complete separate confirmation fields."""

    with pytest.raises(SystemExit) as failure:
        commands.RunRawCommands(arguments, StringIO(), error=StringIO())

    assert failure.value.code == 2, "Malformed wrapper arguments must not become execution success"


@pytest.mark.parametrize("failure,status", [(PermissionError, 3), (PortScanUnavailableError, 4),
    (OSError, 4), (ValueError, 2), (KeyboardInterrupt, 130)])
def test_SelectedOwnerFailuresRetainSafeStatus(monkeypatch, failure, status):
    """Authority, availability, storage and interruption remain separate truthful outcomes."""

    async def Run(*arguments, **keywords):
        """Refuse at the selected owner with untrusted detail that must not leak."""

        raise failure("secret-value")

    monkeypatch.setattr(commands, "RunRawCli", Run)
    output = StringIO()
    assert commands.RunRawCommands([*PREFIX, "--json", "--", *TCP], output) == status, (
        "The selected underlying failure must retain its intended wrapper status")
    assert "secret-value" not in output.getvalue(), "Underlying exception details leaked"


def test_OfflineReplayNeedsNoNativeSelectionOrPolicy(monkeypatch):
    """Receipt-only replay remains offline and classifies original-custody corruption as four."""

    monkeypatch.setattr(commands, "ReplayRawCli", lambda *args: {"state": "verified"})
    arguments = ["replay", "/owned/workspace", "--receipt", "sha256:" + "a" * 64]
    output = StringIO()
    assert commands.RunRawCommands(arguments, output) == 0, "Valid offline replay failed"
    assert output.getvalue() == '{"state": "verified"}\n', "Replay did not use its offline owner"

    def Corrupt(*arguments):
        """Represent independently detected original stream corruption."""

        raise ValueError("private-corruption-detail")

    monkeypatch.setattr(commands, "ReplayRawCli", Corrupt)
    assert commands.RunRawCommands([*arguments, "--json"], StringIO()) == 4, (
        "Original receipt corruption must not become a usage error or successful replay")
