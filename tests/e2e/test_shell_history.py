# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Fresh owned PTY input loops verify native editor history without user history files."""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MARKER = "synthetic-private-terminal-argument"
CHILD = '''# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0
"""Run one isolated test-owned input loop, with only synthetic prior native history."""
import fcntl
import json
import os
import select
import sys
import termios
fcntl.ioctl(0, termios.TIOCSCTTY, 0)
sys.path.insert(0, sys.argv[1])
try:
    import readline
except ImportError:
    print("NATIVE-UNAVAILABLE", flush=True)
    raise SystemExit(0)
from fuzzy1337.shell import InteractiveShell

def DenyHistoryFile(*arguments, **options):
    """Reject all history file operations; this process owns in-memory synthetic data only."""
    raise AssertionError("Owned terminal test must not access a history file.")

for name in ("read_history_file", "write_history_file", "append_history_file"):
    if hasattr(readline, name):
        setattr(readline, name, DenyHistoryFile)

def Completer(text, state):
    """Retain a caller-owned completer without performing any external work."""
    return None

def NativeItems():
    """Inspect only this fresh process's bounded synthetic native history indices."""
    return [value for index in range(1, 201)
            if (value := readline.get_history_item(index)) is not None]

def NativeIndices():
    """Observe this owned process's finite absolute positions for the independent gap oracle."""
    return [[index, value] for index in range(1, 201)
            if (value := readline.get_history_item(index)) is not None]

readline.set_completer(Completer)
readline.set_completer_delims(" ")
readline.set_history_length(17)
enabled = sys.argv[2] != "disabled"
readline.set_auto_history(enabled)
if sys.argv[2] in {"capped", "capped-additions", "capped-budget", "capped-over-budget"}:
    readline.parse_and_bind("set history-size 1")
for value in ("owned-prior-one", "owned-prior-two", "owned-prior-three"):
    readline.add_history(value)
if sys.argv[2] in {"capped-additions", "capped-budget", "capped-over-budget"}:
    for index in range(4, 7):
        readline.add_history("owned-prior-" + str(index))
if sys.argv[2] in {"disabled", "queued"}:
    readline.add_history("report; export synthetic-private-terminal-argument")
before = NativeItems()
before_indices = NativeIndices()
shell = InteractiveShell()
during = []
seed_snapshot = []
after_seed = []
original_report = shell.do_report
def ObserveReport(argument):
    """Capture actual native history before the real protected consumer dispatches."""
    during.append(NativeIndices())
    original_report(argument)
shell.do_report = ObserveReport
if sys.argv[2] in {"capped-additions", "capped-budget", "capped-over-budget"}:
    amount = {"capped-additions": 2, "capped-budget": 100, "capped-over-budget": 101}[sys.argv[2]]
    original_post = shell.postcmd
    def Seed(argument):
        """Add only a fixed finite number of owned ordinary command-time entries."""
        for index in range(1, amount + 1):
            readline.add_history("owned-command-time-" + str(index))
        seed_snapshot.extend(NativeIndices())
    def ObserveAfter(stop, line):
        """Confirm native observation left unowned additions unchanged after the handler returns."""
        result = original_post(stop, line)
        if line == "seed":
            after_seed.extend(NativeIndices())
        return result
    shell.do_seed = Seed
    shell.postcmd = ObserveAfter
if sys.argv[2] == "capped-during":
    original_context = shell.do_context
    def CapDuringCommand(argument):
        """Change only this process's owned cap while the real loop is already running."""
        readline.parse_and_bind("set history-size 1")
        original_context(argument)
    shell.do_context = CapDuringCommand
original_completion = shell.postcmd
completed_commands = 0
def CompletedCommand(stop, line):
    """Acknowledge actual callback completion before the parent accepts a new input prompt."""
    global completed_commands
    result = original_completion(stop, line)
    completed_commands += 1
    print("NATIVE-COMMAND-DONE:" + str(completed_commands) + ":", flush=True)
    return result
shell.postcmd = CompletedCommand
if sys.argv[2] == "queued":
    shell.cmdqueue = ["report; export synthetic-private-terminal-argument", "quit"]
try:
    shell.cmdloop()
except KeyboardInterrupt:
    interrupted = True
    refused = False
except RuntimeError:
    interrupted = False
    refused = True
else:
    interrupted = False
    refused = False
after = NativeItems()
restored = (readline.get_completer() is Completer
            and readline.get_completer_delims() == " "
            and readline.get_history_length() == 17
            and shell._native_history is None)
if sys.argv[3] == "interrupt":
    print("NATIVE-LOOP-EXIT", flush=True)
    release_fd = int(sys.argv[4])
    ready, _, _ = select.select([release_fd], [], [], 10)
    if not ready or os.read(release_fd, 1) != b"1":
        raise AssertionError("Owned terminal interruption release was not acknowledged.")
    os.close(release_fd)
    termios.tcflush(0, termios.TCIFLUSH)
if sys.argv[2] != "queued":
    assert input("probe> ") == "owned-after-loop", (
        "The owned native probe must receive exact input."
    )
print("NATIVE-RESULT:" + json.dumps({"before": before, "after": after,
    "final": NativeItems(), "restored": restored, "interrupted": interrupted,
    "refused": refused, "before_indices": before_indices,
    "during": during, "seed_snapshot": seed_snapshot, "after_seed": after_seed,
    "local": list(shell._history), "lastcmd": shell.lastcmd}), flush=True)
print("NATIVE-END", flush=True)
'''


def ReadUntil(master: int, expected: bytes, process: subprocess.Popen,
              transcript: bytearray, *, after: bytes = b"") -> None:
    """Read only one owned PTY until its expected lifecycle marker, with a finite deadline."""

    deadline = time.monotonic() + 10

    while (
        (position := transcript.find(after)) < 0
        or expected not in transcript[position + len(after):]
    ):
        if time.monotonic() >= deadline:
            raise AssertionError("Owned terminal did not reach its expected lifecycle marker.")

        ready, _, _ = select.select([master], [], [], 0.1)

        if ready:
            try:
                data = os.read(master, 4096)

            except OSError:
                data = b""

            if not data:
                break

            transcript.extend(data)

        elif process.poll() is not None:
            break

    position = transcript.find(after)
    assert (
        position >= 0 and expected in transcript[position + len(after):]
    ) or b"NATIVE-UNAVAILABLE" in transcript, (
        "Only a missing optional editor may skip a native terminal oracle."
    )


def RunTerminal(tmp_path: Path, lines: tuple[bytes, ...], *, mode: str = "enabled",
                ending: str = "quit", executable: str = sys.executable):
    """Own a fresh POSIX PTY/process and feed only synthetic commands without network or scans."""

    import pty
    import termios

    configuration = tmp_path / "owned-inputrc"
    configuration.write_text("")
    master, slave = pty.openpty()
    attributes = termios.tcgetattr(slave)
    assert attributes[3] & termios.ISIG and attributes[6][termios.VINTR] == b"\x03", (
        "The owned terminal must deliver the actual configured interrupt character."
    )
    attributes[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, attributes)
    transcript = bytearray()
    environment = {"PATH": os.defpath, "TERM": "xterm", "INPUTRC": str(configuration),
                   "EDITRC": str(configuration)}
    release_read, release_write = os.pipe() if ending == "interrupt" else (-1, -1)

    try:
        process = subprocess.Popen(
            [executable, "-I", "-c", CHILD, str(ROOT / "src"), mode, ending, str(release_read)],
            cwd=ROOT, env=environment, stdin=slave, stdout=slave, stderr=slave,
            start_new_session=True, pass_fds=(release_read,) if release_read >= 0 else (),
        )

    except BaseException:
        os.close(master)
        os.close(slave)

        if release_write >= 0:
            os.close(release_write)

        raise

    finally:
        if release_read >= 0:
            os.close(release_read)

    os.close(slave)

    try:
        if mode == "queued":
            ReadUntil(master, b"NATIVE-END", process, transcript)

        else:
            ReadUntil(master, b"1337> ", process, transcript)

            if b"NATIVE-UNAVAILABLE" in transcript:
                pytest.skip("This interpreter has no optional native line editor.")

            for command_index, line in enumerate(lines, 1):
                transcript.clear()
                os.write(master, line + b"\n")
                completed = b"NATIVE-COMMAND-DONE:" + str(command_index).encode() + b":"
                ReadUntil(master, b"probe> " if mode == "capped-over-budget" else b"1337> ",
                          process, transcript,
                          after=b"" if mode == "capped-over-budget" else completed)

            if mode != "capped-over-budget":
                transcript.clear()

                if ending == "interrupt":
                    assert os.tcgetpgrp(master) == process.pid, (
                        "The real interrupt must target only the owned foreground process group."
                    )

                os.write(master, b"quit\n" if ending == "quit" else (
                    b"\x04" if ending == "eof" else b"EOF\n" if ending == "eof-command"
                    else b"report; export " + MARKER.encode() + b"\x03\n"
                ))
                if ending == "interrupt":
                    ReadUntil(master, b"NATIVE-LOOP-EXIT", process, transcript)
                    os.write(release_write, b"1")

                ReadUntil(master, b"probe> ", process, transcript)
            os.write(master, b"owned-after-loop\n")
            ReadUntil(master, b"NATIVE-END", process, transcript)

        if b"NATIVE-UNAVAILABLE" in transcript:
            pytest.skip("This interpreter has no optional native line editor.")

        process.wait(timeout=10)
        assert process.returncode == 0, "The owned terminal oracle must exit cleanly."
        record = bytes(transcript).split(b"NATIVE-RESULT:", 1)[1].splitlines()[0]

        return json.loads(record)

    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)

        os.close(master)

        if release_write >= 0:
            os.close(release_write)


@pytest.mark.skipif(os.name != "posix", reason="Native terminal regression requires a POSIX PTY.")
def test_ActualNativeTerminalProtectsAllParsedProductFormsAndArrowReplay(tmp_path):
    """Real input(), native arrow recall and empty repeat cannot retain or replay private argv."""

    commands = (
        b"select asset:owned-terminal", b"report; export " + MARKER.encode(), b"\x1b[A", b"",
        b"report--format=" + MARKER.encode(), b"report/export " + MARKER.encode(),
        b"workspace; " + MARKER.encode(), b"scope/ " + MARKER.encode(),
        b"scan--target=" + MARKER.encode(),
    )
    result = RunTerminal(tmp_path, commands)
    assert MARKER not in json.dumps(result), "Native/local/replay history must not retain argv."
    assert result["before"] == result["after"][:3], "Preserve all unrelated prior caller history."
    assert "select asset:owned-terminal" in result["after"], "Ordinary history remains available."
    assert "report" in result["after"], "Native arrow recall must use the sanitized namespace."
    assert result["restored"], "Completer, delimiters, file limit and loop ownership must restore."
    assert result["final"][-1] == "owned-after-loop", "Automatic history remains enabled afterward."


@pytest.mark.skipif(os.name != "posix", reason="Native terminal regression requires a POSIX PTY.")
@pytest.mark.parametrize("mode", ["disabled", "queued"])
def test_NativeLifecycleDoesNotClaimDisabledOrQueuedCallerHistory(tmp_path, mode):
    """No auto append or actual input means no preexisting native entry belongs to this loop."""

    result = RunTerminal(tmp_path, (b"report; export " + MARKER.encode(),), mode=mode)
    assert result["after"] == result["before"], "Disabled/queued loops cannot edit prior history."
    assert result["final"] == result["before"], "Preserve caller auto-history configuration."
    assert result["restored"] and MARKER not in json.dumps([result["local"], result["lastcmd"]]), (
        "Protect local replay while preserving an identical preexisting native caller entry."
    )


@pytest.mark.skipif(os.name != "posix", reason="Native terminal regression requires a POSIX PTY.")
@pytest.mark.parametrize("ending", ["eof-command", "interrupt"])
def test_ActualNativeEofAndInterruptRestoreCallerState(tmp_path, ending):
    """Terminal EOF/Ctrl+C restore scoped ownership and preserve previously sanitized entries."""

    result = RunTerminal(tmp_path, (b"report; export " + MARKER.encode(),), ending=ending)
    assert MARKER not in json.dumps(result), "Exit/partial interrupted input must not retain argv."
    assert result["restored"] and result["before"] == result["after"][:3], (
        "Every terminal exit path must restore completer/settings and preserve caller history."
    )
    assert result["interrupted"] is (ending == "interrupt"), "Preserve actual interruption truth."


def InstalledGnu(tmp_path: Path) -> str:
    """Select only an existing optional GNU backend without caller configuration or provisioning."""

    executable = Path("/usr/bin/python3")

    if not executable.is_file():
        pytest.skip("No separate installed system Python is available for the GNU backend oracle.")

    configuration = tmp_path / "owned-probe-inputrc"
    configuration.write_text("")
    environment = {"PATH": os.defpath, "INPUTRC": str(configuration), "EDITRC": str(configuration)}
    observed = subprocess.run([str(executable), "-I", "-c",
        "import readline; print(getattr(readline, '_READLINE_LIBRARY_VERSION', ''))"],
        capture_output=True, text=True, timeout=10, check=False, env=environment)

    if observed.returncode or not observed.stdout.strip() or "EditLine" in observed.stdout:
        pytest.skip("The installed system interpreter has no optional GNU readline backend.")

    return str(executable)


@pytest.mark.skipif(os.name != "posix", reason="Native terminal regression requires a POSIX PTY.")
@pytest.mark.parametrize("mode", ["capped", "capped-during"])
def test_ActualInstalledGnuCappedHistoryUsesAbsoluteInputIndices(tmp_path, mode):
    """A capped GNU buffer changes absolute history base while its relative size stays constant."""

    result = RunTerminal(tmp_path, (b"context", b"report; export " + MARKER.encode(),
                                  b"report--format=" + MARKER.encode()), mode=mode,
                         executable=InstalledGnu(tmp_path))
    assert MARKER not in json.dumps(result), "Capped native history cannot retain protected argv."
    assert len(result["after"]) == 1 and result["restored"], (
        "Preserve the caller's cap/completer/settings while identifying absolute native indices."
    )


@pytest.mark.skipif(os.name != "posix", reason="Native terminal regression requires a POSIX PTY.")
def test_ActualInstalledGnuTerminalEofRestoresCallerState(tmp_path):
    """An actual native GNU Ctrl+D EOF restores the same owned loop and caller state."""

    result = RunTerminal(tmp_path, (b"report; export " + MARKER.encode(),), ending="eof",
                         executable=InstalledGnu(tmp_path))
    assert result["restored"] and MARKER not in json.dumps(result), (
        "Actual native EOF must restore caller completer/settings and protect recorded input."
    )


@pytest.mark.skipif(os.name != "posix", reason="Native terminal regression requires a POSIX PTY.")
@pytest.mark.parametrize("mode, additions", [("capped-additions", 2), ("capped-budget", 100)])
def test_ActualGnuRetirementGapProtectsInputBeforeConsumerDispatch(tmp_path, mode, additions):
    """Real GNU tip6/input7/additions/input protects the later raw input before do_report runs."""

    result = RunTerminal(tmp_path, (b"seed", b"report; export " + MARKER.encode()), mode=mode,
                         executable=InstalledGnu(tmp_path))
    assert result["before_indices"] == [[6, "owned-prior-6"]], "Start at exact capped native tip6."
    assert result["seed_snapshot"] == [[7 + additions, "owned-command-time-" + str(additions)]], (
        "The actual handler's final unowned addition must remain unchanged before the next input."
    )
    assert result["after_seed"] == result["seed_snapshot"], (
        "Cursor recovery must preserve unowned caller additions after the real handler returns."
    )
    assert result["during"] == [[[8 + additions, "report"]]], (
        "Retired native indices cannot leave raw argv present while the real consumer executes."
    )
    assert not result["refused"] and result["restored"] and MARKER not in json.dumps(result), (
        "Within-budget native gaps preserve caller state and all actual protected input privacy."
    )


@pytest.mark.skipif(os.name != "posix", reason="Native terminal regression requires a POSIX PTY.")
def test_ActualGnuExcessRetirementRefusesBeforeFurtherInput(tmp_path):
    """A real 101-addition cap gap refuses further input while preserving caller history."""

    result = RunTerminal(tmp_path, (b"seed",), mode="capped-over-budget",
                         executable=InstalledGnu(tmp_path))
    assert result["refused"] and result["restored"], (
        "Excess gaps must refuse and release loop state."
    )
    assert result["seed_snapshot"] == [[108, "owned-command-time-101"]], (
        "Boundary refusal cannot change or discard the latest unowned caller addition."
    )
    assert result["after"] == ["owned-command-time-101"], (
        "The complete failure cleanup must preserve the caller's remaining history byte-for-byte."
    )
    assert result["during"] == [] and result["local"] == ["seed"], (
        "An unidentified native boundary must never dispatch or accept a later protected command."
    )
