# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed isolated raw CLI with an explicitly synthetic no-network executable."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from io import StringIO
from pathlib import Path

import pytest

from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.shell import InteractiveShell
from tests.e2e.test_portscan_cli import Setup
from tests.e2e.test_shell_history import MARKER, RunTerminal

NATIVE = ["--unprivileged", "-n", "-Pn", "-sT", "-p", "80,443", "--host-timeout", "10s",
    "-oX", "-", "127.0.0.1"]


def Console(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    """Invoke the installed product module in an isolated subprocess without checkout imports."""

    return subprocess.run([sys.executable, "-I", "-m", "fuzzy1337", "raw", *arguments],
        capture_output=True, timeout=20, check=False)


@pytest.mark.skipif(os.name == "nt", reason="owned synthetic executable uses a POSIX shebang")
def test_InstalledRawCliPreservesSyntheticSuccessFailureDenialAndRelocatedCustody(tmp_path):
    """Actual process ownership, native exit seven and offline raw replay retain their authority."""

    root = tmp_path / "raw workspace"
    setup = Setup(root)
    prefix = [str(root), "--tool", "nmap", "--scope", "local", "--owner", "operator:owned",
        "--policy", setup[setup.index("--policy") + 1], "--executable", setup[-1]]
    plan = Console(["plan", *prefix, "--", *NATIVE])
    assert plan.returncode == 0, "Installed synthetic native planning failed"
    document = json.loads(plan.stdout)
    assert document["invocation"]["argv"] == [setup[-1], *NATIVE], (
        "Installed planning must preserve the actual exact native argument order")
    denied = Console(["run", *prefix, "--json", "--", *NATIVE])
    assert denied.returncode == 3 and not LocalModelStore(root).Open().objects, (
        "Unconfirmed installed raw work must not execute or create model facts")
    approval = ["--confirm-plan", document["intent_sha256"], "--confirmation-reference",
        "approval:raw-synthetic"]
    success = Console(["run", *prefix, *approval, "--", *NATIVE])
    assert success.returncode == 0 and success.stdout.startswith(b'<?xml version="1.0"'), (
        "Actual original synthetic XML must pass through installed stdout without framing")
    assert success.stderr == b"Owned synthetic Nmap XML producer; no network activity\n", (
        "Original synthetic stderr must remain byte-exact and separate")
    assert len(LocalModelStore(root).Open().Objects(ObjectKind.PORT)) == 2, (
        "Successful original XML must enter the existing canonical object model")
    failed_native = ["127.0.0.1", *NATIVE[:-1]]
    failed_plan = json.loads(Console(["plan", *prefix, "--", *failed_native]).stdout)
    failure = Console(["run", *prefix, "--json", "--confirm-plan", failed_plan["intent_sha256"],
        "--confirmation-reference", "approval:raw-synthetic-failure", "--", *failed_native])
    outcome = json.loads(failure.stdout)
    assert failure.returncode == 7 and outcome["native_exit_code"] == 7, (
        "Actual synthetic process rejection must retain native seven after complete custody")
    assert outcome["model_commit"] == "not-attempted", (
        "Failed actual native work must never create positive model facts")
    records = LocalEvidenceStore(root / "evidence")
    receipt = records.Get(outcome["receipt_id"])
    assert hashlib.sha256(records.Read(receipt.reference)).hexdigest() == (
        receipt.reference.sha256), (
        "Original failed receipt bytes must match the retained original acquisition")
    relocated = tmp_path / "relocated raw workspace"
    shutil.copytree(root, relocated)
    Path(setup[-1]).unlink()
    before = {str(path.relative_to(relocated)): path.read_bytes()
        for path in relocated.rglob("*") if path.is_file()}
    replay = Console(["replay", str(relocated), "--receipt", outcome["receipt_id"]])
    assert replay.returncode == 0 and json.loads(replay.stdout)["native_exit_code"] == 7, (
        "Relocated offline replay must verify failed original custody without the executable")
    assert before == {str(path.relative_to(relocated)): path.read_bytes()
        for path in relocated.rglob("*") if path.is_file()}, (
        "Offline original replay must not write, repair or refresh relocated workspace bytes")


@pytest.mark.skipif(os.name == "nt", reason="owned synthetic executable uses a POSIX shebang")
def test_ForegroundShellRunsSameOriginalSyntheticNativeWorkflow(tmp_path):
    """Actual shell planning and exact confirmation preserve synthetic native streams and model."""

    root = tmp_path / "raw shell workspace"
    setup = Setup(root)
    prefix = [str(root), "--tool", "nmap", "--scope", "local", "--owner", "operator:owned",
        "--policy", setup[setup.index("--policy") + 1], "--executable", setup[-1]]
    output = StringIO()
    shell = InteractiveShell(stdout=output)
    shell.onecmd("raw " + shlex.join(["plan", *prefix, "--json", "--", *NATIVE]))
    plan = json.loads(output.getvalue())
    output.seek(0)
    output.truncate()
    shell.onecmd("raw " + shlex.join(["run", *prefix, "--confirm-plan", plan["intent_sha256"],
        "--confirmation-reference", "approval:raw-shell", "--", *NATIVE]))
    assert output.getvalue().startswith('<?xml version="1.0"'), (
        "Foreground raw success must deliver original XML through the same governed owner")
    assert len(LocalModelStore(root).Open().Objects(ObjectKind.PORT)) == 2, (
        "Actual foreground raw execution must persist canonical individual Port facts")
    assert list(shell._history) == ["raw", "raw"] and shell.lastcmd == "raw", (
        "Successful raw planning and execution must retain no arguments in shell replay or history")


@pytest.mark.skipif(os.name != "posix", reason="Actual native terminal requires a POSIX PTY")
def test_ActualRawTerminalProtectsRejectedArgumentsNativeRecallAndReplay(tmp_path):
    """Owned native history excludes raw arguments, including malformed and rejected input."""

    marker = MARKER.encode()
    result = RunTerminal(tmp_path, (b"raw run absent -- " + marker, b"\x1b[A", b"",
        b"raw replay absent --receipt " + marker, b"raw; " + marker,
        b'raw run "' + marker))
    assert MARKER not in json.dumps(result), (
        "Rejected native, replay and malformed raw arguments must not enter any owned history")
    assert result["before"] == result["after"][:3] and result["restored"], (
        "Raw history protection must preserve unrelated caller entries and editor configuration")
    assert result["local"].count("raw") >= 4 and result["after"].count("raw") >= 4, (
        "Every explicitly typed raw command must retain only its protected namespace")
