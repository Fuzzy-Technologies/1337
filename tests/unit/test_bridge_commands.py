# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual saved-file intake, truthful evidence acknowledgements and static-source boundaries."""

from __future__ import annotations

import hashlib
import json
import shlex
import socket
import subprocess
from io import StringIO
from pathlib import Path

import pytest

from fuzzy1337 import bridge_commands as commands
from fuzzy1337.bridge_sarif import RAW_ROLE, RECEIPT_ROLE
from fuzzy1337.cli import Main
from fuzzy1337.evidence import EvidenceStorageError, LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from fuzzy1337.shell import InteractiveShell
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.sarif_helpers import (
    SHA256,
    Document,
    Files,
    Golden,
    ImportArguments,
    InspectArguments,
    Owned,
    Run,
)


@pytest.mark.parametrize("arguments", [
    ["sarif", "import", "unused", "file"],
    ["sarif", "inspect", "unused", "--original", "invalid", "--receipt", "sha256:" + "b" * 64,
     "--expected-sha256", SHA256],
    ["sarif", "inspect", "unused", "--original", "sha256:" + "a" * 64, "--receipt", "invalid",
     "--expected-sha256", SHA256],
    ["sarif", "inspect", "unused", "--original", "sha256:" + "a" * 64,
     "--receipt", "sha256:" + "b" * 64, "--expected-sha256", "INVALID"],
    ["sarif", "inspect", "unused", "--original", "sha256:" + "a" * 64,
     "--receipt", "sha256:" + "b" * 64, "--expected-sha256", SHA256, "--owner", "rejected"],
    ["sarif", "inspect", "unused", "--original", "sha256:" + "a" * 64,
     "--receipt", "sha256:" + "b" * 64, "--expected-sha256", SHA256,
     "--receipt=sha256:" + "b" * 64],
])
def test_InvalidSelectionsRefuseBeforeFilesystemAccess(arguments, monkeypatch):
    """Malformed source/root options cannot read or create an owning workspace."""

    def Denied(*values, **options):
        """Trip any physical path access after rejected grammar."""

        raise AssertionError("Invalid saved-report selections reached the filesystem")

    monkeypatch.setattr(commands, "IntelPath", Denied)
    status, refused = Run(arguments)
    assert status == 2 and refused["failure"] == "configuration", "Reject invalid input early"
    assert "projection" not in refused and refused["original_commit"] == "not-attempted", (
        "Invalid options cannot produce source facts or publication claims"
    )


@pytest.mark.parametrize("topic", [[], ["sarif"], ["sarif", "import"], ["sarif", "inspect"]])
def test_ExactHelpNeedsNoStorageOrSource(topic, monkeypatch):
    """All ordinary operator help entries are independent from files and provider health."""

    def Denied(*arguments, **options):
        """Trip an unexpected owning access while displaying static help."""

        raise AssertionError("Saved-report help accessed storage")

    monkeypatch.setattr(commands, "IntelPath", Denied)
    status, output = Run([*topic, "--help"], human=True)
    assert status == 0 and "1337 bridge" in output, "Help must describe the real local command"


@pytest.mark.parametrize("fault", ["wrong-pin", "parse", "link", "hardlink", "overflow"])
def test_FileRefusalDoesNotPublishOrMutateCanonicalOwners(tmp_path, fault):
    """Unsupported or physically unsafe input fails before any immutable evidence publication."""

    root, source = Owned(tmp_path)
    arguments = ImportArguments(root, source)

    if fault == "wrong-pin":
        arguments[-1] = "a" * 64

    elif fault == "parse":
        source.write_bytes(b"not a saved SARIF file")

    elif fault == "overflow":
        source.write_bytes(b"x" * (1024 * 1024 + 1))

    else:
        original = tmp_path / "original.sarif"
        source.rename(original)

        try:
            if fault == "link":
                source.symlink_to(original)

            else:
                source.hardlink_to(original)

        except (OSError, NotImplementedError):
            pytest.skip("This owned filesystem does not support the selected link fixture")

    before = Files(root)
    status, refused = Run(arguments)
    assert status == 4 and "projection" not in refused, "Refused file must produce no partial facts"
    assert refused["original_commit"] == refused["receipt_commit"] == "not-attempted", (
        "Prepublication refusal must not fabricate original or receipt acknowledgements"
    )
    assert Files(root) == before, "Rejected files must not change the workspace or model"


def test_LiteralSourceUrisNeverBecomeReadsNetworkOrExecution(tmp_path, monkeypatch):
    """A real local URI can name an existing file without granting any read of that file."""

    root, source = Owned(tmp_path)
    sentinel = tmp_path / "do-not-read-source.py"
    sentinel.write_text("owned private sentinel", encoding="utf-8")
    document = Document()
    uri = sentinel.as_uri()
    document["$schema"] = "https://never-fetch.invalid/schema.json"
    run = document["runs"][0]
    run["tool"]["driver"]["informationUri"] = "https://never-fetch.invalid/tool"
    run["artifacts"][0]["location"]["uri"] = uri
    run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = uri
    raw = json.dumps(document).encode("utf-8")
    source.write_bytes(raw)
    beforeModel = LocalModelStore(root).Open()
    originalOpen = Path.open

    def Open(path, *arguments, **options):
        """Permit real owner I/O while denying the report's untrusted source-file locator."""

        assert sentinel.name not in str(path), "The report source URI was turned into file I/O"

        return originalOpen(path, *arguments, **options)

    def Denied(*arguments, **options):
        """Trip any external action or canonical-owner mutation during source-only import."""

        raise AssertionError("Saved SARIF import attempted execution/network/model/workspace save")

    monkeypatch.setattr(Path, "open", Open)
    monkeypatch.setattr(socket, "socket", Denied)
    monkeypatch.setattr(socket, "getaddrinfo", Denied)
    monkeypatch.setattr(subprocess, "Popen", Denied)
    monkeypatch.setattr(LocalModelStore, "Save", Denied)
    monkeypatch.setattr(LocalWorkspaceStore, "Save", Denied)
    status, imported = Run(ImportArguments(root, source, hashlib.sha256(raw).hexdigest()))
    assert status == 0 and imported["projection"]["runs"][0]["results"][0][
        "locations"
    ][0]["uri"] == uri, "Keep the literal source URI without reading it"
    assert LocalModelStore(root).Open() == beforeModel, "Source-only import cannot change the model"


@pytest.mark.parametrize("stage,lost", [(1, False), (1, True), (2, False), (2, True)])
def test_PublicationFailureKeepsIndependentAcknowledgements(tmp_path, monkeypatch, stage, lost):
    """A failed owner return can follow publication without a usable source projection."""

    root, source = Owned(tmp_path)
    actualPut = LocalEvidenceStore.Put
    calls = []
    beforeModel = LocalModelStore(root).Open()

    def Put(store, payload, role, media, provenance):
        """Inject failure before or after one actual immutable owning publication."""

        calls.append(role)

        if len(calls) == stage and not lost:
            raise EvidenceStorageError("owned failure before publication")

        record = actualPut(store, payload, role, media, provenance)

        if len(calls) == stage:
            raise EvidenceStorageError("owned lost acknowledgement after publication")

        return record

    monkeypatch.setattr(LocalEvidenceStore, "Put", Put)
    status, refused = Run(ImportArguments(root, source))
    assert status == 4 and refused["failure"] == "storage" and "projection" not in refused, (
        "An uncertain owning publication cannot expose usable source assertions"
    )
    assert refused["original_commit"] == ("unknown" if stage == 1 else "confirmed"), (
        "Original acknowledgement must follow the actual returned handle"
    )
    assert refused["receipt_commit"] == ("not-attempted" if stage == 1 else "unknown"), (
        "Receipt acknowledgement must remain independent from the original"
    )
    assert calls == [RAW_ROLE, RECEIPT_ROLE][:stage], "Do not retry a failed immutable publication"
    assert LocalModelStore(root).Open() == beforeModel, "Publication cannot mutate the model"


def test_PortableOutputAndPresentationRefusalDoNotLeakPartialSourceFacts(tmp_path):
    """Actual Unicode expansion can exceed the terminal budget after successful original custody."""

    root, source = Owned(tmp_path)
    document = Document()
    row = document["runs"][0]["results"][0]
    row["message"]["text"] = "😀" * 1024
    document["runs"][0]["results"] = [row] * 192
    raw = json.dumps(document, ensure_ascii=False).encode("utf-8")
    source.write_bytes(raw)
    status, refused = Run(ImportArguments(root, source, hashlib.sha256(raw).hexdigest()))
    assert status == 4 and refused["failure"] == "presentation-limit" and (
        "projection" not in refused
    ), (
        "An over-budget terminal must not expose a partially staged source projection"
    )
    assert refused["original_commit"] == refused["receipt_commit"] == "confirmed", (
        "Presentation refusal must preserve truthful completed immutable custody"
    )


def test_CommandRouterAndShellKeepActualSourcePinsAndArgumentsPrivate(tmp_path, capsys):
    """The real dispatcher and shell reach the owning command without retaining source arguments."""

    root, source = Owned(tmp_path)
    arguments = ImportArguments(root, source)
    assert Main(["bridge", *arguments, "--json"]) == 0, "The real route must import the file"
    imported = json.loads(capsys.readouterr().out)
    before = Files(root)
    output = StringIO()
    shell = InteractiveShell(stdout=output)
    shell.onecmd("bridge " + shlex.join([
        *InspectArguments(root, imported), "--json"
    ]))
    assert json.loads(output.getvalue())["projection"] == Golden(), "Shell must use the same owner"
    assert list(shell._history) == ["bridge"] and shell.lastcmd == "bridge", (
        "Neither native history nor empty-line replay may retain private report selections"
    )
    assert Files(root) == before, "Foreground inspection must leave every owning byte unchanged"


@pytest.mark.parametrize("mode", ["short", "none", "interrupted-read", "interrupted-render"])
def test_OutputAndInterruptionCannotReturnFalseSuccess(tmp_path, monkeypatch, mode):
    """A terminal or interruption failure cannot expose positive source projection as success."""

    root, source = Owned(tmp_path)

    if mode.startswith("interrupted"):
        def Denied(*arguments, **options):
            """Interrupt the actual read or complete terminal staging before output publication."""

            raise KeyboardInterrupt

        if mode == "interrupted-read":
            monkeypatch.setattr(commands, "ReadArtifactFile", Denied)

        else:
            monkeypatch.setattr(commands, "BridgeTerminal", Denied)

        status, refused = Run(ImportArguments(root, source))
        assert status == 130 and "projection" not in refused, "Cancellation must remove facts"

    else:
        class Output:
            """Record one publication attempt and return an incomplete acknowledgement."""

            calls = 0

            def Write(self, text):
                """Return a caller-owned incomplete write without retry or source mutation."""

                self.calls += 1

                return len(text) - 1 if mode == "short" else None

            write = Write

        output = Output()

        with pytest.raises(OSError, match="not written completely"):
            commands.RunBridgeCommands(ImportArguments(root, source), output, jsonOutput=True)

        assert output.calls == 1, "Never retry a caller stream after ambiguous output publication"
