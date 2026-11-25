# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Durable real-console selector for installed offline saved-syslog originals."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from fuzzy1337.evidence import LocalEvidenceStore
from tests.syslog_helpers import (
    ORIGINAL,
    Files,
    ImportArguments,
    InspectArguments,
    Owned,
)


def Console(arguments: list[str]) -> tuple[int, dict]:
    """Run the installed console in a separate process with no source selection inferred."""

    executable = Path(sys.executable).with_name("1337.exe" if sys.platform == "win32" else "1337")
    result = subprocess.run([str(executable), "trace", "syslog", *arguments, "--json"],
                            capture_output=True, text=True, timeout=15, check=False)
    assert not result.stderr, "Saved-syslog console leaked rejected selections or a traceback"
    outcome = json.loads(result.stdout)
    assert outcome["exit_code"] == result.returncode, "Console status and terminal facts disagree"

    return result.returncode, outcome


def test_InstalledConsoleReopensCopiedOriginalWithoutInputAndRefusesCorruption(tmp_path):
    """Import real bytes, delete input/store, reopen a copy and reject subsequent raw corruption."""

    root, path = Owned(tmp_path)
    workspace = (root / "workspace.json").read_bytes()
    status, imported = Console(ImportArguments(root, path))
    assert status == 0 and imported["record_count"] == 3 and imported["raw_ack"] == (
        imported["receipt_ack"]
    ) == "confirmed", "Installed console did not genuinely retain both original owner records"
    owner = LocalEvidenceStore(root / "evidence")
    raw = owner.Get(imported["raw_id"])
    receipt = owner.Get(imported["receipt_id"])
    assert owner.Read(raw.reference) == ORIGINAL, "Installed intake changed original syslog bytes"
    assert json.loads(owner.Read(receipt.reference))["raw_id"] == raw.evidence_id, (
        "Installed receipt did not pin its actual original acquisition manifest"
    )
    copied = tmp_path / "copied original store"
    shutil.copytree(root, copied)
    shutil.rmtree(root)
    path.unlink()
    before = Files(copied)
    arguments = InspectArguments(copied, imported)
    status, inspected = Console(arguments)
    assert status == 0 and inspected["source_sha256"] == imported["source_sha256"] and (
        inspected["raw_id"] == imported["raw_id"]
        and inspected["receipt_id"] == imported["receipt_id"]
        and inspected["provenance"] == imported["provenance"]
        and inspected["read_declaration"] == imported["read_declaration"]
        and inspected["ack_basis"] == "verified-present"
    ), "Installed replay lost independent original pins or refreshed source provenance"
    assert [(item["byte_offset"], item["byte_length"]) for item in inspected["records"]] == [
        (0, 99), (101, 16), (118, 48)
    ], "Installed replay changed independently known original byte coordinates"
    first, second, third = inspected["records"]
    assert first["timestamp"] == "2026-11-25T10:15:30.123456+05:30" and (
        first["timestamp_offset"] == "+05:30" and first["hostname"] == "h"
        and first["app_name"] == "app" and first["procid"] == "42" and first["msgid"] == "ID"
        and second["timestamp"] is None and second["hostname"] is None
        and third["message"]["byte_length"] == 0
    ), "Installed operator output lost original fields, offset, NIL or empty-message semantics"
    parameters = first["structured_data"][0]["parameters"]
    assert all("value" not in parameter for parameter in parameters), (
        "Default installed output disclosed arbitrary structured-data values"
    )
    status, exported = Console([*arguments, "--export-records"])
    assert status == 0 and [item["value"] for item in exported["records"][0][
        "structured_data"][0]["parameters"]] == ["one", "two", 'x]y"z\\'], (
        "Installed explicit record export lost repeated parameters or exact decoded escapes"
    )
    assert "café" not in json.dumps(exported, ensure_ascii=False), (
        "The installed record export exposed arbitrary message text"
    )
    assert Console(arguments) == (0, inspected) and Files(copied) == before and (
        (copied / "workspace.json").read_bytes() == workspace
    ), "Repeated installed replay changed original evidence or workspace bytes"
    wrong = [*arguments]
    wrong[-1] = "0" * 64
    assert Console(wrong)[0] == 4, "Installed inspect accepted a stale independent original pin"
    (copied / "evidence" / raw.reference.locator).write_bytes(b"corrupt")
    damaged = Files(copied)
    status, refused = Console([*arguments, "--export-records"])
    assert status == 4 and refused["failure"] == "integrity" and "records" not in refused, (
        "Installed replay presented unverified source records after original corruption"
    )
    assert Files(copied) == damaged, "Corruption refusal changed retained store bytes"
