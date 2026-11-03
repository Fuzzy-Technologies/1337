# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Assembled local CWE CLI custody and portable exact-root replay of owned synthetic ZIPs."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest

from fuzzy1337.evidence import LocalEvidenceStore
from tests.e2e.test_intelligence_cli import Files
from tests.integration.test_intelligence_acquisition_persistence import Context
from tests.unit.test_intelligence_cwe_commands import Arguments, Body, Inspect


def Run(arguments):
    """Invoke the assembled product process and require one clean terminal JSON object."""

    result = subprocess.run([sys.executable, "-m", "fuzzy1337", "intel", "cwe", *arguments,
                             "--json"], capture_output=True, text=True, timeout=15, check=False)
    assert not result.stderr, "Assembled CWE CLI leaked diagnostics or a traceback"

    return result.returncode, json.loads(result.stdout)


def test_ActualProductRetainsOriginalAndReopensAfterCallerDeletionAndRelocation(tmp_path):
    """The full command stack preserves custody without authoritative model writes."""

    model, _ = Context(tmp_path)
    raw = Body()
    source = tmp_path / "owned.zip"
    source.write_bytes(raw)
    before_model = model.Open()
    status, imported = Run([*Arguments(model.root, source, raw), "--max-bytes", str(len(raw))])
    assert status == 0 and imported["ack_basis"] == "sdk-returned", "Actual CLI import failed"
    assert all(imported[key] == "confirmed"
               for key in ("raw_ack", "selection_ack", "receipt_ack")), (
        "Actual successful import lacked three returned acknowledgements"
    )
    store = LocalEvidenceStore(model.root / "evidence")
    original = store.Get(imported["raw_id"])
    assert store.Read(original.reference) == raw, "Actual CLI changed original ZIP"
    records = [store.Get(imported[key]) for key in ("selection_id", "receipt_id")]
    assert all(record.provenance == original.provenance for record in records), (
        "Custody joins changed"
    )
    assert imported["source"]["notice_bundle"]["text"].endswith("[image alt: HSSEDI]\n"), (
        "Actual CLI omitted the captured notice footer"
    )
    assert imported["selection"]["unmatched_ids"] == ["CWE-999"], "Absent ID became source fact"
    before = Files(model.root)
    status, inspected = Run(Inspect(model.root, imported))
    assert status == 0 and inspected["selection"] == imported["selection"], (
        "Exact-root replay changed"
    )
    assert inspected["ack_basis"] == "verified-present", (
        "Inspection rewrote historical returned ACKs"
    )
    assert Files(model.root) == before and model.Open() == before_model, (
        "Inspection or import saved model"
    )
    source.unlink()
    moved = tmp_path / "relocated"
    shutil.move(model.root, moved)
    before = Files(moved)
    status, inspected = Run(Inspect(moved, imported))
    assert status == 0 and inspected["selection"] == imported["selection"], (
        "Relocated replay failed"
    )
    assert Files(moved) == before, "Relocated read-only inspection wrote owning files"
    status, rejected = Run([*Inspect(moved, imported), "--identifier", "CWE-1"])
    assert status == 2 and rejected["failure"] == "configuration", (
        "Inspect replaced source selection"
    )
    assert Files(moved) == before, "Rejected inspection changed owning state"


@pytest.mark.parametrize("artifact", ["raw_id", "receipt_id", "selection_id"])
def test_ActualProductRejectsCorruptOrAbsentRootsWithoutExposingAssertions(tmp_path, artifact):
    """Actual owning corruption is an integrity failure without selection or state mutation."""

    model, _ = Context(tmp_path)
    raw = Body()
    source = tmp_path / "owned.zip"
    source.write_bytes(raw)
    status, imported = Run(Arguments(model.root, source, raw))
    assert status == 0, "Actual fixture setup failed"
    store = LocalEvidenceStore(model.root / "evidence")
    record = store.Get(imported[artifact])
    path = model.root / "evidence" / record.reference.locator
    path.write_bytes(b"owned corrupt bytes")
    before = Files(model.root)
    status, rejected = Run(Inspect(model.root, imported))
    assert status == 4 and rejected["failure"] == "integrity", "Corruption became successful replay"
    assert "source" not in rejected and "selection" not in rejected, "Corruption exposed assertions"
    assert Files(model.root) == before, "Refused exact-root inspection wrote owning state"
