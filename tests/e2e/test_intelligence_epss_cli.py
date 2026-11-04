# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual offline selected EPSS CLI custody, relocation and read-only inspection workflows."""

from __future__ import annotations

import gzip
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from fuzzy1337.evidence import LocalEvidenceStore
from tests.e2e.test_intelligence_cli import Files
from tests.integration.test_intelligence_acquisition_persistence import Context


def Body() -> bytes:
    """Return original tiny gzip bytes with one selected and one unrelated synthetic CVE."""

    return gzip.compress(
        b"#model_version:synthetic-1,score_date:2026-10-12T00:00:00Z\n"
        b"cve,epss,percentile\nCVE-1900-9999,2e-1,0.8\nCVE-1900-7777,0.9,0.99\n",
        mtime=0,
    )


def ImportArguments(root: Path, source: Path) -> list[str]:
    """Declare all exact local source facts and two explicit CVEs without publisher authority."""

    return [
        "epss", "import", str(root), str(source), "--model-version", "synthetic-1",
        "--score-date", "2026-10-12", "--identifier", "CVE-1900-9999",
        "--identifier", "CVE-1900-8888", "--origin", "synthetic",
        "--publisher", "Owned synthetic EPSS CLI fixture", "--source-url",
        "https://example.invalid/scores.csv.gz", "--license-name", "Synthetic fixture terms",
        "--license-url", "https://example.invalid/LICENSE", "--terms-url",
        "https://example.invalid/terms", "--terms-url", "https://example.invalid/attribution",
        "--scope", "scope:owned",
    ]


def Selection(root: Path, outcome: dict) -> list[str]:
    """Select both exact successful custody roots without replacing the persisted CVE scope."""

    return ["epss", "inspect", str(root), "--selection", outcome["selection_id"],
            "--receipt", outcome["receipt_id"]]


def Run(arguments: list[str]) -> tuple[int, dict]:
    """Invoke the assembled product entry point in a separate process with JSON presentation."""

    result = subprocess.run(
        [sys.executable, "-m", "fuzzy1337", "intel", *arguments, "--json"],
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert not result.stderr, "EPSS CLI leaked a traceback or rejected argument content."

    return result.returncode, json.loads(result.stdout)


def test_ActualSelectedImportReopensOriginalGzipAfterRelocationAndSourceDeletion(tmp_path):
    """The actual product keeps source assertions and exact raw custody without model changes."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.csv.gz"
    raw = Body()
    source.write_bytes(raw)
    beforeModel = model.Open()
    status, imported = Run([
        *ImportArguments(model.root, source), "--expected-sha256", hashlib.sha256(raw).hexdigest(),
        "--max-bytes", str(len(raw)),
    ])
    assert status == 0 and imported["acquisition_state"] == "succeeded", (
        "Actual selected EPSS acquisition failed its product entry point."
    )
    assert imported["profile"] == "epss-local-selected-cli" and "snapshot_id" not in imported, (
        "New selected custody reused the legacy snapshot terminal schema."
    )
    acknowledgements = ("raw_ack", "selection_ack", "receipt_ack")
    assert all(imported[key] == "confirmed" for key in acknowledgements), (
        "Successful CLI custody omitted one independent publication acknowledgement."
    )
    store = LocalEvidenceStore(model.root / "evidence")
    retained = [store.Get(imported[key]) for key in ("raw_id", "selection_id", "receipt_id")]
    assert store.Read(retained[0].reference) == raw, "Acquisition changed original gzip bytes."
    assert retained[0].provenance == retained[1].provenance == retained[2].provenance, (
        "Selected CLI custody lost common acquisition attribution."
    )
    selected = imported["selection"]
    assert selected["requested_ids"] == ["CVE-1900-8888", "CVE-1900-9999"] and selected[
        "unmatched_ids"
    ] == ["CVE-1900-8888"], "The CLI enlarged selection or changed absence into a score."
    assert selected["records"] == [{"identifier": "CVE-1900-9999", "probability": "2e-1",
                                     "percentile": "0.8"}], (
        "Selected source numeric assertions were replaced by recalculated values."
    )
    assert selected["model_version"] == "synthetic-1" and selected[
        "effective_at"
    ] == "2026-10-12T00:00:00.000000+00:00", "The source model or source measurement time changed."
    assert imported["publisher_authentication"] == "not-assessed" and imported[
        "target_applicability"
    ] == "not-evaluated", "Local custody became publisher authentication or target applicability."
    assert imported["source"]["terms_urls"] == ["https://example.invalid/attribution",
                                               "https://example.invalid/terms"], (
        "Distinct source terms and attribution links disappeared from the acquired declaration."
    )
    before = Files(model.root)
    status, inspected = Run(Selection(model.root, imported))
    assert status == 0 and inspected["selection"] == selected, (
        "Actual read-only selected inspection did not reparse the immutable original gzip."
    )
    assert Files(model.root) == before and model.Open() == beforeModel, (
        "Import or inspection silently changed authoritative model or retained evidence."
    )
    relocated = tmp_path / "relocated"
    source.unlink()
    shutil.move(model.root, relocated)
    before = Files(relocated)
    status, moved = Run(Selection(relocated, imported))
    assert status == 0 and moved["selection"] == selected and Files(relocated) == before, (
        "Relocated workspace inspection required the deleted input or mutated custody."
    )


@pytest.mark.parametrize("failure", ["digest", "parse", "size", "model", "day"])
def test_ActualFailedImportKeepsHonestOriginalBytesAndNoUsableSelection(tmp_path, failure):
    """Digest, decoder, source metadata and byte-budget failures retain truthful custody facts."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.csv.gz"
    raw = b"invalid owned gzip" if failure == "parse" else Body()
    source.write_bytes(raw)
    arguments = ImportArguments(model.root, source)

    if failure == "digest":
        arguments.extend(["--expected-sha256", "0" * 64])

    elif failure == "size":
        arguments.extend(["--max-bytes", "7"])

    elif failure in ("model", "day"):
        option, value = ("--model-version", "other-model") if failure == "model" else (
            "--score-date", "2026-10-11",
        )
        arguments[arguments.index(option) + 1] = value

    beforeModel = model.Open()
    status, outcome = Run(arguments)
    expected = {"digest": "digest-mismatch", "parse": "parse-failed", "size": "size-exceeded",
                "model": "parse-failed", "day": "parse-failed"}[failure]
    assert status == 4 and outcome["acquisition_state"] == expected and outcome[
        "selection_id"
    ] is None, "Rejected actual import invented a usable selection or successful terminal state."
    store = LocalEvidenceStore(model.root / "evidence")
    rawRecord = store.Get(outcome["raw_id"])
    assert store.Read(rawRecord.reference) == (raw[:7] if failure == "size" else raw), (
        "Failed actual acquisition changed its bounded original bytes."
    )
    receipt = store.Get(outcome["receipt_id"])
    assert json.loads(store.Read(receipt.reference))["state"] == expected, (
        "The product output disagrees with its retained terminal receipt."
    )
    assert model.Open() == beforeModel, "Rejected actual source import changed model state."


def test_ActualInspectionRejectsMissingReceiptAndScopeReplacementWithoutWrites(tmp_path):
    """Exact successful receipt selection is mandatory and inspect cannot enlarge stored CVEs."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.csv.gz"
    source.write_bytes(Body())
    status, imported = Run(ImportArguments(model.root, source))
    assert status == 0, "Actual source setup failed before receipt refusal."
    before = Files(model.root)
    status, rejected = Run([*Selection(model.root, imported), "--identifier", "CVE-1900-7777"])
    assert status == 2 and rejected["failure"] == "configuration", (
        "Read-only inspection accepted a replacement identifier selection."
    )
    missing = dict(imported, receipt_id="sha256:" + "0" * 64)
    status, rejected = Run(Selection(model.root, missing))
    assert status == 4 and rejected["failure"] == "integrity" and Files(model.root) == before, (
        "Inspection accepted absent terminal custody or changed owning bytes on refusal."
    )
