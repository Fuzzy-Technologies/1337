# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual offline intelligence CLI import/replay and explicit durable finding enrichment."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.findings import Finding, FindingStatus, TransitionFinding
from fuzzy1337.intelligence import IntelligenceFeed
from fuzzy1337.model import LocalModelStore, ObjectKind
from tests.integration.test_intelligence_acquisition_persistence import Context, FeedBody


def Files(root: Path) -> dict[str, bytes]:
    """Capture all owning state bytes to prove rejected commands did not mutate storage."""

    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}


def Run(arguments: list[str]) -> tuple[int, dict]:
    """Run the actual installed package module in a separate process with stable JSON output."""

    result = subprocess.run(
        [sys.executable, "-m", "fuzzy1337", "intel", *arguments, "--json"],
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert not result.stderr, "Intelligence CLI leaked a traceback or argument diagnostic."

    return result.returncode, json.loads(result.stdout)


def ImportArguments(root: Path, source: Path, feed: IntelligenceFeed) -> list[str]:
    """Declare exact owned source facts without attributing the fixture to an official corpus."""

    return [
        "import", str(root), str(source), "--feed", feed.value,
        "--catalog-version", "synthetic-1", "--origin", "synthetic",
        "--publisher", "Owned synthetic CLI fixture", "--source-url",
        "https://example.invalid/owned.data", "--license-name", "Apache-2.0 synthetic fixture",
        "--license-url", "https://example.invalid/LICENSE", "--scope", "scope:owned",
    ]


def Imported(tmp_path: Path) -> tuple[LocalModelStore, str, dict]:
    """Prepare a real finding and acquire one source through the actual CLI process."""

    model, finding = Context(tmp_path)
    source = tmp_path / "owned.csv"
    source.write_bytes(FeedBody(IntelligenceFeed.EPSS))
    status, outcome = Run(ImportArguments(model.root, source, IntelligenceFeed.EPSS))
    assert status == 0, "Owned source acquisition did not succeed through the product CLI."

    return model, finding, outcome


def Selection(action: str, root: Path, outcome: dict) -> list[str]:
    """Select the exact acquired snapshot and terminal receipt, never a moving latest source."""

    return [action, str(root), "--snapshot", outcome["snapshot_id"],
            "--receipt", outcome["receipt_id"]]


def ApplyArguments(model: LocalModelStore, finding: str, outcome: dict) -> list[str]:
    """Select one finding, source, exact association, model revision and interpretation time."""

    as_of = (datetime.fromisoformat(outcome["finished_at"]) + timedelta(seconds=1)).isoformat()

    return [*Selection("apply", model.root, outcome), "--finding", finding,
            "--identifier", "CVE-1900-9999", "--expected-revision", str(model.Open().revision),
            "--as-of", as_of, "--max-age-seconds", "86400", "--scope", "scope:owned",
            "--run", "run:cli-fixture"]


@pytest.mark.parametrize("feed", list(IntelligenceFeed))
def test_AllFourOwnedFormatsUseActualCliImmutableStorageAndReparse(tmp_path, feed):
    """All CLI format claims traverse actual receiver-clock acquisition and original-byte replay."""

    model, _ = Context(tmp_path)
    source = tmp_path / "source.data"
    raw = FeedBody(feed)
    source.write_bytes(raw)
    before_model = model.Open()
    status, imported = Run([
        *ImportArguments(model.root, source, feed), "--expected-sha256",
        hashlib.sha256(raw).hexdigest(), "--max-bytes", str(len(raw)),
    ])
    assert status == 0 and imported["acquisition_state"] == "succeeded", (
        "A claimed source family failed its actual product acquisition boundary."
    )
    store = LocalEvidenceStore(model.root / "evidence")
    retained = [store.Get(imported[key]) for key in ("raw_id", "snapshot_id", "receipt_id")]
    assert store.Read(retained[0].reference) == raw, "Source publication changed original bytes."
    assert retained[0].provenance == retained[1].provenance == retained[2].provenance, (
        "The original source, snapshot and receipt lost exact common acquisition attribution."
    )
    assert imported["started_at"] <= imported["finished_at"], (
        "The CLI invented or reordered actual receiver acquisition times."
    )
    before = Files(model.root)
    status, inspected = Run(Selection("inspect", model.root, imported))
    assert status == 0 and inspected["source_sha256"] == hashlib.sha256(raw).hexdigest(), (
        "Read-only CLI inspection did not verify the original retained source."
    )
    assert inspected["record_count"] == 1 and inspected["feed"] == feed.value, (
        "Inspection silently changed source family or failed to reparse its one actual record."
    )
    assert model.Open() == before_model and Files(model.root) == before, (
        "Import or inspection implicitly enriched the model or mutated retained acquisitions."
    )
    relocated = tmp_path / "relocated"
    shutil.move(model.root, relocated)
    status, moved = Run(Selection("inspect", relocated, imported))
    assert status == 0 and moved["snapshot_id"] == imported["snapshot_id"], (
        "A portable owning workspace lost its immutable snapshot identity after relocation."
    )


def test_ExplicitApplyPersistsOneVerifiedObservationAndPreservesExistingTriage(tmp_path):
    """The real CLI appends attributable candidate intelligence without changing finding triage."""

    model, reference, imported = Imported(tmp_path)
    state = model.Open()
    finding = Finding.FromObject(state.Objects(ObjectKind.FINDING)[0])
    state, delta = TransitionFinding(
        state, reference, FindingStatus.DISMISSED,
        replace(finding.provenance[0], source_id="operator", run_reference="run:triage"),
        "Owned fixture disposition",
    )
    model.Save(state, expected_revision=delta.previous_revision)
    original_finding = state.Objects(ObjectKind.FINDING)[0]
    evidence_before = Files(model.root / "evidence")
    arguments = ApplyArguments(model, reference, imported)
    status, applied = Run(arguments)
    saved = model.Open()
    assert status == 0 and applied["model_commit"] == "confirmed", (
        "Explicit verified enrichment did not commit through the owning model store."
    )
    assert saved.revision == state.revision + 1 and saved.Objects(ObjectKind.FINDING) == (
        original_finding,
    ), "Intelligence interpretation rewrote identity, severity, confidence, or operator triage."
    observations = [item for item in saved.observations if item.kind == "finding-intelligence"]
    assert len(observations) == 1 and observations[0].subject_reference == reference, (
        "Actual CLI enrichment failed to retain exactly one observation on the selected finding."
    )
    assertions = observations[0].attributes["source_assertions"]
    assert assertions[0]["record"]["identifier"] == "CVE-1900-9999", (
        "The saved observation lost the selected exact source identifier."
    )
    assert assertions[0]["association_state"] == "candidate", (
        "A caller-declared source match became exploit applicability or a reviewed assertion."
    )
    assert Files(model.root / "evidence") == evidence_before, (
        "Interpretation changed or reacquired the original detector/source evidence."
    )
    before_replay = Files(model.root)
    arguments[arguments.index("--expected-revision") + 1] = str(saved.revision)
    status, replay = Run(arguments)
    assert status == 0 and replay["model_revision"] == saved.revision, (
        "An exact interpretation replay invented another observation or revision."
    )
    assert Files(model.root) == before_replay, "Idempotent interpretation rewrote saved bytes."


@pytest.mark.parametrize("failure", ["digest", "parse", "size"])
def test_FailedActualImportRetainsHonestTerminalAndOriginalBoundedBytes(tmp_path, failure):
    """Failed source acquisition publishes a non-success receipt without a usable snapshot."""

    model, _ = Context(tmp_path)
    source = tmp_path / "rejected.data"
    raw = FeedBody(IntelligenceFeed.EPSS) if failure != "parse" else b"owned invalid source"
    source.write_bytes(raw)
    arguments = ImportArguments(model.root, source, IntelligenceFeed.EPSS)

    if failure == "digest":
        arguments.extend(["--expected-sha256", "0" * 64])

    elif failure == "size":
        arguments.extend(["--max-bytes", "7"])

    before_model = model.Open()
    status, outcome = Run(arguments)
    assert status == 4 and outcome["status"] == "failed" and outcome["snapshot_id"] is None, (
        "Failed actual acquisition supplied a usable snapshot or false success."
    )
    expected = {"digest": "digest-mismatch", "parse": "parse-failed", "size": "size-exceeded"}
    assert outcome["acquisition_state"] == expected[failure], (
        "The CLI replaced the actual terminal state with an invented complete import."
    )
    store = LocalEvidenceStore(model.root / "evidence")
    raw_record = store.Get(outcome["raw_id"])
    receipt = store.Get(outcome["receipt_id"])
    assert store.Read(raw_record.reference) == (raw[:7] if failure == "size" else raw), (
        "Failed acquisition lost the bounded original source bytes."
    )
    assert json.loads(store.Read(receipt.reference))["state"] == expected[failure], (
        "The retained immutable receipt does not match the reported terminal failure."
    )
    assert model.Open() == before_model, "Rejected acquisition mutated existing finding state."


@pytest.mark.parametrize("failure", [
    "missing-raw", "corrupt-raw", "missing-receipt", "foreign-receipt", "receipt-source",
    "receipt-fields", "receipt-raw", "foreign-workspace", "stale-revision", "bad-time",
    "missing-finding", "bad-identifier",
])
def test_ActualReplayAndApplyRefuseInvalidSelectionWithoutMutatingAnyBytes(tmp_path, failure):
    """Exact CLI selection failures leave authoritative model and remaining evidence unchanged."""

    model, finding, imported = Imported(tmp_path)
    store = LocalEvidenceStore(model.root / "evidence")
    raw = store.Get(imported["raw_id"])
    receipt = store.Get(imported["receipt_id"])
    arguments = ApplyArguments(model, finding, imported)

    if failure == "missing-raw":
        (model.root / "evidence" / "records" / (raw.evidence_id[7:] + ".json")).unlink()

    elif failure == "corrupt-raw":
        (model.root / "evidence" / raw.reference.locator).write_bytes(
            b"x" * raw.reference.size_bytes,
        )

    elif failure == "missing-receipt":
        (model.root / "evidence" / "records" / (receipt.evidence_id[7:] + ".json")).unlink()

    elif failure in {"foreign-receipt", "receipt-source", "receipt-fields", "receipt-raw"}:
        document = json.loads(store.Read(receipt.reference))
        provenance = receipt.provenance

        if failure == "foreign-receipt":
            provenance = replace(provenance, workspace_id="foreign")

        elif failure == "receipt-source":
            document["source"]["publisher"] = "Invented replacement publisher"

        elif failure == "receipt-fields":
            document["invented"] = True

        else:
            document["raw"]["provenance"]["scope_reference"] = "scope:foreign"

        replacement = store.Put(json.dumps(document).encode(), "intelligence-acquisition",
                                "application/json", provenance)
        arguments[arguments.index("--receipt") + 1] = replacement.evidence_id

    elif failure == "foreign-workspace":
        foreign, _ = Context(tmp_path, "foreign")
        shutil.copytree(model.root / "evidence", foreign.root / "evidence", dirs_exist_ok=True)
        model = foreign
        arguments[1] = str(model.root)

    else:
        option, value = {
            "stale-revision": ("--expected-revision", "0"),
            "bad-time": ("--as-of", "2000-01-01T00:00:00Z"),
            "missing-finding": ("--finding", "object:" + "0" * 64),
            "bad-identifier": ("--identifier", "cve-1900-9999"),
        }[failure]
        arguments[arguments.index(option) + 1] = value

    before = Files(model.root)
    status, outcome = Run(arguments)
    assert status == 4 and outcome["status"] == "failed", (
        "An invalid source, receipt, association or model revision passed actual CLI application."
    )
    assert outcome["model_commit"] == "not-attempted" and Files(model.root) == before, (
        "Rejected CLI selection wrote authoritative state or changed retained evidence."
    )
