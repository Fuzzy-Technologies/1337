# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify one pinned official KEV retrieval through the unchanged isolated HTTPS receiver."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from fuzzy1337.evidence import (
    EvidenceError,
    LocalEvidenceStore,
    RejectManifestConstant,
    UniqueManifestObject,
)
from fuzzy1337.intelligence import IntelligenceFeed
from fuzzy1337.intelligence_acquisition import (
    AcquireIntelligenceSnapshot,
    AcquisitionOutcome,
    AcquisitionState,
    CisaKevSource,
    LoadAcquiredSnapshot,
    SnapshotRequest,
)
from fuzzy1337.model import CanonicalModelJson
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

SOURCE_COMMIT = "7ccba8e1223ccec82d12c7736bf3fae11e5bee86"
EXPECTED_SHA256 = "3aa9cf3c01f116362a29d111702979175453c425e3733bde80fc4f6f8e2294e5"
EXPECTED_CATALOG_VERSION = "2026.10.30"
EXPECTED_RECORDS = 1766
EXPECTED_BYTES = 1826755
RECEIVER_TIMEOUT_SECONDS = 30


def VerifyOutcome(root: Path, outcome: AcquisitionOutcome) -> dict[str, object]:
    """Reopen original immutable receipt, snapshot and raw records after real HTTPS acquisition.

    Args:
        root: Owning acceptance workspace created for this one retrieval.
        outcome: Actual first-party acquisition result, with no substituted source bytes.

    Returns:
        Exact successful verification facts; no publisher or target-applicability approval.

    Raises:
        ValueError: Terminal/source/receipt facts differ from the pinned acceptance selection.
        EvidenceError: An original manifest or its retained bytes cannot be verified.
    """

    source = CisaKevSource(SOURCE_COMMIT, EXPECTED_CATALOG_VERSION,
                           expected_sha256=EXPECTED_SHA256)

    if (
        outcome.state is not AcquisitionState.SUCCEEDED or outcome.source != source
        or outcome.transport != "https" or outcome.http_status != 200
        or not outcome.body_complete or outcome.received_bytes != EXPECTED_BYTES
        or outcome.max_bytes != EXPECTED_BYTES
        or outcome.timeout_seconds != RECEIVER_TIMEOUT_SECONDS
        or outcome.raw is None or outcome.snapshot is None
        or outcome.snapshot_record is None or outcome.receipt is None
    ):
        raise ValueError("pinned official-source acquisition did not complete exactly")

    store = LocalEvidenceStore(root / "evidence")

    for record in (outcome.raw, outcome.snapshot_record, outcome.receipt):
        if store.Get(record.evidence_id) != record:
            raise ValueError("original acquisition manifest differs from terminal outcome")

    if not outcome.raw.provenance == outcome.snapshot_record.provenance == (
        outcome.receipt.provenance
    ):
        raise ValueError("original acquisition records lost common receiver provenance")

    if outcome.receipt.reference.role != "intelligence-acquisition" or (
        outcome.receipt.reference.media_type != "application/json"
    ):
        raise ValueError("selected receipt is not an acquisition terminal record")

    receipt = json.loads(store.Read(outcome.receipt.reference),
                         object_pairs_hook=UniqueManifestObject,
                         parse_constant=RejectManifestConstant)

    if CanonicalModelJson(receipt) != CanonicalModelJson(outcome.ToDict()):
        raise ValueError("original receipt differs from exact HTTPS acquisition facts")

    raw = store.Read(outcome.raw.reference)
    replayed = LoadAcquiredSnapshot(root, outcome.snapshot_record.evidence_id)

    if (
        len(raw) != EXPECTED_BYTES or outcome.raw.reference.sha256 != EXPECTED_SHA256
        or outcome.raw.reference != replayed.evidence
        or replayed != outcome.snapshot or replayed.feed is not IntelligenceFeed.KEV
        or replayed.catalog_version != EXPECTED_CATALOG_VERSION
        or len(replayed.records) != EXPECTED_RECORDS
        or replayed.source.artifact_sha256 != EXPECTED_SHA256
    ):
        raise ValueError("original source or verified reparse differs from pinned catalog")

    return {
        "raw_bytes": len(raw), "raw_sha256": outcome.raw.reference.sha256,
        "verified_records": len(replayed.records), "receipt": "verified",
        "original_source_reparse": "verified", "snapshot_reference": replayed.Reference(),
        "target_applicability": "not-evaluated", "publisher_authentication": "not-assessed",
    }


def RunAcceptance(destination: Path) -> int:
    """Retrieve once into an absent physical destination and preserve honest terminal evidence.

    Args:
        destination: New artifact directory, normally ignored functional-evidence output.

    Returns:
        Zero only after exact HTTPS/source/receipt verification; four for a retained failure.
    """

    if ".." in destination.parts:
        raise ValueError("acceptance destination must not contain traversal")

    output = destination.absolute()

    if output.exists() or output.is_symlink() or any(parent.is_symlink()
                                                    for parent in output.parents):
        raise ValueError("acceptance destination must be absent with physical parents")

    output.mkdir(parents=True, exist_ok=False)
    root = output / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Pinned official KEV acceptance"),
                                     "official-kev-source-acceptance")
    request = SnapshotRequest(
        CisaKevSource(SOURCE_COMMIT, EXPECTED_CATALOG_VERSION, expected_sha256=EXPECTED_SHA256),
        max_bytes=EXPECTED_BYTES, timeout_seconds=RECEIVER_TIMEOUT_SECONDS,
    )
    outcome = AcquireIntelligenceSnapshot(root, request, scope_reference="scope:official-source")
    summary: dict[str, object] = {
        "schema_version": 1, "status": "failed", "source_commit": SOURCE_COMMIT,
        "expected_sha256": EXPECTED_SHA256, "expected_catalog_version": EXPECTED_CATALOG_VERSION,
        "expected_records": EXPECTED_RECORDS, "expected_bytes": EXPECTED_BYTES,
        "acquisition": outcome.ToDict(), "verification": None,
    }
    status = 4

    try:
        summary["verification"] = VerifyOutcome(root, outcome)
        summary["status"] = "succeeded"
        status = 0

    except (EvidenceError, OSError, ValueError):
        summary["failure"] = "official-source-verification-failed"

    (output / "summary.json").write_bytes(CanonicalModelJson(summary) + b"\n")
    print(CanonicalModelJson(summary).decode("utf-8"))

    return status


def Main(argv: Sequence[str] | None = None) -> int:
    """Run the single fixed official-source acceptance without generic URLs or discovery.

    Args:
        argv: Optional explicit script arguments; only artifact destination is configurable.

    Returns:
        Actual acceptance status, or two when local output setup cannot be used safely.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=Path("functional-evidence/intel-source-acceptance"))
    arguments = parser.parse_args(argv)

    try:
        return RunAcceptance(arguments.output)

    except (EvidenceError, OSError, ValueError):
        print('{"status":"failed","failure":"acceptance-setup"}')

        return 2


if __name__ == "__main__":
    raise SystemExit(Main())
