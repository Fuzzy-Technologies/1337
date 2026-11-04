# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify one pinned installed EPSS HTTPS fetch and original offline custody."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from fuzzy1337 import intelligence_epss_remote as remote
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.intel_references import CanonicalReferenceJson, UniqueReferenceObject
from fuzzy1337.model import LocalModelStore
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

SOURCE_COMMIT = "489cd9fcf989cdc3ec87168b873c858938a53517"
SOURCE_DAY = "2026-11-02"
SOURCE_MODEL = "v2026.06.15"
EXPECTED_SHA256 = "86885067d459c6f3ca888bfeb6219d536b428afda9a776c14b48c82bb6a85635"
EXPECTED_DECODED_SHA256 = "ba3fd708e5138ba8b873090f58aee58ce4086d72ab903c457753ba7ddcb5944a"
EXPECTED_BYTES = 2796673
EXPECTED_ROWS = 398815
EXPECTED_DECODED_BYTES = 12129716
SELECTED_IDS = ("CVE-1999-0001", "CVE-2023-20914", "CVE-9999-9999")


def VerifyFetch(document: object) -> dict[str, object]:
    """Require exact terminal pins and independent acknowledgements before reading artifacts.

    Args:
        document: Parsed actual CLI JSON, never a replacement for original-store verification.

    Returns:
        The unchanged terminal document after finite typed acceptance checks.

    Raises:
        ValueError: A terminal result differs from the one pinned genuine selection.
    """

    if not isinstance(document, dict):
        raise ValueError("EPSS acceptance requires a terminal object")

    source = remote.EpssHttpsSource(SOURCE_COMMIT, SOURCE_DAY, SOURCE_MODEL, EXPECTED_SHA256)
    expected = {"profile": "epss-https-selected-cli", "command": "intel.epss.https.fetch",
                "status": "succeeded", "acquisition_state": "succeeded",
                "receive_state": "succeeded", "transport": "https", "http_status": 200,
                "body_complete": True, "received_bytes": EXPECTED_BYTES,
                "source_sha256": EXPECTED_SHA256, "source": source.ToDict(),
                "raw_ack": "confirmed", "selection_ack": "confirmed", "receipt_ack": "confirmed",
                "model_commit": "not-attempted", "publisher_authentication": "not-assessed"}

    if any(document.get(key) != value for key, value in expected.items()) or (
        type(document.get("http_status")) is not int
        or type(document.get("received_bytes")) is not int
        or type(document.get("body_complete")) is not bool
    ):
        raise ValueError("EPSS acceptance terminal facts do not match the pinned source")

    handles = [document.get(key) for key in ("raw_id", "selection_id", "receipt_id")]

    if any(not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
           for value in handles) or len(set(handles)) != 3:
        raise ValueError("EPSS acceptance requires three exact distinct custody handles")

    return document


def NoReceive(*args: object, **kwargs: object) -> tuple[bytes, str, int | None]:
    """Make any receiver call during original-source reopening an explicit failure.

    Args:
        args: Unexpected positional receiver arguments; never used to acquire bytes.
        kwargs: Unexpected receiver options; never used to acquire bytes.

    Returns:
        Never returns; an attempted receiver call raises immediately.

    Raises:
        AssertionError: Offline reopening attempted network acquisition.
    """

    raise AssertionError("Offline original-source acceptance attempted another receiver")


def RunAcceptance(output: Path) -> dict[str, object]:
    """Execute exactly one installed pinned fetch and verify original relocated custody.

    Args:
        output: New acceptance directory retaining original evidence and controlled terminal facts.

    Returns:
        Successful exact source/receipt/selection/relocation facts; publisher trust stays separate.

    Raises:
        ValueError: Installed product, source body, metadata or immutable roots disagree.
        EvidenceError: An original acquisition cannot be verified.
        subprocess.SubprocessError: The bounded installed product invocation fails.
    """

    output.mkdir(parents=True, exist_ok=False)
    workspace = output / "workspace"
    LocalWorkspaceStore(workspace).Create(WorkspaceConfiguration("Pinned EPSS HTTPS acceptance"),
                                         "pinned-epss-https-acceptance")
    before = LocalModelStore(workspace).Create()
    command = [sys.executable, "-I", "-m", "fuzzy1337", "intel", "epss", "https", "fetch",
        str(workspace), "--commit", SOURCE_COMMIT, "--score-date", SOURCE_DAY,
        "--model-version", SOURCE_MODEL, "--expected-sha256", EXPECTED_SHA256,
        "--scope", "scope:pinned-official-data", "--max-bytes", str(EXPECTED_BYTES),
        "--timeout-seconds", "30", "--json"]

    for identifier in SELECTED_IDS:
        command.extend(("--identifier", identifier))

    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    (output / "fetch.json").write_text(result.stdout, encoding="utf-8")
    (output / "fetch-stderr.txt").write_text(result.stderr, encoding="utf-8")

    if result.returncode != 0 or result.stderr:
        raise ValueError("Pinned installed HTTPS fetch did not succeed")

    document = VerifyFetch(json.loads(result.stdout, object_pairs_hook=UniqueReferenceObject))
    selectedId, receiptId = str(document["selection_id"]), str(document["receipt_id"])
    received = remote.LoadHttpsEpssSelection(workspace, selectedId, receiptId)
    expectedSource = remote.EpssHttpsSource(
        SOURCE_COMMIT, SOURCE_DAY, SOURCE_MODEL, EXPECTED_SHA256,
    )

    if received.source != expectedSource or received.source.ToDict() != document["source"]:
        raise ValueError("Original HTTPS source differs from the pinned terminal source")

    selection = received.selection

    if (selection.raw_sha256 != EXPECTED_SHA256 or selection.raw_size != EXPECTED_BYTES
        or selection.decoded_sha256 != EXPECTED_DECODED_SHA256
        or selection.decoded_size != EXPECTED_DECODED_BYTES or selection.row_count != EXPECTED_ROWS
        or selection.requested_ids != SELECTED_IDS
        or selection.unmatched_ids != ("CVE-9999-9999",)
        or selection.records[1].percentile != "6e-05"
        or selection.model_version != SOURCE_MODEL or selection.score_date != SOURCE_DAY):
        raise ValueError("Pinned original gzip selection did not match expected decode facts")

    if received.ToDict()["selection"] != document.get("selection") or (
        received.Reference() != document.get("selection_reference")
        or LocalModelStore(workspace).Open() != before
    ):
        raise ValueError("CLI selected facts or model state disagreed with original custody")

    store = LocalEvidenceStore(workspace / "evidence")
    raw = store.Get(str(document["raw_id"]))

    if raw != received.raw or (
        hashlib.sha256(store.Read(raw.reference)).hexdigest() != EXPECTED_SHA256
    ):
        raise ValueError("Original raw manifest or bytes differ from actual HTTPS selection")

    moved = output / "relocated-workspace"
    shutil.move(str(workspace), moved)
    originalReceiver = getattr(remote, "ReceiveIsolatedHttps")
    setattr(remote, "ReceiveIsolatedHttps", NoReceive)

    try:
        reopened = remote.LoadHttpsEpssSelection(moved, selectedId, receiptId)

    finally:
        setattr(remote, "ReceiveIsolatedHttps", originalReceiver)

    if reopened != received or LocalModelStore(moved).Open() != before:
        raise ValueError("Relocated original-source reopening changed custody or model state")

    productionHashes = {}

    for name in ("intelligence_epss_remote.py", "intelligence_receiver.py",
                 "intelligence_transport.py", "intelligence_acquisition.py",
                 "intelligence_epss_https_commands.py"):
        productionHashes[name] = hashlib.sha256(
            Path(remote.__file__).with_name(name).read_bytes(),
        ).hexdigest()

    facts = {"status": "passed", "profile": "pinned-epss-https-acceptance", "version": 1,
        "source": received.source.ToDict(), "source_sha256": EXPECTED_SHA256,
        "received_bytes": EXPECTED_BYTES, "http_status": document["http_status"],
        "received_rows": selection.row_count, "selection_reference": received.Reference(),
        "selection_id": selectedId, "receipt_id": receiptId,
        "decoder": selection.ToDict(), "offline_relocated_reopen": True,
        "canonical_model_unchanged": True, "publisher_authentication": "not-assessed",
        "production_hashes": productionHashes}
    (output / "acceptance.json").write_bytes(CanonicalReferenceJson(facts))

    return facts


def Main(argv: Sequence[str] | None = None) -> int:
    """Run the finite acceptance command and preserve an honest failure marker when possible.

    Args:
        argv: Explicit command options, or process arguments when omitted.

    Returns:
        Zero only after complete original-source acceptance; one for controlled failure.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=Path("functional-evidence/epss-https-source"))
    options = parser.parse_args(argv)

    if options.output.exists():
        print("Acceptance output already exists; original evidence was not changed.")

        return 1

    try:
        facts = RunAcceptance(options.output.resolve())

    except (ValueError, EvidenceError, OSError, AssertionError, subprocess.SubprocessError):
        options.output.mkdir(parents=True, exist_ok=True)
        (options.output / "acceptance-failed.json").write_text(
            '{"status":"failed","profile":"pinned-epss-https-acceptance"}\n', encoding="utf-8",
        )
        print("Pinned EPSS HTTPS acceptance failed; retained terminal facts are not success.")

        return 1

    print(json.dumps({"status": facts["status"], "received_bytes": EXPECTED_BYTES,
                      "received_rows": EXPECTED_ROWS, "source_sha256": EXPECTED_SHA256}))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
