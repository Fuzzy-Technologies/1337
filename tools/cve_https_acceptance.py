# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify one installed pinned CVE HTTPS fetch and original offline inspection."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from io import StringIO
from pathlib import Path

from fuzzy1337 import intelligence_cve_remote as remote
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.intel_references import CanonicalReferenceJson, UniqueReferenceObject
from fuzzy1337.intelligence_cve_https_commands import RunCveHttpsCommands
from fuzzy1337.model import LocalModelStore
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

SOURCE_COMMIT = "124afead838875e8bf8f5f0bbaf929340216d81b"
SOURCE_IDENTIFIER = "CVE-2024-3094"
EXPECTED_SHA256 = "f9f0858cc058006963ed8338b802cadaf559f4fa5c501c53752407dfaf3227f9"
EXPECTED_BYTES = 23216


def VerifyFetch(document: object) -> dict[str, object]:
    """Require exact typed terminal source facts before opening original custody.

    Args:
        document: Actual installed CLI JSON; this check does not replace original-store replay.

    Returns:
        The unchanged terminal object after fixed source, network and acknowledgement checks.

    Raises:
        ValueError: The terminal result does not describe this one pinned source completely.
    """

    if not isinstance(document, dict):
        raise ValueError("CVE acceptance requires a terminal object")

    source = remote.CveHttpsSource(SOURCE_COMMIT, SOURCE_IDENTIFIER, EXPECTED_SHA256)
    expected = {"profile": "cve-https-selected-cli", "command": "intel.cve.https.fetch",
        "status": "succeeded", "acquisition_state": "succeeded", "receive_state": "succeeded",
        "transport": "https", "http_status": 200, "body_complete": True,
        "received_bytes": EXPECTED_BYTES, "source_sha256": EXPECTED_SHA256,
        "source": source.ToDict(), "raw_ack": "confirmed", "selection_ack": "confirmed",
        "receipt_ack": "confirmed", "model_commit": "not-attempted",
        "publisher_authentication": "not-assessed"}

    if any(document.get(key) != value for key, value in expected.items()) or (
        type(document.get("http_status")) is not int
        or type(document.get("received_bytes")) is not int
        or type(document.get("body_complete")) is not bool
    ):
        raise ValueError("CVE acceptance terminal facts differ from the pinned source")

    handles = [document.get(key) for key in ("raw_id", "selection_id", "receipt_id")]

    if any(not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
           for value in handles) or len(set(handles)) != 3:
        raise ValueError("CVE acceptance requires three distinct exact custody handles")

    return document


def NoReceive(*args: object, **kwargs: object) -> tuple[bytes, str, int | None]:
    """Refuse any attempt to replace original evidence during offline reopening.

    Args:
        args: Unexpected positional receiver arguments; no bytes are acquired.
        kwargs: Unexpected receiver options; no request is attempted.

    Returns:
        Never returns; the receiver tripwire raises immediately.

    Raises:
        AssertionError: Offline inspection attempted another acquisition.
    """

    raise AssertionError("Offline CVE inspection attempted another receiver")


def RunAcceptance(output: Path) -> dict[str, object]:
    """Fetch the selected source once through the installed CLI and reopen its original roots.

    Args:
        output: New directory retaining actual terminal JSON, original workspace and facts.

    Returns:
        Exact successful source/network/custody/relocation facts without publisher trust claims.

    Raises:
        ValueError: Terminal, original body, source identity or model facts disagree.
        EvidenceError: Original manifest or content integrity cannot be verified.
        subprocess.SubprocessError: The bounded installed product invocation fails.
    """

    output.mkdir(parents=True, exist_ok=False)
    workspace = output / "workspace"
    LocalWorkspaceStore(workspace).Create(WorkspaceConfiguration("Pinned CVE HTTPS acceptance"),
                                         "pinned-cve-https-acceptance")
    before = LocalModelStore(workspace).Create()
    command = [sys.executable, "-I", "-m", "fuzzy1337", "intel", "cve", "https", "fetch",
        str(workspace), "--commit", SOURCE_COMMIT, "--identifier", SOURCE_IDENTIFIER,
        "--expected-sha256", EXPECTED_SHA256, "--scope", "scope:pinned-official-data",
        "--max-bytes", str(EXPECTED_BYTES), "--timeout-seconds", "30", "--json"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    (output / "fetch.json").write_text(result.stdout, encoding="utf-8")
    (output / "fetch-stderr.txt").write_text(result.stderr, encoding="utf-8")

    if result.returncode != 0 or result.stderr:
        raise ValueError("Pinned installed CVE HTTPS fetch did not succeed")

    document = VerifyFetch(json.loads(result.stdout, object_pairs_hook=UniqueReferenceObject))
    selection_id, receipt_id = str(document["selection_id"]), str(document["receipt_id"])
    received = remote.LoadHttpsCveSelection(workspace, selection_id, receipt_id)
    expected_source = remote.CveHttpsSource(SOURCE_COMMIT, SOURCE_IDENTIFIER, EXPECTED_SHA256)

    if received.source != expected_source or received.source.ToDict() != document["source"] or (
        received.max_bytes != EXPECTED_BYTES or received.timeout_seconds != 30
    ):
        raise ValueError("Original CVE source differs from the pinned terminal source")

    snapshot = json.loads(received.snapshot.Serialize(), object_pairs_hook=UniqueReferenceObject)

    if len(received.snapshot.records) != 1 or (
        received.snapshot.records[0].identifier != SOURCE_IDENTIFIER
        or snapshot != document.get("snapshot")
        or received.Reference() != document.get("selection_reference")
        or LocalModelStore(workspace).Open() != before
    ):
        raise ValueError("CLI selected facts or model differ from original CVE custody")

    store = LocalEvidenceStore(workspace / "evidence")
    raw = store.Get(str(document["raw_id"]))
    payload = store.Read(raw.reference)

    if raw != received.raw or len(payload) != EXPECTED_BYTES or (
        hashlib.sha256(payload).hexdigest() != EXPECTED_SHA256
    ):
        raise ValueError("Original CVE manifest or bytes differ from the selected source")

    original = json.loads(payload, object_pairs_hook=UniqueReferenceObject)
    metadata = original.get("cveMetadata") if isinstance(original, dict) else None

    if not isinstance(original, dict) or not isinstance(metadata, dict) or (
        original.get("dataType") != "CVE_RECORD" or original.get("dataVersion") != "5.2"
        or metadata.get("cveId") != SOURCE_IDENTIFIER or metadata.get("state") != "PUBLISHED"
    ):
        raise ValueError("Original CVE source does not match the finite published 5.2 profile")

    moved = output / "relocated-workspace"
    shutil.move(str(workspace), moved)
    original_receiver = getattr(remote, "ReceiveIsolatedHttps")
    setattr(remote, "ReceiveIsolatedHttps", NoReceive)

    try:
        reopened = remote.LoadHttpsCveSelection(moved, selection_id, receipt_id)
        inspected_output = StringIO()
        status = RunCveHttpsCommands([
            "inspect", str(moved), "--selection", selection_id, "--receipt", receipt_id,
        ], inspected_output, json_output=True)
        (output / "inspect.json").write_text(inspected_output.getvalue(), encoding="utf-8")
        inspected = json.loads(inspected_output.getvalue(), object_pairs_hook=UniqueReferenceObject)

    finally:
        setattr(remote, "ReceiveIsolatedHttps", original_receiver)

    expected_inspection = {"profile": "cve-https-selected-cli", "status": "succeeded",
        "command": "intel.cve.https.inspect", "publisher_authentication": "not-assessed",
        "model_commit": "not-attempted", "raw_ack": "confirmed", "selection_ack": "confirmed",
        "receipt_ack": "confirmed", "http_status": 200, "body_complete": True,
        "receive_state": "succeeded", "transport": "https"}

    if not isinstance(inspected, dict) or reopened != received or status != 0 or (
        any(inspected.get(key) != value for key, value in expected_inspection.items())
        or inspected.get("source") != document["source"]
        or inspected.get("snapshot") != snapshot
        or inspected.get("selection_reference") != received.Reference()
        or any(inspected.get(key) != document[key]
               for key in ("raw_id", "selection_id", "receipt_id"))
        or LocalModelStore(moved).Open() != before
    ):
        raise ValueError("Relocated original CVE inspection changed custody or model state")

    production_hashes = {}

    for name in ("intelligence_cve_remote.py", "intelligence_cve_https_commands.py",
                 "intelligence_commands.py", "intelligence_receiver.py",
                 "intelligence_transport.py"):
        production_hashes[name] = hashlib.sha256(
            Path(remote.__file__).with_name(name).read_bytes(),
        ).hexdigest()

    facts = {"status": "passed", "profile": "pinned-cve-https-acceptance", "version": 1,
        "source": received.source.ToDict(), "source_sha256": EXPECTED_SHA256,
        "received_bytes": EXPECTED_BYTES, "http_status": document["http_status"],
        "record_count": 1, "source_state": "PUBLISHED", "source_data_version": "5.2",
        "selection_id": selection_id, "receipt_id": receipt_id,
        "selection_reference": received.Reference(),
        "snapshot_reference": received.snapshot.Reference(),
        "offline_relocated_reopen": True, "installed_offline_inspect": True,
        "canonical_model_unchanged": True, "publisher_authentication": "not-assessed",
        "legal_rights": "not-assessed", "production_hashes": production_hashes}
    (output / "acceptance.json").write_bytes(CanonicalReferenceJson(facts))

    return facts


def Main(argv: Sequence[str] | None = None) -> int:
    """Run finite source acceptance while preserving original success or honest failure facts.

    Args:
        argv: Explicit command options, or process arguments when omitted.

    Returns:
        Zero only after complete original-source verification; one for controlled failure.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("functional-evidence/cve-https-source"))
    options = parser.parse_args(argv)

    if options.output.exists():
        print("Acceptance output already exists; original evidence was not changed.")

        return 1

    try:
        facts = RunAcceptance(options.output.resolve())

    except (ValueError, EvidenceError, OSError, AssertionError, subprocess.SubprocessError):
        options.output.mkdir(parents=True, exist_ok=True)
        (options.output / "acceptance-failed.json").write_text(
            '{"status":"failed","profile":"pinned-cve-https-acceptance"}\n', encoding="utf-8",
        )
        print("Pinned CVE HTTPS acceptance failed; retained terminal facts are not success.")

        return 1

    print(json.dumps({"status": facts["status"], "received_bytes": EXPECTED_BYTES,
                      "identifier": SOURCE_IDENTIFIER, "source_sha256": EXPECTED_SHA256}))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
