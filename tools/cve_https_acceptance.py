# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify installed pinned CVE HTTPS acquisition and original offline inspection."""

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
from zipfile import BadZipFile, ZipFile

from fuzzy1337 import intelligence_cve_batch as batch
from fuzzy1337 import intelligence_cve_remote as remote
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.intel_references import CanonicalReferenceJson, UniqueReferenceObject
from fuzzy1337.intelligence_acquisition import SyncState
from fuzzy1337.intelligence_cve_https_commands import RunCveHttpsCommands
from fuzzy1337.model import LocalModelStore
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

SOURCE_COMMIT = "124afead838875e8bf8f5f0bbaf929340216d81b"
SOURCE_IDENTIFIER = "CVE-2024-3094"
EXPECTED_SHA256 = "f9f0858cc058006963ed8338b802cadaf559f4fa5c501c53752407dfaf3227f9"
EXPECTED_BYTES = 23216
BATCH_PINS = (
    (SOURCE_IDENTIFIER, EXPECTED_BYTES, EXPECTED_SHA256),
    ("CVE-2025-55182", 9350, "d41f4dede961b926e5662dbcd2a0c52e5e58fb7bb3a79930b4ff125bf06d321f"),
)
BATCH_PROFILE = "pinned-cve-https-batch-acceptance"
BATCH_MODULES = ("intelligence_cve_batch.py", "intelligence_cve_remote.py",
                 "intelligence_receiver.py", "intelligence_transport.py")


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
    selectionId, receiptId = str(document["selection_id"]), str(document["receipt_id"])
    received = remote.LoadHttpsCveSelection(workspace, selectionId, receiptId)
    expectedSource = remote.CveHttpsSource(SOURCE_COMMIT, SOURCE_IDENTIFIER, EXPECTED_SHA256)

    if received.source != expectedSource or received.source.ToDict() != document["source"] or (
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
    originalReceiver = getattr(remote, "ReceiveIsolatedHttps")
    setattr(remote, "ReceiveIsolatedHttps", NoReceive)

    try:
        reopened = remote.LoadHttpsCveSelection(moved, selectionId, receiptId)
        inspectedOutput = StringIO()
        status = RunCveHttpsCommands([
            "inspect", str(moved), "--selection", selectionId, "--receipt", receiptId,
        ], inspectedOutput, json_output=True)
        (output / "inspect.json").write_text(inspectedOutput.getvalue(), encoding="utf-8")
        inspected = json.loads(inspectedOutput.getvalue(), object_pairs_hook=UniqueReferenceObject)

    finally:
        setattr(remote, "ReceiveIsolatedHttps", originalReceiver)

    expectedInspection = {"profile": "cve-https-selected-cli", "status": "succeeded",
        "command": "intel.cve.https.inspect", "publisher_authentication": "not-assessed",
        "model_commit": "not-attempted", "raw_ack": "confirmed", "selection_ack": "confirmed",
        "receipt_ack": "confirmed", "http_status": 200, "body_complete": True,
        "receive_state": "succeeded", "transport": "https"}

    if not isinstance(inspected, dict) or reopened != received or status != 0 or (
        any(inspected.get(key) != value for key, value in expectedInspection.items())
        or inspected.get("source") != document["source"]
        or inspected.get("snapshot") != snapshot
        or inspected.get("selection_reference") != received.Reference()
        or any(inspected.get(key) != document[key]
               for key in ("raw_id", "selection_id", "receipt_id"))
        or LocalModelStore(moved).Open() != before
    ):
        raise ValueError("Relocated original CVE inspection changed custody or model state")

    productionHashes = {}

    for name in ("intelligence_cve_remote.py", "intelligence_cve_https_commands.py",
                 "intelligence_commands.py", "intelligence_receiver.py",
                 "intelligence_transport.py"):
        productionHashes[name] = hashlib.sha256(
            Path(remote.__file__).with_name(name).read_bytes(),
        ).hexdigest()

    facts = {"status": "passed", "profile": "pinned-cve-https-acceptance", "version": 1,
        "source": received.source.ToDict(), "source_sha256": EXPECTED_SHA256,
        "received_bytes": EXPECTED_BYTES, "http_status": document["http_status"],
        "record_count": 1, "source_state": "PUBLISHED", "source_data_version": "5.2",
        "selection_id": selectionId, "receipt_id": receiptId,
        "selection_reference": received.Reference(),
        "snapshot_reference": received.snapshot.Reference(),
        "offline_relocated_reopen": True, "installed_offline_inspect": True,
        "canonical_model_unchanged": True, "publisher_authentication": "not-assessed",
        "legal_rights": "not-assessed", "production_hashes": productionHashes}
    (output / "acceptance.json").write_bytes(CanonicalReferenceJson(facts))

    return facts


def InstalledBatchHashes(wheel: Path, sourceRoot: Path) -> dict[str, str]:
    """Verify and hash the checked-out, wheel and genuinely installed batch modules.

    Args:
        wheel: Exact local wheel installed in this interpreter's environment.
        sourceRoot: Checkout from which the wheel was built.

    Returns:
        SHA-256 of each exact production module exercised by this checkpoint.
    """

    installed = Path(batch.__file__).resolve().parent

    if not installed.is_relative_to(Path(sys.prefix).resolve()):
        raise ValueError("Pinned CVE batch requires a clean installed wheel")

    hashes = {}

    try:
        with ZipFile(wheel) as archive:
            for name in BATCH_MODULES:
                member = "fuzzy1337/" + name
                actual = (installed / name).read_bytes()

                if actual != archive.read(member) or (
                    actual != (sourceRoot / "src" / member).read_bytes()
                ):
                    raise ValueError("Pinned CVE batch production bytes differ from the wheel")

                hashes[name] = hashlib.sha256(actual).hexdigest()

    except (BadZipFile, KeyError) as error:
        raise ValueError("Pinned CVE batch wheel lacks the expected production modules") from error

    return hashes


def BatchTerminalFacts(result: batch.CveHttpsBatchOutcome) -> list[dict[str, object]]:
    """Retain actual transport and independently acknowledged custody for each slot.

    Args:
        result: Installed SDK result in original caller order.

    Returns:
        Terminal facts suitable for retaining on both success and failure.
    """

    facts: list[dict[str, object]] = []

    for member in result.members:
        outcome = member.outcome
        receive = (member.stoppedReceive if outcome is None
                   else remote.CveHttpsReceiveFacts.FromOutcome(outcome))
        facts.append({"source": member.request.source.ToDict(), "member_state": member.state.value,
            "acquisition_state": outcome.state.value if outcome else None,
            "stop_reason": member.stopReason,
            "receive_state": receive.receiveState if receive else None,
            "http_status": receive.httpStatus if receive else None,
            "received_bytes": receive.receivedBytes if receive else None,
            "body_complete": receive.bodyComplete if receive else None,
            "raw_ack": member.rawAck.value, "selection_ack": member.snapshotAck.value,
            "receipt_ack": member.receiptAck.value,
            "raw_id": outcome.raw.evidence_id if outcome and outcome.raw else None,
            "selection_id": (outcome.snapshot_record.evidence_id
                             if outcome and outcome.snapshot_record else None),
            "receipt_id": outcome.receipt.evidence_id if outcome and outcome.receipt else None})

    return facts


def WorkspaceHashes(root: Path) -> dict[str, str]:
    """Hash the owned workspace files for byte-exact read-only replay verification.

    Args:
        root: Physical workspace created exclusively for this invocation.

    Returns:
        Relative file names and original byte hashes.
    """

    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


def RunBatchAcceptance(output: Path, wheel: Path, sourceRoot: Path) -> dict[str, object]:
    """Acquire the two ADR pins and re-open exact member custody after relocation.

    Args:
        output: New directory retaining transport, installed-byte and replay evidence.
        wheel: Exact local wheel of the isolated interpreter.
        sourceRoot: Checkout from which the wheel was built.

    Returns:
        Accepted bounded batch and exact replay facts.
    """

    output.mkdir(parents=True, exist_ok=False)
    productionHashes = InstalledBatchHashes(wheel, sourceRoot)
    workspace = output / "workspace"
    workspaceId = BATCH_PROFILE
    scope = "scope:pinned-official-data"
    LocalWorkspaceStore(workspace).Create(WorkspaceConfiguration("Pinned CVE HTTPS batch"),
                                         workspaceId)
    modelBefore = LocalModelStore(workspace).Create()
    requests = tuple(remote.CveHttpsRequest(
        remote.CveHttpsSource(SOURCE_COMMIT, identifier, digest), size, 30,
    ) for identifier, size, digest in BATCH_PINS)
    result = batch.AcquireHttpsCveBatch(workspace, requests, scopeReference=scope)
    facts: dict[str, object] = {"profile": BATCH_PROFILE, "version": 1,
        "batch_state": result.state.value, "source_commit": SOURCE_COMMIT,
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "production_hashes": productionHashes, "members": BatchTerminalFacts(result),
        "publisher_authentication": "not-assessed", "legal_rights": "not-assessed"}
    (output / "batch-terminal.json").write_bytes(CanonicalReferenceJson(facts))

    if result.state is not SyncState.SUCCEEDED or result.workspaceId != workspaceId or (
        result.scopeReference != scope
        or tuple(member.request for member in result.members) != requests
    ):
        raise ValueError("Pinned CVE batch did not acquire both exact selected members")

    store = LocalEvidenceStore(workspace / "evidence")
    members = []

    for member in result.members:
        expected = member.request
        acquired = member.outcome

        if member.state is not batch.CveHttpsBatchMemberState.SUCCEEDED or acquired is None or (
            acquired.state is not remote.CveHttpsState.SUCCEEDED
            or acquired.source != expected.source or acquired.max_bytes != expected.max_bytes
            or acquired.timeout_seconds != expected.timeout_seconds or acquired.http_status != 200
            or acquired.received_bytes != expected.max_bytes or acquired.body_complete is not True
            or acquired.receive_state != "succeeded" or acquired.raw is None
            or acquired.snapshot_record is None or acquired.receipt is None
            or acquired.envelope is None or not (
                member.rawAck is member.snapshotAck is member.receiptAck is
                remote.CveHttpsAcknowledgement.CONFIRMED)
        ):
            raise ValueError("Pinned CVE batch member lacks complete original custody")

        original = store.Get(acquired.raw.evidence_id)
        payload = store.Read(original.reference)

        if original != acquired.raw or original != acquired.envelope.raw or (
            len(payload) != expected.max_bytes
            or original.provenance.scope_reference != scope
            or original.provenance.workspace_id != workspaceId
        ) or (
            hashlib.sha256(payload).hexdigest() != expected.source.expected_sha256
        ):
            raise ValueError("Pinned CVE batch original bytes differ from the declared source")

        members.append((acquired.snapshot_record.evidence_id, acquired.receipt.evidence_id,
                        acquired.envelope))

    if LocalModelStore(workspace).Open() != modelBefore:
        raise ValueError("Pinned CVE batch acquisition altered canonical model state")

    before = WorkspaceHashes(workspace)
    relocated = output / "relocated-workspace"
    shutil.move(workspace, relocated)
    originalReceiver = getattr(remote, "ReceiveIsolatedHttps")
    setattr(remote, "ReceiveIsolatedHttps", NoReceive)

    try:
        for selection, receipt, envelope in members:
            if remote.LoadHttpsCveSelection(relocated, selection, receipt) != envelope:
                raise ValueError("Relocated CVE batch selection differs from original evidence")

    finally:
        setattr(remote, "ReceiveIsolatedHttps", originalReceiver)

    if WorkspaceHashes(relocated) != before or LocalModelStore(relocated).Open() != modelBefore:
        raise ValueError("Relocated CVE batch replay changed workspace files or canonical model")

    facts.update({"status": "passed", "offline_relocated_reopen": True,
                  "canonical_model_unchanged": True, "reparsed_members": len(members)})
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
    parser.add_argument("--batch-wheel", type=Path,
                        help="Run the exact two-record batch from this installed wheel")
    options = parser.parse_args(argv)

    if options.output.exists():
        print("Acceptance output already exists; original evidence was not changed.")

        return 1

    profile = BATCH_PROFILE if options.batch_wheel else "pinned-cve-https-acceptance"

    try:
        if options.batch_wheel:
            facts = RunBatchAcceptance(options.output.resolve(), options.batch_wheel.resolve(),
                                       Path(__file__).resolve().parents[1])

        else:
            facts = RunAcceptance(options.output.resolve())

    except (ValueError, EvidenceError, OSError, AssertionError, subprocess.SubprocessError):
        options.output.mkdir(parents=True, exist_ok=True)
        (options.output / "acceptance-failed.json").write_bytes(
            CanonicalReferenceJson({"status": "failed", "profile": profile}))
        print("Pinned CVE HTTPS acceptance failed; retained terminal facts are not success.")

        return 1

    if options.batch_wheel:
        print(json.dumps({"status": facts["status"], "profile": profile,
                          "reparsed_members": facts["reparsed_members"]}))

    else:
        print(json.dumps({"status": facts["status"], "received_bytes": EXPECTED_BYTES,
                          "identifier": SOURCE_IDENTIFIER, "source_sha256": EXPECTED_SHA256}))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
