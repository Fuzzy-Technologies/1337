# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify installed CLI acquisition and offline custody for two pinned CWE archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from io import BytesIO, StringIO
from pathlib import Path
from time import monotonic
from typing import cast
from unittest.mock import patch
from zipfile import BadZipFile, ZipFile

import fuzzy1337
from fuzzy1337 import intelligence_cwe_remote as remote
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.intel_references import CanonicalReferenceJson, UniqueReferenceObject
from fuzzy1337.intelligence_commands import RunIntelCommands
from fuzzy1337.model import LocalModelStore
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

PROFILE = "pinned-cwe-https-acceptance"
IDS = ("CWE-1000", "CWE-79", "CWE-89", "CWE-9999999999")
SCOPE = "scope:pinned-official-data"
TIMEOUT_SECONDS = 15
OUTPUT_LIMIT = 2 * 1024 * 1024
ARTIFACT_LIMIT = 32 * 1024 * 1024
HANDLES = ("raw_id", "selection_id", "receipt_id")


@dataclass(frozen=True, slots=True)
class CwePin:
    """Exact original and decoder facts retained for one official release."""

    version: str
    raw_sha256: str
    size: int
    schema: str
    namespace: str
    decoded_sha256: str
    decoded_size: int
    decoded_crc32: str
    counts: tuple[int, int, int, int]


PINS = (
    CwePin("5.0", "bcda44c9abf61ff977f50c3c6649eea5a97a7b0626b0396c2c3ec4bfb973a3dc",
           2119263, "8.0", "http://cwe.mitre.org/cwe-8",
           "47165a9593def89c69b9ef50c34d99ac68db55df8373613e85e9cc9ceecefb1d",
           19105731, "c01f0a7d", (984, 0, 431, 62)),
    CwePin("4.21", "5225e2b4976696b5b90b62cdad0ddab4e8898103d61350971e366a377e718862",
           2101714, "7.4", "http://cwe.mitre.org/cwe-7",
           "3bd5b7f8a1dbc2223fbcd95500bee6d501b8faaba7b62b78a9a7a16e2756bdeb",
           18571978, "0575b537", (984, 431, 0, 62)),
)


def _Digest(payload: bytes) -> str:
    """Return the original byte SHA-256."""

    return hashlib.sha256(payload).hexdigest()


def _Read(path: Path, limit: int) -> bytes:
    """Read one physical regular file within the stated evidence cap."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("Acceptance requires a physical regular file")

    with path.open("rb") as stream:
        payload = stream.read(limit + 1)

    if len(payload) > limit:
        raise ValueError("Acceptance evidence exceeds its bound")

    return payload


def _Git(root: Path, *args: str) -> bytes:
    """Read local commit identity without any remote operation."""

    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, timeout=10).stdout


def VerifyInstallation(root: Path, wheel: Path) -> dict[str, object]:
    """Verify exact committed source and non-editable installed wheel package bytes.

    Args:
        root: Checked-out source tree containing the committed package.
        wheel: One explicitly selected local wheel produced by the hosted build.

    Returns:
        Source commit/tree, wheel digest and every verified installed package hash.
    """

    package = Path(fuzzy1337.__file__).resolve().parent
    prefix_path = Path(sys.prefix).resolve()

    if sys.prefix == sys.base_prefix or not package.is_relative_to(prefix_path):
        raise ValueError("Acceptance requires the installed package in a separate environment")

    prefix = "src/fuzzy1337/"
    wheel_bytes = _Read(wheel, ARTIFACT_LIMIT)
    records = _Git(root, "ls-tree", "-r", "-z", "HEAD", "--", "src/fuzzy1337").split(b"\0")
    source: dict[str, str] = {}

    for record in filter(None, records):
        header, path = record.decode("utf-8").split("\t", 1)
        mode, kind, blob = header.split()

        if mode not in ("100644", "100755") or kind != "blob" or not path.startswith(prefix):
            raise ValueError("Unexpected committed package entry")

        source[path.removeprefix("src/")] = blob

    installed: dict[str, str] = {}

    with ZipFile(BytesIO(wheel_bytes)) as archive:
        members = [item for item in archive.infolist()
                   if item.filename.startswith("fuzzy1337/") and not item.is_dir()]

        if not source or sorted(item.filename for item in members) != sorted(source):
            raise ValueError("Wheel package inventory differs from committed source")

        if sum(item.file_size for item in members) > ARTIFACT_LIMIT:
            raise ValueError("Wheel package exceeds the verification budget")

        for item in members:
            name = item.filename
            original = _Git(root, "cat-file", "blob", source[name])
            wheel_member = archive.read(item)
            installed_path = package / name.removeprefix("fuzzy1337/")

            if original != wheel_member or _Read(installed_path, ARTIFACT_LIMIT) != original:
                raise ValueError("Installed or wheel bytes differ from committed source")

            installed[name] = _Digest(original)

    actual = {"fuzzy1337/" + path.relative_to(package).as_posix()
              for path in package.rglob("*") if path.is_file()
              and "__pycache__" not in path.relative_to(package).parts}

    if actual != set(installed):
        raise ValueError("Installed package inventory differs from verified wheel")

    return {"source_sha": _Git(root, "rev-parse", "HEAD").decode().strip(),
            "source_tree": _Git(root, "rev-parse", "HEAD^{tree}").decode().strip(),
            "wheel_sha256": _Digest(wheel_bytes), "installed_package_hashes": installed}


def _Equal(actual: dict[str, object], expected: dict[str, object]) -> bool:
    """Compare selected terminal fields with exact JSON type and content semantics."""

    return CanonicalReferenceJson({key: actual[key] for key in expected if key in actual}) == (
        CanonicalReferenceJson(expected)
    )


def VerifyTerminal(payload: bytes, pin: CwePin, *, inspect: bool = False) -> dict[str, object]:
    """Verify typed success and the complete finite source and selection oracle.

    Args:
        payload: Bounded exact terminal JSON emitted by the product.
        pin: Expected original source and decoded facts.
        inspect: Select offline command and verified-present acknowledgement semantics.

    Returns:
        Terminal facts that must still be matched to original custody.
    """

    if len(payload) > OUTPUT_LIMIT:
        raise ValueError("CWE terminal output exceeds the acceptance bound")

    document = json.loads(payload, object_pairs_hook=UniqueReferenceObject)
    source = remote.CweHttpsSource(pin.version, pin.raw_sha256)
    action = "inspect" if inspect else "fetch"
    expected = {"schema_version": 1, "profile_version": 1, "profile": "cwe-https-selected-cli",
        "command": f"intel.cwe.https.{action}", "status": "succeeded", "failure": None,
        "acquisition_state": "succeeded", "receive_state": "succeeded", "transport": "https",
        "transport_profile": remote.TRANSPORT_PROFILE, "http_status": 200, "body_complete": True,
        "received_bytes": pin.size, "source_sha256": pin.raw_sha256, "source": source.ToDict(),
        "raw_ack": "confirmed", "selection_ack": "confirmed", "receipt_ack": "confirmed",
        "ack_basis": "verified-present" if inspect else "sdk-returned",
        "limits": {"max_zip_bytes": pin.size, "timeout_seconds": float(TIMEOUT_SECONDS)},
        "model_commit": "not-attempted", "publisher_authentication": "not-assessed",
        "legal_rights": "not-assessed", "notice_applicability": "not-assessed",
        "target_applicability": "not-evaluated"}

    if not isinstance(document, dict) or not _Equal(document, expected):
        raise ValueError("CWE terminal facts differ from the pinned source")

    remaining = {"selection", "selection_reference", "started_at", "finished_at", *HANDLES}

    if set(document) != set(expected) | remaining:
        raise ValueError("CWE acceptance requires the exact terminal field inventory")

    CanonicalReferenceJson(document)

    handles = [document.get(key) for key in HANDLES]

    if any(not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
           for value in handles) or len(set(handles)) != 3:
        raise ValueError("CWE acceptance requires three distinct exact custody handles")

    selection = document.get("selection")
    weakness, category, grouping, view = pin.counts
    expected_selection = {"catalog_version": pin.version, "cwe_schema_version": pin.schema,
        "xml_namespace": pin.namespace, "member_name": f"cwec_v{pin.version}.xml",
        "raw_sha256": pin.raw_sha256, "raw_size": pin.size, "decoded_sha256": pin.decoded_sha256,
        "decoded_size": pin.decoded_size, "decoded_crc32": pin.decoded_crc32,
        "weakness_count": weakness, "category_count": category, "grouping_count": grouping,
        "view_count": view, "requested_ids": list(IDS), "matched_ids": ["CWE-79", "CWE-89"],
        "unsupported_entries": [{"identifier": "CWE-1000", "source_kind": "View"}],
        "unmatched_ids": ["CWE-9999999999"]}

    if not isinstance(selection, dict) or not _Equal(selection, expected_selection):
        raise ValueError("CWE decoder or selected partitions differ from the original oracle")

    return document


def _Inventory(root: Path) -> dict[str, str]:
    """Hash all bounded workspace files and reject links before offline replay."""

    files = {}
    total = 0

    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Unexpected link in acceptance workspace")

        if path.is_dir():
            continue

        payload = _Read(path, ARTIFACT_LIMIT - total)
        total += len(payload)
        files[path.relative_to(root).as_posix()] = _Digest(payload)

        if len(files) > 128:
            raise ValueError("Acceptance workspace contains unexpected files")

    return files


def _Tripwire(*args: object, **kwargs: object) -> None:
    """Refuse network, process creation or writes while verifying relocated originals."""

    raise AssertionError("Offline CWE replay crossed its resource boundary")


def _Save(path: Path, value: object) -> None:
    """Create a canonical evidence document without overwriting original facts."""

    with path.open("xb") as stream:
        stream.write(CanonicalReferenceJson(value))


def _Fetch(output: Path, workspace: Path, pin: CwePin) -> dict[str, object]:
    """Invoke the installed CLI once and retain its exact terminal output and process facts."""

    command = [sys.executable, "-I", "-m", "fuzzy1337", "intel", "cwe", "https", "fetch",
        str(workspace), "--catalog-version", pin.version, "--expected-sha256", pin.raw_sha256,
        "--scope", SCOPE, "--max-bytes", str(pin.size),
        "--timeout-seconds", str(TIMEOUT_SECONDS), "--json"]

    for identifier in IDS:
        command.extend(("--identifier", identifier))

    started = monotonic()
    returncode = None
    status = "execution-failed"

    try:
        with ((output / "fetch.stdout").open("xb") as out,
              (output / "fetch.stderr").open("xb") as err):
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                    timeout=30, check=False)

        returncode = result.returncode
        status = "exited"

    except subprocess.TimeoutExpired:
        status = "timed-out"
        raise

    finally:
        _Save(output / "fetch-invocation.json", {"argv": command, "returncode": returncode,
            "status": status, "elapsed_ms": round((monotonic() - started) * 1000)})

    if returncode != 0 or _Read(output / "fetch.stderr", OUTPUT_LIMIT):
        raise ValueError("Installed CWE HTTPS fetch failed")

    return VerifyTerminal(_Read(output / "fetch.stdout", OUTPUT_LIMIT), pin)


def _VerifyOriginal(
    workspace: Path, pin: CwePin, document: dict[str, object],
) -> remote.CweHttpsSelection:
    """Match the terminal proof to original bytes and the independently reopened envelope."""

    raw_id, selection_id, receipt_id = (cast(str, document[key]) for key in HANDLES)
    original = remote.LoadHttpsCweSelection(workspace, selection_id, receipt_id)
    store = LocalEvidenceStore(workspace / "evidence")
    raw = original.raw

    if raw.evidence_id != raw_id:
        raise ValueError("CWE terminal raw manifest differs from original custody")

    payload = store.Read(raw.reference)

    if len(payload) != pin.size or _Digest(payload) != pin.raw_sha256:
        raise ValueError("CWE raw body or manifest differs from original custody")

    if not _Equal(document, {"source": original.source.ToDict(),
                             "selection": original.selection.ToDict(),
                             "selection_reference": original.Reference(),
                             "started_at": raw.provenance.started_at,
                             "finished_at": raw.provenance.finished_at}) or (
        original.max_bytes != pin.size or original.timeout_seconds != TIMEOUT_SECONDS
        or raw.provenance.scope_reference != SCOPE
    ):
        raise ValueError("CWE terminal assertions differ from original custody")

    return original


def _Replay(
    output: Path, workspace: Path, pin: CwePin, document: dict[str, object],
    original: remote.CweHttpsSelection,
) -> None:
    """Verify relocated exact roots and preserve inspection streams and byte inventories."""

    moved = output / "relocated-workspace"
    workspace.rename(moved)
    before = _Inventory(moved)
    _Save(output / "relocated-before.json", before)
    selection_id, receipt_id = (cast(str, document[key]) for key in HANDLES[1:])
    stdout = StringIO()
    argv = ["cwe", "https", "inspect", str(moved), "--selection", selection_id,
            "--receipt", receipt_id]
    status = None
    started = monotonic()

    with (patch.object(remote, "ReceiveIsolatedHttps", _Tripwire),
          patch.object(socket, "socket", _Tripwire),
          patch.object(subprocess, "Popen", _Tripwire),
          patch.object(LocalEvidenceStore, "Put", _Tripwire),
          patch.object(LocalModelStore, "Save", _Tripwire),
          (output / "inspect.stderr").open("x", encoding="utf-8") as stderr,
          patch.object(sys, "stderr", stderr)):
        try:
            reopened = remote.LoadHttpsCweSelection(moved, selection_id, receipt_id)
            status = RunIntelCommands(argv, stdout, json_output=True)

        finally:
            (output / "inspect.stdout").write_text(stdout.getvalue(), encoding="utf-8")
            _Save(output / "inspect-invocation.json", {"arguments": argv, "returncode": status,
                "elapsed_ms": round((monotonic() - started) * 1000)})

    after = _Inventory(moved)
    _Save(output / "relocated-after.json", after)

    if status != 0 or reopened != original or before != after or (
        _Read(output / "inspect.stderr", OUTPUT_LIMIT)
    ):
        raise ValueError("Relocated CWE inspection failed or changed the workspace")

    inspected = VerifyTerminal(_Read(output / "inspect.stdout", OUTPUT_LIMIT), pin, inspect=True)
    shared = ("source", "selection", "selection_reference", "started_at", "finished_at", *HANDLES)

    if not _Equal(inspected, {key: document[key] for key in shared}):
        raise ValueError("Relocated CWE inspection substituted original facts")


def RunAcceptance(output: Path, identity: dict[str, object]) -> bool:
    """Attempt both fixed sources independently and retain successful or failed evidence.

    Args:
        output: New directory to receive exact per-version evidence.
        identity: Verified source, wheel and installed package identity.

    Returns:
        True only after both original installed source acquisitions and replays pass.
    """

    output.mkdir(parents=True, exist_ok=False)
    _Save(output / "installation.json", identity)
    outcomes = []

    for pin in PINS:
        target = output / pin.version
        target.mkdir()
        workspace = target / "workspace"
        facts: dict[str, object] = {"catalog_version": pin.version,
            "expected_sha256": pin.raw_sha256, "status": "failed", "phase": "workspace"}

        try:
            LocalWorkspaceStore(workspace).Create(
                WorkspaceConfiguration("Pinned CWE HTTPS acceptance"),
                f"pinned-cwe-https-{pin.version}",
            )
            baseline = LocalModelStore(workspace).Create()
            facts["phase"] = "fetch"
            document = _Fetch(target, workspace, pin)
            facts["phase"] = "original-custody"
            original = _VerifyOriginal(workspace, pin, document)

            if LocalModelStore(workspace).Open() != baseline:
                raise ValueError("CWE acquisition changed the canonical model")

            facts["phase"] = "offline-replay"
            _Replay(target, workspace, pin, document, original)

            if LocalModelStore(target / "relocated-workspace").Open() != baseline:
                raise ValueError("CWE offline replay changed the canonical model")

            facts.update({"status": "passed", "phase": "complete", "terminal": document,
                          "canonical_model_unchanged": True, "offline_relocated_reopen": True})

        except (ValueError, EvidenceError, OSError, AssertionError, subprocess.SubprocessError,
                OverflowError, RecursionError) as error:
            facts["error_type"] = type(error).__name__

        _Save(target / "outcome.json", facts)
        outcomes.append(facts)

    passed = all(facts["status"] == "passed" for facts in outcomes)
    _Save(output / ("acceptance.json" if passed else "acceptance-failed.json"),
          {"profile": PROFILE, "version": 1, "status": "passed" if passed else "failed",
           "outcomes": outcomes, "installation": identity})

    return passed


def Main(argv: Sequence[str] | None = None) -> int:
    """Run the pinned hosted acceptance wrapper under the installed Python.

    Args:
        argv: Explicit options, or process arguments when omitted.

    Returns:
        Zero only when both source pins pass all acquisition and replay checks.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    options = parser.parse_args(argv)

    if options.output.exists() or options.output.is_symlink():
        print("Acceptance output already exists.")

        return 1

    try:
        identity = VerifyInstallation(Path(__file__).resolve().parents[1], options.wheel)
        passed = RunAcceptance(options.output.absolute(), identity)

    except (ValueError, OSError, BadZipFile, subprocess.SubprocessError) as error:
        passed = False

        try:
            options.output.mkdir(parents=True, exist_ok=False)
            _Save(options.output / "acceptance-failed.json",
                  {"profile": PROFILE, "status": "failed", "phase": "installation-or-execution",
                   "error_type": type(error).__name__})

        except OSError:
            # A concurrent or partial run may already own this directory.
            pass

    print(json.dumps({"profile": PROFILE, "status": "passed" if passed else "failed"}))

    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(Main())
