# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded selected-chain transfer, independent pins and atomic publication refusal oracles."""

import base64
import hashlib
import json
from io import StringIO

import pytest

from fuzzy1337 import ioc_bundle as bundles
from fuzzy1337 import report_commands as reports
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.ioc_commands import RunIocCommands
from tests.ioc_cli_helpers import (
    BundleVerifyArguments,
    ExportArguments,
    Files,
    ImportArguments,
    Owned,
    Run,
)


def Acquired(parent):
    """Acquire original bytes through the real unchanged command and owning evidence stores."""

    root, source = Owned(parent)
    status, imported = Run(ImportArguments(root, source))
    assert status == 0, "Bundle fixture must acquire a real original IOC chain"

    return root, imported


@pytest.mark.parametrize("mutation", ["version", "family", "receipt", "snapshot", "extra",
    "count", "part-fields", "base64", "noncanonical-base64", "manifest", "role", "media",
    "source", "payload", "receipt-body", "derived-body"])
def test_DetachedVerificationRefusesSubstitutionEvenWithRehashedBundle(tmp_path, mutation):
    """Rehashing the transfer wrapper cannot replace its independent original acquisition pin."""

    root, imported = Acquired(tmp_path)
    payload = bundles.ExportIocBundle(root, imported["snapshot_id"], imported["receipt_id"])
    document = json.loads(payload)

    if mutation == "version":
        document["schema_version"] = True

    elif mutation == "family":
        document["family"] = "foreign"

    elif mutation in ("receipt", "snapshot"):
        document[mutation + "_id"] = "sha256:" + "0" * 64

    elif mutation == "extra":
        document["unselected"] = {}

    elif mutation == "count":
        document["records"].append(document["records"][0])

    elif mutation == "part-fields":
        document["records"][0]["path"] = "unselected"

    elif mutation in ("base64", "noncanonical-base64", "manifest"):
        key = "manifest_base64" if mutation == "manifest" else "payload_base64"
        document["records"][0][key] = "eA==" if mutation == "manifest" else (
            "!" if mutation == "base64" else document["records"][0][key] + "=")

    elif mutation in ("role", "media", "source"):
        original = json.loads(base64.b64decode(document["records"][0]["manifest_base64"]))

        if mutation == "role":
            original["reference"]["role"] = "foreign"

        elif mutation == "media":
            original["reference"]["media_type"] = "text/plain"

        else:
            original["provenance"]["source_id"] = "foreign"

        document["records"][0]["manifest_base64"] = base64.b64encode(
            bundles.JsonBytes(original)).decode()

    else:
        index = {"payload": 0, "receipt-body": 1, "derived-body": 2}[mutation]
        document["records"][index]["payload_base64"] = base64.b64encode(b"changed").decode()

    changed = bundles.JsonBytes(document)

    with pytest.raises(ValueError):
        bundles.VerifyIocBundle(changed, imported["receipt_id"],
                                hashlib.sha256(changed).hexdigest())


def test_CompleteTransferCeilingIncludesEveryOwningLimitAndEncodingOverhead():
    """The full envelope fits even when every manifest and payload occupies its original ceiling."""

    document = dict(bundles._EMPTY)
    document["records"] = [{
        "manifest_base64": base64.b64encode(b"x" * bundles.EVIDENCE_MANIFEST_MAX_BYTES).decode(),
        "payload_base64": base64.b64encode(b"x" * bundles._ROLES[role][0]).decode(),
    } for role in bundles.ROLES]
    assert len(bundles.JsonBytes(document)) == bundles.MAX_BUNDLE_BYTES, (
        "Transfer ceiling omitted a valid owning limit, base64 padding or fixed envelope overhead"
    )

    with pytest.raises(ValueError):
        bundles.DecodePart("A" * (4 * ((65536 + 2) // 3) + 1), 65536)


@pytest.mark.parametrize("mode", ["existing", "inside", "missing-opt-in", "corrupt-source"])
def test_ExportRefusalsPublishNoSelectedOutputAndPreserveSourceTruth(tmp_path, mode):
    """Explicit opt-in, new external destinations and intact selected evidence are mandatory."""

    root, imported = Acquired(tmp_path)
    destination = root / "bundle.json" if mode == "inside" else tmp_path / "bundle.json"
    arguments = ExportArguments(root, imported, destination)

    if mode == "existing":
        destination.write_bytes(b"existing output")

    elif mode == "missing-opt-in":
        arguments.remove("--include-originals")

    elif mode == "corrupt-source":
        store = LocalEvidenceStore(root / "evidence")
        original = store.Get(imported["raw_id"])
        (root / "evidence" / original.reference.locator).write_bytes(b"corrupt")

    before = Files(root)
    status, refused = Run(arguments)
    assert status == (4 if mode == "corrupt-source" else 2) and not refused[
        "output_published"
    ], "Rejected export must not acknowledge a publication"
    assert destination.read_bytes() == b"existing output" if mode == "existing" else (
        not destination.exists()
    ), "Refused export overwrote an existing target or published partial data"
    assert Files(root) == before, "Refused transfer modified its selected source workspace"


@pytest.mark.parametrize("after", [False, True], ids=("before-link", "after-complete-link"))
def test_InterruptedPublicationNeverLeavesAPartialSelectedFile(tmp_path, monkeypatch, after):
    """An interrupt preserves either absence or the complete privately staged original bytes."""

    root, imported = Acquired(tmp_path)
    expected = bundles.ExportIocBundle(root, imported["snapshot_id"], imported["receipt_id"])
    destination = tmp_path / "bundle.json"
    original = reports.os.link

    def Link(source, target):
        """Interrupt immediately before or after the actual atomic publication boundary."""

        if after:
            original(source, target)

        raise KeyboardInterrupt

    monkeypatch.setattr(reports.os, "link", Link)
    before = Files(root)
    status, refused = Run(ExportArguments(root, imported, destination))
    assert status == 130 and refused["output_published"] is after, (
        "Interrupted publication must report its actual complete-link acknowledgement"
    )
    assert destination.read_bytes() == expected if after else not destination.exists(), (
        "Interrupted export left a partial target or lost a complete published bundle"
    )

    if after:
        verified = bundles.VerifyIocBundle(destination.read_bytes(), refused["receipt_id"],
                                            refused["bundle_sha256"])
        assert verified.raw_evidence_id == imported["raw_id"], (
            "A complete post-link failure must retain independently usable original transfer pins"
        )

    assert Files(root) == before and not list(tmp_path.glob(".1337-report-*.pending")), (
        "Interrupted export modified its source or left a private staging file"
    )


def test_ConcurrentDestinationCreatorIsPreservedWithoutPublicationClaim(tmp_path, monkeypatch):
    """A competing selected target never gets overwritten or mistaken for the staged bundle."""

    root, imported = Acquired(tmp_path)
    destination = tmp_path / "bundle.json"
    original = bundles.PublishReport

    def Publish(path, payload):
        """Introduce the competing target after initial path selection, before atomic linking."""

        path.write_bytes(b"foreign output")
        original(path, payload)

    monkeypatch.setattr(bundles, "PublishReport", Publish)
    before = Files(root)
    status, refused = Run(ExportArguments(root, imported, destination))
    assert status == 4 and refused["output_published"] is False and destination.read_bytes() == (
        b"foreign output"
    ), "A racing destination was overwritten or reported as this command's publication"
    assert Files(root) == before, "A destination conflict changed retained source bytes"


def test_ChangedOriginalBeforePublicationRefusesTheStagedBundle(tmp_path, monkeypatch):
    """Final revalidation refuses publication after observed original corruption."""

    root, imported = Acquired(tmp_path)
    destination = tmp_path / "bundle.json"
    original = bundles.ExportIocBundle
    calls = []

    def Export(*arguments):
        """Corrupt one selected raw blob only after the initial bundle has been constructed."""

        calls.append(True)

        if len(calls) == 2:
            store = LocalEvidenceStore(root / "evidence")
            record = store.Get(imported["raw_id"])
            (root / "evidence" / record.reference.locator).write_bytes(b"changed source")

        return original(*arguments)

    monkeypatch.setattr(bundles, "ExportIocBundle", Export)
    status, refused = Run(ExportArguments(root, imported, destination))
    assert status == 4 and refused["output_published"] is False and not destination.exists(), (
        "A stale staged bundle was published after its original owning source changed"
    )


def test_IndependentlyRetainedReceiptRejectsAValidDifferentAcquisition(tmp_path):
    """A complete self-consistent foreign chain cannot substitute its own original receipt pin."""

    root, imported = Acquired(tmp_path)
    source = tmp_path / "owned candidate.tsv"
    arguments = ImportArguments(root, source)
    arguments[arguments.index("--license-name") + 1] = "other-declaration"
    status, alternative = Run(arguments)
    assert status == 0, "The alternative valid acquisition must exist for this anchor oracle"
    payload = bundles.ExportIocBundle(root, alternative["snapshot_id"], alternative["receipt_id"])

    with pytest.raises(ValueError):
        bundles.VerifyIocBundle(payload, imported["receipt_id"],
                                hashlib.sha256(payload).hexdigest())


def test_RecipientVerificationExposesSafeTransferPinsAndNeverWrites(tmp_path):
    """Exercise the actual dispatcher and readable recipient outcome over a real selected bundle."""

    root, imported = Acquired(tmp_path)
    destination = tmp_path / "bundle.json"
    status, exported = Run(ExportArguments(root, imported, destination))
    assert status == 0 and exported["output_published"], "The original transfer must publish fully"
    before = Files(root)
    arguments = BundleVerifyArguments(destination, exported)
    status, verified = Run(arguments)
    assert status == 0 and verified["candidate_count"] == 5 and not verified[
        "output_published"
    ], "Recipient verification must reparse selected originals without publication"
    output = StringIO()
    assert RunIocCommands(arguments, output) == 0 and exported["bundle_sha256"] in (
        output.getvalue()
    ) and exported["receipt_id"] in output.getvalue(), "Human verification omitted independent pins"
    assert "EXAMPLE.Invalid." not in output.getvalue(), "Human verification disclosed source tokens"
    arguments[-1] = "invalid-secret-pin"
    output = StringIO()
    assert RunIocCommands(arguments, output) == 2 and "invalid-secret-pin" not in (
        output.getvalue()
    ), "Invalid transfer pins must fail with generic text before selected-file reads"
    assert Files(root) == before, "Recipient verification changed original source state"
