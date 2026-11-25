# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed detached candidate handoff after deletion of the original workspace and source."""

import base64
import hashlib
import json
import shutil

import pytest

from fuzzy1337.ioc_bundle import JsonBytes
from tests.e2e.test_ioc_cli import Console
from tests.ioc_cli_helpers import (
    RAW,
    BundleVerifyArguments,
    ExportArguments,
    Files,
    ImportArguments,
    InspectArguments,
    Owned,
)


def test_InstalledConsoleExportsVerifiedDetachedCandidatesAfterWorkspaceDeletion(tmp_path):
    """Read the accepted DTO through the installed console using only the transferred file."""

    root, source = Owned(tmp_path)
    status, imported = Console(ImportArguments(root, source))
    assert status == 0, "Acquire the original IOC chain through the installed console"
    status, inspected = Console([*InspectArguments(root, imported), "--export-candidates"])
    assert status == 0, "Obtain the already supported workspace-bound candidate DTO for comparison"
    destination = tmp_path / "received original bundle.json"
    status, transferred = Console(ExportArguments(root, imported, destination))
    assert status == 0, "Publish the selected original transfer through the installed console"
    shutil.rmtree(root)
    source.unlink()
    before = Files(tmp_path)
    arguments = BundleVerifyArguments(destination, transferred)
    status, summary = Console(arguments)
    assert status == 0 and "candidate_export" not in summary, (
        "The default installed verifier must retain its original safe summary"
    )
    status, result = Console([*arguments, "--export-candidates"])
    assert status == 0 and result["candidate_export"] == inspected["candidate_export"], (
        "Detached export must preserve the unchanged DTO from the original workspace inspection"
    )
    candidates = result["candidate_export"]["candidates"]
    assert len(candidates) == 5 and candidates[2]["raw_token"] == "EXAMPLE.Invalid.", (
        "Keep original source order and spellings, including separate normalized duplicates"
    )
    assert candidates[-1]["observed_at"] == "2099-01-01T12:00:00+05:30", (
        "Preserve the declared source timestamp instead of introducing a verification clock"
    )
    assert candidates[-1]["observation_timezone"] == "+05:30", "Preserve the original source offset"
    assert candidates[0]["observed_at"] is None, "Do not invent an absent source observation time"

    for candidate in candidates:
        start = candidate["byte_offset"]
        end = start + candidate["byte_length"]
        assert RAW[start:end].decode("ascii") == candidate["raw_token"], (
            "Detached candidate coordinates must still retrieve the exact original token bytes"
        )

    summaryOnly = dict(result)
    del summaryOnly["candidate_export"]
    assert summaryOnly == summary, "The explicit option must not rewrite the existing outcome DTO"
    assert Console([*arguments, "--export-candidates"]) == (status, result), (
        "Repeated source-free export must preserve the exact original candidate and outcome data"
    )
    assert Files(tmp_path) == before, "Detached export must write no workspace or artifact"


@pytest.mark.parametrize("fault", ["transfer-pin", "receipt-pin", "derived-payload"])
def test_InstalledConsoleRefusesCorruptDetachedExportBeforeCandidateOutput(tmp_path, fault):
    """Refuse altered pins or final-role bytes before printing candidates."""

    root, source = Owned(tmp_path)
    status, imported = Console(ImportArguments(root, source))
    assert status == 0, "Acquire actual original evidence for the installed refusal probe"
    destination = tmp_path / "received.json"
    status, transferred = Console(ExportArguments(root, imported, destination))
    assert status == 0, "Publish the original bundle before introducing the selected fault"
    selected = dict(transferred)

    if fault == "transfer-pin":
        selected["bundle_sha256"] = "0" * 64

    elif fault == "receipt-pin":
        selected["receipt_id"] = "sha256:" + "0" * 64

    else:
        document = json.loads(destination.read_bytes())
        payload = base64.b64decode(document["records"][2]["payload_base64"])
        document["records"][2]["payload_base64"] = base64.b64encode(
            bytes([payload[0] ^ 1]) + payload[1:]).decode()
        changed = JsonBytes(document)
        destination.write_bytes(changed)
        selected["bundle_sha256"] = hashlib.sha256(changed).hexdigest()

    shutil.rmtree(root)
    source.unlink()
    before = Files(tmp_path)
    arguments = [*BundleVerifyArguments(destination, selected), "--export-candidates"]
    status, refused = Console(arguments)
    assert status == 4 and refused["failure"] == "integrity", (
        "Installed detached disclosure must not accept a changed transfer, receipt or snapshot"
    )
    assert "candidate_export" not in refused, "Failed verification must emit no partial candidates"
    assert "EXAMPLE.Invalid." not in json.dumps(refused), "Failure output must not leak tokens"
    assert refused["core_mutation"] == "none" and refused["evidence_commit"] == "not-attempted", (
        "Refused presentation must not write evidence or reinterpret the Core model"
    )
    assert Files(tmp_path) == before, "Installed refusal must preserve the selected received bytes"
