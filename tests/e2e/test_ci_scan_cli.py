# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual assembled CLI subprocess over explicitly owned closed configuration sources."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from xml.etree import ElementTree

import pytest
from configuration_helpers import LiveConfiguration

from fuzzy1337.model import LocalModelStore
from tests.ci_helpers import CiArguments


@pytest.mark.parametrize("case_id,mode,expected", [
    ("dockerfile.non-root-user", "complete", 0),
    ("dockerfile.root-user", "complete", 1),
    ("kubernetes.non-privileged-container", "missing-ack", 2),
    ("kubernetes.privileged-container", "missing-approval", 3),
])
def test_RegisteredCliSubprocessPreservesActualGateAndArtifactTaxonomy(
    tmp_path, case_id, mode, expected
):
    """Invoke the installed entry point with real worker execution and no browser/network."""

    root, selection, _ = LiveConfiguration(tmp_path, case_id)
    arguments = CiArguments(root, selection, tmp_path)

    if mode == "missing-ack":
        arguments.remove("--acknowledge-unassessed-completeness")

    elif mode == "missing-approval":
        arguments.remove("--approve-safe-configuration")

    result = subprocess.run([sys.executable, "-m", "fuzzy1337", "ci", *arguments, "--json"],
        cwd=tmp_path, check=False, capture_output=True, text=True, timeout=60)
    outcome = json.loads(result.stdout)
    assert result.returncode == expected == outcome["exit_code"] and not result.stderr, (
        "The actual assembled process must preserve the documented safe terminal taxonomy"
    )
    assert outcome["scope"] == "selected-profile-finding-predicate" and (
        outcome["scan_completeness"] == "not-assessed"
    ), "Actual machine output cannot turn predicate satisfaction into a global clean claim"

    if expected in {0, 1}:
        saved = LocalModelStore(root).Open()
        exported = json.loads((tmp_path / "ci.json").read_bytes())
        assert saved.revision == outcome["model_revision"] == 1 and exported["model"] == (
            saved.ToDict()
        ), "Actual subprocess must publish the exact durable saved snapshot"
        assert all(item["status"] == "completed" and item["output_published"] is True
                   for item in outcome["reports"].values()), (
            "Criterion violation and satisfaction both retain all real snapshot artifacts"
        )
        sarif = json.loads((tmp_path / "ci.sarif").read_bytes())
        junit = ElementTree.parse(tmp_path / "ci.xml").getroot()
        properties = {item.attrib["name"]: item.attrib["value"]
                      for item in junit.findall("properties/property")}
        pin = exported["snapshot_sha256"]
        assert pin == outcome["snapshot_sha256"] == properties["snapshot_sha256"] == (
            sarif["runs"][0]["properties"]["canonicalSnapshotSha256"]
        ), "Actual CLI artifacts must all bind the same complete saved model digest"

        for name, filename in (("json", "ci.json"), ("sarif", "ci.sarif"), ("junit", "ci.xml")):
            raw = (tmp_path / filename).read_bytes()
            assert outcome["reports"][name]["report_sha256"] == hashlib.sha256(raw).hexdigest(), (
                "Actual subprocess outcomes must identify the originally published artifact bytes"
            )

    else:
        assert LocalModelStore(root).Open().revision == 0 and not (tmp_path / "ci.json").exists(), (
            "Invalid configuration or authority refusal cannot fabricate a saved scan or artifact"
        )
