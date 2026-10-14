# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Additive product format outcomes and exact accepted SDK serialization contracts."""

from __future__ import annotations

import hashlib

import pytest

from fuzzy1337.report_commands import OpenReportInput
from fuzzy1337.report_formats import RenderHtml, SerializeJson, SerializeJunit, SerializeSarif
from tests.contract.report_export_fixture import (
    Context,
    DenyExecution,
    Files,
    OutcomeValidator,
    Run,
)


@pytest.mark.parametrize("format_name,renderer", [
    ("json", SerializeJson), ("sarif", SerializeSarif),
    ("html", RenderHtml), ("junit", SerializeJunit),
], ids=["json", "sarif", "html", "junit"])
def test_ExplicitFormatPublishesExactAcceptedSdkBytesAndVersionOneOutcome(
    tmp_path, monkeypatch, format_name, renderer
):
    """Every product format consumes the same owner-verified saved snapshot and pure exporter."""

    root, _ = Context(tmp_path)
    before = Files(root)
    original = OpenReportInput(root)
    expected = renderer(original.report)
    DenyExecution(monkeypatch)
    destination = tmp_path / ("report." + format_name)
    status, outcome = Run(root, destination, format_name=format_name)
    assert status == 0 and outcome["status"] == "completed" and outcome["format"] == format_name, (
        "Explicit supported format must retain original successful product outcome semantics"
    )
    assert outcome["schema_version"] == 1 and outcome["scan_completeness"] == "not-assessed", (
        "Additive presentation formats cannot change the outcome version or assess completeness"
    )
    assert destination.read_bytes() == expected, (
        "Product output must be byte-identical to the accepted unchanged SDK renderer"
    )
    assert outcome["snapshot_sha256"] == original.report.SnapshotDigest() and (
        outcome["report_sha256"] == hashlib.sha256(expected).hexdigest()
    ), "Machine outcome must identify the actual owning snapshot and complete published bytes"
    assert Files(root) == before, "All report formats must leave every owning source file unchanged"


@pytest.mark.parametrize("format_name", ["pdf", "xml", "clean", "HTML", "", None])
def test_OutcomeFormatExpansionDoesNotAdmitOtherFormatsOrInventedSuccess(format_name):
    """The experimental enum grows only by the exact two implemented canonical names."""

    completed = {"schema_version": 1, "command": "report.export", "status": "completed",
        "format": format_name, "model_revision": 0, "snapshot_sha256": "a" * 64,
        "report_sha256": "b" * 64, "size_bytes": 1, "output_published": True,
        "scan_completeness": "not-assessed", "verified_retained_acquisitions": 0,
        "checked_model_evidence_references": 0, "failure": None}
    assert not OutcomeValidator().is_valid(completed), (
        "Unsupported or absent formats cannot be a completed version-one export outcome"
    )


@pytest.mark.parametrize("format_name", ["html", "junit", "json", "sarif", None])
def test_AdditiveFailedOutcomeFormatsPreserveExistingVersionAndStrictFields(format_name):
    """Failure projections admit known selections and the original unselected setup outcome."""

    document = {"schema_version": 1, "command": "report.export", "status": "failed",
        "format": format_name, "model_revision": None, "snapshot_sha256": None,
        "report_sha256": None, "size_bytes": None, "output_published": False,
        "scan_completeness": "not-assessed", "verified_retained_acquisitions": None,
        "checked_model_evidence_references": None, "failure": "configuration"}
    assert OutcomeValidator().is_valid(document), (
        "Known selections retain schema-v1 failure support"
    )
    document["format"] = "arbitrary"
    assert not OutcomeValidator().is_valid(document), "Unknown format names must remain unsupported"
    document["format"] = format_name
    document["authorization"] = "granted"
    assert not OutcomeValidator().is_valid(document), "Format growth cannot admit authority fields"
