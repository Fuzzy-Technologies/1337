# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure image selection/summary bounds and actual-manifest evidence read quotas."""

from __future__ import annotations

import asyncio
from copy import copy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import (
    EvidenceIntegrityError,
    EvidenceProvenance,
    LocalEvidenceStore,
)
from fuzzy1337.image_evidence import ImageEvidenceStore
from fuzzy1337.image_workflow import ImageReportOutcome, ImageScanSelection, RunSyntheticImageScan


@pytest.mark.parametrize("value", [Path("relative.tar"), "absolute-path-text", None])
def test_SelectionRequiresTypedExplicitAbsolutePaths(tmp_path, value):
    """No constructor discovers an archive/scanner path or follows caller-relative context."""

    with pytest.raises(ValueError, match="explicit consent"):
        ImageScanSelection(value, tmp_path, tmp_path, tmp_path,
            ArtifactReadConsent("owner:test", "read:explicit"))


@pytest.mark.parametrize("configuration", [
    {"timeout_seconds": True}, {"timeout_seconds": 0}, {"timeout_seconds": 61},
    {"timeout_seconds": 1.5}, {"timeout_seconds": "1"}, {"approve_safe_image": 1},
    {"report_format": "json"}, {"report_output": Path("report.json")},
])
def test_RunConfigurationDeniesUnsupportedInputsBeforeAnyWorkspaceRead(tmp_path, configuration):
    """Caller coercion cannot weaken deadlines, explicit opt-in or paired report selection."""

    selection = ImageScanSelection(tmp_path, tmp_path, tmp_path, tmp_path,
        ArtifactReadConsent("owner:test", "read:explicit"))

    with pytest.raises(ValueError, match="configuration"):
        asyncio.run(RunSyntheticImageScan(tmp_path, "scope", "owner:test", selection,
            **configuration))


@pytest.mark.parametrize("role,media,bound", [
    ("provider-version", "application/json", 16 * 1024),
    ("provider-version-stderr", "text/plain", 16 * 1024),
    ("artifact-version-receipt", "application/json", 1024 * 1024),
    ("artifact-scan-receipt", "application/json", 1024 * 1024),
])
def test_ActualOversizedManifestIsRefusedBeforeOwnersEagerBlobRead(tmp_path, monkeypatch,
                                                                  role, media, bound):
    """A copied wrapper cannot hide a different actual acquisition's role size from Get's Read."""

    now = datetime.now(UTC).isoformat()
    source = EvidenceProvenance("owned-images", "scope:owned", "synthetic.trivy", "1",
        "0.75.0-synthetic", now, now)
    (tmp_path / "evidence").mkdir()
    owner = LocalEvidenceStore(tmp_path / "evidence")
    actual = owner.Put(b"x" * (bound + 1), role, media, source)
    small = owner.Put(b"{}", role, media, source)
    forged = copy(small)
    object.__setattr__(forged, "evidence_id", actual.evidence_id)
    original = LocalEvidenceStore.Read

    def NoOversizedRead(self, reference):
        """Record an eager oversized allocation as a test failure, before invoking the owner."""

        assert reference.size_bytes <= bound, (
            "Actual oversized manifest reached eager blob allocation"
        )

        return original(self, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", NoOversizedRead)

    with pytest.raises(EvidenceIntegrityError, match="role bound"):
        ImageEvidenceStore(owner.root).Get(forged.evidence_id)


def test_ActualWrongRoleOrMediaFailsBeforeOwnerRead(tmp_path):
    """The six-role reader never admits selected-material roles or relabelled stream media."""

    now = datetime.now(UTC).isoformat()
    source = EvidenceProvenance("owned-images", "scope:owned", "synthetic.trivy", "1",
        "0.75.0-synthetic", now, now)
    (tmp_path / "evidence").mkdir()
    store = LocalEvidenceStore(tmp_path / "evidence")
    record = store.Put(b"{}", "stdout", "application/json", source)

    for reference in (replace(record.reference, role="artifact-input-manifest"),
                      replace(record.reference, media_type="text/plain")):
        with pytest.raises(EvidenceIntegrityError):
            ImageEvidenceStore(store.root).Read(reference)


def test_ReportOutcomeKeepsPublicationTruthSeparateFromFailure():
    """A failed post-link publication still describes the complete output already published."""

    outcome = ImageReportOutcome("failed", "json", output_published=True, failure="publication")
    assert outcome.output_published and outcome.status == "failed", (
        "Export failure cannot erase confirmed complete output publication"
    )
