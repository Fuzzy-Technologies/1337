# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""The additive CVE inspection profile preserves source declarations and legacy snapshots."""

from __future__ import annotations

import hashlib
import json

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.intel_references import ReferenceSource, SourceOrigin
from fuzzy1337.intelligence import IntelligenceFeed, ParseIntelligenceSnapshot
from fuzzy1337.intelligence_applicability import ParseCveAffectedStatements


def test_SourceInspectionRetainsLegacySnapshotBytesAndDetachedDeclarationShape():
    """The profile adds ordered source declarations without changing v1 snapshot serialization."""

    product = {"vendor": "Synthetic vendor", "product": "Synthetic product", "versions": [
        {"version": "9", "status": "unknown"}, {"version": "1", "status": "affected"},
    ]}
    provider = {"orgId": "synthetic-cna", "shortName": "Synthetic CNA"}
    raw = json.dumps({
        "dataType": "CVE_RECORD", "dataVersion": "5.2", "cveMetadata": {
            "cveId": "CVE-1900-9999", "state": "PUBLISHED",
            "dateUpdated": "2026-10-12T10:00:00Z",
        }, "containers": {"cna": {"providerMetadata": provider, "affected": [product]}},
    }).encode()
    digest = hashlib.sha256(raw).hexdigest()
    source = ReferenceSource(
        SourceOrigin.SYNTHETIC, "1337 synthetic fixture", "https://example.invalid/source",
        digest, "Apache-2.0 (synthetic fixture only)", "https://example.invalid/LICENSE",
        "2026-10-12T12:00:00Z", "synthetic-importer", "1",
    )
    evidence = EvidenceReference("intelligence-source", f"blobs/sha256/{digest}", digest,
                                 "application/json", len(raw))
    legacy = ParseIntelligenceSnapshot(raw, IntelligenceFeed.CVE, "synthetic-1", source, evidence)
    before = legacy.Serialize()
    inspected = ParseCveAffectedStatements(raw, "synthetic-1", source, evidence)

    assert inspected.snapshot.Serialize() == before, "The additive reader changed v1 snapshot bytes"
    assert inspected.ToDict() == {
        "profile_version": 1, "format_version": "5.2", "snapshot": legacy.Content(),
        "snapshot_reference": legacy.Reference(),
        "containers": [{"role": "cna", "index": 0, "providerMetadata": provider,
                        "affected": [product]}],
    }, "Source inspection lost attribution, version order, or exact declaration fields"
    detached = inspected.ToDict()
    detached["containers"].clear()

    assert len(inspected.containers) == 1, "Inspection output mutation changed frozen declarations"
    assert legacy.Serialize() == before, "Inspection mutated the original legacy snapshot"
