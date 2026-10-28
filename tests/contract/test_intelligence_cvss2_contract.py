# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Legacy CVSS inspection remains additive to source-bound schema-one snapshot transport."""

from __future__ import annotations

import hashlib
import json

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.intel_references import ReferenceSource, SourceOrigin
from fuzzy1337.intelligence import IntelligenceFeed, ParseIntelligenceSnapshot
from fuzzy1337.intelligence_cvss2 import ParseCveCvss2Statements


def test_OriginalSnapshotBytesAndUnsupportedMetricContractRemainUnchanged():
    """The reader adds source statements while keeping exact historical snapshot serialization."""

    provider = {"orgId": "synthetic-cna", "shortName": "Synthetic CNA"}
    metric = {"cvssV2_0": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                           "baseScore": 0.1}}
    raw = json.dumps({
        "dataType": "CVE_RECORD", "dataVersion": "5.2", "cveMetadata": {
            "cveId": "CVE-1900-9999", "state": "PUBLISHED", "dateUpdated": "2026-10-28T10:00:00Z",
        }, "containers": {"cna": {"providerMetadata": provider, "metrics": [metric]}},
    }).encode()
    digest = hashlib.sha256(raw).hexdigest()
    source = ReferenceSource(
        SourceOrigin.SYNTHETIC, "1337 synthetic fixture", "https://example.invalid/source",
        digest, "Apache-2.0 (synthetic fixture only)", "https://example.invalid/LICENSE",
        "2026-10-28T12:00:00Z", "synthetic-importer", "1",
    )
    evidence = EvidenceReference("intelligence-source", f"blobs/sha256/{digest}", digest,
                                 "application/json", len(raw))
    original = ParseIntelligenceSnapshot(raw, IntelligenceFeed.CVE, "synthetic-1", source, evidence)
    before = original.Serialize()
    inspected = ParseCveCvss2Statements(raw, "synthetic-1", source, evidence)

    assert inspected.snapshot.Serialize() == before, (
        "The new reader changed original snapshot bytes"
    )
    assert original.records[0].data["unsupported_metrics"] == ("cvssV2_0",), (
        "Original schema-one source replay gained a newly normalized CVSS 2 assessment"
    )
    assert inspected.ToDict() == {
        "profile_version": 1, "format_version": "5.2", "snapshot": original.Content(),
        "snapshot_reference": original.Reference(), "assessments": [
            {"role": "cna", "index": 0, "metric_index": 0,
             "providerMetadata": provider, "metric": metric},
        ],
    }, "Inspection altered asserted scores, provider attribution or exact source field names"
    inspected.ToDict()["assessments"].clear()

    assert len(inspected.assessments) == 1, "Detached transport mutation changed frozen statements"
    assert original.Serialize() == before, "The additive reader mutated its original snapshot"
