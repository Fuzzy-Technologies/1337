# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Keep derived CVSS 2 base values separate from unchanged attributed source bytes."""

from __future__ import annotations

import hashlib
import json

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.intel_references import ReferenceSource, SourceOrigin
from fuzzy1337.intelligence_cvss2 import ParseCveCvss2Statements
from fuzzy1337.intelligence_cvss2_base import CveCvss2BaseCalculations


def test_CalculationsRetainOriginalSourceOnceWithoutReplacingAssertedScores():
    """Actual parsing and calculation preserve all source custody and provider coordinates."""

    metric = {"cvssV2_0": {
        "version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:N/I:N/A:C", "baseScore": 0.1,
        "temporalScore": 1.2, "environmentalScore": 3.4,
    }, "format": "synthetic-legacy", "scenarios": [{"lang": "en", "value": "Fixture"}]}
    other_metric = {"cvssV2_0": {
        "version": "2.0", "vectorString": "AV:L/AC:L/Au:N/C:C/I:C/A:C", "baseScore": 9.9,
    }}
    raw = json.dumps({
        "dataType": "CVE_RECORD", "dataVersion": "5.2", "cveMetadata": {
            "cveId": "CVE-1900-9999", "state": "PUBLISHED", "dateUpdated": "2026-10-28T10:00:00Z",
        }, "containers": {
            "cna": {"providerMetadata": {"orgId": "synthetic-cna", "shortName": "Fixture CNA"},
                    "metrics": [{"other": {"type": "synthetic"}}, metric]},
            "adp": [{"providerMetadata": {"orgId": "synthetic-without-v2"}},
                    {"providerMetadata": {"orgId": "synthetic-adp"}, "metrics": [other_metric]}],
        },
    }).encode()
    digest = hashlib.sha256(raw).hexdigest()
    source = ReferenceSource(
        SourceOrigin.SYNTHETIC, "1337 synthetic fixture", "https://example.invalid/source",
        digest, "Apache-2.0 (synthetic fixture only)", "https://example.invalid/LICENSE",
        "2026-10-28T12:00:00Z", "synthetic-importer", "1",
    )
    evidence = EvidenceReference("intelligence-source", f"blobs/sha256/{digest}", digest,
                                 "application/json", len(raw))
    statements = ParseCveCvss2Statements(raw, "synthetic-1", source, evidence)
    original_output = statements.ToDict()
    original_snapshot = statements.snapshot.Serialize()
    original_reference = statements.snapshot.Reference()
    calculated = CveCvss2BaseCalculations(statements)
    output = calculated.ToDict()

    assert calculated.statements is statements, "Calculation replaced the original source profile"
    assert output == {"statements": original_output, "calculations": [
        {"assessment_index": 0, "algorithm": "cvss2-base-2.10", "base_score_tenths": 78},
        {"assessment_index": 1, "algorithm": "cvss2-base-2.10", "base_score_tenths": 72},
    ]}, "Derived scores were mixed with source assertions or ordered source positions"
    assert [(item.role, item.index, item.metric_index) for item in statements.assessments] == [
        ("cna", 0, 1), ("adp", 1, 0),
    ], "Calculation changed source provider or metric coordinates"
    assert statements.snapshot.Serialize() == original_snapshot, "Original snapshot bytes changed"
    assert statements.snapshot.Reference() == original_reference, "Source reference changed"
    assert statements.snapshot.records[0].data["unsupported_metrics"] == ("cvssV2_0", "other"), (
        "The base calculation changed original schema-one unsupported metric semantics"
    )
    output["statements"]["assessments"][0]["metric"].clear()
    output["calculations"][0]["base_score_tenths"] = 1

    assert statements.ToDict() == original_output, "Detached result mutation changed source data"
    assert calculated.ToDict()["calculations"][0]["base_score_tenths"] == 78, (
        "Detached result mutation changed a derived score"
    )
