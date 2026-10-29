# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Strict portable intelligence snapshots retain raw evidence binding and reject corruption."""

from __future__ import annotations

import hashlib
import json

import pytest

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.intel_references import ReferenceSource, SourceOrigin
from fuzzy1337.intelligence import (
    IntelligenceFeed,
    IntelligenceSnapshot,
    ParseIntelligenceSnapshot,
)
from fuzzy1337.model import CanonicalModelJson


def Snapshot(feed=IntelligenceFeed.EPSS):
    """Construct an explicitly synthetic portable daily score or KEV source."""

    raw = (
        b'#model_version:synthetic-1,score_date:2026-10-12T00:00:00Z\n'
        b'cve,epss,percentile\nCVE-1900-9999,0.2,0.9\n'
    )

    if feed is IntelligenceFeed.KEV:
        raw = json.dumps({
            "catalogVersion": "synthetic-1", "dateReleased": "2026-10-12T10:00:00Z", "count": 1,
            "vulnerabilities": [{
                "cveID": "CVE-1900-9999", "dateAdded": "2026-10-12", "dueDate": "2026-10-31",
                "vendorProject": "Synthetic", "product": "Synthetic", "vulnerabilityName": "Test",
                "requiredAction": "Review synthetic evidence",
                "knownRansomwareCampaignUse": "Unknown",
            }],
        }).encode()

    digest = hashlib.sha256(raw).hexdigest()

    return ParseIntelligenceSnapshot(
        raw, feed, "synthetic-1", ReferenceSource(
            SourceOrigin.SYNTHETIC, "1337 synthetic fixture", "https://example.invalid/source",
            digest, "Apache-2.0 (synthetic fixture only)", "https://example.invalid/LICENSE",
            "2026-10-12T12:00:00Z", "synthetic-importer", "1",
        ), EvidenceReference("intelligence-source", f"blobs/sha256/{digest}", digest,
                             "text/csv", len(raw)),
    )


@pytest.mark.parametrize("boundary", ["snapshot", "record", "data", "source", "evidence"])
@pytest.mark.parametrize("mutation", ["extra", "missing"])
def test_ExactNestedSchemaNeverDropsAttributionOrInventsRequiredFields(boundary, mutation):
    """No normalized boundary may silently ignore new semantics or fabricate missing provenance."""

    document = json.loads(Snapshot().Serialize())
    selected = {
        "snapshot": document, "record": document["records"][0],
        "data": document["records"][0]["data"], "source": document["source"],
        "evidence": document["evidence"],
    }[boundary]

    if mutation == "extra":
        selected["unsupported_field"] = "ignored?"

    else:
        selected.pop(next(iter(selected)))

    with pytest.raises(ValueError):
        IntelligenceSnapshot.Deserialize(json.dumps(document).encode())


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", "1"), ("schema_version", 2),
    ("reference", "intel-snapshot:" + "f" * 64), ("feed", "unknown"), ("records", {}),
    ("catalog_version", "wrong-model"),
])
def test_TransportRejectsVersionCoercionReferencesAndCatalogSubstitution(field, value):
    """A changed interpretation cannot retain its original content or external model revision."""

    document = json.loads(Snapshot().Serialize())
    document[field] = value

    with pytest.raises(ValueError):
        IntelligenceSnapshot.Deserialize(json.dumps(document).encode())


@pytest.mark.parametrize("boundary,field,value", [
    ("record", "identifier", "CVE-1900-9998"), ("data", "probability", 0.99),
    ("source", "artifact_sha256", "f" * 64), ("source", "license_name", "Invented rights"),
    ("evidence", "sha256", "f" * 64), ("data", "probability", "0.2"),
])
def test_ChangedSourceContentLicenseAndScoreCannotRetainPriorSnapshot(boundary, field, value):
    """Corrupt transport cannot inherit trust by leaving an outer content reference unchanged."""

    document = json.loads(Snapshot().Serialize())
    selected = {"record": document["records"][0], "data": document["records"][0]["data"],
                "source": document["source"], "evidence": document["evidence"]}[boundary]
    selected[field] = value

    with pytest.raises(ValueError):
        IntelligenceSnapshot.Deserialize(json.dumps(document).encode())


def test_EquivalentWhitespaceAndUtf8TransportDoNotChangeSourceOrRecordMeaning():
    """Canonical serialization is stable even when accepted interchange whitespace differs."""

    snapshot = Snapshot()
    payload = json.dumps(json.loads(snapshot.Serialize()), indent=2).encode()

    assert IntelligenceSnapshot.Deserialize(payload).Serialize() == snapshot.Serialize(), (
        "Interchange whitespace changed canonical source/license/version facts"
    )


@pytest.mark.parametrize("feed,changes,message", [
    (IntelligenceFeed.EPSS, {"model_version": "different-model"}, "model version"),
    (IntelligenceFeed.KEV, {"date_added": "2027-01-01", "due_date": "2027-01-02"}, "addition"),
])
def test_ContradictoryNormalizedJoinsFailEvenWithARecomputedSnapshotReference(
    feed, changes, message,
):
    """A public content hash cannot legitimize conflicting model versions or source chronology."""

    document = json.loads(Snapshot(feed).Serialize())
    document["records"][0]["data"].update(changes)
    content = {key: value for key, value in document.items() if key != "reference"}
    document["reference"] = "intel-snapshot:" + hashlib.sha256(CanonicalModelJson({
        "domain": "fuzzy1337.intelligence.snapshot.v1", "content": content,
    })).hexdigest()

    with pytest.raises(ValueError, match=message):
        IntelligenceSnapshot.Deserialize(CanonicalModelJson(document))
