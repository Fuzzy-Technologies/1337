# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Synthetic upstream intelligence formats, exact attribution, bounds, and adversarial parsing."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace

import pytest

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.intel_references import ReferenceSource, SourceOrigin
from fuzzy1337.intelligence import (
    BoundedJson,
    CvssAssessment,
    IntelligenceDate,
    IntelligenceFeed,
    IntelligenceIdentifier,
    IntelligenceNumber,
    IntelligenceSnapshot,
    IntelligenceText,
    IntelligenceTime,
    ParseCve,
    ParseCwe,
    ParseEpss,
    ParseIntelligenceSnapshot,
    ParseKev,
)

CVE = "CVE-1900-9999"
VECTOR3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
VECTOR4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
VERSIONS = {
    IntelligenceFeed.CVE: "synthetic-list-revision-1", IntelligenceFeed.CWE: "synthetic-1",
    IntelligenceFeed.KEV: "synthetic-1", IntelligenceFeed.EPSS: "synthetic-model-1",
}


def CveDocument():
    """Return fictional CVE content following the supported upstream format subset."""

    return {
        "dataType": "CVE_RECORD", "dataVersion": "5.1",
        "cveMetadata": {"cveId": CVE, "state": "PUBLISHED", "dateUpdated": "2026-10-12T10:00:00Z"},
        "containers": {"cna": {
            "providerMetadata": {"orgId": "synthetic-cna"},
            "descriptions": [{"lang": "en", "value": "Synthetic\n vulnerability description"}],
            "problemTypes": [{"descriptions": [{"cweId": "CWE-89"}]}],
            "metrics": [{"cvssV3_1": {
                "version": "3.1", "vectorString": VECTOR3, "baseScore": 9.8,
            }}],
        }},
    }


def KevDocument():
    """Return fictional KEV membership with explicit unknown ransomware-use assertion."""

    return {
        "catalogVersion": "synthetic-1", "dateReleased": "2026-10-12T10:00:00Z", "count": 1,
        "vulnerabilities": [{
            "cveID": CVE, "vendorProject": "Synthetic vendor", "product": "Synthetic product",
            "vulnerabilityName": "Synthetic entry", "dateAdded": "2026-10-12",
            "dueDate": "2026-10-31", "requiredAction": "Review this synthetic fixture",
            "knownRansomwareCampaignUse": "Unknown",
        }],
    }


def Payload(feed):
    """Provide small reproducible upstream-shaped bytes without bundling an official corpus."""

    if feed is IntelligenceFeed.CVE:
        return json.dumps(CveDocument()).encode()

    if feed is IntelligenceFeed.KEV:
        return json.dumps(KevDocument()).encode()

    if feed is IntelligenceFeed.CWE:
        return (
            '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Version="synthetic-1" '
            'Date="2026-10-12"><Weaknesses><Weakness ID="89" Name="Synthetic weakness" '
            'Status="Stable"><Description>Preserved only in raw bytes</Description></Weakness>'
            '</Weaknesses></Weakness_Catalog>'
        ).encode()

    return (
        "#model_version:synthetic-model-1,score_date:2026-10-12T00:00:00Z\n"
        f"cve,epss,percentile\n{CVE},0.125,0.8\n"
    ).encode()


def Snapshot(feed, payload=None):
    """Bind a pure parser to explicit synthetic attribution and the exact artifact digest."""

    raw = Payload(feed) if payload is None else payload
    digest = hashlib.sha256(raw).hexdigest()
    source = ReferenceSource(
        SourceOrigin.SYNTHETIC, "1337 synthetic fixture", "https://example.invalid/source",
        digest, "Apache-2.0 (synthetic fixture only)", "https://example.invalid/LICENSE",
        "2026-10-12T12:00:00Z", "synthetic-importer", "1",
    )
    evidence = EvidenceReference(
        "intelligence-source", f"blobs/sha256/{digest}", digest,
        "application/octet-stream", len(raw),
    )

    return ParseIntelligenceSnapshot(raw, feed, VERSIONS[feed], source, evidence)


@pytest.mark.parametrize("feed", list(IntelligenceFeed))
def test_UpstreamAssertionsPreservePortableVersionLicenseTimesAndDeterminism(feed):
    """Every supported source retains exact source context without creating evidence or approval."""

    snapshot = Snapshot(feed)
    restored = IntelligenceSnapshot.Deserialize(snapshot.Serialize())

    assert restored == snapshot, "Source metadata or normalized assertions changed across transport"
    assert restored.Serialize() == snapshot.Serialize(), "Canonical snapshot bytes drifted"
    assert snapshot.source.artifact_sha256 == snapshot.evidence.sha256, "Raw digest binding drifted"
    assert "synthetic fixture only" in snapshot.source.license_name, "Synthetic rights were lost"
    assert snapshot.records[0].catalog_version == VERSIONS[feed], "Catalog version was replaced"
    assert snapshot.records[0].Reference().startswith("intel-record:"), "Record namespace drifted"
    assert snapshot.records[0].CanonicalUrl().startswith("https://"), "Canonical locator drifted"
    document = snapshot.Content()
    document["records"].clear()

    assert snapshot.records, "Detached output mutation changed immutable source assertions"

    with pytest.raises(FrozenInstanceError):
        snapshot.catalog_version = "changed"

    assert not hasattr(snapshot, "review"), "A parser must not manufacture an approval attestation"


def test_CveAssessorRejectedStateUnsupportedMetricsAndProseRemainHonest():
    """Unknown metrics stay explicitly unsupported; rejected records do not retain assessments."""

    document = CveDocument()
    document["containers"]["adp"] = [{
        "providerMetadata": {"orgId": "synthetic-adp"},
        "problemTypes": [{"descriptions": [{"description": "unclassified"}]}],
        "metrics": [{"cvssV4_0": {"version": "4.0", "vectorString": VECTOR4, "baseScore": 9.3}},
                    {"cvssV2_0": {"version": "2.0"}, "other": {"type": "synthetic"}}],
    }]
    record = Snapshot(IntelligenceFeed.CVE, json.dumps(document).encode()).records[0]

    assert record.data["description"] == "Synthetic vulnerability description", (
        "Normalized prose must remain deterministic while raw bytes preserve paragraph structure"
    )
    assert set(item["assessor"] for item in record.data["cvss"]) == {
        "synthetic-cna", "synthetic-adp",
    }, "Assessments from separate publishers lost attribution"
    assert record.data["unsupported_metrics"] == ("cvssV2_0", "other"), (
        "An unsupported metric was converted or silently discarded"
    )
    document["cveMetadata"]["state"] = "REJECTED"
    document["containers"]["cna"]["rejectedReasons"] = [
        {"lang": "en", "value": "Synthetic rejection"},
    ]
    rejected = Snapshot(IntelligenceFeed.CVE, json.dumps(document).encode()).records[0]

    assert rejected.data["state"] == "REJECTED" and rejected.data["cvss"] == (), (
        "Catalog rejection must not retain a positive vulnerability assessment"
    )
    document["containers"]["cna"].pop("rejectedReasons")
    assert Snapshot(IntelligenceFeed.CVE, json.dumps(document).encode()).records[0].data[
        "description"
    ] is None, "A missing source description must stay missing"


@pytest.mark.parametrize("timestamp,expected", [
    ("2026-10-12T10:00:00", "2026-10-12T10:00:00.000000+00:00"),
    ("2026-10-12T10:00:00.125", "2026-10-12T10:00:00.125000+00:00"),
    ("2026-10-12T12:00:00+02:00", "2026-10-12T10:00:00.000000+00:00"),
])
def test_CveUpdateTimestampUsesThePublishersExplicitGmtDefault(timestamp, expected):
    """CVE timestamps without a zone retain the documented GMT meaning rather than local time."""

    document = CveDocument()
    document["cveMetadata"]["dateUpdated"] = timestamp
    snapshot = Snapshot(IntelligenceFeed.CVE, json.dumps(document).encode())

    assert snapshot.records[0].effective_at == expected, "CVE publisher timestamp meaning drifted"
    assert IntelligenceSnapshot.Deserialize(snapshot.Serialize()) == snapshot, (
        "The normalized publisher timestamp changed across portable interchange"
    )


@pytest.mark.parametrize("timestamp", [
    "2026-10-12T10", "2026-10-12T10:00", "2026-10-12 10:00:00",
    "2026-10-12T24:00:00", "2026-10-12T10:00:60", "2026-02-30T10:00:00",
    "2026-10-12T10:00:00Ztrailing", "2026-10-12T10:00:00+02:99", None,
])
def test_CveGmtDefaultDoesNotGuessMissingOrMalformedCalendarTimes(timestamp):
    """Only the publisher-defined optional zone is normalized; missing or malformed dates fail."""

    document = CveDocument()
    document["cveMetadata"]["dateUpdated"] = timestamp

    with pytest.raises(ValueError):
        Snapshot(IntelligenceFeed.CVE, json.dumps(document).encode())


def test_EpssNormalizedRecordRequiresOneConsistentModelVersion():
    """Public construction and record decoding cannot carry contradictory score-model identities."""

    record = Snapshot(IntelligenceFeed.EPSS).records[0]
    changed = {**record.data, "model_version": "different-model"}

    with pytest.raises(ValueError, match="model version"):
        replace(record, data=changed)

    with pytest.raises(ValueError, match="model version"):
        replace(record, catalog_version="different-model")

    with pytest.raises(ValueError, match="model version"):
        record.FromDict({**record.ToDict(), "data": changed})


def test_KevNormalizedRecordCannotAddAnEntryAfterItsCatalogRelease():
    """Public construction and decoding enforce the parser's catalog/addition chronology."""

    record = Snapshot(IntelligenceFeed.KEV).records[0]
    changed = {**record.data, "date_added": "2027-01-01", "due_date": "2027-01-02"}

    with pytest.raises(ValueError, match="addition"):
        replace(record, data=changed)

    with pytest.raises(ValueError, match="addition"):
        record.FromDict({**record.ToDict(), "data": changed})


def test_CvePublisherZoneDefaultCannotLeakIntoOtherSourceOrCallerTimes():
    """Other feed dates and generic interpretation timestamps still require explicit offsets."""

    with pytest.raises(ValueError):
        IntelligenceTime("2026-10-12T10:00:00")

    for feed in (IntelligenceFeed.KEV, IntelligenceFeed.EPSS):
        raw = Payload(feed).replace(b"2026-10-12T10:00:00Z", b"2026-10-12T10:00:00")
        raw = raw.replace(b"2026-10-12T00:00:00Z", b"2026-10-12T00:00:00")

        with pytest.raises(ValueError):
            Snapshot(feed, raw)


@pytest.mark.parametrize("value", ["cve-1900-9999", "CVE-1900-12", "CWE-089", "CWE-0", "CWE-89 ",
                                  "CWE-89\u202e", True, None, "CVE-1900-" + "9" * 20])
def test_IdentifierMatchingRejectsAmbiguousCaseWhitespaceAndNonIdentifiers(value):
    """Exact identifier matching cannot acquire meaning through case folding or coercion."""

    with pytest.raises(ValueError):
        IntelligenceIdentifier(value)


@pytest.mark.parametrize("value", ["2026-10", "2026-W42-1", "2026-02-30", None, "2026-10-12Z"])
def test_CalendarDatesRejectReducedWeekAndInvalidDates(value):
    """Source dates retain their explicit calendar meaning without permissive ISO coercion."""

    with pytest.raises(ValueError):
        IntelligenceDate(value)


@pytest.mark.parametrize("value", [
    "2026-10-12", "2026-W42-1T12:00:00Z", "2026-10-12T12:00:00",
    "0001-01-01T00:00:00+01:00", "2026-10-12T10Z", "2026-10-12T10.9Z",
    "2026-10-12T103001Z", "2026-10-12T10:30:01+02", "2026-10-12T10:30:01+02:00:01",
    "2026-10-12T10:30:01+02:99",
])
def test_TimestampsRequireAnOffsetAndRepresentableUtcCalendarTime(value):
    """Naive or UTC-overflow dates cannot become accepted historical provenance."""

    with pytest.raises(ValueError):
        IntelligenceTime(value)


@pytest.mark.parametrize("value", [True, "0.5", -1, 1.1, float("nan"), float("inf"), 10**10000],
                         ids=["boolean", "numeric-string", "negative", "above-bound", "nan",
                              "infinity", "huge-integer"])
def test_NumericValidationRejectsCoercionNonfiniteAndIntegerOverflow(value):
    """Source scores fail through validation instead of numeric overflow or truth-value coercion."""

    with pytest.raises(ValueError):
        IntelligenceNumber(value, 1)


@pytest.mark.parametrize("payload", [
    b'{"a":1,"a":2}', b'{"nested":{"x":1,"x":2}}', b'{"a":NaN}', b'{"a":Infinity}',
    b'{"a":1e999}', b'{"a":' + b'9' * 33 + b'}', b'\xff', b'[' * 2000,
    b'[' * 34 + b'0' + b']' * 34, "not bytes", b"not JSON",
], ids=["duplicate", "nested-duplicate", "nan", "infinity", "exponent-overflow",
        "oversized-integer", "encoding", "recursion", "depth", "nonbytes", "syntax"])
def test_JsonBoundaryRejectsAmbiguousUnboundedAndNonstandardDocuments(payload):
    """Adversarial tokens cannot evade bounds in unused or deeply nested source fields."""

    with pytest.raises(ValueError):
        BoundedJson(payload)

    assert BoundedJson(b'{"finite":0.5,"integer":1}') == {"finite": 0.5, "integer": 1}, (
        "Supported finite JSON numbers must remain available to parsers"
    )


@pytest.mark.parametrize("version,vector", [
    ("3.1", VECTOR3), ("3.0", VECTOR3.replace("3.1", "3.0")), ("4.0", VECTOR4),
    ("3.1", VECTOR3 + "/E:X/MA:N"), ("4.0", VECTOR4 + "/MSI:S/U:Red"),
    ("3.1", "CVSS:3.1/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N/S:U"),
])
def test_CvssGrammarPreservesSourceScoresAndSupportsVersionSpecificOrdering(version, vector):
    """Valid vectors remain source assertions; 3.x permits permutations and 4.0 uses fixed order."""

    parsed = CvssAssessment(
        {"version": version, "vectorString": vector, "baseScore": 7.0}, "fixture",
    )

    assert parsed["base_score"] == 7.0 and parsed["vector"] == vector, (
        "CVSS parsing recomputed a score, reordered a vector, or changed its asserted version"
    )


@pytest.mark.parametrize("version,vector,score", [
    ("2.0", "AV:N", 1), ("3.1", VECTOR4, 1), ("3.1", VECTOR3 + "/AV:N", 1),
    ("3.1", VECTOR3.replace("AV:N", "AV:NN"), 1), ("3.1", VECTOR3 + "/XX:N", 1),
    ("3.1", VECTOR3 + "/E", 1), ("3.1", VECTOR3.replace("/C:H", ""), 1),
    ("4.0", VECTOR4.replace("AV:N/AC:L", "AC:L/AV:N"), 1),
    ("4.0", VECTOR4 + "/U:Never", 1), ("3.1", VECTOR3, True),
    ("3.1", VECTOR3, 11),
])
def test_CvssMalformedOrUnsupportedAssessmentsFailWithoutConversion(version, vector, score):
    """Invalid metrics, duplicate/base omissions, version disagreement, and score coercion fail."""

    with pytest.raises(ValueError):
        CvssAssessment({"version": version, "vectorString": vector, "baseScore": score}, "fixture")


@pytest.mark.parametrize("change", [
    {"dataType": "OTHER"}, {"dataVersion": "6.0"}, {"containers": []},
    {"cveMetadata": {"cveId": CVE, "state": "RESERVED", "dateUpdated": "2026-10-12T10:00:00Z"}},
])
def test_CveRejectsUnrecognizedFormatsAndStates(change):
    """Version or source-state ambiguity cannot be reinterpreted as a vulnerability record."""

    with pytest.raises(ValueError):
        Snapshot(IntelligenceFeed.CVE, json.dumps({**CveDocument(), **change}).encode())


@pytest.mark.parametrize("version", [[], {}, True, False, None, 5, 5.1, ""])
def test_CveRejectsUntypedFormatRevisionsThroughItsDocumentedValidationError(version):
    """Unsupported JSON format types fail validation before they can enter hashed membership."""

    document = CveDocument()
    document["dataVersion"] = version

    with pytest.raises(ValueError):
        Snapshot(IntelligenceFeed.CVE, json.dumps(document).encode())


@pytest.mark.parametrize("version", ["5.0", "5.0.0", "5.1", "5.1.0", "5.1.1", "5.2", "5.2.0"])
def test_CveRecognizedFormatRevisionsRetainTheSameExplicitIdentifierAndAssessor(version):
    """Supported historical and current format labels preserve the consumed upstream boundaries."""

    document = CveDocument()
    document["dataVersion"] = version
    snapshot = Snapshot(IntelligenceFeed.CVE, json.dumps(document).encode())

    assert snapshot.records[0].identifier == CVE, "A supported schema revision changed the CVE ID"


def test_CveRejectsMissingAssessorUnboundedProseAndCvssFieldVersionDisagreement():
    """Malformed consumed fields fail while unknown provider fields remain in raw evidence."""

    for field, value in (("providerMetadata", {}), ("descriptions", [{"lang": "en", "value": 1}]),
                         ("descriptions", [{"lang": "en", "value": "a" * 8193}]),
                         ("metrics", [{"cvssV3_1": {"version": "4.0", "vectorString": VECTOR4,
                                                   "baseScore": 9.3}}])):
        document = CveDocument()
        document["containers"]["cna"][field] = value

        with pytest.raises(ValueError):
            Snapshot(IntelligenceFeed.CVE, json.dumps(document).encode())


@pytest.mark.parametrize("payload", [
    b'<!DOCTYPE x [<!ENTITY y "expanded">]><x/>', b'<!ENTITY x "expanded"><x/>', b'<x>',
    b'<x/>', b'\xff', b'<x>' * 33 + b'</x>' * 33,
])
def test_CweRejectsEntityDeclarationsUnknownNamespaceAndInvalidEncoding(payload):
    """Catalog parsing cannot load external entities, trust another namespace, or expand depth."""

    with pytest.raises(ValueError):
        ParseCwe(payload, "synthetic-1")


@pytest.mark.parametrize("change", [
    {"catalogVersion": "different"}, {"count": True}, {"count": 0}, {"vulnerabilities": {}},
    {"dateReleased": "2026-10-12"},
])
def test_KevRejectsVersionCountAndDateAmbiguity(change):
    """A partial or mislabeled artifact cannot acquire complete supplied-snapshot semantics."""

    with pytest.raises(ValueError):
        Snapshot(IntelligenceFeed.KEV, json.dumps({**KevDocument(), **change}).encode())


@pytest.mark.parametrize("field,value", [
    ("dueDate", "2026-10-11"), ("dateAdded", "2026-10-13"),
    ("knownRansomwareCampaignUse", "No"), ("vendorProject", ""), ("cveID", "CWE-89"),
])
def test_KevMembershipKeepsUnknownDistinctFromNegativeAndRejectsImpossibleDates(field, value):
    """CISA uncertainty is retained rather than treated as proof of no ransomware exploitation."""

    document = KevDocument()
    document["vulnerabilities"][0][field] = value

    with pytest.raises(ValueError):
        Snapshot(IntelligenceFeed.KEV, json.dumps(document).encode())


@pytest.mark.parametrize("payload", [
    b'cve,epss,percentile\n',
    b'#model_version:x,score_date:2026-10-12T00:00:00Z\ncve,epss,percentile\n',
    b'#model_version:synthetic-model-1,model_version:synthetic-model-1\ncve,epss,percentile\n',
    b'#malformed\ncve,epss,percentile\n', b'\xff',
])
def test_EpssRejectsAbsentDuplicateAndMismatchedModelMetadata(payload):
    """The EPSS API version cannot substitute for a daily score model revision and score date."""

    with pytest.raises(ValueError):
        ParseEpss(payload, "synthetic-model-1")


@pytest.mark.parametrize("mutation", [
    "bad-columns", "missing-column", "nan", "infinity", "out-of-range", "huge-number",
    "duplicate-id", "quoted-unclosed",
])
def test_EpssRejectsNonfiniteMalformedOversizedAndDuplicateRows(mutation):
    """Daily score rows stay finite, versioned, complete by column, and uniquely identified."""

    raw = Payload(IntelligenceFeed.EPSS)
    replacements = {
        "bad-columns": raw.replace(b'cve,epss,percentile', b'cve,percentile,epss'),
        "missing-column": raw.replace(b'0.125,0.8', b'0.125'),
        "nan": raw.replace(b'0.125', b'NaN'), "infinity": raw.replace(b'0.125', b'Infinity'),
        "out-of-range": raw.replace(b'0.125', b'1.1'),
        "huge-number": raw.replace(b'0.125', b'0.' + b'1' * 33),
        "duplicate-id": raw + f'{CVE},0.1,0.2\n'.encode(),
        "quoted-unclosed": raw + b'"unclosed',
    }

    with pytest.raises(ValueError):
        Snapshot(IntelligenceFeed.EPSS, replacements[mutation])


def test_RuntimeRecordAndSnapshotRejectTypedBoundaryAndSourceBindingViolations():
    """Direct construction cannot bypass strict transport's attribution and identity invariants."""

    snapshot = Snapshot(IntelligenceFeed.CVE)

    for changes in ({"feed": "cve"}, {"source": {}}, {"evidence": {}}, {"records": "records"},
                    {"records": ({},)}, {"records": (snapshot.records[0],) * 2},
                    {"catalog_version": "different"},
                    {"source": replace(snapshot.source, artifact_sha256="f" * 64)},
                    {"source": replace(snapshot.source, acquired_at="2026-10-11T12:00:00Z")}):
        with pytest.raises(ValueError):
            replace(snapshot, **changes)

    for changes in ({"feed": "cve"}, {"identifier": "CWE-89"}, {"data": {}},
                    {"effective_at": "2026-10-12"}):
        with pytest.raises(ValueError):
            replace(snapshot.records[0], **changes)


def test_ParserRejectsInputBoundsTypedValuesAndMismatchedBytesBeforeParsing(monkeypatch):
    """A source label and digest alone cannot replace verification of the actual supplied bytes."""

    snapshot = Snapshot(IntelligenceFeed.CVE)
    args = [Payload(IntelligenceFeed.CVE), IntelligenceFeed.CVE, VERSIONS[IntelligenceFeed.CVE],
            snapshot.source, snapshot.evidence]

    for index, value in ((0, "bytes"), (1, "cve"), (3, {}), (4, {}), (0, b'{}')):
        changed = args.copy()
        changed[index] = value

        with pytest.raises(ValueError):
            ParseIntelligenceSnapshot(*changed)

    monkeypatch.setattr("fuzzy1337.intelligence.MAX_SOURCE_BYTES", 1)

    for parser in (BoundedJson,):
        with pytest.raises(ValueError):
            parser(b'{}')

    for parser in (ParseCwe, ParseEpss):
        with pytest.raises(ValueError):
            parser(b'{}', "synthetic-1")

    with pytest.raises(ValueError):
        snapshot.Serialize()

    with pytest.raises(ValueError):
        ParseIntelligenceSnapshot(*args)


def test_TextAndUnsupportedRuntimeAssertionFieldsFailClosed():
    """Printable text and typed format assertions remain strict outside the real parser path."""

    with pytest.raises(ValueError):
        IntelligenceText("hidden\u202e", "text")

    record = Snapshot(IntelligenceFeed.CVE).records[0]

    for changes in ({"state": "OTHER"}, {"cwe_ids": [CVE]}, {"cvss": [{}]},
                    {"unsupported_metrics": [True]}, {"description": " "},
                    {"state": "REJECTED"}):
        with pytest.raises(ValueError):
            replace(record, data={**record.data, **changes})

    with pytest.raises(ValueError):
        ParseCve(b'[]', "synthetic-1")

    with pytest.raises(ValueError):
        ParseKev(b'{}', "synthetic-1")


def test_CweStructuralDepthNodeCollectionAndRecordBoundsAreIndependent(monkeypatch):
    """A valid catalog prefix cannot conceal deep nesting or records moved into another section."""

    prefix = (b'<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Version="synthetic-1" '
              b'Date="2026-10-12">')
    weakness = b'<Weakness ID="89" Name="Synthetic weakness" Status="Stable"/>'

    for body in (b'<x>' * 33 + b'</x>' * 33, weakness,
                 b'<WrongSection>' + weakness + b'</WrongSection>'):
        with pytest.raises(ValueError):
            ParseCwe(prefix + body + b'</Weakness_Catalog>', "synthetic-1")

    monkeypatch.setattr("fuzzy1337.intelligence.MAX_RECORDS", 1)

    for body in (b'<x/>' * 16, b'<Weaknesses>' + weakness * 2 + b'</Weaknesses>'):
        with pytest.raises(ValueError):
            ParseCwe(prefix + body + b'</Weakness_Catalog>', "synthetic-1")

    with pytest.raises(ValueError):
        ParseEpss(Payload(IntelligenceFeed.EPSS) + f'{CVE},0.1,0.2\n'.encode(), "synthetic-model-1")
