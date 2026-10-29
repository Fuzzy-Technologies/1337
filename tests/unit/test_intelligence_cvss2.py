# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded legacy assessments retain exact source assertions without score computation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace

import pytest

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.intel_references import ReferenceSource, SourceOrigin
from fuzzy1337.intelligence_cvss2 import (
    CveCvss2Assessment,
    ParseCveCvss2Statements,
)

VECTOR = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
FULL_VECTOR = VECTOR + "/E:POC/RL:TF/RC:UR/CDP:LM/TD:M/CR:H/IR:L/AR:ND"


def Document(assessment=None):
    """Supply original fictional CVE bytes with a legacy metric and optional explicit fields."""

    if assessment is None:
        assessment = {"version": "2.0", "vectorString": VECTOR, "baseScore": 0.1}

    return {"dataType": "CVE_RECORD", "dataVersion": "5.2", "cveMetadata": {
        "cveId": "CVE-1900-9999", "state": "PUBLISHED", "dateUpdated": "2026-10-28T10:00:00Z",
    }, "containers": {"cna": {"providerMetadata": {"orgId": "synthetic-cna"},
                               "metrics": [{"cvssV2_0": assessment}]}}}


def Inputs(document=None, raw=None):
    """Bind fixture bytes to explicit synthetic attribution and exact evidence custody."""

    if raw is None:
        raw = json.dumps(Document() if document is None else document).encode()

    digest = hashlib.sha256(raw).hexdigest()
    source = ReferenceSource(
        SourceOrigin.SYNTHETIC, "1337 synthetic fixture", "https://example.invalid/source",
        digest, "Apache-2.0 (synthetic fixture only)", "https://example.invalid/LICENSE",
        "2026-10-28T12:00:00Z", "synthetic-importer", "1",
    )

    return raw, "synthetic-1", source, EvidenceReference(
        "intelligence-source", f"blobs/sha256/{digest}", digest, "application/json", len(raw),
    )


def test_SourceProvidersMetricPositionsScenariosAndAssertedScoresStaySeparate():
    """Full source wrappers and ordered coordinates preserve attribution and optional context."""

    document = Document({"version": "2.0", "vectorString": FULL_VECTOR, "baseScore": 0.1,
                         "temporalScore": 9, "environmentalScore": 10.0,
                         "accessVector": "NETWORK", "exploitability": "PROOF_OF_CONCEPT",
                         "remediationLevel": "TEMPORARY_FIX", "reportConfidence": "UNCORROBORATED",
                         "collateralDamagePotential": "LOW_MEDIUM", "targetDistribution": "MEDIUM",
                         "confidentialityRequirement": "HIGH", "integrityRequirement": "LOW",
                         "availabilityRequirement": "NOT_DEFINED"})
    metric = document["containers"]["cna"]["metrics"][0]
    metric.update({"format": "synthetic-legacy", "scenarios": [
        {"lang": "en", "value": "Synthetic deployment"},
    ]})
    document["containers"]["cna"]["metrics"].insert(0, {"other": {"type": "synthetic"}})
    document["containers"]["adp"] = [
        {"providerMetadata": {"orgId": "synthetic-without-legacy"}},
        {"providerMetadata": {"orgId": "synthetic-adp", "shortName": "Synthetic ADP"},
         "metrics": [Document()["containers"]["cna"]["metrics"][0], metric]},
    ]
    result = ParseCveCvss2Statements(*Inputs(document))
    output = result.ToDict()["assessments"]

    assert [(item["role"], item["index"], item["metric_index"]) for item in output] == [
        ("cna", 0, 1), ("adp", 1, 0), ("adp", 1, 1),
    ], "The original source provider or metric-array positions changed"
    assert output[0]["metric"] == metric, "The source wrapper or asserted scores changed"
    assert output[1]["providerMetadata"] == document["containers"]["adp"][1]["providerMetadata"], (
        "Complete ADP attribution was reduced or merged with the CNA"
    )
    assert "scenarios" not in output[1]["metric"], "An absent source scenario was filled in"
    assert "temporalScore" not in output[1]["metric"]["cvssV2_0"], "An absent score was computed"
    assert result.snapshot.records[0].data["unsupported_metrics"] == ("cvssV2_0", "other"), (
        "Legacy schema-one unsupported metric behavior changed"
    )


@pytest.mark.parametrize("version", ["5.2", "5.2.0"])
def test_SourceOrderingAndExactOptionalMetadataRemainUnnormalized(version):
    """Import-schema vector ordering and optional field omission remain visible source facts."""

    vector = "A:C/I:N/C:P/Au:M/AC:H/AV:A/AR:ND/E:ND"
    assessment = {"version": "2.0", "vectorString": vector, "baseScore": 7,
                  "authentication": "MULTIPLE", "accessComplexity": "HIGH",
                  "confidentialityImpact": "PARTIAL", "integrityImpact": "NONE",
                  "availabilityImpact": "COMPLETE", "targetDistribution": "HIGH"}
    document = Document(assessment)
    document["dataVersion"] = version
    result = ParseCveCvss2Statements(*Inputs(document))

    assert result.format_version == version, "The declared format label was normalized"
    assert result.ToDict()["assessments"][0]["metric"]["cvssV2_0"] == assessment, (
        "Source vector order or independent optional field presence was changed"
    )


def test_FrozenAssessmentContextAndDetachedOutputCannotMutateOriginalStatements():
    """No mutable caller/provider/scenario mapping can alter retained source assessments."""

    document = Document()
    document["containers"]["cna"]["metrics"][0]["scenarios"] = [
        {"lang": "en", "value": "Synthetic"},
    ]
    result = ParseCveCvss2Statements(*Inputs(document))
    assessment = result.assessments[0]

    with pytest.raises(FrozenInstanceError):
        result.format_version = "changed"

    with pytest.raises(TypeError):
        assessment.metric["cvssV2_0"]["baseScore"] = 9

    with pytest.raises(TypeError):
        assessment.metric["scenarios"][0]["value"] = "changed"

    detached = result.ToDict()
    detached["assessments"][0]["providerMetadata"]["orgId"] = "changed"
    detached["assessments"][0]["metric"]["scenarios"].clear()

    assert result.assessments[0].provider["orgId"] == "synthetic-cna", (
        "Provider data stayed mutable"
    )
    assert result.assessments[0].metric["scenarios"], "Detached output retained a mutable alias"


@pytest.mark.parametrize("vector", [
    "AV:N/AC:L/Au:N/C:P/I:P", VECTOR + "/AV:N", VECTOR + "/E:ND/E:H",
    "CVSS:2.0/" + VECTOR, "(" + VECTOR + ")", VECTOR + "/", VECTOR + "/X:N",
    VECTOR.replace("Au:N", "AU:N"), VECTOR.replace("Au:N", "Au:X"),
    VECTOR + "/E:P", VECTOR + "/RL:X", VECTOR + "/RC:X", VECTOR + "/CDP:X",
    VECTOR + "/TD:X", VECTOR + "/CR:X", VECTOR + "/IR:X", VECTOR + "/AR:X",
    VECTOR + "/E", VECTOR + "/E:H:ND", "",
])
def test_MalformedIncompleteDuplicateOrUnsupportedVectorsFailExplicitly(vector):
    """Consumed legacy vectors refuse ambiguous grammar instead of disappearing from inspection."""

    with pytest.raises(ValueError):
        ParseCveCvss2Statements(*Inputs(Document({
            "version": "2.0", "vectorString": vector, "baseScore": 5,
        })))


@pytest.mark.parametrize("change", [
    {}, {"version": "2.0"}, {"version": "2.0", "vectorString": VECTOR},
    {"version": 2.0, "vectorString": VECTOR, "baseScore": 5},
    {"version": "3.0", "vectorString": VECTOR, "baseScore": 5},
    {"version": "2.0", "vectorString": [], "baseScore": 5},
    {"version": "2.0", "vectorString": VECTOR, "baseScore": 5, "baseSeverity": "HIGH"},
    {"version": "2.0", "vectorString": VECTOR, "baseScore": 5, "authentication": "SINGLE"},
    {"version": "2.0", "vectorString": VECTOR, "baseScore": 5, "exploitability": "UNKNOWN"},
    {"version": "2.0", "vectorString": VECTOR, "baseScore": 5, "accessVector": []},
    None, [], "invalid",
])
def test_RequiredVersionVectorScoreAndExplicitFieldAgreementCannotBeBypassed(change):
    """Malformed objects fail, including unknown fields and vector/field conflicts."""

    document = Document()
    document["containers"]["cna"]["metrics"][0]["cvssV2_0"] = change

    with pytest.raises(ValueError):
        ParseCveCvss2Statements(*Inputs(document))


@pytest.mark.parametrize("field", ["baseScore", "temporalScore", "environmentalScore"])
@pytest.mark.parametrize("score", [True, False, "5", None, -0.1, 10.1])
def test_AllScoreFieldsRejectBooleansStringsMissingOrOutOfRangeNumbers(field, score):
    """Python boolean subclassing and optional source-score presence never permit coercion."""

    assessment = {"version": "2.0", "vectorString": VECTOR, "baseScore": 5, field: score}

    with pytest.raises(ValueError):
        ParseCveCvss2Statements(*Inputs(Document(assessment)))


@pytest.mark.parametrize("score", [float("nan"), float("inf"), float("-inf")])
def test_NonfiniteSourceOrDirectScoresCannotEnterTheRetainedAssessment(score):
    """Strict source JSON and direct construction both refuse nonfinite numeric assertions."""

    document = Document({"version": "2.0", "vectorString": VECTOR, "baseScore": score})

    with pytest.raises(ValueError):
        ParseCveCvss2Statements(*Inputs(document))

    with pytest.raises(ValueError):
        CveCvss2Assessment("cna", 0, 0, {"orgId": "synthetic"},
                           document["containers"]["cna"]["metrics"][0])


@pytest.mark.parametrize("state", ["no_metrics", "other_only", "rejected"])
def test_NoLegacyMetricsAndRejectedRecordsSupplyNoPositiveAssessments(state):
    """No matching source entry is an empty inspection result, without an invented score."""

    document = Document()

    if state == "no_metrics":
        document["containers"]["cna"].pop("metrics")

    elif state == "other_only":
        document["containers"]["cna"]["metrics"] = [{"other": {"type": "synthetic"}}]

    else:
        document["cveMetadata"]["state"] = "REJECTED"

    result = ParseCveCvss2Statements(*Inputs(document))

    assert result.assessments == (), "No-v2/rejected source manufactured a positive assessment"


@pytest.mark.parametrize("mutation", ["digest", "length", "duplicate_keys", "unknown_format"])
def test_SourceBindingDuplicateKeysAndUnknownSourceVersionsRefuse(mutation):
    """The additive parser preserves original byte custody and the source-format boundary."""

    inputs = list(Inputs())

    if mutation == "digest":
        inputs[2] = replace(inputs[2], artifact_sha256="f" * 64)

    elif mutation == "length":
        inputs[3] = replace(inputs[3], size_bytes=inputs[3].size_bytes + 1)

    elif mutation == "duplicate_keys":
        inputs = list(Inputs(raw=inputs[0].replace(b'"baseScore": 0.1',
                                                  b'"baseScore":0.1,"baseScore":0.1')))

    else:
        document = Document()
        document["dataVersion"] = "5.1.1"
        inputs = list(Inputs(document))

    with pytest.raises(ValueError):
        ParseCveCvss2Statements(*inputs)


@pytest.mark.parametrize("bound", ["containers", "metrics", "total", "provider_bytes",
                                  "metric_bytes", "vector_bytes", "depth", "source_bytes"])
def test_CountDepthAndByteBoundsApplyThroughTheOriginalParser(monkeypatch, bound):
    """Bounded synthetic mutations reach each refusal without a live or oversized source corpus."""

    document = Document()

    if bound == "containers":
        monkeypatch.setattr("fuzzy1337.intelligence_cvss2.MAX_CONTAINERS", 1)
        document["containers"]["adp"] = [{"providerMetadata": {"orgId": "synthetic-adp"}}]

    elif bound == "metrics":
        monkeypatch.setattr("fuzzy1337.intelligence_cvss2.MAX_METRICS", 1)
        document["containers"]["cna"]["metrics"] *= 2

    elif bound == "total":
        monkeypatch.setattr("fuzzy1337.intelligence_cvss2.MAX_ASSESSMENTS", 1)
        document["containers"]["adp"] = [document["containers"]["cna"]]

    elif bound == "provider_bytes":
        document["containers"]["cna"]["providerMetadata"]["metadata"] = "a" * (64 * 1024)

    elif bound == "metric_bytes":
        document["containers"]["cna"]["metrics"][0]["context"] = "a" * (64 * 1024)

    elif bound == "vector_bytes":
        document["containers"]["cna"]["metrics"][0]["cvssV2_0"].update({
            "vectorString": VECTOR + "a" * 2048,
        })

    elif bound == "depth":
        nested = "bounded"

        for _ in range(35):
            nested = [nested]

        document["containers"]["cna"]["providerMetadata"]["nested"] = nested

    else:
        monkeypatch.setattr("fuzzy1337.intelligence.MAX_SOURCE_BYTES", 8)

    with pytest.raises(ValueError):
        ParseCveCvss2Statements(*Inputs(document))


def test_DirectCoordinatesContextsAndSnapshotInvariantsStayTypedBoundedAndFrozen():
    """Direct values cannot bypass location/order/state bounds or retain mutable caller context."""

    result = ParseCveCvss2Statements(*Inputs())
    original = result.assessments[0]

    for changes in ({"role": "unknown"}, {"index": True}, {"index": -1}, {"index": 1},
                    {"role": "adp", "index": 64}, {"metric_index": True}, {"metric_index": -1},
                    {"metric_index": 256}, {"provider": []}, {"provider": {}},
                    {"metric": []}, {"metric": {}}, {"metric": {"cvssV2_0": []}}):
        with pytest.raises(ValueError):
            replace(original, **changes)

    adp = replace(original, role="adp", index=0)

    for changes in ({"snapshot": None}, {"format_version": []}, {"format_version": "5.1"},
                    {"assessments": {}}, {"assessments": ["invalid"]},
                    {"assessments": (original, original)}, {"assessments": (adp, original)}):
        with pytest.raises(ValueError):
            replace(result, **changes)

    document = Document()
    document["cveMetadata"]["state"] = "REJECTED"
    rejected = ParseCveCvss2Statements(*Inputs(document))

    with pytest.raises(ValueError):
        replace(rejected, assessments=(original,))

    provider = {"orgId": "synthetic-direct"}
    metric = Document()["containers"]["cna"]["metrics"][0]
    direct = CveCvss2Assessment("cna", 0, 0, provider, metric)
    provider["orgId"] = "changed"
    metric["cvssV2_0"].clear()

    assert direct.provider["orgId"] == "synthetic-direct", "Direct provider data stayed mutable"
    assert direct.metric["cvssV2_0"]["baseScore"] == 0.1, "Direct metric data stayed mutable"
    assert replace(result, assessments=[direct]).assessments == (direct,), (
        "Direct assessment sequences were not frozen"
    )


def test_DirectConstructionRejectsRecursiveOverdeepOrOversizedSourceContexts(monkeypatch):
    """Direct construction shares the original parser's JSON bounds and total-assessment bound."""

    result = ParseCveCvss2Statements(*Inputs())
    original = result.assessments[0]
    recursive = {"orgId": "synthetic"}
    recursive["nested"] = recursive

    with pytest.raises(ValueError):
        replace(original, provider=recursive)

    nested = "bounded"

    for _ in range(35):
        nested = [nested]

    with pytest.raises(ValueError):
        replace(original, provider={"orgId": "synthetic", "nested": nested})

    monkeypatch.setattr("fuzzy1337.intelligence_cvss2.MAX_ASSESSMENTS", 0)

    with pytest.raises(ValueError):
        replace(result, assessments=(original,))
