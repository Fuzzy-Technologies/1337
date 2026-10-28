# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded source-only CVE product inspection keeps ordering, uncertainty, and raw custody."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace

import pytest

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.intel_references import ReferenceSource, SourceOrigin
from fuzzy1337.intelligence import IntelligenceFeed, ParseIntelligenceSnapshot
from fuzzy1337.intelligence_applicability import (
    CveAffectedContainer,
    CveAffectedStatements,
    ParseCveAffectedStatements,
)


def Product():
    """Return a fictional range with deliberately unsorted changes and explicit unknown status."""

    return {"vendor": "Synthetic vendor", "product": "Synthetic product", "versions": [
        {"version": "1", "status": "affected", "versionType": "synthetic-order",
         "lessThan": "*", "changes": [{"at": "9", "status": "unknown"},
                                      {"at": "2", "status": "unaffected"}]},
        {"version": "0", "status": "unknown"},
    ]}


def Document():
    """Supply a small synthetic 5.2 record whose product metadata never describes a real target."""

    return {"dataType": "CVE_RECORD", "dataVersion": "5.2", "cveMetadata": {
        "cveId": "CVE-1900-9999", "state": "PUBLISHED", "dateUpdated": "2026-10-12T10:00:00Z",
    }, "containers": {"cna": {"providerMetadata": {"orgId": "synthetic-cna"},
                               "affected": [Product()]}}}


def Inputs(document=None, raw=None):
    """Bind fixture bytes to synthetic attribution and the exact immutable evidence reference."""

    if raw is None:
        raw = json.dumps(Document() if document is None else document).encode()

    digest = hashlib.sha256(raw).hexdigest()
    source = ReferenceSource(
        SourceOrigin.SYNTHETIC, "1337 synthetic fixture", "https://example.invalid/source",
        digest, "Apache-2.0 (synthetic fixture only)", "https://example.invalid/LICENSE",
        "2026-10-12T12:00:00Z", "synthetic-importer", "1",
    )

    return raw, "synthetic-1", source, EvidenceReference(
        "intelligence-source", f"blobs/sha256/{digest}", digest, "application/json", len(raw),
    )


def test_ProvidersProductsVersionsAndChangesRetainTheirOriginalOrderAndUncertainty():
    """Separate containers and default-only/unknown statements never collapse into a verdict."""

    document = Document()
    document["containers"]["adp"] = [
        {"providerMetadata": {"orgId": "synthetic-adp", "shortName": "Synthetic ADP",
                              "dateUpdated": "2026-10-11T09:00:00Z"},
         "affected": [Product(), {"collectionURL": "https://example.invalid/packages",
                                  "packageName": "synthetic-package", "defaultStatus": "unknown"}]},
        {"providerMetadata": {"orgId": "synthetic-adp-without-products"}},
    ]
    result = ParseCveAffectedStatements(*Inputs(document))
    inspected = result.ToDict()["containers"]

    assert [(item["role"], item["index"]) for item in inspected] == [
        ("cna", 0), ("adp", 0), ("adp", 1),
    ], "CNA/ADP source paths or array order changed"
    assert inspected[0]["affected"][0] == Product(), "Version or change declarations were altered"
    assert "defaultStatus" not in inspected[0]["affected"][0], "An omitted default was invented"
    assert inspected[1]["affected"][1]["defaultStatus"] == "unknown", "Unknown became absence"
    assert "affected" not in inspected[2], "An omitted ADP declaration became an empty array"
    assert inspected[1]["providerMetadata"] == document["containers"]["adp"][0][
        "providerMetadata"
    ], (
        "Original provider metadata was reduced or normalized"
    )
    assert not hasattr(result, "applicable"), "Inspection manufactured an applicability verdict"


def test_AllProductQualifiersAndRepeatedProductsRemainSeparatelyInspectable():
    """Complete affected declarations retain qualifiers and separate same-product source entries."""

    document = Document()
    product = Product()
    product.update({"packageURL": "pkg:generic/synthetic", "repo": "https://example.invalid/repo",
                    "cpes": ["cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*"],
                    "platforms": ["Synthetic OS"], "modules": ["Synthetic module"],
                    "programFiles": ["synthetic.py"], "programRoutines": [{"name": "Synthetic"}]})
    document["containers"]["cna"]["affected"] = [product, product]
    result = ParseCveAffectedStatements(*Inputs(document))

    assert result.ToDict()["containers"][0]["affected"] == [product, product], (
        "Source product entries or qualifiers were silently dropped, merged, or interpreted"
    )


def test_OptionalEmptyQualifierArraysRemainExplicitWhereThePinnedSchemaAllowsThem():
    """Permitted empty qualifiers stay distinct from omitted fields without adding defaults."""

    document = Document()
    product = {"vendor": "Synthetic", "product": "Synthetic", "defaultStatus": "unaffected",
               "cpes": [], "modules": [], "programFiles": [], "programRoutines": []}
    document["containers"]["cna"]["affected"] = [product]
    result = ParseCveAffectedStatements(*Inputs(document))

    assert result.ToDict()["containers"][0]["affected"] == [product], (
        "Allowed explicit empty qualifiers were omitted or filled with guessed source metadata"
    )


def test_FrozenResultAndDetachedOutputCannotMutateSourceDeclarations():
    """Every retained provider/product array is immutable while detached inspection is editable."""

    result = ParseCveAffectedStatements(*Inputs())
    product = result.containers[0].products[0]

    with pytest.raises(FrozenInstanceError):
        result.format_version = "changed"

    with pytest.raises(TypeError):
        product["defaultStatus"] = "unaffected"

    with pytest.raises(TypeError):
        product["versions"][0]["changes"][0]["status"] = "unaffected"

    detached = result.ToDict()
    detached["containers"][0]["affected"][0]["versions"].reverse()

    assert result.ToDict()["containers"][0]["affected"][0] == Product(), (
        "A detached output changed frozen source arrays"
    )


@pytest.mark.parametrize("version", ["5.2", "5.2.0"])
def test_PinnedSourceVersionsPreserveExplicitInclusiveAndExactVersionDeclarations(version):
    """The additive envelope accepts the two pinned labels without changing source spellings."""

    document = Document()
    document["dataVersion"] = version
    document["containers"]["cna"]["affected"][0]["versions"] = [
        {"version": "02.00", "versionType": "custom", "status": "affected",
         "lessThanOrEqual": "z-unknown-order"},
        {"version": "trunk", "versionType": "git", "status": "unaffected"},
    ]
    result = ParseCveAffectedStatements(*Inputs(document))

    assert result.format_version == version, "The explicitly declared schema label changed"
    assert result.ToDict()["containers"][0]["affected"] == document["containers"]["cna"][
        "affected"
    ], "Unknown version kinds or version spellings were compared, converted, or dropped"


@pytest.mark.parametrize("change", [
    {}, {"vendor": "Synthetic"}, {"vendor": "Synthetic", "product": "Synthetic"},
    {"vendor": "Synthetic", "product": "Synthetic", "defaultStatus": None},
    {"vendor": "Synthetic", "product": "Synthetic", "defaultStatus": True},
    {"vendor": "Synthetic", "product": "Synthetic", "defaultStatus": "AFFECTED"},
    {"vendor": "Synthetic", "product": "Synthetic", "versions": []},
    {**Product(), "unknownQualifier": "unsupported"},
    {**Product(), "platforms": []}, {**Product(), "cpes": ["duplicate", "duplicate"]},
    {**Product(), "programRoutines": [{"name": "Synthetic", "unknown": True}]},
    {**Product(), "programFiles": [False]},
])
def test_InvalidAmbiguousOrUnsupportedProductDeclarationsFailExplicitly(change):
    """Missing identity/status, duplicate qualifiers and unknown product semantics cannot pass."""

    document = Document()
    document["containers"]["cna"]["affected"] = [change]

    with pytest.raises(ValueError):
        ParseCveAffectedStatements(*Inputs(document))


@pytest.mark.parametrize("version", [
    {}, {"version": "1", "status": "invalid"},
    {"version": "1", "status": "affected", "lessThan": "2"},
    {"version": "1", "status": "affected", "versionType": "custom", "lessThan": "2",
     "lessThanOrEqual": "3"},
    {"version": "1", "status": "affected", "changes": [{"at": "2", "status": "unknown"}]},
    {"version": "1", "status": "affected", "versionType": "custom", "lessThan": "2",
     "changes": []},
    {"version": "1", "status": "affected", "versionType": "custom", "lessThan": "2",
     "changes": [{"at": "1", "status": "unknown"}, {"at": "1", "status": "unaffected"}]},
    {"version": "1", "status": "affected", "versionType": "custom", "lessThan": "2",
     "changes": [{"at": "1", "status": "unknown", "extra": True}]},
    {"version": "1", "status": "affected", "extra": True},
])
def test_InvalidVersionRangesAndAmbiguousChangePositionsFailWithoutGuessing(version):
    """A range needs declared semantics; conflicting bounds/positions receive no guessed meaning."""

    document = Document()
    document["containers"]["cna"]["affected"][0]["versions"] = [version]

    with pytest.raises(ValueError):
        ParseCveAffectedStatements(*Inputs(document))


@pytest.mark.parametrize("mutation", ["duplicate_keys", "duplicate_versions", "duplicate_changes",
                                     "missing_cna_affected", "null_adp_affected", "empty_affected",
                                     "unknown_format", "bad_digest", "bad_length"])
def test_SourceEnvelopeDuplicatesAndEvidenceDisagreementAreRejected(mutation):
    """The actual public parser refuses malformed source and custody before returning statements."""

    document = Document()

    if mutation == "duplicate_versions":
        document["containers"]["cna"]["affected"][0]["versions"] = [
            {"version": "1", "status": "affected"}, {"version": "1", "status": "affected"},
        ]

    elif mutation == "duplicate_changes":
        document["containers"]["cna"]["affected"][0]["versions"][0]["changes"] *= 2

    elif mutation == "missing_cna_affected":
        document["containers"]["cna"].pop("affected")

    elif mutation == "null_adp_affected":
        document["containers"]["adp"] = [{"providerMetadata": {"orgId": "synthetic-adp"},
                                           "affected": None}]

    elif mutation == "empty_affected":
        document["containers"]["cna"]["affected"] = []

    elif mutation == "unknown_format":
        document["dataVersion"] = "5.1.1"

    inputs = list(Inputs(document))

    if mutation == "duplicate_keys":
        inputs = list(Inputs(raw=inputs[0].replace(b'"dataVersion": "5.2"',
                                                  b'"dataVersion":"5.2","dataVersion":"5.2"')))

    elif mutation == "bad_digest":
        inputs[2] = replace(inputs[2], artifact_sha256="f" * 64)

    elif mutation == "bad_length":
        inputs[3] = replace(inputs[3], size_bytes=inputs[3].size_bytes + 1)

    with pytest.raises(ValueError):
        ParseCveAffectedStatements(*inputs)


def test_RejectedCveRetainsItsStateAndSuppliesNoPositiveProductDeclarations():
    """A rejected record cannot expose stale product statements as current positive assertions."""

    document = Document()
    document["cveMetadata"]["state"] = "REJECTED"
    result = ParseCveAffectedStatements(*Inputs(document))

    assert result.containers == (), "Rejected source produced a positive applicability statement"
    assert result.snapshot.records[0].data["state"] == "REJECTED", "Rejected state was lost"


@pytest.mark.parametrize("boundary", ["containers", "products", "total_products", "versions",
                                     "changes", "product_bytes", "depth", "source_bytes"])
def test_DeclarationCountsDepthAndByteBoundsFailDeterministically(monkeypatch, boundary):
    """Explicit profile bounds apply through the real parser without large/live source fixtures."""

    document = Document()

    if boundary == "containers":
        monkeypatch.setattr("fuzzy1337.intelligence_applicability.MAX_CONTAINERS", 1)
        document["containers"]["adp"] = [{"providerMetadata": {"orgId": "synthetic-adp"}}]

    elif boundary == "products":
        monkeypatch.setattr("fuzzy1337.intelligence_applicability.MAX_PRODUCTS_PER_CONTAINER", 1)
        document["containers"]["cna"]["affected"] *= 2

    elif boundary == "total_products":
        monkeypatch.setattr("fuzzy1337.intelligence_applicability.MAX_TOTAL_PRODUCTS", 1)
        document["containers"]["adp"] = [{"providerMetadata": {"orgId": "synthetic-adp"},
                                           "affected": [Product()]}]

    elif boundary in ("versions", "changes"):
        monkeypatch.setattr("fuzzy1337.intelligence_applicability.MAX_DECLARATION_ITEMS", 1)

        if boundary == "changes":
            document["containers"]["cna"]["affected"][0]["versions"] = [Product()["versions"][0]]

    elif boundary == "product_bytes":
        document["containers"]["cna"]["affected"][0]["product"] = "a" * (64 * 1024)

    elif boundary == "depth":
        value = "nested"

        for _ in range(35):
            value = [value]

        document["containers"]["cna"]["affected"][0]["platforms"] = value

    else:
        monkeypatch.setattr("fuzzy1337.intelligence.MAX_SOURCE_BYTES", 8)

    with pytest.raises(ValueError):
        ParseCveAffectedStatements(*Inputs(document))


def test_DirectConstructionEnforcesTypedOriginalSnapshotContainerOrderAndFrozenDeclarations():
    """Direct values cannot bypass source-result invariants or retain mutable provider payloads."""

    result = ParseCveAffectedStatements(*Inputs())

    for changes in ({"snapshot": None}, {"format_version": []}, {"containers": {}},
                    {"containers": ()}, {"containers": ("invalid",)},
                    {"containers": (replace(result.containers[0], role="adp"),)}):
        with pytest.raises(ValueError):
            replace(result, **changes)

    for changes in ({"role": "unknown"}, {"index": True}, {"index": 1},
                    {"index": -1}, {"provider": {}}, {"provider": []},
                    {"products": ()}, {"products": ({},)}):
        with pytest.raises(ValueError):
            replace(result.containers[0], **changes)

    provider = {"orgId": "synthetic-direct"}
    product = Product()
    direct = CveAffectedContainer("cna", 0, provider, (product,))
    provider["orgId"] = "changed"
    product["versions"].clear()

    assert direct.provider["orgId"] == "synthetic-direct" and direct.products[0]["versions"], (
        "Direct construction retained mutable caller dictionaries"
    )
    args = Inputs()
    snapshot = ParseIntelligenceSnapshot(args[0], IntelligenceFeed.CVE, *args[1:])

    assert CveAffectedStatements(snapshot, "5.2", (direct,)).snapshot is snapshot, (
        "The original source snapshot was copied or changed"
    )


def test_DirectConstructionRejectsRecursiveOrOverdeepDeclarationsAndRejectedPositiveProducts():
    """Direct values preserve parser bounds and cannot attach positive declarations to rejection."""

    product = Product()
    product["recursive"] = product

    with pytest.raises(ValueError):
        CveAffectedContainer("cna", 0, {"orgId": "synthetic"}, (product,))

    product = Product()
    nested = "bounded"

    for _ in range(35):
        nested = [nested]

    product["platforms"] = nested

    with pytest.raises(ValueError):
        CveAffectedContainer("cna", 0, {"orgId": "synthetic"}, (product,))

    document = Document()
    document["cveMetadata"]["state"] = "REJECTED"
    rejected = ParseCveAffectedStatements(*Inputs(document))
    container = CveAffectedContainer("cna", 0, {"orgId": "synthetic"}, (Product(),))

    with pytest.raises(ValueError):
        replace(rejected, containers=(container,))
