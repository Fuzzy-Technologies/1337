# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Keep the bounded selected CWE profile immutable, distinct and structurally exact."""

from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import Mock

import pytest

import fuzzy1337.intelligence_cwe_selection as selection_module
from fuzzy1337.intel_references import CanonicalReferenceJson
from fuzzy1337.intelligence import INTELLIGENCE_SCHEMA_VERSION, MAX_SOURCE_BYTES
from fuzzy1337.intelligence_cwe_selection import (
    CweSelectedRecord,
    CweSelection,
    CweUnsupportedEntry,
    ParseCweSelection,
)
from tests.unit.test_intelligence_cwe_selection import Archive, Catalog, Entry, Selected


class TextSubclass(str):
    """Represent an override-capable scalar that cannot enter the exact-type profile."""


class BytesSubclass(bytes):
    """Represent override-capable original bytes that must be refused before decoding."""


@pytest.mark.parametrize("requested", [
    [], ["CWE-79"], (), ("CWE-79", "CWE-1"), ("CWE-79", "CWE-79"),
    ("CVE-1900-0001",), ("CWE-0",), ("CWE-079",), ("cwe-79",), ("CWE-10000000000",),
    (TextSubclass("CWE-79"),), tuple("CWE-" + str(index) for index in range(1, 66)),
])
def test_RequestAdmissionIsExactImmutableCanonicalAndPrecedesAnyZipRead(requested, monkeypatch):
    """No iterable coercion, source discovery, request sorting or subclass execution is admitted."""

    consume = Mock()
    monkeypatch.setattr(selection_module, "ConsumeCweZip", consume)

    with pytest.raises(ValueError):
        ParseCweSelection(Archive(Catalog()), requested, catalog_version="5.0")

    assert not consume.called, "Invalid explicit selection reached original ZIP consumption"


@pytest.mark.parametrize("payload,version", [
    (bytearray(b"zip"), "5.0"), (BytesSubclass(b"zip"), "5.0"), (b"", "5.0"),
    (b"x" * (4 * 1024 * 1024 + 1), "5.0"), (b"zip", "latest"),
    (b"zip", TextSubclass("5.0")), (b"zip", 5.0),
])
def test_SourceAdmissionRequiresBoundedExactBytesAndOneClosedMode(payload, version, monkeypatch):
    """Neither alternate source inputs nor caller aliases can reach the fixed ZIP parser."""

    consume = Mock()
    monkeypatch.setattr(selection_module, "ConsumeCweZip", consume)

    with pytest.raises(ValueError):
        ParseCweSelection(payload, ("CWE-79",), catalog_version=version)

    assert not consume.called, "Invalid original input or mode reached the ZIP owner"


@pytest.mark.parametrize("kwargs", [
    {"identifier": "CVE-1900-0001"}, {"identifier": TextSubclass("CWE-79")},
    {"name": ""}, {"name": "x" * 8193}, {"name": "line\nbreak"},
    {"name": TextSubclass("Owned")}, {"status": "Unknown"}, {"status": True},
    {"status": TextSubclass("Stable")},
])
def test_DirectSelectedRecordConstructionValidatesEveryExactSourceField(kwargs):
    """Typed source records cannot create another source kind or normalize malformed fields."""

    values = {"identifier": "CWE-79", "name": "Owned", "status": "Stable", **kwargs}

    with pytest.raises(ValueError):
        CweSelectedRecord(**values)


@pytest.mark.parametrize("kind", ["Weakness", "category", "Absent", None, TextSubclass("View")])
def test_DirectUnsupportedEntryRequiresExactOriginalNonWeaknessKind(kind):
    """Known unsupported source kinds never become inferred or unknown aliases."""

    with pytest.raises(ValueError):
        CweUnsupportedEntry("CWE-79", kind)


@pytest.mark.parametrize("field,value", [
    ("requested_ids", ["CWE-79"]), ("records", []), ("records", ("CWE-79",)),
    ("records", (CweSelectedRecord("CWE-79", "x", "Stable"),) * 2),
    ("records", (CweSelectedRecord("CWE-80", "x", "Stable"),)),
    ("unsupported_entries", []), ("unsupported_entries", ("View",)),
    ("unsupported_entries", (CweUnsupportedEntry("CWE-79", "View"),)),
    ("unmatched_ids", []), ("unmatched_ids", ("CWE-79",)),
    ("catalog_version", "latest"), ("catalog_version", TextSubclass("5.0")),
    ("cwe_schema_version", "7.4"), ("xml_namespace", "http://cwe.mitre.org/cwe-7"),
    ("member_name", "../cwec_v5.0.xml"), ("member_name", TextSubclass("cwec_v5.0.xml")),
    ("catalog_name", ""), ("catalog_name", "x" * 257), ("catalog_date", True),
    ("catalog_date", "2026-02-30"), ("catalog_date", "2026-11-03T00:00:00Z"),
    ("raw_sha256", "A" * 64), ("decoded_sha256", "0" * 63),
    ("member_declared_crc32", "ABCDEF00"), ("decoded_crc32", "x" * 8),
    ("decoded_crc32", "00000000"), ("decoded_size", 1), ("raw_size", 1),
    ("weakness_count", 0), ("category_count", 10000),
    ("xml_node_count", 1), ("maximum_depth", 1), ("maximum_entry_nodes", 0),
    ("maximum_entry_text_attribute_bytes", 0), ("maximum_entry_text_attribute_bytes", 1000),
    ("maximum_entry_nodes", 10), ("maximum_markup_token_bytes", 60000),
    ("maximum_comment_pi_bytes", 60000), ("maximum_reference_bytes", 1),
    ("xml_attribute_bytes", 1),
])
def test_DirectSelectionConstructionRejectsTypedJoinAndCounterInconsistencies(field, value):
    """DTO reconstruction validates structure without claiming unavailable raw proof."""

    with pytest.raises(ValueError):
        replace(Selected(), **{field: value})


@pytest.mark.parametrize("field", [
    "raw_size", "member_compressed_size", "member_declared_size", "decoded_size",
    "weakness_count", "category_count", "grouping_count", "view_count", "xml_node_count",
    "xml_text_bytes", "xml_attribute_bytes", "maximum_depth", "maximum_entry_nodes",
    "maximum_entry_text_attribute_bytes", "maximum_markup_token_bytes", "maximum_comment_pi_bytes",
    "maximum_reference_bytes",
])
@pytest.mark.parametrize("value", [True, -1, 2**64])
def test_AllIntegerObservationsExcludeBooleansNegativesAndExcessiveValues(field, value):
    """Direct integer construction obeys the same fixed observation ceilings."""

    with pytest.raises(ValueError):
        replace(Selected(), **{field: value})


def test_PartitionOrderingAndPerKindCountsRemainExactInDirectConstruction():
    """Complete ordered partitions include known unsupported kinds and source counts."""

    xml = Catalog(b"<Views>" + Entry("1", kind="View") + Entry("2", kind="View") + b"</Views>")
    result = Selected(xml, ("CWE-1", "CWE-2", "CWE-79"))

    for change in ({"unsupported_entries": result.unsupported_entries[::-1]},
                   {"unsupported_entries": result.unsupported_entries * 2},
                   {"view_count": 1}, {"unmatched_ids": (TextSubclass("CWE-79"),)}):
        with pytest.raises(ValueError):
            replace(result, **change)

    seven = Selected(Catalog(version="4.21"), version="4.21")

    with pytest.raises(ValueError):
        replace(seven, grouping_count=1, xml_node_count=3, maximum_depth=3,
                maximum_entry_nodes=1, maximum_entry_text_attribute_bytes=1)


def test_DirectDtoAppliesTheSameIndependentCanonicalByteCeiling():
    """Direct DTO construction cannot bypass canonical escaping growth."""

    records = tuple(CweSelectedRecord("CWE-" + str(index), "\\" * 8192, "Stable")
                    for index in range(1, 65))
    records = tuple(sorted(records, key=lambda item: item.identifier))

    with pytest.raises(ValueError, match="canonical JSON"):
        replace(Selected(), requested_ids=tuple(item.identifier for item in records),
            records=records,
            weakness_count=64, xml_node_count=66, decoded_size=600000, member_declared_size=600000,
            xml_attribute_bytes=600000, maximum_entry_text_attribute_bytes=9000)


def test_ReferenceIncludesEveryFieldAndDetachedContentCannotMutateFrozenFacts():
    """The separate complete canonical identity binds requested scope and all observed raw facts."""

    result = Selected()
    document = result.ToDict()
    expected = "cwe-selection:" + hashlib.sha256(CanonicalReferenceJson(document)).hexdigest()
    assert result.Reference() == expected, "Selection reference omitted canonical identity content"
    document["records"][0]["name"] = "mutated"
    document["limits"]["requested_ids"] = 999
    assert result.Reference() == expected and result.records[0].name == "Owned name", (
        "Detached public content modified immutable source/limit identity"
    )

    with pytest.raises(FrozenInstanceError):
        result.catalog_name = "mutable"

    for field in fields(result):
        assert field.name in result.ToDict(), "A constructor field was omitted from identity"

    for change in ({"raw_sha256": "a" * 64}, {"decoded_sha256": "b" * 64},
                   {"xml_text_bytes": 1}, {"maximum_reference_bytes": 4},
                   {"catalog_name": "Another"}, {"catalog_date": "2026-11-04"}):
        assert replace(result, **change).Reference() != expected, "Changed facts reused identity"


def test_PublicSurfaceAndLegacyContractsRemainSeparateAndUnchanged():
    """Only the four adopted symbols are Experimental exports; no snapshot schema is repurposed."""

    assert selection_module.__all__ == (
        "CweSelectedRecord", "CweUnsupportedEntry", "CweSelection", "ParseCweSelection"), (
        "Internal parsing helpers entered the public supported surface"
    )
    assert INTELLIGENCE_SCHEMA_VERSION == 1 and MAX_SOURCE_BYTES == 16 * 1024 * 1024, (
        "Pure profile changed legacy schema or source budget"
    )
    document = Selected().ToDict()
    assert document["profile"] == "cwe-zipped-xml-selected" and document["schema_version"] == 1, (
        "Separate selection wire family was relabeled"
    )
    assert document["date_precision"] == "day" and document["zip_members"] == 1, (
        "Fixed source granularity or member count changed"
    )
    assert "Deserialize" not in dir(CweSelection), (
        "Pure DTO acquired an unsupported serialized loader"
    )


@pytest.mark.parametrize("field,value", [
    ("records", (CweSelectedRecord("CWE-79", "x", "Stable"),) * 1000),
    ("unsupported_entries", (CweUnsupportedEntry("CWE-79", "View"),) * 1000),
    ("unmatched_ids", ("CWE-79",) * 1000),
])
def test_ResultContainerCeilingsArePreflightedBeforePartitionAllocation(field, value):
    """Direct DTO admission bounds all result tuple lengths before constructing ID sets."""

    with pytest.raises(ValueError, match="item profile"):
        replace(Selected(), **{field: value})


def test_MultibyteNameBudgetCountsUtf8BytesAfterBoundedCodepointAdmission():
    """A short printable Unicode scalar can still exceed its independent byte ceiling."""

    with pytest.raises(ValueError, match="byte profile"):
        CweSelectedRecord("CWE-79", "é" * 4097, "Stable")

    with pytest.raises(ValueError, match="byte profile"):
        replace(Selected(), catalog_name="é" * 129)
