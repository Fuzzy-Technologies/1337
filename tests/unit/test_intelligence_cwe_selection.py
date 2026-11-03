# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise pure selected CWE composition with owned complete ZIP/XML fixtures."""

from __future__ import annotations

import hashlib
import html
import io
import zipfile

import pytest

from fuzzy1337.intelligence_cwe_selection import ParseCweSelection


def Catalog(inner: bytes = b"", version: str = "5.0", *, declaration: bytes = b"") -> bytes:
    """Build a bounded owned namespace/catalog root without a publisher authenticity assertion."""

    namespace = "8" if version == "5.0" else "7"
    root = (f'<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-{namespace}" '
            f'Name="Owned CWE" Version="{version}" Date="2026-11-03">').encode()

    return declaration + root + inner + b"</Weakness_Catalog>"


def Entry(identifier: str = "79", name: str = "Owned name", status: str = "Stable", *,
          kind: str = "Weakness", content: bytes = b"") -> bytes:
    """Create exact source-kind fields with normal XML attribute escaping."""

    return (f'<{kind} ID="{identifier}" Name="{html.escape(name, quote=True)}" '
            f'Status="{status}">').encode() + content + f'</{kind}>'.encode()


def Archive(xml: bytes, version: str = "5.0", *, extra: bytes = b"") -> bytes:
    """Package an owned exact regular-file member; no third-party catalog is redistributed."""

    output = io.BytesIO()
    item = zipfile.ZipInfo("cwec_v" + version + ".xml")
    item.create_system = 3
    item.external_attr = 0o100644 << 16
    item.compress_type = zipfile.ZIP_DEFLATED
    item.extra = extra

    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(item, xml)

    return output.getvalue()


def Selected(xml: bytes | None = None, requested: tuple[str, ...] = ("CWE-79",), *,
             version: str = "5.0"):
    """Obtain genuine public structural facts from one owned complete ZIP/XML composition."""

    if xml is None:
        xml = Catalog(b"<Weaknesses>" + Entry() + b"</Weaknesses>", version)

    return ParseCweSelection(Archive(xml, version), requested, catalog_version=version)


@pytest.mark.parametrize("version", ["5.0", "4.21"])
def test_SelectedNamesStatusesAndRawIdentityArePreservedInBothClosedModes(version):
    """Normal XML normalization preserves source prose while raw/expanded hashes bind originals."""

    name = '  Original & "quoted" \\ exact  '
    xml = Catalog(b"<Weaknesses>" + Entry(name=name, status="Deprecated") + b"</Weaknesses>",
                  version, declaration=b'<?xml version="1.0" encoding="UTF-8"?>')
    raw = Archive(xml, version)
    result = ParseCweSelection(raw, ("CWE-79", "CWE-999"), catalog_version=version)
    assert result.records[0].name == name and result.records[0].status == "Deprecated", (
        "Selection rewrote original normalized source name or status"
    )
    assert result.unmatched_ids == ("CWE-999",), "Absent source identity acquired a record"
    assert result.raw_sha256 == hashlib.sha256(raw).hexdigest(), "Original ZIP identity was lost"
    assert result.decoded_sha256 == hashlib.sha256(xml).hexdigest(), "Expanded identity was lost"
    assert result.catalog_date == "2026-11-03" and "effective_at" not in result.ToDict(), (
        "Day-only source metadata acquired an invented publisher instant"
    )


def test_UnsupportedKindsAndAbsentIdsFormDistinctCompletePartitions():
    """Schema eight Category and Grouping source kinds coexist without automatic relabeling."""

    xml = Catalog(b"<Weaknesses>" + Entry() + b"</Weaknesses><Categories>"
        + Entry("1", kind="Category") + b"</Categories><Groupings>"
        + Entry("2", kind="Grouping") + b"</Groupings><Views>"
        + Entry("3", kind="View") + b"</Views>")
    result = Selected(xml, ("CWE-1", "CWE-2", "CWE-3", "CWE-79", "CWE-999"))
    assert tuple((item.identifier, item.source_kind) for item in result.unsupported_entries) == (
        ("CWE-1", "Category"), ("CWE-2", "Grouping"), ("CWE-3", "View")), (
        "Known unsupported source identities were normalized or treated as absent"
    )
    assert result.unmatched_ids == ("CWE-999",), "Known source kind became unmatched"
    assert (result.weakness_count, result.category_count, result.grouping_count,
            result.view_count) == (1, 1, 1, 1), "Source-wide kind counts lost unselected scope"


def test_EmptyAndOnlyUnsupportedSelectionsDoNotInventWeaknesses():
    """Zero selected Weaknesses is a valid exact result, without a zero-risk interpretation."""

    absent = Selected(Catalog(), ("CWE-79",))
    unsupported = Selected(Catalog(b"<Views>" + Entry("79", kind="View") + b"</Views>"))
    assert absent.records == unsupported.records == (), "Selection invented a Weakness"
    assert absent.unmatched_ids == ("CWE-79",) and unsupported.unmatched_ids == (), (
        "Absent and known unsupported outcomes were conflated"
    )
    assert absent.maximum_entry_nodes == absent.maximum_entry_text_attribute_bytes == 0, (
        "Empty source acquired fabricated entry observations"
    )


@pytest.mark.parametrize("inner", [
    b"<Unknown/>", b"<Weaknesses/><Weaknesses/>",
    b"<Weaknesses><Category ID='79' Name='x' Status='Stable'/></Weaknesses>",
    b"<Views><View ID='1' Name='x' Status='Stable'><Weakness ID='79' Name='x' "
    b"Status='Stable'/></View></Views>",
    b"<External_References><Wrong/></External_References>",
    b"<Weaknesses><w:Weakness xmlns:w='urn:wrong' ID='79' Name='x' Status='Stable'/></Weaknesses>",
    b"<Weaknesses><Weakness ID='79' Name='x' Status='Stable'/></Weaknesses><Categories>"
    b"<Category ID='79' Name='x' Status='Stable'/></Categories>",
])
def test_ConsumedCollectionGrammarAndCrossKindUniquenessFailClosed(inner):
    """Direct paths and one identity across kinds are validated before publishing any DTO."""

    with pytest.raises(ValueError):
        Selected(Catalog(inner))


def test_SchemaSevenGroupingsAreUnsupportedGrammarRatherThanAbsentOrRelabeled():
    """A schema-eight collection cannot be silently interpreted under namespace seven."""

    xml = Catalog(b"<Groupings>" + Entry("79", kind="Grouping") + b"</Groupings>", "4.21")

    with pytest.raises(ValueError, match="collection"):
        Selected(xml, version="4.21")


@pytest.mark.parametrize("field,replacement", [
    (b'ID="80"', b'ID="080"'), (b'ID="80"', b'ID="0"'),
    (b'ID="80"', b'ID="10000000000"'), (b'ID="80"', b'ID="CWE-80"'),
    (b'Name="Owned name"', b'Name=""'), (b'Name="Owned name"', b'Name="&#10;"'),
    (b'Status="Stable"', b'Status="Unknown"'), (b'Status="Stable"', b''),
])
def test_UnselectedConsumedFieldsCannotEvadeAdmission(field, replacement):
    """Finding the requested ID does not bypass later malformed unselected source entries."""

    invalid = Entry("80").replace(field, replacement)
    xml = Catalog(b"<Weaknesses>" + Entry() + invalid + b"</Weaknesses>")

    with pytest.raises(ValueError):
        Selected(xml)


@pytest.mark.parametrize("original,replacement", [
    (b'Name="Owned CWE"', b'Name=""'),
    (b'Name="Owned CWE"', b'Name="' + b"x" * 257 + b'"'),
    (b'Date="2026-11-03"', b'Date="2026-02-30"'),
    (b'Date="2026-11-03"', b'Date="2026-11-03T00:00:00Z"'),
    (b'Version="5.0"', b'Version="4.21"'),
    (b'http://cwe.mitre.org/cwe-8', b'http://cwe.mitre.org/cwe-7'),
])
def test_RootMetadataRequiresExactModeAndRealCivilDay(original, replacement):
    """Root metadata is consumed source information rather than a freely replaceable label."""

    with pytest.raises(ValueError):
        Selected(Catalog().replace(original, replacement))


@pytest.mark.parametrize("tail", [b"<", b"<Wrong/>", b"&unfinished", b"\xff", b"\0"])
def test_CompleteTailMustBeValidEvenAfterAllRequestedIdsMatched(tail):
    """A valid early record never grants success before all original source bytes are consumed."""

    with pytest.raises(ValueError):
        Selected(Catalog(b"<Weaknesses>" + Entry() + b"</Weaknesses>") + tail)


def test_SelectedCanonicalEscapingHasItsOwnOneMiBCeiling():
    """Sixty-four individually legal escaped names exceed the normalized cap and must refuse."""

    entries = b"".join(Entry(str(index), "\\" * 8192) for index in range(1, 65))
    ids = tuple(sorted("CWE-" + str(index) for index in range(1, 65)))

    with pytest.raises(ValueError, match="canonical JSON"):
        Selected(Catalog(b"<Weaknesses>" + entries + b"</Weaknesses>"), ids)


def test_SourceEntryCeilingCountsAllUnselectedKinds():
    """Ten-thousand source IDs remain a source work budget even for one requested identity."""

    entries = b"".join(Entry(str(index)) for index in range(1, 10002))

    with pytest.raises(ValueError, match="count"):
        Selected(Catalog(b"<Weaknesses>" + entries + b"</Weaknesses>"))


def test_ExactlySixtyFourOrdinarySelectedWeaknessesFitTheClosedRequestProfile():
    """The maximum ordinary request succeeds independently of oversized escaped-name denials."""

    identifiers = tuple(sorted("CWE-" + str(index) for index in range(1, 65)))
    entries = b"".join(Entry(identifier[4:]) for identifier in identifiers)
    result = Selected(Catalog(b"<Weaknesses>" + entries + b"</Weaknesses>"), identifiers)
    assert tuple(item.identifier for item in result.records) == identifiers, (
        "The exact 64-ID supported boundary lost an ordinary selected source record"
    )
    assert not result.unsupported_entries and not result.unmatched_ids, (
        "The maximum all-Weakness selection invented another outcome partition"
    )
