# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental pure selected CWE ZIP/XML profile; no acquisition, replay or model mutation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from fuzzy1337.intelligence import IntelligenceDate, IntelligenceIdentifier
from fuzzy1337.intelligence_cwe_xml import (
    MAX_ATTRIBUTE_BYTES,
    MAX_ATTRIBUTES,
    MAX_DEPTH,
    MAX_ENTRIES,
    MAX_ENTRY_BYTES,
    MAX_ENTRY_NODES,
    MAX_NODES,
    MAX_QNAME_BYTES,
    MAX_REFERENCE_BYTES,
    MAX_TEXT_BYTES,
    MAX_TOKEN_BYTES,
    MAX_VALUE_BYTES,
    MODES,
    STATUS_VALUES,
    CweName,
    CweXmlCollector,
)
from fuzzy1337.intelligence_cwe_zip import (
    CHUNK_BYTES,
    MAX_CENTRAL_DIRECTORY_BYTES,
    MAX_EXTRA_BYTES,
    MAX_EXTRA_FIELDS,
    MAX_XML_BYTES,
    MAX_ZIP_BYTES,
    ConsumeCweZip,
)

__all__ = ("CweSelectedRecord", "CweUnsupportedEntry", "CweSelection", "ParseCweSelection")

MAX_REQUESTED_IDS = 64
MAX_SELECTED_BYTES = 1024 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_CRC = re.compile(r"[0-9a-f]{8}\Z")


def CweIdentifier(value: object) -> str:
    """Require an exact positive canonical CWE identifier without spelling normalization.

    Args:
        value: Candidate exact string, never a CVE or subclass with custom operations.

    Returns:
        Unchanged CWE identifier with one to ten nonzero-leading decimal digits.
    """

    if type(value) is not str or not 5 <= len(value) <= 14 or not (
        IntelligenceIdentifier(value).startswith("CWE-")
    ):
        raise ValueError("CWE selection requires exact canonical CWE identifiers")

    return value


def RequestedIds(value: object) -> tuple[str, ...]:
    """Require an already sorted immutable bounded selection before decoding any source.

    Args:
        value: Exact tuple containing one to 64 unique exact canonical CWE strings.

    Returns:
        Unchanged admitted tuple; no sorting, deduplication or implicit full-corpus selection.
    """

    if type(value) is not tuple or not 1 <= len(value) <= MAX_REQUESTED_IDS:
        raise ValueError("CWE selection requires one to 64 immutable requested IDs")

    identifiers = tuple(CweIdentifier(item) for item in value)

    if identifiers != tuple(sorted(set(identifiers))):
        raise ValueError("CWE requested IDs must already be sorted and unique")

    return identifiers


def BoundedCanonical(value: object) -> bytes:
    """Encode exact canonical identity while checking each extension of its finite result buffer.

    Args:
        value: Detached finite profile dictionary; no caller-selected encoder settings.

    Returns:
        UTF-8 sorted-key compact JSON within the one-MiB selected result ceiling.
    """

    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                               allow_nan=False)
    result = bytearray()

    for part in encoder.iterencode(value):
        encoded = part.encode("utf-8")

        if len(result) + len(encoded) > MAX_SELECTED_BYTES:
            raise ValueError("CWE selected canonical JSON exceeds its byte profile")

        result.extend(encoded)

    return bytes(result)


@dataclass(frozen=True, slots=True)
class CweSelectedRecord:
    """Retain one selected Weakness name and source status without applicability interpretation."""

    identifier: str
    name: str
    status: str

    def __post_init__(self) -> None:
        """Validate direct source-field construction without claiming official corpus membership."""

        CweIdentifier(self.identifier)
        CweName(self.name)

        if type(self.status) is not str or self.status not in STATUS_VALUES:
            raise ValueError("CWE record status is outside the reviewed XSD enumeration")

    def ToDict(self) -> dict[str, str]:
        """Detach unchanged source fields with a non-overridable Weakness kind.

        Returns:
            Exact identifier, name, status and constant Weakness source kind.
        """

        return {"identifier": self.identifier, "name": self.name, "status": self.status,
                "source_kind": "Weakness"}


@dataclass(frozen=True, slots=True)
class CweUnsupportedEntry:
    """Retain the exact known source kind of a requested non-Weakness identity."""

    identifier: str
    source_kind: str

    def __post_init__(self) -> None:
        """Refuse missing, automatic or Weakness relabeling in direct construction."""

        CweIdentifier(self.identifier)

        if type(self.source_kind) is not str or self.source_kind not in (
            "Category", "Grouping", "View",
        ):
            raise ValueError("CWE unsupported entry requires its exact non-Weakness source kind")

    def ToDict(self) -> dict[str, str]:
        """Detach a known unsupported identity without fabricating a selected Weakness.

        Returns:
            Exact canonical identifier and original Category, Grouping or View kind.
        """

        return {"identifier": self.identifier, "source_kind": self.source_kind}


@dataclass(frozen=True, slots=True)
class CweSelection:
    """Hold immutable structural source/selection facts, distinct from authenticated raw proof."""

    requested_ids: tuple[str, ...]
    records: tuple[CweSelectedRecord, ...]
    unsupported_entries: tuple[CweUnsupportedEntry, ...]
    unmatched_ids: tuple[str, ...]
    catalog_version: str
    cwe_schema_version: str
    xml_namespace: str
    catalog_name: str
    catalog_date: str
    raw_sha256: str
    raw_size: int
    member_name: str
    member_compressed_size: int
    member_declared_size: int
    member_declared_crc32: str
    decoded_sha256: str
    decoded_size: int
    decoded_crc32: str
    weakness_count: int
    category_count: int
    grouping_count: int
    view_count: int
    xml_node_count: int
    xml_text_bytes: int
    xml_attribute_bytes: int
    maximum_depth: int
    maximum_entry_nodes: int
    maximum_entry_text_attribute_bytes: int
    maximum_markup_token_bytes: int
    maximum_comment_pi_bytes: int
    maximum_reference_bytes: int

    def __post_init__(self) -> None:
        """Validate structure and canonical size without claiming unavailable raw proof."""

        RequestedIds(self.requested_ids)

        if type(self.records) is not tuple or type(self.unsupported_entries) is not tuple or (
            type(self.unmatched_ids) is not tuple
            or len(self.records) + len(self.unsupported_entries) > len(self.requested_ids)
            or len(self.unmatched_ids) > len(self.requested_ids)
        ):
            raise ValueError("CWE selection result containers exceed their immutable item profile")

        if any(type(item) is not CweSelectedRecord for item in self.records) or any(
            type(item) is not CweUnsupportedEntry for item in self.unsupported_entries
        ):
            raise ValueError("CWE selection requires immutable exact typed records")

        matched = tuple(item.identifier for item in self.records)
        unsupported = tuple(item.identifier for item in self.unsupported_entries)

        if matched != tuple(sorted(set(matched))) or unsupported != tuple(sorted(set(unsupported))):
            raise ValueError("CWE selection result partitions must be sorted and unique")

        retained = set(matched) | set(unsupported)

        if set(matched) & set(unsupported) or not retained <= set(self.requested_ids) or (
            type(self.unmatched_ids) is not tuple
            or any(type(value) is not str for value in self.unmatched_ids)
            or self.unmatched_ids != tuple(value for value in self.requested_ids
                                           if value not in retained)
        ):
            raise ValueError("CWE selection partitions must exactly cover the immutable request")

        if type(self.catalog_version) is not str or self.catalog_version not in MODES:
            raise ValueError("CWE selection requires one supported exact catalog mode")

        mode = MODES[self.catalog_version]

        if any(type(value) is not str for value in (
            self.cwe_schema_version, self.xml_namespace, self.member_name,
        )) or (self.cwe_schema_version, self.xml_namespace, self.member_name) != mode:
            raise ValueError("CWE selection release, schema, namespace and member disagree")

        CweName(self.catalog_name, 256)

        if type(self.catalog_date) is not str or len(self.catalog_date) != 10:
            raise ValueError("CWE catalog date requires exact civil-day text")

        IntelligenceDate(self.catalog_date)

        for value in (self.raw_sha256, self.decoded_sha256):
            if type(value) is not str or not _DIGEST.fullmatch(value):
                raise ValueError("CWE selection requires lowercase SHA-256 facts")

        for value in (self.member_declared_crc32, self.decoded_crc32):
            if type(value) is not str or not _CRC.fullmatch(value):
                raise ValueError("CWE selection requires lowercase CRC32 facts")

        bounds = ((self.raw_size, 1, MAX_ZIP_BYTES),
            (self.member_compressed_size, 1, MAX_ZIP_BYTES),
            (self.member_declared_size, 1, MAX_XML_BYTES), (self.decoded_size, 1, MAX_XML_BYTES),
            (self.weakness_count, 0, MAX_ENTRIES), (self.category_count, 0, MAX_ENTRIES),
            (self.grouping_count, 0, MAX_ENTRIES), (self.view_count, 0, MAX_ENTRIES),
            (self.xml_node_count, 1, MAX_NODES), (self.xml_text_bytes, 0, MAX_TEXT_BYTES),
            (self.xml_attribute_bytes, 1, MAX_ATTRIBUTE_BYTES), (self.maximum_depth, 1, MAX_DEPTH),
            (self.maximum_entry_nodes, 0, MAX_ENTRY_NODES),
            (self.maximum_entry_text_attribute_bytes, 0, MAX_ENTRY_BYTES),
            (self.maximum_markup_token_bytes, 1, MAX_TOKEN_BYTES),
            (self.maximum_comment_pi_bytes, 0, MAX_TOKEN_BYTES),
            (self.maximum_reference_bytes, 0, MAX_REFERENCE_BYTES))

        if any(type(value) is not int or not minimum <= value <= maximum
               for value, minimum, maximum in bounds):
            raise ValueError("CWE selection observations exceed their integer profiles")

        if self.decoded_size != self.member_declared_size or (
            self.decoded_crc32 != self.member_declared_crc32
            or self.raw_size < self.member_compressed_size + 98 + 2 * len(self.member_name)
        ):
            raise ValueError("CWE selection byte sizes or declared/actual CRC facts disagree")

        counts = (self.weakness_count, self.category_count, self.grouping_count, self.view_count)
        total = sum(counts)
        retained_counts = {kind: sum(item.source_kind == kind for item in self.unsupported_entries)
                           for kind in ("Category", "Grouping", "View")}
        selected_attribute_sizes = [12 + len(item.identifier[4:]) + len(item.name.encode())
                                    + len(item.status) for item in self.records]
        root_attribute_size = 15 + len(self.catalog_name.encode()) + len(self.catalog_version) + 10

        if total > MAX_ENTRIES or self.weakness_count < len(self.records) or any(
            count < retained_counts[kind] for count, kind in zip(counts[1:], retained_counts)
        ) or self.catalog_version == "4.21" and self.grouping_count != 0:
            raise ValueError("CWE selection source-kind counts disagree with retained items")

        if self.xml_node_count < 1 + total + sum(count > 0 for count in counts) or (
            self.maximum_depth > self.xml_node_count
            or total > 0 and self.maximum_depth < 3
            or (total == 0) != (self.maximum_entry_nodes == 0)
            or (total == 0) != (self.maximum_entry_text_attribute_bytes == 0)
            or self.maximum_entry_nodes > self.xml_node_count
            or self.maximum_entry_text_attribute_bytes > (
                self.xml_text_bytes + self.xml_attribute_bytes)
            or self.maximum_markup_token_bytes > self.decoded_size
            or self.maximum_comment_pi_bytes > self.decoded_size
            or self.maximum_reference_bytes not in (0, 4, 5, 6, 7, 8, 9, 10)
            or self.maximum_reference_bytes > self.decoded_size
            or self.maximum_entry_text_attribute_bytes < max(selected_attribute_sizes, default=0)
            or self.xml_attribute_bytes < root_attribute_size + sum(selected_attribute_sizes)
        ):
            raise ValueError("CWE selection counters have inconsistent zero or containment facts")

        BoundedCanonical(self.ToDict())

    def ToDict(self) -> dict[str, object]:
        """Detach the complete profile-one scope, source facts, partitions and fixed limits.

        Returns:
            Schema-one selection content with day precision and no legacy snapshot claims.
        """

        return {"schema_version": 1, "profile_version": 1, "profile": "cwe-zipped-xml-selected",
            "requested_ids": list(self.requested_ids),
            "matched_ids": [item.identifier for item in self.records],
            "records": [item.ToDict() for item in self.records],
            "unsupported_entries": [item.ToDict() for item in self.unsupported_entries],
            "unmatched_ids": list(self.unmatched_ids), "catalog_version": self.catalog_version,
            "cwe_schema_version": self.cwe_schema_version, "xml_namespace": self.xml_namespace,
            "catalog_name": self.catalog_name, "catalog_date": self.catalog_date,
            "date_precision": "day", "raw_sha256": self.raw_sha256, "raw_size": self.raw_size,
            "member_name": self.member_name, "member_compressed_size": self.member_compressed_size,
            "member_declared_size": self.member_declared_size,
            "member_declared_crc32": self.member_declared_crc32,
            "decoded_sha256": self.decoded_sha256, "decoded_size": self.decoded_size,
            "decoded_crc32": self.decoded_crc32, "weakness_count": self.weakness_count,
            "category_count": self.category_count, "grouping_count": self.grouping_count,
            "view_count": self.view_count, "xml_node_count": self.xml_node_count,
            "xml_text_bytes": self.xml_text_bytes, "xml_attribute_bytes": self.xml_attribute_bytes,
            "maximum_depth": self.maximum_depth, "maximum_entry_nodes": self.maximum_entry_nodes,
            "maximum_entry_text_attribute_bytes": self.maximum_entry_text_attribute_bytes,
            "maximum_markup_token_bytes": self.maximum_markup_token_bytes,
            "maximum_comment_pi_bytes": self.maximum_comment_pi_bytes,
            "maximum_reference_bytes": self.maximum_reference_bytes,
            "zip_members": 1, "zip_method": 8, "zip_flags": 0,
            "validation_scope": "consumed-fields-only; no full XSD validation",
            "limits": {"raw_zip_bytes": MAX_ZIP_BYTES, "decoded_xml_bytes": MAX_XML_BYTES,
                "selected_json_bytes": MAX_SELECTED_BYTES, "requested_ids": MAX_REQUESTED_IDS,
                "central_directory_bytes": MAX_CENTRAL_DIRECTORY_BYTES,
                "extra_bytes_per_header": MAX_EXTRA_BYTES,
                "extra_fields_per_header": MAX_EXTRA_FIELDS,
                "compressed_chunk_bytes": CHUNK_BYTES, "decoded_chunk_bytes": CHUNK_BYTES,
                "markup_token_bytes": MAX_TOKEN_BYTES, "comment_pi_bytes": MAX_TOKEN_BYTES,
                "reference_bytes": MAX_REFERENCE_BYTES, "source_entries": MAX_ENTRIES,
                "xml_nodes": MAX_NODES, "xml_depth": MAX_DEPTH, "xml_text_bytes": MAX_TEXT_BYTES,
                "xml_attribute_bytes": MAX_ATTRIBUTE_BYTES,
                "attributes_per_element": MAX_ATTRIBUTES,
                "qname_bytes": MAX_QNAME_BYTES, "attribute_value_bytes": MAX_VALUE_BYTES,
                "entry_nodes": MAX_ENTRY_NODES, "entry_text_attribute_bytes": MAX_ENTRY_BYTES}}

    def Reference(self) -> str:
        """Bind the entire bounded canonical selection with its own reference family.

        Returns:
            cwe-selection SHA-256 identity, never a stored snapshot or replay proof.
        """

        return "cwe-selection:" + hashlib.sha256(BoundedCanonical(self.ToDict())).hexdigest()


def ParseCweSelection(payload: bytes, requested_ids: tuple[str, ...], *,
                      catalog_version: str) -> CweSelection:
    """Decode one complete finite supplied ZIP and select explicit Weakness identities.

    Args:
        payload: Exact original ZIP bytes, at most four MiB; no path or acquisition callback.
        requested_ids: Exact immutable lexically sorted unique tuple of one to 64 canonical CWEs.
        catalog_version: Exactly 5.0 or 4.21, binding namespace and sole member name.

    Returns:
        Complete immutable selection only after ZIP EOF/CRC and XML completion; unsupported
        source kinds remain distinct from absent IDs. No publisher authentication is asserted.

    Raises:
        ValueError: Input, framing, encoding, consumed grammar, completion or resource bound fails.
    """

    requested = RequestedIds(requested_ids)

    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_ZIP_BYTES:
        raise ValueError("CWE selection requires bounded exact original ZIP bytes")

    if type(catalog_version) is not str or catalog_version not in MODES:
        raise ValueError("CWE selection requires one supported exact catalog mode")

    schema, namespace, member = MODES[catalog_version]
    collector = CweXmlCollector(catalog_version, requested)
    raw = ConsumeCweZip(payload, member, collector.Feed)
    xml = collector.Finish()
    retained = {item[0] for item in xml.records} | {item[0] for item in xml.unsupported}

    return CweSelection(requested, tuple(CweSelectedRecord(*item) for item in xml.records),
        tuple(CweUnsupportedEntry(*item) for item in xml.unsupported),
        tuple(value for value in requested if value not in retained), catalog_version, schema,
        namespace, xml.catalog_name, xml.catalog_date, raw.raw_sha256, raw.raw_size,
        raw.member_name,
        raw.member_compressed_size, raw.member_declared_size, raw.member_declared_crc32,
        raw.decoded_sha256, raw.decoded_size, raw.decoded_crc32, xml.weakness_count,
        xml.category_count, xml.grouping_count, xml.view_count, xml.xml_node_count,
        xml.xml_text_bytes, xml.xml_attribute_bytes, xml.maximum_depth, xml.maximum_entry_nodes,
        xml.maximum_entry_text_attribute_bytes, xml.maximum_markup_token_bytes,
        xml.maximum_comment_pi_bytes, xml.maximum_reference_bytes)
