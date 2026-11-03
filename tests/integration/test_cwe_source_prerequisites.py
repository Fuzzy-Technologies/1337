# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Opt-in bounded official CWE research; no product receiver or source-acceptance claim."""

from __future__ import annotations

import codecs
import hashlib
import http.client
import io
import json
import os
import re
import ssl
import struct
import sys
import time
import xml.etree.ElementTree as element_tree
import xml.parsers.expat as expat
import zipfile
import zlib
from datetime import date, datetime, timezone
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "functional-evidence" / "cwe-prerequisites"
CHUNK_BYTES = 65536
MAX_ZIP_BYTES = 4 * 1024 * 1024
MAX_XML_BYTES = 32 * 1024 * 1024
STATUS_VALUES = ("Deprecated", "Draft", "Incomplete", "Obsolete", "Stable", "Usable")
SCHEMAS = (
    ("8.0", "http://cwe.mitre.org/cwe-8", "cwe_schema_v8.0.xsd",
     "e68782e818d5b1ba048ebfcf5ca0b663948373fa747c825f455af83fd7fbc2e0"),
    ("7.4", "http://cwe.mitre.org/cwe-7", "cwe_schema_v7.4.xsd",
     "8ce1683110ac049cc378f41527b5f00512955071bc90c2d975d2a52ff5aa384e"),
)
ARCHIVES = (
    ("5.0", "http://cwe.mitre.org/cwe-8", "cwec_v5.0.xml.zip",
     "bcda44c9abf61ff977f50c3c6649eea5a97a7b0626b0396c2c3ec4bfb973a3dc"),
    ("4.21", "http://cwe.mitre.org/cwe-7", "cwec_v4.21.xml.zip",
     "5225e2b4976696b5b90b62cdad0ddab4e8898103d61350971e366a377e718862"),
)
TAG_SPECIAL_PATTERN = re.compile(br"[\'\">]")
RAW_NAME_PATTERN = re.compile(br"[^\x20\x09\x0a\x0d=/>]+")
REFERENCE_PATTERN = re.compile(br"&(?:amp|lt|gt|apos|quot|#[0-9]{1,7}|#x[0-9A-Fa-f]{1,6});")


def ResearchOutput() -> Path:
    """Create only the fixed repository-owned evidence path without following output aliases."""

    path = ROOT

    for name in ("functional-evidence", "cwe-prerequisites", "inputs"):
        path = path / name

        if path.is_symlink():
            raise ValueError("research output must not follow a symlink")

        path.mkdir(exist_ok=True)

    return path.parent


def SaveFacts(name: str, value: object) -> None:
    """Retain finite research facts separately from product receipts or authentication proof."""

    (ResearchOutput() / name).write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8",
    )


def FetchInput(name: str, digest: str, maximum: int, *, schema: bool) -> tuple[bytes, dict]:
    """Read one fixed literal source once with default TLS, no redirect and bounded bytes/time."""

    directory = "xsd" if schema else "xml"
    url = f"https://cwe.mitre.org/data/{directory}/{name}"
    allowed = {(item[2], item[3], 524288, True) for item in SCHEMAS}
    allowed.update((item[2], item[3], MAX_ZIP_BYTES, False) for item in ARCHIVES)

    if (name, digest, maximum, schema) not in allowed:
        raise ValueError("research only admits the four fixed original source names")

    selected = urlsplit(url)
    started = time.monotonic()
    deadline = started + 15
    connection = http.client.HTTPSConnection(
        selected.hostname, timeout=10, context=ssl.create_default_context(),
    )
    facts = {"url": url, "started_at": datetime.now(timezone.utc).isoformat(),
             "max_bytes": maximum, "expected_sha256": digest, "requests": 1,
             "transport": "external research HTTPS; not product SDK", "received_bytes": 0}
    body = bytearray()

    try:
        connection.request("GET", selected.path, headers={"Accept-Encoding": "identity",
            "Connection": "close", "User-Agent": "1337-cwe-prerequisite-research/1"})
        response = connection.getresponse()
        facts.update(http_status=response.status,
                     content_length=response.getheader("Content-Length"),
                     content_encoding=response.getheader("Content-Encoding"),
                     last_modified=response.getheader("Last-Modified"))

        if response.status != 200 or response.getheader("Content-Encoding") not in (
            None, "identity",
        ):
            raise ValueError("research requires original HTTP 200 identity body without redirect")

        declared = response.getheader("Content-Length")
        length = None

        if declared is not None:
            if not re.fullmatch(r"0|[1-9][0-9]{0,19}", declared):
                raise ValueError("research Content-Length is not canonical bounded decimal")

            length = int(declared)

            if length > maximum:
                raise ValueError("declared research source exceeds fixed original byte cap")

        facts["content_length_absent"] = declared is None

        while True:
            if time.monotonic() > deadline:
                raise ValueError("research source read deadline exceeded")

            chunk = response.read1(min(CHUNK_BYTES, maximum - len(body) + 1))

            if len(body) + len(chunk) > maximum:
                raise ValueError("research original-source ceiling exceeded")

            body.extend(chunk)
            facts["received_bytes"] = len(body)

            if time.monotonic() > deadline:
                raise ValueError("research source read deadline exceeded")

            if not chunk:
                break

        if length is not None and len(body) != length:
            raise ValueError("original HTTP body differs from declared Content-Length")

        payload = bytes(body)
        observed = hashlib.sha256(payload).hexdigest()
        (ResearchOutput() / "inputs" / name).write_bytes(payload)
        facts.update(sha256=observed, body_complete=True, retained_file="inputs/" + name)

        if observed != digest:
            raise ValueError("bounded original source differs from recorded mandatory pin")

        if time.monotonic() > deadline:
            raise ValueError("research source read deadline exceeded")

        facts["state"] = "pin-matched"

    except (OSError, ValueError, http.client.HTTPException) as error:
        payload = bytes(body)
        facts.update(state="research-refused", reason=str(error), error_type=type(error).__name__)

        if body and "retained_file" not in facts:
            (ResearchOutput() / "inputs" / (name + ".partial")).write_bytes(payload)
            facts["retained_partial_file"] = "inputs/" + name + ".partial"

    finally:
        connection.close()
        facts["finished_at"] = datetime.now(timezone.utc).isoformat()
        facts["elapsed_seconds"] = time.monotonic() - started

    return payload, facts


def SchemaFacts(payload: bytes, version: str, namespace: str) -> tuple[dict, bytes]:
    """Extract exact hash-bound StatusEnumeration bytes without fetching any XSD import."""

    if len(payload) > 524288 or b"<!DOCTYPE" in payload or b"<!ENTITY" in payload:
        raise ValueError("research schema exceeds its finite XML profile")

    root = element_tree.fromstring(payload)
    ns = {"xs": "http://www.w3.org/2001/XMLSchema"}
    node = root.find("xs:simpleType[@name='StatusEnumeration']", ns)

    if node is None:
        raise ValueError("selected schema has no StatusEnumeration")

    values = tuple(item.attrib["value"] for item in node.findall(".//xs:enumeration", ns))
    spans = list(re.finditer(
        br'<xs:simpleType\s+name="StatusEnumeration">.*?</xs:simpleType>', payload, re.DOTALL,
    ))

    if len(spans) != 1 or values != STATUS_VALUES or root.get("version") != version or (
        root.get("targetNamespace") != namespace
    ):
        raise ValueError("exact schema mode or recorded StatusEnumeration policy disagrees")

    span = spans[0]
    excerpt = span.group()

    return {"version": version, "namespace": namespace, "status_values": values,
            "original_sha256": hashlib.sha256(payload).hexdigest(),
            "extract_start": span.start(), "extract_end": span.end(),
            "extract_sha256": hashlib.sha256(excerpt).hexdigest(),
            "external_schema_imports_followed": 0}, excerpt


def ExtraFacts(payload: bytes) -> list[dict]:
    """Inspect finite opaque TLVs independently for local and central headers."""

    if len(payload) > 256:
        raise ValueError("research extra metadata exceeds proposed 256-byte ceiling")

    result = []
    seen = set()
    position = 0

    while position < len(payload):
        if position + 4 > len(payload):
            raise ValueError("truncated ZIP extra-field header")

        field_id, length = struct.unpack_from("<HH", payload, position)
        position += 4

        if field_id == 1 or field_id in seen or position + length > len(payload) or (
            len(result) >= 8
        ):
            raise ValueError("ZIP64, duplicate, malformed or excessive extra metadata")

        seen.add(field_id)
        result.append({"id": field_id, "id_hex": f"{field_id:04x}", "length": length,
                       "data_hex": payload[position:position + length].hex()})
        position += length

    return result


def ArchiveFacts(payload: bytes, member: str) -> tuple[dict, int, int]:
    """Inspect one complete bounded local/central/EOCD chain without extracting paths."""

    if not 22 <= len(payload) <= MAX_ZIP_BYTES:
        raise ValueError("original ZIP exceeds research byte profile")

    end = struct.unpack_from("<4s4H2IH", payload, len(payload) - 22)

    if end[0] != b"PK\x05\x06" or end[1:5] != (0, 0, 1, 1) or end[-1] != 0:
        raise ValueError("ZIP requires final comment-free single-disk single-entry EOCD")

    central_size, central_offset = end[5:7]

    if central_size > 16384 or central_offset + central_size != len(payload) - 22:
        raise ValueError("central directory is oversized or not adjacent to EOCD")

    central = struct.unpack_from("<4s6H3I5H2I", payload, central_offset)
    local = struct.unpack_from("<4s5H3I2H", payload, 0)

    if central[0] != b"PK\x01\x02" or local[0] != b"PK\x03\x04":
        raise ValueError("ZIP local or central signature mismatch")

    name_length, extra_length, comment_length = central[10:13]
    local_name_length, local_extra_length = local[9:11]
    central_name_start = central_offset + 46
    local_name = payload[30:30 + local_name_length]
    central_name = payload[central_name_start:central_name_start + name_length]
    compressed_start = 30 + local_name_length + local_extra_length
    compressed_end = compressed_start + central[8]
    expected = member.encode("ascii")

    if local_name != expected or central_name != expected or central[16] != 0 or (
        comment_length != 0 or central[13] != 0
        or 46 + name_length + extra_length != central_size
        or compressed_end != central_offset or compressed_start > compressed_end
    ):
        raise ValueError("ZIP filename, offset, count or exact frame adjacency mismatch")

    if local[1:4] != central[2:5] or local[6:9] != central[7:10] or (
        local[3] != 8 or local[2] != 0 or central[9] > MAX_XML_BYTES
    ):
        raise ValueError("ZIP local/central versions, flags, method, CRC or sizes disagree")

    local_extra = payload[30 + local_name_length:compressed_start]
    central_extra_start = central_name_start + name_length
    central_extra = payload[central_extra_start:central_extra_start + extra_length]
    creator_host = central[1] >> 8
    unix_mode = central[15] >> 16
    violations = []

    if local[1] != 20:
        violations.append("proposed extraction version 20 differs from original")

    if creator_host != 3 or unix_mode & 0o170000 != 0o100000 or central[15] & 0x10:
        violations.append("proposed Unix creator/regular-file type policy differs from original")

    return {"member_name": member, "original_size": len(payload),
            "original_sha256": hashlib.sha256(payload).hexdigest(),
            "local_extract_version": local[1], "central_extract_version": central[2],
            "creator_host": creator_host, "creator_version": central[1] & 255,
            "flags": central[3], "method": central[4], "declared_crc32": f"{central[7]:08x}",
            "compressed_size": central[8], "declared_decoded_size": central[9],
            "central_directory_size": central_size, "central_directory_offset": central_offset,
            "local_extra_bytes": len(local_extra), "central_extra_bytes": len(central_extra),
            "local_extras": ExtraFacts(local_extra), "central_extras": ExtraFacts(central_extra),
            "external_attributes": central[15], "unix_mode_octal": oct(unix_mode),
            "internal_attributes": central[14], "local_header_offset": central[16],
            "frame_complete": True, "policy_violations": violations}, compressed_start, (
                compressed_end
            )


class XmlMeasurements:
    """Measure hash-pinned research XML; this is not the future untrusted-input lexical gate."""

    def __init__(self, version: str, namespace: str) -> None:
        """Configure finite SAX counters and a two-chunk raw diagnostic window."""

        self.version = version
        self.namespace = namespace
        self.parser = expat.ParserCreate(encoding="UTF-8", namespace_separator="|")
        self.parser.buffer_text = False
        self.parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
        self.parser.StartElementHandler = self.Start
        self.parser.EndElementHandler = self.End
        self.parser.CharacterDataHandler = self.Text
        self.parser.StartNamespaceDeclHandler = self.Namespace
        self.parser.CommentHandler = self.Comment
        self.parser.ProcessingInstructionHandler = self.Instruction
        self.parser.XmlDeclHandler = self.Declaration
        self.parser.StartDoctypeDeclHandler = self.Forbidden
        self.parser.EntityDeclHandler = self.Forbidden
        self.parser.ExternalEntityRefHandler = self.Forbidden
        self.parser.SkippedEntityHandler = self.Forbidden
        self.parser.StartCdataSectionHandler = self.StartCdata
        self.parser.EndCdataSectionHandler = self.EndCdata
        self.decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self.window = b""
        self.window_start = 0
        self.received = 0
        self.stack = []
        self.empty_stack = []
        self.last_markup_empty = False
        self.pending_namespaces = []
        self.in_cdata = False
        self.active_entry = None
        self.entry_nodes = 0
        self.entry_bytes = 0
        self.ids = set()
        self.notice_excerpts = []
        self.facts = {"root": None, "kind_counts": {kind: 0 for kind in
            ("Weakness", "Category", "Grouping", "View")}, "node_count": 0,
            "text_bytes": 0, "attribute_bytes": 0, "maximum_depth": 0,
            "maximum_attributes": 0, "maximum_expanded_name_bytes": 0,
            "maximum_raw_qname_bytes": 0, "maximum_attribute_value_bytes": 0,
            "maximum_entry_nodes": 0, "maximum_entry_text_attribute_bytes": 0,
            "maximum_markup_token_bytes": 0, "maximum_comment_pi_bytes": 0,
            "maximum_reference_bytes": 0, "maximum_name_bytes": 0,
            "namespace_declarations": 0, "statuses": set(),
            "callback_counts": {kind: 0 for kind in ("start_element", "end_element",
                "character_data", "namespace", "comment", "instruction", "declaration",
                "cdata_start", "cdata_end", "forbidden")},
            "notice_candidates": []}

    def RawOffset(self) -> int:
        """Locate the current callback without copying the remaining source-window suffix."""

        offset = self.parser.CurrentByteIndex - self.window_start

        if offset < 0 or offset > len(self.window):
            raise ValueError("raw callback context exceeded two bounded research chunks")

        return offset

    def References(self, raw: bytes) -> None:
        """Measure bounded actual reference spellings with one forward scan, not suffix rescans."""

        offset = raw.find(b"&")

        while offset >= 0:
            match = REFERENCE_PATTERN.match(raw, offset)

            if match is None:
                raise ValueError("source reference differs from proposed bounded spelling policy")

            self.facts["maximum_reference_bytes"] = max(
                self.facts["maximum_reference_bytes"], match.end() - offset,
            )
            offset = raw.find(b"&", match.end())

    def Markup(self) -> None:
        """Measure one complete token with forward C-level scans and quoted delimiter state."""

        offset = self.RawOffset()
        limit = min(len(self.window), offset + 65536)
        position = offset + 1
        quote = None
        end = None

        while position < limit:
            if quote is not None:
                found = self.window.find(quote, position, limit)

                if found < 0:
                    break

                position = found + 1
                quote = None

            else:
                match = TAG_SPECIAL_PATTERN.search(self.window, position, limit)

                if match is None:
                    break

                position = match.end()

                if match.group() == b">":
                    end = position
                    break

                quote = match.group()

        if end is None:
            raise ValueError("ordinary XML token exceeds proposed 64 KiB ceiling")

        token = self.window[offset:end]
        self.last_markup_empty = token.endswith(b"/>")
        self.facts["maximum_markup_token_bytes"] = max(
            self.facts["maximum_markup_token_bytes"], len(token),
        )
        self.References(token)
        self.RawNames(token)

    def RawNames(self, token: bytes) -> None:
        """Measure original prefix-bearing element and attribute names outside quoted values."""

        position = 2 if token.startswith(b"</") else 1

        while position < len(token):
            match = RAW_NAME_PATTERN.match(token, position)

            if match is None:
                raise ValueError("complete raw element/attribute name could not be measured")

            self.facts["maximum_raw_qname_bytes"] = max(
                self.facts["maximum_raw_qname_bytes"], match.end() - match.start(),
            )
            position = match.end()

            while token[position:position + 1] in (b" ", b"\t", b"\r", b"\n"):
                position += 1

            if token[position:position + 1] == b"=":
                position += 1

                while token[position:position + 1] in (b" ", b"\t", b"\r", b"\n"):
                    position += 1

                quote = token[position:position + 1]

                if quote not in (b"'", b'"'):
                    raise ValueError("complete raw attribute has no quoted value")

                position = token.find(quote, position + 1) + 1

                if position == 0:
                    raise ValueError("complete raw attribute has no closing quote")

                while token[position:position + 1] in (b" ", b"\t", b"\r", b"\n"):
                    position += 1

            if token[position:position + 1] in (b"/", b">"):
                break

    def Namespace(self, prefix: str | None, uri: str | None) -> None:
        """Count declarations separately because Expat omits xmlns from its attribute mapping."""

        self.facts["callback_counts"]["namespace"] += 1
        self.pending_namespaces.append(("xmlns" + (":" + prefix if prefix else ""), uri or ""))
        self.facts["namespace_declarations"] += 1

    def Start(self, name: str, attributes: dict[str, str]) -> None:
        """Measure all selected and ignored entry fields under exact namespace paths."""

        self.facts["callback_counts"]["start_element"] += 1
        self.Markup()
        self.stack.append(name)
        self.empty_stack.append(self.last_markup_empty)
        self.Node()
        self.facts["maximum_depth"] = max(self.facts["maximum_depth"], len(self.stack))
        pairs = [*self.pending_namespaces, *attributes.items()]
        self.pending_namespaces = []
        size = sum(len(key.encode()) + len(value.encode()) for key, value in pairs)
        self.facts["attribute_bytes"] += size
        self.facts["maximum_attributes"] = max(self.facts["maximum_attributes"], len(pairs))
        self.facts["maximum_expanded_name_bytes"] = max(
            self.facts["maximum_expanded_name_bytes"], len(name.encode()),
            *(len(key.encode()) for key in attributes))
        self.facts["maximum_attribute_value_bytes"] = max(
            self.facts["maximum_attribute_value_bytes"],
            *(len(value.encode()) for _, value in pairs),
        ) if pairs else self.facts["maximum_attribute_value_bytes"]

        if len(self.stack) == 1:
            self.facts["root"] = {"qname": name, **attributes}

            if name != self.namespace + "|Weakness_Catalog" or (
                attributes.get("Version") != self.version
            ):
                raise ValueError("original root namespace/catalog version disagrees")

            if not attributes.get("Name") or len(attributes["Name"].encode()) > 256:
                raise ValueError("original root Name is outside its nonempty 256-byte profile")

            day = attributes.get("Date", "")

            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", day):
                raise ValueError("original root Date is not a canonical calendar day")

            date.fromisoformat(day)
            self.facts["publisher_date_precision"] = "day; no publisher instant inferred"

        kind = name.removeprefix(self.namespace + "|")

        if kind in self.facts["kind_counts"]:
            collection = {"Weakness": "Weaknesses", "Category": "Categories",
                          "Grouping": "Groupings", "View": "Views"}[kind]

            if len(self.stack) != 3 or self.stack[-2] != self.namespace + "|" + collection:
                raise ValueError("recognized CWE source kind occurs at a wrong qualified path")

            identifier = attributes.get("ID", "")

            if not re.fullmatch(r"[1-9][0-9]{0,9}", identifier) or identifier in self.ids:
                raise ValueError("original entry ID is noncanonical or globally duplicated")

            self.ids.add(identifier)
            self.active_entry = (kind, identifier)
            self.entry_nodes = 1
            self.entry_bytes = size
            self.facts["kind_counts"][kind] += 1
            status = attributes.get("Status")

            if status not in STATUS_VALUES:
                raise ValueError("original source kind Status is outside exact XSD enumeration")

            self.facts["statuses"].add(status)
            self.facts["maximum_name_bytes"] = max(
                self.facts["maximum_name_bytes"], len(attributes.get("Name", "").encode()),
            )

        elif self.active_entry is not None:
            self.entry_bytes += size

    def Node(self) -> None:
        """Count elements, comments and processing instructions with finite global work."""

        self.facts["node_count"] += 1

        if self.facts["node_count"] > 1000000:
            raise ValueError("original XML exceeds proposed global node ceiling")

        if self.active_entry is not None:
            self.entry_nodes += 1

    def End(self, name: str) -> None:
        """Finalize per-entry observations without retaining a source tree."""

        self.facts["callback_counts"]["end_element"] += 1

        if not self.empty_stack[-1]:
            self.Markup()

        if self.active_entry is not None and len(self.stack) == 3:
            self.facts["maximum_entry_nodes"] = max(
                self.facts["maximum_entry_nodes"], self.entry_nodes,
            )
            self.facts["maximum_entry_text_attribute_bytes"] = max(
                self.facts["maximum_entry_text_attribute_bytes"], self.entry_bytes,
            )
            self.active_entry = None

        self.stack.pop()
        self.empty_stack.pop()

    def AddText(self, value: str) -> None:
        """Count normalized UTF-8 text cumulatively regardless of callback segmentation."""

        size = len(value.encode())
        self.facts["text_bytes"] += size

        if self.active_entry is not None:
            self.entry_bytes += size

    def Text(self, value: str) -> None:
        """Measure character data and actual live references, excluding literal CDATA."""

        self.facts["callback_counts"]["character_data"] += 1
        self.AddText(value)

        if not self.in_cdata and self.window.startswith(b"&", self.RawOffset()):
            match = REFERENCE_PATTERN.match(self.window, self.RawOffset())

            if match is None:
                raise ValueError("original live reference exceeds bounded proposed spelling")

            self.facts["maximum_reference_bytes"] = max(
                self.facts["maximum_reference_bytes"], len(match.group()),
            )

    def Comment(self, value: str) -> None:
        """Count complete comment tokens without treating their literal text as declarations."""

        self.facts["callback_counts"]["comment"] += 1
        self.Node()
        self.AddText(value)
        offset = self.RawOffset()
        end = self.window.find(b"-->", offset, offset + 65536)

        if end < 0:
            raise ValueError("comment exceeds bounded research diagnostic window")

        self.facts["maximum_comment_pi_bytes"] = max(
            self.facts["maximum_comment_pi_bytes"], end + 3 - offset,
        )
        raw = self.window[offset:end + 3]
        lower = raw.lower()

        if b"copyright" in lower and b"mitre" in lower and len(self.notice_excerpts) < 4:
            self.notice_excerpts.append(raw)
            self.facts["notice_candidates"].append({
                "kind": "original XML comment containing copyright and MITRE",
                "start_byte": self.parser.CurrentByteIndex,
                "end_byte": self.parser.CurrentByteIndex + len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "contains_license_word": b"license" in lower,
                "contains_terms_url": b"cwe.mitre.org/about/termsofuse.html" in lower,
                "legal_coverage_assessed": False})

    def Instruction(self, target: str, value: str) -> None:
        """Count PI target/content without interpreting or resolving them."""

        self.facts["callback_counts"]["instruction"] += 1
        self.Node()
        self.AddText(target + value)
        self.facts["maximum_raw_qname_bytes"] = max(
            self.facts["maximum_raw_qname_bytes"], len(target.encode()),
        )
        self.DeclarationToken()

    def DeclarationToken(self) -> None:
        """Measure the current PI/XML-declaration token through its exact terminator."""

        offset = self.RawOffset()
        end = self.window.find(b"?>", offset, offset + 65536)

        if end < 0:
            raise ValueError("PI/declaration exceeds bounded research diagnostic window")

        self.facts["maximum_comment_pi_bytes"] = max(
            self.facts["maximum_comment_pi_bytes"], end + 2 - offset,
        )

    def Declaration(self, version: str, encoding: str | None, standalone: int) -> None:
        """Require the observed XML 1.0 UTF-8 declaration without treating it as a timestamp."""

        self.facts["callback_counts"]["declaration"] += 1
        self.DeclarationToken()
        self.facts["declaration"] = [version, encoding, standalone]

        if version != "1.0" or encoding is not None and encoding.lower() != "utf-8":
            raise ValueError("original declaration is outside the finite UTF-8 XML profile")

    def Forbidden(self, *arguments: object) -> None:
        """Refuse DTD/entity/external resolution instead of fetching any secondary input."""

        self.facts["callback_counts"]["forbidden"] += 1
        raise ValueError("DTD/entity/external content is forbidden in research measurement")

    def StartCdata(self) -> None:
        """Keep CDATA reference-looking bytes literal."""

        self.facts["callback_counts"]["cdata_start"] += 1
        self.in_cdata = True

    def EndCdata(self) -> None:
        """Restore ordinary text reference measurement after CDATA closes."""

        self.facts["callback_counts"]["cdata_end"] += 1
        self.in_cdata = False

    def Feed(self, chunk: bytes) -> None:
        """Feed bounded known-pinned research bytes without storing the expanded catalog."""

        self.decoder.decode(chunk, final=False)

        if b"\0" in chunk:
            raise ValueError("NUL is outside the finite XML profile")

        self.received += len(chunk)
        self.window = (self.window + chunk)[-2 * CHUNK_BYTES:]
        self.window_start = self.received - len(self.window)
        self.parser.Parse(chunk, False)

    def Finish(self) -> dict:
        """Require complete XML before exposing observed counters as complete facts."""

        self.decoder.decode(b"", final=True)
        self.parser.Parse(b"", True)

        if self.stack or self.empty_stack or self.in_cdata or self.pending_namespaces:
            raise ValueError("XML source finished with pending structural state")

        self.facts["statuses"] = sorted(self.facts["statuses"])
        self.facts["entry_count"] = len(self.ids)
        self.facts["xml_complete"] = True

        return self.facts


def DecodeFacts(payload: bytes, start: int, end: int, collector: XmlMeasurements) -> dict:
    """Consume the complete bounded raw-deflate range; never flush or return early on matches."""

    decoder = zlib.decompressobj(-15)
    digest = hashlib.sha256()
    crc = 0
    decoded = 0
    xml_error = None
    notice_tail = b""
    notice_hits = {name: [] for name in ("copyright", "mitre", "license", "termsofuse.html")}

    def Emit(chunk: bytes) -> None:
        """Account for bounded output before any diagnostic XML interpretation."""

        nonlocal decoded, crc, xml_error, notice_tail
        window = notice_tail + chunk
        lower = window.lower()
        base = decoded - len(notice_tail)

        for word, hits in notice_hits.items():
            position = lower.find(word.encode("ascii"))

            while position >= 0 and len(hits) < 16:
                absolute = base + position

                if absolute not in hits:
                    hits.append(absolute)

                position = lower.find(word.encode("ascii"), position + len(word))

        notice_tail = window[-64:]
        decoded += len(chunk)

        if decoded > MAX_XML_BYTES:
            raise ValueError("actual expanded source exceeds fixed 32 MiB ceiling")

        digest.update(chunk)
        crc = zlib.crc32(chunk, crc)

        if xml_error is None:
            try:
                collector.Feed(chunk)

            except (ValueError, expat.ExpatError) as error:
                xml_error = str(error)

    for offset in range(start, end, CHUNK_BYTES):
        pending = payload[offset:min(end, offset + CHUNK_BYTES)]

        while pending:
            before = len(pending)
            chunk = decoder.decompress(pending, CHUNK_BYTES)
            pending = decoder.unconsumed_tail

            if not chunk and len(pending) == before:
                raise ValueError("raw-deflate drain made no progress")

            Emit(chunk)

    while not decoder.eof:
        chunk = decoder.decompress(b"", CHUNK_BYTES)

        if not chunk and not decoder.eof:
            raise ValueError("raw-deflate source ended before bounded drain completed")

        Emit(chunk)

    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("raw-deflate input is truncated or contains unused/trailing bytes")

    result = {"actual_decoded_size": decoded, "actual_decoded_sha256": digest.hexdigest(),
              "actual_crc32": f"{crc:08x}", "deflate_eof": True, "unused_data_bytes": 0,
              "max_compressed_input_chunk": CHUNK_BYTES, "max_output_chunk": CHUNK_BYTES,
              "flush_calls": 0, "xml_error": xml_error,
              "original_xml_notice_keyword_offsets": notice_hits,
              "notice_keyword_presence_is_not_legal_coverage": True}

    if xml_error is None:
        try:
            result["xml"] = collector.Finish()

        except (ValueError, expat.ExpatError) as error:
            result["xml_error"] = str(error)

    if result["xml_error"] is not None:
        result["xml_partial_observations"] = {**collector.facts,
            "statuses": sorted(collector.facts["statuses"]), "xml_complete": False}

    return result


def RuntimeFacts() -> dict:
    """Probe declaration, namespace and reparse behavior on small owned fixtures only."""

    parser = expat.ParserCreate(encoding="UTF-8", namespace_separator="|")
    declarations = []
    parser.XmlDeclHandler = lambda *items: declarations.append(items)
    parser.Parse(b'<?xml version="1.0" encoding="ISO-8859-1"?><r/>', True)
    guarded = XmlMeasurements("5.0", "http://cwe.mitre.org/cwe-8")
    refused = False

    try:
        guarded.Feed(b'<?xml version="1.0" encoding="ISO-8859-1"?><r/>')

    except ValueError as error:
        refused = "original declaration is outside" in str(error)

    return {"python": sys.version, "expat": expat.EXPAT_VERSION,
            "get_reparse_api": hasattr(parser, "GetReparseDeferralEnabled"),
            "set_reparse_api": hasattr(parser, "SetReparseDeferralEnabled"),
            "reparse_default_enabled": parser.GetReparseDeferralEnabled(),
            "forced_utf8_alone_accepts_conflicting_ascii_declaration": bool(declarations),
            "explicit_declaration_guard_refuses_conflict": refused,
            "buffer_text_default": parser.buffer_text}


def WorstSelectedEncodingFacts() -> dict:
    """Prove that 64 legal bounded escaped names need an independent normalized-byte ceiling."""

    records = [{"identifier": f"CWE-{index}", "source_kind": "Weakness", "status": "Stable",
        "name": "\\" * 8189 + f"{index:03d}"} for index in range(1, 65)]
    document = {"records": records, "profile": "owned worst-case selected encoding fixture"}
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                               allow_nan=False)
    total = 0
    largest = 0
    digest = hashlib.sha256()

    for text in encoder.iterencode(document):
        encoded = text.encode("utf-8")
        total += len(encoded)
        largest = max(largest, len(encoded))
        digest.update(encoded)

    return {"kind": "owned fixture, not official normalized source acceptance",
            "records": 64, "name_bytes_each": 8192, "encoded_bytes": total,
            "encoded_sha256": digest.hexdigest(), "maximum_encoder_chunk": largest,
            "one_mib_cap_exceeded": total > 1024 * 1024, "full_result_buffer_retained": False}


def PolicyViolations(facts: dict) -> list[str]:
    """Compare actual research measurements with each independent proposed finite ceiling."""

    ceilings = {"entry_count": 10000, "node_count": 1000000, "text_bytes": 24 * 1024 * 1024,
        "attribute_bytes": 4 * 1024 * 1024, "maximum_depth": 32, "maximum_attributes": 32,
        "maximum_raw_qname_bytes": 256, "maximum_attribute_value_bytes": 8192,
        "maximum_entry_nodes": 65536, "maximum_entry_text_attribute_bytes": 1024 * 1024,
        "maximum_markup_token_bytes": 65536, "maximum_comment_pi_bytes": 65536,
        "maximum_reference_bytes": 10, "maximum_name_bytes": 8192}

    return [name for name, maximum in ceilings.items() if facts.get(name, maximum + 1) > maximum]


@pytest.mark.integration
@pytest.mark.timeout(170)
def test_OfficialCweSourcePrerequisites():
    """Retain actual four-source research proof only when the dedicated opt-in job enables it."""

    if os.environ.get("FUZZY1337_RUN_CWE_PREREQUISITES") != "1":
        pytest.skip("official CWE prerequisite research is disabled; no source proof executed")

    report = {"schema_version": 1, "purpose": "bounded prerequisite research; not SDK acceptance",
              "sources": [], "schemas": [], "archives": [], "runtime": RuntimeFacts(),
              "full_xsd_validation": "not-performed", "model_writes": 0,
              "data_terms_url": "https://cwe.mitre.org/about/termsofuse.html",
              "publisher_authentication": "not-assessed", "legal_rights": "not-assessed",
              "notice_coverage": "raw presence/spans only; applicable legal coverage not assessed",
              "data_spdx_identifier": None,
              "worst_selected_encoding": WorstSelectedEncodingFacts()}
    errors = []

    try:
        for version, namespace, name, digest in SCHEMAS:
            payload, source = FetchInput(name, digest, 524288, schema=True)
            report["sources"].append(source)
            SaveFacts("facts.json", report)

            if source["state"] != "pin-matched":
                errors.append(name + ": source pin was not verified")
                continue

            try:
                facts, excerpt = SchemaFacts(payload, version, namespace)
                target = "StatusEnumeration-v" + version + ".xsd.fragment"
                (ResearchOutput() / target).write_bytes(excerpt)
                report["schemas"].append({**facts, "extract_file": target})

            except (ValueError, element_tree.ParseError) as error:
                errors.append(name + ": " + str(error))

        for version, namespace, name, digest in ARCHIVES:
            payload, source = FetchInput(name, digest, MAX_ZIP_BYTES, schema=False)
            report["sources"].append(source)
            SaveFacts("facts.json", report)

            if source["state"] != "pin-matched":
                errors.append(name + ": source pin was not verified")
                continue

            try:
                archive, start, end = ArchiveFacts(payload, name.removesuffix(".zip"))
                collector = XmlMeasurements(version, namespace)
                decoded = DecodeFacts(payload, start, end, collector)

                for index, excerpt in enumerate(collector.notice_excerpts):
                    target = ResearchOutput() / (name + f".notice-{index}.xml.fragment")
                    target.write_bytes(excerpt)

                observations = {**archive, **decoded, "catalog_version": version}
                report["archives"].append(observations)

                if decoded["actual_decoded_size"] != archive["declared_decoded_size"] or (
                    decoded["actual_crc32"] != archive["declared_crc32"]
                ):
                    errors.append(name + ": actual decoded size/CRC disagrees with declared header")

                if decoded["xml_error"] is not None:
                    errors.append(name + ": " + decoded["xml_error"])

                else:
                    violations = PolicyViolations(decoded["xml"])
                    observations["xml_policy_violations"] = violations
                    errors.extend(name + ": proposed XML ceiling " + value for value in violations)

                errors.extend(name + ": " + value for value in archive["policy_violations"])

            except (ValueError, struct.error, zlib.error) as error:
                errors.append(name + ": " + str(error))

        report["errors"] = errors
        report["state"] = "research-verified" if not errors else "research-refused"

    finally:
        SaveFacts("facts.json", report)

    assert not errors, (
        "CWE prerequisite research refused; inspect retained facts: " + "; ".join(errors)
    )


def SyntheticArchive(xml: bytes, *, extra: bytes = b"") -> bytes:
    """Create one owned regular-file deflate ZIP, never an external catalog or security target."""

    output = io.BytesIO()
    item = zipfile.ZipInfo("cwec_v5.0.xml")
    item.compress_type = zipfile.ZIP_DEFLATED
    item.create_system = 3
    item.external_attr = 0o100644 << 16
    item.extra = extra

    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(item, xml)

    return output.getvalue()


def SyntheticXml() -> bytes:
    """Return a tiny owned catalog with namespace declarations and distinct source kinds."""

    return (b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8" xmlns:h="urn:owned-html" '
        b'Name="Owned" Version="5.0" Date="2026-11-03"><Weaknesses>'
        b'<Weakness ID="79" Name="Owned &amp; exact" Status="Stable">'
        b'<Description>Owned &#x41; text \xc3\xa9<h:b>literal</h:b><![CDATA[&not-a-reference;]]>'
        b'</Description></Weakness></Weaknesses><Categories>'
        b'<Category ID="1" Name="Owned category" Status="Usable"/></Categories>'
        b'<Groupings><Grouping ID="2" Name="Owned grouping" Status="Draft"/></Groupings>'
        b'<Views><View ID="3" Name="Owned view" Status="Obsolete"/></Views></Weakness_Catalog>')


def test_ResearchMeasurementConsumesWholeOwnedFrameAndXmlWithoutExtraction():
    """Actual bounded deflate/CRC/XML composition retains distinct kinds and callback maxima."""

    xml = SyntheticXml()
    payload = SyntheticArchive(xml, extra=struct.pack("<HHI", 0x5455, 4, 0))
    frame, start, end = ArchiveFacts(payload, "cwec_v5.0.xml")
    facts = DecodeFacts(payload, start, end, XmlMeasurements("5.0", "http://cwe.mitre.org/cwe-8"))
    assert facts["deflate_eof"] and facts["actual_crc32"] == frame["declared_crc32"], (
        "Owned research probe lost complete raw-deflate EOF/CRC proof"
    )
    assert facts["actual_decoded_sha256"] == hashlib.sha256(xml).hexdigest(), (
        "Owned research probe changed original expanded source bytes"
    )
    expected = {"Weakness": 1, "Category": 1, "Grouping": 1, "View": 1}
    assert facts["xml"]["kind_counts"] == expected, (
        "Known source kinds were relabeled or omitted by diagnostic counters"
    )
    assert facts["xml"]["maximum_reference_bytes"] == 6, "Live reference measurement changed"
    assert facts["xml"]["namespace_declarations"] == 2, "xmlns declarations were not counted"
    assert not PolicyViolations(facts["xml"]), "Tiny fixture exceeded proposed source ceilings"


@pytest.mark.parametrize("mutation", ["trailer", "wrong-name", "crc", "truncate"])
def test_ResearchMeasurementRefusesIncompleteOrContradictoryOwnedSources(mutation):
    """Synthetic corrupt frames cannot establish real-source completion evidence."""

    payload = SyntheticArchive(SyntheticXml())

    if mutation == "trailer":
        payload += b"trailing"

    elif mutation == "wrong-name":
        payload = payload.replace(b"cwec_v5.0.xml", b"other_v5.xmlx")

    elif mutation == "crc":
        payload = bytearray(payload)
        payload[14] ^= 1
        payload = bytes(payload)

    else:
        payload = payload[:-1]

    with pytest.raises((ValueError, struct.error)):
        ArchiveFacts(payload, "cwec_v5.0.xml")


def test_ResearchMeasurementsAreIndependentOfXmlFeedBoundaries():
    """Cumulative facts omit callback-call segmentation and preserve actual parsed source fields."""

    results = []

    for size in (1, 7, CHUNK_BYTES):
        collector = XmlMeasurements("5.0", "http://cwe.mitre.org/cwe-8")
        payload = SyntheticXml()

        for offset in range(0, len(payload), size):
            collector.Feed(payload[offset:offset + size])

        facts = collector.Finish()
        facts["callback_counts"].pop("character_data")
        results.append(facts)

    assert results[0] == results[1] == results[2], "Counters depend on XML chunk boundaries"


def test_RuntimeProbeRequiresExplicitDeclarationGuardAndReparseCapability():
    """Forced UTF-8 is insufficient declaration policy; the proposed runtime APIs must exist."""

    facts = RuntimeFacts()
    assert (facts["get_reparse_api"] and facts["set_reparse_api"]
            and facts["reparse_default_enabled"]), (
        "Supported runtime lacks enabled Expat reparse-deferral APIs"
    )
    assert facts["forced_utf8_alone_accepts_conflicting_ascii_declaration"], (
        "Runtime declaration behavior changed; reassess the finite profile guard"
    )
    assert facts["explicit_declaration_guard_refuses_conflict"], (
        "Diagnostic XML declaration guard silently accepted a conflicting source encoding"
    )


@pytest.mark.parametrize("bad", ["utf8", "nul", "declaration", "doctype"])
def test_DiagnosticRuntimeGuardsRejectOwnedXmlFailures(bad):
    """Observed callback and UTF-8 defenses deny source failures without any resolver or network."""

    payload = SyntheticXml()

    if bad == "utf8":
        payload = payload.replace(b"Owned &#x41;", b"Owned \xff")

    elif bad == "nul":
        payload = payload.replace(b"Owned &#x41;", b"Owned \0")

    elif bad == "declaration":
        payload = payload.replace(b'encoding="UTF-8"', b'encoding="ISO-8859-1"')

    else:
        payload = payload.replace(b"?>", b"?><!DOCTYPE Weakness_Catalog []>", 1)

    collector = XmlMeasurements("5.0", "http://cwe.mitre.org/cwe-8")

    with pytest.raises((ValueError, UnicodeError, expat.ExpatError)):
        collector.Feed(payload)
        collector.Finish()


def test_ActualEscapedSelectedEncodingCanExceedOneMiBWithoutUnboundedResultBuffer():
    """Per-field and item ceilings do not prove the final normalized transport byte ceiling."""

    facts = WorstSelectedEncodingFacts()
    assert facts["one_mib_cap_exceeded"] and not facts["full_result_buffer_retained"], (
        "Owned selected-encoding fixture failed to exercise the real normalized-byte denial"
    )


@pytest.mark.parametrize("size", [CHUNK_BYTES, 2 * CHUNK_BYTES])
def test_BoundedDeflateDrainAcceptsExactOutputChunkBoundaries(size):
    """Exact bounded output boundaries preserve complete original deflate streams."""

    original = SyntheticXml()
    marker = b"Owned &#x41; text"
    xml = original.replace(marker, b"x" * (size - len(original) + len(marker)))
    payload = SyntheticArchive(xml)
    frame, start, end = ArchiveFacts(payload, "cwec_v5.0.xml")
    facts = DecodeFacts(payload, start, end, XmlMeasurements("5.0", "http://cwe.mitre.org/cwe-8"))
    assert facts["actual_decoded_size"] == size and facts["deflate_eof"], (
        "Exact bounded output boundary lost complete deflate EOF"
    )
    assert facts["actual_crc32"] == frame["declared_crc32"] and facts["xml_error"] is None, (
        "Exact output boundary lost original CRC or complete XML measurement"
    )


def test_FetchAdmissionCannotBroadenTheFourLiteralInputs():
    """Refuse changed literal source admission before opening a connection."""

    with pytest.raises(ValueError, match="four fixed"):
        FetchInput("cwe_schema_v8.0.xsd", "0" * 64, 524288, schema=True)


def test_ResearchDeadlineRefusesAnEmptyEofReadThatCompletesTooLate(monkeypatch):
    """A fixed-source socket fixture cannot promote a late EOF to successful source proof."""

    connection = Mock()
    response = connection.getresponse.return_value
    response.status = 200
    response.getheader.side_effect = lambda name: "0" if name == "Content-Length" else None
    response.read1.return_value = b""
    monkeypatch.setattr(http.client, "HTTPSConnection", lambda *args, **kwargs: connection)
    ticks = iter((0, 0, 16, 16))
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks))
    _, facts = FetchInput(SCHEMAS[0][2], SCHEMAS[0][3], 524288, schema=True)
    assert facts["state"] == "research-refused" and "deadline" in facts["reason"], (
        "Late final EOF became successful original-source proof"
    )
    assert facts["elapsed_seconds"] == 16, "Late-read refusal lost observed elapsed time"


@pytest.mark.parametrize("field,value", [
    (b'Name="Owned"', b'Name=""'), (b'Date="2026-11-03"', b'Date="2026-02-30"'),
    (b'Date="2026-11-03"', b'Date="2026-11-03T00:00:00Z"'),
    (b'Status="Stable"', b'Status="Unknown"'),
])
def test_ConsumedRootAndStatusFieldsHaveExplicitFiniteAdmission(field, value):
    """Raw field visibility alone does not establish consumed-field compatibility."""

    collector = XmlMeasurements("5.0", "http://cwe.mitre.org/cwe-8")

    with pytest.raises(ValueError):
        collector.Feed(SyntheticXml().replace(field, value, 1))
        collector.Finish()


def test_RawQnameMetricRetainsSourcePrefixesWithoutCountingQuotedAttributeText():
    """Namespace expansion is reported separately from original lexical name lengths."""

    prefix = b"p" * 80
    payload = SyntheticXml().replace(b"xmlns:h", b"xmlns:" + prefix)
    payload = payload.replace(b"h:b", prefix + b":b")
    payload = payload.replace(b'Name="Owned &amp; exact"', b'Name="literal long_fake_name=value"')
    collector = XmlMeasurements("5.0", "http://cwe.mitre.org/cwe-8")
    collector.Feed(payload)
    facts = collector.Finish()
    assert facts["maximum_raw_qname_bytes"] == len(b"xmlns:" + prefix), (
        "Original namespace-prefix declarations vanished from raw QName measurement"
    )
    assert facts["maximum_expanded_name_bytes"] < facts["maximum_raw_qname_bytes"], (
        "Raw and expanded source-name measurements were conflated"
    )
