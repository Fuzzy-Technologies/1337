# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal bounded XML lexical gate and consumed-field collector for selected CWE catalogs."""

from __future__ import annotations

import codecs
import re
import xml.parsers.expat as expat
from dataclasses import dataclass
from typing import Never

from fuzzy1337.intelligence import IntelligenceDate, IntelligenceIdentifier

__all__ = ()

MAX_XML_BYTES = 32 * 1024 * 1024
CHUNK_BYTES = 65536
MAX_TOKEN_BYTES = 65536
MAX_REFERENCE_BYTES = 10
MAX_ENTRIES = 10000
MAX_NODES = 1000000
MAX_DEPTH = 32
MAX_TEXT_BYTES = 24 * 1024 * 1024
MAX_ATTRIBUTE_BYTES = 4 * 1024 * 1024
MAX_ATTRIBUTES = 32
MAX_QNAME_BYTES = 256
MAX_VALUE_BYTES = 8192
MAX_ENTRY_NODES = 65536
MAX_ENTRY_BYTES = 1024 * 1024
STATUS_VALUES = ("Deprecated", "Draft", "Incomplete", "Obsolete", "Stable", "Usable")
MODES = {"5.0": ("8.0", "http://cwe.mitre.org/cwe-8", "cwec_v5.0.xml"),
         "4.21": ("7.4", "http://cwe.mitre.org/cwe-7", "cwec_v4.21.xml")}
_TEXT_SPECIAL = re.compile(br"[<&]")
_TAG_SPECIAL = re.compile(br"[\"'>&<]")
_REFERENCE = re.compile(br"&(?:amp|lt|gt|apos|quot|#[0-9]{1,7}|#x[0-9A-Fa-f]{1,6});\Z")
_RAW_NAME = re.compile(br"[^\x20\x09\x0a\x0d=/>]+")
_NONSPACE = re.compile(br"[^\x20\x09\x0a\x0d]")
_SPACE = b" \t\r\n"
_XINCLUDE = "http://www.w3.org/2001/XInclude|"


def NextNonspace(token: bytes, position: int) -> int:
    """Skip one lexical whitespace run using a forward C-level search.

    Args:
        token: Already bounded complete markup bytes.
        position: First candidate whitespace byte.

    Returns:
        Index of the next nonspace byte, or the token end.
    """

    match = _NONSPACE.search(token, position)

    return match.start() if match else len(token)


def CweName(value: object, maximum: int = MAX_VALUE_BYTES) -> str:
    """Preserve a nonempty printable XML attribute value without prose normalization.

    Args:
        value: Exact string produced by XML or a direct DTO constructor.
        maximum: Fixed caller-owned UTF-8 byte ceiling.

    Returns:
        Unchanged name; leading and trailing printable spaces are retained.
    """

    if type(value) is not str or not value or len(value) > maximum or not value.isprintable():
        raise ValueError("CWE name must be nonempty printable exact text")

    try:
        size = len(value.encode("utf-8"))

    except UnicodeError as error:
        raise ValueError("CWE name must be valid UTF-8") from error

    if size > maximum:
        raise ValueError("CWE name exceeds its byte profile")

    return value


@dataclass(frozen=True, slots=True)
class CweXmlFacts:
    """Hold only completed Internal XML observations and immutable selected source fields."""

    records: tuple[tuple[str, str, str], ...]
    unsupported: tuple[tuple[str, str], ...]
    catalog_name: str
    catalog_date: str
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


class CweXmlCollector:
    """Consume complete gated XML without a tree, network resolver or public DTO callback."""

    def __init__(self, catalog_version: str, requested_ids: tuple[str, ...]) -> None:
        """Initialize one fixed mode and bounded selection with required safe runtime behavior.

        Args:
            catalog_version: Exactly 5.0 or 4.21, never a moving source alias.
            requested_ids: Already admitted immutable explicit canonical selection.
        """

        if type(catalog_version) is not str or catalog_version not in MODES:
            raise ValueError("CWE requires a supported exact catalog mode")

        self.namespace = MODES[catalog_version][1]
        self.version = catalog_version
        self.requested = frozenset(requested_ids)
        self.parser = expat.ParserCreate(encoding="UTF-8", namespace_separator="|")

        if not (hasattr(self.parser, "GetReparseDeferralEnabled")
                and hasattr(self.parser, "SetReparseDeferralEnabled")
                and self.parser.GetReparseDeferralEnabled()):
            raise ValueError("CWE requires enabled Expat reparse deferral")

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
        self.utf8 = codecs.getincrementaldecoder("utf-8")("strict")
        self.state = "text"
        self.pending = bytearray()
        self.reference = bytearray()
        self.reference_return = "text"
        self.quote: int | None = None
        self.cdata_tail = b""
        self.stack: list[str] = []
        self.namespaces: list[tuple[str, str]] = []
        self.collections: set[str] = set()
        self.identities: set[str] = set()
        self.records: list[tuple[str, str, str]] = []
        self.unsupported: list[tuple[str, str]] = []
        self.counts = {kind: 0 for kind in ("Weakness", "Category", "Grouping", "View")}
        self.catalog_name = ""
        self.catalog_date = ""
        self.root_closed = False
        self.finished = False
        self.received = 0
        self.nodes = 0
        self.text_bytes = 0
        self.attribute_bytes = 0
        self.depth = 0
        self.entry_active = False
        self.entry_nodes = 0
        self.entry_bytes = 0
        self.max_entry_nodes = 0
        self.max_entry_bytes = 0
        self.max_markup = 0
        self.max_comment_pi = 0
        self.max_reference = 0

    def Parse(self, payload: bytes) -> None:
        """Feed only admitted bytes while translating parser details to a fixed refusal category.

        Args:
            payload: Complete bounded token or streaming text/CDATA segment.
        """

        if not payload:
            return

        try:
            self.parser.Parse(payload, False)

        except expat.ExpatError as error:
            raise ValueError("CWE XML is not well formed") from error

    def Append(self, payload: bytes) -> None:
        """Check the token ceiling before extending its sole bounded pending buffer.

        Args:
            payload: Next original token segment, unchanged.
        """

        if len(self.pending) + len(payload) > MAX_TOKEN_BYTES:
            raise ValueError("CWE XML token exceeds its byte profile")

        self.pending.extend(payload)

    def TagNames(self, token: bytes) -> None:
        """Bound raw QName and attribute counts before Expat allocates a start-event mapping.

        Args:
            token: Complete ordinary start/end markup admitted by the gate.
        """

        position = 2 if token.startswith(b"</") else 1
        attributes = -1

        while position < len(token):
            match = _RAW_NAME.match(token, position)

            if match is None or match.end() - position > MAX_QNAME_BYTES:
                raise ValueError("CWE XML raw QName exceeds its profile")

            attributes += 1

            if attributes > MAX_ATTRIBUTES:
                raise ValueError("CWE XML attribute count exceeds its profile")

            position = NextNonspace(token, match.end())

            if token[position:position + 1] == b"=":
                position = NextNonspace(token, position + 1)

                quote = token[position:position + 1]

                if quote not in (b"'", b'"'):
                    raise ValueError("CWE XML attribute value must be quoted")

                position = token.find(quote, position + 1) + 1

                if position == 0:
                    raise ValueError("CWE XML attribute quote is incomplete")

                position = NextNonspace(token, position)

            if token[position:position + 1] in (b"/", b">"):
                return

        raise ValueError("CWE XML markup is incomplete")

    def BeginReference(self, return_state: str) -> None:
        """Withhold a live reference until its complete bounded spelling is known.

        Args:
            return_state: Internal text or quoted-tag state to resume on completion.
        """

        self.reference = bytearray(b"&")
        self.reference_return = return_state
        self.state = "reference"

    def ReferenceByte(self, value: int) -> None:
        """Refuse impossible or oversized reference prefixes before any reach Expat.

        Args:
            value: One next original source byte; the loop spans at most ten bytes.
        """

        if len(self.reference) >= MAX_REFERENCE_BYTES:
            raise ValueError("CWE XML reference exceeds its byte profile")

        self.reference.append(value)
        raw = bytes(self.reference)

        if value == 59:
            if not _REFERENCE.fullmatch(raw):
                raise ValueError("CWE XML reference spelling is unsupported")

            self.max_reference = max(self.max_reference, len(raw))
            self.state = self.reference_return

            if self.state == "tag":
                self.Append(raw)

            else:
                self.Parse(raw)

            self.reference.clear()

            return

        prefix = raw[1:]
        builtin = any(word.startswith(prefix)
                      for word in (b"amp;", b"lt;", b"gt;", b"apos;", b"quot;"))
        numeric = bool(re.fullmatch(br"#(?:[0-9]{0,7}|x[0-9A-Fa-f]{0,6})", prefix))

        if not builtin and not numeric:
            raise ValueError("CWE XML reference prefix is unsupported")

    def Delimited(self, chunk: bytes, position: int, terminator: bytes) -> int:
        """Scan only new bytes and a delimiter suffix for one bounded comment or PI token.

        Args:
            chunk: Current decoded bounded chunk.
            position: First unconsumed byte in that chunk.
            terminator: Fixed comment or processing-instruction terminator.

        Returns:
            First unconsumed byte after the segment or completed token.
        """

        suffix = bytes(self.pending[-(len(terminator) - 1):])
        boundary = suffix + chunk[position:position + len(terminator) - 1]
        crossing = boundary.find(terminator)
        found = -1 if crossing >= 0 else chunk.find(terminator, position)

        if crossing >= 0:
            consumed = crossing + len(terminator) - len(suffix)

        elif found >= 0:
            consumed = found + len(terminator) - position

        else:
            self.Append(chunk[position:])

            return len(chunk)

        self.Append(chunk[position:position + consumed])
        token = bytes(self.pending)
        self.max_comment_pi = max(self.max_comment_pi, len(token))

        self.Parse(token)
        self.pending.clear()
        self.state = "text"

        return position + consumed

    def Cdata(self, chunk: bytes, position: int) -> int:
        """Stream literal CDATA while retaining at most its two-byte delimiter suffix.

        Args:
            chunk: Current decoded bounded chunk.
            position: First unconsumed byte.

        Returns:
            First unconsumed byte after the streaming segment or closing delimiter.
        """

        boundary = self.cdata_tail + chunk[position:position + 2]
        crossing = boundary.find(b"]]>")
        found = -1 if crossing >= 0 else chunk.find(b"]]>", position)

        if crossing >= 0 or found >= 0:
            consumed = (crossing + 3 - len(self.cdata_tail) if crossing >= 0
                        else found + 3 - position)
            self.Parse(self.cdata_tail + chunk[position:position + consumed])
            self.cdata_tail = b""
            self.state = "text"

            return position + consumed

        candidate = self.cdata_tail + chunk[position:]
        split = max(0, len(candidate) - 2)
        self.Parse(candidate[:split])
        self.cdata_tail = candidate[split:]

        return len(chunk)

    def Feed(self, chunk: bytes) -> None:
        """Gate original UTF-8 bytes with linear scans and finite token/reference state.

        Args:
            chunk: Exact bytes of at most 64 KiB from the bounded ZIP owner.
        """

        if self.finished or type(chunk) is not bytes or len(chunk) > CHUNK_BYTES:
            raise ValueError("CWE XML feed requires unfinished bounded exact bytes")

        self.received += len(chunk)

        if self.received > MAX_XML_BYTES or b"\0" in chunk:
            raise ValueError("CWE XML bytes exceed their finite UTF-8 profile")

        try:
            self.utf8.decode(chunk, final=False)

        except UnicodeError as error:
            raise ValueError("CWE XML must be strict UTF-8") from error

        position = 0

        while position < len(chunk):
            if self.state == "text":
                match = _TEXT_SPECIAL.search(chunk, position)
                end = match.start() if match else len(chunk)
                self.Parse(chunk[position:end])
                position = end

                if match is None:
                    continue

                if chunk[position] == 38:
                    self.BeginReference("text")

                else:
                    self.pending = bytearray(b"<")
                    self.state = "open"

                position += 1

            elif self.state == "reference":
                self.ReferenceByte(chunk[position])
                position += 1

            elif self.state == "open":
                value = chunk[position]

                if value == 33:
                    self.Append(b"!")
                    self.state = "declaration"
                    position += 1

                elif value == 63:
                    self.Append(b"?")
                    self.state = "pi-open"
                    position += 1

                else:
                    self.state = "tag"
                    self.quote = None

            elif self.state == "pi-open":
                self.Append(chunk[position:position + 1])
                position += 1
                prefix = bytes(self.pending)

                if len(prefix) == 6 and prefix[:5] == b"<?xml" and prefix[5] in _SPACE:
                    self.state = "xml-declaration"
                    self.quote = None

                elif not b"<?xml".startswith(prefix):
                    self.state = "pi"

            elif self.state == "declaration":
                self.Append(chunk[position:position + 1])
                position += 1
                prefix = bytes(self.pending)

                if prefix == b"<!--":
                    self.state = "comment"

                elif prefix == b"<![CDATA[":
                    self.Parse(prefix)
                    self.pending.clear()
                    self.state = "cdata"

                elif not (b"<!--".startswith(prefix) or b"<![CDATA[".startswith(prefix)):
                    raise ValueError("CWE XML DTD and declarations are forbidden")

            elif self.state in ("comment", "pi"):
                terminator = b"-->" if self.state == "comment" else b"?>"
                position = self.Delimited(chunk, position, terminator)

            elif self.state == "cdata":
                position = self.Cdata(chunk, position)

            else:
                match = _TAG_SPECIAL.search(chunk, position)
                end = match.start() if match else len(chunk)
                self.Append(chunk[position:end])
                position = end

                if match is None:
                    continue

                value = chunk[position]
                position += 1

                if value == 38:
                    if self.quote is None or self.state == "xml-declaration":
                        raise ValueError("CWE XML references are forbidden in names")

                    self.BeginReference("tag")
                    continue

                self.Append(bytes((value,)))

                if value == self.quote:
                    self.quote = None

                elif value in (34, 39) and self.quote is None:
                    self.quote = value

                elif value == 60:
                    raise ValueError("CWE XML nested markup is malformed")

                elif value == 62 and self.quote is None:
                    token = bytes(self.pending)

                    if self.state == "xml-declaration":
                        if not token.endswith(b"?>"):
                            raise ValueError("CWE XML declaration is malformed")

                        self.max_comment_pi = max(self.max_comment_pi, len(token))

                    else:
                        self.TagNames(token)

                    self.max_markup = max(self.max_markup, len(token))
                    self.Parse(token)
                    self.pending.clear()
                    self.state = "text"

    def Namespace(self, prefix: str | None, uri: str | None) -> None:
        """Account for xmlns values before the ordinary start-attribute callback.

        Args:
            prefix: Original namespace prefix, or default namespace.
            uri: Normalized namespace URI without any resolver activity.
        """

        name = "xmlns" + (":" + prefix if prefix else "")
        value = uri or ""

        if len(name.encode()) > MAX_QNAME_BYTES or len(value.encode()) > MAX_VALUE_BYTES or (
            len(self.namespaces) >= MAX_ATTRIBUTES
        ):
            raise ValueError("CWE XML namespace declarations exceed their profile")

        self.namespaces.append((name, value))

    def Node(self) -> None:
        """Apply global and active-entry node ceilings before incrementing work."""

        if self.nodes >= MAX_NODES or self.entry_active and self.entry_nodes >= MAX_ENTRY_NODES:
            raise ValueError("CWE XML node count exceeds its profile")

        self.nodes += 1

        if self.entry_active:
            self.entry_nodes += 1

    def EntryBytes(self, size: int) -> None:
        """Count active-entry normalized text and attributes across every callback boundary.

        Args:
            size: Next nonnegative UTF-8 byte contribution.
        """

        if self.entry_active:
            if self.entry_bytes + size > MAX_ENTRY_BYTES:
                raise ValueError("CWE XML entry text and attributes exceed their profile")

            self.entry_bytes += size

    def Start(self, name: str, attributes: dict[str, str]) -> None:
        """Validate exact root/collection/kind paths and every consumed source field.

        Args:
            name: Expat expanded namespace-qualified name.
            attributes: Normalized bounded ordinary attributes, excluding xmlns.
        """

        if name.startswith(_XINCLUDE) or len(self.stack) >= MAX_DEPTH:
            raise ValueError("CWE XML XInclude or excessive depth is forbidden")

        if len(name) > MAX_QNAME_BYTES or len(name.encode()) > MAX_QNAME_BYTES or any(
            len(key) > MAX_QNAME_BYTES or len(key.encode()) > MAX_QNAME_BYTES for key in attributes
        ):
            raise ValueError("CWE XML expanded QName exceeds its profile")

        pairs = [*self.namespaces, *attributes.items()]
        self.namespaces.clear()
        size = sum(len(key.encode()) + len(value.encode()) for key, value in pairs)

        if len(pairs) > MAX_ATTRIBUTES or any(len(value.encode()) > MAX_VALUE_BYTES
                                            for _, value in pairs) or (
            self.attribute_bytes + size > MAX_ATTRIBUTE_BYTES
        ):
            raise ValueError("CWE XML attributes exceed their profile")

        self.attribute_bytes += size
        self.stack.append(name)
        self.depth = max(self.depth, len(self.stack))
        self.Node()
        qualified = self.namespace + "|"
        kind = name.removeprefix(qualified)

        if len(self.stack) == 1:
            if self.root_closed or name != qualified + "Weakness_Catalog" or (
                attributes.get("Version") != self.version
            ):
                raise ValueError("CWE XML root namespace or catalog version disagrees")

            self.catalog_name = CweName(attributes.get("Name"), 256)
            self.catalog_date = IntelligenceDate(attributes.get("Date"))

        elif len(self.stack) == 2:
            allowed = {"Weaknesses", "Categories", "Views", "External_References"}

            if self.version == "5.0":
                allowed.add("Groupings")

            if not name.startswith(qualified) or kind not in allowed or kind in self.collections:
                raise ValueError("CWE XML root collection is unknown or repeated")

            self.collections.add(kind)

        elif len(self.stack) == 3:
            parent = self.stack[-2].removeprefix(qualified)
            expected = {"Weaknesses": "Weakness", "Categories": "Category",
                        "Groupings": "Grouping", "Views": "View",
                        "External_References": "External_Reference"}[parent]

            if name != qualified + expected:
                raise ValueError("CWE XML collection direct child has the wrong source kind")

        if name.startswith(qualified) and kind in self.counts:
            if len(self.stack) != 3:
                raise ValueError("CWE XML source entry occurs outside its direct collection")

            identifier = attributes.get("ID", "")

            if not re.fullmatch(r"[1-9][0-9]{0,9}", identifier):
                raise ValueError("CWE XML entry ID is not canonical")

            identifier = IntelligenceIdentifier("CWE-" + identifier)
            value = CweName(attributes.get("Name"))
            status = attributes.get("Status")

            if status not in STATUS_VALUES or identifier in self.identities or (
                len(self.identities) >= MAX_ENTRIES
            ):
                raise ValueError("CWE XML entry status, uniqueness or count is invalid")

            self.identities.add(identifier)
            self.counts[kind] += 1
            self.entry_active = True
            self.entry_nodes = 1
            self.entry_bytes = 0

            if identifier in self.requested:
                if kind == "Weakness":
                    self.records.append((identifier, value, status))

                else:
                    self.unsupported.append((identifier, kind))

        self.EntryBytes(size)

    def End(self, name: str) -> None:
        """Close an entry/root only after its complete counted content.

        Args:
            name: Expat-validated expanded closing name.
        """

        if self.entry_active and len(self.stack) == 3:
            self.max_entry_nodes = max(self.max_entry_nodes, self.entry_nodes)
            self.max_entry_bytes = max(self.max_entry_bytes, self.entry_bytes)
            self.entry_active = False

        self.stack.pop()

        if not self.stack:
            self.root_closed = True

    def Text(self, value: str) -> None:
        """Count normalized ignored and selected text without retaining whole text nodes.

        Args:
            value: One parser-owned character-data segment.
        """

        size = len(value.encode())

        if self.text_bytes + size > MAX_TEXT_BYTES:
            raise ValueError("CWE XML text exceeds its profile")

        self.text_bytes += size
        self.EntryBytes(size)

    def Comment(self, value: str) -> None:
        """Count comments as nodes and text while preserving their literal reference semantics.

        Args:
            value: Bounded complete comment content.
        """

        self.Node()
        self.Text(value)

    def Instruction(self, target: str, value: str) -> None:
        """Count PI target/content without interpreting either as an execution directive.

        Args:
            target: Bounded source PI target.
            value: Bounded source PI content.
        """

        if len(target.encode()) > MAX_QNAME_BYTES:
            raise ValueError("CWE XML PI target exceeds its QName profile")

        self.Node()
        self.Text(target + value)

    def Declaration(self, version: str, encoding: str | None, standalone: int) -> None:
        """Require XML 1.0 and UTF-8-or-omitted encoding independently of forced parser encoding.

        Args:
            version: Original XML declaration version.
            encoding: Explicit declared encoding, or absent.
            standalone: Expat declaration fact; no source authority is inferred.
        """

        if version != "1.0" or encoding is not None and encoding.lower() != "utf-8":
            raise ValueError("CWE XML declaration is outside the UTF-8 profile")

    def Forbidden(self, *arguments: object) -> Never:
        """Refuse every DTD/entity/external/skipped callback without creating a resolver.

        Args:
            arguments: Ignored parser callback facts; never paths or network input.

        Returns:
            Never returns; all secondary resolution is refused.
        """

        raise ValueError("CWE XML DTD and entity resolution are forbidden")

    def Finish(self) -> CweXmlFacts:
        """Require complete UTF-8, lexical, parser and root states before publishing private facts.

        Returns:
            Immutable observed facts only after the entire XML source is complete.
        """

        if self.finished or self.state != "text" or self.pending or (
            self.reference or self.cdata_tail
        ):
            raise ValueError("CWE XML source ended with incomplete lexical state")

        try:
            self.utf8.decode(b"", final=True)
            self.parser.Parse(b"", True)

        except (UnicodeError, expat.ExpatError) as error:
            raise ValueError("CWE XML source is incomplete") from error

        if not self.root_closed or self.stack or self.namespaces or self.entry_active:
            raise ValueError("CWE XML source ended with incomplete structural state")

        self.finished = True

        return CweXmlFacts(tuple(sorted(self.records)), tuple(sorted(self.unsupported)),
            self.catalog_name, self.catalog_date, self.counts["Weakness"], self.counts["Category"],
            self.counts["Grouping"], self.counts["View"], self.nodes, self.text_bytes,
            self.attribute_bytes, self.depth, self.max_entry_nodes, self.max_entry_bytes,
            self.max_markup, self.max_comment_pi, self.max_reference)
