# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Retain versioned MCP inventories in the shared model and redacted evidence store."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, cast

from fuzzy1337.adapters.contracts import EvidenceReference, RequireIdentifier
from fuzzy1337.adapters.native_http import Endpoint
from fuzzy1337.artifact_inputs import ArtifactReadConsent, ReadArtifactFile
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.executors.contracts import RequireReference
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelDelta,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Observation,
    PrepareModelState,
    Relation,
    RelationKind,
    SecurityObject,
)
from fuzzy1337.policy import ImpactPolicy, UtcNow
from fuzzy1337.scope import LocalScopeStore, Target, TargetKind
from fuzzy1337.workspace import (
    RejectWorkspaceConstant,
    RequireWorkspaceInteger,
    UniqueWorkspaceObject,
    WorkspaceConflictError,
)

if TYPE_CHECKING:
    from fuzzy1337.mcp_metadata import McpMetadataLimits, McpMetadataResult

__all__ = (
    "CollectAndImportMcpMetadata", "ImportMcpInventory", "McpInventoryImport", "ParseMcpInventory",
)

_MCP_VERSION = 1
_MAX_BYTES = 256 * 1024
_MAX_NODES = 12_000
_MAX_DEPTH = 20
_MAX_ITEMS = 128
_MAX_TEXT_BYTES = 8192
_SOURCE_ID = "mcp-inventory-local"
_SOURCE_VERSION = "offline-v1"
METADATA_SOURCE_ID = "mcp-inventory-http"
METADATA_SOURCE_VERSION = "metadata-http-v1"
_EVIDENCE_ROLE = "mcp-inventory-redacted"
_METADATA_ACQUISITION_FIELDS = {
    "source_reference", "scope_reference", "scope_revision", "protocol_version", "issues",
    "actor_ref", "operator_receipt_reference",
}
_METADATA_REASONS = {
    "capability-not-advertised", "event-stream-ended", "http-status", "invalid-cursor",
    "invalid-declaration", "invalid-notification-ack", "malformed", "malformed-page",
    "malformed-session", "page-limit", "redirect", "rpc-error", "session-material", "size-limit",
    "timeout", "transport-failure", "transport-unavailable", "unsupported-transport",
    "unsupported-version",
}
_SECTIONS = {
    "capabilities": "capability", "tools": "tool", "resources": "resource",
    "resource_templates": "resource-template", "prompts": "prompt",
}
_STATUS = ("unknown", "unsupported", "incomplete", "complete")
_LABEL = re.compile(r"[A-Za-z0-9._-]{1,128}", re.ASCII)
_URI = re.compile(r"([A-Za-z][A-Za-z0-9+.-]{0,31}):([^\x00-\x20\x7f]+)", re.ASCII)
_URI_QUERY_EXPRESSION = re.compile(r"\{[?#][^{}]*\}")
_MIME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]*/[a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]*")
_PROTOCOL_VERSION = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", re.ASCII)
_INLINE_CREDENTIAL = re.compile(
    r"""(?i)(?P<quote>["']?)\b(?:authorization|api[-_ ]?key|access[-_ ]?token|"""
    r"refresh[-_ ]?token|client[-_ ]?secret|password|secret|token)\b(?P=quote)"
    r"\s*[:=]\s*(?:bearer\s+|basic\s+)?"
    r"""(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;&]+)"""
)
_AUTH_TOKEN = re.compile(
    r"(?i)\b(?:bearer|basic)\s+[^\s,;]+"
    r"|(?<![A-Za-z0-9])(?:(?:gh[pousr]_|github_pat_|sk-|xox[baprs]-)[A-Za-z0-9_-]+"
    r"|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"
)
_USERINFO = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/\s?#]*@")
_HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
_TYPES = ("array", "boolean", "integer", "null", "number", "object", "string")
_SCHEMA_MAPS = {"$defs", "definitions", "properties", "patternProperties", "dependentSchemas"}
_SCHEMA_LISTS = {"allOf", "anyOf", "oneOf", "prefixItems"}
_SCHEMA_NODES = {
    "additionalProperties", "contains", "else", "if", "items", "not", "propertyNames", "then",
    "unevaluatedItems", "unevaluatedProperties",
}
_SCHEMA_NUMBERS = {
    "exclusiveMaximum", "exclusiveMinimum", "maximum", "maxItems", "maxLength", "maxProperties",
    "minimum", "minItems", "minLength", "minProperties", "multipleOf", "minContains", "maxContains",
}
_SCHEMA_BOOLEANS = {"deprecated", "readOnly", "uniqueItems", "writeOnly"}
_SCHEMA_OPAQUE_TEXT = {
    "$anchor", "$comment", "$dynamicAnchor", "$dynamicRef", "$id", "$ref", "$schema",
    "contentEncoding", "contentMediaType", "description", "format", "pattern", "title",
}
_SCHEMA_LITERALS = {"const", "default"}


def Invalid(location: str, message: str) -> ValueError:
    """Build an actionable error using only source coordinates and fixed diagnostic text.

    Args:
        location: Fixed field path in the inventory.
        message: Safe diagnostic with no source values.

    Returns:
        A bounded inventory validation error.
    """

    return ValueError(f"MCP inventory {location}: {message}")


def ReadObject(
    value: object, location: str, required: set[str], optional: set[str],
) -> dict[str, object]:
    """Validate a closed object without displaying attacker-controlled field names.

    Args:
        value: Candidate JSON object.
        location: Field path for validation errors.
        required: Member names required by the profile.
        optional: Additional member names accepted by the profile.

    Returns:
        The validated JSON mapping.
    """

    if not isinstance(value, dict):
        raise Invalid(location, "expected an object")

    record = cast(dict[str, object], value)
    missing = sorted(required - record.keys())

    if missing:
        raise Invalid(location, "missing " + ", ".join(missing))

    if record.keys() - required - optional:
        raise Invalid(location, "contains unsupported fields")

    return record


def ReadArray(value: object, location: str) -> list[object]:
    """Require a bounded declaration array.

    Args:
        value: Candidate JSON array.
        location: Field path for validation errors.

    Returns:
        The array within the inventory item bound.
    """

    if not isinstance(value, list) or len(value) > _MAX_ITEMS:
        raise Invalid(location, f"expected an array with at most {_MAX_ITEMS} items")

    return cast(list[object], value)


def ReadText(value: object, location: str) -> str:
    """Require text that already passed the whole-document UTF-8 bound.

    Args:
        value: Candidate JSON string.
        location: Field path for validation errors.

    Returns:
        A string already covered by the document bounds.
    """

    if not isinstance(value, str):
        raise Invalid(location, "expected a string")

    return value


def RedactedText(value: str) -> str:
    """Strip credential assignments, auth tokens and URI userinfo before hashing.

    Args:
        value: Bounded text containing possible credential-like data.

    Returns:
        Text after recognized credential spellings are removed.
    """

    value = _INLINE_CREDENTIAL.sub("[redacted]", value)
    value = _AUTH_TOKEN.sub("[redacted]", value)

    return _USERINFO.sub(r"\1", value)


def TextFingerprint(value: object, location: str) -> str:
    """Retain a change signal for opaque text without keeping its original contents.

    Args:
        value: Candidate text to fingerprint.
        location: Field path for validation errors.

    Returns:
        A SHA-256 reference to the redacted text.
    """

    text = RedactedText(ReadText(value, location))

    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def ReadLabel(value: object, location: str) -> str:
    """Accept a bounded declaration identifier while refusing recognized credentials.

    Args:
        value: Candidate declaration identifier.
        location: Field path for validation errors.

    Returns:
        An allowed non-secret declaration name.
    """

    text = ReadText(value, location)

    if not _LABEL.fullmatch(text) or RedactedText(text) != text:
        raise Invalid(location, "expected a non-secret identifier of at most 128 ASCII characters")

    return text


def Flag(value: object, location: str) -> bool:
    """Validate an explicit JSON boolean without applying protocol defaults.

    Args:
        value: Candidate JSON boolean.
        location: Field path for validation errors.

    Returns:
        The declared boolean.
    """

    if not isinstance(value, bool):
        raise Invalid(location, "expected a boolean")

    return value


def DecodeInventory(value: bytes) -> object:
    """Read strict UTF-8 JSON under byte, node, depth and string limits.

    Args:
        value: Original UTF-8 snapshot bytes.

    Returns:
        A decoded JSON value validated against the inventory resource limits.
    """

    if not isinstance(value, bytes) or not value or len(value) > _MAX_BYTES:
        raise Invalid("#", f"expected nonempty UTF-8 JSON of at most {_MAX_BYTES} bytes")

    try:
        document: object = json.loads(
            value.decode("utf-8"), object_pairs_hook=UniqueWorkspaceObject,
            parse_constant=RejectWorkspaceConstant,
        )

    except json.JSONDecodeError as error:
        raise Invalid("#", f"invalid JSON at line {error.lineno}, column {error.colno}") from None

    except (UnicodeError, RecursionError):
        raise Invalid("#", "JSON must have valid UTF-8 and bounded nesting") from None

    except ValueError:
        raise Invalid("#", "JSON has a duplicate key or invalid numeric literal") from None

    pending = [(document, 0)]
    count = 0

    while pending:
        item, depth = pending.pop()
        count += 1

        if count > _MAX_NODES or depth > _MAX_DEPTH:
            raise Invalid("#", "JSON exceeds its node or depth limit")

        if isinstance(item, dict):
            pending.extend((key, depth + 1) for key in item)
            pending.extend((child, depth + 1) for child in item.values())

        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)

        elif isinstance(item, str):
            try:
                byteCount = len(item.encode("utf-8"))

            except UnicodeError:
                raise Invalid("#", "JSON strings must be valid UTF-8") from None

            if byteCount > _MAX_TEXT_BYTES:
                raise Invalid("#", "a JSON string exceeds its byte limit")

        elif isinstance(item, float) and not math.isfinite(item):
            raise Invalid("#", "JSON numbers must be finite")

    return document


def SchemaType(value: object, location: str) -> str:
    """Validate a declared JSON Schema type name.

    Args:
        value: Candidate JSON Schema type string.
        location: Field path for validation errors.

    Returns:
        A recognized JSON Schema type name.
    """

    if not isinstance(value, str) or value not in _TYPES:
        raise Invalid(location, "expected a JSON Schema type name")

    return value


def SchemaName(value: str, location: str) -> str:
    """Keep recognizable field names and fingerprint arbitrary or sensitive spellings.

    Args:
        value: Schema member name supplied in the source.
        location: Field path for validation errors.

    Returns:
        The safe name or its redacted fingerprint.
    """

    if _LABEL.fullmatch(value) and RedactedText(value) == value:
        return value

    return TextFingerprint(value, location)


def ProjectSchema(value: object, location: str, *, root: bool = False) -> object:
    """Project bounded schema structure without interpreting schema branches or literals.

    Args:
        value: Candidate schema declaration.
        location: Field path for validation errors.
        root: Require an object root for a tool input or output.

    Returns:
        Retained structure and markers for omitted schema data.
    """

    if isinstance(value, bool) and not root:
        return value

    if not isinstance(value, dict) or (root and value.get("type") != "object"):
        raise Invalid(location, "expected an object-root schema" if root else "expected a schema")

    result: dict[str, object] = {}

    for keyword, field in value.items():
        if keyword == "type":
            if isinstance(field, list):
                types = [SchemaType(item, location) for item in ReadArray(field, location)]

                if not types or len(set(types)) != len(types):
                    raise Invalid(location, "type array must contain unique schema types")

                result[keyword] = sorted(types)

            else:
                result[keyword] = SchemaType(field, location)

        elif keyword == "required":
            names = [SchemaName(ReadText(item, location), location)
                     for item in ReadArray(field, location)]

            if len(set(names)) != len(names):
                raise Invalid(location, "required contains colliding redacted keys")

            result[keyword] = sorted(names)

        elif keyword in _SCHEMA_MAPS:
            if not isinstance(field, dict):
                raise Invalid(location, f"{keyword} must contain an object of schemas")

            entries: dict[str, object] = {}

            for key, child in field.items():
                name = SchemaName(key, location)

                if name in entries:
                    raise Invalid(location, f"{keyword} contains colliding redacted keys")

                entries[name] = ProjectSchema(child, location)

            result[keyword] = entries

        elif keyword in _SCHEMA_LISTS:
            branches = [ProjectSchema(item, location) for item in ReadArray(field, location)]
            result[keyword] = branches if keyword == "prefixItems" else sorted(
                branches, key=CanonicalModelJson,
            )

        elif keyword in _SCHEMA_NODES:
            result[keyword] = ProjectSchema(field, location)

        elif keyword in _SCHEMA_BOOLEANS:
            result[keyword] = Flag(field, location)

        elif keyword in _SCHEMA_NUMBERS:
            if isinstance(field, bool) or not isinstance(field, (int, float)):
                raise Invalid(location, f"{keyword} must be a number")

            result[keyword] = field

        elif keyword in _SCHEMA_OPAQUE_TEXT:
            result[keyword] = TextFingerprint(field, location)

        elif keyword in {"enum", "examples"}:
            ReadArray(field, location + "/" + keyword)
            result[keyword] = "redacted"

        elif keyword in _SCHEMA_LITERALS:
            result[keyword] = "redacted"

        else:
            result["has_unsupported_keywords"] = True

    return result


def OpaqueFields(record: dict[str, object], location: str,
                 fields: tuple[str, ...]) -> dict[str, object]:
    """Fingerprint declared optional prose and preserve omission.

    Args:
        record: Already validated descriptor mapping.
        location: Field path for validation errors.
        fields: Optional text fields to fingerprint.

    Returns:
        Fingerprints of the supplied fields, keyed by their profile names.
    """

    return {key + "_fingerprint": TextFingerprint(record[key], location + "/" + key)
            for key in fields if key in record}


def Tool(value: object, location: str) -> tuple[str, dict[str, object]]:
    """Validate a tool declaration, keeping hints literal and descriptor text opaque.

    Args:
        value: Candidate tool descriptor.
        location: Field path for validation errors.

    Returns:
        The tool name and normalized metadata.
    """

    record = ReadObject(value, location, {"name", "inputSchema"}, {
        "outputSchema", "annotations", "description", "title", "_meta", "icons", "execution",
    })
    name = ReadLabel(record["name"], location + "/name")
    hints = ReadObject(record.get("annotations", {}), location + "/annotations",
                       set(), {*_HINTS, "title"})
    data = OpaqueFields(record, location, ("description", "title"))
    data.update({
        "name": name,
        "input_schema": ProjectSchema(record["inputSchema"], location + "/inputSchema", root=True),
        "output_schema": ProjectSchema(
            record["outputSchema"], location + "/outputSchema", root=True,
        ) if "outputSchema" in record else None,
        "annotations": {
            **OpaqueFields(hints, location + "/annotations", ("title",)),
            **{key: Flag(hints[key], location + "/annotations/" + key) if key in hints else None
               for key in _HINTS},
        },
    })

    return name, data


def Resource(value: object, location: str, identifier: str) -> tuple[str, dict[str, object]]:
    """Describe declared resource reach without exposing, expanding or fetching locators.

    Args:
        value: Candidate resource or template descriptor.
        location: Field path for validation errors.
        identifier: Name of the locator field for this descriptor kind.

    Returns:
        The redacted locator identity and normalized metadata.
    """

    record = ReadObject(value, location, {"name", identifier}, {
        "title", "description", "mimeType", "size", "_meta", "icons", "annotations",
    })
    uri = ReadText(record[identifier], location + "/" + identifier)
    match = _URI.fullmatch(uri)

    if match is None:
        raise Invalid(location + "/" + identifier, "expected an absolute URI or URI template")

    scheme = match[1].lower()

    if RedactedText(scheme) != scheme:
        raise Invalid(location + "/" + identifier, "URI scheme contains credential-shaped text")

    locator = _USERINFO.sub(r"\1", scheme + ":" + match[2])

    if identifier == "uriTemplate":
        locator = _URI_QUERY_EXPRESSION.sub("", locator)

    locator = re.split(r"[?#]", locator, maxsplit=1)[0]
    fingerprint = TextFingerprint(locator, location + "/" + identifier)
    data = OpaqueFields(record, location, ("name", "title", "description"))
    data.update({"scheme": scheme, "locator_fingerprint": fingerprint})

    if "mimeType" in record:
        mimeType = ReadText(record["mimeType"], location + "/mimeType")

        if len(mimeType) > 128 or not _MIME.fullmatch(mimeType):
            raise Invalid(location + "/mimeType", "expected a media type with no parameters")

        data["mime_type_fingerprint"] = TextFingerprint(mimeType.lower(), location + "/mimeType")

    if "size" in record:
        data["size"] = RequireWorkspaceInteger(record["size"], location + "/size")

    return fingerprint, data


def Prompt(value: object, location: str) -> tuple[str, dict[str, object]]:
    """Project one prompt descriptor and declared argument names without rendering the prompt.

    Args:
        value: Candidate prompt descriptor.
        location: Field path for validation errors.

    Returns:
        The prompt name and normalized metadata.
    """

    record = ReadObject(value, location, {"name"},
                        {"title", "description", "arguments", "_meta", "icons"})
    name = ReadLabel(record["name"], location + "/name")
    data = OpaqueFields(record, location, ("title", "description"))
    data.update({"name": name, "arguments": None})

    if "arguments" in record:
        arguments: dict[str, dict[str, object]] = {}

        for index, argument in enumerate(ReadArray(record["arguments"], location + "/arguments")):
            pointer = f"{location}/arguments/{index}"
            declared = ReadObject(argument, pointer, {"name"}, {"description", "required"})
            argumentName = ReadLabel(declared["name"], pointer + "/name")

            if argumentName in arguments:
                raise Invalid(pointer + "/name", "duplicate prompt argument name")

            arguments[argumentName] = {
                **OpaqueFields(declared, pointer, ("description",)), "name": argumentName,
                "required": Flag(declared["required"], pointer + "/required")
                if "required" in declared else None,
            }

        data["arguments"] = [arguments[key] for key in sorted(arguments)]

    return name, data


def Capability(value: object, location: str) -> tuple[str, dict[str, object]]:
    """Record capability names and known flags, omitting extension payloads.

    Args:
        value: Candidate capability descriptor.
        location: Field path for validation errors.

    Returns:
        The capability name and retained declaration flags.
    """

    record = ReadObject(value, location, {"name"}, {"declaration"})
    name = ReadLabel(record["name"], location + "/name")
    declaration = record.get("declaration", {})

    if not isinstance(declaration, dict):
        raise Invalid(location + "/declaration", "expected an object")

    flags = ("listChanged", "subscribe") if name == "resources" else (
        ("listChanged",) if name in ("tools", "prompts") else ()
    )
    data = {
        key: Flag(declaration[key], location + "/declaration/" + key)
        if key in declaration else None for key in flags
    }

    return name, {
        "name": name, "flags": data,
        "has_unsupported_fields": bool(declaration.keys() - set(flags)),
    }


def Section(value: object, section: str) -> dict[str, object]:
    """Normalize one bounded section and preserve the exact enumeration state.

    Args:
        value: Candidate section with its status and items.
        section: Recognized section name controlling descriptor interpretation.

    Returns:
        The enumeration status and sorted normalized declarations.
    """

    location = "#/" + section
    record = ReadObject(value, location, {"status", "items"}, set())
    status = record["status"]
    items = ReadArray(record["items"], location + "/items")

    if status not in _STATUS:
        raise Invalid(location + "/status", "expected one of " + ", ".join(_STATUS))

    if status in ("unknown", "unsupported") and items:
        raise Invalid(location + "/items", "unknown and unsupported require an empty array")

    result: dict[str, dict[str, object]] = {}

    for index, item in enumerate(items):
        pointer = f"{location}/items/{index}"

        if section == "tools":
            key, data = Tool(item, pointer)

        elif section == "prompts":
            key, data = Prompt(item, pointer)

        elif section == "capabilities":
            key, data = Capability(item, pointer)

        else:
            identifier = "uri" if section == "resources" else "uriTemplate"
            key, data = Resource(item, pointer, identifier)

        if key in result:
            raise Invalid(pointer, "duplicate declaration identity after redaction")

        result[key] = {"key": key, **data}

    return {"status": status, "items": [result[key] for key in sorted(result)]}


def ParseMcpInventory(value: bytes) -> dict[str, object]:
    """Validate offline v1 snapshot bytes and return detached redacted declarations.

    Args:
        value: UTF-8 inventory JSON bytes from a caller-owned snapshot.

    Returns:
        Canonicalizable normalized metadata retaining no original input document.

    Raises:
        ValueError: Syntax, profile version, structure or bounds are invalid.
    """

    record = ReadObject(DecodeInventory(value), "#", {"schema_version", "server"},
                        {"instructions", *_SECTIONS})

    if type(record["schema_version"]) is not int or record["schema_version"] != _MCP_VERSION:
        raise Invalid("#/schema_version", "expected version 1")

    server = ReadObject(record["server"], "#/server", {"name", "version"},
                        {"protocolVersion", "title", "description", "_meta", "icons"})
    protocol = server.get("protocolVersion")

    if "protocolVersion" in server and (
        not isinstance(protocol, str) or not _PROTOCOL_VERSION.fullmatch(protocol)
    ):
        raise Invalid("#/server/protocolVersion", "expected a YYYY-MM-DD protocol revision")

    return {
        "schema_version": _MCP_VERSION,
        "server": {
            **OpaqueFields(server, "#/server", ("name", "version", "title", "description")),
            "protocol_version": protocol,
        },
        "instructions_fingerprint": TextFingerprint(record["instructions"], "#/instructions")
        if "instructions" in record else None,
        "sections": {
            name: Section(record[name], name) if name in record
            else {"status": "unknown", "items": []}
            for name in _SECTIONS
        },
    }


@dataclass(frozen=True, slots=True)
class McpInventoryImport:
    """Describe one committed model transition and its immutable redacted evidence."""

    state: ModelState
    delta: ModelDelta
    evidence: EvidenceRecord
    serverReference: str
    snapshotReference: str


def ProjectInventory(
    state: ModelState, serverIdentity: ObjectIdentity, inventory: dict[str, object],
    digest: str, provenance: ModelProvenance, *, acquisition: dict[str, object] | None = None,
) -> tuple[ModelState, ModelDelta, str]:
    """Prepare one canonical patch plus an immutable snapshot-membership observation.

    Args:
        state: Current shared model snapshot.
        serverIdentity: Workplace-local stable identity for this server.
        inventory: Validated redacted inventory.
        digest: Digest of the normalized inventory.
        provenance: Attribution bound to the redacted evidence record.
        acquisition: Validated HTTP provenance retained with the declaration when present.

    Returns:
        The proposed model, its delta, and the immutable observation reference.
    """

    serverReference = serverIdentity.Reference()
    sections = cast(dict[str, dict[str, object]], inventory["sections"])
    objects: list[SecurityObject] = []
    relations: list[Relation] = []
    membership: dict[str, object] = {}
    statuses = {}

    for section, kind in _SECTIONS.items():
        record = sections[section]
        references = []
        statuses[section] = record["status"]

        for item in cast(list[dict[str, object]], record["items"]):
            identity = ObjectIdentity(
                state.workspace_id, ObjectKind.ASSET, f"{serverIdentity.key}:{kind}:{item['key']}",
            )
            reference = identity.Reference()
            references.append(reference)
            objects.append(SecurityObject(
                identity, {"mcp_descriptor": {"kind": kind, **item}}, (provenance,),
            ))
            relations.append(Relation(
                RelationKind.CONTAINS, serverReference, reference, {}, (provenance,),
            ))

        membership[section] = {"status": record["status"], "objects": sorted(references)}

    server = {
        "schema_version": inventory["schema_version"],
        "server": inventory["server"],
        "instructions_fingerprint": inventory["instructions_fingerprint"],
        "snapshot_digest": digest,
    }

    if acquisition is not None:
        server["acquisition"] = acquisition

    objects.append(SecurityObject(
        serverIdentity, {"mcp_inventory": {**server, "section_status": statuses}}, (provenance,),
    ))
    snapshot = Observation(
        "mcp-inventory-snapshot", serverReference, {**server, "sections": membership}, provenance,
    )
    snapshotReference = snapshot.Reference()

    if snapshot in state.observations:
        return state, ModelDelta(state.revision, state.revision), snapshotReference

    updated, delta = state.Apply(
        objects=tuple(objects), relations=tuple(relations), observations=(snapshot,),
    )

    return updated, delta, snapshotReference


def CommitInventory(
    model: LocalModelStore, state: ModelState, serverKey: str, inventory: dict[str, object],
    collection: EvidenceProvenance, *, offlineConsent: ArtifactReadConsent | None = None,
    acquisition: dict[str, object] | None = None, verifyScope: Callable[[], None] | None = None,
) -> McpInventoryImport:
    """Publish the fresh normalized output of an admitted source through both existing owners.

    Only the offline parser and approved HTTP collector feed this internal owner path.

    Args:
        model: Existing local model owner.
        state: Immutable CAS basis selected before reading or collecting metadata.
        serverKey: Approved stable model key in this workspace.
        inventory: Fresh redacted declaration from the selected source path.
        collection: Evidence attribution for that source.
        offlineConsent: Operator's selected-file read references for an offline receipt.
        acquisition: Validated HTTP-only attribution copied into immutable model history.
        verifyScope: Recheck exact HTTP scope beside each independent publication boundary.

    Returns:
        Acknowledged model and evidence transition.
    """

    receiptFields: dict[str, object]

    if offlineConsent is not None and acquisition is None and verifyScope is None:
        receiptFields = {"actor_ref": offlineConsent.actor_ref,
                         "read_consent_reference": offlineConsent.record_ref}

    elif offlineConsent is None and acquisition is not None and verifyScope is not None:
        receiptFields = {"acquisition": acquisition}

    else:
        raise ValueError("MCP inventory publication requires exactly one admitted source")

    digest = "sha256:" + hashlib.sha256(CanonicalModelJson(inventory)).hexdigest()
    content = CanonicalModelJson({
        **receiptFields, "schema_version": _MCP_VERSION, "profile": collection.source_version,
        "server_key": serverKey, "snapshot_digest": digest, "inventory": inventory,
    })

    if len(content) > _MAX_BYTES:
        raise Invalid("#", "redacted evidence exceeds its byte limit")

    evidenceHash = hashlib.sha256(content).hexdigest()
    evidence = EvidenceRecord(EvidenceReference(
        _EVIDENCE_ROLE, f"blobs/sha256/{evidenceHash}", evidenceHash,
        "application/json", len(content),
    ), collection)
    serverIdentity = ObjectIdentity(state.workspace_id, ObjectKind.SERVICE, "mcp:v1:" + serverKey)
    provenance = ModelProvenance(
        collection.source_id, evidence.evidence_id, collection.finished_at,
        collection.scope_reference, serverIdentity.Reference(), collection.source_version,
        (evidence.reference,),
    )
    proposal, delta, snapshotReference = ProjectInventory(
        state, serverIdentity, inventory, digest, provenance, acquisition=acquisition,
    )
    PrepareModelState(proposal)
    evidenceStore = LocalEvidenceStore(model.root / "evidence")

    if verifyScope is not None:
        verifyScope()

    committed = evidenceStore.Put(content, _EVIDENCE_ROLE, "application/json", collection)

    if committed != evidence:
        raise ValueError("MCP inventory evidence publication returned an unexpected record")

    if verifyScope is not None:
        verifyScope()

    saved = model.Save(proposal, expected_revision=state.revision)

    return McpInventoryImport(
        saved, delta, committed, serverIdentity.Reference(), snapshotReference,
    )


def ImportMcpInventory(
    model: LocalModelStore, path: Path, *, serverKey: str, scopeId: str,
    consent: ArtifactReadConsent, observedAt: str, expectedRevision: int,
) -> McpInventoryImport:
    """Read one local snapshot and retain a validated redacted model transition.

    Args:
        model: Existing shared model owner inside the caller's workspace.
        path: Explicit singly linked physical inventory file.
        serverKey: Stable caller-selected non-secret server key, independent of declared name.
        scopeId: Existing workspace scope used for attribution.
        consent: Caller-selected non-secret actor and file-read consent references.
        observedAt: Original snapshot observation time with a UTC offset.
        expectedRevision: Model revision against which to import using the existing CAS.

    Returns:
        Committed model, delta, verified redacted evidence and canonical snapshot references.

    Raises:
        ValueError: A selection, document, redacted projection or workspace binding is invalid.
        WorkspaceConflictError: The model revision is stale.
        OSError: A required local path or storage operation failed.

    Evidence publication precedes the independent model save. A storage or concurrent
    CAS failure can leave the redacted evidence available for exact replay.
    """

    RequireIdentifier(serverKey, "MCP server key")
    RequireIdentifier(scopeId, "scope_id")
    RequireWorkspaceInteger(expectedRevision, "expected model revision")

    if not isinstance(consent, ArtifactReadConsent):
        raise ValueError("MCP inventory requires explicit artifact read consent")

    if any(RedactedText(value) != value for value in (
        serverKey, scopeId, consent.actor_ref, consent.record_ref,
    )):
        raise ValueError("MCP server, scope and consent selections must be non-secret references")

    state = model.Open()

    if state.revision != expectedRevision:
        raise WorkspaceConflictError("model revision changed; reopen before importing inventory")

    scope = LocalScopeStore(model.root).Open(scopeId)

    if scope.workspace_id != state.workspace_id:
        raise ValueError("MCP inventory scope belongs to another workspace")

    collection = EvidenceProvenance(
        state.workspace_id, scope.Reference(), _SOURCE_ID, _SOURCE_VERSION, None,
        observedAt, observedAt,
    )
    buffer = BytesIO()
    ReadArtifactFile(path.absolute(), "mcp-inventory.json", buffer, max_bytes=_MAX_BYTES)
    inventory = ParseMcpInventory(buffer.getvalue())

    return CommitInventory(model, state, serverKey, inventory, collection, offlineConsent=consent)


def OperatorReceipt(actor: object, receipt: object) -> tuple[str, str]:
    """Validate bounded, non-secret references from the scope's granted authorization.

    Args:
        actor: Recorded scope authority reference.
        receipt: Recorded operator consent reference at the pinned scope revision.

    Returns:
        Exact safe references ready for retention.
    """

    references = (ReadText(actor, "#/acquisition/actor_ref"),
                  ReadText(receipt, "#/acquisition/operator_receipt_reference"))

    for reference in references:
        RequireReference(reference, "MCP operator receipt")

        if len(reference) > 4096 or RedactedText(reference) != reference:
            raise ValueError("MCP operator receipt must use bounded non-secret references")

    return references


def ValidateMetadataAcquisition(
    value: object, inventory: dict[str, object], scopeReference: str,
) -> dict[str, object]:
    """Verify the closed HTTP attribution shared by publication and historical review.

    Args:
        value: Candidate acquisition fields from collection or stored redacted evidence.
        inventory: Exact redacted declaration carried by the same receipt.
        scopeReference: Scope bound to the owning evidence manifest.

    Returns:
        The validated acquisition fields without reinterpretation.
    """

    from fuzzy1337.mcp_metadata import MCP_PROTOCOL_VERSION

    location = "#/acquisition"
    record = ReadObject(value, location, _METADATA_ACQUISITION_FIELDS, set())
    source = ReadText(record["source_reference"], location + "/source_reference")
    server = inventory.get("server") if isinstance(inventory, dict) else None

    if (not re.fullmatch(r"target:[0-9a-f]{64}", source)
            or record["scope_reference"] != scopeReference
            or not scopeReference.startswith("scope:")
            or RedactedText(scopeReference) != scopeReference
            or record["protocol_version"] != MCP_PROTOCOL_VERSION
            or not isinstance(server, dict)
            or server.get("protocol_version") != MCP_PROTOCOL_VERSION):
        raise Invalid(location, "HTTP source, scope or negotiated protocol disagrees")

    RequireIdentifier(scopeReference.removeprefix("scope:"), "scope_id")
    RequireWorkspaceInteger(record["scope_revision"], "MCP collection scope revision")
    OperatorReceipt(record["actor_ref"], record["operator_receipt_reference"])
    stages: set[str] = set()

    for item in ReadArray(record["issues"], location + "/issues"):
        issue = ReadObject(item, location + "/issues", {"stage", "reason"}, set())
        stage = ReadText(issue["stage"], location + "/issues/stage")
        reason = ReadText(issue["reason"], location + "/issues/reason")

        if (stage not in {"initialized", "tools", "resources", "resource_templates", "prompts"}
                or stage in stages or reason not in _METADATA_REASONS):
            raise Invalid(location + "/issues", "expected fixed unique collection diagnostics")

        stages.add(stage)

    return record


def CheckMetadataServerBinding(
    state: ModelState, serverKey: str, scopeReference: str, sourceReference: str,
) -> None:
    """Keep a previously collected logical server bound to one exact endpoint and scope.

    Args:
        state: Authoritative model before the first exchange.
        serverKey: Selected stable identifier for this server.
        scopeReference: Exact selected scope identity, independent of revision.
        sourceReference: Exact canonical endpoint reference.
    """

    server = ObjectIdentity(state.workspace_id, ObjectKind.SERVICE, "mcp:v1:" + serverKey)
    serverReference = server.Reference()

    for item in state.observations:
        if item.kind != "mcp-inventory-snapshot" or item.subject_reference != serverReference:
            continue

        if item.provenance.source_id != METADATA_SOURCE_ID:
            continue

        acquisition = item.attributes.get("acquisition")

        if (not isinstance(acquisition, Mapping)
                or acquisition.get("source_reference") != sourceReference
                or acquisition.get("scope_reference") != scopeReference):
            raise ValueError("MCP server key is already bound to a different scope or endpoint")


def CollectAndImportMcpMetadata(
    model: LocalModelStore, endpoint: str, *, serverKey: str, scopeId: str, approved: bool,
    policyProvider: Callable[[], ImpactPolicy], expectedRevision: int,
    credentialProvider: Callable[[], str | None] | None = None,
    limits: McpMetadataLimits | None = None,
) -> tuple[McpMetadataResult, McpInventoryImport | None]:
    """Collect approved MCP declarations and retain their fresh redacted acquisition.

    Args:
        model: Existing shared model owner for the scope's workspace.
        endpoint: Exact permitted literal HTTP(S) endpoint.
        serverKey: Stable non-secret model key chosen for this server.
        scopeId: Current scope registering the endpoint and its destination address.
        approved: Explicit opt-in for this collection.
        policyProvider: Current Workbench impact policy for the reviewed HTTP provider.
        expectedRevision: Exact model revision to check before collection and saving.
        credentialProvider: Optional provider of in-memory HTTP authorization material.
        limits: Typed collection ceilings, or the HTTP profile defaults.

    Returns:
        The redacted collection outcome and its acknowledged import, if initialization succeeded.

    Raises:
        McpMetadataDenied: Explicit permission or current scope binding cannot be verified.
        WorkspaceConflictError: The selected model basis changed.
        ValueError: Endpoint, attribution or collected declaration is inconsistent.
    """

    from fuzzy1337.mcp_metadata import McpMetadataDenied, McpMetadataLimits, ReadScope
    from fuzzy1337.mcp_metadata_http import CollectMcpMetadataHttp

    if approved is not True:
        raise McpMetadataDenied("MCP metadata collection requires explicit approval")

    RequireIdentifier(serverKey, "MCP server key")
    RequireIdentifier(scopeId, "scope_id")
    RequireWorkspaceInteger(expectedRevision, "expected model revision")

    if RedactedText(serverKey) != serverKey or RedactedText(scopeId) != scopeId:
        raise ValueError("MCP server and scope selections must be non-secret references")

    state = model.Open()

    if state.revision != expectedRevision:
        raise WorkspaceConflictError("model revision changed; reopen before collecting metadata")

    try:
        source, address, _, _ = Endpoint(endpoint)

    except ValueError:
        del endpoint
        raise ValueError("MCP metadata endpoint selection is invalid") from None

    del endpoint
    destination = Target(TargetKind.IP, address)
    scope = ReadScope(model.root, scopeId, source, destination)

    if scope.workspace_id != state.workspace_id or scope.scope_id != scopeId:
        raise McpMetadataDenied("MCP metadata scope does not belong to the selected model")

    actor, receipt = OperatorReceipt(
        scope.authorization.authority_reference, scope.authorization.record_reference,
    )
    scopeReference = scope.Reference()
    sourceReference = source.Reference()
    CheckMetadataServerBinding(state, serverKey, scopeReference, sourceReference)
    selectedLimits = McpMetadataLimits() if limits is None else limits
    result = CollectMcpMetadataHttp(
        model.root, scopeId, source.value, approved=approved, policyProvider=policyProvider,
        credentialProvider=credentialProvider, limits=selectedLimits,
    )

    def VerifyScope() -> None:
        """Require the exact admitted scope and current consent at publication."""

        if ReadScope(model.root, scopeId, source, destination) != scope:
            raise McpMetadataDenied("MCP metadata collection no longer matches its exact scope")

    if (result.scopeReference != scopeReference or result.scopeRevision != scope.revision
            or result.sourceReference != sourceReference):
        raise McpMetadataDenied("MCP metadata collection no longer matches its exact scope")

    VerifyScope()

    if result.inventory is None:
        return result, None

    if model.Open() != state:
        raise WorkspaceConflictError("model changed during MCP metadata collection")

    acquisition = ValidateMetadataAcquisition({
        "source_reference": sourceReference, "scope_reference": scopeReference,
        "scope_revision": scope.revision, "protocol_version": result.protocolVersion,
        "issues": [{"stage": item.stage, "reason": item.reason} for item in result.issues],
        "actor_ref": actor, "operator_receipt_reference": receipt,
    }, result.inventory, scopeReference)
    observedAt = UtcNow().isoformat()
    collection = EvidenceProvenance(
        state.workspace_id, scopeReference, METADATA_SOURCE_ID, METADATA_SOURCE_VERSION, None,
        observedAt, observedAt,
    )
    committed = CommitInventory(
        model, state, serverKey, result.inventory, collection,
        acquisition=acquisition, verifyScope=VerifyScope,
    )

    return result, committed
