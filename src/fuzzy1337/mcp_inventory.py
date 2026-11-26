# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Import versioned local MCP metadata into the shared model and redacted evidence store."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import cast

from fuzzy1337.adapters.contracts import EvidenceReference, RequireIdentifier
from fuzzy1337.artifact_inputs import ArtifactReadConsent, ReadArtifactFile
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
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
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import (
    RejectWorkspaceConstant,
    RequireWorkspaceInteger,
    UniqueWorkspaceObject,
    WorkspaceConflictError,
)

__all__ = ("ImportMcpInventory", "McpInventoryImport", "ParseMcpInventory")

_MCP_VERSION = 1
_MAX_BYTES = 256 * 1024
_MAX_NODES = 12_000
_MAX_DEPTH = 20
_MAX_ITEMS = 128
_MAX_TEXT_BYTES = 8192
_SOURCE_ID = "mcp-inventory-local"
_SOURCE_VERSION = "offline-v1"
_EVIDENCE_ROLE = "mcp-inventory-redacted"
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


def _Invalid(location: str, message: str) -> ValueError:
    """Build an actionable error using only source coordinates and fixed diagnostic text."""

    return ValueError(f"MCP inventory {location}: {message}")


def _ReadObject(
    value: object, location: str, required: set[str], optional: set[str],
) -> dict[str, object]:
    """Validate a closed object without displaying attacker-controlled field names."""

    if not isinstance(value, dict):
        raise _Invalid(location, "expected an object")

    record = cast(dict[str, object], value)
    missing = sorted(required - record.keys())

    if missing:
        raise _Invalid(location, "missing " + ", ".join(missing))

    if record.keys() - required - optional:
        raise _Invalid(location, "contains unsupported fields")

    return record


def _ReadArray(value: object, location: str) -> list[object]:
    """Require a bounded declaration array."""

    if not isinstance(value, list) or len(value) > _MAX_ITEMS:
        raise _Invalid(location, f"expected an array with at most {_MAX_ITEMS} items")

    return cast(list[object], value)


def _ReadText(value: object, location: str) -> str:
    """Require text that already passed the whole-document UTF-8 bound."""

    if not isinstance(value, str):
        raise _Invalid(location, "expected a string")

    return value


def _RedactedText(value: str) -> str:
    """Strip credential assignments, auth tokens and URI userinfo before hashing."""

    value = _INLINE_CREDENTIAL.sub("[redacted]", value)
    value = _AUTH_TOKEN.sub("[redacted]", value)

    return _USERINFO.sub(r"\1", value)


def _TextFingerprint(value: object, location: str) -> str:
    """Retain a change signal for opaque text without keeping its original contents."""

    text = _RedactedText(_ReadText(value, location))

    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _ReadLabel(value: object, location: str) -> str:
    """Accept a bounded declaration identifier while refusing recognized credentials."""

    text = _ReadText(value, location)

    if not _LABEL.fullmatch(text) or _RedactedText(text) != text:
        raise _Invalid(location, "expected a non-secret identifier of at most 128 ASCII characters")

    return text


def _Flag(value: object, location: str) -> bool:
    """Validate an explicit JSON boolean without applying protocol defaults."""

    if not isinstance(value, bool):
        raise _Invalid(location, "expected a boolean")

    return value


def _DecodeInventory(value: bytes) -> object:
    """Read strict UTF-8 JSON under byte, node, depth and string limits."""

    if not isinstance(value, bytes) or not value or len(value) > _MAX_BYTES:
        raise _Invalid("#", f"expected nonempty UTF-8 JSON of at most {_MAX_BYTES} bytes")

    try:
        document: object = json.loads(
            value.decode("utf-8"), object_pairs_hook=UniqueWorkspaceObject,
            parse_constant=RejectWorkspaceConstant,
        )

    except json.JSONDecodeError as error:
        raise _Invalid("#", f"invalid JSON at line {error.lineno}, column {error.colno}") from None

    except (UnicodeError, RecursionError):
        raise _Invalid("#", "JSON must have valid UTF-8 and bounded nesting") from None

    except ValueError:
        raise _Invalid("#", "JSON has a duplicate key or invalid numeric literal") from None

    pending = [(document, 0)]
    count = 0

    while pending:
        item, depth = pending.pop()
        count += 1

        if count > _MAX_NODES or depth > _MAX_DEPTH:
            raise _Invalid("#", "JSON exceeds its node or depth limit")

        if isinstance(item, dict):
            pending.extend((key, depth + 1) for key in item)
            pending.extend((child, depth + 1) for child in item.values())

        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)

        elif isinstance(item, str):
            try:
                byteCount = len(item.encode("utf-8"))

            except UnicodeError:
                raise _Invalid("#", "JSON strings must be valid UTF-8") from None

            if byteCount > _MAX_TEXT_BYTES:
                raise _Invalid("#", "a JSON string exceeds its byte limit")

        elif isinstance(item, float) and not math.isfinite(item):
            raise _Invalid("#", "JSON numbers must be finite")

    return document


def _SchemaType(value: object, location: str) -> str:
    """Validate a declared JSON Schema type name."""

    if not isinstance(value, str) or value not in _TYPES:
        raise _Invalid(location, "expected a JSON Schema type name")

    return value


def _SchemaName(value: str, location: str) -> str:
    """Keep recognizable field names and fingerprint arbitrary or sensitive spellings."""

    if _LABEL.fullmatch(value) and _RedactedText(value) == value:
        return value

    return _TextFingerprint(value, location)


def _ProjectSchema(value: object, location: str, *, root: bool = False) -> object:
    """Project bounded schema structure without interpreting schema branches or literals."""

    if isinstance(value, bool) and not root:
        return value

    if not isinstance(value, dict) or (root and value.get("type") != "object"):
        raise _Invalid(location, "expected an object-root schema" if root else "expected a schema")

    result: dict[str, object] = {}

    for keyword, field in value.items():
        if keyword == "type":
            if isinstance(field, list):
                types = [_SchemaType(item, location) for item in _ReadArray(field, location)]

                if not types or len(set(types)) != len(types):
                    raise _Invalid(location, "type array must contain unique schema types")

                result[keyword] = sorted(types)

            else:
                result[keyword] = _SchemaType(field, location)

        elif keyword == "required":
            names = [_SchemaName(_ReadText(item, location), location)
                     for item in _ReadArray(field, location)]

            if len(set(names)) != len(names):
                raise _Invalid(location, "required contains colliding redacted keys")

            result[keyword] = sorted(names)

        elif keyword in _SCHEMA_MAPS:
            if not isinstance(field, dict):
                raise _Invalid(location, f"{keyword} must contain an object of schemas")

            entries: dict[str, object] = {}

            for key, child in field.items():
                name = _SchemaName(key, location)

                if name in entries:
                    raise _Invalid(location, f"{keyword} contains colliding redacted keys")

                entries[name] = _ProjectSchema(child, location)

            result[keyword] = entries

        elif keyword in _SCHEMA_LISTS:
            branches = [_ProjectSchema(item, location) for item in _ReadArray(field, location)]
            result[keyword] = branches if keyword == "prefixItems" else sorted(
                branches, key=CanonicalModelJson,
            )

        elif keyword in _SCHEMA_NODES:
            result[keyword] = _ProjectSchema(field, location)

        elif keyword in _SCHEMA_BOOLEANS:
            result[keyword] = _Flag(field, location)

        elif keyword in _SCHEMA_NUMBERS:
            if isinstance(field, bool) or not isinstance(field, (int, float)):
                raise _Invalid(location, f"{keyword} must be a number")

            result[keyword] = field

        elif keyword in _SCHEMA_OPAQUE_TEXT:
            result[keyword] = _TextFingerprint(field, location)

        elif keyword in {"enum", "examples"}:
            _ReadArray(field, location + "/" + keyword)
            result[keyword] = "redacted"

        elif keyword in _SCHEMA_LITERALS:
            result[keyword] = "redacted"

        else:
            result["has_unsupported_keywords"] = True

    return result


def _OpaqueFields(record: dict[str, object], location: str,
                 fields: tuple[str, ...]) -> dict[str, object]:
    """Fingerprint declared optional prose and preserve omission."""

    return {key + "_fingerprint": _TextFingerprint(record[key], location + "/" + key)
            for key in fields if key in record}


def _Tool(value: object, location: str) -> tuple[str, dict[str, object]]:
    """Validate a tool declaration, keeping hints literal and descriptor text opaque."""

    record = _ReadObject(value, location, {"name", "inputSchema"}, {
        "outputSchema", "annotations", "description", "title", "_meta", "icons", "execution",
    })
    name = _ReadLabel(record["name"], location + "/name")
    hints = _ReadObject(record.get("annotations", {}), location + "/annotations",
                       set(), {*_HINTS, "title"})
    data = _OpaqueFields(record, location, ("description", "title"))
    data.update({
        "name": name,
        "input_schema": _ProjectSchema(record["inputSchema"], location + "/inputSchema", root=True),
        "output_schema": _ProjectSchema(
            record["outputSchema"], location + "/outputSchema", root=True,
        ) if "outputSchema" in record else None,
        "annotations": {
            **_OpaqueFields(hints, location + "/annotations", ("title",)),
            **{key: _Flag(hints[key], location + "/annotations/" + key) if key in hints else None
               for key in _HINTS},
        },
    })

    return name, data


def _Resource(value: object, location: str, identifier: str) -> tuple[str, dict[str, object]]:
    """Describe declared resource reach without exposing, expanding or fetching locators."""

    record = _ReadObject(value, location, {"name", identifier}, {
        "title", "description", "mimeType", "size", "_meta", "icons", "annotations",
    })
    uri = _ReadText(record[identifier], location + "/" + identifier)
    match = _URI.fullmatch(uri)

    if match is None:
        raise _Invalid(location + "/" + identifier, "expected an absolute URI or URI template")

    scheme = match[1].lower()

    if _RedactedText(scheme) != scheme:
        raise _Invalid(location + "/" + identifier, "URI scheme contains credential-shaped text")

    locator = _USERINFO.sub(r"\1", scheme + ":" + match[2])

    if identifier == "uriTemplate":
        locator = _URI_QUERY_EXPRESSION.sub("", locator)

    locator = re.split(r"[?#]", locator, maxsplit=1)[0]
    fingerprint = _TextFingerprint(locator, location + "/" + identifier)
    data = _OpaqueFields(record, location, ("name", "title", "description"))
    data.update({"scheme": scheme, "locator_fingerprint": fingerprint})

    if "mimeType" in record:
        mimeType = _ReadText(record["mimeType"], location + "/mimeType")

        if len(mimeType) > 128 or not _MIME.fullmatch(mimeType):
            raise _Invalid(location + "/mimeType", "expected a media type with no parameters")

        data["mime_type_fingerprint"] = _TextFingerprint(mimeType.lower(), location + "/mimeType")

    if "size" in record:
        data["size"] = RequireWorkspaceInteger(record["size"], location + "/size")

    return fingerprint, data


def _Prompt(value: object, location: str) -> tuple[str, dict[str, object]]:
    """Project one prompt descriptor and declared argument names without rendering the prompt."""

    record = _ReadObject(value, location, {"name"},
                        {"title", "description", "arguments", "_meta", "icons"})
    name = _ReadLabel(record["name"], location + "/name")
    data = _OpaqueFields(record, location, ("title", "description"))
    data.update({"name": name, "arguments": None})

    if "arguments" in record:
        arguments: dict[str, dict[str, object]] = {}

        for index, argument in enumerate(_ReadArray(record["arguments"], location + "/arguments")):
            pointer = f"{location}/arguments/{index}"
            declared = _ReadObject(argument, pointer, {"name"}, {"description", "required"})
            argumentName = _ReadLabel(declared["name"], pointer + "/name")

            if argumentName in arguments:
                raise _Invalid(pointer + "/name", "duplicate prompt argument name")

            arguments[argumentName] = {
                **_OpaqueFields(declared, pointer, ("description",)), "name": argumentName,
                "required": _Flag(declared["required"], pointer + "/required")
                if "required" in declared else None,
            }

        data["arguments"] = [arguments[key] for key in sorted(arguments)]

    return name, data


def _Capability(value: object, location: str) -> tuple[str, dict[str, object]]:
    """Record capability names and known flags, omitting extension payloads."""

    record = _ReadObject(value, location, {"name"}, {"declaration"})
    name = _ReadLabel(record["name"], location + "/name")
    declaration = record.get("declaration", {})

    if not isinstance(declaration, dict):
        raise _Invalid(location + "/declaration", "expected an object")

    flags = ("listChanged", "subscribe") if name == "resources" else (
        ("listChanged",) if name in ("tools", "prompts") else ()
    )
    data = {
        key: _Flag(declaration[key], location + "/declaration/" + key)
        if key in declaration else None for key in flags
    }

    return name, {
        "name": name, "flags": data,
        "has_unsupported_fields": bool(declaration.keys() - set(flags)),
    }


def _Section(value: object, section: str) -> dict[str, object]:
    """Normalize one bounded section and preserve the exact enumeration state."""

    location = "#/" + section
    record = _ReadObject(value, location, {"status", "items"}, set())
    status = record["status"]
    items = _ReadArray(record["items"], location + "/items")

    if status not in _STATUS:
        raise _Invalid(location + "/status", "expected one of " + ", ".join(_STATUS))

    if status in ("unknown", "unsupported") and items:
        raise _Invalid(location + "/items", "unknown and unsupported require an empty array")

    result: dict[str, dict[str, object]] = {}

    for index, item in enumerate(items):
        pointer = f"{location}/items/{index}"

        if section == "tools":
            key, data = _Tool(item, pointer)

        elif section == "prompts":
            key, data = _Prompt(item, pointer)

        elif section == "capabilities":
            key, data = _Capability(item, pointer)

        else:
            identifier = "uri" if section == "resources" else "uriTemplate"
            key, data = _Resource(item, pointer, identifier)

        if key in result:
            raise _Invalid(pointer, "duplicate declaration identity after redaction")

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

    record = _ReadObject(_DecodeInventory(value), "#", {"schema_version", "server"},
                        {"instructions", *_SECTIONS})

    if type(record["schema_version"]) is not int or record["schema_version"] != _MCP_VERSION:
        raise _Invalid("#/schema_version", "expected version 1")

    server = _ReadObject(record["server"], "#/server", {"name", "version"},
                        {"protocolVersion", "title", "description", "_meta", "icons"})
    protocol = server.get("protocolVersion")

    if "protocolVersion" in server and (
        not isinstance(protocol, str) or not _PROTOCOL_VERSION.fullmatch(protocol)
    ):
        raise _Invalid("#/server/protocolVersion", "expected a YYYY-MM-DD protocol revision")

    return {
        "schema_version": _MCP_VERSION,
        "server": {
            **_OpaqueFields(server, "#/server", ("name", "version", "title", "description")),
            "protocol_version": protocol,
        },
        "instructions_fingerprint": _TextFingerprint(record["instructions"], "#/instructions")
        if "instructions" in record else None,
        "sections": {
            name: _Section(record[name], name) if name in record
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


def _ProjectInventory(
    state: ModelState, serverIdentity: ObjectIdentity, inventory: dict[str, object],
    digest: str, provenance: ModelProvenance,
) -> tuple[ModelState, ModelDelta, str]:
    """Prepare one canonical patch plus an immutable snapshot-membership observation."""

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

    if any(_RedactedText(value) != value for value in (
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
    digest = "sha256:" + hashlib.sha256(CanonicalModelJson(inventory)).hexdigest()
    content = CanonicalModelJson({
        "schema_version": _MCP_VERSION, "profile": _SOURCE_VERSION, "server_key": serverKey,
        "snapshot_digest": digest, "inventory": inventory,
        "actor_ref": consent.actor_ref, "read_consent_reference": consent.record_ref,
    })

    if len(content) > _MAX_BYTES:
        raise _Invalid("#", "redacted evidence exceeds its byte limit")

    evidenceHash = hashlib.sha256(content).hexdigest()
    evidence = EvidenceRecord(EvidenceReference(
        _EVIDENCE_ROLE, f"blobs/sha256/{evidenceHash}", evidenceHash,
        "application/json", len(content),
    ), collection)
    serverIdentity = ObjectIdentity(state.workspace_id, ObjectKind.SERVICE, "mcp:v1:" + serverKey)
    provenance = ModelProvenance(
        _SOURCE_ID, evidence.evidence_id, collection.finished_at, collection.scope_reference,
        serverIdentity.Reference(), _SOURCE_VERSION, (evidence.reference,),
    )
    proposal, delta, snapshotReference = _ProjectInventory(
        state, serverIdentity, inventory, digest, provenance,
    )
    PrepareModelState(proposal)
    evidenceStore = LocalEvidenceStore(model.root / "evidence")
    committed = evidenceStore.Put(content, _EVIDENCE_ROLE, "application/json", collection)

    if committed != evidence:
        raise ValueError("MCP inventory evidence publication returned an unexpected record")

    saved = model.Save(proposal, expected_revision=expectedRevision)

    return McpInventoryImport(
        saved, delta, committed, serverIdentity.Reference(), snapshotReference,
    )
