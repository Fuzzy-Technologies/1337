# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental bounded offline API descriptions, symbolic requests and scope preflight."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from typing import cast
from urllib.parse import urlsplit

from fuzzy1337.model import CanonicalModelJson, ModelProvenance, SecurityObject
from fuzzy1337.requests import (
    BodyKind,
    Endpoint,
    InjectionLocation,
    InjectionPoint,
    ProjectRequests,
    RequestDigest,
    RequestTemplate,
    RequirePointer,
    SessionReference,
    ValueBinding,
)
from fuzzy1337.scope import NormalizeTarget, ScopeDecision, ScopeSnapshot, Target, TargetKind
from fuzzy1337.workspace import RejectWorkspaceConstant, UniqueWorkspaceObject

OPENAPI_IMPORT_VERSION = 1
MAX_OPENAPI_BYTES = 1024 * 1024
MAX_OPENAPI_NODES = 20000
MAX_OPENAPI_DEPTH = 32
MAX_OPENAPI_OPERATIONS = 128
MAX_OPENAPI_OUTPUT_BYTES = 512 * 1024
_METHODS = frozenset(("get", "put", "post", "delete", "options", "head", "patch", "trace"))
_TYPES = frozenset(("object", "array", "string", "integer", "number", "boolean", "null"))
_COMPOSITION = frozenset(("allOf", "anyOf", "oneOf", "not", "if", "then", "else"))
_CONSTRAINTS = frozenset((
    "enum", "const", "pattern", "format", "minimum", "maximum", "exclusiveMinimum",
    "exclusiveMaximum", "multipleOf", "minLength", "maxLength", "minItems", "maxItems",
    "uniqueItems", "additionalProperties", "minProperties", "maxProperties",
))


def _Object(value: object) -> dict[str, object]:
    """Require a decoded object without interpreting ignored description fields."""

    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError("API document fields must be JSON objects")

    return cast(dict[str, object], value)


def _Array(value: object, maximum: int = 128) -> list[object]:
    """Require a finite JSON array before constructing children."""

    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError("API document array exceeds its structural bound")

    return value


def _Text(value: object, maximum: int = 128) -> str:
    """Require bounded single-line metadata without echoing an invalid input."""

    if not isinstance(value, str) or not value or len(value) > maximum or any(
        ord(char) < 32 or ord(char) == 127 for char in value
    ):
        raise ValueError("API metadata must be bounded nonempty single-line text")

    return value


def _Boolean(value: object) -> bool:
    """Reject coercion in required, nullable, explode and read-only flags."""

    if not isinstance(value, bool):
        raise ValueError("API declaration flags must be booleans")

    return value


def _Pointer(parent: str, token: str | int) -> str:
    """Append one correctly escaped JSON Pointer token for source provenance."""

    return parent + "/" + str(token).replace("~", "~0").replace("/", "~1")


def _Point(location: InjectionLocation, selector: str) -> InjectionPoint:
    """Create a deterministic symbolic binding without reading any source example value."""

    digest = hashlib.sha256(CanonicalModelJson([location.value, selector])).hexdigest()[:32]

    return InjectionPoint(location, selector, ValueBinding("value-" + digest))


@dataclass(frozen=True, slots=True)
class ApiInput:
    """A typed symbolic input with schema summary and source/serialization metadata."""

    point: InjectionPoint
    source_pointer: str
    value_type: str
    required: bool
    nullable: bool
    constrained: bool
    serialization: str
    explode: bool

    def ToDict(self) -> dict[str, object]:
        """Render summary fields without source values, examples or schema expressions.

        Returns:
            Independent JSON-compatible point, provenance and schema summary fields.
        """

        return {
            "point": self.point.ToDict(), "source_pointer": self.source_pointer,
            "value_type": self.value_type, "required": self.required, "nullable": self.nullable,
            "constrained": self.constrained, "serialization": self.serialization,
            "explode": self.explode,
        }


@dataclass(frozen=True, slots=True)
class ApiSecurityRequirement:
    """One symbolic scheme in an authentication alternative; credentials remain external."""

    scheme_name: str
    scheme_type: str
    location: str | None
    selector: str | None
    scopes: tuple[str, ...]

    def ToDict(self) -> dict[str, object]:
        """Describe authentication metadata without token endpoints or session material.

        Returns:
            Symbolic scheme, scope names and optional credential location descriptors.
        """

        return {
            "scheme_name": self.scheme_name, "scheme_type": self.scheme_type,
            "location": self.location, "selector": self.selector, "scopes": list(self.scopes),
        }


@dataclass(frozen=True, slots=True)
class ApiOperation:
    """One server/media variant bound to a source operation and an existing request template."""

    operation_id: str | None
    source_pointer: str
    source_digest: str
    media_type: str | None
    template: RequestTemplate
    inputs: tuple[ApiInput, ...]
    security: tuple[tuple[ApiSecurityRequirement, ...], ...]

    def Reference(self) -> str:
        """Bind operation identity to immutable source bytes, media and structural request.

        Returns:
            Domain-separated api-operation digest; no authenticity or authority is implied.
        """

        return RequestDigest("api-operation", {
            "source_digest": self.source_digest, "source_pointer": self.source_pointer,
            "request_reference": self.template.Reference(), "media_type": self.media_type,
        })

    def ToDict(self) -> dict[str, object]:
        """Render attributable non-secret operation metadata using existing request references.

        Returns:
            Independent source/input/auth annotations and recomputable request/operation references.
        """

        return {
            "operation_reference": self.Reference(), "operation_id": self.operation_id,
            "source_pointer": self.source_pointer, "source_digest": self.source_digest,
            "media_type": self.media_type, "request_reference": self.template.Reference(),
            "inputs": [item.ToDict() for item in self.inputs],
            "security": [[item.ToDict() for item in alternative] for alternative in self.security],
        }


@dataclass(frozen=True, slots=True)
class OpenApiImport:
    """Offline imported metadata; no raw document, state store or execution grant is retained."""

    workspace_id: str
    specification_version: str
    source_digest: str
    operations: tuple[ApiOperation, ...]

    def ToDict(self) -> dict[str, object]:
        """Render deterministic import metadata with each real structural request producer.

        Returns:
            Versioned metadata and real structural template fields, without the raw source.
        """

        return {
            "schema_version": OPENAPI_IMPORT_VERSION, "workspace_id": self.workspace_id,
            "specification_version": self.specification_version,
            "source_digest": self.source_digest,
            "operations": [
                {**operation.ToDict(), "template": operation.template.ToDict()}
                for operation in self.operations
            ],
        }


class _ImportContext:
    """Own bounded temporary parsing state without retaining source data in result records."""

    def __init__(self, document: dict[str, object], version: str) -> None:
        """Bind one already byte/depth-bounded document and a finite resolution budget."""

        self.document = document
        self.legacy = version == "2.0"
        self.version = version
        self.work = 0

    def Resolve(
        self, value: object, pointer: str, trail: tuple[str, ...] = (),
    ) -> tuple[dict[str, object], str, tuple[str, ...]]:
        """Resolve finite local JSON Pointers while rejecting cycles and semantic siblings."""

        self.work += 1

        if self.work > 4096 or len(trail) > 16:
            raise ValueError("API reference/schema work exceeds its bound")

        record = _Object(value)

        if "$ref" not in record:
            return record, pointer, trail

        if set(record) - {"$ref", "description", "summary"}:
            raise ValueError("API reference semantic siblings are unsupported")

        reference = _Text(record["$ref"], 256)

        if not reference.startswith("#/") or "%" in reference:
            raise ValueError("only local canonical JSON Pointer references are supported")

        RequirePointer(reference[1:])

        if reference in trail:
            raise ValueError("API reference cycle is unsupported")

        resolved: object = self.document

        for token in reference[2:].split("/"):
            key = token.replace("~1", "/").replace("~0", "~")

            if isinstance(resolved, dict) and key in resolved:
                resolved = resolved[key]

            elif isinstance(resolved, list) and re.fullmatch(r"0|[1-9][0-9]*", key):
                index = int(key)

                if index >= len(resolved):
                    raise ValueError("API local reference does not resolve")

                resolved = resolved[index]

            else:
                raise ValueError("API local reference does not resolve")

        return self.Resolve(resolved, reference, (*trail, reference))

    def Schema(
        self, value: object, pointer: str, trail: tuple[str, ...] = (),
    ) -> tuple[dict[str, object], str, tuple[str, ...], str, bool, bool]:
        """Read structural type flags without evaluating or retaining literal constraints."""

        record, pointer, trail = self.Resolve(value, pointer, trail)

        if set(record) & (_COMPOSITION | {
            "$id", "$schema", "$anchor", "$dynamicRef", "$dynamicAnchor", "discriminator",
        }):
            raise ValueError("API schema composition or dynamic identities are unsupported")

        value_type = record.get("type", "object" if "properties" in record else "unspecified")
        nullable = _Boolean(record.get("nullable", False))

        if self.version.startswith("3.1.") and "nullable" in record:
            raise ValueError("OpenAPI 3.1 nullable flags require an explicit null type")

        if isinstance(value_type, list):
            if not self.version.startswith("3.1.") or len(value_type) != 2 or (
                value_type.count("null") != 1
            ):
                raise ValueError("only one nullable schema type is supported")

            value_type = next(item for item in value_type if item != "null")
            nullable = True

        if not isinstance(value_type, str) or value_type not in _TYPES | {"unspecified", "file"}:
            raise ValueError("unsupported API structural schema type")

        if value_type == "file" and not self.legacy:
            raise ValueError("file schema type is supported only for Swagger multipart inputs")

        constrained = bool(set(record) & (_CONSTRAINTS | {"items"}))

        return record, pointer, trail, value_type, nullable, constrained

    def Parameters(
        self, parent: object, operation: object, parent_pointer: str, operation_pointer: str,
    ) -> list[tuple[dict[str, object], str]]:
        """Apply operation overrides to validated unique location/name parameter declarations."""

        merged: dict[tuple[str, str], tuple[dict[str, object], str]] = {}

        for values, pointer in ((parent, parent_pointer), (operation, operation_pointer)):
            seen: set[tuple[str, str]] = set()

            for index, value in enumerate(_Array(values)):
                record, source, _ = self.Resolve(value, _Pointer(pointer, index))
                location = _Text(record.get("in"))
                name = _Text(record.get("name"))
                coordinate = location, name.lower() if location == "header" else name

                if coordinate in seen:
                    raise ValueError("API parameter coordinates must be unique within each list")

                seen.add(coordinate)
                merged[coordinate] = record, source

        return [merged[key] for key in sorted(merged)]

    def Input(self, record: dict[str, object], pointer: str) -> ApiInput:
        """Decode a parameter into one symbolic slot and explicit serialization metadata."""

        location = record.get("in")

        if not isinstance(location, str) or (
            location not in {"query", "path", "header", "cookie"}
            or (self.legacy and location == "cookie")
        ):
            raise ValueError("unsupported API parameter location")

        if "content" in record:
            raise ValueError("API parameter content encoding is unsupported")

        point = _Point(InjectionLocation(location), _Text(record.get("name")))

        if point.location is InjectionLocation.HEADER and point.selector in {
            "authorization", "content-type", "accept",
        }:
            raise ValueError("reserved API header parameters require a separate runtime owner")

        required = _Boolean(record.get("required", False))

        if point.location is InjectionLocation.PATH and not required:
            raise ValueError("API path parameters must be required")

        schema = record if self.legacy else record.get("schema", {})
        _, _, _, value_type, nullable, constrained = self.Schema(schema, pointer)

        if value_type == "file":
            raise ValueError("file parameters require a multipart body")

        if self.legacy:
            serialization = _Text(record.get("collectionFormat", "csv"))

            if serialization not in {"csv", "ssv", "tsv", "pipes", "multi"} or (
                serialization == "multi" and location != "query"
            ):
                raise ValueError("unsupported Swagger parameter collection format")

            return ApiInput(point, pointer, value_type, required, nullable, constrained,
                            "swagger:" + serialization, serialization == "multi")

        default_style = "simple" if location in {"path", "header"} else "form"
        style = _Text(record.get("style", default_style))
        explode = _Boolean(record.get("explode", style == "form"))

        if style != default_style or _Boolean(record.get("allowReserved", False)):
            raise ValueError("nondefault parameter styles or reserved-value expansion unsupported")

        return ApiInput(point, pointer, value_type, required, nullable, constrained, style, explode)

    def BodyInputs(
        self, value: object, pointer: str, kind: BodyKind, required: bool,
        selector: str = "", trail: tuple[str, ...] = (), depth: int = 0,
        inherited_constraints: bool = False,
    ) -> list[ApiInput]:
        """Project fixed JSON properties or form parts without inventing concrete request values."""

        if depth > 16:
            raise ValueError("API body schema nesting exceeds its bound")

        record, pointer, trail, value_type, nullable, constrained = self.Schema(
            value, pointer, trail,
        )
        constrained = constrained or inherited_constraints

        if _Boolean(record.get("readOnly", False)):
            return []

        properties = _Object(record.get("properties", {}))

        if value_type == "object" and properties:
            names = _Array(record.get("required", []))

            if not all(isinstance(name, str) and name in properties for name in names) or (
                len(set(names)) != len(names)
            ):
                raise ValueError("API required property names must be unique declared properties")

            inputs = []

            for name in sorted(properties):
                child_selector = _Pointer(selector, name) if kind is BodyKind.JSON else name

                if kind is not BodyKind.JSON and selector:
                    raise ValueError("nested form/multipart property expansion is unsupported")

                inputs.extend(self.BodyInputs(
                    properties[name], _Pointer(_Pointer(pointer, "properties"), name), kind,
                    required and name in names, child_selector, trail, depth + 1, constrained,
                ))

            return inputs

        if kind in {BodyKind.FORM, BodyKind.MULTIPART} and not selector:
            raise ValueError("form and multipart schemas require declared named properties")

        if value_type == "file" and kind is not BodyKind.MULTIPART:
            raise ValueError("file schema requires a multipart body")

        location = {
            BodyKind.JSON: InjectionLocation.JSON, BodyKind.FORM: InjectionLocation.BODY,
            BodyKind.MULTIPART: InjectionLocation.MULTIPART, BodyKind.TEXT: InjectionLocation.BODY,
        }[kind]

        return [ApiInput(_Point(location, selector), pointer, value_type, required, nullable,
                         constrained, "body", False)]

    def Bodies(
        self, operation: dict[str, object], parameters: list[tuple[dict[str, object], str]],
        pointer: str,
    ) -> list[tuple[str | None, BodyKind, list[ApiInput]]]:
        """Decode bounded supported media alternatives and legacy body/form declarations."""

        if not self.legacy:
            if "requestBody" not in operation:
                return [(None, BodyKind.NONE, [])]

            body, source, _ = self.Resolve(
                operation["requestBody"], _Pointer(pointer, "requestBody"),
            )
            required = _Boolean(body.get("required", False))
            content = _Object(body.get("content"))

        else:
            body_parameters = [
                (item, source) for item, source in parameters if item.get("in") == "body"
            ]
            form_parameters = [
                (item, source) for item, source in parameters if item.get("in") == "formData"
            ]

            if len(body_parameters) > 1 or (body_parameters and form_parameters):
                raise ValueError("Swagger permits one body or form parameters, not both")

            if not body_parameters and not form_parameters:
                return [(None, BodyKind.NONE, [])]

            media = _Array(operation.get("consumes", self.document.get("consumes", [])), 8)

            if not media or not all(isinstance(item, str) for item in media):
                raise ValueError("Swagger request bodies require explicit supported consumes types")

            media_names = [_Text(item) for item in media]

            if body_parameters:
                body, source = body_parameters[0]
                required = _Boolean(body.get("required", False))
                content = {item: {"schema": body.get("schema", {})} for item in media_names}

            else:
                properties = {_Text(item.get("name")): item for item, _ in form_parameters}
                required_names = [name for name, item in properties.items()
                                  if _Boolean(item.get("required", False))]
                source = _Pointer(pointer, "parameters")
                required = True
                content = {item: {"schema": {
                    "type": "object", "properties": properties, "required": required_names,
                }} for item in media_names}

        if not 1 <= len(content) <= 8:
            raise ValueError("API body content must have between one and eight media variants")

        variants: list[tuple[str | None, BodyKind, list[ApiInput]]] = []

        for media_type in sorted(content):
            _Text(media_type)
            kind = {
                "application/json": BodyKind.JSON,
                "application/x-www-form-urlencoded": BodyKind.FORM,
                "multipart/form-data": BodyKind.MULTIPART, "text/plain": BodyKind.TEXT,
            }.get(media_type)

            if kind is None and media_type.startswith("application/") and (
                media_type.endswith("+json")
            ):
                kind = BodyKind.JSON

            if kind is None:
                raise ValueError("unsupported API request body media type")

            media_record = _Object(content[media_type])

            if media_record.get("encoding"):
                raise ValueError("custom form/multipart encodings are unsupported")

            if self.legacy and form_parameters and kind not in {BodyKind.FORM, BodyKind.MULTIPART}:
                raise ValueError("Swagger formData requires a form or multipart media type")

            schema_pointer = source if self.legacy else _Pointer(
                _Pointer(source, "content"), media_type,
            )

            if "schema" in media_record:
                schema_pointer = _Pointer(schema_pointer, "schema")

            if self.legacy and form_parameters:
                inputs = []

                for item, item_source in form_parameters:
                    inputs.extend(self.BodyInputs(
                        item, item_source, kind, _Boolean(item.get("required", False)),
                        _Text(item.get("name")),
                    ))

            else:
                inputs = self.BodyInputs(
                    media_record.get("schema", {}), schema_pointer, kind, required,
                )

            variants.append((media_type, kind, inputs))

        return variants

    def Security(
        self, operation: dict[str, object],
    ) -> tuple[tuple[ApiSecurityRequirement, ...], ...]:
        """Preserve authentication OR/AND alternatives without selecting a session or auth flow."""

        security = _Array(operation.get("security", self.document.get("security", [])), 8)
        components = _Object(self.document.get("components", {}))
        definitions = _Object(self.document.get("securityDefinitions", {}) if self.legacy
                              else components.get("securitySchemes", {}))
        alternatives = []

        for alternative in security:
            requirement = _Object(alternative)

            if len(requirement) > 8:
                raise ValueError("API authentication alternative exceeds its bound")

            entries = []

            for name in sorted(requirement):
                _Text(name)
                scopes = tuple(sorted(_Text(item) for item in _Array(requirement[name], 32)))

                if len(set(scopes)) != len(scopes) or name not in definitions:
                    raise ValueError("API authentication scopes/scheme references are invalid")

                scheme, _, _ = self.Resolve(definitions[name], "#/securitySchemes")
                scheme_type = _Text(scheme.get("type"))
                location: str | None = None
                selector: str | None = None

                if scheme_type == "apiKey":
                    location = _Text(scheme.get("in"))

                    if location not in {"header", "query", "cookie"} or (
                        self.legacy and location == "cookie"
                    ):
                        raise ValueError("unsupported API key location")

                    selector = _Point(
                        InjectionLocation(location), _Text(scheme.get("name")),
                    ).selector

                elif scheme_type == "http" and not self.legacy:
                    http_scheme = _Text(scheme.get("scheme")).lower()

                    if http_scheme not in {"basic", "bearer"}:
                        raise ValueError("unsupported HTTP authentication scheme")

                    scheme_type = "http-" + http_scheme

                elif scheme_type == "basic" and self.legacy:
                    scheme_type = "http-basic"

                elif scheme_type not in {"oauth2", "openIdConnect", "mutualTLS"} or (
                    self.legacy and scheme_type != "oauth2"
                ):
                    raise ValueError("unsupported API authentication scheme type")

                if scopes and scheme_type not in {"oauth2", "openIdConnect"}:
                    raise ValueError("non-OAuth authentication cannot declare scopes")

                entries.append(ApiSecurityRequirement(
                    name, scheme_type, location, selector, scopes,
                ))

            alternatives.append(tuple(entries))

        return tuple(alternatives)


def _BaseUrl(value: object) -> str:
    """Normalize an HTTP(S) base with a literal path and without captured query/fragment data."""

    url = NormalizeTarget(TargetKind.URL, _Text(value, 4096))
    parsed = urlsplit(url)

    if parsed.query or "?" in str(value) or "{" in str(value) or "}" in str(value):
        raise ValueError("API server requires a literal HTTP(S) base without query or variables")

    Endpoint("api-import", f"{parsed.scheme}://{parsed.netloc}", parsed.path)

    return url.rstrip("/")


def _Servers(
    document: dict[str, object], path: dict[str, object], operation: dict[str, object],
    legacy: bool, base_url: str | None,
) -> tuple[str, ...]:
    """Apply declared server precedence with explicit context for document-relative locations."""

    context = _BaseUrl(base_url) if base_url is not None else None

    if legacy:
        context_parts = urlsplit(context) if context is not None else None
        host = document.get("host", context_parts.netloc if context_parts else None)
        schemes = _Array(operation.get("schemes", document.get(
            "schemes", [context_parts.scheme] if context_parts else [],
        )), 4)

        if not schemes or any(
            not isinstance(scheme, str) or scheme not in {"http", "https"} for scheme in schemes
        ):
            raise ValueError("Swagger requires explicit supported schemes or a base URL context")

        base_path = _Text(document.get("basePath", "/"), 1024)

        if not base_path.startswith("/") or "{" in base_path or "}" in base_path:
            raise ValueError("Swagger basePath must be a literal absolute path")

        return tuple(sorted({_BaseUrl(f"{scheme}://{_Text(host, 256)}{base_path}")
                             for scheme in schemes}))

    servers = _Array(operation.get("servers", path.get("servers", document.get("servers", []))), 4)

    if not servers:
        if context is None:
            raise ValueError("relative/default API servers require an explicit base URL")

        parsed = urlsplit(context)

        return (f"{parsed.scheme}://{parsed.netloc}",)

    result = set()

    for server in servers:
        url = _Text(_Object(server).get("url"), 4096)

        if not url.lower().startswith(("http://", "https://")):
            if context is None or not url.startswith("/") or url.startswith("//"):
                raise ValueError("relative API servers require a literal path and explicit base")

            parsed = urlsplit(context)
            url = f"{parsed.scheme}://{parsed.netloc}{url}"

        result.add(_BaseUrl(url))

    return tuple(sorted(result))


def _Document(value: str) -> tuple[dict[str, object], str, bool, str]:
    """Decode bounded strict JSON and validate every node before schema/reference traversal."""

    if not isinstance(value, str):
        raise ValueError("API import requires JSON text")

    try:
        raw = value.encode("utf-8")

        if len(raw) > MAX_OPENAPI_BYTES:
            raise ValueError("API input exceeds its byte bound")

        try:
            parsed_document = json.loads(
                value, object_pairs_hook=UniqueWorkspaceObject,
                parse_constant=RejectWorkspaceConstant,
            )

        except ValueError:
            raise ValueError("API JSON syntax, keys or numeric constants are invalid") from None

        document = _Object(parsed_document)
        pending: list[tuple[object, int]] = [(document, 0)]
        count = 0

        while pending:
            item, depth = pending.pop()
            count += 1

            if count > MAX_OPENAPI_NODES or depth > MAX_OPENAPI_DEPTH:
                raise ValueError("API JSON nodes/nesting exceeds its bound")

            if isinstance(item, dict):
                pending.extend((key, depth + 1) for key in item)
                pending.extend((nested, depth + 1) for nested in item.values())

            elif isinstance(item, list):
                pending.extend((nested, depth + 1) for nested in item)

            elif isinstance(item, str):
                item.encode("utf-8")

            elif isinstance(item, float) and not math.isfinite(item):
                raise ValueError("API JSON must not contain non-finite numbers")

        version = document.get("openapi", document.get("swagger"))

        if ("openapi" in document and "swagger" in document) or not isinstance(version, str) or (
            version != "2.0" and not re.fullmatch(r"3\.[01]\.[0-9]+", version)
        ):
            raise ValueError("only OpenAPI 3.0/3.1 and Swagger 2.0 are supported")

        legacy = "swagger" in document

        if legacy != (version == "2.0"):
            raise ValueError("API version belongs to a different specification field")

        return document, version, legacy, "sha256:" + hashlib.sha256(raw).hexdigest()

    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError("API JSON encoding, structure or nesting is invalid") from error


def ImportOpenApi(
    value: str, *, workspace_id: str, base_url: str | None = None,
    session_reference: SessionReference | None = None,
) -> OpenApiImport:
    """Import bounded JSON into symbolic requests without network, file or credential access.

    Args:
        value: Untrusted supplied JSON text, not a filename or retrieval URL.
        workspace_id: Existing workspace-local endpoint owner.
        base_url: Explicit HTTP(S) resolution context for document-relative servers.
        session_reference: Optional separately owned same-workspace session reference.

    Returns:
        Deterministic operation/media/server variants and structural schema/auth summaries.

    Raises:
        ValueError: Input or a consumed operation exceeds bounds or unsupported semantics.
    """

    Endpoint(workspace_id, "http://127.0.0.1", "/")
    document, version, legacy, digest = _Document(value)
    context = _ImportContext(document, version)
    paths = _Object(document.get("paths"))
    operations = []
    operation_ids: set[str] = set()

    for route in sorted(paths):
        if route.startswith("x-"):
            continue

        Endpoint(workspace_id, "http://127.0.0.1", route)
        path, path_pointer, _ = context.Resolve(paths[route], _Pointer("#/paths", route))

        for method in sorted(set(path) & _METHODS):
            operation = _Object(path[method])
            pointer = _Pointer(path_pointer, method)
            raw_operation_id = operation.get("operationId")
            operation_id: str | None = None

            if raw_operation_id is not None:
                operation_id = _Text(raw_operation_id)

                if operation_id in operation_ids:
                    raise ValueError("API operationId values must be unique")

                operation_ids.add(operation_id)

            parameters = context.Parameters(
                path.get("parameters", []), operation.get("parameters", []),
                _Pointer(path_pointer, "parameters"), _Pointer(pointer, "parameters"),
            )
            ordinary = [context.Input(record, source) for record, source in parameters
                        if record.get("in") not in {"body", "formData"}]

            if not legacy and len(ordinary) != len(parameters):
                raise ValueError("OpenAPI 3 parameters cannot declare body or formData locations")

            security = context.Security(operation)
            bodies = context.Bodies(operation, parameters, pointer)

            for server in _Servers(document, path, operation, legacy, base_url):
                parsed = urlsplit(server)
                origin = f"{parsed.scheme}://{parsed.netloc}"
                endpoint = Endpoint(workspace_id, origin, parsed.path.rstrip("/") + route, method)
                path_names = {item.point.selector for item in ordinary
                              if item.point.location is InjectionLocation.PATH}

                if path_names != set(endpoint.PathVariables()):
                    raise ValueError("API path parameters must match every declared path variable")

                for media_type, body_kind, body_inputs in bodies:
                    inputs = tuple(sorted(
                        (*ordinary, *body_inputs), key=lambda item: item.point.Coordinate(),
                    ))
                    template = RequestTemplate(endpoint, tuple(item.point for item in inputs),
                                               body_kind, session_reference)
                    operations.append(ApiOperation(operation_id, pointer, digest, media_type,
                                                   template, inputs, security))

                    if len(operations) > MAX_OPENAPI_OPERATIONS:
                        raise ValueError("API operation variants exceed their count bound")

    if not operations:
        raise ValueError("API import requires at least one supported operation")

    result = OpenApiImport(workspace_id, version, digest, tuple(operations))

    if len(CanonicalModelJson(result.ToDict())) > MAX_OPENAPI_OUTPUT_BYTES:
        raise ValueError("API import output exceeds its byte bound")

    return result


def ProjectOpenApi(
    imported: OpenApiImport, *, provenance: tuple[ModelProvenance, ...],
) -> tuple[SecurityObject, ...]:
    """Compose complete existing request collections plus attributable operation metadata.

    Args:
        imported: Validated offline import; callers compose all sources before replacing attributes.
        provenance: Existing nonempty model attribution, not the raw API document.

    Returns:
        Existing Endpoint patches, deterministically grouped and bounded by the model contract.

    Raises:
        ValueError: Import type, endpoint collection, provenance or attribute size is invalid.
    """

    if not isinstance(imported, OpenApiImport):
        raise ValueError("API projection requires an OpenApiImport")

    groups: dict[str, list[ApiOperation]] = {}

    for operation in imported.operations:
        groups.setdefault(operation.template.endpoint.Identity().Reference(), []).append(operation)

    result = []

    for reference in sorted(groups):
        operations = groups[reference]
        requests = {operation.template.Reference(): operation.template for operation in operations}
        projection = ProjectRequests(
            tuple(requests[key] for key in sorted(requests)), provenance=provenance,
        )
        metadata = {operation.Reference(): operation.ToDict() for operation in operations}
        result.append(SecurityObject(projection.identity, {
            **projection.attributes,
            "openapi_operations": [metadata[key] for key in sorted(metadata)],
        }, projection.provenance))

    return tuple(result)


def CheckOpenApiTarget(
    operation: ApiOperation, target: Target, scope: ScopeSnapshot, *, at: datetime,
) -> ScopeDecision:
    """Check an explicit concrete URL's endpoint shape and current exact scope membership.

    Args:
        operation: Imported structural operation; its method is not approved by this check.
        target: Caller-bound actual URL, including its actual query, never a template wildcard.
        scope: Current matching-workspace scope snapshot with existing consent/rules.
        at: Explicit aware membership time consumed by the existing scope validator.

    Returns:
        Existing allowed scope decision; callers retain the snapshot revision as evidence.

    Raises:
        ValueError: Types, endpoint shape, workspace binding or decision time are invalid.
        PermissionError: The concrete URL fails existing scope membership or consent.
    """

    if not isinstance(operation, ApiOperation) or not isinstance(target, Target) or (
        not isinstance(scope, ScopeSnapshot) or target.kind is not TargetKind.URL
    ):
        raise ValueError("API preflight requires an operation, exact URL Target and ScopeSnapshot")

    endpoint = operation.template.endpoint
    parsed = urlsplit(target.value)
    parts = parsed.path.split("/")
    expected = endpoint.path_template.split("/")

    if scope.workspace_id != endpoint.workspace_id or endpoint.origin != (
        f"{parsed.scheme}://{parsed.netloc}"
    ) or len(parts) != len(expected) or any(
        not actual if structural.startswith("{") else actual != structural
        for actual, structural in zip(parts, expected, strict=True)
    ):
        raise ValueError("API concrete target must match its endpoint shape and workspace")

    decision = scope.Check(target, at=at)

    if not decision.Allowed():
        raise PermissionError("API concrete target rejected by scope: " + decision.reason.value)

    return decision
