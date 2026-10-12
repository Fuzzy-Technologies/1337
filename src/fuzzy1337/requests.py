# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental structural web requests without values, execution, or scope authority."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from fuzzy1337.adapters.contracts import JsonValue, RequireIdentifier
from fuzzy1337.model import (
    CanonicalModelJson,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.scope import NormalizeTarget, TargetKind
from fuzzy1337.workspace import (
    RejectWorkspaceConstant,
    RequireWorkspaceInteger,
    RequireWorkspaceText,
    UniqueWorkspaceObject,
    WorkspaceFields,
)

REQUEST_SCHEMA_VERSION = 1
MAX_REQUEST_BYTES = 64 * 1024
MAX_INJECTION_POINTS = 128
_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
_PATH_SEGMENT_PATTERN = re.compile(r"[A-Za-z0-9._~-]+|\{[A-Za-z_][A-Za-z0-9_]{0,63}\}")
_METHOD_PATTERN = re.compile(r"[A-Z][A-Z0-9-]{0,31}")
_REFERENCE_PATTERN = re.compile(r"request:[0-9a-f]{64}")


class InjectionLocation(StrEnum):
    """Select one typed input coordinate without providing an injection payload."""

    QUERY = "query"
    BODY = "body"
    JSON = "json"
    COOKIE = "cookie"
    HEADER = "header"
    PATH = "path"
    GRAPHQL = "graphql"
    MULTIPART = "multipart"


class BodyKind(StrEnum):
    """Describe the runtime body encoding while storing no body values or bytes."""

    NONE = "none"
    FORM = "form"
    TEXT = "text"
    JSON = "json"
    GRAPHQL = "graphql"
    MULTIPART = "multipart"


class BindingSource(StrEnum):
    """Distinguish caller input names from separately owned session input names."""

    INPUT = "input"
    SESSION = "session"


def RequestDigest(namespace: str, value: object) -> str:
    """Derive a domain-separated structural identity without consulting runtime values.

    Args:
        namespace: Request, injection, or session reference namespace.
        value: Validated immutable structural identity fields.

    Returns:
        Namespace and lowercase SHA-256 digest over canonical JSON.
    """

    digest = hashlib.sha256(CanonicalModelJson({"namespace": namespace, "identity": value}))

    return f"{namespace}:{digest.hexdigest()}"


def RequirePointer(value: str) -> None:
    """Validate a bounded RFC 6901 pointer without resolving or decoding a body.

    Args:
        value: Root pointer or slash-prefixed pointer containing only valid tilde escapes.

    Raises:
        ValueError: The pointer is malformed, oversized, or contains controls.
    """

    if (
        not isinstance(value, str) or len(value) > 256
        or (value != "" and not value.startswith("/"))
        or re.search(r"~(?![01])", value)
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("selector must be a bounded RFC 6901 pointer")


@dataclass(frozen=True, slots=True)
class ValueBinding:
    """Name a runtime value source rather than persisting its content."""

    name: str
    source: BindingSource = BindingSource.INPUT

    def __post_init__(self) -> None:
        """Require a bounded non-secret identifier and an explicit source enum."""

        RequireIdentifier(self.name, "binding name")

        if len(self.name) > 64 or not isinstance(self.source, BindingSource):
            raise ValueError("binding requires a bounded name and BindingSource")

    def ToDict(self) -> dict[str, object]:
        """Return symbolic fields without resolving a value.

        Returns:
            Exact schema fields for an unresolved named input.
        """

        return {"name": self.name, "source": self.source.value}

    @classmethod
    def FromDict(cls, value: object) -> ValueBinding:
        """Decode an exact symbolic binding and reject literal-value extension fields.

        Args:
            value: Decoded binding object.

        Returns:
            Validated binding without side effects.

        Raises:
            ValueError: Fields, source, or identifier are invalid.
        """

        record = WorkspaceFields(value, {"name", "source"}, "value binding")
        source = RequireWorkspaceText(record["source"], "binding source")

        if source not in tuple(item.value for item in BindingSource):
            raise ValueError("binding source must be input or session")

        return cls(
            RequireWorkspaceText(record["name"], "binding name"),
            BindingSource(source),
        )


@dataclass(frozen=True, slots=True)
class SessionReference:
    """Reference a separately owned session using non-secret workspace-local identifiers."""

    workspace_id: str
    session_id: str

    def __post_init__(self) -> None:
        """Require bounded identifiers without reading credentials or session state."""

        for field_name in ("workspace_id", "session_id"):
            value = getattr(self, field_name)
            RequireIdentifier(value, field_name)

            if len(value) > 64:
                raise ValueError("session identifiers must not exceed 64 characters")

    def Reference(self) -> str:
        """Expose a workspace-bound reference that does not prove session availability.

        Returns:
            Deterministic session digest independent of credentials.
        """

        return RequestDigest("session", self.ToDict())

    def ToDict(self) -> dict[str, object]:
        """Render the owned identifiers without credential material.

        Returns:
            Workspace and session identifier fields.
        """

        return {"workspace_id": self.workspace_id, "session_id": self.session_id}

    @classmethod
    def FromDict(cls, value: object) -> SessionReference:
        """Decode a reference rather than a captured authenticated session.

        Args:
            value: Exact workspace/session identifier object.

        Returns:
            Validated unresolved session reference.

        Raises:
            ValueError: A field is unknown, absent, or not an identifier.
        """

        record = WorkspaceFields(value, {"workspace_id", "session_id"}, "session reference")

        return cls(
            RequireWorkspaceText(record["workspace_id"], "workspace_id"),
            RequireWorkspaceText(record["session_id"], "session_id"),
        )


@dataclass(frozen=True, slots=True)
class Endpoint:
    """Describe a structural HTTP endpoint in the existing Security Object Model namespace."""

    workspace_id: str
    origin: str
    path_template: str
    method: str = "GET"

    def __post_init__(self) -> None:
        """Canonicalize an offline origin/method and reject inline values or ambiguous paths."""

        RequireIdentifier(self.workspace_id, "workspace_id")
        canonical_url = NormalizeTarget(TargetKind.URL, self.origin)
        parsed = urlsplit(canonical_url)

        if parsed.path != "/" or parsed.query or "?" in self.origin:
            raise ValueError("endpoint origin must contain only an HTTP(S) authority")

        RequireWorkspaceText(self.path_template, "path_template")
        parts = self.path_template.split("/")[1:]

        if (
            len(self.path_template) > 1024 or not self.path_template.startswith("/")
            or len(parts) > 64
            or any(
                part in {".", ".."} or (part and not _PATH_SEGMENT_PATTERN.fullmatch(part))
                for part in parts
            )
            or "//" in self.path_template
        ):
            raise ValueError("path_template requires structural segments or named path variables")

        variables = self.PathVariables()

        if len(variables) != len(set(variables)):
            raise ValueError("path variables must have unique names")

        method = RequireWorkspaceText(self.method, "method").upper()

        if not _METHOD_PATTERN.fullmatch(method):
            raise ValueError("method must be a bounded HTTP method token")

        object.__setattr__(self, "origin", f"{parsed.scheme}://{parsed.netloc}")
        object.__setattr__(self, "method", method)

    def PathVariables(self) -> tuple[str, ...]:
        """Return declared structural path names without substituting runtime data.

        Returns:
            Ordered path variable names.
        """

        return tuple(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", self.path_template))

    def Identity(self) -> ObjectIdentity:
        """Reuse the SOM Endpoint identity rather than inventing another object store.

        Returns:
            Workspace-bound Endpoint natural key over canonical method/origin/path fields.
        """

        key = CanonicalModelJson({
            "origin": self.origin, "path_template": self.path_template, "method": self.method,
        }).decode("utf-8")

        return ObjectIdentity(self.workspace_id, ObjectKind.ENDPOINT, key)

    def ToDict(self) -> dict[str, object]:
        """Render canonical endpoint fields with their recomputable existing model reference.

        Returns:
            Endpoint fields and object reference, without request values.
        """

        return {
            "workspace_id": self.workspace_id, "origin": self.origin,
            "path_template": self.path_template, "method": self.method,
            "object_reference": self.Identity().Reference(),
        }

    @classmethod
    def FromDict(cls, value: object) -> Endpoint:
        """Decode stored canonical endpoint spelling and reject forged references.

        Args:
            value: Exact decoded endpoint object.

        Returns:
            Validated endpoint; alias spelling is accepted only by the constructor.

        Raises:
            ValueError: Fields, spelling or reference differ from the canonical endpoint.
        """

        record = WorkspaceFields(value, {
            "workspace_id", "origin", "path_template", "method", "object_reference",
        }, "endpoint")
        endpoint = cls(*(
            RequireWorkspaceText(record[key], key)
            for key in ("workspace_id", "origin", "path_template", "method")
        ))

        if record != endpoint.ToDict():
            raise ValueError("stored endpoint fields and reference must be canonical")

        return endpoint


@dataclass(frozen=True, slots=True)
class InjectionPoint:
    """Address one typed value slot without storing its value or a mutation payload."""

    location: InjectionLocation
    selector: str
    binding: ValueBinding
    occurrence: int = 0

    def __post_init__(self) -> None:
        """Validate location syntax and freeze header names before template-level checks."""

        if not isinstance(self.location, InjectionLocation) or not isinstance(
            self.binding, ValueBinding,
        ):
            raise ValueError("injection requires InjectionLocation and ValueBinding")

        occurrence = RequireWorkspaceInteger(self.occurrence, "occurrence")

        if occurrence > 1023 or not isinstance(self.selector, str):
            raise ValueError("injection requires a string selector and bounded occurrence")

        if self.location in {InjectionLocation.JSON, InjectionLocation.GRAPHQL}:
            RequirePointer(self.selector)

            if self.location is InjectionLocation.GRAPHQL and not re.fullmatch(
                r"/variables/[_A-Za-z][_0-9A-Za-z]{0,63}(?:/.*)?", self.selector,
            ):
                raise ValueError("GraphQL selector must address a variable")

        elif self.location is not InjectionLocation.BODY or self.selector != "":
            if not _NAME_PATTERN.fullmatch(self.selector):
                raise ValueError("selector must be a bounded structural input name")

        if self.location in {
            InjectionLocation.JSON, InjectionLocation.GRAPHQL, InjectionLocation.PATH,
        } or (self.location is InjectionLocation.BODY and self.selector == ""):
            if occurrence != 0:
                raise ValueError("this injection location has no repeated field occurrence")

        if self.location is InjectionLocation.HEADER:
            object.__setattr__(self, "selector", self.selector.lower())

    def Coordinate(self) -> tuple[str, str, int]:
        """Identify an injection position independently of its value binding.

        Returns:
            Location, selector and occurrence in canonical order.
        """

        return self.location.value, self.selector, self.occurrence

    def Reference(self, request_reference: str) -> str:
        """Bind an injection identity to one recomputable request template reference.

        Args:
            request_reference: Validated request digest from the owning template.

        Returns:
            Domain-separated injection reference.

        Raises:
            ValueError: The owner reference is malformed.
        """

        if not isinstance(request_reference, str) or not _REFERENCE_PATTERN.fullmatch(
            request_reference,
        ):
            raise ValueError("injection owner must be a request reference")

        return RequestDigest("injection", {
            "request_reference": request_reference, "coordinate": self.Coordinate(),
        })

    def ToDict(self) -> dict[str, object]:
        """Render a structural coordinate and symbolic binding.

        Returns:
            Exact location, selector, binding and occurrence fields.
        """

        return {
            "location": self.location.value, "selector": self.selector,
            "binding": self.binding.ToDict(), "occurrence": self.occurrence,
        }

    @classmethod
    def FromDict(cls, value: object) -> InjectionPoint:
        """Decode an exact injection descriptor without accepting captured values.

        Args:
            value: Decoded injection descriptor object.

        Returns:
            Validated immutable injection point.

        Raises:
            ValueError: Fields, coordinate, binding or stored spelling are invalid.
        """

        record = WorkspaceFields(value, {
            "location", "selector", "binding", "occurrence",
        }, "injection point")

        if not isinstance(record["selector"], str):
            raise ValueError("selector must be a string")

        location = RequireWorkspaceText(record["location"], "location")

        if location not in tuple(item.value for item in InjectionLocation):
            raise ValueError("location must select a supported injection coordinate")

        point = cls(
            InjectionLocation(location),
            record["selector"], ValueBinding.FromDict(record["binding"]),
            RequireWorkspaceInteger(record["occurrence"], "occurrence"),
        )

        if record != point.ToDict():
            raise ValueError("stored injection coordinate must be canonical")

        return point


@dataclass(frozen=True, slots=True)
class RequestTemplate:
    """Group structural inputs, encoding and a session reference without resolving values."""

    endpoint: Endpoint
    injection_points: tuple[InjectionPoint, ...] = ()
    body_kind: BodyKind = BodyKind.NONE
    session_reference: SessionReference | None = None
    graphql_operation: str | None = None

    def __post_init__(self) -> None:
        """Require coherent locations, ownership and unique deterministic coordinates."""

        if not isinstance(self.endpoint, Endpoint) or not isinstance(self.body_kind, BodyKind):
            raise ValueError("template requires Endpoint and BodyKind")

        if not isinstance(self.injection_points, (tuple, list)) or len(
            self.injection_points,
        ) > MAX_INJECTION_POINTS:
            raise ValueError("injection_points must be a bounded sequence")

        if self.session_reference is not None and (
            not isinstance(self.session_reference, SessionReference)
            or self.session_reference.workspace_id != self.endpoint.workspace_id
        ):
            raise ValueError("session reference must belong to the endpoint workspace")

        if self.graphql_operation is not None and (
            self.body_kind is not BodyKind.GRAPHQL
            or not isinstance(self.graphql_operation, str)
            or not re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]{0,63}", self.graphql_operation)
        ):
            raise ValueError("graphql_operation requires a GraphQL body and operation name")

        points: dict[tuple[str, str, int], InjectionPoint] = {}

        for point in self.injection_points:
            if not isinstance(point, InjectionPoint):
                raise ValueError("injection_points must contain InjectionPoint values")

            if point.Coordinate() in points:
                raise ValueError("injection coordinates must be unique")

            self.ValidatePoint(point)
            points[point.Coordinate()] = point

        object.__setattr__(self, "injection_points", tuple(points[key] for key in sorted(points)))

        if len(CanonicalModelJson(self.ToDict())) > MAX_REQUEST_BYTES:
            raise ValueError("request template exceeds its serialized size bound")

    def ValidatePoint(self, point: InjectionPoint) -> None:
        """Check encoding, path ownership and session-reference relationships.

        Args:
            point: Typed input descriptor from this template.

        Raises:
            ValueError: A descriptor cannot be represented by this template's structure.
        """

        expected = {
            InjectionLocation.BODY: BodyKind.TEXT if point.selector == "" else BodyKind.FORM,
            InjectionLocation.JSON: BodyKind.JSON,
            InjectionLocation.GRAPHQL: BodyKind.GRAPHQL,
            InjectionLocation.MULTIPART: BodyKind.MULTIPART,
        }.get(point.location)

        if expected is not None and self.body_kind is not expected:
            raise ValueError("injection location is incompatible with body_kind")

        if point.location is InjectionLocation.PATH and (
            point.selector not in self.endpoint.PathVariables()
        ):
            raise ValueError("path selector must reference a declared path variable")

        if point.binding.source is BindingSource.SESSION and self.session_reference is None:
            raise ValueError("session bindings require a session reference")

    def Fields(self) -> dict[str, object]:
        """Render identity fields without recursively including their digest.

        Returns:
            Strict schema-versioned structural fields, with deterministic point order.
        """

        return {
            "schema_version": REQUEST_SCHEMA_VERSION, "endpoint": self.endpoint.ToDict(),
            "body_kind": self.body_kind.value,
            "session_reference": (
                None if self.session_reference is None else self.session_reference.ToDict()
            ),
            "graphql_operation": self.graphql_operation,
            "injection_points": [point.ToDict() for point in self.injection_points],
        }

    def Reference(self) -> str:
        """Return a digest of the complete unresolved structural template.

        Returns:
            Canonical request reference, including session and symbolic binding identity.
        """

        return RequestDigest("request", self.Fields())

    def ToDict(self) -> dict[str, object]:
        """Render a complete schema-versioned template with a verifiable reference.

        Returns:
            Canonical serializable request template object.
        """

        return {**self.Fields(), "request_reference": self.Reference()}

    def ToJson(self) -> str:
        """Serialize a deterministic portable template without accessing runtime values.

        Returns:
            Strict UTF-8 JSON text with no trailing newline.
        """

        return CanonicalModelJson(self.ToDict()).decode("utf-8")

    @classmethod
    def FromDict(cls, value: object) -> RequestTemplate:
        """Decode exact schema fields and recompute identity instead of trusting stored digests.

        Args:
            value: Decoded canonical schema-versioned object.

        Returns:
            Validated template ready for a separate authorized runtime consumer.

        Raises:
            ValueError: Size, version, fields, canonical spelling or relationships are invalid.
        """

        record = WorkspaceFields(value, {
            "schema_version", "endpoint", "body_kind", "session_reference",
            "graphql_operation", "injection_points", "request_reference",
        }, "request template")

        if RequireWorkspaceInteger(record["schema_version"], "schema_version") != (
            REQUEST_SCHEMA_VERSION
        ):
            raise ValueError("unsupported request schema version")

        if len(CanonicalModelJson(record)) > MAX_REQUEST_BYTES:
            raise ValueError("request template exceeds its serialized size bound")

        if not isinstance(record["injection_points"], list):
            raise ValueError("stored injection_points must be an array")

        operation = record["graphql_operation"]

        if operation is not None and not isinstance(operation, str):
            raise ValueError("graphql_operation must be a name or null")

        body_kind = RequireWorkspaceText(record["body_kind"], "body_kind")

        if body_kind not in tuple(item.value for item in BodyKind):
            raise ValueError("body_kind must select a supported encoding")

        template = cls(
            Endpoint.FromDict(record["endpoint"]),
            tuple(InjectionPoint.FromDict(point) for point in record["injection_points"]),
            BodyKind(body_kind),
            None if record["session_reference"] is None else SessionReference.FromDict(
                record["session_reference"],
            ),
            operation,
        )

        if record != template.ToDict():
            raise ValueError("stored template and request reference must be canonical")

        return template

    @classmethod
    def FromJson(cls, value: str) -> RequestTemplate:
        """Parse bounded strict JSON without duplicate-key or non-finite-value ambiguity.

        Args:
            value: Serialized structural template, never a captured raw HTTP request.

        Returns:
            Validated immutable request template.

        Raises:
            ValueError: Input is oversized, malformed, noncanonical or outside schema version 1.
        """

        if not isinstance(value, str):
            raise ValueError("request JSON must be text")

        try:
            if len(value.encode("utf-8")) > MAX_REQUEST_BYTES:
                raise ValueError("request JSON exceeds its size bound")

            record = json.loads(
                value, object_pairs_hook=UniqueWorkspaceObject,
                parse_constant=RejectWorkspaceConstant,
            )

        except (UnicodeError, RecursionError) as error:
            raise ValueError("request JSON must be bounded valid UTF-8") from error

        return cls.FromDict(record)


def ProjectRequests(
    templates: tuple[RequestTemplate, ...], *, provenance: tuple[ModelProvenance, ...],
) -> SecurityObject:
    """Project one endpoint's complete request collection into the existing model.

    Args:
        templates: Nonempty complete collection for one endpoint; replaces this attribute.
        provenance: Nonempty existing model attribution for the structural observation.

    Returns:
        Endpoint patch containing only the owned request_templates attribute.

    Raises:
        ValueError: Collection types, ownership, duplicates or model attribute bounds are invalid.
    """

    if not isinstance(templates, (tuple, list)) or not templates:
        raise ValueError("request projection requires a nonempty template sequence")

    endpoint: Endpoint | None = None
    records: dict[str, dict[str, object]] = {}

    for template in templates:
        if not isinstance(template, RequestTemplate):
            raise ValueError("request projection requires RequestTemplate values")

        if endpoint is not None and template.endpoint != endpoint:
            raise ValueError("request projection must belong to one endpoint")

        endpoint = template.endpoint
        reference = template.Reference()

        if reference in records:
            raise ValueError("request projection must not contain duplicate templates")

        records[reference] = template.ToDict()

    assert endpoint is not None, "A nonempty typed collection must contain an endpoint"

    return SecurityObject(endpoint.Identity(), {
        "request_templates": [records[key] for key in sorted(records)],
    }, provenance)


def RequestsFromObject(value: SecurityObject) -> tuple[RequestTemplate, ...]:
    """Reopen validated structural requests from the existing model's immutable attributes.

    Args:
        value: Endpoint object from a real model snapshot; no scope authority is inferred.

    Returns:
        Ordered complete template collection, or empty when no projection is present.

    Raises:
        ValueError: Object kind, projection schema, order, identity or duplicates are invalid.
    """

    if not isinstance(value, SecurityObject) or value.identity.kind is not ObjectKind.ENDPOINT:
        raise ValueError("request consumer requires a SOM Endpoint object")

    if "request_templates" not in value.attributes:
        return ()

    records = JsonValue(value.attributes["request_templates"])

    if not isinstance(records, list):
        raise ValueError("request_templates projection must be an array")

    templates = tuple(RequestTemplate.FromDict(record) for record in records)
    references = [template.Reference() for template in templates]

    if references != sorted(set(references)) or any(
        template.endpoint.Identity() != value.identity for template in templates
    ):
        raise ValueError("request projection has duplicate, unordered, or foreign identities")

    return templates
