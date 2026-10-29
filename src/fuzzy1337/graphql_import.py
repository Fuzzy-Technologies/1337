# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Import bounded owned GraphQL introspection into symbolic requests and ephemeral previews."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlsplit

from fuzzy1337.model import CanonicalModelJson, ModelProvenance, SecurityObject
from fuzzy1337.openapi import ApiImportArray, ApiImportObject, ApiImportPoint, ApiImportPointer
from fuzzy1337.requests import (
    BodyKind,
    Endpoint,
    InjectionLocation,
    ProjectRequests,
    RequestDigest,
    RequestTemplate,
    RequirePointer,
)
from fuzzy1337.scope import ScopeDecision, ScopeSnapshot, Target, TargetKind
from fuzzy1337.workspace import RejectWorkspaceConstant, UniqueWorkspaceObject

GRAPHQL_IMPORT_VERSION = 1
MAX_GRAPHQL_BYTES = 512 * 1024
MAX_GRAPHQL_NODES = 10000
MAX_GRAPHQL_DEPTH = 24
MAX_GRAPHQL_TYPES = 128
MAX_GRAPHQL_OPERATIONS = 32
MAX_GRAPHQL_MEMBERS = 32
MAX_GRAPHQL_TYPE_DEPTH = 8
MAX_GRAPHQL_OUTPUT_BYTES = 256 * 1024
MAX_GRAPHQL_BODY_BYTES = 32 * 1024
MAX_GRAPHQL_GENERATED_NODES = 2048
_KINDS = {"SCALAR", "ENUM", "INPUT_OBJECT", "OBJECT", "INTERFACE", "UNION"}
_INPUT_KINDS = {"SCALAR", "ENUM", "INPUT_OBJECT"}
_OUTPUT_KINDS = {"SCALAR", "ENUM", "OBJECT", "INTERFACE", "UNION"}
_TYPE_FIELDS = {
    "kind", "name", "description", "fields", "inputFields", "enumValues", "interfaces",
    "possibleTypes", "ofType", "specifiedByURL", "isOneOf",
}
__all__ = [
    "GRAPHQL_IMPORT_VERSION", "GraphQlTypeReference", "GraphQlArgument", "GraphQlTypeDefinition",
    "GraphQlOperation", "GraphQlImport", "GeneratedGraphQlRequest", "ImportGraphQl",
    "GenerateGraphQlRequest", "ProjectGraphQl", "CheckGraphQlTarget",
]


def GraphQlFields(value: object, allowed: set[str]) -> dict[str, object]:
    """Require an object with an explicitly supported consumed field vocabulary.

    Args:
        value: Already byte/node-bounded decoded JSON value.
        allowed: Exact supported keys; invalid source values are never echoed.

    Returns:
        Original validated object without mutation.
    """

    record = ApiImportObject(value)

    if set(record) - allowed:
        raise ValueError("GraphQL declaration contains unsupported fields")

    return record


def GraphQlName(value: object, *, internal: bool = False) -> str:
    """Require a bounded GraphQL identifier and distinguish reserved introspection names.

    Args:
        value: Candidate name, not a document expression or concrete runtime value.
        internal: Whether this position may name a reserved introspection type.

    Returns:
        Validated ASCII identifier.
    """

    if not isinstance(value, str) or not re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]{0,63}", value) or (
        not internal and value.startswith("__")
    ):
        raise ValueError("GraphQL names must be bounded non-reserved identifiers")

    return value


def DecodeGraphQl(value: bytes) -> tuple[dict[str, object], str, str]:
    """Decode exact supplied bytes with bounded JSON structure and sanitized failures.

    Args:
        value: Owned UTF-8 introspection bytes; never interpreted as a path or URL.

    Returns:
        Schema object, original schema pointer and exact original-byte SHA-256 reference.

    Raises:
        ValueError: Encoding, keys, envelope, numeric constants or resource limits are invalid.
    """

    if not isinstance(value, bytes) or not value or len(value) > MAX_GRAPHQL_BYTES:
        raise ValueError("GraphQL input requires nonempty bounded bytes")

    try:
        document = ApiImportObject(json.loads(value.decode("utf-8"),
            object_pairs_hook=UniqueWorkspaceObject, parse_constant=RejectWorkspaceConstant))
        pending: list[tuple[object, int]] = [(document, 0)]
        count = 0

        while pending:
            item, depth = pending.pop()
            count += 1

            if count > MAX_GRAPHQL_NODES or depth > MAX_GRAPHQL_DEPTH:
                raise ValueError("GraphQL JSON nodes or nesting exceed their bounds")

            if isinstance(item, dict):
                pending.extend((key, depth + 1) for key in item)
                pending.extend((nested, depth + 1) for nested in item.values())

            elif isinstance(item, list):
                pending.extend((nested, depth + 1) for nested in item)

            elif isinstance(item, str):
                item.encode("utf-8")

            elif isinstance(item, float) and not math.isfinite(item):
                raise ValueError("GraphQL JSON contains a non-finite number")

        if "data" in document:
            GraphQlFields(document, {"data", "extensions"})
            data = GraphQlFields(document["data"], {"__schema"})
            schema = ApiImportObject(data.get("__schema"))
            pointer = "#/data/__schema"

        else:
            GraphQlFields(document, {"__schema"})
            schema = ApiImportObject(document.get("__schema"))
            pointer = "#/__schema"

        GraphQlFields(schema, {
            "queryType", "mutationType", "subscriptionType", "types", "directives", "description",
        })

        return schema, pointer, "sha256:" + hashlib.sha256(value).hexdigest()

    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("GraphQL introspection encoding or structure is invalid") from None


@dataclass(frozen=True, slots=True)
class GraphQlTypeReference:
    """Describe a named type with outer-to-inner list/non-null wrappers, without expansion."""

    kind: str
    name: str
    wrappers: tuple[str, ...] = ()

    def Expression(self) -> str:
        """Render the original structural variable type without values or source expressions.

        Returns:
            Bounded GraphQL type spelling such as [ID!]!.
        """

        result = self.name

        for wrapper in reversed(self.wrappers):
            result = "[" + result + "]" if wrapper == "LIST" else result + "!"

        return result

    def ToDict(self) -> dict[str, object]:
        """Render independent typed metadata without resolving named input types.

        Returns:
            Named kind, identifier and wrapping sequence.
        """

        return {"kind": self.kind, "name": self.name, "wrappers": list(self.wrappers)}


@dataclass(frozen=True, slots=True)
class GraphQlArgument:
    """Bind one symbolic argument or input field to its exact original type coordinate."""

    name: str
    value_type: GraphQlTypeReference
    source_pointer: str
    has_default: bool

    def ToDict(self) -> dict[str, object]:
        """Expose structural metadata while retaining no original default value.

        Returns:
            Argument name, type, pointer and default-presence flag.
        """

        return {"name": self.name, "type": self.value_type.ToDict(),
                "source_pointer": self.source_pointer, "has_default": self.has_default}


@dataclass(frozen=True, slots=True)
class GraphQlTypeDefinition:
    """Keep finite named input structure and enum names without raw descriptions/defaults."""

    kind: str
    name: str
    input_fields: tuple[GraphQlArgument, ...] = ()
    enum_values: tuple[str, ...] = ()

    def ToDict(self) -> dict[str, object]:
        """Render typed input structure for existing model metadata.

        Returns:
            Identifier, kind and bounded input/enum members.
        """

        return {"kind": self.kind, "name": self.name,
                "input_fields": [item.ToDict() for item in self.input_fields],
                "enum_values": list(self.enum_values)}


@dataclass(frozen=True, slots=True)
class GraphQlOperation:
    """Describe one root field and existing symbolic request without execution authority."""

    operation_kind: str
    field_name: str
    source_pointer: str
    source_digest: str
    target: Target
    template: RequestTemplate
    arguments: tuple[GraphQlArgument, ...]
    result_type: GraphQlTypeReference

    def Reference(self) -> str:
        """Bind operation identity to exact source, selected endpoint and typed structure.

        Returns:
            Domain-separated operation digest; not source authenticity or authorization.
        """

        return RequestDigest("graphql-operation", {
            "profile_version": GRAPHQL_IMPORT_VERSION, "source_digest": self.source_digest,
            "source_pointer": self.source_pointer, "operation_kind": self.operation_kind,
            "field_name": self.field_name, "target_reference": self.target.Reference(),
            "request_reference": self.template.Reference(),
            "arguments": [item.ToDict() for item in self.arguments],
            "result_type": self.result_type.ToDict(),
        })

    def ToDict(self) -> dict[str, object]:
        """Render attributable symbolic operation fields, excluding concrete request bytes.

        Returns:
            Source, target, template and typed argument/result metadata.
        """

        return {"operation_reference": self.Reference(), "operation_kind": self.operation_kind,
                "field_name": self.field_name, "source_pointer": self.source_pointer,
                "source_digest": self.source_digest, "target_reference": self.target.Reference(),
                "template": self.template.ToDict(),
                "arguments": [item.ToDict() for item in self.arguments],
                "result_type": self.result_type.ToDict()}


@dataclass(frozen=True, slots=True)
class GraphQlImport:
    """Hold bounded offline typed metadata; neither source bytes nor authority are retained."""

    workspace_id: str
    source_digest: str
    operations: tuple[GraphQlOperation, ...]
    types: tuple[GraphQlTypeDefinition, ...]

    def ToDict(self) -> dict[str, object]:
        """Render deterministic attributable metadata for the existing projection owner.

        Returns:
            Versioned operations and named types without source literals.
        """

        return {"schema_version": GRAPHQL_IMPORT_VERSION, "workspace_id": self.workspace_id,
                "source_digest": self.source_digest,
                "operations": [item.ToDict() for item in self.operations],
                "types": [item.ToDict() for item in self.types]}


class GraphQlImportContext:
    """Own temporary bounded schema parsing without a network or filesystem consumer."""

    def __init__(self, schema: dict[str, object], pointer: str) -> None:
        """Index named definitions before validating finite input/output references.

        Args:
            schema: Bounded decoded introspection schema object.
            pointer: Original source pointer, including its real envelope location.
        """

        self.records: dict[str, tuple[dict[str, object], str]] = {}

        for index, item in enumerate(ApiImportArray(schema.get("types"), MAX_GRAPHQL_TYPES)):
            record = GraphQlFields(item, _TYPE_FIELDS)
            name = GraphQlName(record.get("name"), internal=True)

            kind = record.get("kind")

            if name in self.records or not isinstance(kind, str) or kind not in _KINDS or (
                name in {"Int", "Float", "Boolean", "String", "ID"} and kind != "SCALAR"
            ):
                raise ValueError("GraphQL named types require unique names and supported kinds")

            self.records[name] = (record, ApiImportPointer(pointer + "/types", index))

        if not self.records:
            raise ValueError("GraphQL introspection requires named types")

    def Type(self, value: object, allowed: set[str]) -> GraphQlTypeReference:
        """Validate one finite wrapper chain and its exact indexed named-kind binding.

        Args:
            value: Original introspection type-reference object.
            allowed: Permitted input or output named type kinds.

        Returns:
            Finite reference without recursively expanding named type definitions.
        """

        wrappers: list[str] = []
        record = GraphQlFields(value, {"kind", "name", "ofType"})

        while isinstance(record.get("kind"), str) and record.get("kind") in {"LIST", "NON_NULL"}:
            kind = record["kind"]

            if record.get("name") is not None or len(wrappers) >= MAX_GRAPHQL_TYPE_DEPTH or (
                kind == "NON_NULL" and wrappers and wrappers[-1] == "NON_NULL"
            ):
                raise ValueError("GraphQL type wrappers exceed their supported structure")

            assert isinstance(kind, str), "Validated wrapper kind must be text"
            wrappers.append(kind)
            record = GraphQlFields(record.get("ofType"), {"kind", "name", "ofType"})

        name = GraphQlName(record.get("name"))
        kind = record.get("kind")

        if not isinstance(kind, str) or kind not in allowed or record.get("ofType") is not None or (
            name not in self.records or self.records[name][0]["kind"] != kind
        ):
            raise ValueError("GraphQL reference must match an indexed permitted named type")

        return GraphQlTypeReference(kind, name, tuple(wrappers))

    def Arguments(self, value: object, pointer: str) -> tuple[GraphQlArgument, ...]:
        """Import unique finite input names/types while discarding default-value contents.

        Args:
            value: Original argument or input-field array.
            pointer: Exact original array coordinate.

        Returns:
            Deterministically sorted symbolic input fields.
        """

        result: dict[str, GraphQlArgument] = {}

        for index, item in enumerate(ApiImportArray(value, MAX_GRAPHQL_MEMBERS)):
            record = GraphQlFields(item, {
                "name", "description", "type", "defaultValue", "isDeprecated", "deprecationReason",
            })
            name = GraphQlName(record.get("name"))
            default = record.get("defaultValue")

            if name in result or (default is not None and not isinstance(default, str)):
                raise ValueError("GraphQL inputs require unique names and textual default metadata")

            result[name] = GraphQlArgument(name, self.Type(record.get("type"), _INPUT_KINDS),
                ApiImportPointer(pointer, index), default is not None)

        return tuple(result[key] for key in sorted(result))

    def Definitions(self) -> tuple[GraphQlTypeDefinition, ...]:
        """Validate finite input/enum definitions; named cycles are preserved without expansion.

        Returns:
            Named structural types in deterministic identifier order.
        """

        result = []

        for name in sorted(self.records):
            if name.startswith("__"):
                continue

            record, pointer = self.records[name]
            kind = record["kind"]
            assert isinstance(kind, str), "Indexed named kinds must be text"
            inputs: tuple[GraphQlArgument, ...] = ()
            enums: tuple[str, ...] = ()

            if kind == "INPUT_OBJECT":
                if record.get("isOneOf") is not None and record.get("isOneOf") is not False:
                    raise ValueError("GraphQL oneOf input objects are outside this profile")

                inputs = self.Arguments(record.get("inputFields"), pointer + "/inputFields")

                if not inputs:
                    raise ValueError("GraphQL input objects require declared fields")

            elif kind == "ENUM":
                values = []

                for item in ApiImportArray(record.get("enumValues"), MAX_GRAPHQL_MEMBERS):
                    enum = GraphQlFields(item, {
                        "name", "description", "isDeprecated", "deprecationReason",
                    })
                    enum_name = GraphQlName(enum.get("name"))

                    if enum_name in {"true", "false", "null"} or enum_name in values:
                        raise ValueError("GraphQL enum values require unique non-literal names")

                    values.append(enum_name)

                if not values:
                    raise ValueError("GraphQL enums require declared values")

                enums = tuple(sorted(values))

            result.append(GraphQlTypeDefinition(kind, name, inputs, enums))

        self.CheckRequiredInputCycles(tuple(result))

        return tuple(result)

    def CheckRequiredInputCycles(self, definitions: tuple[GraphQlTypeDefinition, ...]) -> None:
        """Refuse invalid cycles made entirely of required singular input-object fields.

        Args:
            definitions: Finite validated named input types; nullable/list cycles remain metadata.

        Raises:
            ValueError: No finite input can satisfy a required singular cycle.
        """

        edges = {item.name: tuple(member.value_type.name for member in item.input_fields
            if member.value_type.kind == "INPUT_OBJECT"
            and member.value_type.wrappers == ("NON_NULL",)) for item in definitions}
        states: dict[str, int] = {}

        for name in edges:
            if states.get(name) == 2:
                continue

            pending = [(name, False)]

            while pending:
                current, finished = pending.pop()

                if finished:
                    states[current] = 2
                    continue

                if states.get(current) == 1:
                    raise ValueError("GraphQL required singular input cycles are invalid")

                if states.get(current) == 2:
                    continue

                states[current] = 1
                pending.append((current, True))
                pending.extend((child, False) for child in edges[current])


def ImportGraphQl(value: bytes, *, workspace_id: str, endpoint_url: str) -> GraphQlImport:
    """Import owned introspection bytes for an explicitly selected endpoint without I/O.

    Args:
        value: Exact original UTF-8 JSON bytes, not a path or retrieval URL.
        workspace_id: Existing request/model owner identifier.
        endpoint_url: Caller-selected concrete HTTP(S) URL with no query or path variables.

    Returns:
        Bounded typed root operations and input definitions with source-byte provenance.

    Raises:
        ValueError: Source, endpoint, named type references or finite profile limits are invalid.
    """

    target = Target(TargetKind.URL, endpoint_url)
    parsed = urlsplit(target.value)
    endpoint = Endpoint(workspace_id, f"{parsed.scheme}://{parsed.netloc}", parsed.path, "POST")

    if parsed.query or "?" in endpoint_url or endpoint.PathVariables():
        raise ValueError("GraphQL import requires a concrete endpoint URL without query")

    schema, pointer, digest = DecodeGraphQl(value)
    context = GraphQlImportContext(schema, pointer)
    types = context.Definitions()
    operations = []
    roots: set[str] = set()

    for operation_kind in ("query", "mutation", "subscription"):
        root = schema.get(operation_kind + "Type")

        if root is None:
            if operation_kind == "query":
                raise ValueError("GraphQL schema requires a query root")

            continue

        root_name = GraphQlName(GraphQlFields(root, {"name"}).get("name"))

        if root_name in roots or root_name not in context.records or (
            context.records[root_name][0]["kind"] != "OBJECT"
        ):
            raise ValueError("GraphQL roots require distinct indexed object types")

        roots.add(root_name)
        record, root_pointer = context.records[root_name]
        field_names: set[str] = set()

        for index, item in enumerate(ApiImportArray(record.get("fields"), MAX_GRAPHQL_OPERATIONS)):
            declared = GraphQlFields(item, {
                "name", "description", "args", "type", "isDeprecated", "deprecationReason",
            })
            name = GraphQlName(declared.get("name"))

            if name in field_names:
                raise ValueError("GraphQL root fields require unique names")

            field_names.add(name)
            source = ApiImportPointer(root_pointer + "/fields", index)
            arguments = context.Arguments(declared.get("args"), source + "/args")
            result_type = context.Type(declared.get("type"), _OUTPUT_KINDS)
            operation_name = "Gql" + operation_kind.title() + "_" + hashlib.sha256(
                name.encode("ascii")
            ).hexdigest()[:16]
            template = RequestTemplate(endpoint, tuple(ApiImportPoint(
                InjectionLocation.GRAPHQL, "/variables/" + argument.name,
            ) for argument in arguments), BodyKind.GRAPHQL, graphql_operation=operation_name)
            operations.append(GraphQlOperation(operation_kind, name, source, digest, target,
                                              template, arguments, result_type))

            if len(operations) > MAX_GRAPHQL_OPERATIONS:
                raise ValueError("GraphQL operation count exceeds its bound")

        if not field_names:
            raise ValueError("GraphQL roots require declared fields")

    result = GraphQlImport(workspace_id, digest,
        tuple(sorted(operations, key=lambda item: (item.operation_kind, item.field_name))), types)

    if len(CanonicalModelJson(result.ToDict())) > MAX_GRAPHQL_OUTPUT_BYTES:
        raise ValueError("GraphQL imported metadata exceeds its byte bound")

    return result


@dataclass(frozen=True, slots=True)
class GeneratedGraphQlRequest:
    """Hold one ephemeral synthetic JSON body; no execution or authentication grant exists."""

    operation: GraphQlOperation
    target: Target
    headers: tuple[tuple[str, str], ...]
    body: bytes = field(repr=False)

    def Reference(self) -> str:
        """Bind exact preview encoding and selected operation to the finite profile.

        Returns:
            Deterministic synthetic preview reference.
        """

        return RequestDigest("graphql-generated-request", {
            "profile_version": GRAPHQL_IMPORT_VERSION,
            "operation_reference": self.operation.Reference(), "target": self.target.value,
            "headers": self.headers, "body_sha256": hashlib.sha256(self.body).hexdigest(),
        })

    def Metadata(self) -> dict[str, object]:
        """Expose attributable references without copying concrete body bytes into model state.

        Returns:
            Source, request, operation, target and body-digest references.
        """

        return {"profile_version": GRAPHQL_IMPORT_VERSION,
                "generated_request_reference": self.Reference(),
                "operation_reference": self.operation.Reference(),
                "request_reference": self.operation.template.Reference(),
                "source_digest": self.operation.source_digest,
                "source_pointer": self.operation.source_pointer,
                "target_reference": self.target.Reference(),
                "body_sha256": "sha256:" + hashlib.sha256(self.body).hexdigest()}


class GraphQlGenerationContext:
    """Own bounded pure input expansion using typed declarations and finite synthetic values."""

    def __init__(self, types: tuple[GraphQlTypeDefinition, ...]) -> None:
        """Bind exact reimported definitions and a per-preview expansion budget."""

        self.types = {item.name: item for item in types}
        self.nodes = 0

    def Value(
        self, reference: GraphQlTypeReference, *, depth: int = 0, trail: tuple[str, ...] = (),
        wrapper_index: int = 0,
    ) -> object:
        """Generate deterministic typed values, refusing cycles and custom scalar assumptions.

        Args:
            reference: Exact source-validated finite named/wrapped input type.
            depth: Current wrapper/input-object expansion depth.
            trail: Active named input-object expansion chain.
            wrapper_index: Next outer-to-inner wrapper to consume.

        Returns:
            One synthetic scalar, declared enum name, fixed list or complete input object.

        Raises:
            ValueError: Cycles, unsupported scalar semantics or expansion budgets are encountered.
        """

        self.nodes += 1

        if self.nodes > MAX_GRAPHQL_GENERATED_NODES or depth > MAX_GRAPHQL_TYPE_DEPTH:
            raise ValueError("GraphQL generated input exceeds its node or depth bound")

        if wrapper_index < len(reference.wrappers):
            value = self.Value(reference, depth=depth + 1, trail=trail,
                               wrapper_index=wrapper_index + 1)

            return [value] if reference.wrappers[wrapper_index] == "LIST" else value

        definition = self.types[reference.name]

        if definition.kind == "SCALAR":
            scalars: dict[str, object] = {
                "Int": 0, "Float": 0.5, "Boolean": False,
                "String": "synthetic", "ID": "synthetic-id",
            }

            if definition.name not in scalars:
                raise ValueError("GraphQL custom scalar generation is outside this profile")

            return scalars[definition.name]

        if definition.kind == "ENUM":
            return definition.enum_values[0]

        if definition.name in trail:
            raise ValueError("GraphQL input cycles cannot be synthesized by this profile")

        active = (*trail, definition.name)

        return {item.name: self.Value(item.value_type, depth=depth + 1, trail=active)
                for item in definition.input_fields}


def GenerateGraphQlRequest(
    value: bytes, operation_reference: str, *, workspace_id: str, endpoint_url: str,
) -> GeneratedGraphQlRequest:
    """Reimport exact original bytes and prepare one anonymous synthetic preview without I/O.

    Args:
        value: Original introspection bytes; source/default literals are never rendered.
        operation_reference: Exact reference from ImportGraphQl for this source and endpoint.
        workspace_id: Same existing owner used during import.
        endpoint_url: Same explicit concrete endpoint context used during import.

    Returns:
        Ephemeral POST JSON body and fixed content-type header without transport permission.

    Raises:
        ValueError: Reference substitution, unsupported input semantics or body limits fail.
    """

    imported = ImportGraphQl(value, workspace_id=workspace_id, endpoint_url=endpoint_url)
    operations = {item.Reference(): item for item in imported.operations}

    if not isinstance(operation_reference, str) or operation_reference not in operations:
        raise ValueError("GraphQL generation requires an exact source-bound operation reference")

    operation = operations[operation_reference]

    if operation.operation_kind == "subscription":
        raise ValueError("GraphQL subscription transport is outside the preview profile")

    generator = GraphQlGenerationContext(imported.types)
    variables = {item.name: generator.Value(item.value_type) for item in operation.arguments}
    declaration = ", ".join("$" + item.name + ": " + item.value_type.Expression()
                            for item in operation.arguments)
    arguments = ", ".join(item.name + ": $" + item.name for item in operation.arguments)
    query = operation.operation_kind + " " + str(operation.template.graphql_operation)
    query += "(" + declaration + ")" if declaration else ""
    query += " { " + operation.field_name + ("(" + arguments + ")" if arguments else "")
    query += " { __typename }" if operation.result_type.kind in {
        "OBJECT", "INTERFACE", "UNION",
    } else ""
    query += " }"
    body = CanonicalModelJson({"query": query,
        "operationName": operation.template.graphql_operation, "variables": variables})

    if len(body) > MAX_GRAPHQL_BODY_BYTES:
        raise ValueError("GraphQL synthetic body exceeds its byte bound")

    return GeneratedGraphQlRequest(operation, operation.target,
                                  (("content-type", "application/json"),), body)


def RequireGraphQlType(reference: object, allowed: set[str]) -> None:
    """Require closed immutable type metadata before consuming a caller-constructed record.

    Args:
        reference: Candidate producer type record, including values rebuilt by dataclasses.replace.
        allowed: Permitted named kinds for this input/output coordinate.

    Raises:
        ValueError: A substituted type or wrapping sequence is outside the producer contract.
    """

    if type(reference) is not GraphQlTypeReference:
        raise ValueError("GraphQL consumers require the closed producer type record")

    GraphQlName(reference.name)

    if not isinstance(reference.kind, str) or reference.kind not in allowed or (
        type(reference.wrappers) is not tuple
        or len(reference.wrappers) > MAX_GRAPHQL_TYPE_DEPTH
        or any(not isinstance(item, str) or item not in {"LIST", "NON_NULL"}
               for item in reference.wrappers)
        or any(left == right == "NON_NULL"
               for left, right in zip(reference.wrappers, reference.wrappers[1:]))
    ):
        raise ValueError("GraphQL consumed type metadata is invalid")


def RequireGraphQlArguments(arguments: object) -> None:
    """Validate immutable symbolic arguments without trusting replaceable source annotations.

    Args:
        arguments: Candidate exact producer argument/input-field tuple.

    Raises:
        ValueError: Types, pointers, identifiers, default flags or member bounds are invalid.
    """

    if type(arguments) is not tuple or len(arguments) > MAX_GRAPHQL_MEMBERS:
        raise ValueError("GraphQL consumers require a bounded immutable argument tuple")

    names = []

    for argument in arguments:
        if type(argument) is not GraphQlArgument or type(argument.has_default) is not bool or (
            not isinstance(argument.source_pointer, str)
            or not argument.source_pointer.startswith("#/")
        ):
            raise ValueError("GraphQL consumed argument metadata is invalid")

        names.append(GraphQlName(argument.name))
        RequirePointer(argument.source_pointer[1:])
        RequireGraphQlType(argument.value_type, _INPUT_KINDS)

    if names != sorted(set(names)):
        raise ValueError("GraphQL consumed arguments require sorted unique names")


def RequireGraphQlOperation(operation: object) -> None:
    """Bind an exact producer operation to its concrete template target and typed variables.

    Args:
        operation: Candidate closed producer value; no source authenticity is attested.

    Raises:
        ValueError: Endpoint, operation kind, attribution or symbolic template was substituted.
    """

    if type(operation) is not GraphQlOperation or type(operation.target) is not Target or (
        type(operation.template) is not RequestTemplate
        or type(operation.template.endpoint) is not Endpoint
        or operation.target.kind is not TargetKind.URL
    ):
        raise ValueError("GraphQL consumers require a closed operation, target and template")

    if not isinstance(operation.operation_kind, str) or operation.operation_kind not in {
        "query", "mutation", "subscription",
    } or not isinstance(operation.source_digest, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", operation.source_digest,
    ) or not isinstance(operation.source_pointer, str) or not re.fullmatch(
        r"#/(?:data/)?__schema/types/(?:0|[1-9][0-9]*)/fields/(?:0|[1-9][0-9]*)",
        operation.source_pointer,
    ):
        raise ValueError("GraphQL consumed operation kind or source attribution is invalid")

    GraphQlName(operation.field_name)
    RequireGraphQlArguments(operation.arguments)
    RequireGraphQlType(operation.result_type, _OUTPUT_KINDS)
    endpoint = operation.template.endpoint
    expected_target = Target(TargetKind.URL, endpoint.origin + endpoint.path_template)
    expected_name = "Gql" + operation.operation_kind.title() + "_" + hashlib.sha256(
        operation.field_name.encode("ascii")
    ).hexdigest()[:16]
    expected_template = RequestTemplate(endpoint, tuple(ApiImportPoint(
        InjectionLocation.GRAPHQL, "/variables/" + item.name,
    ) for item in operation.arguments), BodyKind.GRAPHQL, graphql_operation=expected_name)

    if endpoint.method != "POST" or endpoint.PathVariables() or (
        operation.target != expected_target or operation.template != expected_template
    ):
        raise ValueError("GraphQL consumed target and template must match the producer context")


def RequireGraphQlImport(imported: object) -> None:
    """Keep projection attribution coherent with every operation's original producer context.

    Args:
        imported: Candidate closed finite import; raw source bytes remain separately owned evidence.

    Raises:
        ValueError: Workspace, digest, operation collection or named type metadata is inconsistent.
    """

    if type(imported) is not GraphQlImport or type(imported.operations) is not tuple or (
        not 1 <= len(imported.operations) <= MAX_GRAPHQL_OPERATIONS
        or type(imported.types) is not tuple or not 1 <= len(imported.types) <= MAX_GRAPHQL_TYPES
    ):
        raise ValueError("GraphQL projection requires a closed bounded import")

    definitions = {}

    for definition in imported.types:
        if type(definition) is not GraphQlTypeDefinition or (
            not isinstance(definition.kind, str)
        ) or (
            definition.kind not in _KINDS or type(definition.enum_values) is not tuple
            or len(definition.enum_values) > MAX_GRAPHQL_MEMBERS
        ):
            raise ValueError("GraphQL consumed named type definition is invalid")

        name = GraphQlName(definition.name)
        RequireGraphQlArguments(definition.input_fields)

        if name in definitions or (
            name in {"Int", "Float", "Boolean", "String", "ID"} and definition.kind != "SCALAR"
        ) or (bool(definition.input_fields) != (definition.kind == "INPUT_OBJECT")) or (
            bool(definition.enum_values) != (definition.kind == "ENUM")
        ):
            raise ValueError("GraphQL consumed named definitions contradict their kinds")

        values = [GraphQlName(item) for item in definition.enum_values]

        if values != sorted(set(values)) or set(values) & {"true", "false", "null"}:
            raise ValueError("GraphQL consumed enums require sorted unique declared names")

        definitions[name] = definition

    keys = []
    endpoint: Endpoint | None = None
    references = [item.value_type for definition in imported.types
                  for item in definition.input_fields]

    for operation in imported.operations:
        RequireGraphQlOperation(operation)

        if operation.template.endpoint.workspace_id != imported.workspace_id or (
            operation.source_digest != imported.source_digest
            or endpoint is not None and operation.template.endpoint != endpoint
        ):
            raise ValueError("GraphQL import attribution must match every operation producer")

        endpoint = operation.template.endpoint
        keys.append((operation.operation_kind, operation.field_name))
        references.extend(item.value_type for item in operation.arguments)
        references.append(operation.result_type)

    if keys != sorted(set(keys)):
        raise ValueError("GraphQL consumed operations require sorted unique root fields")

    for reference in references:
        if reference.name not in definitions or definitions[reference.name].kind != reference.kind:
            raise ValueError("GraphQL consumed references must match their named definitions")


def ProjectGraphQl(
    imported: GraphQlImport, *, provenance: tuple[ModelProvenance, ...],
) -> SecurityObject:
    """Compose complete existing request collections with typed source/evidence attribution.

    Args:
        imported: Validated offline import for one caller-selected endpoint.
        provenance: Nonempty existing model attribution with caller-owned evidence references.

    Returns:
        Existing Endpoint patch; caller owns Apply, persistence and complete-source composition.

    Raises:
        ValueError: Import, request ownership, provenance or existing model attribute limits fail.
    """

    RequireGraphQlImport(imported)
    projection = ProjectRequests(tuple(item.template for item in imported.operations),
                                 provenance=provenance)

    return SecurityObject(projection.identity, {
        **projection.attributes, "graphql_import": imported.ToDict(),
    }, projection.provenance)


def CheckGraphQlTarget(
    operation: GraphQlOperation, target: Target, scope: ScopeSnapshot, *, at: datetime,
) -> ScopeDecision:
    """Check current exact scope membership without approving query/mutation impact or transport.

    Args:
        operation: Source-bound descriptive operation, not an execution authorization.
        target: Actual caller-selected URL; must equal the imported concrete endpoint.
        scope: Current matching-workspace scope snapshot with explicit existing consent/rules.
        at: Explicit aware membership time consumed by the existing scope validator.

    Returns:
        Existing allowed scope decision, with no state mutation or execution grant.

    Raises:
        ValueError: Types, exact endpoint, workspace or decision time are invalid.
        PermissionError: Current explicit scope or consent denies the actual URL.
    """

    RequireGraphQlOperation(operation)

    if type(target) is not Target or (
        type(scope) is not ScopeSnapshot or target != operation.target
        or target.kind is not TargetKind.URL
        or scope.workspace_id != operation.template.endpoint.workspace_id
    ):
        raise ValueError("GraphQL preflight requires the exact imported target and workspace")

    decision = scope.Check(target, at=at)

    if not decision.Allowed():
        raise PermissionError("GraphQL concrete target rejected by scope: " + decision.reason.value)

    return decision
