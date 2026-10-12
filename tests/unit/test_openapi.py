# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Adversarial offline OpenAPI parsing, work bounds, server identity and scope preflight."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone

import pytest

from fuzzy1337.openapi import (
    MAX_OPENAPI_BYTES,
    CheckOpenApiTarget,
    ImportOpenApi,
    ProjectOpenApi,
)
from fuzzy1337.requests import BodyKind, InjectionLocation, SessionReference
from fuzzy1337.scope import (
    AuthorizationState,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)

AT = datetime(2026, 10, 13, tzinfo=timezone.utc)


def Document() -> dict:
    """Create a minimal structural API with one required path and one query parameter."""

    return {
        "openapi": "3.1.0", "servers": [{"url": "http://127.0.0.1:19001/base"}],
        "paths": {"/items/{item_id}": {"get": {"parameters": [
            {"in": "path", "name": "item_id", "required": True, "schema": {"type": "integer"}},
            {"in": "query", "name": "q", "schema": {"type": "string"}},
        ]}}},
    }


def Operation(document: dict) -> dict:
    """Return the synthetic fixture's primary operation for explicit mutation tests."""

    return document["paths"]["/items/{item_id}"]["get"]


def Import(document: dict, **options):
    """Exercise the public strict JSON producer instead of internal parser helpers."""

    return ImportOpenApi(json.dumps(document), workspace_id="demo", **options)


@pytest.mark.parametrize("version", ["3.0.0", "3.0.4", "3.1.0", "3.1.2"])
def test_SupportedVersionsGenerateSymbolicImmutableRequests(version):
    """Every supported feature line preserves a real path/query request without sending traffic."""

    document = Document()
    document["openapi"] = version
    imported = Import(document, session_reference=SessionReference("demo", "operator"))
    operation = imported.operations[0]
    assert operation.template.endpoint.path_template == "/base/items/{item_id}", (
        "OpenAPI expectation failed: "
        "operation.template.endpoint.path_template == "
        "'/base/items/{item_id}' "
    )
    assert operation.template.endpoint.method == "GET", (
        "OpenAPI expectation failed: operation.template.endpoint.method "
        "== 'GET' "
    )
    assert operation.template.session_reference == SessionReference("demo", "operator"), (
        "OpenAPI expectation failed: "
        "operation.template.session_reference == "
        "SessionReference('demo', 'operator') "
    )
    assert {item.point.location for item in operation.inputs} == {
        InjectionLocation.PATH, InjectionLocation.QUERY,
    }, (
        "OpenAPI expectation failed: {item.point.location for item in "
        "operation.inputs} == {InjectionLocation.PATH, "
        "InjectionLocation.QUERY} "
    )
    assert all(item.point.binding.name.startswith("value-") for item in operation.inputs), (
        "OpenAPI expectation failed: "
        "all((item.point.binding.name.startswith('value-') for item in "
        "operation.inputs)) "
    )
    original = imported.ToDict()
    document["paths"].clear()
    derived = imported.ToDict()
    derived["operations"].clear()
    assert imported.ToDict() == original, "Input/output mutation altered imported records"

    with pytest.raises(FrozenInstanceError):
        imported.operations = ()


@pytest.mark.parametrize("value", [
    None, 42, "null", "[]", "{", '{"openapi":"3.1.0","openapi":"3.1.0"}',
    '{"value":NaN}', '{"value":Infinity}', '{"value":1e999}', '\ud800',
    '{"value":"\\ud800"}', " " * (MAX_OPENAPI_BYTES + 1), "[" * 2000,
], ids=[
    "nontext-null", "nontext-integer", "json-null", "json-array", "truncated-json",
    "duplicate-key", "nan", "infinity", "overflow-number", "raw-surrogate",
    "escaped-surrogate", "oversized-json", "deep-json",
])
def test_StrictJsonRejectsDuplicatesConstantsUnicodeAndOversizedInputs(value):
    """Untrusted input fails as a validation error before producing any operation metadata."""

    with pytest.raises(ValueError):
        ImportOpenApi(value, workspace_id="demo")


@pytest.mark.parametrize("change", [
    {"openapi": "3.2.0"}, {"openapi": 3.1}, {"openapi": "2.0"},
    {"openapi": "3.1.0", "swagger": "2.0"}, {"paths": []}, {"paths": {}},
    {"servers": []}, {"servers": "http://127.0.0.1/"},
])
def test_UnsupportedVersionsAndUnownedServerDefaultsFailClosed(change):
    """The importer neither guesses a retrieval URL nor silently accepts another dialect."""

    document = Document()
    document.update(change)

    with pytest.raises(ValueError):
        Import(document)


@pytest.mark.parametrize("server", [
    "https://user:synthetic@localhost/", "http://localhost/?token=synthetic",
    "http://localhost/?", "http://localhost/{tenant}", "http://localhost/../outside",
    "//outside.test/api", "api-relative", "file:///tmp/schema", 42,
])
def test_ServerAddressesCannotCarryCapturedOrAmbiguousTargetMaterial(server):
    """Unsafe authority, path, variables and non-HTTP addressing cannot become endpoints."""

    document = Document()
    document["servers"] = [{"url": server}]

    with pytest.raises(ValueError):
        Import(document, base_url="http://127.0.0.1:19001/")


def test_ServerPrecedenceRelativeContextAndAliasesAreExplicit():
    """Operation overrides path/root servers while relative servers use a supplied authority."""

    document = Document()
    path = document["paths"]["/items/{item_id}"]
    path["servers"] = [{"url": "http://127.0.0.1:19001/path"}]
    assert Import(document).operations[0].template.endpoint.path_template.startswith("/path/"), (
        "OpenAPI expectation failed: "
        "Import(document).operations[0].template.endpoint.path_template.startswith('/path/') "
    )
    Operation(document)["servers"] = [{"url": "/op"}]
    imported = Import(document, base_url="http://127.0.0.1:19001/context")
    assert imported.operations[0].template.endpoint.path_template == "/op/items/{item_id}", (
        "OpenAPI expectation failed: "
        "imported.operations[0].template.endpoint.path_template == "
        "'/op/items/{item_id}' "
    )
    Operation(document)["servers"] = []
    contextual = Import(document, base_url="http://127.0.0.1:19001/context")
    assert contextual.operations[0].template.endpoint.path_template == "/items/{item_id}", (
        "OpenAPI expectation failed: "
        "contextual.operations[0].template.endpoint.path_template == "
        "'/items/{item_id}' "
    )
    document["servers"] = [{"url": "HTTP://localhost:80"}, {"url": "http://localhost/"}]
    del path["servers"]
    del Operation(document)["servers"]
    assert len(Import(document).operations) == 1, "Server aliases created duplicate variants"


@pytest.mark.parametrize("parameter", [
    {"in": "unknown", "name": "q"}, {"in": "body", "name": "body"},
    {"in": "formData", "name": "form"}, {"in": "query", "name": "with space"},
    {"in": "query", "name": "q", "required": 1},
    {"in": "header", "name": "Authorization"}, {"in": "header", "name": "Content-Type"},
    {"in": "query", "name": "q", "content": {}},
    {"in": "query", "name": "q", "style": "deepObject"},
    {"in": "query", "name": "q", "allowReserved": True},
    {"in": "query", "name": "q", "explode": "true"},
    {"in": "query", "name": "q", "schema": {"type": "file"}},
    {"in": "query", "name": "q", "schema": {"type": ["null", "null"]}},
    {"in": "query", "name": "q", "schema": {"type": "unknown"}},
    {"in": "query", "name": "q", "schema": True},
    {"in": "query", "name": "q", "schema": {"$id": "https://outside.test/"}},
    {"in": "query", "name": "q", "schema": {"allOf": []}},
    {"in": "query", "name": "q", "schema": {"nullable": True}},
])
def test_ConsumedUnsupportedParameterSemanticsDoNotReturnPartialResults(parameter):
    """Supported fields are validated rather than repairing malformed/unsupported declarations."""

    document = Document()
    Operation(document)["parameters"][1] = parameter

    with pytest.raises(ValueError):
        Import(document)


def test_PathBindingDuplicatesOperationIdentityAndNullableDialectValidation():
    """Parameter overrides retain exact coordinate identity and dialect-specific nullable flags."""

    document = Document()
    path_parameter = Operation(document)["parameters"][0]
    path_parameter["required"] = False

    with pytest.raises(ValueError, match="required"):
        Import(document)

    path_parameter["required"] = True
    path_parameter["name"] = "other"

    with pytest.raises(ValueError):
        Import(document)

    document = Document()
    Operation(document)["parameters"].append(deepcopy(Operation(document)["parameters"][1]))

    with pytest.raises(ValueError, match="unique"):
        Import(document)

    document = Document()
    Operation(document)["operationId"] = "Same"
    document["paths"]["/another/{item_id}"] = deepcopy(document["paths"]["/items/{item_id}"])

    with pytest.raises(ValueError, match="operationId"):
        Import(document)

    document = Document()
    document["openapi"] = "3.0.4"
    Operation(document)["parameters"][1]["schema"]["nullable"] = True
    assert next(item for item in Import(document).operations[0].inputs
                if item.point.selector == "q").nullable, (
        "OpenAPI expectation failed: next((item for item in "
        "Import(document).operations[0].inputs if item.point.selector "
        "== 'q')).nullable "
    )
    Operation(document)["parameters"][1]["schema"]["type"] = ["string", "null"]

    with pytest.raises(ValueError):
        Import(document)


@pytest.mark.parametrize("dialect", ["3.0.4", "2.0"])
def test_DialectSpecificNullTypesCannotBeImportedAsSupportedSchemas(dialect):
    """Pre-3.1 dialects cannot silently inherit a newer structural null type."""

    document = Document()
    document["openapi"] = dialect
    Operation(document)["parameters"][1]["schema"] = {"type": "null"}

    if dialect == "2.0":
        document["swagger"] = document.pop("openapi")
        document["host"] = "127.0.0.1:19001"
        document["schemes"] = ["http"]
        Operation(document)["parameters"] = [
            {"in": "path", "name": "item_id", "required": True, "type": "integer"},
            {"in": "query", "name": "q", "type": "null"},
        ]

    with pytest.raises(ValueError, match="null schema"):
        Import(document)


def test_HeaderAliasesConvergeBeforeSymbolicBindingIdentity():
    """Canonical header coordinates determine binding identity regardless of source case."""

    document = Document()
    Operation(document)["parameters"].append({"in": "header", "name": "X-Owned"})
    upper = Import(document).operations[0].template
    Operation(document)["parameters"][-1]["name"] = "x-owned"
    lower = Import(document).operations[0].template
    assert upper.Reference() == lower.Reference(), "Header alias changed canonical request identity"


def test_StandaloneOpenApi31NullSchemaRetainsNullableMeaning():
    """A schema permitting only null cannot advertise that null itself is forbidden."""

    document = Document()
    Operation(document)["parameters"][1]["schema"] = {"type": "null"}
    point = next(item for item in Import(document).operations[0].inputs
                 if item.point.selector == "q")
    assert point.value_type == "null" and point.nullable, "Standalone null lost its schema meaning"


def test_OptionalBodiesKeepConditionalRequiredPropertyMetadata():
    """An optional body does not erase required properties when the body is actually present."""

    document = Document()
    Operation(document)["requestBody"] = {"required": False, "content": {"application/json": {
        "schema": {"type": "object", "required": ["name"], "properties": {
            "name": {"type": "string"}, "optional": {"type": "string"},
        }},
    }}}
    operation = Import(document).operations[0]
    name = next(item for item in operation.inputs if item.point.selector == "/name")
    optional = next(item for item in operation.inputs if item.point.selector == "/optional")
    assert not operation.body_required, "Optional body became globally mandatory"
    assert not name.required and name.schema_required, "Conditional body requirement was lost"
    assert not optional.schema_required, "Optional property became conditionally required"


def test_OpaqueObjectParametersMarkUnrepresentedShapeConstraints():
    """An opaque object cannot claim its omitted property constraints were represented."""

    document = Document()
    Operation(document)["parameters"][1]["schema"] = {
        "type": "object", "properties": {"name": {"type": "string", "enum": ["synthetic"]}},
        "required": ["name"],
    }
    point = next(item for item in Import(document).operations[0].inputs
                 if item.point.selector == "q")
    assert point.value_type == "object" and point.constrained, "Object constraints were hidden"


@pytest.mark.parametrize("reference", [
    "https://outside.test/schema.json", "file:///tmp/source", "other.json#/schema",
    "#anchor", "#/missing", "#/parts/01", "#/parts/9", "#/parts/0/no", "#/invalid~2",
])
def test_ReferencesAreLocalCanonicalFiniteAndNeverFetched(reference):
    """Only valid same-document pointers can resolve; no source is opened or retrieved."""

    document = Document()
    document["parts"] = [{"type": "string"}]
    Operation(document)["parameters"][1]["schema"] = {"$ref": reference}

    with pytest.raises(ValueError):
        Import(document)


def test_LocalPointersCyclesSiblingSemanticsAndReferenceWorkBounds():
    """Escaped pointer names work while recursive/ambiguous or excessive references fail closed."""

    document = Document()
    document["parts"] = [{"type": "string"}]
    Operation(document)["parameters"][1]["schema"] = {"$ref": "#/parts/0"}
    assert Import(document).operations[0].inputs, (
        "OpenAPI expectation failed: "
        "Import(document).operations[0].inputs "
    )
    document["parts"][0] = {"$ref": "#/parts/0"}

    with pytest.raises(ValueError, match="cycle"):
        Import(document)

    document["parts"] = [{"$ref": f"#/parts/{index + 1}"} for index in range(18)]
    document["parts"].append({"type": "string"})

    with pytest.raises(ValueError, match="bound"):
        Import(document)

    Operation(document)["parameters"][1]["schema"]["type"] = "string"

    with pytest.raises(ValueError, match="siblings"):
        Import(document)


def test_BodyReferenceCyclesAndBoundedExpansionCannotHideInShallowInput():
    """Local references cannot turn a shallow document into an unbounded generated body."""

    document = Document()
    document["components"] = {"schemas": {"Node": {
        "type": "object", "properties": {"child": {"$ref": "#/components/schemas/Node"}},
    }}}
    Operation(document)["requestBody"] = {"content": {"application/json": {
        "schema": {"$ref": "#/components/schemas/Node"},
    }}}

    with pytest.raises(ValueError, match="cycle"):
        Import(document)

    schemas = {f"node-{index}": {
        "type": "object", "properties": {"child": {
            "$ref": f"#/components/schemas/node-{index + 1}",
        }},
    } for index in range(18)}
    schemas["node-18"] = {"type": "string"}
    document["components"]["schemas"] = schemas
    Operation(document)["requestBody"]["content"]["application/json"]["schema"] = {
        "$ref": "#/components/schemas/node-0",
    }

    with pytest.raises(ValueError, match="bound"):
        Import(document)


def test_ReferenceWorkBudgetBoundsRepeatedSharedComponents():
    """Acyclic reuse still consumes a finite aggregate parsing budget across operations."""

    document = Document()
    document["components"] = {"parameters": {
        f"param-{index}": {"in": "query", "name": f"p{index}", "schema": {"type": "string"}}
        for index in range(64)
    }}
    parameters = [{"$ref": f"#/components/parameters/param-{index}"} for index in range(64)]
    document["paths"] = {f"/op-{index}": {"get": {"parameters": parameters}} for index in range(33)}

    with pytest.raises(ValueError, match="work"):
        Import(document)


def test_NestedJsonEscapedPropertiesAndOpaqueArrayBindingsRetainConstraintFlags():
    """Selectors remain reversible and unrepresented parent/item constraints remain explicit."""

    document = Document()
    schema = {"type": "object", "additionalProperties": False, "properties": {
        "a/b~c": {"type": "object", "properties": {"child": {"type": "string"}}},
        "items": {"type": "array", "items": {"type": "string"}},
    }}
    Operation(document)["requestBody"] = {"content": {"application/json": {"schema": schema}}}
    inputs = [item for item in Import(document).operations[0].inputs
              if item.point.location is InjectionLocation.JSON]
    assert {item.point.selector for item in inputs} == {"/a~1b~0c/child", "/items"}, (
        "OpenAPI expectation failed: {item.point.selector for item in "
        "inputs} == {'/a~1b~0c/child', '/items'} "
    )
    assert all(item.constrained for item in inputs), (
        "OpenAPI expectation failed: all((item.constrained for item in "
        "inputs)) "
    )


@pytest.mark.parametrize("media", [
    "application/json", "application/vnd.synthetic+json", "text/plain",
    "application/x-www-form-urlencoded", "multipart/form-data",
])
def test_BodyVariantsProduceCorrectLocationsWithoutExamples(media):
    """Each supported media family yields actual bounded structural request descriptors."""

    document = Document()
    schema = {"type": "string"} if media == "text/plain" else {
        "type": "object", "properties": {"name": {"type": "string", "example": "marker"}},
    }
    Operation(document)["requestBody"] = {"content": {media: {"schema": schema}}}
    operation = Import(document).operations[0]
    assert operation.media_type == media, (
        "OpenAPI expectation failed: operation.media_type == media "
    )
    assert operation.template.body_kind is not BodyKind.NONE, (
        "OpenAPI expectation failed: operation.template.body_kind is "
        "not BodyKind.NONE "
    )
    assert "marker" not in json.dumps(operation.ToDict()), "A literal example was copied"


@pytest.mark.parametrize("body", [
    {"content": {}}, {"content": {"application/xml": {}}},
    {"content": {"application/json": {"encoding": {"x": {}}}}},
    {"content": {"application/x-www-form-urlencoded": {"schema": {"type": "string"}}}},
    {"content": {"application/json": {"schema": {
        "type": "object", "properties": {"x": {"type": "string"}}, "required": ["missing"],
    }}}},
    {"content": {"application/x-www-form-urlencoded": {"schema": {
        "type": "object", "properties": {"x": {"type": "object", "properties": {"y": {}}}},
    }}}},
])
def test_UnsupportedBodySemanticsAreExplicitFailures(body):
    """The importer never labels an unsupported body as an empty supported request."""

    document = Document()
    Operation(document)["requestBody"] = body

    with pytest.raises(ValueError):
        Import(document)


def test_JsonNodeDepthVariantCountAndOutputByteBounds(monkeypatch):
    """Both ignored source material and generated variants remain within explicit finite limits."""

    document = Document()
    document["x-padding"] = [0] * 20001

    with pytest.raises(ValueError, match="nodes"):
        Import(document)

    document = Document()
    nested = []

    for _ in range(40):
        nested = [nested]

    document["x-padding"] = nested

    with pytest.raises(ValueError, match="nesting"):
        Import(document)

    document = Document()
    document["paths"] = {f"/items-{index}": {"get": {}} for index in range(129)}

    with pytest.raises(ValueError, match="operation variants"):
        Import(document)

    monkeypatch.setattr("fuzzy1337.openapi.MAX_OPENAPI_OUTPUT_BYTES", 1)

    with pytest.raises(ValueError, match="output"):
        Import(Document())


def test_ConcreteTargetPreflightChecksCurrentScopeAndNeverUsesPathWildcards():
    """A route grants nothing until its actual URL is registered and explicitly allowed."""

    operation = Import(Document()).operations[0]
    target = Target(TargetKind.URL, "http://127.0.0.1:19001/base/items/1?q=actual")
    scope = ScopeSnapshot("api", "demo", ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:synthetic", "consent:synthetic",
    ), targets=(target,), allow=(target,))
    assert CheckOpenApiTarget(operation, target, scope, at=AT).Allowed(), (
        "OpenAPI expectation failed: CheckOpenApiTarget(operation, "
        "target, scope, at=AT).Allowed() "
    )

    for change in ({"targets": ()}, {"allow": ()}, {"deny": (target,)}, {
        "authorization": ScopeAuthorization(AuthorizationState.UNKNOWN),
    }):
        with pytest.raises(PermissionError):
            CheckOpenApiTarget(operation, target, replace(scope, **change), at=AT)

    for url in (
        "http://127.0.0.1:19002/base/items/1", "http://127.0.0.1:19001/base/outside/1",
        "http://127.0.0.1:19001/base/items/", "http://127.0.0.1:19001/base/items/1/extra",
    ):
        with pytest.raises(ValueError):
            CheckOpenApiTarget(operation, Target(TargetKind.URL, url), scope, at=AT)

    with pytest.raises(ValueError):
        CheckOpenApiTarget(operation, target, replace(scope, workspace_id="other"), at=AT)

    with pytest.raises(ValueError):
        CheckOpenApiTarget(operation, target, scope, at=datetime(2026, 10, 13))

    with pytest.raises(ValueError):
        CheckOpenApiTarget(None, target, scope, at=AT)

    with pytest.raises(ValueError):
        ProjectOpenApi(None, provenance=())
