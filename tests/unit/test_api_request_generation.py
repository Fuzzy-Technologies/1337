# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Adversarial original-schema validation, exact-source binding and request byte bounds."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from traceback import format_exception
from urllib.parse import parse_qsl, urlsplit

import pytest
from jsonschema import Draft202012Validator, ValidationError

from fuzzy1337.api_request_generation import GenerateOpenApiRequest
from fuzzy1337.openapi import ImportOpenApi
from fuzzy1337.requests import SessionReference

ROOT = Path(__file__).resolve().parents[2]


def Document(version="3.1.0") -> dict:
    """Build an anonymous source with a real selected operation.

    Args:
        version: Supported OpenAPI dialect for the synthetic document.

    Returns:
        Mutable source fixture for explicit original-field mutations.
    """

    return {"openapi": version, "servers": [{"url": "http://127.0.0.1:19001/api"}],
            "paths": {"/owned": {"post": {"operationId": "Owned", "responses": {
                "200": {"description": "Owned response"},
            }}}}}


def Operation(document: dict) -> dict:
    """Locate the fixture operation without asking the importer to create the source oracle.

    Args:
        document: The minimal synthetic source fixture.

    Returns:
        Mutable primary source operation.
    """

    return document["paths"]["/owned"]["post"]


def Body(document: dict, schema: object, media="application/json") -> None:
    """Declare an optional original body with the chosen schema and media.

    Args:
        document: Source fixture whose primary operation is changed.
        schema: Exact schema assertions, including unsupported adversarial fields.
        media: Selected literal source media token.
    """

    Operation(document)["requestBody"] = {"required": False, "content": {media: {"schema": schema}}}


def Generate(document: dict):
    """Exercise both public producers with the exact same bytes and workspace context.

    Args:
        document: Original synthetic API schema document.

    Returns:
        Concrete offline synthetic request preview.
    """

    text = json.dumps(document)
    operation = ImportOpenApi(text, workspace_id="generation-unit").operations[0]

    return GenerateOpenApiRequest(text, operation.Reference(), workspace_id="generation-unit")


@pytest.mark.parametrize("value_type,expected", [
    ("string", "synthetic"), ("integer", 1), ("number", 1.5), ("boolean", True), ("null", None),
])
@pytest.mark.parametrize("array", [False, True])
def test_ExplicitPrimitiveJsonSchemasGenerateValidFiniteValues(value_type, expected, array):
    """Independent JSON schema validation checks scalar and homogeneous primitive samples."""

    schema = {"type": value_type}

    if array:
        schema = {"type": "array", "items": schema}

    document = Document()
    Body(document, schema)
    payload = json.loads(Generate(document).body)
    Draft202012Validator(schema).validate(payload)

    if array:
        first = "synthetic-0" if value_type == "string" else expected
        assert len(payload) == 2 and payload[0] == first, (
            "Primitive array sample shape or first value changed"
        )

    else:
        assert payload == expected and type(payload) is type(expected), "Scalar type/value changed"


@pytest.mark.parametrize("version,schema", [
    ("3.0.4", {"type": "string", "nullable": True}),
    ("3.1.2", {"type": ["null", "string"]}),
    ("3.1.0", {"type": ["object", "null"], "properties": {"name": {"type": "string"}}}),
])
def test_NullableBaseTypesSelectTheirSupportedNonNullSample(version, schema):
    """Nullable metadata does not force null or weaken original fixed-object validation."""

    document = Document(version)
    Body(document, schema)
    payload = json.loads(Generate(document).body)
    assert payload == ({"name": "synthetic"} if "properties" in schema else "synthetic"), (
        "Nullable base type lost its deterministic non-null sample"
    )


@pytest.mark.parametrize("keyword,value", [
    ("format", "uuid"), ("enum", ["private"]), ("const", "private"),
    ("minimum", 10), ("maximum", 0), ("exclusiveMinimum", 10), ("multipleOf", 7),
    ("pattern", "^private$"), ("minLength", 50), ("maxLength", 0),
    ("minItems", 4), ("maxItems", 0), ("uniqueItems", True),
    ("additionalProperties", False), ("unevaluatedProperties", False),
    ("readOnly", True), ("writeOnly", False), ("x-private-assertion", "private"),
])
def test_UnimplementedOriginalAssertionsNeverBecomeApparentlyValidSamples(keyword, value):
    """Original assertion fields fail closed even when a structural type summary is usable."""

    document = Document()
    Body(document, {"type": "string", keyword: value})

    with pytest.raises(ValueError, match="bounded synthetic"):
        Generate(document)


def test_LossyUnconstrainedSummaryDoesNotCertifyConditionalObjectRequirements():
    """An importer summary cannot hide an original dependency that defeats a naive sample."""

    schema = {"type": "object", "properties": {"present": {"type": "string"}},
              "dependentRequired": {"present": ["absent"]}}
    document = Document()
    Body(document, schema)
    text = json.dumps(document)
    imported = ImportOpenApi(text, workspace_id="generation-unit")
    assert not imported.operations[0].inputs[0].constrained, "Repro no longer uses a false summary"

    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate({"present": "synthetic"})

    with pytest.raises(ValueError, match="bounded synthetic"):
        GenerateOpenApiRequest(
            text, imported.operations[0].Reference(), workspace_id="generation-unit",
        )


@pytest.mark.parametrize("schema", [
    {}, {"properties": {"name": {"type": "string"}}},
    {"type": "object"}, {"type": "array"},
    {"type": "array", "items": {"type": "object", "properties": {}}},
    {"type": "array", "items": {"type": "array", "items": {"type": "string"}}},
    {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["missing"]},
])
def test_UnspecifiedStructuredAndInvalidRequiredSchemasFailClosed(schema):
    """Explicit fixed shapes are necessary; nested array structures remain outside the profile."""

    document = Document()
    Body(document, schema)

    with pytest.raises(ValueError):
        Generate(document)


def test_EffectiveOverridesAndEscapedLocalReferencesUseOriginalSelectedSources():
    """Only effective operation parameters and the resolved path item govern generated values."""

    document = Document()
    selected = document["paths"].pop("/owned")
    selected["parameters"] = [{"in": "query", "name": "q", "schema": {
        "type": "string", "pattern": "^private$",
    }}]
    selected["post"]["parameters"] = [{"in": "query", "name": "q", "schema": {
        "$ref": "#/components/schemas/a~1b~0c",
    }}]
    document["components"] = {"schemas": {"a/b~c": {"type": "integer"}}}
    document["x-owned-path-items"] = {"owned": selected}
    document["paths"]["/owned"] = {"$ref": "#/x-owned-path-items/owned"}
    generated = Generate(document)
    assert parse_qsl(urlsplit(generated.target.value).query) == [("q", "1")], "Override was lost"
    assert generated.operation.source_pointer.startswith("#/x-owned-path-items/owned/"), (
        "Resolved source attribution was lost"
    )


@pytest.mark.parametrize("change", ["source", "workspace", "base", "session", "reference"])
def test_OperationReferenceMustMatchExactOriginalImportContext(change):
    """Source, workspace, server, session and operation identities cannot be substituted."""

    document = Document()
    document["servers"][0]["url"] = "/api"
    text = json.dumps(document)
    base = "http://127.0.0.1:19001"
    options = {"workspace_id": "generation-unit", "base_url": base}
    imported = ImportOpenApi(text, **options, **({
        "session_reference": SessionReference("generation-unit", "owned"),
    } if change == "session" else {}))
    reference = imported.operations[0].Reference()

    if change == "source":
        text += " "

    elif change == "workspace":
        options["workspace_id"] = "other"

    elif change == "base":
        options["base_url"] = "http://127.0.0.1:19002"

    elif change == "reference":
        reference = "api-operation:" + "0" * 64

    with pytest.raises(ValueError, match="bounded synthetic"):
        GenerateOpenApiRequest(text, reference, **options)


def test_CanonicalSelectionBindsTheActualServerAndMediaWithinOneOriginalDocument():
    """A four-variant source retains independent exact destinations and selected body encodings."""

    document = Document()
    document["servers"] = [
        {"url": "http://127.0.0.1:19001/first"},
        {"url": "http://127.0.0.1:19002/second"},
    ]
    Body(document, {"type": "integer"})
    Operation(document)["requestBody"]["content"]["text/plain"] = {"schema": {"type": "string"}}
    text = json.dumps(document)
    imported = ImportOpenApi(text, workspace_id="generation-unit")
    generated = [GenerateOpenApiRequest(text, operation.Reference(), workspace_id="generation-unit")
                 for operation in imported.operations]
    actual = {(item.target.value, item.headers, item.body) for item in generated}
    expected = {
        ("http://127.0.0.1:19001/first/owned", (("content-type", "application/json"),), b"1"),
        ("http://127.0.0.1:19001/first/owned", (("content-type", "text/plain"),), b"synthetic"),
        ("http://127.0.0.1:19002/second/owned", (("content-type", "application/json"),), b"1"),
        ("http://127.0.0.1:19002/second/owned", (("content-type", "text/plain"),), b"synthetic"),
    }
    assert actual == expected, "Selected server/media was replaced by another source variant"
    assert len({item.Reference() for item in generated}) == 4, "Distinct encodings shared identity"


def test_OnlyExplicitAnonymousSecurityAlternativeCanProduceAPreview():
    """An empty OR alternative permits synthetic generation without creating an auth session."""

    document = Document()
    document["components"] = {"securitySchemes": {
        "owned": {"type": "apiKey", "in": "header", "name": "X-Owned-Key"},
    }}
    document["security"] = [{"owned": []}]

    with pytest.raises(ValueError, match="bounded synthetic"):
        Generate(document)

    Operation(document)["security"] = [{"owned": []}, {}]
    generated = Generate(document)
    assert generated.operation.template.session_reference is None, "Anonymous session invented"
    assert not generated.headers and not generated.body, "Authentication material was assembled"


@pytest.mark.parametrize("name", [
    "Host", "Cookie", "Set-Cookie", "Authorization", "Proxy-Authorization", "Content-Type",
    "Content-Length", "Transfer-Encoding", "Connection", "TE", "Expect", "Upgrade", "Accept",
])
def test_TransportAndAuthenticationHeadersRemainSeparatelyOwned(name):
    """Ordinary schema parameters cannot replace protocol framing or authentication owners."""

    document = Document()
    Operation(document)["parameters"] = [{
        "in": "header", "name": name, "schema": {"type": "string"},
    }]

    with pytest.raises(ValueError):
        Generate(document)


@pytest.mark.parametrize("location,schema", [
    ("query", {"type": "object", "properties": {"name": {"type": "string"}}}),
    ("query", {"type": "null"}), ("header", {"type": "null"}),
    ("cookie", {"type": "null"}),
    ("cookie", {"type": "array", "items": {"type": "string"}}),
])
def test_UnrepresentableTextualCoordinatesFailBeforeReturningAPreview(location, schema):
    """Null, opaque objects and cookie arrays cannot become ambiguous textual data."""

    document = Document()
    Operation(document)["parameters"] = [{"in": location, "name": "owned", "schema": schema}]

    with pytest.raises(ValueError):
        Generate(document)


@pytest.mark.parametrize("media,schema", [
    ("text/plain", {"type": "integer"}),
    ("application/x-www-form-urlencoded", {"type": "object", "properties": {
        "owned": {"type": "array", "items": {"type": "string"}},
    }}),
    ("multipart/form-data", {"type": "object", "properties": {
        "owned": {"type": "array", "items": {"type": "string"}},
    }}),
    ("application/x-www-form-urlencoded", {"type": "object", "properties": {
        "owned": {"type": "null"},
    }}),
])
def test_UnsupportedBodyCoordinateShapesFailClosed(media, schema):
    """Body encodings require the declared scalar/JSON shape instead of coercing arbitrary data."""

    document = Document()
    Body(document, schema, media)

    with pytest.raises(ValueError):
        Generate(document)


@pytest.mark.parametrize("encoding", [[], False, 0, None, "", {"owned": {"style": "form"}}])
def test_MalformedOrCustomEncodingDeclarationsCannotMasqueradeAsAbsent(encoding):
    """False-valued malformed encoding fields still fail original-field validation."""

    document = Document()
    Body(document, {"type": "string"})
    Operation(document)["requestBody"]["content"]["application/json"]["encoding"] = encoding

    with pytest.raises(ValueError):
        Generate(document)


def test_ValidJsonSuffixAndEmptyEncodingDoNotSelectSourceLiteralSamples():
    """Valid JSON media uses generated values and an empty encoding retains default semantics."""

    document = Document()
    Body(document, {"type": "string", "example": "synthetic-private-source-value"},
         "application/problem+json")
    Operation(document)["requestBody"]["content"]["application/problem+json"]["encoding"] = {}
    generated = Generate(document)
    assert generated.headers == (("content-type", "application/problem+json"),), "Subtype changed"
    assert json.loads(generated.body) == "synthetic", "Source example was selected"


@pytest.mark.parametrize("media", [
    "application/private marker+json", "application/private;owned+json",
])
def test_MalformedJsonSuffixCannotReachAContentTypeHeader(media):
    """Structural +json detection alone does not certify a safe HTTP media token."""

    document = Document()
    Body(document, {"type": "string"}, media)

    with pytest.raises(ValueError, match="bounded synthetic"):
        Generate(document)


@pytest.mark.parametrize("boundary", ["url", "headers", "depth"])
def test_RealGeneratedEncodingAndNestingBudgetsRejectOversizedSources(boundary):
    """Encoded output limits independently reject structurally bounded original documents."""

    document = Document()

    if boundary in {"url", "headers"}:
        Operation(document)["parameters"] = [{
            "in": "query" if boundary == "url" else "header",
            "name": "owned" + "x" * 54 + str(index),
            "schema": {"type": "array", "items": {"type": "string"}},
        } for index in range(120)]

    else:
        schema = {"type": "string"}

        for _ in range(10):
            schema = {"type": "object", "properties": {"owned": schema}}

        Body(document, schema)

    text = json.dumps(document)
    operation = ImportOpenApi(text, workspace_id="generation-unit").operations[0]

    with pytest.raises(ValueError, match="bounded synthetic"):
        GenerateOpenApiRequest(text, operation.Reference(), workspace_id="generation-unit")


def test_ExistingSymbolicTemplateBoundRejectsOversizedUnicodeBodiesBeforeGeneration():
    """An earlier owner's template limit remains effective when source names expand in UTF-8."""

    document = Document()
    original = json.dumps(document)
    reference = ImportOpenApi(original, workspace_id="generation-unit").operations[0].Reference()
    Body(document, {"type": "object", "properties": {
        "owned" + "\U0001f9ec" * 240 + str(index): {"type": "string"}
        for index in range(75)
    }})
    text = json.dumps(document)

    with pytest.raises(ValueError, match="serialized size"):
        ImportOpenApi(text, workspace_id="generation-unit")

    with pytest.raises(ValueError, match="bounded synthetic"):
        GenerateOpenApiRequest(text, reference, workspace_id="generation-unit")


def test_UnsupportedSourceDiagnosticsAndTracebacksDoNotEchoPrivateLiteralFields():
    """Sanitized failures suppress private field names and values in ordinary traceback logging."""

    document = Document()
    Body(document, {"type": "string", "synthetic-private-source-value": "private"})

    with pytest.raises(ValueError) as caught:
        Generate(document)

    assert "synthetic-private-source-value" not in "".join(format_exception(caught.value)), (
        "Source data escaped through chained exception diagnostics"
    )


@pytest.mark.parametrize("collection", ["ssv", "tsv", "pipes"])
def test_LegacyArrayCollectionFormatsOutsideCsvAndMultiAreNotSilentlyReinterpreted(collection):
    """A structurally imported legacy array retains its unsupported serialization boundary."""

    fixture = ROOT / "tests/contract/fixtures/api_request_generation.swagger.json"
    document = json.loads(fixture.read_text())
    document["paths"] = {"/arrays/{ids}": deepcopy(document["paths"]["/arrays/{ids}"])}
    document["paths"]["/arrays/{ids}"]["get"]["parameters"][1]["collectionFormat"] = collection

    with pytest.raises(ValueError):
        Generate(document)


def test_LegacyFormMultipartArraysAndReferencedItemsRemainOutsideTheDeclaredProfile():
    """Swagger form fields cannot borrow JSON object or array-item reference semantics."""

    fixture = ROOT / "tests/contract/fixtures/api_request_generation.swagger.json"
    document = json.loads(fixture.read_text())
    document["paths"] = {"/form": document["paths"]["/form"]}
    operation = document["paths"]["/form"]["post"]
    operation["consumes"] = ["multipart/form-data"]

    with pytest.raises(ValueError):
        Generate(document)

    operation["consumes"] = ["application/x-www-form-urlencoded"]
    document["definitions"] = {"Owned": {"type": "string"}}
    operation["parameters"][0]["items"] = {"$ref": "#/definitions/Owned"}

    with pytest.raises(ValueError):
        Generate(document)


def test_LegacyScalarMultipartAndRepeatedQueryArraysRetainTheirDeclaredEncoding():
    """Legacy scalar parts and multi query arrays use their actual original source profile."""

    fixture = ROOT / "tests/contract/fixtures/api_request_generation.swagger.json"
    document = json.loads(fixture.read_text())
    document["paths"] = {"/form": document["paths"]["/form"]}
    operation = document["paths"]["/form"]["post"]
    operation["parameters"] = [operation["parameters"][-1]]
    operation["consumes"] = ["multipart/form-data"]
    generated = Generate(document)
    assert b'name="label"' in generated.body and b"synthetic\r\n" in generated.body, (
        "Legacy scalar multipart semantics were lost"
    )
    document = json.loads(fixture.read_text())
    document["paths"] = {"/arrays/{ids}": document["paths"]["/arrays/{ids}"]}
    document["paths"]["/arrays/{ids}"]["get"]["parameters"][1]["collectionFormat"] = "multi"
    generated = Generate(document)
    expected = [("values", "1.5"), ("values", "2.5")]
    assert parse_qsl(urlsplit(generated.target.value).query) == expected, (
        "Legacy multi query array was silently converted to a comma-separated scalar"
    )


def test_MultipleScalarCookiesUseTheDeclaredRfc6265StyleWithoutUriPrefixes():
    """Cookie composition keeps scalar names and locale-independent boolean spelling."""

    document = Document()
    Operation(document)["parameters"] = [
        {"in": "cookie", "name": "a_owned", "schema": {"type": "string"}},
        {"in": "cookie", "name": "b_owned", "schema": {"type": "boolean"}},
    ]
    assert Generate(document).headers == (("cookie", "a_owned=synthetic; b_owned=true"),), (
        "Scalar cookie framing differs from the declared implementation choice"
    )


@pytest.mark.parametrize("reference", [None, 42, "", "request:owned", "api-operation:private"])
def test_NoncanonicalSelectionReferencesFailWithSanitizedPublicDiagnostics(reference):
    """Selection references are typed canonical identities, never free-form source selectors."""

    with pytest.raises(ValueError, match="bounded synthetic"):
        GenerateOpenApiRequest(json.dumps(Document()), reference, workspace_id="generation-unit")


def test_TraceCannotRenderADeclaredBodyEvenWhenTheStructuralSchemaIsSupported():
    """TRACE can preview an empty request, but original body declarations fail HTTP semantics."""

    document = Document()
    document["paths"]["/owned"]["trace"] = document["paths"]["/owned"].pop("post")
    assert Generate(document).body == b"", "Body-free TRACE acquired content"
    document["paths"]["/owned"]["trace"]["requestBody"] = {
        "content": {"application/json": {"schema": {"type": "string"}}},
    }

    with pytest.raises(ValueError, match="bounded synthetic"):
        Generate(document)


@pytest.mark.parametrize("field", ["description", "title", "example"])
def test_LegacyItemsCannotBorrowSchemaOnlyAnnotations(field):
    """Consumed Swagger Items vocabulary stays distinct from Schema Object annotations."""

    fixture = ROOT / "tests/contract/fixtures/api_request_generation.swagger.json"
    document = json.loads(fixture.read_text())
    document["paths"] = {"/arrays/{ids}": document["paths"]["/arrays/{ids}"]}
    items = document["paths"]["/arrays/{ids}"]["get"]["parameters"][1]["items"]
    items[field] = "synthetic-private-source-value"

    with pytest.raises(ValueError, match="bounded synthetic"):
        Generate(document)

    items.pop(field)
    items["default"] = 99999
    generated = Generate(document)
    assert parse_qsl(urlsplit(generated.target.value).query) == [("values", "1.5,2.5")], (
        "Legacy Items default became a selected array sample"
    )
