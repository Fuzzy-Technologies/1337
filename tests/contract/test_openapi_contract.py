# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent API fixtures consumed through existing typed request and JSON Schema contracts."""

from __future__ import annotations

import hashlib
import json
import traceback
from pathlib import Path

import jsonschema
import pytest

from fuzzy1337.openapi import ImportOpenApi
from fuzzy1337.requests import BindingSource, BodyKind, RequestTemplate

ROOT = Path(__file__).resolve().parents[2]


def Fixture(name: str) -> dict:
    """Load hand-written API descriptions independently of the importer producer."""

    return json.loads((ROOT / "tests/contract/fixtures" / name).read_text(encoding="utf-8"))


def SourceAt(document: dict, pointer: str):
    """Resolve emitted provenance with an independent literal JSON Pointer consumer."""

    value = document

    for token in pointer[2:].split("/"):
        key = token.replace("~1", "/").replace("~0", "~")
        value = value[int(key)] if isinstance(value, list) else value[key]

    return value


@pytest.mark.parametrize("name,version,count", [
    ("openapi.v3.json", "3.1.2", 4), ("swagger.v2.json", "2.0", 3),
])
def test_IndependentFixturesGenerateRealRequestsAndSafeMetadata(name, version, count):
    """Schema/type consumers receive exact request objects while private examples remain absent."""

    text = (ROOT / "tests/contract/fixtures" / name).read_text(encoding="utf-8")
    source = json.loads(text)
    imported = ImportOpenApi(text, workspace_id="demo")
    request_schema = json.loads((ROOT / "contracts/request-template.schema.json").read_text())
    assert imported.source_digest == "sha256:" + hashlib.sha256(text.encode()).hexdigest(), (
        "OpenAPI expectation failed: imported.source_digest == "
        "'sha256:' + hashlib.sha256(text.encode()).hexdigest() "
    )
    assert imported.specification_version == version and len(imported.operations) == count, (
        "OpenAPI expectation failed: imported.specification_version == "
        "version and len(imported.operations) == count "
    )
    assert imported.ToDict() == ImportOpenApi(text, workspace_id="demo").ToDict(), (
        "OpenAPI expectation failed: imported.ToDict() == "
        "ImportOpenApi(text, workspace_id='demo').ToDict() "
    )
    assert "synthetic-private-source-value" not in json.dumps(imported.ToDict()), (
        "OpenAPI expectation failed: 'synthetic-private-source-value' "
        "not in json.dumps(imported.ToDict()) "
    )
    assert {operation.template.body_kind for operation in imported.operations} == {
        BodyKind.NONE, BodyKind.JSON, BodyKind.MULTIPART,
    }, (
        "OpenAPI expectation failed: {operation.template.body_kind for "
        "operation in imported.operations} == {BodyKind.NONE, "
        "BodyKind.JSON, BodyKind.MULTIPART} "
    )

    for operation in imported.operations:
        jsonschema.validate(operation.template.ToDict(), request_schema)
        assert RequestTemplate.FromJson(operation.template.ToJson()) == operation.template, (
            "OpenAPI expectation failed: "
            "RequestTemplate.FromJson(operation.template.ToJson()) == "
            "operation.template "
        )
        assert SourceAt(source, operation.source_pointer)["operationId"] == (
            operation.operation_id
        ), (
            "OpenAPI expectation failed: SourceAt(source, "
            "operation.source_pointer)['operationId'] == "
            "operation.operation_id "
        )
        assert all(item.point.binding.source is BindingSource.INPUT for item in operation.inputs), (
            "OpenAPI expectation failed: all((item.point.binding.source is "
            "BindingSource.INPUT for item in operation.inputs)) "
        )

        for item in operation.inputs:
            assert isinstance(SourceAt(source, item.source_pointer), dict), (
                "Importer fabricated a source location absent from the original document"
            )


def test_PathOverridesReadonlySchemaFlagsAuthAlternativesAndMediaIdentityArePreserved():
    """Modern semantics survive importing without choosing auth or copying source literals."""

    imported = ImportOpenApi(json.dumps(Fixture("openapi.v3.json")), workspace_id="demo")
    get = next(item for item in imported.operations if item.operation_id == "GetUser")
    query = next(item for item in get.inputs if item.point.selector == "limit")
    assert query.value_type == "string" and query.required, "Operation override was lost"
    assert len(get.security) == 2 and get.security[1] == (), "Anonymous OR branch was lost"
    assert get.security[0][0].location == "header", (
        "OpenAPI expectation failed: get.security[0][0].location == "
        "'header' "
    )
    assert get.security[0][0].selector == "x-api-key", (
        "OpenAPI expectation failed: get.security[0][0].selector == "
        "'x-api-key' "
    )
    post = [item for item in imported.operations if item.operation_id == "SaveUser"]
    assert len(post) == 2 and post[0].Reference() != post[1].Reference(), (
        "OpenAPI expectation failed: len(post) == 2 and "
        "post[0].Reference() != post[1].Reference() "
    )
    assert post[0].template.Reference() == post[1].template.Reference(), (
        "Same structural template invented a different identity for a media annotation"
    )
    assert {item.point.selector for item in post[0].inputs} == {
        "user_id", "limit", "/name", "/nickname",
    }, "Read-only fields were emitted as request inputs"
    name = next(item for item in post[0].inputs if item.point.selector == "/name")
    nickname = next(item for item in post[0].inputs if item.point.selector == "/nickname")
    assert name.required and name.constrained and nickname.nullable and not nickname.required, (
        "OpenAPI expectation failed: name.required and name.constrained "
        "and nickname.nullable and (not nickname.required) "
    )
    upload = next(item for item in imported.operations if item.operation_id == "Upload")
    assert upload.security == (), "Operation-level empty security failed to override root auth"


@pytest.mark.parametrize("scheme,scopes,expected", [
    ({"type": "http", "scheme": "bearer"}, [], "http-bearer"),
    ({"type": "http", "scheme": "basic"}, [], "http-basic"),
    ({"type": "oauth2", "flows": {}}, ["read"], "oauth2"),
    ({"type": "openIdConnect", "openIdConnectUrl": "https://example.test/.well-known"},
     ["read"], "openIdConnect"),
    ({"type": "mutualTLS"}, [], "mutualTLS"),
    ({"type": "apiKey", "in": "query", "name": "key"}, [], "apiKey"),
    ({"type": "apiKey", "in": "cookie", "name": "sid"}, [], "apiKey"),
])
def test_AuthenticationAnnotationsRemainSeparateFromSessionMaterial(scheme, scopes, expected):
    """The importer preserves scheme alternatives and scopes without contacting an issuer."""

    document = Fixture("openapi.v3.json")
    document["components"]["securitySchemes"]["apiKey"] = scheme
    document["security"] = [{"apiKey": scopes}]
    imported = ImportOpenApi(json.dumps(document), workspace_id="demo")
    protected = next(item for item in imported.operations if item.operation_id == "GetUser")
    assert protected.security[0][0].scheme_type == expected, (
        "OpenAPI expectation failed: "
        "protected.security[0][0].scheme_type == expected "
    )
    assert protected.security[0][0].scopes == tuple(scopes), (
        "OpenAPI expectation failed: protected.security[0][0].scopes == "
        "tuple(scopes) "
    )
    assert all(item.template.session_reference is None for item in imported.operations), (
        "OpenAPI expectation failed: "
        "all((item.template.session_reference is None for item in "
        "imported.operations)) "
    )
    assert "well-known" not in json.dumps(imported.ToDict()), "Issuer endpoint became retained data"


@pytest.mark.parametrize("scheme,scopes", [
    ({"type": "unknown"}, []), ({"type": "http", "scheme": "digest"}, []),
    ({"type": "apiKey", "in": "body", "name": "key"}, []),
    ({"type": "apiKey", "in": "header", "name": "key"}, ["read"]),
    ({"type": "oauth2"}, ["read", "read"]),
])
def test_UnsupportedAuthenticationSemanticsFailAsValidationErrors(scheme, scopes):
    """Unsupported type/location/scope combinations cannot become execution-ready claims."""

    document = Fixture("openapi.v3.json")
    document["components"]["securitySchemes"]["apiKey"] = scheme
    document["security"] = [{"apiKey": scopes}]

    with pytest.raises(ValueError):
        ImportOpenApi(json.dumps(document), workspace_id="demo")


def test_SwaggerContextSchemesCollectionFormatAndFormSourceLocations():
    """Legacy host defaults and operation overrides preserve explicit source ownership."""

    document = Fixture("swagger.v2.json")
    del document["host"]
    del document["schemes"]
    document["paths"]["/upload"]["post"]["schemes"] = ["https"]
    imported = ImportOpenApi(json.dumps(document), workspace_id="demo",
                             base_url="http://127.0.0.1:19001/spec.json")
    get = next(item for item in imported.operations if item.operation_id == "GetLegacyUser")
    tags = next(item for item in get.inputs if item.point.selector == "tags")
    assert tags.serialization == "swagger:multi" and tags.explode, (
        "OpenAPI expectation failed: tags.serialization == "
        "'swagger:multi' and tags.explode "
    )
    upload = next(item for item in imported.operations if item.operation_id == "UploadLegacy")
    assert upload.template.endpoint.origin == "https://127.0.0.1:19001", (
        "OpenAPI expectation failed: upload.template.endpoint.origin == "
        "'https://127.0.0.1:19001' "
    )
    assert upload.inputs[0].source_pointer == "#/paths/~1upload/post/parameters/0", (
        "OpenAPI expectation failed: upload.inputs[0].source_pointer == "
        "'#/paths/~1upload/post/parameters/0' "
    )


def test_DuplicateUntrustedKeysCannotLeakSourceValuesInErrors():
    """Parser errors contain diagnostic categories rather than source-provided key text."""

    marker = "synthetic-private-source-value"

    with pytest.raises(ValueError) as caught:
        ImportOpenApi('{"' + marker + '":1,"' + marker + '":2}', workspace_id="demo")

    assert marker not in str(caught.value), (
        "OpenAPI expectation failed: marker not in str(caught.value) "
    )


def test_MutualTlsAndTraceAreNotSilentlyImportedFromOlderDialects():
    """Scheme and HTTP operation support must remain specific to the declared feature line."""

    document = Fixture("openapi.v3.json")
    document["openapi"] = "3.0.4"
    document["components"]["securitySchemes"]["apiKey"] = {"type": "mutualTLS"}

    with pytest.raises(ValueError, match="mutual TLS"):
        ImportOpenApi(json.dumps(document), workspace_id="demo")

    legacy = Fixture("swagger.v2.json")
    legacy["paths"]["/upload"]["trace"] = {"responses": {"200": {"description": "Synthetic"}}}

    with pytest.raises(ValueError, match="trace"):
        ImportOpenApi(json.dumps(legacy), workspace_id="demo")


@pytest.mark.parametrize("collection_format", ["csv", "ssv", "tsv", "pipes", "multi"])
def test_LegacyFormArraysRetainDeclaredSerialization(collection_format):
    """Multipart form arrays retain repeated-field/collection metadata for a future renderer."""

    document = Fixture("swagger.v2.json")
    document["paths"]["/upload"]["post"]["parameters"] = [{
        "in": "formData", "name": "tags", "type": "array", "items": {"type": "string"},
        "collectionFormat": collection_format,
    }]
    imported = ImportOpenApi(json.dumps(document), workspace_id="demo")
    upload = next(item for item in imported.operations if item.operation_id == "UploadLegacy")
    assert upload.inputs[0].serialization == "swagger:" + collection_format, (
        "Swagger form array serialization was discarded"
    )
    assert upload.inputs[0].explode == (collection_format == "multi"), (
        "Swagger repeated form field declaration was lost"
    )
    document["paths"]["/upload"]["post"]["parameters"][0]["collectionFormat"] = "unsupported"

    with pytest.raises(ValueError, match="collection format"):
        ImportOpenApi(json.dumps(document), workspace_id="demo")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:synthetic-private-source-value/",
    "http://[synthetic-private-source-value]/",
])
def test_ServerValidationTracebacksCannotLeakCapturedAuthorityText(url):
    """Ordinary traceback logging must not expose private values from urllib validation causes."""

    document = Fixture("openapi.v3.json")
    document["servers"] = [{"url": url}]

    with pytest.raises(ValueError) as caught:
        ImportOpenApi(json.dumps(document), workspace_id="demo")

    formatted = "".join(traceback.format_exception(caught.value))
    assert "synthetic-private-source-value" not in formatted, (
        "Server validation propagated a private source value through its exception cause"
    )


@pytest.mark.parametrize("host", [
    "127.0.0.1:19001/prefix", "user:synthetic@localhost", "127.0.0.1?query", "127.0.0.1#frag",
])
def test_SwaggerHostCannotRedefineBasePathOrCredentialAuthority(host):
    """Host and basePath retain their distinct Swagger meaning before endpoint construction."""

    document = Fixture("swagger.v2.json")
    document["host"] = host

    with pytest.raises(ValueError, match="host must"):
        ImportOpenApi(json.dumps(document), workspace_id="demo")


@pytest.mark.parametrize("parameter", [
    {"in": "query", "name": "q", "type": "object"},
    {"in": "header", "name": "X-Owned"},
    {"in": "query", "name": "q", "type": "string", "nullable": True},
    {"in": "formData", "name": "form", "type": "object"},
    {"in": "formData", "name": "form"},
])
def test_LegacyNonbodyParametersCannotBorrowModernSchemaSemantics(parameter):
    """Ordinary/formData Swagger parameters require supported explicit legacy types."""

    document = Fixture("swagger.v2.json")

    if parameter["in"] == "formData":
        document["paths"]["/upload"]["post"]["parameters"] = [parameter]

    else:
        document["paths"]["/users/{id}"]["get"]["parameters"].append(parameter)

    with pytest.raises(ValueError):
        ImportOpenApi(json.dumps(document), workspace_id="demo")
