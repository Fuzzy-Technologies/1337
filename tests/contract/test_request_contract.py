# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Strict schema-versioned structural request contracts with no captured values or authority."""

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from fuzzy1337.requests import (
    MAX_REQUEST_BYTES,
    BindingSource,
    BodyKind,
    Endpoint,
    InjectionLocation,
    InjectionPoint,
    RequestTemplate,
    SessionReference,
    ValueBinding,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "contracts/request-template.schema.json").read_text(encoding="utf-8"))


def Document() -> dict[str, object]:
    """Build a multi-location template for a synthetic form endpoint, using references only."""

    endpoint = Endpoint("demo", "https://example.test", "/users/{user_id}", "POST")

    return RequestTemplate(endpoint, (
        InjectionPoint(InjectionLocation.PATH, "user_id", ValueBinding("user-id")),
        InjectionPoint(InjectionLocation.QUERY, "next", ValueBinding("next")),
        InjectionPoint(InjectionLocation.BODY, "display_name", ValueBinding("display-name")),
        InjectionPoint(
            InjectionLocation.HEADER, "X-CSRF-Token", ValueBinding("csrf", BindingSource.SESSION),
        ),
        InjectionPoint(
            InjectionLocation.COOKIE, "sid", ValueBinding("cookie", BindingSource.SESSION),
        ),
    ), BodyKind.FORM, SessionReference("demo", "operator")).ToDict()


def test_ExampleAndProducerAgreeWithVersionedSchema():
    """The committed example is produced by real contracts and independently validates as JSON."""

    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    document = Document()
    example = json.loads(
        (ROOT / "contracts/examples/request-template.example.json").read_text(encoding="utf-8")
    )
    jsonschema.validate(document, SCHEMA)
    jsonschema.validate(example, SCHEMA)
    assert example == document, "Committed request example drifted from its real producer"
    assert RequestTemplate.FromDict(example).ToDict() == document, "Schema example lost data"
    assert set(document) == {
        "schema_version", "request_reference", "endpoint", "body_kind",
        "session_reference", "graphql_operation", "injection_points",
    }, "Request schema v1 changed its exact top-level boundary"


@pytest.mark.parametrize("field,value", [
    ("schema_version", 2), ("schema_version", True), ("schema_version", "1"),
    ("request_reference", "request:" + "f" * 64), ("request_reference", None),
    ("endpoint", []), ("body_kind", "unknown"), ("body_kind", 0),
    ("session_reference", "captured-session"), ("graphql_operation", 1),
    ("injection_points", {}), ("injection_points", ()),
    ("body_kind", "x" * MAX_REQUEST_BYTES),
], ids=(
    "unsupported-version", "boolean-version", "text-version", "forged-reference",
    "null-reference", "untyped-endpoint", "unknown-encoding", "numeric-encoding",
    "captured-session", "numeric-operation", "point-object", "point-tuple",
    "oversized-envelope",
))
def test_EnvelopeRejectsUnknownVersionsCoercionAndForgedReferences(field, value):
    """Persisted machine contracts reject invalid fields before downstream consumption."""

    document = Document()
    document[field] = value

    with pytest.raises(ValueError):
        RequestTemplate.FromDict(document)


@pytest.mark.parametrize("boundary,field", [
    ("root", "raw_body"), ("root", "headers"), ("endpoint", "url"),
    ("session_reference", "cookies"), ("injection", "value"), ("binding", "value"),
])
def test_UnknownCapturedFieldsAreRejectedWithoutEchoingValues(boundary, field):
    """A capture producer cannot quietly persist secret-like values via extension fields."""

    document = Document()
    record = document

    if boundary in {"endpoint", "session_reference"}:
        record = document[boundary]

    elif boundary in {"injection", "binding"}:
        record = document["injection_points"][0]

        if boundary == "binding":
            record = record["binding"]

    marker = "synthetic-private-value-not-for-output"
    record[field] = marker

    with pytest.raises(ValueError) as caught:
        RequestTemplate.FromDict(document)

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(document, SCHEMA)

    assert marker not in str(caught.value), "Validation leaked an untrusted captured value"


@pytest.mark.parametrize("boundary,field,value", [
    ("endpoint", "method", "post"),
    ("endpoint", "origin", "https://EXAMPLE.TEST"),
    ("endpoint", "object_reference", "object:" + "a" * 64),
    ("endpoint", "workspace_id", 7),
    ("session_reference", "workspace_id", "other"),
    ("injection", "location", "unknown"),
    ("injection", "selector", 7),
    ("injection", "occurrence", True),
    ("binding", "source", "cookie"),
    ("binding", "name", 7),
])
def test_NestedContractTamperingFailsCanonicalValidation(boundary, field, value):
    """Unknown locations, foreign ownership, aliases and forged endpoints are rejected."""

    document = Document()
    record = document[boundary] if boundary in {"endpoint", "session_reference"} else (
        document["injection_points"][0]
    )

    if boundary == "binding":
        record = record["binding"]

    record[field] = value

    with pytest.raises(ValueError):
        RequestTemplate.FromDict(document)


def test_StoredOrderDuplicatesAndHeaderAliasesAreNotAccepted():
    """Canonical templates cannot preserve producer ordering or duplicate injection coordinates."""

    document = Document()
    reordered = deepcopy(document)
    reordered["injection_points"].reverse()
    duplicate = deepcopy(document)
    duplicate["injection_points"].append(duplicate["injection_points"][0])
    header_alias = deepcopy(document)
    header = next(
        point for point in header_alias["injection_points"] if point["location"] == "header"
    )
    header["selector"] = "X-CSRF-Token"

    for tampered in (reordered, duplicate, header_alias):
        with pytest.raises(ValueError):
            RequestTemplate.FromDict(tampered)


def test_RequiredFieldsCannotDisappearAtAnyBoundary():
    """Strict decoding rejects absent fields in every structural object family."""

    for boundary in ("root", "endpoint", "session_reference", "injection", "binding"):
        document = Document()
        record = document

        if boundary in {"endpoint", "session_reference"}:
            record = document[boundary]

        elif boundary in {"injection", "binding"}:
            record = document["injection_points"][0]

            if boundary == "binding":
                record = record["binding"]

        del record[next(iter(record))]

        with pytest.raises(ValueError):
            RequestTemplate.FromDict(document)


@pytest.mark.parametrize("location,selector,body_kind", [
    (InjectionLocation.JSON, "/user/name", BodyKind.JSON),
    (InjectionLocation.GRAPHQL, "/variables/id", BodyKind.GRAPHQL),
    (InjectionLocation.MULTIPART, "file", BodyKind.MULTIPART),
    (InjectionLocation.BODY, "", BodyKind.TEXT),
])
def test_AdditionalBodyContractsValidateThroughIndependentSchema(location, selector, body_kind):
    """Every non-form body encoding is produced and consumed via the real machine contract."""

    endpoint = Endpoint("demo", "http://127.0.0.1:8080", "/api", "POST")
    template = RequestTemplate(endpoint, (
        InjectionPoint(location, selector, ValueBinding("input")),
    ), body_kind, graphql_operation="FindUser" if body_kind is BodyKind.GRAPHQL else None)
    jsonschema.validate(template.ToDict(), SCHEMA)
    assert RequestTemplate.FromJson(template.ToJson()) == template, "Body contract roundtrip drift"
