# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Validate generated requests through independent URI, schema, form and MIME consumers."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest
from jsonschema import Draft202012Validator

from fuzzy1337.api_request_generation import GenerateOpenApiRequest
from fuzzy1337.model import CanonicalModelJson
from fuzzy1337.openapi import ImportOpenApi

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("name", ["oas", "swagger"])
def test_IndependentFixtureOraclesConsumeRealGeneratedRequests(name):
    """Hand-authored expectations verify all encodings without invoking an HTTP client."""

    text = (ROOT / f"tests/contract/fixtures/api_request_generation.{name}.json").read_text()
    document = json.loads(text)
    oracle_path = ROOT / "tests/contract/fixtures/api_request_generation.expected.json"
    expected = json.loads(oracle_path.read_text())
    imported = ImportOpenApi(text, workspace_id="generation-contract")

    for operation in imported.operations:
        generated = GenerateOpenApiRequest(
            text, operation.Reference(), workspace_id=imported.workspace_id,
        )
        oracle = expected[operation.operation_id]
        parts = urlsplit(generated.target.value)
        assert generated.operation == operation, "Generation changed the canonical source operation"
        assert operation.template.endpoint.method == oracle["method"], "Method differs from oracle"
        assert parts.scheme == "http" and parts.netloc == "127.0.0.1:19001", "Server changed"
        assert parts.path == oracle["path"], "Path serialization differs from fixture oracle"
        assert parse_qsl(parts.query) == [tuple(pair) for pair in oracle["query"]], "Query changed"
        headers = dict(generated.headers)

        if "headers" in oracle:
            assert headers == oracle["headers"], "Headers differ from independent fixture oracle"

        if "json" in oracle:
            payload = json.loads(generated.body)
            assert payload == oracle["json"], "Generated JSON differs from the independent oracle"
            route = operation.source_pointer.split("/")[2].replace("~1", "/").replace("~0", "~")
            source = document["paths"][route][operation.template.endpoint.method.lower()]
            if name == "oas":
                schema = source["requestBody"]["content"][operation.media_type]["schema"]

            else:
                schema = next(parameter["schema"] for parameter in source["parameters"]
                              if parameter["in"] == "body")

            Draft202012Validator(schema).validate(payload)

        elif "form" in oracle:
            assert parse_qsl(generated.body.decode("ascii")) == [
                tuple(pair) for pair in oracle["form"]
            ], (
                "Form body differs from independently declared collection semantics"
            )

        elif "multipart" in oracle:
            content_type = headers["content-type"]
            message = BytesParser(policy=policy.default).parsebytes(
                f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii")
                + generated.body
            )
            assert message.is_multipart() and not message.defects, "MIME framing failed"
            parsed = {}

            for part in message.iter_parts():
                assert part.get_content_disposition() == "form-data", "Part is not form-data"
                assert part.get_filename() is None and not part.defects, "File part invented"
                field_name = part.get_param("name", header="content-disposition")
                parsed[field_name] = part.get_content().rstrip("\r\n")

            assert parsed == oracle["multipart"], "Multipart values differ from oracle"
            assert b"\n" not in generated.body.replace(b"\r\n", b""), "Non-CRLF framing"
            closing = ("--" + message.get_boundary() + "--\r\n").encode("ascii")
            assert generated.body.endswith(closing), (
                "Multipart closing delimiter is incomplete"
            )

        else:
            assert generated.body.decode("ascii") == oracle["body"], "Body differs from oracle"

        marker = "synthetic-private-source-value"
        assert marker.encode() not in generated.body, "Source example became a sample"
        assert marker not in str(generated.headers), "Source header leaked"
        assert GenerateOpenApiRequest(
            text, operation.Reference(), workspace_id=imported.workspace_id,
        ) == generated, (
            "Exact input produced a nondeterministic request preview"
        )


def test_PreviewIdentityAndMetadataBindSourceWithoutPersistingConcreteValues():
    """Immutable previews expose reference-only metadata instead of payload/header attributes."""

    text = (ROOT / "tests/contract/fixtures/api_request_generation.oas.json").read_text()
    operation = ImportOpenApi(text, workspace_id="generation-contract").operations[0]
    generated = GenerateOpenApiRequest(
        text, operation.Reference(), workspace_id="generation-contract",
    )
    metadata = generated.Metadata()
    assert metadata["generated_request_reference"] == generated.Reference(), "Preview changed"
    assert metadata["operation_reference"] == operation.Reference(), "Operation dropped"
    assert metadata["target_reference"] == generated.target.Reference(), "Actual target dropped"
    assert metadata["request_reference"] == operation.template.Reference(), "Template changed"
    encoded = CanonicalModelJson(metadata)
    assert b'"headers"' not in encoded and b'"body"' not in encoded, (
        "Reference metadata retained concrete request values"
    )
    assert "body=" not in repr(generated), "Preview representation printed its body"

    with pytest.raises(FrozenInstanceError):
        generated.body = b"changed"
