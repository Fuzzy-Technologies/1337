# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Adversarial explicit YAML input through the real offline importer and request producer."""

from __future__ import annotations

import hashlib
import json
import sys
import traceback
from pathlib import Path

import pytest

import fuzzy1337.openapi as openapi
from fuzzy1337.api_request_generation import GenerateOpenApiRequest
from fuzzy1337.openapi import DecodeApiDocument, ImportOpenApi

ROOT = Path(__file__).resolve().parents[2]
MINIMAL = """openapi: 3.1.0
servers: [{url: 'http://127.0.0.1:19001'}]
paths: {/owned: {get: {operationId: ReadOwned}}}
"""


def Import(value: str):
    """Invoke the actual YAML feature without bypassing existing import validation."""

    return ImportOpenApi(value, workspace_id="owned", document_format="yaml")


@pytest.mark.parametrize("name", ["oas", "swagger"])
def test_ExplicitYamlPreservesIndependentJsonSemanticsAndExactSourceBytes(name):
    """Hand-written flow/block YAML matches the independent source tree without source rewriting."""

    fixture_root = ROOT / "tests/contract/fixtures"
    yaml_text = (fixture_root / f"api_request_generation.{name}.yaml").read_text(encoding="utf-8")
    json_text = (fixture_root / f"api_request_generation.{name}.json").read_text(encoding="utf-8")
    document, version, legacy, digest = DecodeApiDocument(yaml_text, document_format="yaml")
    assert document == json.loads(json_text), "YAML scalar/key semantics changed the JSON oracle"
    assert version == ("3.1.0" if name == "oas" else "2.0") and legacy == (name == "swagger"), (
        "YAML changed the declared OpenAPI dialect"
    )
    assert digest == "sha256:" + hashlib.sha256(yaml_text.encode()).hexdigest(), (
        "YAML source identity must use exact original UTF-8 bytes"
    )
    yaml_import = Import(yaml_text)
    json_import = ImportOpenApi(json_text, workspace_id="owned")
    assert [item.template for item in yaml_import.operations] == [
        item.template for item in json_import.operations
    ], "Equivalent YAML changed canonical structural request identities"
    assert all(a.Reference() != b.Reference() for a, b in zip(
        yaml_import.operations, json_import.operations, strict=True
    )), "Different raw YAML/JSON bytes lost their independent operation attribution"


@pytest.mark.parametrize("prefix,suffix", [
    ("", ""), ("\ufeff", ""), ("%YAML 1.2\n---\n", "...\n"), ("---\n", "...\n"),
])
def test_BomAndSingleDocumentMarkersRemainBoundToOriginalInput(prefix, suffix):
    """Accepted YAML presentation markers never normalize or discard source attribution bytes."""

    text = prefix + MINIMAL + suffix
    imported = Import(text)
    assert imported.source_digest == "sha256:" + hashlib.sha256(text.encode()).hexdigest(), (
        "YAML presentation normalization changed source identity"
    )


@pytest.mark.parametrize("value,expected", [
    ("null", None), ("", None), ("true", True), ("false", False), ("-12", -12),
    ("1.25", 1.25), ("1e3", 1000.0), ("!!float 1", 1.0), ("!!int '1'", 1),
    ("!!null ''", None), ("!!bool 'true'", True), ("!!str null", "null"),
    ("'true'", "true"), ("on", "on"), ("yes", "yes"), ("2026-10-13", "2026-10-13"),
    ("'\u00e9'", "\u00e9"), ('"\\u00e9"', "\u00e9"), ("|\n  owned\n", "owned\n"),
    (">-\n  owned\n  folded\n", "owned folded"),
])
def test_DeclaredScalarProfileDoesNotUseLegacyImplicitResolvers(value, expected):
    """Boolean/date/quoted/block values follow the profile without YAML 1.1 guessing."""

    document, _, _, _ = DecodeApiDocument(MINIMAL + "x-owned: " + value + "\n",
                                          document_format="yaml")
    assert document["x-owned"] == expected, "YAML scalar conversion disagreed with its contract"
    assert type(document["x-owned"]) is type(expected), "YAML scalar type was implicitly coerced"


@pytest.mark.parametrize("extension", [
    "x-owned: &owned []\n", "x-owned: *owned\n", "x-owned: &owned [*owned]\n",
    "x-owned: {<<: {private: value}}\n", "x-owned: {'<<': {private: value}}\n",
    "x-owned: !!python/object/apply:os.system ['synthetic-private-source-value']\n",
    "x-owned: !owned value\n", "x-owned: !!binary SGVsbG8=\n",
    "x-owned: !!timestamp 2026-10-13\n", "x-owned: !!set {owned: null}\n",
    "x-owned: !!omap [{owned: 1}]\n", "x-owned: !!pairs [{owned: 1}]\n",
    "x-owned: !!str []\n", "x-owned: !!seq {}\n", "x-owned: !!map value\n",
    "x-owned: !!int 1.2\n", "x-owned: !!bool on\n", "x-owned: !!null unknown\n",
    "x-owned: .inf\n", "x-owned: -.Inf\n", "x-owned: .NaN\n", "x-owned: 1e999\n",
    "x-owned: !!float 1e999\n", "x-owned: 0x12\n", "x-owned: 0o12\n",
    "x-owned: 1_000\n", "x-owned: 01\n", "x-owned: +1\n", "x-owned: 1.\n",
    "x-owned: .5\n", "x-owned: 1:00\n", "x-owned: {'a': 1, a: 2}\n",
    'x-owned: {"\\u00e9": 1, \u00e9: 2}\n', "x-owned: {1: value}\n",
    "x-owned: {true: value}\n", "x-owned: {null: value}\n",
    "x-owned: {[owned]: value}\n", "x-owned: {{owned: value}: value}\n",
    "---\n" + MINIMAL, 'x-owned: "\\uD800"\n', "x-owned: [\n",
])
def test_UnsafeOrNonJsonRepresentationsFailBeforeAnyImport(extension):
    """Even ignored input cannot retain aliases, tags, duplicate/typed keys or numeric bombs."""

    with pytest.raises(ValueError):
        Import(MINIMAL + extension)


@pytest.mark.parametrize("text", [
    "", "# empty\n", "[]", "null", "%YAML 1.1\n---\n" + MINIMAL,
    "%TAG !owned! tag:owned.test,2026:\n---\n" + MINIMAL,
    "%YAML 1.3\n---\n" + MINIMAL, "\ud800", b"\xff",
])
def test_OnlyOneUtf8CompatibleJsonObjectDocumentIsAccepted(text):
    """The explicit profile never guesses another dialect, stream or input representation."""

    with pytest.raises(ValueError):
        Import(text)


def test_ResourceLimitsApplyBeforeTreeConstructionAndDependencyLoading(monkeypatch):
    """Real byte limits and reduced exact event budgets stop malformed material early."""

    monkeypatch.setitem(sys.modules, "yaml", None)

    with pytest.raises(ValueError, match="byte bound"):
        Import(" " * (openapi.MAX_OPENAPI_BYTES + 1))

    monkeypatch.undo()
    document = "openapi: 3.1.0\npaths: {}\n"
    monkeypatch.setattr(openapi, "MAX_OPENAPI_NODES", 5)
    assert DecodeApiDocument(document, document_format="yaml")[0]["paths"] == {}, (
        "The inclusive node limit rejected an exactly bounded YAML document"
    )
    monkeypatch.setattr(openapi, "MAX_OPENAPI_NODES", 4)

    with pytest.raises(ValueError, match="resource bound"):
        DecodeApiDocument(document, document_format="yaml")

    monkeypatch.setattr(openapi, "MAX_OPENAPI_NODES", 20000)
    monkeypatch.setattr(openapi, "MAX_OPENAPI_DEPTH", 2)
    bounded = document + "x-owned: [null]\n"
    assert DecodeApiDocument(bounded, document_format="yaml")[0]["x-owned"] == [None], (
        "The inclusive depth limit rejected an exactly bounded YAML child"
    )
    nested = document + "x-owned: [[null]]\n"

    with pytest.raises(ValueError, match="resource bound"):
        Import(nested)


def test_DeepFlowYamlFailsWithoutRecursiveObjectConstruction():
    """Deep bracket nesting is cut off while consuming events, before building a huge tree."""

    with pytest.raises(ValueError, match="resource bound"):
        Import(MINIMAL + "x-owned: " + "[" * 2000 + "null" + "]" * 2000)


def test_MissingOptionalParserPreservesJsonDefaultAndNeverGuessesYaml(monkeypatch):
    """Core JSON input works without the optional parser and YAML requires an explicit selection."""

    text = '{"openapi":"3.1.0","servers":[{"url":"http://127.0.0.1"}],"paths":{"/":' \
           '{"get":{}}}}'
    expected = ImportOpenApi(text, workspace_id="owned")
    monkeypatch.setitem(sys.modules, "yaml", None)
    assert ImportOpenApi(text, workspace_id="owned") == expected, (
        "Optional YAML dependency became mandatory for existing JSON callers"
    )

    with pytest.raises(ValueError, match="openapi-yaml"):
        Import(text)

    with pytest.raises(ValueError, match="JSON"):
        ImportOpenApi(MINIMAL, workspace_id="owned")


@pytest.mark.parametrize("document_format", [None, [], "auto", "YAML", "toml"])
def test_UnsupportedFormatSelectionsFailWithoutAutomaticDetection(document_format):
    """A format is caller-selected interpretation, not an inferred parser fallback."""

    with pytest.raises(ValueError, match="format"):
        ImportOpenApi(MINIMAL, workspace_id="owned", document_format=document_format)


def test_YamlErrorsAndGenerationFailuresCannotLeakPrivateSourceDiagnostics():
    """Parser marks, duplicated keys, original assertions and custom tags stay out of tracebacks."""

    marker = "synthetic-private-source-value"

    for extension in (f"x-owned: {{{marker}: 1, {marker}: 2}}\n",
                      f"x-owned: !{marker} value\n", f"x-owned: [{marker}\n"):
        with pytest.raises(ValueError) as caught:
            Import(MINIMAL + extension)

        assert marker not in "".join(traceback.format_exception(caught.value)), (
            "The YAML parser leaked source text through exception context"
        )

    imported = Import(MINIMAL)

    with pytest.raises(ValueError) as caught:
        GenerateOpenApiRequest(MINIMAL + "x-owned: [" + marker,
            imported.operations[0].Reference(), workspace_id="owned", document_format="yaml")

    assert marker not in "".join(traceback.format_exception(caught.value)), (
        "Request generation leaked original YAML parser diagnostics"
    )


def test_YamlDoesNotResolveRemoteReferencesOrBypassGenerationAssertions():
    """The new syntax feeds the same reference and source-schema refusal boundaries."""

    text = MINIMAL.replace("operationId: ReadOwned", "parameters: [{'$ref': 'https://owned.test/p'}]")

    with pytest.raises(ValueError, match="local"):
        Import(text)

    text = MINIMAL.replace("operationId: ReadOwned",
        "parameters: [{in: query, name: q, schema: {type: string, pattern: '^owned$'}}]")
    imported = Import(text)

    with pytest.raises(ValueError, match="bounded synthetic"):
        GenerateOpenApiRequest(text, imported.operations[0].Reference(), workspace_id="owned",
                               document_format="yaml")


def test_YamlRequestSelectionRequiresTheExactOriginalSourceAndInterpretation():
    """Equivalent rewrites and JSON fallback cannot render an operation from different bytes."""

    operation = Import(MINIMAL).operations[0]
    preview = GenerateOpenApiRequest(MINIMAL, operation.Reference(), workspace_id="owned",
                                     document_format="yaml")
    assert preview.operation == operation and preview.target.value.endswith("/owned"), (
        "The explicit YAML interpretation failed to render its own canonical operation"
    )

    with pytest.raises(ValueError, match="bounded synthetic"):
        GenerateOpenApiRequest(MINIMAL + "# equivalent presentation\n", operation.Reference(),
                               workspace_id="owned", document_format="yaml")

    with pytest.raises(ValueError, match="bounded synthetic"):
        GenerateOpenApiRequest(MINIMAL, operation.Reference(), workspace_id="owned")


def test_StrictJsonSubsetHasTheSameBytesAndInterpretationUnderEitherExplicitFormat():
    """Format selection adds no new source normalization or identity fields to existing records."""

    document = DecodeApiDocument(MINIMAL, document_format="yaml")[0]
    text = json.dumps(document)
    assert ImportOpenApi(text, workspace_id="owned") == Import(text), (
        "The same JSON-compatible bytes and tree invented a different operation identity"
    )
