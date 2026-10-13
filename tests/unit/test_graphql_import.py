# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Check bounded introspection metadata, pure preview encoding and closed failure semantics."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

import fuzzy1337.graphql_import as graphql
from fuzzy1337.model import ModelProvenance
from fuzzy1337.requests import BodyKind, InjectionLocation, RequestsFromObject, RequestTemplate
from fuzzy1337.scope import (
    AuthorizationState,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)

FIXTURE = Path(__file__).resolve().parents[1] / "contract/fixtures/graphql_introspection.owned.json"
ENDPOINT = "http://127.0.0.1:8080/graphql"


def Source() -> bytes:
    """Read the hand-authored owned introspection description without network or rewriting."""

    return FIXTURE.read_bytes()


def Changed(path: tuple[str | int, ...], value: object) -> bytes:
    """Replace one specified original-source coordinate for an independent malformed input."""

    document = json.loads(Source())
    current = document

    for token in path[:-1]:
        current = current[token]

    current[path[-1]] = value

    return json.dumps(document).encode("utf-8")


def Imported(value: bytes | None = None, endpoint_url: str = ENDPOINT, workspace_id: str = "owned"):
    """Use the actual public offline producer with explicit fixed caller context."""

    return graphql.ImportGraphQl(Source() if value is None else value,
                                workspace_id=workspace_id, endpoint_url=endpoint_url)


def Preview(field_name: str = "lookup", value: bytes | None = None):
    """Select a real source-bound operation and use the public pure preview producer."""

    source = Source() if value is None else value
    operation = next(item for item in Imported(source).operations if item.field_name == field_name)

    return graphql.GenerateGraphQlRequest(source, operation.Reference(),
                                         workspace_id="owned", endpoint_url=ENDPOINT)


def test_TypedOperationsPreserveIndependentCoordinateAndRequestOracle():
    """Typed inputs and original pointers match hand-authored source, without retained literals."""

    imported = Imported()
    assert [(item.operation_kind, item.field_name) for item in imported.operations] == [
        ("mutation", "updateOwned"), ("query", "lookup"), ("query", "opaque"),
        ("query", "ping"), ("subscription", "ticks"),
    ], "Root operations were lost or determinism changed"
    assert imported.source_digest == "sha256:" + hashlib.sha256(Source()).hexdigest(), (
        "Import no longer identifies exact original bytes"
    )
    operation = next(item for item in imported.operations if item.field_name == "lookup")
    assert operation.source_pointer == "#/data/__schema/types/10/fields/0", (
        "Operation pointer no longer addresses its original array position"
    )
    assert [(item.name, item.value_type.Expression()) for item in operation.arguments] == [
        ("filter", "Filter"), ("ids", "[ID!]!"),
    ], "Argument wrapper types were guessed or reordered incorrectly"
    assert operation.arguments[1].source_pointer.endswith("/args/0"), "Original pointer changed"
    assert operation.template.endpoint.method == "POST", "GraphQL template method changed"
    assert operation.template.body_kind is BodyKind.GRAPHQL, "Body lost typed GraphQL encoding"
    assert operation.template.session_reference is None, "Import manufactured authentication"
    assert [(item.location, item.selector) for item in operation.template.injection_points] == [
        (InjectionLocation.GRAPHQL, "/variables/filter"),
        (InjectionLocation.GRAPHQL, "/variables/ids"),
    ], "Variable descriptors no longer match actual generated variable names"
    assert RequestTemplate.FromDict(operation.template.ToDict()) == operation.template, (
        "Existing request consumer cannot decode the actual producer"
    )
    filter_type = next(item for item in imported.types if item.name == "Filter")
    assert next(item for item in filter_type.input_fields if item.name == "tag").has_default, (
        "Default presence was discarded"
    )
    assert b"synthetic-private-default" not in json.dumps(imported.ToDict()).encode(), (
        "Descriptions or original default values entered structural metadata"
    )


@pytest.mark.parametrize("field_name,kind,operation_name,expected_arguments,expected_variables", [
    ("lookup", "query", "GqlQuery_29a1af58c1382740",
     "($filter: Filter, $ids: [ID!]!) { lookup(filter: $filter, ids: $ids) { __typename } }",
     {"filter": {"enabled": False, "sort": "ASC", "tag": "synthetic", "weight": 0.5,
                 "window": {"offset": 0}}, "ids": ["synthetic-id"]}),
    ("updateOwned", "mutation", "GqlMutation_24b58b49226913ff",
     "($input: Filter!) { updateOwned(input: $input) }",
     {"input": {"enabled": False, "sort": "ASC", "tag": "synthetic", "weight": 0.5,
                "window": {"offset": 0}}}),
    ("ping", "query", "GqlQuery_758d61f26a444483", " { ping }", {}),
])
def test_ActualSyntheticBodyMatchesIndependentGraphQlAndJsonOracle(
    field_name, kind, operation_name, expected_arguments, expected_variables,
):
    """Each body has independently specified operation, argument types and synthetic values."""

    preview = Preview(field_name)
    body = json.loads(preview.body)
    assert body == {"operationName": operation_name,
                    "query": kind + " " + operation_name + expected_arguments,
                    "variables": expected_variables}, "Synthetic request violates the owned oracle"
    assert preview.headers == (("content-type", "application/json"),), (
        "Preview manufactured headers or authentication"
    )
    assert preview.target.value == ENDPOINT, "Schema content changed the caller-selected endpoint"
    assert b"synthetic-private-default" not in preview.body, "Default literal entered actual body"
    assert preview.Reference() == Preview(field_name).Reference(), "Preview identity is unstable"
    expected_body_digest = "sha256:" + hashlib.sha256(preview.body).hexdigest()
    assert preview.Metadata()["body_sha256"] == expected_body_digest, (
        "Reference metadata no longer identifies actual generated body bytes"
    )
    assert "query" not in preview.Metadata() and "variables" not in preview.Metadata(), (
        "Reference metadata persisted ephemeral concrete values"
    )


@pytest.mark.parametrize("field_name", ["opaque", "ticks"])
def test_UnsupportedCustomScalarAndSubscriptionRemainExplicit(field_name):
    """Import models source declarations while refusing unsupported synthesis or transport."""

    with pytest.raises(ValueError):
        Preview(field_name)


@pytest.mark.parametrize("source", [
    b"", b"not-json", b"[]", b"null", b"\xff", rb'{"secret": "\ud800"}',
    b'{"__schema":{},"__schema":{}}', b'{"__schema":{"types":NaN}}',
    b'{"__schema":{"ignored":1e999}}', b'{"data":null}',
    b'{"data":{"__schema":{}},"errors":[]}', b'{"errors":[{"message":"private"}]}',
])
def test_InvalidSourceFailsWithoutEchoingOriginalValues(source):
    """Encoding, duplicates, partial results and non-finite numbers fail with fixed diagnostics."""

    with pytest.raises(ValueError) as caught:
        Imported(source)

    assert "private" not in str(caught.value), "Untrusted source was echoed into a diagnostic"


@pytest.mark.parametrize("path,value", [
    (("data", "__schema", "queryType"), None),
    (("data", "__schema", "queryType"), {"name": "Absent"}),
    (("data", "__schema", "mutationType"), {"name": "Query"}),
    (("data", "__schema", "types", 0, "kind"), []),
    (("data", "__schema", "types", 0, "kind"), "ENUM"),
    (("data", "__schema", "types", 1, "name"), "Int"),
    (("data", "__schema", "types", 8, "isOneOf"), True),
    (("data", "__schema", "types", 8, "isOneOf"), 0),
    (("data", "__schema", "types", 8, "inputFields"), []),
    (("data", "__schema", "types", 6, "enumValues"), []),
    (("data", "__schema", "types", 6, "enumValues"), [{"name": "null"}]),
    (("data", "__schema", "types", 6, "enumValues"), [{"name": "A"}, {"name": "A"}]),
    (("data", "__schema", "types", 10, "fields"), []),
    (("data", "__schema", "types", 10, "fields", 1, "name"), "lookup"),
    (("data", "__schema", "types", 10, "fields", 0, "name"), "__private"),
    (("data", "__schema", "types", 10, "fields", 0, "args", 0, "name"), "filter"),
    (("data", "__schema", "types", 10, "fields", 0, "args", 0, "defaultValue"), 1),
    (("data", "__schema", "types", 10, "fields", 0, "type"),
     {"kind": "OBJECT", "name": "Absent"}),
    (("data", "__schema", "types", 10, "fields", 0, "type"),
     {"kind": "SCALAR", "name": "User"}),
    (("data", "__schema", "types", 10, "fields", 0, "type"),
     {"kind": "INPUT_OBJECT", "name": "Filter"}),
    (("data", "__schema", "types", 10, "fields", 0, "args", 0, "type"),
     {"kind": "OBJECT", "name": "User"}),
    (("data", "__schema", "types", 10, "fields", 0, "args", 0, "type"),
     {"kind": [], "name": "ID"}),
    (("data", "__schema", "types", 10, "fields", 0, "args", 0, "type"),
     {"kind": "LIST", "name": "ID", "ofType": {"kind": "SCALAR", "name": "ID"}}),
    (("data", "__schema", "types", 10, "fields", 0, "args", 0, "type"),
     {"kind": "NON_NULL", "ofType": {"kind": "NON_NULL", "ofType":
         {"kind": "SCALAR", "name": "ID"}}}),
    (("data", "__schema", "types", 10, "fields", 0, "args", 0, "type"),
     {"kind": "SCALAR", "name": "ID", "ofType": {"kind": "SCALAR", "name": "Int"}}),
    (("data", "__schema", "types", 10, "fields", 0, "auth"), "ignored"),
])
def test_ConsumedDeclarationsFailClosed(path, value):
    """Unknown semantics, wrapper errors, mismatched kinds and duplicate members are refused."""

    with pytest.raises(ValueError):
        Imported(Changed(path, value))


@pytest.mark.parametrize("endpoint_url", [
    "http://127.0.0.1/graphql?", "http://127.0.0.1/graphql?token=owned",
    "http://127.0.0.1/{path}", "http://user:synthetic@127.0.0.1/graphql",
    "file:///owned/graphql", "http://127.0.0.1/graphql#fragment",
])
def test_EndpointContextCannotCarryRuntimeValuesOrImplicitResolution(endpoint_url):
    """A caller context must be a concrete structural HTTP(S) endpoint without extra authority."""

    with pytest.raises(ValueError):
        Imported(endpoint_url=endpoint_url)


def test_ExactOriginalBytesWorkspaceAndEndpointBindGenerationReference():
    """A shape-equivalent description or another caller context cannot reuse an operation grant."""

    original = Imported()
    operation = next(item for item in original.operations if item.field_name == "lookup")
    spaced = Source() + b"\n"
    same_shape = Imported(spaced)
    other = next(item for item in same_shape.operations if item.field_name == "lookup")
    assert other.template.Reference() == operation.template.Reference(), (
        "Identical symbolic request structure changed identity"
    )
    assert other.Reference() != operation.Reference(), "Original source bytes lost identity binding"

    for source, workspace_id, endpoint_url in [
        (spaced, "owned", ENDPOINT), (Source(), "different", ENDPOINT),
        (Source(), "owned", "http://127.0.0.1:8080/other"),
    ]:
        with pytest.raises(ValueError):
            graphql.GenerateGraphQlRequest(source, operation.Reference(),
                workspace_id=workspace_id, endpoint_url=endpoint_url)


def test_DirectSchemaEnvelopeUsesRealPointersAndDistinctSourceIdentity():
    """Explicit schema exports are imported without inventing a successful network response."""

    document = json.loads(Source())
    direct = json.dumps(document["data"]).encode()
    imported = Imported(direct)
    assert all(item.source_pointer.startswith("#/__schema/types/")
               for item in imported.operations), "Exporter pointers inherited a false envelope"
    assert imported.source_digest != Imported().source_digest, "Distinct original bytes collapsed"


def test_NamedInputCyclesAreFiniteMetadataButCannotProduceGuessedValues():
    """An actual recursive input is represented without recursive expansion and preview fails."""

    cyclic = Changed(("data", "__schema", "types", 7, "inputFields", 0, "type"),
                     {"kind": "INPUT_OBJECT", "name": "Filter"})
    assert Imported(cyclic), "Finite named recursive metadata was mistaken for JSON recursion"

    with pytest.raises(ValueError, match="cycles"):
        Preview(value=cyclic)


def test_RequiredSingularInputCycleCannotProduceAValidSchemaObservation():
    """A non-null singular self-cycle has no finite valid value and fails during import."""

    invalid = Changed(("data", "__schema", "types", 7, "inputFields", 0, "type"),
        {"kind": "NON_NULL", "ofType": {"kind": "INPUT_OBJECT", "name": "Window"}})

    with pytest.raises(ValueError, match="required singular"):
        Imported(invalid)


def test_ByteCeilingAcceptsExactSourceAndRefusesOneAdditionalByte():
    """Original bytes are bounded before parsing, with an inclusive exact ceiling."""

    source = Source()
    exact = source + b" " * (graphql.MAX_GRAPHQL_BYTES - len(source))
    assert Imported(exact).source_digest == "sha256:" + hashlib.sha256(exact).hexdigest(), (
        "Exact allowed original-byte input was rejected or normalized"
    )

    with pytest.raises(ValueError):
        Imported(exact + b" ")


@pytest.mark.parametrize("constant,ceiling", [
    ("MAX_GRAPHQL_BYTES", 8), ("MAX_GRAPHQL_NODES", 20), ("MAX_GRAPHQL_DEPTH", 2),
    ("MAX_GRAPHQL_TYPES", 2), ("MAX_GRAPHQL_OPERATIONS", 3),
    ("MAX_GRAPHQL_MEMBERS", 1), ("MAX_GRAPHQL_TYPE_DEPTH", 1),
    ("MAX_GRAPHQL_OUTPUT_BYTES", 64),
])
def test_ImporterEnforcesEveryFiniteResourceBudget(monkeypatch, constant, ceiling):
    """Each configured ceiling actually rejects a source exceeding that distinct resource."""

    monkeypatch.setattr(graphql, constant, ceiling)

    with pytest.raises(ValueError):
        Imported()


@pytest.mark.parametrize("constant,ceiling", [
    ("MAX_GRAPHQL_GENERATED_NODES", 2), ("MAX_GRAPHQL_BODY_BYTES", 64),
])
def test_PreviewEnforcesExpansionAndActualEncodingBudgets(monkeypatch, constant, ceiling):
    """Typed source success does not bypass separate generated-node or concrete-body limits."""

    monkeypatch.setattr(graphql, constant, ceiling)

    with pytest.raises(ValueError):
        Preview()


def test_SameRootFieldAcrossKindsProducesDistinctExistingRequestTemplates():
    """Query and mutation names must not collide inside the real request collection producer."""

    document = json.loads(Source())
    schema = document["data"]["__schema"]
    schema["types"][11]["fields"] = [schema["types"][10]["fields"][0]]
    imported = Imported(json.dumps(document).encode())
    matching = [item for item in imported.operations if item.field_name == "lookup"]
    assert len(matching) == 2, "Root-kind distinction dropped an actual declaration"
    assert len({item.template.Reference() for item in matching}) == 2, (
        "Root-kind operations collapsed into one existing RequestTemplate identity"
    )
    provenance = ModelProvenance("graphql-import", "run:owned", "2026-10-13T00:00:01Z",
                                "scope:owned", matching[0].target.Reference(), "1", ())
    actual = RequestsFromObject(graphql.ProjectGraphQl(imported, provenance=(provenance,)))
    assert all(item.template in actual for item in matching), (
        "Actual projection/decoder lost a distinct root-kind operation"
    )


@pytest.mark.parametrize("imported", [None, "description", b"schema"])
def test_ProjectionRequiresTypedImportAndExistingProvenanceOwner(imported):
    """An arbitrary description cannot be passed directly to the model producer."""

    with pytest.raises(ValueError):
        graphql.ProjectGraphQl(imported, provenance=())


def test_ExactScopePreflightDoesNotManufactureConsentOrApproveRuntimeImpact():
    """Current membership and explicit target identity still decide for descriptive mutations."""

    operation = next(item for item in Imported().operations if item.operation_kind == "mutation")
    at = datetime(2026, 10, 13, tzinfo=timezone.utc)
    unknown = ScopeSnapshot("owned", "owned", ScopeAuthorization(
        AuthorizationState.UNKNOWN, "operator:owned", "consent:owned",
    ), targets=(operation.target,), allow=(operation.target,))

    with pytest.raises(PermissionError):
        graphql.CheckGraphQlTarget(operation, operation.target, unknown, at=at)

    allowed = ScopeSnapshot("owned", "owned", ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:owned", "consent:owned",
    ), targets=(operation.target,), allow=(operation.target,))
    assert graphql.CheckGraphQlTarget(operation, operation.target, allowed, at=at).Allowed(), (
        "Explicit exact current mutation target membership was rejected"
    )

    for target in [Target(TargetKind.IP, "127.0.0.1"), Target(TargetKind.URL, ENDPOINT + "/other")]:
        with pytest.raises(ValueError):
            graphql.CheckGraphQlTarget(operation, target, allowed, at=at)

    with pytest.raises(ValueError):
        graphql.CheckGraphQlTarget(None, operation.target, allowed, at=at)


def test_ReplacedOperationCannotBorrowConsentFromAnotherConcreteTemplateTarget():
    """Ordinary record replacement must not check /allowed consent for a /graphql template."""

    operation = next(item for item in Imported().operations if item.field_name == "lookup")
    other = Target(TargetKind.URL, "http://127.0.0.1:8080/allowed")
    forged = replace(operation, target=other)
    at = datetime(2026, 10, 13, tzinfo=timezone.utc)
    scope = ScopeSnapshot("owned", "owned", ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:owned", "consent:owned",
    ), targets=(other,), allow=(other,))
    assert scope.Check(other, at=at).Allowed(), "Control target lacks its intended exact consent"

    with pytest.raises(ValueError, match="producer context"):
        graphql.CheckGraphQlTarget(forged, other, scope, at=at)

    assert operation.template.endpoint.path_template == "/graphql", "Original template changed"


@pytest.mark.parametrize("field,value", [
    ("workspace_id", "foreign"), ("source_digest", "sha256:" + "f" * 64),
    ("operations", []), ("types", []),
])
def test_ReplacedImportCannotPublishContradictoryWorkspaceOrByteAttribution(field, value):
    """Actual model projection rejects inconsistent global/operation producer annotations."""

    imported = Imported()
    provenance = ModelProvenance("graphql-import", "run:owned", "2026-10-13T00:00:01Z",
        "scope:owned", imported.operations[0].target.Reference(), "1", ())

    with pytest.raises(ValueError):
        graphql.ProjectGraphQl(replace(imported, **{field: value}), provenance=(provenance,))


@pytest.mark.parametrize("field,value", [
    ("arguments", []), ("source_digest", "bad"), ("source_pointer", "#/foreign"),
    ("operation_kind", "execute"), ("field_name", "__reserved"), ("result_type", "String"),
])
def test_ReplacedOperationCannotBypassClosedSymbolicProducerContract(field, value):
    """The scope consumer refuses malformed typed records before interpreting their context."""

    operation = next(item for item in Imported().operations if item.field_name == "lookup")
    scope = ScopeSnapshot("owned", "owned", ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:owned", "consent:owned",
    ), targets=(operation.target,), allow=(operation.target,))

    with pytest.raises(ValueError):
        graphql.CheckGraphQlTarget(replace(operation, **{field: value}), operation.target, scope,
                                  at=datetime(2026, 10, 13, tzinfo=timezone.utc))


def test_ReplacedArgumentAndNamedDefinitionCannotContradictActualProducerTypes():
    """Argument bindings and type registries are checked before existing model publication."""

    imported = Imported()
    operation = next(item for item in imported.operations if item.field_name == "lookup")
    provenance = ModelProvenance("graphql-import", "run:owned", "2026-10-13T00:00:01Z",
                                "scope:owned", operation.target.Reference(), "1", ())
    argument = operation.arguments[0]
    malformed = replace(argument, value_type=replace(argument.value_type, wrappers=["LIST"]))
    forged_operation = replace(operation, arguments=(malformed, *operation.arguments[1:]))
    operations = tuple(forged_operation if item == operation else item
                       for item in imported.operations)

    with pytest.raises(ValueError):
        graphql.ProjectGraphQl(replace(imported, operations=operations), provenance=(provenance,))

    definitions = tuple(replace(item, kind="OBJECT", input_fields=()) if item.name == "Filter"
                        else item for item in imported.types)

    with pytest.raises(ValueError, match="named definitions"):
        graphql.ProjectGraphQl(replace(imported, types=definitions), provenance=(provenance,))


class UntrustedGraphQlImport(graphql.GraphQlImport):
    """Represent a record subclass that is not part of the closed offline producer contract."""


def test_RecordSubclassCannotOverrideClosedProjectionConsumer():
    """Projection accepts exact producer records without arbitrary overriding behaviors."""

    imported = Imported()
    subclass = UntrustedGraphQlImport(imported.workspace_id, imported.source_digest,
                                     imported.operations, imported.types)

    with pytest.raises(ValueError, match="closed bounded"):
        graphql.ProjectGraphQl(subclass, provenance=())
