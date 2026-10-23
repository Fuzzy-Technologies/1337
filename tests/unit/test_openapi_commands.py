# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Closed original OpenAPI input, complete custody and independent storage acknowledgements."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path

import pytest

from fuzzy1337 import openapi_commands as commands
from fuzzy1337.api_commands import ApiEvidenceStore, RunApiCommands
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.model import LocalModelStore, SecurityObject
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration
from tests.api_import_helpers import Arguments as GraphQlArguments
from tests.api_import_helpers import Context as GraphQlContext

NOW = datetime(2026, 10, 23, 18, tzinfo=UTC)
ORIGIN = "http://127.0.0.1:19004"


def Document():
    """Declare independent concrete GET/POST operations without transport or template code."""

    return {"openapi": "3.1.2", "servers": [{"url": "/v1"}], "paths": {
        "/status": {"get": {"operationId": "status", "responses": {}}},
        "/items": {"post": {"operationId": "items", "responses": {}}},
    }}


def Context(parent, *, document=None):
    """Create the actual file/model/workspace/scope owners using a fixed decision time."""

    root = parent / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned OpenAPI"), "openapi-owned")
    LocalModelStore(root).Create()
    targets = tuple(Target(TargetKind.URL, ORIGIN + path) for path in ("/v1/status", "/v1/items"))
    LocalScopeStore(root).Create(ScopeSnapshot("local", "openapi-owned", ScopeAuthorization(
        AuthorizationState.GRANTED, "actor:owned", "consent:endpoints",
        (NOW - timedelta(minutes=1)).isoformat(), (NOW + timedelta(minutes=1)).isoformat(),
    ), targets=targets, allow=targets))
    source = parent / "owned.json"
    source.write_text(json.dumps(Document() if document is None else document), encoding="utf-8")

    return root, source


def Arguments(context, *, evidence=None):
    """Select explicit original read consent and independently current owner revisions."""

    root, source = context
    result = ["import", "openapi-json", str(root), "--scope", "local", "--run", "run:original",
        "--base-url", ORIGIN + "/", "--expected-revision",
        str(LocalModelStore(root).Open().revision),
        "--expected-workspace-revision", str(LocalWorkspaceStore(root).Open().revision)]

    if evidence is None:
        result.extend(("--file", str(source), "--owner", "actor:owned",
                       "--read-consent-reference", "consent:source"))

    else:
        result.extend(("--evidence", evidence))

    return result


def Run(arguments, *, clock=lambda: NOW):
    """Exercise the existing actual API dispatcher and its bounded JSON summary."""

    output = StringIO()
    result = RunApiCommands(arguments, output, json_output=True, clock=clock)

    return result, json.loads(output.getvalue())


def test_WholeConcreteDocumentKeepsOriginalBytesAndReplaysExactCustody(tmp_path):
    """All source operations create existing endpoints and retained replay is an exact no-op."""

    context = Context(tmp_path)
    status, first = Run(Arguments(context))
    assert status == 0, first
    root, source = context
    evidence = LocalEvidenceStore(root / "evidence")
    record = evidence.Get(first["evidence_id"])
    assert evidence.Read(record.reference) == source.read_bytes(), "Original source bytes changed."
    assert first["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest(), (
        "Source digest did not cover the exact original file."
    )
    model = LocalModelStore(root).Open()
    facts = tuple(item for item in model.observations if item.kind == "openapi-import-source")
    assert len(model.objects) == 2 and len(facts) == 2, (
        "Whole source operations were dropped or source custody was incomplete."
    )
    source.unlink()
    status, replay = Run(Arguments(context, evidence=first["evidence_id"]))
    assert status == 0 and replay["created"] == replay["updated"] == 0, replay
    assert LocalModelStore(root).Open() == model, "Known original replay changed the model."


@pytest.mark.parametrize("base", [
    ORIGIN, "HTTP://127.0.0.1:19004/", ORIGIN + "/?", ORIGIN + "/{id}",
])
def test_RawNoncanonicalBasesAreRefusedBeforeSourceAcquisition(tmp_path, base):
    """Canonicalization must not erase unsupported original base spelling or template data."""

    context = Context(tmp_path)
    arguments = Arguments(context)
    arguments[arguments.index("--base-url") + 1] = base
    status, outcome = Run(arguments)
    assert status == 2 and outcome["acquisition_commit"] == "not-attempted", outcome


@pytest.mark.parametrize("option", ["--owner", "--read-consent-reference", "--run", "--scope"])
def test_MissingExplicitContextRefusesOriginalReads(tmp_path, option):
    """No workspace or source metadata can infer explicit consent or import context."""

    context = Context(tmp_path)
    arguments = Arguments(context)
    index = arguments.index(option)
    del arguments[index:index + 2]
    status, outcome = Run(arguments)
    assert status == 2 and outcome["acquisition_commit"] == "not-attempted", outcome


@pytest.mark.parametrize("selection", ["base", "run", "unknown"])
def test_RetainedSelectionCannotAdoptOrChangeOriginalCustody(tmp_path, monkeypatch, selection):
    """Known original context is checked before the generic retained raw reader is reached."""

    context = Context(tmp_path)
    status, first = Run(Arguments(context))
    assert status == 0, first
    identity = first["evidence_id"]

    if selection == "unknown":
        root, source = context
        evidence = LocalEvidenceStore(root / "evidence")
        source_context = EvidenceProvenance("openapi-owned", "scope:local", "openapi-import",
            "1", None, (NOW + timedelta(seconds=1)).isoformat(),
            (NOW + timedelta(seconds=1)).isoformat())
        identity = evidence.Put(source.read_bytes(), "openapi-json", "application/json",
                                 source_context).evidence_id

    arguments = Arguments(context, evidence=identity)

    if selection == "base":
        arguments[arguments.index("--base-url") + 1] = ORIGIN + "/other"

    elif selection == "run":
        arguments[arguments.index("--run") + 1] = "run:changed"

    def Refuse(*args, **kwargs):
        """Fail if a refused source reaches the generic evidence-consuming report owner."""

        pytest.fail("Original custody refusal reached a generic raw consumer.")

    monkeypatch.setattr(commands, "OpenReportInput", Refuse)
    status, outcome = Run(arguments)
    assert status == 4 and outcome["failure"] == "source-context", outcome


@pytest.mark.parametrize("owner", ["acquisition", "model", "workspace"])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("interrupt", [False, True])
def test_OriginalOwnerAcknowledgementLossRemainsUnknown(
    tmp_path, monkeypatch, owner, after, interrupt,
):
    """An actual owner may commit before losing acknowledgement; no rollback is inferred."""

    context = Context(tmp_path)
    storage = {"acquisition": commands.ApiEvidenceStore, "model": LocalModelStore,
               "workspace": LocalWorkspaceStore}[owner]
    name = "Put" if owner == "acquisition" else "Save"
    original = getattr(storage, name)

    def Lose(self, *args, **kwargs):
        """Optionally call the actual owner and then lose its acknowledgement deterministically."""

        if after:
            original(self, *args, **kwargs)

        if interrupt:
            raise KeyboardInterrupt

        raise OSError("PRIVATE_ACK_MARKER")

    monkeypatch.setattr(storage, name, Lose)
    status, outcome = Run(Arguments(context))
    assert status == (130 if interrupt else 4) and outcome[owner + "_commit"] == "unknown", outcome
    assert "PRIVATE_ACK_MARKER" not in json.dumps(outcome), "Raw owner diagnostics escaped."
    model, workspace = LocalModelStore(context[0]).Open(), LocalWorkspaceStore(context[0]).Open()
    assert model.revision == int(owner == "workspace" or owner == "model" and after), (
        "Actual committed model state differs from the acknowledged partial state."
    )
    assert workspace.revision == int(owner == "workspace" and after), (
        "Actual committed workspace state differs from the acknowledged partial state."
    )


def test_DuplicateOperationMembersDoNotBecomeSilentlyDroppedOperations(tmp_path):
    """Original duplicate JSON members fail inside the existing strict SDK decoder."""

    context = Context(tmp_path)
    context[1].write_text('{"openapi":"3.1.2","paths":{},"paths":{}}', encoding="utf-8")
    status, outcome = Run(Arguments(context))
    assert status == 4 and outcome["failure"] == "normalization", outcome
    assert outcome["acquisition_commit"] == "confirmed" and (
        outcome["model_commit"] == "not-attempted"
    ), "Parsing refusal invented a successful model transition or lost original acquisition."


@pytest.mark.parametrize("profile", ["openapi-json", "graphql-introspection"])
def test_NewOriginalFileCannotPublishAnAliasOfExistingWorkspaceCustody(
    tmp_path, monkeypatch, profile,
):
    """A new role must pass existing custody checks before its raw read or model write."""

    context = Context(tmp_path) if profile == "openapi-json" else GraphQlContext(tmp_path)
    root = context[0]
    source = context[1] if profile == "openapi-json" else context[4]
    workspace = LocalWorkspaceStore(root).Open()
    scope_id = "local" if profile == "openapi-json" else "owned"
    evidence = LocalEvidenceStore(root / "evidence")
    previous = evidence.Put(source.read_bytes(), "other-original", "application/json",
        EvidenceProvenance(workspace.workspace_id, "scope:" + scope_id, "owned.original", "1",
            None, NOW.isoformat(), NOW.isoformat()))
    workspace = LocalWorkspaceStore(root).Save(replace(workspace,
        evidence_references=(previous.reference,),
        evidence_record_references=(previous.evidence_id,)))
    basis = LocalModelStore(root).Open()
    original_read = LocalEvidenceStore.Read
    roles = []

    def Observe(store, reference):
        """Observe exact raw roles without replacing the actual evidence integrity reader."""

        roles.append(reference.role)

        return original_read(store, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", Observe)
    arguments = Arguments(context) if profile == "openapi-json" else GraphQlArguments(context)
    status, outcome = Run(arguments)
    assert status == 4 and outcome["failure"] == "integrity", outcome
    assert outcome["acquisition_commit"] == "confirmed" and (
        outcome["model_commit"] == outcome["workspace_commit"] == "not-attempted"
    ), "Alias refusal lost the real acquisition or attempted an incompatible model transition."
    assert profile not in roles, "The new aliased role reached a raw source consumer."
    assert LocalModelStore(root).Open() == basis and (
        LocalWorkspaceStore(root).Open() == workspace
    ), "Refused alias changed the existing model or workspace custody."


@pytest.mark.parametrize("field,value", [
    ("profile", "graphql-introspection"),
    ("source_sha256", "a" * 64),
    ("source_version", "2"),
    ("base_url", ORIGIN),
    ("read_actor_reference", None),
    ("read_consent_reference", ""),
    ("endpoint_count", 1),
    ("endpoint_count", True),
    ("operation_count", 1),
    ("operation_count", 129),
    ("operation_references", []),
    ("operation_references", "api-operation:" + "a" * 64),
    ("operation_references", ["api-operation:" + "a" * 64]),
])
def test_KnownOriginalFactsRejectMutatedClosedContext(tmp_path, field, value):
    """Persisted descriptive metadata cannot silently redefine original complete source custody."""

    context = Context(tmp_path)
    status, first = Run(Arguments(context))
    assert status == 0, first
    model = LocalModelStore(context[0]).Open()
    fact = next(item for item in model.observations if item.kind == "openapi-import-source")
    altered = replace(fact, attributes={**fact.attributes, field: value})
    changed = replace(model, observations=tuple(altered if item == fact else item
        for item in model.observations))
    record = LocalEvidenceStore(context[0] / "evidence").Get(first["evidence_id"])

    with pytest.raises((commands.RuntimeFailure, ValueError, TypeError)):
        commands.KnownOpenApiFacts(changed, record)


@pytest.mark.parametrize("mutation", ["missing-fact", "missing-field", "unknown-field",
    "wrong-run", "missing-operations", "false-operation", "missing-templates"])
def test_KnownOriginalFactsRequireCompleteSubjectAndOperationBindings(tmp_path, mutation):
    """Original custody requires every endpoint and recomputable operation/request join."""

    context = Context(tmp_path)
    status, first = Run(Arguments(context))
    assert status == 0, first
    model = LocalModelStore(context[0]).Open()
    fact = next(item for item in model.observations if item.kind == "openapi-import-source")
    subject = next(item for item in model.objects if item.Reference() == fact.subject_reference)
    observations, objects = model.observations, model.objects

    if mutation == "missing-fact":
        observations = tuple(item for item in observations if item != fact)

    elif mutation in ("missing-field", "unknown-field"):
        attributes = dict(fact.attributes)

        if mutation == "missing-field":
            del attributes["base_url"]

        else:
            attributes["invented"] = "value"

        altered = replace(fact, attributes=attributes)
        observations = tuple(altered if item == fact else item for item in observations)

    elif mutation == "wrong-run":
        altered = replace(fact, provenance=replace(fact.provenance, run_reference="run:other"))
        observations = tuple(altered if item == fact else item for item in observations)

    else:
        attributes = dict(subject.attributes)

        if mutation == "missing-operations":
            del attributes["openapi_operations"]

        elif mutation == "missing-templates":
            del attributes["request_templates"]

        else:
            operation = dict(attributes["openapi_operations"][0])
            operation["request_reference"] = "request:" + "a" * 64
            attributes["openapi_operations"] = [operation]

        altered = SecurityObject(subject.identity, attributes, subject.provenance)
        objects = tuple(altered if item == subject else item for item in objects)

    changed = replace(model, objects=objects, observations=observations)
    record = LocalEvidenceStore(context[0] / "evidence").Get(first["evidence_id"])

    with pytest.raises((commands.RuntimeFailure, ValueError, TypeError)):
        commands.KnownOpenApiFacts(changed, record)


@pytest.mark.parametrize("boundary", ["model", "workspace"])
def test_CurrentConsentExpiryCannotCrossEitherPersistenceBoundary(tmp_path, monkeypatch, boundary):
    """A deterministic phase-triggered clock change prevents the next actual owner write."""

    context = Context(tmp_path)
    instant = [NOW]

    if boundary == "model":
        original = commands.OpenApiProjection

        def Project(*args, **kwargs):
            """Complete pure projection, then advance authority time before model persistence."""

            result = original(*args, **kwargs)
            instant[0] = NOW + timedelta(minutes=2)

            return result

        monkeypatch.setattr(commands, "OpenApiProjection", Project)

    else:
        original = LocalModelStore.Save

        def Save(self, *args, **kwargs):
            """Commit the actual model, then expire authority before the workspace write."""

            result = original(self, *args, **kwargs)
            instant[0] = NOW + timedelta(minutes=2)

            return result

        monkeypatch.setattr(LocalModelStore, "Save", Save)

    status, outcome = Run(Arguments(context), clock=lambda: instant[0])
    assert status == 4 and outcome[boundary + "_commit"] == "not-attempted", outcome
    assert LocalModelStore(context[0]).Open().revision == int(boundary == "workspace"), (
        "Current consent expiry was ignored or earlier actual model state was hidden."
    )
    assert LocalWorkspaceStore(context[0]).Open().revision == 0, (
        "Expired authority saved workspace."
    )


def test_GraphQlAndOpenApiOriginalProfilesCoexistAndReplayIndependently(tmp_path):
    """Each original profile retains its custody and physical read ceiling in a shared workspace."""

    from tests.api_import_helpers import ENDPOINT
    from tests.api_import_helpers import Arguments as GraphQlArguments
    from tests.api_import_helpers import Run as GraphQlRun

    context = Context(tmp_path)
    root, _ = context
    scope = LocalScopeStore(root).Open("local")
    graphql = Target(TargetKind.URL, ENDPOINT)
    LocalScopeStore(root).Save(replace(scope, targets=(*scope.targets, graphql),
                                      allow=(*scope.allow, graphql)))
    source = tmp_path / "graphql.json"
    source.write_bytes((Path(__file__).parents[1] /
        "contract/fixtures/graphql_introspection.owned.json").read_bytes())
    graphql_context = root, LocalModelStore(root).Open(), scope,
    graphql_context = (*graphql_context, LocalEvidenceStore(root / "evidence"), source)
    arguments = GraphQlArguments(graphql_context)
    arguments[arguments.index("--scope") + 1] = "local"
    status, first_graphql = GraphQlRun(arguments, clock=lambda: NOW)
    assert status == 0, first_graphql
    status, first_openapi = Run(Arguments(context))
    assert status == 0, first_openapi
    status, replay = Run(Arguments(context, evidence=first_openapi["evidence_id"]))
    assert status == 0, replay
    arguments = GraphQlArguments(graphql_context, evidence_id=first_graphql["evidence_id"])
    arguments[arguments.index("--scope") + 1] = "local"
    status, replay = GraphQlRun(arguments, clock=lambda: NOW)
    assert status == 0, replay
    assert len(LocalModelStore(root).Open().objects) == 3, (
        "One profile replaced the other endpoints."
    )


@pytest.mark.parametrize("route", ["openapi-json", "graphql-introspection"])
@pytest.mark.parametrize("mutation", ["physical-growth", "role-alias", "unknown-raw-reference"])
def test_BothRoutesPreflightOpenApiCustodyAndPhysicalReferencesBeforeGenericReads(
    tmp_path, monkeypatch, route, mutation,
):
    """Changing the selected product route cannot bypass another original profile's read guards."""

    context = Context(tmp_path)
    status, first = Run(Arguments(context))
    assert status == 0, first
    root, source = context
    evidence = LocalEvidenceStore(root / "evidence")
    record = evidence.Get(first["evidence_id"])

    if mutation == "physical-growth":
        evidence.StoragePath(("blobs", "sha256", record.reference.sha256)).write_bytes(
            source.read_bytes() + b"excess")

    else:
        workspace = LocalWorkspaceStore(root).Open()
        alias = replace(record.reference, role="other-original")

        if mutation == "unknown-raw-reference":
            original = replace(record.provenance,
                started_at=(NOW + timedelta(seconds=1)).isoformat(),
                finished_at=(NOW + timedelta(seconds=1)).isoformat())
            alias = evidence.Put(source.read_bytes() + b"\n", "openapi-json", "application/json",
                                 original).reference

        LocalWorkspaceStore(root).Save(replace(workspace,
            evidence_references=(*workspace.evidence_references, alias)))

    arguments = Arguments(context)

    if route == "graphql-introspection":
        arguments[1] = route
        index = arguments.index("--base-url")
        del arguments[index:index + 2]
        arguments.extend(("--endpoint", ORIGIN + "/v1/status"))

    def Refuse(*args, **kwargs):
        """Fail if preflight reaches a raw consumer before refusing the changed original."""

        pytest.fail("Original profile corruption reached a raw read.")

    monkeypatch.setattr(LocalEvidenceStore, "Read", Refuse)
    status, outcome = Run(arguments)
    assert status == 4 and outcome["acquisition_commit"] == "not-attempted", outcome


@pytest.mark.parametrize("profile,maximum", [
    ("graphql-introspection", 512 * 1024), ("openapi-json", 1024 * 1024),
])
def test_ClosedOriginalProfilesHaveSeparatePhysicalReadCeilings(tmp_path, profile, maximum):
    """A shared evidence helper preserves each original profile's own declared maximum."""

    from fuzzy1337.adapters import EvidenceReference

    store = ApiEvidenceStore(tmp_path, "openapi-owned", "scope:local", profile=profile)
    reference = EvidenceReference(profile, "blobs/sha256/" + "a" * 64,
                                  "a" * 64, "application/json", maximum + 1)

    with pytest.raises(commands.RuntimeFailure, match="integrity"):
        store.CheckReference(reference)
