# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Handwritten source/type/request oracle through the original API product handler."""

from __future__ import annotations

import hashlib
import json

from fuzzy1337.findings import Findings
from fuzzy1337.model import CanonicalModelJson, LocalModelStore
from fuzzy1337.requests import BindingSource, BodyKind, RequestsFromObject
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.api_import_helpers import Arguments, Context, Run


def test_OriginalImportMatchesIndependentTypedPointerAndCustodyOracle(tmp_path):
    """Five structural operations retain pointers/types and no authority or values."""

    context = Context(tmp_path)
    root, initial, scope, evidence, source = context
    original = source.read_bytes()
    status, outcome = Run(Arguments(context))
    assert status == 0 and outcome["status"] == "succeeded", "Owned import failed"
    assert all(
        outcome[field] == "confirmed"
        for field in (
            "acquisition_commit",
            "model_commit",
            "workspace_commit",
        )
    ), "Independent storage acknowledgements were lost"
    record = evidence.Get(outcome["evidence_id"])
    assert record.reference.role == "graphql-introspection", "Original source role changed"
    assert record.reference.sha256 == hashlib.sha256(original).hexdigest(), "Original hash changed"
    assert evidence.Read(record.reference) == original, "Original bytes were normalized"
    assert record.provenance.source_id == "graphql-import" and (
        record.provenance.source_version == "1"
        and record.provenance.tool_version is None
        and record.provenance.execution is None
        and record.provenance.invocation_sha256 is None
    ), "Structural collection acquired execution or invented provider metadata"
    model = LocalModelStore(root).Open()
    assert model.revision == initial.revision + 1, (
        "Projection/custody used multiple model revisions"
    )
    assert len(model.objects) == 1 and not model.relations, (
        "Import manufactured other graph entities"
    )
    endpoint = model.objects[0]
    metadata = json.loads(CanonicalModelJson(endpoint.attributes["graphql_import"]))
    operations = metadata["operations"]
    assert [
        (item["operation_kind"], item["field_name"], item["source_pointer"]) for item in operations
    ] == [
        ("mutation", "updateOwned", "#/data/__schema/types/11/fields/0"),
        ("query", "lookup", "#/data/__schema/types/10/fields/0"),
        ("query", "opaque", "#/data/__schema/types/10/fields/2"),
        ("query", "ping", "#/data/__schema/types/10/fields/1"),
        ("subscription", "ticks", "#/data/__schema/types/12/fields/0"),
    ], "Typed root operation/source coordinate oracle failed"
    assert metadata["source_digest"] == "sha256:" + hashlib.sha256(original).hexdigest(), (
        "Typed metadata did not bind the verified exact source bytes"
    )
    lookup = next(item for item in operations if item["field_name"] == "lookup")
    assert [
        (item["name"], item["source_pointer"], item["type"]) for item in lookup["arguments"]
    ] == [
        (
            "filter",
            "#/data/__schema/types/10/fields/0/args/1",
            {"kind": "INPUT_OBJECT", "name": "Filter", "wrappers": []},
        ),
        (
            "ids",
            "#/data/__schema/types/10/fields/0/args/0",
            {"kind": "SCALAR", "name": "ID", "wrappers": ["NON_NULL", "LIST", "NON_NULL"]},
        ),
    ], "Finite symbolic argument type oracle failed"
    templates = RequestsFromObject(endpoint)
    assert len(templates) == 5 and all(
        item.body_kind is BodyKind.GRAPHQL
        and item.endpoint.method == "POST"
        and item.session_reference is None
        for item in templates
    ), "Existing typed request consumer lost GraphQL structure or gained sessions"
    assert all(
        point.binding.source is BindingSource.INPUT
        for item in templates
        for point in item.injection_points
    ), "Source import acquired session bindings"
    assert not Findings(model), "Descriptive mutation/subscription manufactured findings"
    custody = [item for item in model.observations if item.kind == "api-import-source"]
    assert (
        len(custody) == 1
        and custody[0].subject_reference == endpoint.Reference()
        and (
            custody[0].attributes["evidence_id"] == record.evidence_id
            and custody[0].attributes["read_actor_reference"] == "actor:owned"
            and custody[0].attributes["read_consent_reference"] == "consent:original"
        )
    ), "Original manifest identity/read custody was lost"
    workspace = LocalWorkspaceStore(root).Open()
    assert workspace.evidence_record_references == (record.evidence_id,) and (
        workspace.evidence_references == (record.reference,)
        and workspace.object_references == (endpoint.Reference(),)
        and workspace.scope_references == (scope.Reference(),)
        and not workspace.job_references
    ), "Portable owners lost the original acquisition or manufactured a job"
    safe = CanonicalModelJson({"model": model.ToDict(), "outcome": outcome})
    assert b"synthetic-private-default" not in safe and str(source).encode() not in safe, (
        "Source defaults/descriptions or filename escaped original evidence"
    )
