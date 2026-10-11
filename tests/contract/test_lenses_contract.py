# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Published declarative lens schemas and exact decoding contracts for automation clients."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from fuzzy1337.lenses import LENS_CATALOG, LensDescriptor, LensQuery, ResolveLens
from fuzzy1337.model import CanonicalModelJson, ModelState

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "contracts/workflow-lens.schema.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("lens", LENS_CATALOG, ids=lambda lens: lens.identifier)
def test_AllCatalogDescriptorsAndActualViewsValidateAndRoundTrip(lens):
    """Real metadata/view producers match the published schema and exact decoder, not a mock."""

    Draft202012Validator.check_schema(SCHEMA)
    validator = Draft202012Validator(SCHEMA)
    document = lens.ToDict()
    validator.validate(document)
    validator.validate(lens.Project(ModelState("synthetic")))
    decoded = LensDescriptor.FromDict(json.loads(CanonicalModelJson(document)))

    assert decoded == lens, (
        'Lens contract failed: all catalog descriptors and actual views validate and round trip.'
    )
    assert CanonicalModelJson(decoded.ToDict()) == CanonicalModelJson(document), (
        'Lens contract failed: all catalog descriptors and actual views validate and round trip.'
    )


@pytest.mark.parametrize("field,value", [
    ("schema_version", 2), ("schema_version", True), ("identifier", ""),
    ("preferred_object_kinds", ["unknown-object"]),
    ("preferred_relation_kinds", ["unknown-relation"]),
    ("contextual_actions", [{"identifier": "action", "summary": "Test", "execute": "rm"}]),
    ("overlays", ["scope-override"]),
    ("attribute_mappings", {"known": 1}),
    ("presentation", {"columns": [], "group_by": "impact", "observation_order": "reference"}),
])
def test_MalformedDescriptorsFailBothPublishedSchemaAndRuntime(field, value):
    """Reject unsupported versions, kinds, handlers, and policy fields in active lens metadata."""

    document = ResolveLens("pentest").ToDict()
    document[field] = value

    assert list(Draft202012Validator(SCHEMA).iter_errors(document)), (
        'Lens contract failed: malformed descriptors fail both published schema and runtime.'
    )

    with pytest.raises(ValueError):
        LensDescriptor.FromDict(document)


@pytest.mark.parametrize("field", ["scope", "authorization", "impact", "execute", "workspace"])
def test_ExtraAuthorityOrStateFieldsAreRejected(field):
    """Lens metadata cannot contain policy overrides, executable instructions, or copied state."""

    document = ResolveLens("pentest").ToDict()
    document[field] = "override"

    assert list(Draft202012Validator(SCHEMA).iter_errors(document)), (
        'Lens contract failed: extra authority or state fields are rejected.'
    )

    with pytest.raises(ValueError, match="exactly"):
        LensDescriptor.FromDict(document)


@pytest.mark.parametrize("field,value", [
    ("object_kinds", ["unknown"]), ("relation_kinds", "related-to"),
    ("include_observations", 1), ("require_provenance", None),
    ("attributes_match", ["not-an-object"]), ("key_contains", None),
])
def test_MalformedQueryFieldsFailBothSchemaAndRuntime(field, value):
    """Machine clients receive failures instead of guessed filters or policy-sensitive fallbacks."""

    document = ResolveLens("pentest").ToDict()
    document["default_query"][field] = value

    assert list(Draft202012Validator(SCHEMA).iter_errors(document)), (
        'Lens contract failed: malformed query fields fail both schema and runtime.'
    )

    with pytest.raises(ValueError):
        LensDescriptor.FromDict(document)


def test_MissingFieldsAreRejectedRatherThanAssumed():
    """No missing required field silently expands a query to all canonical objects."""

    document = LensQuery().ToDict()
    del document["object_kinds"]

    with pytest.raises(ValueError, match="exactly"):
        LensQuery.FromDict(document)


def test_ReferenceViewIsNotWritableCanonicalModelFormat():
    """Automation cannot import a persona projection as another authoritative model state."""

    state = ModelState("synthetic")
    projected = ResolveLens("purple").Project(state)

    with pytest.raises(ValueError):
        ModelState.FromDict(projected)
