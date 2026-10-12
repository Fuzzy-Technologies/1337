# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic shared-model lens filters, suggestions, and validation boundaries."""

from dataclasses import replace

import pytest

from fuzzy1337.lenses import (
    LENS_CATALOG,
    LensAction,
    LensDescriptor,
    LensPresentation,
    LensQuery,
    ResolveLens,
)
from fuzzy1337.model import (
    CanonicalModelJson,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Observation,
    Relation,
    RelationKind,
    SecurityObject,
)


def Model() -> ModelState:
    """Create one canonical snapshot with distinct surfaces and attributed local history."""

    later = ModelProvenance(
        "native", "run:two", "2026-10-11T10:00:00Z", "scope:lab", "target:" + "a" * 64,
    )
    earlier = replace(later, run_reference="run:one", observed_at="2026-10-11T09:00:00Z")
    host = SecurityObject(ObjectIdentity("synthetic", ObjectKind.HOST, "127.0.0.1"),
                          {"state": "up", "number": 1}, (later,))
    asset = SecurityObject(ObjectIdentity("synthetic", ObjectKind.ASSET, "build:one"),
                           {"version": "1", "number": True, "nested": {"value": [1, None]}},
                           (earlier,))
    service = SecurityObject(ObjectIdentity("synthetic", ObjectKind.SERVICE, "loopback/tcp/80"),
                             provenance=(later,))
    relation = Relation(RelationKind.RELATED_TO, host.Reference(), asset.Reference(),
                        provenance=(later,))
    observations = (
        Observation("test.fact", host.Reference(), {"state": "earlier"}, earlier),
        Observation("test.fact", relation.Reference(), {"test": "edge"}, later),
    )
    state, _ = ModelState("synthetic").Apply(
        objects=(host, asset, service), relations=(relation,), observations=observations,
    )

    return state


def test_FourLensesProjectDifferentReferencesFromOneUnchangedModel():
    """Changing persona preserves objects, revisions, observations, and policy projections."""

    state = Model()
    original = CanonicalModelJson(state.ToDict())
    views = {lens.identifier: lens.Project(state) for lens in LENS_CATALOG}

    assert tuple(views) == ("pentest", "dfir", "devsecops", "purple"), (
        'Lens contract failed: four lenses project different references from one unchanged model.'
    )
    assert views["pentest"]["object_references"] != views["devsecops"]["object_references"], (
        'Lens contract failed: four lenses project different references from one unchanged model.'
    )
    assert len(views["purple"]["object_references"]) == len(state.objects), (
        'Lens contract failed: four lenses project different references from one unchanged model.'
    )
    assert len(views["dfir"]["object_references"]) == 2, (
        'Lens contract failed: four lenses project different references from one unchanged model.'
    )
    assert views["dfir"]["relation_references"] == [state.relations[0].Reference()], (
        'Lens contract failed: four lenses project different references from one unchanged model.'
    )
    assert views["pentest"]["relation_references"] == [], (
        'Lens contract failed: four lenses project different references from one unchanged model.'
    )
    assert CanonicalModelJson(state.ToDict()) == original, (
        'Lens contract failed: four lenses project different references from one unchanged model.'
    )
    assert all(view["revision"] == state.revision for view in views.values()), (
        'Lens contract failed: four lenses project different references from one unchanged model.'
    )
    assert all(view["workspace_id"] == state.workspace_id for view in views.values()), (
        'Lens contract failed: four lenses project different references from one unchanged model.'
    )


def test_AttributeFiltersUseStrictJsonEqualityWithoutBooleanNumericCoercion():
    """Query matches distinguish missing/null, bool/int, nesting, text, kinds, and attribution."""

    state = Model()
    host = next(item for item in state.objects if item.identity.kind is ObjectKind.HOST)
    asset = next(item for item in state.objects if item.identity.kind is ObjectKind.ASSET)
    service = next(item for item in state.objects if item.identity.kind is ObjectKind.SERVICE)

    assert LensQuery(attributes_match={"number": 1}).Matches(host), (
        'Attribute filters changed strict JSON matching.'
    )
    assert not LensQuery(attributes_match={"number": 1}).Matches(asset), (
        'Attribute filters changed strict JSON matching.'
    )
    assert not LensQuery(attributes_match={"missing": None}).Matches(host), (
        'Attribute filters changed strict JSON matching.'
    )
    assert LensQuery(attributes_match={"nested": {"value": [1, None]}}).Matches(asset), (
        'Attribute filters changed strict JSON matching.'
    )
    assert LensQuery(key_contains="BUILD").Matches(asset), (
        'Attribute filters changed strict JSON matching.'
    )
    assert not LensQuery(key_contains="BUILD").Matches(host), (
        'Attribute filters changed strict JSON matching.'
    )
    assert not LensQuery(object_kinds=(ObjectKind.HOST,)).Matches(asset), (
        'Attribute filters changed strict JSON matching.'
    )
    assert LensQuery(require_provenance=True).Matches(service), (
        'Attribute filters changed strict JSON matching.'
    )


def test_QueryOverridesDoNotChangeDefaultsAndExcludeDanglingContext():
    """Only induced relations/observations appear; overriding a preset never updates it."""

    state = Model()
    lens = ResolveLens("purple")
    original = lens.ToDict()
    query = LensQuery((ObjectKind.HOST,), include_observations=False)
    view = lens.Project(state, query)

    assert len(view["object_references"]) == 1, (
        'Lens contract failed: query overrides do not change defaults and exclude dangling context.'
    )
    assert view["relation_references"] == view["observation_references"] == [], (
        'Lens contract failed: query overrides do not change defaults and exclude dangling context.'
    )
    assert lens.ToDict() == original, (
        'Lens contract failed: query overrides do not change defaults and exclude dangling context.'
    )
    view["object_references"].clear()
    assert len(lens.Project(state)["object_references"]) == 3, (
        'Lens contract failed: query overrides do not change defaults and exclude dangling context.'
    )


def test_ChronologicalHistoryUsesNormalizedTimeAndStableReferenceTies():
    """DFIR sorts retained attribution in time order rather than claiming an inferred timeline."""

    state = Model()
    view = ResolveLens("dfir").Project(state)
    observations = {item.Reference(): item for item in state.observations}
    order = [(observations[reference].provenance.observed_at, reference)
             for reference in view["observation_references"]]

    assert order == sorted(order), (
        'Observation order changed time/reference ordering.'
    )
    assert len(order) == 5, (
        'Observation order changed time/reference ordering.'
    )


def test_CollectionsAndMappingsAreDetachedImmutableContracts():
    """Caller mutations cannot change a configured query or presentation descriptor."""

    attributes = {"nested": {"value": [1]}}
    query = LensQuery(attributes_match=attributes)
    attributes["nested"]["value"].append(2)
    assert query.ToDict()["attributes_match"] == {"nested": {"value": [1]}}, (
        'Lens contract failed: collections and mappings are detached immutable contracts.'
    )

    with pytest.raises(TypeError):
        query.attributes_match["new"] = "value"

    lens = ResolveLens("pentest")
    document = lens.ToDict()
    document["attribute_mappings"]["reported-state"] = "unknown"
    assert lens.attribute_mappings["reported-state"] == "state", (
        'Lens contract failed: collections and mappings are detached immutable contracts.'
    )
    assert ResolveLens("pentest") is lens, (
        'Lens contract failed: collections and mappings are detached immutable contracts.'
    )
    assert LensDescriptor.FromDict(lens.ToDict()) == lens, (
        'Lens contract failed: collections and mappings are detached immutable contracts.'
    )


@pytest.mark.parametrize("identifier", ["missing", "Pentest", "", None])
def test_UnknownLensesFailWithoutChoosingMorePermissiveDefaults(identifier):
    """Invalid identifiers never resolve fuzzily or select an implicit alternative."""

    with pytest.raises(ValueError):
        ResolveLens(identifier)


@pytest.mark.parametrize("arguments", [
    {"object_kinds": "host"}, {"object_kinds": ("host",)},
    {"object_kinds": (ObjectKind.HOST,) * 2}, {"relation_kinds": ("related-to",)},
    {"attributes_match": {"value": float("nan")}}, {"attributes_match": []},
    {"key_contains": None}, {"key_contains": "x" * 4097}, {"key_contains": "\ud800"},
    {"require_provenance": 1}, {"include_observations": "yes"},
])
def test_MalformedQueriesFailBeforeModelAccess(arguments):
    """Runtime callers must obey the same typed filter boundary as serialized clients."""

    with pytest.raises(ValueError):
        LensQuery(**arguments)


@pytest.mark.parametrize("arguments", [
    {"identifier": "INVALID"}, {"title": ""}, {"summary": "bad\ntext"},
    {"title": "\ud800"}, {"summary": "\ud800"},
    {"preferred_object_kinds": ("host",)}, {"preferred_relation_kinds": "contains"},
    {"default_query": {}}, {"presentation": {}},
    {"contextual_actions": ("not-an-action",)},
    {"contextual_actions": (LensAction("inspect", "First"), LensAction("inspect", "Second"))},
    {"preferred_capabilities": "network.test"},
    {"preferred_capabilities": ("network.test",) * 2},
    {"overlays": ("unknown",)}, {"attribute_mappings": {"invalid label": "state"}},
    {"attribute_mappings": {"valid": 1}},
])
def test_MalformedDescriptorsCannotSmuggleExecutionMetadata(arguments):
    """Invalid declarative metadata is rejected without touching policy or dispatch."""

    with pytest.raises(ValueError):
        replace(ResolveLens("pentest"), **arguments)


def test_ActionRejectsInvalidUtf8BeforePublishingMetadata():
    """An action suggestion cannot retain a lone surrogate that fails later JSON emission."""

    with pytest.raises(ValueError, match="UTF-8"):
        LensAction("inspect", "\ud800")


@pytest.mark.parametrize("arguments", [
    {"group_by": "policy"}, {"group_by": []}, {"observation_order": "random"},
    {"columns": ("kind",) * 2}, {"columns": "kind"},
])
def test_UnsupportedPresentationSemanticsAreExplicitFailures(arguments):
    """Unknown grouping/order hints never silently select security-affecting behavior."""

    with pytest.raises(ValueError):
        LensPresentation(**arguments)


@pytest.mark.parametrize("state,query", [(None, None), (Model(), {}), (Model(), "all")])
def test_ProjectionRequiresActualTypedSnapshotAndQuery(state, query):
    """View clients cannot substitute a writable persona database or arbitrary executable query."""

    with pytest.raises(ValueError):
        ResolveLens("purple").Project(state, query)
