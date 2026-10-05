# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Strict portable model schemas, typed relations, and attributable snapshot contracts."""

from __future__ import annotations

from dataclasses import replace

import pytest

from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.model import (
    CanonicalModelJson,
    ModelDelta,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Relation,
    RelationKind,
    SecurityObject,
)


def State() -> ModelState:
    """Build a shared synthetic model carrying typed projections and one attributed relation."""

    provenance = ModelProvenance(
        "native", "run:one", "2026-10-05T20:00:00+00:00", "scope:local", "target:" + "a" * 64,
    )
    host = SecurityObject(ObjectIdentity("synthetic", ObjectKind.HOST, "127.0.0.1"),
                          {"state": "up"}, (provenance,))
    port = SecurityObject(ObjectIdentity("synthetic", ObjectKind.PORT, "loopback/tcp/443"),
                          {"number": 443}, (provenance,))
    relation = Relation(RelationKind.HAS_PORT, host.Reference(), port.Reference(),
                        {"confidence": "reported"}, (provenance,))
    state, _ = ModelState("synthetic").Apply(objects=(host, port), relations=(relation,))

    return state


def test_SnapshotSchemaRoundTripsRelationsAndObservationHistory():
    """Portable schema v1 reproduces all identities, typed edges, and acquisition observations."""

    state = State()
    document = state.ToDict()

    assert set(document) == {
        "schema_version", "workspace_id", "revision", "objects", "relations", "observations",
    }, "Model schema v1 changed its exact top-level boundary"
    assert ModelState.FromDict(document) == state, (
        "Model round trip lost typed relations or history"
    )
    reencoded = CanonicalModelJson(ModelState.FromDict(document).ToDict())

    assert reencoded == CanonicalModelJson(document), (
        "Canonical snapshot bytes changed during a validated round trip"
    )


@pytest.mark.parametrize("collection,field,value", [
    ("relations", "reference", "relation:" + "f" * 64),
    ("relations", "kind", "unknown-provider-edge"),
    ("relations", "source_reference", "object:" + "f" * 64),
    ("observations", "reference", "observation:" + "f" * 64),
    ("observations", "kind", "UPPER"),
    ("observations", "subject_reference", "object:" + "f" * 64),
    ("observations", "attributes", {"nonfinite": float("nan")}),
])
def test_SchemaRejectsUnsupportedTypesAndTamperedContentAddresses(collection, field, value):
    """Changing stored identity or observation content cannot retain the original trusted digest."""

    document = State().ToDict()
    document[collection][0][field] = value

    with pytest.raises(ValueError):
        ModelState.FromDict(document)


@pytest.mark.parametrize("outcome,exit_code", [
    (ExecutionState.SUCCEEDED, 0), (ExecutionState.FAILED, 2),
    (ExecutionState.TIMED_OUT, None), (ExecutionState.CANCELLED, None),
])
def test_ProvenanceRetainsExactTerminalExecutionStates(outcome, exit_code):
    """Failed, timed-out, and cancelled acquisition attribution never changes into success."""

    provenance = replace(State().objects[0].provenance[0],
                         execution=AdapterExecution(outcome, exit_code, 1.25))
    decoded = ModelProvenance.FromDict({
        "source_id": provenance.source_id, "run_reference": provenance.run_reference,
        "observed_at": provenance.observed_at, "scope_reference": provenance.scope_reference,
        "target_reference": provenance.target_reference, "provider_version": None,
        "evidence_references": [],
        "execution": {"state": outcome.value, "exit_code": exit_code, "duration_seconds": 1.25},
    })

    assert decoded == provenance, (
        "Provenance decoding changed the actual terminal execution outcome"
    )


@pytest.mark.parametrize("field,value", [
    ("duration_seconds", True), ("duration_seconds", "1.0"),
    ("duration_seconds", float("nan")), ("exit_code", True),
    ("exit_code", "0"), ("state", "unknown"),
])
def test_ExecutionMetadataRejectsCoercionAndNonstandardValues(field, value):
    """Portable provenance never coerces invalid execution metadata into successful evidence."""

    provenance = {
        "source_id": "native", "run_reference": "run:one",
        "observed_at": "2026-10-05T20:00:00+00:00", "scope_reference": "scope:local",
        "target_reference": "target:" + "a" * 64, "provider_version": None,
        "evidence_references": [],
        "execution": {"state": "succeeded", "exit_code": 0, "duration_seconds": 1.0},
    }
    provenance["execution"][field] = value

    with pytest.raises(ValueError):
        ModelProvenance.FromDict(provenance)


def test_RuntimeExecutionMetadataCannotProduceAnUnreadableSnapshot():
    """Reject duration booleans before they can create an unreadable persisted snapshot."""

    with pytest.raises(ValueError, match="booleans"):
        replace(State().objects[0].provenance[0],
                execution=AdapterExecution(ExecutionState.SUCCEEDED, 0, True))


@pytest.mark.parametrize("arguments", [
    {"previous_revision": 0, "revision": 2},
    {"previous_revision": True, "revision": 0},
    {"previous_revision": 0, "revision": 0, "created": ("object:" + "a" * 64,)},
    {"previous_revision": 0, "revision": 1, "created": ("bad-reference",)},
    {"previous_revision": 0, "revision": 1, "created": ("object:" + "a" * 64,) * 2},
    {"previous_revision": 0, "revision": 1, "created": ("object:" + "a" * 64,),
     "updated": ("object:" + "a" * 64,)},
])
def test_DeltasRequireUniqueCanonicalReferencesAndOneTransition(arguments):
    """Incremental consumers receive immutable, disjoint changes for one transition."""

    with pytest.raises(ValueError):
        ModelDelta(**arguments)
