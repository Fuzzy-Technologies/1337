# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real SDK, evidence, workspace, and model persistence integration using local synthetic data."""

from __future__ import annotations

import os
import shutil
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterInvocation,
    AdapterReport,
    AdapterRequest,
    AdapterResult,
    ExecutionState,
    ImpactLevel,
    NormalizedFinding,
    NormalizedObservation,
    ObjectEnrichment,
    RelationEnrichment,
)
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Observation,
    Relation,
    RelationKind,
    SecurityObject,
)
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    WorkspaceBusyError,
    WorkspaceConfiguration,
    WorkspaceConflictError,
)


def Context(tmp_path: Path, outcome: ExecutionState = ExecutionState.SUCCEEDED):
    """Create real evidence and SDK envelopes while never invoking a scanner or external target."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Synthetic integration"), "synthetic")
    store = LocalModelStore(root)
    initial = store.Create()
    target_reference = "target:" + "a" * 64
    execution = AdapterExecution(outcome, 0 if outcome is ExecutionState.SUCCEEDED else 2, 0.1)
    evidence = LocalEvidenceStore(root / "evidence").Put(
        b'<synthetic><host address="127.0.0.1"/></synthetic>', "stdout", "application/xml",
        EvidenceProvenance(
            "synthetic", "scope:local", "synthetic-adapter", "1", "fixture-1",
            "2026-10-05T20:00:00+00:00", "2026-10-05T20:00:01+00:00", execution=execution,
        ),
    )
    invocation = AdapterInvocation(
        "synthetic-adapter",
        AdapterRequest("network-discovery", target_reference, ImpactLevel.SAFE),
        ("synthetic-provider", "127.0.0.1"), 5, "fixture-1",
    )
    report = AdapterReport(invocation, execution, (evidence.reference,))
    port_reference = target_reference + ":tcp:443"
    service_reference = port_reference + ":service"
    result = AdapterResult(
        report,
        observations=(NormalizedObservation("host-state", target_reference, {"state": "up"}),),
        findings=(NormalizedFinding("synthetic", target_reference, "Future finding owner"),),
        object_enrichments=(
            ObjectEnrichment("host", target_reference, {"address": "127.0.0.1", "state": "up"}),
            ObjectEnrichment("port", port_reference, {"protocol": "tcp", "number": 443}),
            ObjectEnrichment("service", service_reference, {"name": "https"}),
        ),
        relation_enrichments=(
            RelationEnrichment("has-port", target_reference, port_reference),
            RelationEnrichment("hosts-service", port_reference, service_reference),
        ),
    )
    bindings = {
        target_reference: ObjectIdentity("synthetic", ObjectKind.HOST, "127.0.0.1"),
        port_reference: ObjectIdentity("synthetic", ObjectKind.PORT, "host:127.0.0.1/tcp/443"),
        service_reference: ObjectIdentity(
            "synthetic", ObjectKind.SERVICE, "host:127.0.0.1/tcp/443",
        ),
    }
    provenance = ModelProvenance(
        "synthetic-adapter", evidence.evidence_id, "2026-10-05T20:00:01+00:00",
        "scope:local", target_reference, "fixture-1", (evidence.reference,), execution,
    )

    return store, initial, result, bindings, provenance


@pytest.mark.parametrize("outcome", [ExecutionState.SUCCEEDED, ExecutionState.FAILED])
def test_AdapterEvidenceAndPortableModelRoundTrip(tmp_path, outcome):
    """Existing SDK output updates one attributable model and survives a complete workspace move."""

    store, initial, result, bindings, provenance = Context(tmp_path, outcome)
    workspace_bytes = (store.root / "workspace.json").read_bytes()
    state, delta = initial.ApplyAdapterResult(result, bindings, provenance)
    store.Save(state, expected_revision=0)
    replayed, no_op = store.Open().ApplyAdapterResult(result, bindings, provenance)
    original_bytes = (store.root / "state" / "model" / "model.json").read_bytes()
    moved_root = tmp_path / "moved-workspace"
    shutil.move(str(store.root), moved_root)
    reopened = LocalModelStore(moved_root).Open()

    assert len(state.objects) == 3 and len(state.relations) == 2, (
        "SDK enrichments did not populate typed host, port, service, and relation records"
    )
    assert state == replayed == reopened and no_op.created == no_op.updated == (), (
        "Exact adapter replay or workspace relocation changed the authoritative model"
    )
    assert delta.previous_revision == 0 and delta.revision == 1, (
        "SDK batch did not produce exactly one incremental revision transition"
    )
    assert (moved_root / "workspace.json").read_bytes() == workspace_bytes, (
        "Model publication unexpectedly changed authoritative workspace metadata"
    )
    assert (moved_root / "state" / "model" / "model.json").read_bytes() == original_bytes, (
        "Relocation changed portable model snapshot bytes"
    )
    assert LocalEvidenceStore(moved_root / "evidence").Read(provenance.evidence_references[0]) == (
        b'<synthetic><host address="127.0.0.1"/></synthetic>'
    ), "Model provenance lost the portable verified raw evidence reference"
    assert all(item.provenance.execution.state is outcome for item in reopened.observations), (
        "Adapter model ingestion changed failed acquisition attribution into success"
    )
    assert result.findings[0].summary == "Future finding owner", (
        "Model ingestion modified findings belonging to the future finding subsystem"
    )


@pytest.mark.parametrize("field,value", [
    ("source_id", "other-adapter"), ("target_reference", "target:other"),
    ("provider_version", "another-version"), ("evidence_references", ()),
    ("execution", None),
])
def test_AdapterBoundaryRejectsMismatchedAttribution(tmp_path, field, value):
    """Caller attribution must match the executor-owned adapter, target, version, and evidence."""

    _, initial, result, bindings, provenance = Context(tmp_path)

    with pytest.raises(ValueError, match="provenance"):
        initial.ApplyAdapterResult(result, bindings, replace(provenance, **{field: value}))

    assert initial == ModelState("synthetic"), "Rejected attribution mutated the original model"


@pytest.mark.parametrize("mutation", [
    "missing-binding", "foreign-binding", "unknown-object-kind", "mismatched-kind",
    "unknown-relation-kind", "untyped-object", "untyped-observation", "untyped-relation",
    "untyped-report", "untyped-bindings", "untyped-provenance", "untyped-result",
])
def test_AdapterBoundaryRejectsUnsupportedOrUnresolvedEnvelopes(tmp_path, mutation):
    """Only explicitly mapped supported first-party identities can consume normalized SDK output."""

    _, initial, result, bindings, provenance = Context(tmp_path)
    host_reference = result.report.invocation.request.target_reference

    if mutation == "missing-binding":
        del bindings[host_reference]

    elif mutation == "foreign-binding":
        bindings[host_reference] = replace(bindings[host_reference], workspace_id="other")

    elif mutation == "unknown-object-kind":
        result = replace(result, object_enrichments=(
            ObjectEnrichment("provider-owned-host", host_reference),
        ))

    elif mutation == "mismatched-kind":
        result = replace(result, object_enrichments=(ObjectEnrichment("asset", host_reference),))

    elif mutation == "unknown-relation-kind":
        result = replace(result, relation_enrichments=(
            RelationEnrichment("unknown-edge", host_reference, host_reference),
        ))

    elif mutation == "untyped-object":
        result = replace(result, object_enrichments=({},))

    elif mutation == "untyped-observation":
        result = replace(result, observations=({},))

    elif mutation == "untyped-relation":
        result = replace(result, relation_enrichments=({},))

    elif mutation == "untyped-report":
        result = replace(result, report={})

    elif mutation == "untyped-bindings":
        bindings = []

    elif mutation == "untyped-provenance":
        provenance = {}

    else:
        result = {}

    with pytest.raises(ValueError):
        initial.ApplyAdapterResult(result, bindings, provenance)


@pytest.mark.parametrize("field", ["identity", "provenance", "kind", "source", "observation"])
def test_EntityConstructorsRejectUntypedOwnershipAndReferences(tmp_path, field):
    """Typed records reject malformed ownership and relation references before updates."""

    _, _, _, bindings, provenance = Context(tmp_path)
    identity = next(iter(bindings.values()))

    if field == "identity":
        with pytest.raises(ValueError):
            SecurityObject({}, {}, (provenance,))

    elif field == "provenance":
        with pytest.raises(ValueError):
            SecurityObject(identity, {}, ())

    elif field == "kind":
        with pytest.raises(ValueError):
            Relation("contains", identity.Reference(), identity.Reference(), {}, (provenance,))

    elif field == "source":
        with pytest.raises(ValueError):
            Relation(RelationKind.CONTAINS, "relation:" + "a" * 64,
                     identity.Reference(), {}, (provenance,))

    else:
        with pytest.raises(ValueError):
            Observation("native", identity.Reference(), {}, {})


def test_CooperatingModelWritersCannotLoseUpdates(tmp_path):
    """Independent stores race from one revision and permit only one complete publication."""

    store, initial, _, bindings, provenance = Context(tmp_path)
    barrier = Barrier(2)
    proposals = [initial.Apply(objects=(SecurityObject(
        identity, {"writer": index}, (provenance,),
    ),))[0] for index, identity in enumerate(list(bindings.values())[:2])]

    def Publish(state):
        """Race one real model save and expose accepted or explicitly denied writer ownership."""

        barrier.wait(timeout=5)

        try:
            return LocalModelStore(store.root).Save(state, expected_revision=0)

        except (WorkspaceBusyError, WorkspaceConflictError) as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(Publish, proposals))

    assert sum(isinstance(outcome, ModelState) for outcome in outcomes) == 1, (
        "Competing writers both committed from one expected revision"
    )
    assert store.Open() in proposals, "Concurrent publication produced a partial or mixed snapshot"
    assert not (store.root / "state" / "model" / ".write-lock").exists(), (
        "Cooperating writers leaked the namespace ownership lock"
    )


def test_HardLinkedAuthoritativeRecordIsRejected(tmp_path):
    """An authoritative document cannot alias another file outside its owned namespace."""

    store, _, _, _, _ = Context(tmp_path)
    document = store.root / "state" / "model" / "model.json"
    outside = tmp_path / "unrelated-model.json"

    try:
        os.link(document, outside)

    except OSError:
        pytest.skip("Test platform does not permit creating hard links")

    with pytest.raises(ValueError, match="hard linked"):
        store.Open()


def test_AbsentRebuildableDirectoriesDoNotAffectModelOpening(tmp_path):
    """Canonical model data remains usable when disposable cache/index directories disappear."""

    store, initial, _, _, _ = Context(tmp_path)
    (store.root / "cache").rmdir()
    (store.root / "indexes").rmdir()

    assert store.Open() == initial, "Model opening incorrectly required disposable cache or indexes"


def test_ProviderReferenceChangesNeverCreateAnotherAuthoritativeObjectModel(tmp_path):
    """Providers with different references enrich the same attributed logical objects."""

    _, initial, first_result, first_bindings, first_provenance = Context(tmp_path)
    state, _ = initial.ApplyAdapterResult(first_result, first_bindings, first_provenance)
    rewritten = {reference: "other-provider:" + reference for reference in first_bindings}
    second_result = replace(
        first_result,
        report=replace(first_result.report, invocation=replace(
            first_result.report.invocation, adapter_id="other-provider",
            provider_version="fixture-2",
        )),
        observations=tuple(replace(item, subject_reference=rewritten[item.subject_reference])
                           for item in first_result.observations),
        object_enrichments=tuple(replace(item, object_reference=rewritten[item.object_reference])
                                for item in first_result.object_enrichments),
        relation_enrichments=tuple(replace(
            item, source_reference=rewritten[item.source_reference],
            target_reference=rewritten[item.target_reference],
        ) for item in first_result.relation_enrichments),
    )
    second_bindings = {rewritten[key]: identity for key, identity in first_bindings.items()}
    second_provenance = replace(first_provenance, source_id="other-provider",
                                run_reference="run:second-provider", provider_version="fixture-2")
    enriched, _ = state.ApplyAdapterResult(second_result, second_bindings, second_provenance)

    assert [item.Reference() for item in enriched.objects] == [
        item.Reference() for item in state.objects
    ], "Provider-specific reference spelling created different authoritative object identities"
    assert [item.Reference() for item in enriched.relations] == [
        item.Reference() for item in state.relations
    ], "Provider-specific reference spelling created different authoritative edge identities"
    assert all({source.source_id for source in item.provenance} == {
        "synthetic-adapter", "other-provider",
    } for item in enriched.objects), "Second provider enrichment lost one provider's attribution"
