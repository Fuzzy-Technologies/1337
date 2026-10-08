# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic model identity, attribution, update, and local persistence boundaries."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from fuzzy1337 import model
from fuzzy1337.adapters import EvidenceReference
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


def Provenance(source_id: str = "native", run_reference: str = "run:one") -> ModelProvenance:
    """Build explicit synthetic acquisition context without resolving authorization."""

    return ModelProvenance(
        source_id, run_reference, "2026-10-05T23:00:00+03:00", "scope:local",
        "target:" + "a" * 64,
    )


def Host(address: str = "127.0.0.1") -> SecurityObject:
    """Build one attributable local host with a provider-independent identity."""

    return SecurityObject(
        ObjectIdentity("synthetic", ObjectKind.HOST, address), {"state": "up"}, (Provenance(),),
    )


def Store(tmp_path: Path) -> tuple[LocalModelStore, ModelState]:
    """Create a real isolated workspace and an independently owned empty model."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Synthetic model"), "synthetic")
    store = LocalModelStore(root)

    return store, store.Create()


@pytest.mark.parametrize("kind,left,right", [
    (ObjectKind.DOMAIN, "EXAMPLE.COM.", "example.com"),
    (ObjectKind.DOMAIN, "BÜCHER.example", "xn--bcher-kva.example"),
    (ObjectKind.HOST, "2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
])
def test_BuiltInIdentitiesNormalizeOffline(kind, left, right):
    """Repeated DNS/IP representations identify the same object without network access."""

    first = ObjectIdentity("synthetic", kind, left)
    second = ObjectIdentity("synthetic", kind, right)

    assert first == second, (
        'Equivalent built-in identities did not retain the same canonical reference'
    )
    assert first.Reference() == second.Reference(), (
        'Equivalent built-in identities did not retain the same canonical reference'
    )


@pytest.mark.parametrize("kind,key", [
    (ObjectKind.DOMAIN, "bad..example"), (ObjectKind.DOMAIN, "-bad.example"),
    (ObjectKind.DOMAIN, "has space.example"), (ObjectKind.DOMAIN, "a" * 64 + ".example"),
    (ObjectKind.DOMAIN, "."), (ObjectKind.DOMAIN, "a." * 128),
    (ObjectKind.HOST, "example.com"), (ObjectKind.HOST, "fe80::1%eth0"),
    (ObjectKind.HOST, "127.000.0.1"), (ObjectKind.ASSET, "a" * 4097),
    (ObjectKind.ASSET, "bad\nkey"), (ObjectKind.WORKSPACE, "another-workspace"),
    ("host", "127.0.0.1"),
])
def test_IdentityRejectsAmbiguousOrMalformedKeys(kind, key):
    """Fail closed rather than inventing identities from malformed or location-specific keys."""

    with pytest.raises(ValueError):
        ObjectIdentity("synthetic", kind, key)


@pytest.mark.parametrize("kind,key", [
    (ObjectKind.WORKSPACE, "synthetic"), (ObjectKind.SCOPE, "scope:local"),
    (ObjectKind.TARGET, "target:" + "a" * 64), (ObjectKind.ASSET, "inventory:synthetic"),
    (ObjectKind.PORT, "host:loopback/tcp/443"), (ObjectKind.SERVICE, "port:loopback/tcp/443"),
    (ObjectKind.ENDPOINT, "service:local/GET/health"),
    (ObjectKind.TECHNOLOGY, "service:local/product:synthetic"),
])
def test_TypedProjectionAndExtensionKeysRemainOpaque(kind, key):
    """Reference projections and generic asset identities reuse one schema without authorization."""

    identity = ObjectIdentity("synthetic", kind, key)
    entity = SecurityObject(identity, {"domain_profile": "extension-example"}, (Provenance(),))
    state, delta = ModelState("synthetic").Apply(objects=(entity,))

    assert identity.key == key, (
        'Typed projection round trip changed the key, query slice, or delta'
    )
    assert state.Objects(kind) == (entity,), (
        'Typed projection round trip changed the key, query slice, or delta'
    )
    assert entity.Reference() in delta.created, (
        'Typed projection round trip changed the key, query slice, or delta'
    )
    assert ModelState.FromDict(state.ToDict()) == state, (
        'Typed projection round trip changed the key, query slice, or delta'
    )


def test_ObjectsAndAttributesAreRecursivelyImmutable():
    """Caller mutations cannot change frozen identity, nested attributes, or attribution."""

    attributes = {"nested": {"values": [1, 2]}}
    entity = SecurityObject(Host().identity, attributes, [Provenance()])
    attributes["nested"]["values"].append(3)

    assert entity.attributes["nested"]["values"] == (1, 2), (
        'Caller mutation changed recursively frozen model attributes'
    )

    with pytest.raises(TypeError):
        entity.attributes["state"] = "changed"

    with pytest.raises(FrozenInstanceError):
        entity.identity = Host("127.0.0.2").identity


@pytest.mark.parametrize("attributes", [
    {"bad": float("nan")}, {"bad": float("inf")}, {"bad": object()},
    {"large": "a" * model.MAX_ATTRIBUTE_BYTES}, {"": 1}, [],
])
def test_ObjectRejectsUnboundedOrNonJsonAttributes(attributes):
    """No unsupported provider objects, non-standard numbers, or unbounded fields become state."""

    with pytest.raises(ValueError):
        SecurityObject(Host().identity, attributes, (Provenance(),))


def test_DeepAttributesAndSurrogateTextAreRejected():
    """Excessive nesting and invalid UTF-8 fail as validation errors before persistence."""

    nested = {}
    current = nested

    for _ in range(1200):
        current["next"] = {}
        current = current["next"]

    with pytest.raises(ValueError):
        model.ModelAttributes(nested)

    with pytest.raises(ValueError):
        model.CanonicalModelJson({"value": "\ud800"})


@pytest.mark.parametrize("field_name,value", [
    ("source_id", "UPPER"), ("run_reference", ""), ("observed_at", "2026-10-05T20:00:00"),
    ("scope_reference", "bad\nref"), ("target_reference", 4), ("provider_version", ""),
    ("execution", {}), ("evidence_references", "all"), ("evidence_references", [{}]),
])
def test_ProvenanceRejectsImplicitOrMalformedContext(field_name, value):
    """Attribution requires explicit typed references and offset-aware collection time."""

    with pytest.raises(ValueError):
        replace(Provenance(), **{field_name: value})


def test_EvidenceReferencesAreTypedCanonicalUniqueAndPreserved():
    """Model provenance retains evidence integrity metadata without claiming byte verification."""

    reference = EvidenceReference("raw", "artifacts/scan.xml", "a" * 64, "application/xml", 7)
    provenance = replace(Provenance(), evidence_references=(reference,))
    decoded = ModelProvenance.FromDict(model.JsonValue(provenance))

    assert decoded == provenance, (
        'Evidence metadata or UTC acquisition attribution changed during decoding'
    )
    assert provenance.observed_at == "2026-10-05T20:00:00.000000+00:00", (
        'Evidence metadata or UTC acquisition attribution changed during decoding'
    )

    with pytest.raises(ValueError):
        replace(provenance, evidence_references=(reference, reference))

    with pytest.raises(ValueError):
        replace(provenance, evidence_references=(replace(reference, locator="./scan.xml"),))


def test_UpdatesPreserveAttributableHistoryAndExactReplayIsIdempotent():
    """Current patches retain absent keys, old sources, and immutable prior observation values."""

    first, created = ModelState("synthetic").Apply(objects=(Host(),))
    patch = SecurityObject(
        Host().identity, {"state": "down", "reason": "synthetic"},
        (Provenance("sensor", "run:two"),),
    )
    updated, delta = first.Apply(objects=(patch,))
    replayed, replay_delta = updated.Apply(objects=(patch,))
    entity = updated.Objects(ObjectKind.HOST)[0]

    assert created.previous_revision == 0 and created.revision == 1, (
        'Model update lost patch history, provenance, or replay idempotency'
    )
    assert delta.previous_revision == 1 and delta.revision == 2, (
        'Model update lost patch history, provenance, or replay idempotency'
    )
    assert delta.updated == (Host().Reference(),), (
        'Model update lost patch history, provenance, or replay idempotency'
    )
    assert replayed == updated and replay_delta.created == replay_delta.updated == (), (
        'Model update lost patch history, provenance, or replay idempotency'
    )
    assert replay_delta.previous_revision == replay_delta.revision == 2, (
        'Model update lost patch history, provenance, or replay idempotency'
    )
    assert dict(entity.attributes) == {"state": "down", "reason": "synthetic"}, (
        'Model update lost patch history, provenance, or replay idempotency'
    )
    assert set(entity.provenance) == {Provenance(), Provenance("sensor", "run:two")}, (
        'Model update lost patch history, provenance, or replay idempotency'
    )
    assert {fact.attributes["state"] for fact in updated.observations} == {"up", "down"}, (
        'Model update lost patch history, provenance, or replay idempotency'
    )
    restored, _ = updated.Apply(objects=(replace(patch, attributes={"state": "up"}),))
    assert restored.objects[0].attributes["reason"] == "synthetic", (
        'Model update lost patch history, provenance, or replay idempotency'
    )


def test_NewAcquisitionOfSameLogicalObjectRetainsDistinctFacts():
    """Logical identity stays stable while separate acquisitions retain their own attribution."""

    first, _ = ModelState("synthetic").Apply(objects=(Host(),))
    second, delta = first.Apply(objects=(
        replace(Host(), provenance=(Provenance("native", "run:two"),)),
    ))

    assert len(second.objects) == 1 and len(second.observations) == 2, (
        'Fresh acquisition changed logical identity or discarded acquisition history'
    )
    assert second.objects[0].Reference() == first.objects[0].Reference(), (
        'Fresh acquisition changed logical identity or discarded acquisition history'
    )
    assert delta.updated == (Host().Reference(),), (
        'Fresh acquisition changed logical identity or discarded acquisition history'
    )


def test_RelationUpdatesUseStableIdentityAndObservationHistory():
    """One typed edge retains current attributes and both attributed patches across updates."""

    host = Host()
    port = SecurityObject(ObjectIdentity("synthetic", ObjectKind.PORT, "loopback/tcp/443"),
                          {"number": 443}, (Provenance(),))
    relation = Relation(RelationKind.HAS_PORT, host.Reference(), port.Reference(),
                        {"state": "reported"}, (Provenance(),))
    first, _ = ModelState("synthetic").Apply(objects=(host, port), relations=(relation,))
    patch = replace(relation, attributes={"state": "verified"},
                    provenance=(Provenance("native", "run:two"),))
    second, delta = first.Apply(relations=(patch,))
    replayed, _ = second.Apply(relations=(patch,))

    assert second.relations[0].Reference() == relation.Reference(), (
        'Typed relation update lost identity, provenance, or replay idempotency'
    )
    assert second.relations[0].attributes["state"] == "verified", (
        'Typed relation update lost identity, provenance, or replay idempotency'
    )
    assert len(second.relations[0].provenance) == 2, (
        'Typed relation update lost identity, provenance, or replay idempotency'
    )
    assert delta.updated == (relation.Reference(),), (
        'Typed relation update lost identity, provenance, or replay idempotency'
    )
    assert replayed == second, (
        'Typed relation update lost identity, provenance, or replay idempotency'
    )


@pytest.mark.parametrize("mutation", ["foreign", "duplicate", "dangling-edge", "dangling-fact"])
def test_SnapshotRejectsInconsistentReferencesAndWorkspaceOwnership(mutation):
    """A snapshot must be self-contained and cannot mix unrelated workspace object identities."""

    host = Host()
    objects = (host,)
    relations = ()
    observations = ()

    if mutation == "foreign":
        objects = (replace(host, identity=replace(host.identity, workspace_id="other")),)

    elif mutation == "duplicate":
        objects = (host, host)

    elif mutation == "dangling-edge":
        relations = (Relation(
            RelationKind.CONTAINS, host.Reference(), Host("127.0.0.2").Reference(),
            {}, (Provenance(),),
        ),)

    else:
        observations = (Observation("native", Host("127.0.0.2").Reference(), {}, Provenance()),)

    with pytest.raises(ValueError):
        ModelState("synthetic", objects=objects, relations=relations, observations=observations)


@pytest.mark.parametrize("operation", ["object", "relation", "observation"])
def test_ForcedDigestCollisionsAreNeverMerged(monkeypatch, operation):
    """Even an injected hash collision cannot silently conflate different immutable identities."""

    real_reference = model.ModelReference

    def CollidingReference(namespace, value):
        """Inject one namespace collision while retaining real references for the others."""

        if namespace == operation:
            return namespace + ":" + "a" * 64

        return real_reference(namespace, value)

    monkeypatch.setattr(model, "ModelReference", CollidingReference)

    with pytest.raises(ValueError, match="collision"):
        if operation == "object":
            ModelState("synthetic").Apply(objects=(Host(), Host("127.0.0.2")))

        elif operation == "relation":
            host, other = Host(), Host("127.0.0.2")
            left = Relation(RelationKind.CONTAINS, host.Reference(), other.Reference(),
                            {}, (Provenance(),))
            right = replace(left, kind=RelationKind.RELATED_TO)
            ModelState("synthetic").Apply(objects=(host, other), relations=(left, right))

        else:
            ModelState("synthetic").Apply(objects=(Host(), Host("127.0.0.2")))


@pytest.mark.parametrize("field_name,value", [
    ("workspace_id", "UPPER"), ("revision", True), ("objects", "objects"),
    ("objects", ({},)), ("relations", ({},)), ("observations", ({},)),
])
def test_RuntimeStateRejectsUntypedMetadata(field_name, value):
    """Immutable state rejects malformed fields before queries or updates can consume them."""

    with pytest.raises(ValueError):
        ModelState(**{"workspace_id": "synthetic", field_name: value})


@pytest.mark.parametrize("patches", [{"objects": ({},)}, {"relations": ({},)},
                                    {"observations": ({},)}, {"objects": "all"}])
def test_ApplyRejectsUntypedPatchesWithoutChangingOriginal(patches):
    """Malformed patch batches cannot partially mutate an existing immutable snapshot."""

    original = ModelState("synthetic")

    with pytest.raises(ValueError):
        original.Apply(**patches)

    assert original == ModelState("synthetic"), (
        'Rejected batch unexpectedly mutated the original model snapshot'
    )


def test_EmptyApplyAndTypedQueryAreDeterministic():
    """No-op updates leave revision unchanged and queries reject arbitrary filter strings."""

    original = ModelState("synthetic")
    state, delta = original.Apply()

    assert state == original and delta.created == delta.updated == (), (
        'Empty model transition changed revision, references, or query results'
    )
    assert state.Objects() == (), (
        'Empty model transition changed revision, references, or query results'
    )

    with pytest.raises(ValueError):
        state.Objects("host")


@pytest.mark.parametrize("mutation", [
    "unknown", "missing", "version", "boolean-version", "bad-object-reference",
    "unknown-kind", "missing-object-field", "unknown-provenance", "bad-evidence", "not-object",
])
def test_StrictSchemaRejectsCorruptionAndUnsupportedMetadata(mutation):
    """Decoded records must reproduce exact supported fields, types, and stored identity hashes."""

    state, _ = ModelState("synthetic").Apply(objects=(Host(),))
    document = state.ToDict()

    if mutation == "unknown":
        document["unknown"] = "not-supported"

    elif mutation == "missing":
        del document["revision"]

    elif mutation == "version":
        document["schema_version"] = 2

    elif mutation == "boolean-version":
        document["schema_version"] = True

    elif mutation == "bad-object-reference":
        document["objects"][0]["reference"] = "object:" + "f" * 64

    elif mutation == "unknown-kind":
        document["objects"][0]["identity"]["kind"] = "provider-truth"

    elif mutation == "missing-object-field":
        del document["objects"][0]["attributes"]

    elif mutation == "unknown-provenance":
        document["objects"][0]["provenance"][0]["unknown"] = "not-supported"

    elif mutation == "bad-evidence":
        document["objects"][0]["provenance"][0]["evidence_references"] = [{}]

    else:
        document = []

    with pytest.raises(ValueError):
        ModelState.FromDict(document)


def test_StoreUsesIndependentRevisionAndDoesNotChangeWorkspaceMetadata(tmp_path):
    """Model writes own their namespace and retain idempotent replay without another commit."""

    store, initial = Store(tmp_path)
    metadata = (store.root / "workspace.json").read_bytes()
    state, _ = initial.Apply(objects=(Host(),))
    committed = store.Save(state, expected_revision=0)

    assert committed == store.Open() == state, (
        'Model publication changed workspace metadata or failed to round trip'
    )
    assert store.Save(state, expected_revision=1) == state, (
        'Model publication changed workspace metadata or failed to round trip'
    )
    assert (store.root / "workspace.json").read_bytes() == metadata, (
        'Model publication changed workspace metadata or failed to round trip'
    )
    assert sorted(
        path.name for path in (store.root / "state" / "model").iterdir()
    ) == ["model.json"], (
        'Model publication changed workspace metadata or failed to round trip'
    )

    with pytest.raises(FileExistsError):
        store.Create()


@pytest.mark.parametrize("mutation", ["stale", "jump", "foreign", "unchanged-revision", "untyped"])
def test_StoreRejectsRevisionOrIdentityConflicts(tmp_path, mutation):
    """Cooperating writers cannot overwrite another revision or replace workspace identity."""

    store, initial = Store(tmp_path)
    state, _ = initial.Apply(objects=(Host(),))

    if mutation == "stale":
        store.Save(state, expected_revision=0)

    elif mutation == "jump":
        state = replace(state, revision=5)

    elif mutation == "foreign":
        state = ModelState("other", revision=1)

    elif mutation == "unchanged-revision":
        state = replace(state, revision=0)

    else:
        state = {}

    expected = ValueError if mutation == "untyped" else WorkspaceConflictError

    with pytest.raises(expected):
        store.Save(state, expected_revision=0)

    assert not (store.root / "state" / "model" / ".write-lock").exists(), (
        'Rejected save left an owned writer lock behind'
    )


def test_AbandonedLockIsNeverStolen(tmp_path):
    """An existing writer lock blocks save while leaving read-only state available."""

    store, initial = Store(tmp_path)
    lock = store.root / "state" / "model" / ".write-lock"
    lock.mkdir()
    state, _ = initial.Apply(objects=(Host(),))

    with pytest.raises(WorkspaceBusyError):
        store.Save(state, expected_revision=0)

    assert lock.is_dir() and store.Open() == initial, (
        'Save stole the existing writer lock or prevented reading committed state'
    )


@pytest.mark.parametrize("payload", [
    b"{", b"\xff", b'{"revision":0,"revision":0}', b'{"value":NaN}',
])
def test_OpenRejectsCorruptOrNonStandardJson(tmp_path, payload):
    """Duplicate keys, invalid encoding, and non-standard constants cannot become state."""

    store, _ = Store(tmp_path)
    (store.root / "state" / "model" / "model.json").write_bytes(payload)

    with pytest.raises(ValueError):
        store.Open()


def test_ReadAndWriteSizeBoundsAreExplicit(tmp_path, monkeypatch):
    """Both decode and publication reject oversized snapshots before accepting an unbounded file."""

    store, state = Store(tmp_path)
    monkeypatch.setattr(model, "MAX_MODEL_BYTES", 1)

    with pytest.raises(ValueError, match="size limit"):
        store.Open()

    with pytest.raises(ValueError, match="size limit"):
        store.WriteState(store.root / "state" / "model", state)


def test_OpenRejectsDifferentWorkspaceIdentity(tmp_path):
    """A portable snapshot cannot be transplanted into unrelated workspace metadata silently."""

    store, _ = Store(tmp_path)
    path = store.root / "state" / "model" / "model.json"
    path.write_text(json.dumps(ModelState("other").ToDict()), encoding="utf-8")

    with pytest.raises(ValueError, match="another workspace"):
        store.Open()


@pytest.mark.parametrize("entry", ["model", "model.json", ".write-lock"])
def test_PathBoundaryRejectsLinksBeforeReadingOrWriting(tmp_path, entry):
    """Observed model links are rejected without following their target."""

    store, _ = Store(tmp_path)
    directory = store.root / "state" / "model"
    path = directory if entry == "model" else directory / entry
    target = tmp_path / "unrelated"
    target.mkdir()

    if path.is_file():
        path.unlink()

    elif path.is_dir():
        (path / "model.json").unlink()
        path.rmdir()

    try:
        path.symlink_to(target, target_is_directory=True)

    except OSError:
        pytest.skip("Test platform does not permit creating symbolic links")

    with pytest.raises(ValueError, match="symlinks"):
        store.Open()


@pytest.mark.parametrize("entry", ["model", "model.json", ".write-lock"])
def test_PathBoundaryRejectsWrongFilesystemTypes(tmp_path, entry):
    """Namespace, authoritative document, and writer lock retain explicit directory/file types."""

    store, _ = Store(tmp_path)
    directory = store.root / "state" / "model"
    path = directory if entry == "model" else directory / entry

    if path.is_file():
        path.unlink()
        path.mkdir()

    elif path.is_dir():
        (path / "model.json").unlink()
        path.rmdir()
        path.write_text("not-a-directory", encoding="utf-8")

    else:
        path.write_text("not-a-directory", encoding="utf-8")

    with pytest.raises(ValueError, match="filesystem types"):
        store.Open()


def test_FailedReplacementCleansTemporaryFilesAndLock(tmp_path, monkeypatch):
    """A failed replacement leaves the old snapshot readable and temporary resources clean."""

    store, initial = Store(tmp_path)
    state, _ = initial.Apply(objects=(Host(),))

    def RejectReplacement(source, destination):
        """Inject a deterministic filesystem failure before authoritative replacement."""

        raise OSError("synthetic replacement failure")

    monkeypatch.setattr(model.os, "replace", RejectReplacement)

    with pytest.raises(OSError, match="synthetic replacement"):
        store.Save(state, expected_revision=0)

    assert store.Open() == initial, (
        'Precommit failure changed authoritative state or leaked temporary files'
    )
    assert sorted(
        path.name for path in (store.root / "state" / "model").iterdir()
    ) == ["model.json"], (
        'Precommit failure changed authoritative state or leaked temporary files'
    )


def test_PostCommitSyncFailureRequiresReopenBeforeRetry(tmp_path, monkeypatch):
    """A postcommit synchronization error requires reopening before retrying a stale revision."""

    store, initial = Store(tmp_path)
    state, _ = initial.Apply(objects=(Host(),))

    def RejectSync(path):
        """Inject a directory durability failure after the new document has replaced the old one."""

        raise OSError("synthetic synchronization failure")

    monkeypatch.setattr(model, "SyncStorageDirectory", RejectSync)

    with pytest.raises(OSError, match="synthetic synchronization"):
        store.Save(state, expected_revision=0)

    assert store.Open() == state, (
        'Postcommit failure did not expose the committed revision on reopen'
    )

    with pytest.raises(WorkspaceConflictError):
        store.Save(state, expected_revision=0)
