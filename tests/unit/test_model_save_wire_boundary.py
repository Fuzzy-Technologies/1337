# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""The model store must publish only snapshots its own strict reader can reopen."""

import json
from dataclasses import dataclass, field, fields, make_dataclass, replace
from pathlib import Path

import pytest

from fuzzy1337 import model
from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.model import (
    CanonicalModelJson,
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
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration


def Subtype(record, *, extra=False):
    """Model an ordinary SDK consumer subclass without changing first-party source."""

    additions = [("unversioned", list[str], field(default_factory=list))] if extra else []
    extended = make_dataclass(
        "ConsumerRecord", additions, bases=(type(record),), frozen=True, slots=True,
    )
    values = {item.name: getattr(record, item.name) for item in fields(record) if item.init}

    if extra:
        values["unversioned"] = ["retained"]

    return extended(**values)


def Proposal(selected=None, *, extra=False):
    """Build one real Apply transition and optionally vary one typed wire boundary."""

    def Select(role, record):
        """Keep every unselected first-party record unchanged."""

        return Subtype(record, extra=extra) if role == selected else record

    execution = Select("execution", AdapterExecution(ExecutionState.FAILED, 7, 0.125))
    provenance = Select("provenance", ModelProvenance(
        "fixture", "run:saved", "2026-11-25T12:00:00+00:00",
        "scope:fixture", "target:" + "a" * 64, execution=execution,
    ))
    identity = Select("identity", ObjectIdentity("fixture", ObjectKind.HOST, "127.0.0.1"))
    first = Select("object", SecurityObject(identity, {"saved": [1, 2]}, (provenance,)))
    second = SecurityObject(
        ObjectIdentity("fixture", ObjectKind.HOST, "127.0.0.2"), {}, (provenance,),
    )
    relation = Select("relation", Relation(
        RelationKind.RELATED_TO, first.Reference(), second.Reference(), {}, (provenance,),
    ))
    observation = Select("observation", Observation(
        "saved.note", first.Reference(), {"retained": True}, provenance,
    ))
    state, _ = ModelState("fixture").Apply(
        objects=(first, second), relations=(relation,), observations=(observation,),
    )

    return Select("state", state)


def Store(root):
    """Initialize the supported local workspace and model owners for an external consumer."""

    workspace = root / "workspace"
    LocalWorkspaceStore(workspace).Create(WorkspaceConfiguration("Saved fixture"), "fixture")
    store = LocalModelStore(workspace)
    initial = store.Create()

    return store, initial


def StoredBytes(root):
    """Compare all owned files, including workspace metadata, across a refused save."""

    return {
        item.relative_to(root).as_posix(): item.read_bytes()
        for item in root.rglob("*") if item.is_file()
    }


@pytest.mark.parametrize("selected", [
    "object", "identity", "provenance", "execution", "relation", "observation",
])
def test_SaveRefusesUnsupportedWireBeforeLockOrPublication(tmp_path, monkeypatch, selected):
    """Previously admitted DTO extensions could leave a successfully saved unreadable model."""

    store, initial = Store(tmp_path)
    proposal = Proposal(selected, extra=True)
    document = proposal.ToDict()

    with pytest.raises(ValueError):
        ModelState.FromDict(document)

    before = StoredBytes(store.root)

    def DeniedPaths(owner):
        """Expose any writer-path admission before unsupported wire has been refused."""

        raise AssertionError("Unsupported wire must fail before writer-path validation")

    with monkeypatch.context() as guard:
        guard.setattr(LocalModelStore, "ValidatePaths", DeniedPaths)

        with pytest.raises(ValueError):
            store.Save(proposal, expected_revision=initial.revision)

    assert StoredBytes(store.root) == before, "A refused wire shape must preserve every stored byte"
    assert not (store.root / "state/model/.write-lock").exists(), (
        "Wire admission must fail before acquiring a durable writer lock"
    )
    assert store.Open() == initial, "The prior authoritative snapshot must remain readable"


@pytest.mark.parametrize("selected", [
    None, "state", "object", "identity", "provenance", "execution", "relation", "observation",
])
def test_SavePreservesConcreteAndCompatibleInheritedWire(tmp_path, selected):
    """Correct version-one bytes remain accepted without a blanket Python subclass restriction."""

    store, _ = Store(tmp_path)
    proposal = Proposal(selected)
    expected = CanonicalModelJson(proposal.ToDict()) + b"\n"
    committed = store.Save(proposal, expected_revision=0)
    path = store.root / "state/model/model.json"

    assert path.read_bytes() == expected, "Retain exact compatible canonical wire bytes"
    assert store.Open() == committed, "Every successfully published snapshot must reopen"
    assert CanonicalModelJson(committed.ToDict()) + b"\n" == expected, (
        "Decoding a compatible Python shape must not lose wire facts"
    )
    assert committed.objects[0].provenance[0].execution.state is ExecutionState.FAILED, (
        "Wire admission must preserve the original failed execution attribution"
    )
    assert store.Save(proposal, expected_revision=1) == committed, (
        "Exact wire replay through a compatible caller must remain idempotent"
    )
    assert path.read_bytes() == expected, "Replay must leave original stored bytes intact"

    if selected is None:
        assert committed == proposal, "Ordinary concrete SDK callers must preserve DTO equality"


def test_AtypicalSizeRefusalPrecedesDeepDecodeAndWriterLock(tmp_path, monkeypatch):
    """The existing serialized limit bounds atypical input before constructing another snapshot."""

    store, initial = Store(tmp_path)
    proposal = Proposal("state")
    before = StoredBytes(store.root)

    def Denied(cls, document):
        """Expose an unexpected deep decode after the document already exceeds its size bound."""

        raise AssertionError("Oversized atypical wire must fail before constructing another model")

    with monkeypatch.context() as guard:
        guard.setattr(model, "MAX_MODEL_BYTES", 32)
        guard.setattr(ModelState, "FromDict", classmethod(Denied))

        with pytest.raises(ValueError, match="size limit"):
            store.Save(proposal, expected_revision=0)

    assert StoredBytes(store.root) == before, "Oversized input must leave no durable change"
    assert not (store.root / "state/model/.write-lock").exists(), (
        "Do not lock refused oversized data"
    )
    assert store.Open() == initial, "A size refusal must preserve the previous readable snapshot"


def test_OrdinaryLargeSaveValidatesProposedBytesWithOneSerialization(tmp_path, monkeypatch):
    """A normal save performs the extra wire decode honestly without serializing twice."""

    store, _ = Store(tmp_path)
    provenance = ModelProvenance(
        "fixture", "run:saved", "2026-11-25T12:00:00+00:00",
        "scope:fixture", "target:" + "a" * 64,
    )
    objects = tuple(SecurityObject(
        ObjectIdentity("fixture", ObjectKind.ASSET, f"retained:{index}"),
        {"saved": [index, "unchanged"]}, (provenance,),
    ) for index in range(256))
    proposal, _ = ModelState("fixture").Apply(objects=objects)
    originalDecode = ModelState.FromDict
    originalDict = ModelState.ToDict
    calls = {"decode": 0, "serialize": 0}

    def Decode(cls, document):
        """Count both the proposed wire admission and current authoritative snapshot read."""

        calls["decode"] += 1

        return originalDecode(document)

    def ToDict(state):
        """Count complete snapshot dictionary construction on the write path."""

        calls["serialize"] += 1

        return originalDict(state)

    with monkeypatch.context() as guard:
        guard.setattr(ModelState, "FromDict", classmethod(Decode))
        guard.setattr(ModelState, "ToDict", ToDict)
        committed = store.Save(proposal, expected_revision=0)

    assert calls == {"decode": 2, "serialize": 1}, (
        "Count proposed/current decodes and exactly one payload serialization"
    )
    assert len(committed.objects) == 256 and store.Open() == committed, (
        "The normal saved fixture must retain all records and reopen"
    )


def test_PreviousGoldenModelBytesReopenReplayAndAdvance(tmp_path):
    """A real prior report's schema-one model remains compatible with the durable owner."""

    fixture = Path(__file__).resolve().parents[1] / "contract/fixtures/reporting/snapshot.json"
    original = fixture.read_bytes()
    document = json.loads(original)["model"]
    workspace = tmp_path / "previous-workspace"
    LocalWorkspaceStore(workspace).Create(
        WorkspaceConfiguration("Previous retained model"), document["workspace_id"],
    )
    store = LocalModelStore(workspace)
    store.Create()
    path = workspace / "state/model/model.json"
    payload = CanonicalModelJson(document) + b"\n"
    path.write_bytes(payload)
    opened = store.Open()
    before = StoredBytes(workspace)

    assert opened.ToDict() == document, "The previously shipped model fixture must decode unchanged"
    assert store.Save(opened, expected_revision=opened.revision) == opened, (
        "Replaying a prior valid file must remain a no-op"
    )
    assert StoredBytes(workspace) == before, "A prior file replay must preserve all original bytes"
    patch = SecurityObject(
        ObjectIdentity(opened.workspace_id, ObjectKind.ASSET, "saved:roundtrip"),
        {"retained": True}, (opened.objects[0].provenance[0],),
    )
    advanced, delta = opened.Apply(objects=(patch,))
    committed = store.Save(advanced, expected_revision=delta.previous_revision)

    assert store.Open() == committed == advanced, "The prior file must support an SDK update"
    assert fixture.read_bytes() == original, "Do not rewrite the original compatibility fixture"


@dataclass(frozen=True)
class TaggedText(str):
    """Expose the actual dataclass-before-scalar behavior in the existing JSON renderer."""

    note: str = "tag"


@dataclass(frozen=True)
class TaggedNumber(float):
    """Retain a valid numeric runtime value with additional dataclass wire fields."""

    note: str = "tag"


@dataclass(frozen=True)
class TaggedInteger(int):
    """Retain a valid integer runtime value with additional dataclass wire fields."""

    note: str = "tag"


class PlainText(str):
    """Keep the ordinary JSON string behavior of an unextended scalar subclass."""


class PlainNumber(float):
    """Keep the ordinary JSON numeric behavior of an unextended scalar subclass."""


class PlainInteger(int):
    """Keep the ordinary JSON integer behavior of an unextended scalar subclass."""


def ScalarProposal(selected, *, tagged=True):
    """Supply scalar subclasses through existing concrete first-party DTO constructors."""

    text = TaggedText if tagged else PlainText
    number = TaggedNumber if tagged else PlainNumber
    integer = TaggedInteger if tagged else PlainInteger
    workspaceId = text("fixture") if selected in ("workspace", "inherited-workspace") else "fixture"
    duration = number(0.125) if selected == "duration" else 0.125
    exitCode = integer(7) if selected == "exit-code" else 7
    sourceId = text("fixture") if selected == "source" else "fixture"
    provider = text("fixture-v1") if selected == "provider" else "fixture-v1"
    identityWorkspace = text("fixture") if selected == "identity-workspace" else "fixture"
    key = text("saved:owned") if selected == "identity-key" else "saved:owned"
    provenance = ModelProvenance(
        sourceId, "run:saved", "2026-11-25T12:00:00Z", "scope:fixture", "target:owned",
        provider, execution=AdapterExecution(ExecutionState.FAILED, exitCode, duration),
    )
    attributes = {"retained": text("value")} if selected == "attribute" else {"retained": True}
    entity = SecurityObject(
        ObjectIdentity(identityWorkspace, ObjectKind.ASSET, key), attributes, (provenance,),
    )
    kind = text("saved.note") if selected == "observation-kind" else "saved.note"
    note = Observation(kind, entity.Reference(), {}, provenance)
    proposal, _ = ModelState(workspaceId).Apply(objects=(entity,), observations=(note,))

    if selected == "revision":
        proposal = replace(proposal, revision=integer(1))

    if selected == "inherited-workspace":
        proposal = Subtype(proposal)

    return proposal


@pytest.mark.parametrize("selected", [
    "workspace", "inherited-workspace", "duration", "revision", "exit-code",
    "source", "provider", "identity-workspace", "identity-key", "observation-kind",
])
def test_SerializedScalarShapeIsRefusedBeforeWriterPaths(tmp_path, monkeypatch, selected):
    """Exact DTOs can contain dataclass scalars whose final JSON is not the runtime scalar."""

    store, initial = Store(tmp_path)
    proposal = ScalarProposal(selected)
    before = StoredBytes(store.root)

    def DeniedPaths(owner):
        """Prove that final wire admission precedes filesystem writer preparation."""

        raise AssertionError("Unsupported serialized scalar shapes must fail before writer paths")

    with monkeypatch.context() as guard:
        guard.setattr(LocalModelStore, "ValidatePaths", DeniedPaths)

        with pytest.raises(ValueError):
            store.Save(proposal, expected_revision=0)

    assert StoredBytes(store.root) == before, "A rejected scalar wire shape must preserve all files"
    assert store.Open() == initial, "The prior snapshot must remain readable after scalar refusal"


@pytest.mark.parametrize("selected", [
    "workspace", "inherited-workspace", "duration", "revision", "exit-code",
    "source", "provider", "identity-workspace", "identity-key", "observation-kind",
])
def test_UnextendedScalarSubclassesPreserveTheirActualWire(tmp_path, selected):
    """A correct scalar JSON representation remains supported without a Python subclass ban."""

    store, _ = Store(tmp_path)
    proposal = ScalarProposal(selected, tagged=False)
    expected = CanonicalModelJson(proposal.ToDict()) + b"\n"
    committed = store.Save(proposal, expected_revision=0)

    assert (store.root / "state/model/model.json").read_bytes() == expected, (
        "A compatible scalar subclass must retain its original canonical JSON bytes"
    )
    assert store.Open() == committed, "The returned concrete snapshot must equal the actual reader"
    assert store.Save(proposal, expected_revision=1) == committed, (
        "Compatible scalar wire replay must remain idempotent"
    )


def test_ReadableAttributeWireReturnsTheActuallyPersistedTypedSnapshot(tmp_path):
    """A dataclass scalar inside JSON attributes may encode a valid object rather than a string."""

    store, _ = Store(tmp_path)
    proposal = ScalarProposal("attribute")
    expected = CanonicalModelJson(proposal.ToDict()) + b"\n"
    committed = store.Save(proposal, expected_revision=0)

    assert (store.root / "state/model/model.json").read_bytes() == expected, (
        "Readable attribute wire must be published unchanged rather than guessed from runtime types"
    )
    assert committed == store.Open(), "Return the same typed snapshot the persisted bytes decode"
    assert committed.objects[0].attributes["retained"] == {"note": "value"}, (
        "The result must describe the original serializer's actual object representation"
    )
    assert isinstance(proposal.objects[0].attributes["retained"], TaggedText), (
        "Byte admission must not rewrite the caller's original Python snapshot"
    )


@dataclass(frozen=True)
class TaggedKey(str):
    """Keep distinct Python mapping keys with the same actual JSON string spelling."""

    value: str
    token: int

    def __new__(cls, value, token):
        """Construct the ordinary string value while retaining separate dataclass identity."""

        return str.__new__(cls, value)


def test_FinalByteDecoderRejectsDuplicateSerializedKeysBeforePublication(tmp_path, monkeypatch):
    """Distinct accepted Python keys must not become an unreadable duplicate-key JSON document."""

    store, initial = Store(tmp_path)
    first = TaggedKey("duplicate", 1)
    second = TaggedKey("duplicate", 2)
    provenance = ModelProvenance(
        "fixture", "run:saved", "2026-11-25T12:00:00Z", "scope:fixture", "target:owned",
    )
    entity = SecurityObject(
        ObjectIdentity("fixture", ObjectKind.ASSET, "saved:duplicate-keys"),
        {first: 1, second: 2}, (provenance,),
    )
    proposal, _ = ModelState("fixture").Apply(objects=(entity,))
    before = StoredBytes(store.root)
    assert len(entity.attributes) == 2, "The control must retain two distinct original Python keys"

    def DeniedPaths(owner):
        """Expose writer preparation before duplicate serialized-key refusal."""

        raise AssertionError("Duplicate final wire keys must fail before writer paths")

    with monkeypatch.context() as guard:
        guard.setattr(LocalModelStore, "ValidatePaths", DeniedPaths)

        with pytest.raises(ValueError, match="duplicate"):
            store.Save(proposal, expected_revision=0)

    assert StoredBytes(store.root) == before, "Duplicate wire keys must preserve all original files"
    assert store.Open() == initial, "The prior snapshot must survive duplicate refusal"
