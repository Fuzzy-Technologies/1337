# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Local graph admission, pure transformation and original-source failure boundaries."""

from __future__ import annotations

import json
import socket
import subprocess
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from traceback import format_exception

import pytest

from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.evidence import (
    EvidenceError,
    EvidenceIntegrityError,
    EvidenceProvenance,
    LocalEvidenceStore,
)
from fuzzy1337.findings import Findings
from fuzzy1337.images import ImageIdentity
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelProvenance
from fuzzy1337.sbom_graph import ApplyVerifiedSpdxGraph, GraphCandidates
from fuzzy1337.sbom_spdx import ApplyVerifiedSpdx
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

ROOT = Path(__file__).resolve().parents[2]
IMAGE = ImageIdentity("sha256:" + "a" * 64)


def Document():
    """Read independently handwritten original source, never an importer-generated graph."""

    return json.loads((ROOT / "tests/contract/fixtures/spdx.graph.v2.3.json").read_bytes())


@pytest.fixture
def context(tmp_path):
    """Create isolated real owned evidence and canonical model stores."""

    root = tmp_path / "ws"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned local graph"), "graph-unit")

    return root, LocalModelStore(root).Create(), LocalEvidenceStore(root / "evidence")


def Acquired(context, payload=None, *, source_changes=None):
    """Preserve original offline bytes and independent acquisition manifest before importing."""

    _, state, store = context
    source = EvidenceProvenance(state.workspace_id, "scope:owned", "inventory.spdx", "1", "owned-1",
                               "2026-10-14T00:00:00Z", "2026-10-14T00:00:01Z")

    if source_changes:
        source = replace(source, **source_changes)

    payload = Document() if payload is None else payload
    raw = payload if isinstance(payload, bytes) else CanonicalModelJson(payload)
    record = store.Put(raw, "sbom", "application/json", source)
    provenance = ModelProvenance(source.source_id, "run:graph", source.finished_at,
        source.scope_reference, "target:owned", source.tool_version, (record.reference,))

    return record, provenance


def Import(context, document=None, *, image=IMAGE):
    """Exercise the supported verified graph interface on owned original inputs."""

    root, initial, _ = context
    record, provenance = Acquired(context, document)

    return ApplyVerifiedSpdxGraph(initial, record, provenance, image, root)


def test_GraphOptInRetainsDirectEdgesAliasesLicensesAndFlatRejection(context):
    """Nested containment and dependency cycles are admitted only through the explicit profile."""

    root, initial, store = context
    record, provenance = Acquired(context)
    state, delta = ApplyVerifiedSpdxGraph(initial, record, provenance, IMAGE, root)
    assert delta.revision == initial.revision + 1, "Graph was not one atomic model transition"
    packages = [item for item in state.objects if item.attributes["asset_type"] == "package"]
    assert len(packages) == 3, "Source PURL aliases created competing package assets"
    claims = [item for item in state.observations if item.kind == "spdx-relationship-claim"]
    assert len(claims) == 9, "Original source edge coordinates were omitted or fabricated"
    assert len([item for item in state.relations if item.kind.value == "contains"]) == 4, (
        "Nested containment was flattened or canonical duplicate claims were not correlated"
    )
    assert len([item for item in state.relations
                if item.attributes.get("association") == "spdx-dependency-claim"]) == 3, (
        "Dependency cycle or distinct source aliases changed canonical dependency relation count"
    )
    facts = {item.attributes["spdx_id"]: item.attributes for item in state.observations
             if item.kind == "spdx-package-license"}
    assert facts["SPDXRef-App"]["declared"]["state"] == "none", "NONE became a named license"
    assert facts["SPDXRef-App"]["concluded"]["state"] == "noassertion", "Unknown role was lost"
    assert facts["SPDXRef-Lib-Alias"]["declared"]["state"] == "absent", "Absent fact was invented"
    assert facts["SPDXRef-Lib"]["concluded"]["expression"] == "Apache-2.0", (
        "Concluded expression was conflated with declaration"
    )
    assert not Findings(state), "Dependency or license facts invented a vulnerability finding"
    assert store.Read(record.reference) == CanonicalModelJson(Document()), "Original bytes changed"
    assert b"SYNTHETIC_PRIVATE_MARKER" not in CanonicalModelJson(state.ToDict()), (
        "Raw-only source values escaped normalization"
    )
    replayed, replay_delta = ApplyVerifiedSpdxGraph(state, record, provenance, IMAGE, root)
    assert replayed == state and not replay_delta.created and not replay_delta.updated, (
        "Exact graph replay changed canonical state"
    )

    with pytest.raises(ValueError):
        ApplyVerifiedSpdx(initial, record, provenance, IMAGE, root)


@pytest.mark.parametrize("change", [
    {"spdxVersion": "SPDX-3.0"}, {"packages": []},
    {"documentDescribes": ["SPDXRef-App"]},
    {"documentDescribes": ["SPDXRef-Image", "SPDXRef-Image"]},
    {"relationships": []}, {"relationships": False},
])
def test_GraphEnvelopeAndRootFailuresAreAtomic(context, change):
    """Unsupported roots and graph envelopes never save partial interpretations."""

    root, initial, _ = context
    source = Document()
    source.update(change)

    with pytest.raises(ValueError):
        Import(context, source)

    assert LocalModelStore(root).Open() == initial, "Rejected graph changed saved basis"


@pytest.mark.parametrize("field", [
    "files", "snippets", "annotations", "externalDocumentRefs", "hasExtractedLicensingInfos",
    "signatures", "vulnerabilities", "vex",
])
@pytest.mark.parametrize("location", ["document", "package"])
def test_SemanticGraphsStillRequireSeparateOwners(context, field, location):
    """Opting in to local package edges does not weaken unsupported semantic graph guards."""

    source = Document()
    row = source if location == "document" else source["packages"][1]
    row[field] = [{"private": "SYNTHETIC_PRIVATE_MARKER"}]

    with pytest.raises(ValueError):
        Import(context, source)


@pytest.mark.parametrize("change", [
    {"SPDXID": "SPDXRef-DOCUMENT"}, {"SPDXID": "DocumentRef-other:SPDXRef-App"},
    {"filesAnalyzed": True}, {"hasFiles": []}, {"packageVerificationCode": {}},
    {"licenseInfoFromFiles": []}, {"name": "different"}, {"versionInfo": "different"},
    {"externalRefs": []}, {"primaryPackagePurpose": "CONTAINER"},
    {"licenseDeclared": "MIT OR licenseref-private"},
    {"licenseConcluded": "DocumentRef-other:LicenseRef-private"},
])
def test_PackageAndLicenseGuardsRemainFailClosed(context, change):
    """Graph admission cannot guess versioned package or globally scoped license identities."""

    source = Document()
    source["packages"][1].update(change)

    with pytest.raises(ValueError):
        Import(context, source)


@pytest.mark.parametrize("kind,source,target", [
    ("DYNAMIC_LINK", "SPDXRef-App", "SPDXRef-Lib"),
    ("RUNTIME_DEPENDENCY_OF", "SPDXRef-App", "SPDXRef-Lib"),
    ("DEPENDS_ON", "SPDXRef-DOCUMENT", "SPDXRef-Lib"),
    ("DESCRIBES", "SPDXRef-App", "SPDXRef-Lib"),
    ("DEPENDS_ON", "SPDXRef-App", "SPDXRef-App"),
    ("DEPENDS_ON", "SPDXRef-App", "SPDXRef-Missing"),
    ("DEPENDS_ON", "SPDXRef-App", "DocumentRef-other:SPDXRef-Lib"),
    ("DEPENDS_ON", "SPDXRef-App", "NONE"),
    ("DEPENDS_ON", "SPDXRef-App", "NOASSERTION"),
])
def test_UnsupportedRelationshipEndpointsAndKindsFail(context, kind, source, target):
    """Only bounded local explicit package relationships are interpreted."""

    document = Document()
    document["relationships"][6] = {"spdxElementId": source, "relationshipType": kind,
                                     "relatedSpdxElement": target}

    with pytest.raises(ValueError):
        Import(context, document)


@pytest.mark.parametrize("edge", [
    ("SPDXRef-Lib", "CONTAINS", "SPDXRef-App"),
    ("SPDXRef-App", "CONTAINS", "SPDXRef-Image"),
    ("SPDXRef-Lib-Alias", "CONTAINS", "SPDXRef-Lib"),
    ("SPDXRef-Lib", "CONTAINS", "SPDXRef-Helper"),
    ("SPDXRef-Helper", "CONTAINED_BY", "SPDXRef-Lib"),
    ("SPDXRef-Lib", "DEPENDENCY_OF", "SPDXRef-App"),
])
def test_ContainmentCyclesCanonicalCollapseAndInverseDuplicatesFail(context, edge):
    """Original and alias-collapsed cycles fail; inverses cannot duplicate one source fact."""

    source = Document()
    source["relationships"].append(dict(zip(
        ("spdxElementId", "relationshipType", "relatedSpdxElement"), edge,
    )))

    with pytest.raises(ValueError):
        Import(context, source)


def test_DependencyOnlyPackagesCannotEstablishImageMembership(context):
    """Removing all Helper containment leaves a dependency-connected but uncontained package."""

    source = Document()
    source["relationships"] = [row for index, row in enumerate(source["relationships"])
                                if index not in {4, 5}]

    with pytest.raises(ValueError, match="cover every package"):
        Import(context, source)


def test_OneInverseDescriptionCanSelectRootWithoutDocumentDescribes(context):
    """The documented inverse description establishes the same explicit local root."""

    source = Document()
    del source["documentDescribes"]
    state, _ = Import(context, source)
    images = [item for item in state.objects if item.attributes["asset_type"] == "image"]
    assert len(images) == 1, "Inverse source description failed to select its unique root"


def test_CanonicalDependencySelfClaimRetainsItsDistinctLocalAliases(context):
    """Different source IDs may refer to one canonical package without losing their claim."""

    source = Document()
    source["relationships"].append({"spdxElementId": "SPDXRef-Lib",
        "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Lib-Alias"})
    state, _ = Import(context, source)
    facts = [item for item in state.observations if item.kind == "spdx-relationship-claim"
             and item.attributes["source_id"] == "SPDXRef-Lib"
             and item.attributes["target_id"] == "SPDXRef-Lib-Alias"]
    assert len(facts) == 1 and facts[0].attributes["source_reference"] == (
        facts[0].attributes["target_reference"]
    ), "Canonical alias correlation erased original dependency endpoints"


@pytest.mark.parametrize("changes", [
    {"observed_at": "2030-01-01T00:00:00Z"}, {"source_id": "inventory.other"},
    {"scope_reference": "scope:other"}, {"provider_version": "invented"},
    {"evidence_references": ()},
    {"execution": AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.01)},
])
def test_AcquisitionMustMatchOriginalManifest(context, changes):
    """Normalized graph claims retain exact original source, version, scope, time and evidence."""

    root, state, _ = context
    record, provenance = Acquired(context)

    with pytest.raises(ValueError):
        ApplyVerifiedSpdxGraph(state, record, replace(provenance, **changes), IMAGE, root)


@pytest.mark.parametrize("changes", [
    {"workspace_id": "foreign"}, {"invocation_sha256": "a" * 64},
    {"execution": AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.01)},
])
def test_OfflineSourceCannotInventWorkspaceOrExecution(context, changes):
    """Recorded offline evidence does not authorize a fabricated scanner operation."""

    root, state, _ = context
    record, provenance = Acquired(context, source_changes=changes)

    with pytest.raises(ValueError):
        ApplyVerifiedSpdxGraph(state, record, provenance, IMAGE, root)


@pytest.mark.parametrize("field", ["state", "record", "provenance", "image"])
@pytest.mark.parametrize("kind", ["untyped", "subclass", "mutated"])
def test_PublicInputsAreRevalidatedBeforeAnyEvidenceRead(context, monkeypatch, field, kind):
    """Frozen objects, subclasses and loose duck typing cannot bypass original input validation."""

    root, state, _ = context
    record, provenance = Acquired(context)
    image = ImageIdentity(IMAGE.digest)
    inputs = {"state": state, "record": record, "provenance": provenance, "image": image}

    if kind == "untyped":
        inputs[field] = object()

    elif kind == "subclass":
        original = inputs[field]
        derived = type("Derived", (type(original),), {"__doc__": "Rejected derived test value."})
        fields = {"state": {"workspace_id": state.workspace_id},
                  "record": {"reference": record.reference, "provenance": record.provenance},
                  "provenance": {"source_id": provenance.source_id,
                      "run_reference": provenance.run_reference,
                      "observed_at": provenance.observed_at,
                      "scope_reference": provenance.scope_reference,
                      "target_reference": provenance.target_reference},
                  "image": {"digest": image.digest}}
        inputs[field] = derived(**fields[field])

    else:
        member, value = {"state": ("revision", True),
                         "record": ("evidence_id", "sha256:" + "b" * 64),
                         "provenance": ("source_id", "INVALID PRIVATE"),
                         "image": ("digest_kind", "archive")}[field]
        object.__setattr__(inputs[field], member, value)

    def Tripwire(*args, **kwargs):
        """Reject evidence or metadata I/O before typed input validation completes."""

        pytest.fail("Invalid public input reached evidence I/O")

    monkeypatch.setattr(LocalEvidenceStore, "Get", Tripwire)
    monkeypatch.setattr(LocalWorkspaceStore, "Open", Tripwire)

    with pytest.raises((ValueError, EvidenceError)):
        ApplyVerifiedSpdxGraph(inputs["state"], inputs["record"], inputs["provenance"],
                               inputs["image"], root)


@pytest.mark.parametrize("field", ["reference", "source", "model-reference"])
def test_NestedTypedSubclassInputsAreRefused(context, field):
    """Nested acquisition/reference subclasses cannot substitute equality-compatible values."""

    root, state, _ = context
    record, provenance = Acquired(context)
    original = record.provenance if field == "source" else record.reference
    derived = type("Derived", (type(original),), {"__doc__": "Rejected nested test value."})
    nested = derived(**{name: getattr(original, name) for name in original.__dataclass_fields__})

    if field == "reference":
        record = replace(record, reference=nested)

    elif field == "source":
        record = replace(record, provenance=nested)

    else:
        object.__setattr__(provenance, "evidence_references", (nested,))

    with pytest.raises(ValueError, match="exact original"):
        ApplyVerifiedSpdxGraph(state, record, provenance, IMAGE, root)


@pytest.mark.parametrize("field", [
    "object", "identity", "provenance", "reference", "collection", "attributes",
])
def test_ExistingBasisNestedTypesCannotInvokeSubclassOverrides(context, monkeypatch, field):
    """Exact nested model values are checked before any subclass serialization method runs."""

    root, initial, _ = context
    record, provenance = Acquired(context)
    state, _ = ApplyVerifiedSpdxGraph(initial, record, provenance, IMAGE, root)
    entity = replace(state.objects[0])
    state = replace(state, objects=(entity, *state.objects[1:]))

    if field == "collection":
        object.__setattr__(state, "objects", list(state.objects))

    elif field == "attributes":
        object.__setattr__(entity, "attributes", dict(entity.attributes))

    else:
        original = {"object": entity, "identity": entity.identity,
                    "provenance": entity.provenance[0],
                    "reference": entity.provenance[0].evidence_references[0]}[field]

        def Tripwire(*args, **kwargs):
            """Fail if an untrusted nested model subclass reaches dynamic serialization."""

            pytest.fail("Nested model subclass override executed before exact type checks")

        derived = type("Derived", (type(original),), {
            "__doc__": "Rejected nested model value.", "Reference": Tripwire, "ToDict": Tripwire,
        })
        nested = object.__new__(derived)

        for name in original.__dataclass_fields__:
            object.__setattr__(nested, name, getattr(original, name))

        if field == "object":
            object.__setattr__(state, "objects", (nested, *state.objects[1:]))

        elif field == "identity":
            object.__setattr__(entity, "identity", nested)

        elif field == "provenance":
            object.__setattr__(entity, "provenance", (nested,))

        else:
            model_context = replace(entity.provenance[0])
            object.__setattr__(model_context, "evidence_references", (nested,))
            object.__setattr__(entity, "provenance", (model_context,))

    def NoRead(*args, **kwargs):
        """Fail if invalid nested model input reaches original evidence access."""

        pytest.fail("Invalid nested model input reached evidence I/O")

    monkeypatch.setattr(LocalEvidenceStore, "Get", NoRead)
    monkeypatch.setattr(LocalWorkspaceStore, "Open", NoRead)

    with pytest.raises(ValueError, match="exact typed"):
        ApplyVerifiedSpdxGraph(state, record, provenance, IMAGE, root)


def test_ManifestSubstitutionAndCorruptBytesFailWithoutSaving(context):
    """Content-only equality cannot replace original manifest or bypass immutable raw hashes."""

    root, state, store = context
    record, provenance = Acquired(context)
    substituted = replace(record, provenance=replace(record.provenance,
                                                      scope_reference="scope:other"))

    with pytest.raises((ValueError, EvidenceError)):
        ApplyVerifiedSpdxGraph(state, substituted, provenance, IMAGE, root)

    raw_path = store.root / record.reference.locator
    raw_path.chmod(0o600)
    raw_path.write_bytes(b"corrupt")

    with pytest.raises(EvidenceIntegrityError):
        ApplyVerifiedSpdxGraph(state, record, provenance, IMAGE, root)

    assert LocalModelStore(root).Open() == state, "Evidence failure saved partial graph state"


@pytest.mark.parametrize("raw", [
    b"{", b"[]", b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b"\xff",
    b" " * (4 * 1024 * 1024 + 1), b'{"x":"\\ud800"}',
], ids=["syntax", "top-level", "duplicate", "constant", "overflow", "encoding", "bytes", "unicode"])
def test_GraphStrictOriginalJsonBoundary(context, raw):
    """Malformed and oversized original bytes are refused before any partial graph is returned."""

    with pytest.raises(ValueError):
        Import(context, raw)


@pytest.mark.parametrize("budget", ["nodes", "depth", "array"])
def test_GraphBudgetsApplyToIgnoredAndConsumedData(context, budget):
    """Ignored padding and supported graph arrays remain within existing deterministic budgets."""

    source = Document()

    if budget == "nodes":
        source["x-padding"] = [0] * 65537

    elif budget == "depth":
        nested = []

        for _ in range(40):
            nested = [nested]

        source["x-padding"] = nested

    else:
        source["relationships"] *= 410

    with pytest.raises(ValueError):
        Import(context, source)


def test_PureCandidatesNeverOpenFilesProcessesOrNetwork(context, monkeypatch):
    """The graph transformation uses only original bytes and supplied validated values."""

    _, state, _ = context
    record, provenance = Acquired(context)
    raw = CanonicalModelJson(Document())

    def Tripwire(*args, **kwargs):
        """Fail if a pure transformation tries any acquisition or execution operation."""

        pytest.fail("Pure graph transformation attempted filesystem, process or network I/O")

    with monkeypatch.context() as patch:
        patch.setattr("builtins.open", Tripwire)
        patch.setattr(Path, "open", Tripwire)
        patch.setattr(subprocess, "Popen", Tripwire)
        patch.setattr(socket, "socket", Tripwire)
        objects, relations, observations = GraphCandidates(raw, state.workspace_id, record,
                                                         provenance, IMAGE)

    assert objects and relations and observations, "Pure original graph produced no interpretations"


def test_ImageChecksumAndKindRemainExplicitAndPrivateErrorsStaySanitized(context):
    """Checksum comparison does not invent config/manifest equivalence or expose source values."""

    root, state, _ = context
    record, provenance = Acquired(context)

    with pytest.raises(ValueError, match="bound SHA256"):
        ApplyVerifiedSpdxGraph(state, record, provenance, ImageIdentity("sha256:" + "b" * 64), root)

    for kind in ("config", "manifest"):
        state, _ = ApplyVerifiedSpdxGraph(state, record, provenance,
                                         ImageIdentity(IMAGE.digest, kind), root)

    images = [item for item in state.objects if item.attributes["asset_type"] == "image"]
    assert len(images) == 2, "Equal generic checksums collapsed distinct explicit image kinds"
    source = deepcopy(Document())
    source["relationships"][6]["relatedSpdxElement"] = "DocumentRef-SYNTHETIC_PRIVATE_MARKER"

    with pytest.raises(ValueError) as caught:
        Import(context, source)

    assert "SYNTHETIC_PRIVATE_MARKER" not in "".join(format_exception(caught.value)), (
        "Graph rejection leaked raw private values through exception text or chaining"
    )
