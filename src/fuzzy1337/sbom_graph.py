# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental original-evidence-backed local SPDX containment and dependency claims."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from fuzzy1337.adapters import AdapterExecution, EvidenceReference
from fuzzy1337.adapters.contracts import JsonValue
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord, ParseEvidenceManifest
from fuzzy1337.images import (
    ApplyBatch,
    Digest,
    ImageIdentity,
    Items,
    LicenseObjects,
    PackageFields,
    Record,
    Text,
    VerifyRecords,
)
from fuzzy1337.model import (
    ModelDelta,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    Observation,
    Relation,
    RelationKind,
    SecurityObject,
)
from fuzzy1337.sbom_spdx import (
    SpdxHeader,
    SpdxIdentifier,
    SpdxJson,
    SpdxLicense,
    SpdxPurl,
    SpdxUnsupported,
)

SPDX_GRAPH_IMPORT_VERSION = 1
_DOCUMENT = "SPDXRef-DOCUMENT"
_INVERSES = {"DESCRIBED_BY": "DESCRIBES", "CONTAINED_BY": "CONTAINS",
             "DEPENDENCY_OF": "DEPENDS_ON"}
__all__ = ["SPDX_GRAPH_IMPORT_VERSION", "ApplyVerifiedSpdxGraph"]


@dataclass(frozen=True, slots=True)
class SourceEdge:
    """Retain an original relationship coordinate beside its normalized direction."""

    index: int
    original_source: str
    original_kind: str
    original_target: str
    source: str
    kind: str
    target: str


@dataclass(frozen=True, slots=True)
class SourceCatalog:
    """Hold an internal validated local catalog without accepting detached graphs as evidence."""

    root_id: str
    packages: dict[str, dict[str, object]]
    edges: tuple[SourceEdge, ...]


def CheckContainment(root: str, nodes: set[str], edges: set[tuple[str, str]]) -> None:
    """Require a bounded rooted DAG covering every catalog node without recursive traversal.

    Args:
        root: Explicitly described image, not a guessed dependency root.
        nodes: Local source IDs or canonical references after package alias correlation.
        edges: Explicit containment claims only; dependencies never establish membership.

    Raises:
        ValueError: A containment cycle, incoming root edge or disconnected node exists.
    """

    incoming = dict.fromkeys(nodes, 0)
    children: dict[str, set[str]] = {node: set() for node in nodes}

    for source, target in edges:
        children[source].add(target)
        incoming[target] += 1

    if incoming[root]:
        raise ValueError("SPDX graph image root cannot be contained by another package")

    pending = [root]
    visited = set()

    while pending:
        source = pending.pop()
        visited.add(source)

        for target in children[source]:
            incoming[target] -= 1

            if incoming[target] == 0:
                pending.append(target)

    if visited != nodes:
        raise ValueError("SPDX graph containment must be acyclic and cover every package")


def GraphCatalog(payload: dict[str, object], image_identity: ImageIdentity) -> SourceCatalog:
    """Validate the explicit local graph profile as a pure transformation of original JSON.

    Args:
        payload: Strictly decoded SPDX 2.3 document whose envelope was already validated.
        image_identity: Caller-declared config/manifest semantics, never inferred from checksums.

    Returns:
        One checksum-bound root, local package rows and exact original relationship coordinates.

    Raises:
        ValueError: Package, root, relationship, checksum or containment claims are unsupported.
    """

    packages = {}

    for value in Items(payload.get("packages")):
        package = Record(value)
        identifier = SpdxIdentifier(package.get("SPDXID"))

        if identifier in packages or package.get("filesAnalyzed") is not False or any(
            name in package for name in (
                "hasFiles", "packageVerificationCode", "licenseInfoFromFiles",
            )
        ):
            raise ValueError("SPDX graph requires unique package IDs with filesAnalyzed false")

        Text(package.get("name"))
        Text(package.get("downloadLocation"))
        SpdxUnsupported(package)
        packages[identifier] = package

    declared = [SpdxIdentifier(value) for value in Items(payload.get("documentDescribes", []))]

    if len(set(declared)) != len(declared):
        raise ValueError("SPDX graph described roots must be unique")

    described = set(declared)
    coordinates = set()
    edges = []

    for index, value in enumerate(Items(payload.get("relationships", []))):
        relation = Record(value)
        original_source = SpdxIdentifier(relation.get("spdxElementId"), document=True)
        original_target = SpdxIdentifier(relation.get("relatedSpdxElement"), document=True)
        original_kind = Text(relation.get("relationshipType"))
        source, kind, target = original_source, original_kind, original_target

        if kind in _INVERSES:
            source, kind, target = target, _INVERSES[kind], source

        coordinate = source, kind, target

        if coordinate in coordinates or source == target or any(
            endpoint not in packages and endpoint != _DOCUMENT for endpoint in (source, target)
        ):
            raise ValueError("SPDX graph edges must be unique, local and resolved")

        coordinates.add(coordinate)

        if kind == "DESCRIBES" and source == _DOCUMENT and target in packages:
            described.add(target)

        elif kind in {"CONTAINS", "DEPENDS_ON"} and source in packages and target in packages:
            edges.append(SourceEdge(index, original_source, original_kind, original_target,
                                    source, kind, target))

        else:
            raise ValueError("SPDX graph supports local description, containment and dependency")

    if len(described) != 1 or (declared and set(declared) != described):
        raise ValueError("SPDX graph requires one consistently described container root")

    root_id = next(iter(described))

    if root_id not in packages or packages[root_id].get("primaryPackagePurpose") != "CONTAINER":
        raise ValueError("SPDX graph described root must resolve to a CONTAINER package")

    if any(package.get("primaryPackagePurpose") == "CONTAINER" for identifier, package
           in packages.items() if identifier != root_id):
        raise ValueError("SPDX graph supports exactly one container package")

    CheckContainment(root_id, set(packages), {
        (edge.source, edge.target) for edge in edges if edge.kind == "CONTAINS"
    })
    hashes = []

    for value in Items(packages[root_id].get("checksums")):
        checksum = Record(value)

        if Text(checksum.get("algorithm")) == "SHA256":
            hashes.append(Digest("sha256:" + Text(checksum.get("checksumValue"))))

    if hashes != [image_identity.digest]:
        raise ValueError("SPDX graph root requires one explicitly bound SHA256 checksum")

    return SourceCatalog(root_id, packages, tuple(edges))


def RevalidateInputs(state: ModelState, record: EvidenceRecord, provenance: ModelProvenance,
                     image_identity: ImageIdentity) -> None:
    """Reconstruct exact typed inputs before reading evidence or trusting frozen instance fields.

    Args:
        state: Original canonical basis snapshot, including its existing triage history.
        record: Original manifest identity with exact typed reference and acquisition provenance.
        provenance: Offline attribution bound to the original source by VerifyRecords.
        image_identity: Explicit validated hash-kind identity.

    Raises:
        ValueError: Subclasses, untyped inputs, mutated frozen fields or offline execution appear.
    """

    if type(state) is not ModelState or type(record) is not EvidenceRecord or (
        type(provenance) is not ModelProvenance or type(image_identity) is not ImageIdentity
    ):
        raise ValueError("SPDX graph requires exact typed model, evidence, attribution and image")

    if type(record.reference) is not EvidenceReference or (
        type(record.provenance) is not EvidenceProvenance
        or type(provenance.evidence_references) is not tuple
        or any(type(item) is not EvidenceReference for item in provenance.evidence_references)
        or provenance.execution is not None or record.provenance.execution is not None
        or record.provenance.invocation_sha256 is not None or record.reference.role != "sbom"
    ):
        raise ValueError("SPDX graph requires exact original offline sbom acquisition fields")

    for field_name, expected in (
        ("objects", SecurityObject), ("relations", Relation), ("observations", Observation),
    ):
        values = getattr(state, field_name)

        if type(values) is not tuple or any(type(value) is not expected for value in values):
            raise ValueError("SPDX graph basis requires exact typed model collections")

    entities: tuple[SecurityObject | Relation, ...] = (*state.objects, *state.relations)

    if any(type(item.identity) is not ObjectIdentity for item in state.objects) or any(
        type(item.provenance) is not tuple for item in entities
    ):
        raise ValueError("SPDX graph basis requires exact typed identities and attribution")

    records: tuple[SecurityObject | Relation | Observation, ...] = (*entities, *state.observations)

    if any(type(item.attributes) is not MappingProxyType for item in records):
        raise ValueError("SPDX graph basis requires exact typed immutable model attributes")

    attribution = [provenance, *(item.provenance for item in state.observations)]

    for item in entities:
        attribution.extend(item.provenance)

    for context in attribution:
        if type(context) is not ModelProvenance or (
            type(context.evidence_references) is not tuple
            or any(type(reference) is not EvidenceReference
                   for reference in context.evidence_references)
            or (context.execution is not None and type(context.execution) is not AdapterExecution)
        ):
            raise ValueError("SPDX graph basis requires exact typed provenance and references")

    try:
        rebuilt_record = ParseEvidenceManifest(record.Serialize())
        rebuilt_provenance = ModelProvenance.FromDict(JsonValue(provenance))
        rebuilt_image = ImageIdentity(image_identity.digest, image_identity.digest_kind)
        rebuilt_state = ModelState.FromDict(state.ToDict())

        if rebuilt_record != record or rebuilt_provenance != provenance or (
            rebuilt_image != image_identity or rebuilt_state != state
        ):
            raise ValueError("changed frozen graph input")

    except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
        raise ValueError("SPDX graph input differs from its validated original fields") from None


def GraphCandidates(raw: bytes, workspace_id: str, record: EvidenceRecord,
                    provenance: ModelProvenance, image_identity: ImageIdentity
                    ) -> tuple[list[SecurityObject], list[Relation], list[Observation]]:
    """Produce source-bound graph interpretations without filesystem, process or network I/O.

    Args:
        raw: Original bytes already verified against the exact immutable source manifest.
        workspace_id: Existing model workspace identity.
        record: Verified original manifest, never a fabricated producer receipt.
        provenance: Revalidated matching source acquisition attribution.
        image_identity: Explicit root checksum and hash-kind semantics.

    Returns:
        Fully validated canonical objects, exact source relations and inert licensing facts.

    Raises:
        ValueError: Source profile, licensing, package linkage or canonical containment fails.
    """

    payload = SpdxJson(raw)
    SpdxHeader(payload)
    catalog = GraphCatalog(payload, image_identity)
    image = SecurityObject(image_identity.Object(workspace_id), {
        "asset_type": "image", "digest": image_identity.digest,
        "digest_kind": image_identity.digest_kind,
    }, (provenance,))
    objects = [image]
    entities = {}
    relations = []
    observations = []
    basis = {"document_sha256": record.reference.sha256, "evidence_id": record.evidence_id,
             "image_reference": image.Reference()}

    for identifier in sorted(catalog.packages):
        package = catalog.packages[identifier]
        identity = SpdxPurl(package, root=identifier == catalog.root_id)
        entity = image if identity is None else SecurityObject(
            identity.Object(workspace_id), PackageFields(identity), (provenance,),
        )
        entities[identifier] = entity

        if identity is not None:
            objects.append(entity)

        declared = SpdxLicense(package.get("licenseDeclared"), present="licenseDeclared" in package)
        concluded = SpdxLicense(
            package.get("licenseConcluded"), present="licenseConcluded" in package,
        )
        alias = {**basis, "spdx_id": identifier}
        observations.append(Observation("spdx-source-alias", entity.Reference(), alias, provenance))
        observations.append(Observation("spdx-package-license", entity.Reference(), {
            **alias, "declared": declared, "concluded": concluded,
        }, provenance))

        if declared["state"] == "expression":
            licenses, links = LicenseObjects(workspace_id, entity, [declared["expression"]],
                                            provenance)
            objects.extend(licenses)
            relations.extend(links)

    CheckContainment(image.Reference(), {entity.Reference() for entity in entities.values()}, {
        (entities[edge.source].Reference(), entities[edge.target].Reference())
        for edge in catalog.edges if edge.kind == "CONTAINS"
    })

    for edge in catalog.edges:
        source, target = entities[edge.source].Reference(), entities[edge.target].Reference()
        relation = Relation(RelationKind.CONTAINS if edge.kind == "CONTAINS"
                            else RelationKind.RELATED_TO, source, target,
                            {} if edge.kind == "CONTAINS"
                            else {"association": "spdx-dependency-claim"}, (provenance,))
        relations.append(relation)
        observations.append(Observation("spdx-relationship-claim", relation.Reference(), {
            **basis, "relationship_index": edge.index,
            "original_source_id": edge.original_source, "original_type": edge.original_kind,
            "original_target_id": edge.original_target, "source_id": edge.source,
            "relationship_type": edge.kind, "target_id": edge.target,
            "source_reference": source, "target_reference": target,
        }, provenance))

    observations.append(Observation("image-sbom-inventory", image.Reference(), {
        **basis, "format": "SPDX", "spec_version": "2.3", "profile": "local-package-graph-v1",
    }, provenance))

    return objects, relations, observations


def ApplyVerifiedSpdxGraph(state: ModelState, record: EvidenceRecord,
                          provenance: ModelProvenance, image_identity: ImageIdentity,
                          workspace_root: Path) -> tuple[ModelState, ModelDelta]:
    """Opt in to bounded local SPDX graph claims through original evidence and canonical model.

    Args:
        state: Original validated same-workspace basis snapshot; existing triage is retained.
        record: Explicit immutable independently acquired offline sbom EvidenceRecord.
        provenance: Matching acquisition attribution with no invocation or execution fabrication.
        image_identity: Caller-declared config or manifest identity bound to one root checksum.
        workspace_root: Owned existing or relocated workspace retaining the original source.

    Returns:
        One atomic in-memory transition. The caller owns LocalModelStore.Save and its CAS check.
        Dependency relations describe source claims; they assert no runtime reachability.

    Raises:
        ValueError: Typed inputs, manifest bindings, package/graph/license profile or basis fail.
        EvidenceError: Original immutable manifest or raw source bytes fail verification.
        OSError: Owning workspace metadata or evidence cannot be read.
    """

    RevalidateInputs(state, record, provenance, image_identity)
    raw = VerifyRecords(state, provenance, (record,), workspace_root)["sbom"]
    objects, relations, observations = GraphCandidates(raw, state.workspace_id, record,
                                                       provenance, image_identity)

    return ApplyBatch(state, objects, relations, observations, [], workspace_root)
