# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Attribute unacceptable outcome declarations and explain technical paths to critical assets."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import cast

from fuzzy1337.adapters.contracts import EvidenceReference
from fuzzy1337.evidence import EvidenceRecord, LocalEvidenceStore, NormalizeEvidenceTime
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelDelta,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Relation,
    RelationKind,
    SecurityObject,
)
from fuzzy1337.path_analysis import AnalyzeReachabilityPaths, PathAnalysis, PathAnalysisLimits
from fuzzy1337.reachability import (
    ReachabilityLimits,
    ReachabilityModelVersion,
    ReachabilityProjection,
)
from fuzzy1337.workspace import RejectWorkspaceConstant, UniqueWorkspaceObject, WorkspaceFields

BUSINESS_EVENT_PROFILE_VERSION = 1
_MAX_DEFINITION_BYTES = 64 * 1024
_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_OBJECT = re.compile(r"object:[0-9a-f]{64}\Z")
_VERIFIED = object()
_ASSET_TYPE = "business-event-definition"

__all__ = [
    "BUSINESS_EVENT_PROFILE_VERSION", "ReadBusinessEventDefinition", "ApplyBusinessEvent",
    "AnalyzeBusinessEventPaths",
]


def Text(value: object, maximum: int) -> str:
    """Internal boundary requiring bounded nonempty single-line UTF-8 declaration text.

    Args:
        value: Explicit source field, never inferred from an environment.
        maximum: Inclusive encoded-byte ceiling for that field.

    Returns:
        Unchanged validated text.

    Raises:
        ValueError: Text is empty, malformed, multiline or oversized.
    """

    if not isinstance(value, str) or not value.strip() or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ValueError("business event text requires nonempty single-line content")

    try:
        encoded = value.encode("utf-8")

    except UnicodeError:
        raise ValueError("business event text requires valid UTF-8") from None

    if len(encoded) > maximum:
        raise ValueError("business event text exceeds its bounded field size")

    return value


def References(value: object, *, maximum: int = 16) -> tuple[str, ...]:
    """Internal boundary for explicit distinct original object memberships or source positions.

    Args:
        value: Exact immutable reference tuple.
        maximum: Inclusive count ceiling; zero entries are never accepted.

    Returns:
        Canonically ordered original references.

    Raises:
        ValueError: Membership is mutable, empty, duplicated, oversized or malformed.
    """

    if type(value) is not tuple or not 1 <= len(value) <= maximum or any(
        not isinstance(item, str) or not _OBJECT.fullmatch(item) for item in value
    ) or len(set(value)) != len(value):
        raise ValueError("business event references require a bounded distinct canonical tuple")

    return tuple(sorted(value))


class DefinitionEvidenceStore(LocalEvidenceStore):
    """Internal read facade bounding actual parsed manifests before owning raw-byte allocation."""

    def Read(self, reference: EvidenceReference) -> bytes:
        """Keep existing integrity ownership while refusing oversized actual source references.

        Args:
            reference: Caller or parsed manifest's original adapter evidence reference.

        Returns:
            Unchanged original bytes after owning verification.

        Raises:
            ValueError: The actual reference exceeds this profile's inclusive 64 KiB ceiling.
            EvidenceError: The existing owner cannot verify the original bytes.
        """

        if not isinstance(reference, EvidenceReference) or (
            type(reference.size_bytes) is not int
            or not 1 <= reference.size_bytes <= _MAX_DEFINITION_BYTES
        ):
            raise ValueError("business event definition evidence exceeds the source byte bound")

        return super().Read(reference)


@dataclass(frozen=True, slots=True)
class BusinessEventDefinition:
    """Internal verified declaration output; constructing fields alone verifies no evidence."""

    definition_reference: str
    model_version: ReachabilityModelVersion
    definition_key: str
    definition_version: str
    owner_reference: str
    title: str
    unacceptable_outcome: str
    declared_at: str
    critical_asset_references: tuple[str, ...]
    record: EvidenceRecord = field(repr=False)
    _seal: object = field(repr=False, compare=False)
    _proof_digest: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class BusinessEventPath:
    """Internal technical-path explanation with separate descriptive impact membership."""

    attacker_reference: str
    critical_asset_reference: str
    membership_relation_reference: str
    technical_analysis: PathAnalysis
    impact_semantics: str = "declared-scenario-only"


@dataclass(frozen=True, slots=True)
class BusinessEventAnalysis:
    """Internal bounded scenario retaining each independent query and its limitations."""

    analysis_reference: str
    definition_reference: str
    declaration_object_reference: str
    definition_evidence_id: str
    owner_reference: str
    unacceptable_outcome: str
    paths_to_assets: tuple[BusinessEventPath, ...]
    enumeration_complete: bool
    cuts_complete: bool
    semantics: str = "declared-unacceptable-outcome-scenario"
    claim_scope: str = "selected-technical-transition-subgraph-only"


def DefinitionFields(definition: BusinessEventDefinition) -> dict[str, object]:
    """Internal canonical semantic declaration fields shared by identity and model representation.

    Args:
        definition: Exact loader-produced declaration.

    Returns:
        Detached bounded definition fields without original raw bytes.
    """

    return {"profile_version": BUSINESS_EVENT_PROFILE_VERSION,
        "workspace_id": definition.model_version.workspace_id,
        "definition_key": definition.definition_key,
        "definition_version": definition.definition_version,
        "owner_reference": definition.owner_reference, "title": definition.title,
        "unacceptable_outcome": definition.unacceptable_outcome,
        "declared_at": definition.declared_at,
        "critical_asset_references": definition.critical_asset_references}


def Digest(value: object) -> str:
    """Internal domain-independent content digest through the existing canonical serializer.

    Args:
        value: Bounded explicit canonical fields.

    Returns:
        Lowercase SHA-256 text.
    """

    return hashlib.sha256(CanonicalModelJson(value)).hexdigest()


def ProofDigest(definition: BusinessEventDefinition) -> str:
    """Internal tamper guard binding all retained fields to the exact original manifest and basis.

    Args:
        definition: Loader-produced or caller-copied output to compare.

    Returns:
        Canonical content digest excluding only the guard and private seal itself.
    """

    return Digest({"definition": DefinitionFields(definition),
        "definition_reference": definition.definition_reference,
        "model_version": definition.model_version, "record": definition.record.ToDict()})


def ValidateDefinition(definition: BusinessEventDefinition, model: ModelState) -> None:
    """Internal recheck of typed loader output, exact current basis and critical-asset membership.

    Args:
        definition: Exact owning-read output, never an arbitrary typed declaration.
        model: Immutable caller basis matching that output's complete snapshot pin.

    Raises:
        ValueError: Output was fabricated/changed, the basis is stale or membership is invalid.
    """

    if not isinstance(definition, BusinessEventDefinition) or definition._seal is not _VERIFIED:
        raise ValueError("business event operation requires an owning-read definition")

    if ProofDigest(definition) != definition._proof_digest or (
        ReachabilityModelVersion.FromModel(model) != definition.model_version
    ):
        raise ValueError("business event definition or exact model basis changed")

    critical = References(definition.critical_asset_references)
    objects = {item.Reference(): item for item in model.objects}

    for reference in critical:
        item = objects.get(reference)

        if item is None or item.identity.kind is not ObjectKind.ASSET or (
            item.attributes.get("asset_type") in (_ASSET_TYPE, "reachability-control")
        ):
            raise ValueError("business event critical membership requires existing ordinary assets")


def ReadBusinessEventDefinition(
    model: ModelState, record: EvidenceRecord, *, workspace_root: Path,
    expected_model_version: ReachabilityModelVersion, scope_reference: str,
) -> BusinessEventDefinition:
    """Verify original owner-definition evidence against the current persisted model and scope.

    Args:
        model: Immutable existing model with explicit ordinary critical Asset members.
        record: Original evidence acquired under role business-event-definition and JSON media type.
        workspace_root: Existing owned workspace accessed only through its storage owners.
        expected_model_version: Exact complete current schema/workspace/revision/content pin.
        scope_reference: Exact declaration scope; attribution conveys no execution authority.

    Returns:
        Frozen internally guarded definition with unchanged evidence provenance and stable identity.

    Raises:
        ValueError: Basis, source grammar, attribution, version, time or membership is invalid.
        EvidenceError: Original owning manifest/blob cannot be verified.
        WorkspaceError: The existing workspace/model cannot be reopened safely.

    This reader writes nothing. It authenticates stored acquisition attribution, not a human
    identity or digital signature; owner_reference is explicitly supplied declaration text.
    """

    scope = Text(scope_reference, 4096)

    if not isinstance(record, EvidenceRecord) or not isinstance(
        expected_model_version, ReachabilityModelVersion,
    ) or ReachabilityModelVersion.FromModel(model) != expected_model_version:
        raise ValueError("business event source requires a typed exact model pin and record")

    current = LocalModelStore(workspace_root).Open()

    if ReachabilityModelVersion.FromModel(current) != expected_model_version:
        raise ValueError("business event current persisted model differs from the selected basis")

    store = DefinitionEvidenceStore(LocalModelStore(workspace_root).root / "evidence")
    stored = store.Get(record.evidence_id)

    if stored != record:
        raise ValueError("business event supplied record differs from its owning manifest")

    provenance = stored.provenance

    if (stored.reference.role != _ASSET_TYPE
        or stored.reference.media_type != "application/json" or (
        provenance.workspace_id != model.workspace_id or provenance.scope_reference != scope
        or provenance.source_version != "1" or provenance.execution is not None
        or provenance.invocation_sha256 is not None
    )):
        raise ValueError("business event original acquisition violates profile-one attribution")

    try:
        raw = store.Read(stored.reference)
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=UniqueWorkspaceObject,
                             parse_constant=RejectWorkspaceConstant)

    except (UnicodeError, RecursionError, json.JSONDecodeError):
        raise ValueError("business event definition requires bounded strict UTF-8 JSON") from None

    fields = WorkspaceFields(decoded, {"profile_version", "workspace_id", "definition_key",
        "definition_version", "owner_reference", "title", "unacceptable_outcome", "declared_at",
        "critical_asset_references"}, "business event definition")

    if type(fields["profile_version"]) is not int or fields["profile_version"] != 1 or (
        fields["workspace_id"] != model.workspace_id
    ):
        raise ValueError("business event definition version or workspace is unsupported")

    key = Text(fields["definition_key"], 128)

    if not _KEY.fullmatch(key):
        raise ValueError("business event definition key requires a bounded ASCII identifier")

    references = fields["critical_asset_references"]

    if type(references) is not list:
        raise ValueError("business event source membership requires an explicit JSON array")

    declared_at = NormalizeEvidenceTime(Text(fields["declared_at"], 128))

    if declared_at > provenance.started_at:
        raise ValueError("business event declaration time must not follow original acquisition")

    definition = BusinessEventDefinition("", expected_model_version, key,
        Text(fields["definition_version"], 128), Text(fields["owner_reference"], 1024),
        Text(fields["title"], 512), Text(fields["unacceptable_outcome"], 4096), declared_at,
        References(tuple(references)), stored, _VERIFIED, "")
    identity = "business-event:" + Digest({"definition": DefinitionFields(definition),
                                         "evidence_id": stored.evidence_id})
    definition = replace(definition, definition_reference=identity)
    definition = replace(definition, _proof_digest=ProofDigest(definition))
    ValidateDefinition(definition, model)

    return definition


def Representation(
    definition: BusinessEventDefinition,
) -> tuple[SecurityObject, tuple[Relation, ...]]:
    """Internal canonical declaration Asset and descriptive links retaining original attribution.

    Args:
        definition: Already checked owning-read declaration.

    Returns:
        One declared-scenario object and sorted critical-asset membership links.
    """

    record = definition.record
    provenance = ModelProvenance(record.provenance.source_id, definition.definition_reference,
        record.provenance.finished_at, record.provenance.scope_reference,
        definition.definition_reference, record.provenance.tool_version, (record.reference,))
    asset = SecurityObject(ObjectIdentity(definition.model_version.workspace_id, ObjectKind.ASSET,
        "business-event-definition:" + definition.definition_reference.split(":", 1)[1]),
        {**DefinitionFields(definition), "asset_type": _ASSET_TYPE,
         "definition_reference": definition.definition_reference,
         "definition_evidence_id": record.evidence_id,
         "semantics": "declared-unacceptable-outcome"}, (provenance,))
    links = tuple(Relation(RelationKind.RELATED_TO, reference, asset.Reference(),
        {"profile_version": BUSINESS_EVENT_PROFILE_VERSION,
         "relation_semantics": "declared-critical-asset-impact-membership",
         "definition_reference": definition.definition_reference}, (provenance,))
        for reference in definition.critical_asset_references)

    return asset, links


def ApplyBusinessEvent(
    definition: BusinessEventDefinition, model: ModelState,
) -> tuple[ModelState, ModelDelta]:
    """Apply one verified immutable declaration using the existing model owner without storage I/O.

    Args:
        definition: Owning-read definition matching the exact current model basis.
        model: Existing immutable model; caller owns revision-checked persistence of the result.

    Returns:
        Canonical new state and delta; exact original-manifest replay is a no-op.

    Raises:
        ValueError: Definition/basis changed or an existing declaration representation conflicts.

    Findings, triage and unrelated objects/relations are preserved. No authorization is issued.
    """

    ValidateDefinition(definition, model)
    asset, links = Representation(definition)
    current: dict[str, SecurityObject | Relation] = {
        item.Reference(): item for item in model.objects
    }
    current.update((item.Reference(), item) for item in model.relations)
    expected: list[SecurityObject | Relation] = [asset, *links]

    if any(item.Reference() in current and current[item.Reference()] != item
           for item in expected):
        raise ValueError("business event existing representation conflicts with its declaration")

    return model.Apply(objects=(asset,), relations=links)


def AnalyzeBusinessEventPaths(
    definition: BusinessEventDefinition, model: ModelState, projection: ReachabilityProjection,
    attacker_references: tuple[str, ...], *,
    search_limits: ReachabilityLimits = ReachabilityLimits(),
    cut_limits: PathAnalysisLimits = PathAnalysisLimits(),
) -> BusinessEventAnalysis:
    """Explain technical paths to declared critical assets and a separate impact scenario.

    Args:
        definition: Fresh owning-read original definition for the current persisted representation.
        model: Exact current immutable basis shared with the existing reachability projection.
        projection: Existing verified technical projection, excluding all descriptive outcome links.
        attacker_references: One to 16 distinct existing eligible positions, explicitly selected.
        search_limits: Existing bounded enumeration limits applied independently to each pair.
        cut_limits: Existing independent cut-work limits applied independently to each pair.

    Returns:
        At most 64 original source/critical-asset query explanations with their exact limitations,
        plus separate declaration membership. There is no outcome probability or observed incident.

    Raises:
        ValueError: Definition/model/representation is changed, selection is invalid or technical
            projection includes declaration links, exceeds pair bounds or fails owner checks.

    This is a pure consumer. Stored acquisition attribution does not authenticate an owner identity.
    Supplied CONFIRMED hop labels remain attestation summaries, never proof of business impact.
    """

    ValidateDefinition(definition, model)
    attackers = References(attacker_references)
    asset, links = Representation(definition)
    current: dict[str, SecurityObject | Relation] = {
        item.Reference(): item for item in model.objects
    }
    current.update((item.Reference(), item) for item in model.relations)
    expected: list[SecurityObject | Relation] = [asset, *links]

    if any(current.get(item.Reference()) != item for item in expected):
        raise ValueError("business event analysis requires exact persisted declaration links")

    if not isinstance(projection, ReachabilityProjection) or (
        projection.scope_reference != definition.record.provenance.scope_reference
        or projection.model_version != definition.model_version
        or projection.at < definition.record.provenance.finished_at
    ):
        raise ValueError("business event technical projection requires matching scope and basis")

    declaration_refs = {item.Reference() for item in model.objects
                        if item.attributes.get("asset_type") == _ASSET_TYPE}

    if any(edge.source_reference in declaration_refs or edge.target_reference in declaration_refs
           for edge in projection.transitions) or set(attackers) & declaration_refs:
        raise ValueError("business event declaration links cannot become technical transitions")

    critical = definition.critical_asset_references

    if len(attackers) * len(critical) > 64 or set(attackers) & set(critical):
        raise ValueError("business event queries require distinct positions and at most 64 pairs")

    memberships = {link.source_reference: link.Reference() for link in links}
    paths = []

    for attacker in attackers:
        for reference in critical:
            analysis = AnalyzeReachabilityPaths(projection, model, attacker, reference,
                search_limits=search_limits, cut_limits=cut_limits)
            paths.append(BusinessEventPath(attacker, reference, memberships[reference], analysis))

    results = cast(tuple[BusinessEventPath, ...], tuple(paths))
    identity = "business-event-analysis:" + Digest({
        "profile_version": BUSINESS_EVENT_PROFILE_VERSION,
        "definition_reference": definition.definition_reference,
        "analyses": [item.technical_analysis.analysis_reference for item in results]})

    return BusinessEventAnalysis(identity, definition.definition_reference, asset.Reference(),
        definition.record.evidence_id, definition.owner_reference, definition.unacceptable_outcome,
        results, all(item.technical_analysis.search.complete for item in results),
        all(item.technical_analysis.choke_points.complete for item in results))
