# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental provider-neutral security objects, attributable updates, and portable state."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import cast

from fuzzy1337.adapters.contracts import (
    AdapterExecution,
    AdapterReport,
    AdapterResult,
    EvidenceReference,
    ExecutionState,
    FreezeMapping,
    JsonValue,
    NormalizedObservation,
    ObjectEnrichment,
    RelationEnrichment,
    RequireIdentifier,
)
from fuzzy1337.evidence import NormalizeEvidenceTime
from fuzzy1337.workspace import (
    DecodeEvidenceReference,
    LocalWorkspaceStore,
    RejectWorkspaceConstant,
    RequireWorkspaceInteger,
    RequireWorkspaceText,
    StoragePathInfo,
    SyncStorageDirectory,
    UniqueWorkspaceObject,
    WorkspaceBusyError,
    WorkspaceConflictError,
    WorkspaceFields,
)

MODEL_SCHEMA_VERSION = 1
MAX_MODEL_BYTES = 8 * 1024 * 1024
MAX_ATTRIBUTE_BYTES = 64 * 1024
_REFERENCE_PATTERN = re.compile(r"^(object|relation|observation):[0-9a-f]{64}$")
_DNS_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ObjectKind(StrEnum):
    """Select typed first-party objects without assigning provider-owned schema semantics."""

    WORKSPACE = "workspace"
    SCOPE = "scope"
    TARGET = "target"
    DOMAIN = "domain"
    HOST = "host"
    ASSET = "asset"
    PORT = "port"
    SERVICE = "service"
    ENDPOINT = "endpoint"
    TECHNOLOGY = "technology"


class RelationKind(StrEnum):
    """Describe an attributed edge without inferring reachability or exploitability."""

    CONTAINS = "contains"
    RESOLVES_TO = "resolves-to"
    HAS_PORT = "has-port"
    HOSTS_SERVICE = "hosts-service"
    EXPOSES = "exposes"
    USES_TECHNOLOGY = "uses-technology"
    RELATED_TO = "related-to"


def CanonicalModelJson(value: object) -> bytes:
    """Render deterministic, strict JSON for identity, persistence, and bounded attributes.

    Args:
        value: JSON-compatible fields or first-party immutable contract values.

    Returns:
        UTF-8 canonical JSON with no trailing newline.

    Raises:
        ValueError: A value is not JSON-compatible or nesting exceeds Python's bound.
    """

    try:
        return json.dumps(
            JsonValue(value), ensure_ascii=False, allow_nan=False,
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")

    except (RecursionError, UnicodeError) as error:
        raise ValueError("model values must be bounded valid UTF-8 JSON") from error


def ModelReference(namespace: str, value: object) -> str:
    """Derive a domain-separated reference independent of mutable state and filesystem paths.

    Args:
        namespace: First-party object, relation, or observation namespace.
        value: Canonical immutable identity fields.

    Returns:
        Namespace-prefixed lowercase SHA-256 reference.
    """

    digest = hashlib.sha256(CanonicalModelJson({"namespace": namespace, "identity": value}))

    return f"{namespace}:{digest.hexdigest()}"


def RequireModelReference(value: object) -> str:
    """Reject malformed model references before lookup or relationship validation.

    Args:
        value: Namespace-prefixed lowercase SHA-256 reference.

    Returns:
        Validated reference without resolving its subject.

    Raises:
        ValueError: The reference does not use a known canonical namespace.
    """

    reference = RequireWorkspaceText(value, "model reference")

    if not _REFERENCE_PATTERN.fullmatch(reference):
        raise ValueError("model reference must be an object, relation, or observation digest")

    return reference


def CanonicalObjectKey(kind: ObjectKind, value: str) -> str:
    """Normalize obvious built-in identities offline while preserving opaque reference keys.

    Args:
        kind: Typed initial object family.
        value: DNS name, literal IP address, or explicit first-party canonical natural key.

    Returns:
        Canonical DNS/IP text or the opaque key unchanged; DNS is never resolved.

    Raises:
        ValueError: The kind, text, domain name, or literal host address is invalid.
    """

    if not isinstance(kind, ObjectKind):
        raise ValueError("kind must be an ObjectKind")

    RequireWorkspaceText(value, "object key")

    if len(value.encode("utf-8")) > 4096:
        raise ValueError("object key exceeds the size limit")

    if kind is ObjectKind.HOST:
        if "%" in value:
            raise ValueError("host address must not contain a machine-specific IPv6 zone")

        return str(ipaddress.ip_address(value))

    if kind is ObjectKind.DOMAIN:
        try:
            name = value.removesuffix(".").encode("idna").decode("ascii").lower()

        except UnicodeError as error:
            raise ValueError("domain key must be a valid IDNA name") from error

        if len(name) > 253 or not all(
            _DNS_LABEL_PATTERN.fullmatch(part) for part in name.split(".")
        ):
            raise ValueError("domain key must contain valid DNS labels")

        return name

    return value


def ModelAttributes(value: Mapping[str, object]) -> Mapping[str, object]:
    """Freeze bounded interpretation fields without retaining mutable provider payloads.

    Args:
        value: Non-secret normalized JSON attributes supplied explicitly by a caller.

    Returns:
        Recursively immutable mapping with deterministic key ordering.

    Raises:
        ValueError: Attributes are malformed, oversized, or excessively nested.
    """

    try:
        frozen = FreezeMapping(value)

    except RecursionError as error:
        raise ValueError("model attributes exceed the nesting bound") from error

    if len(CanonicalModelJson(frozen)) > MAX_ATTRIBUTE_BYTES:
        raise ValueError("model attributes exceed the size limit")

    return frozen


def ModelSequence(value: object, field_name: str) -> tuple[object, ...]:
    """Require an explicit collection rather than iterating text or arbitrary objects.

    Args:
        value: Tuple or list at a runtime or JSON boundary.
        field_name: Collection named in validation failures.

    Returns:
        Immutable sequence for subsequent element validation.

    Raises:
        ValueError: The input is not a list or tuple.
    """

    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{field_name} must be a sequence")

    return tuple(value)


@dataclass(frozen=True, slots=True)
class ObjectIdentity:
    """Bind a normalized natural key to one workspace and first-party object family."""

    workspace_id: str
    kind: ObjectKind
    key: str

    def __post_init__(self) -> None:
        """Freeze canonical identity without consulting a provider or filesystem."""

        RequireIdentifier(self.workspace_id, "workspace_id")
        object.__setattr__(self, "key", CanonicalObjectKey(self.kind, self.key))

        if self.kind is ObjectKind.WORKSPACE and self.key != self.workspace_id:
            raise ValueError("workspace projection key must match workspace_id")

    def Reference(self) -> str:
        """Return the stable reference shared by repeated discovery and all workflow lenses.

        Returns:
            Deterministic object reference independent of attributes and provider.
        """

        return ModelReference("object", self)


@dataclass(frozen=True, slots=True)
class ModelProvenance:
    """Attribute one interpretation without granting authority or embedding evidence bytes."""

    source_id: str
    run_reference: str
    observed_at: str
    scope_reference: str
    target_reference: str
    provider_version: str | None = None
    evidence_references: tuple[EvidenceReference, ...] = ()
    execution: AdapterExecution | None = None

    def __post_init__(self) -> None:
        """Canonicalize collection time and require typed, unique evidence and outcome fields."""

        RequireIdentifier(self.source_id, "source_id")

        for field_name in ("run_reference", "scope_reference", "target_reference"):
            RequireWorkspaceText(getattr(self, field_name), field_name)

        object.__setattr__(self, "observed_at", NormalizeEvidenceTime(self.observed_at))

        if self.provider_version is not None:
            RequireWorkspaceText(self.provider_version, "provider_version")

        if self.execution is not None:
            if not isinstance(self.execution, AdapterExecution):
                raise ValueError("execution must be an AdapterExecution or None")

            duration = self.execution.duration_seconds

            if isinstance(duration, bool) or not isinstance(duration, (int, float)):
                raise ValueError("execution duration must be a number, excluding booleans")

        evidence = ModelSequence(self.evidence_references, "evidence_references")
        validated: list[EvidenceReference] = []

        for reference in evidence:
            if not isinstance(reference, EvidenceReference):
                raise ValueError("evidence_references must contain EvidenceReference values")

            validated.append(DecodeEvidenceReference(JsonValue(reference)))

        identities = [(reference.locator, reference.role) for reference in validated]

        if len(set(identities)) != len(identities):
            raise ValueError("evidence references must be unique by locator and role")

        object.__setattr__(self, "evidence_references", tuple(sorted(
            validated, key=CanonicalModelJson,
        )))

    @classmethod
    def FromDict(cls, value: object) -> ModelProvenance:
        """Decode exact attribution fields while preserving terminal executor failure states.

        Args:
            value: Supported JSON provenance object.

        Returns:
            Validated immutable provenance.

        Raises:
            ValueError: Attribution, fields, evidence, time, or execution are malformed.
        """

        record = WorkspaceFields(value, {
            "source_id", "run_reference", "observed_at", "scope_reference", "target_reference",
            "provider_version", "evidence_references", "execution",
        }, "model provenance")
        outcome = record["execution"]
        execution = None

        if outcome is not None:
            details = WorkspaceFields(
                outcome, {"state", "exit_code", "duration_seconds"}, "model execution"
            )
            duration = details["duration_seconds"]
            exit_code = details["exit_code"]

            if isinstance(duration, bool) or not isinstance(duration, (int, float)):
                raise ValueError("execution duration must be a number")

            if exit_code is not None and (
                isinstance(exit_code, bool) or not isinstance(exit_code, int)
            ):
                raise ValueError("execution exit code must be an integer or None")

            execution = AdapterExecution(
                ExecutionState(RequireWorkspaceText(details["state"], "execution state")),
                exit_code, duration,
            )

        version = record["provider_version"]

        return cls(
            source_id=RequireWorkspaceText(record["source_id"], "source_id"),
            run_reference=RequireWorkspaceText(record["run_reference"], "run_reference"),
            observed_at=RequireWorkspaceText(record["observed_at"], "observed_at"),
            scope_reference=RequireWorkspaceText(record["scope_reference"], "scope_reference"),
            target_reference=RequireWorkspaceText(record["target_reference"], "target_reference"),
            provider_version=None if version is None else RequireWorkspaceText(version, "version"),
            evidence_references=tuple(DecodeEvidenceReference(item) for item in ModelSequence(
                record["evidence_references"], "evidence_references"
            )),
            execution=execution,
        )


def ProvenanceCollection(value: object) -> tuple[ModelProvenance, ...]:
    """Retain unique attribution records in deterministic order without dropping history.

    Args:
        value: Nonempty collection of typed immutable provenance records.

    Returns:
        Unique records sorted by their canonical JSON representation.

    Raises:
        ValueError: The collection is empty or contains an untyped record.
    """

    records = ModelSequence(value, "provenance")

    if not records or any(not isinstance(record, ModelProvenance) for record in records):
        raise ValueError("provenance must contain ModelProvenance values")

    typed_records = cast(tuple[ModelProvenance, ...], records)
    unique = {CanonicalModelJson(record): record for record in typed_records}

    return tuple(unique[key] for key in sorted(unique))


@dataclass(frozen=True, slots=True)
class SecurityObject:
    """Hold one current interpretation and all attribution in the shared canonical model."""

    identity: ObjectIdentity
    attributes: Mapping[str, object] = field(default_factory=dict)
    provenance: tuple[ModelProvenance, ...] = ()

    def __post_init__(self) -> None:
        """Require first-party typed identity and recursively immutable attributed fields."""

        if not isinstance(self.identity, ObjectIdentity):
            raise ValueError("identity must be an ObjectIdentity")

        object.__setattr__(self, "attributes", ModelAttributes(self.attributes))
        object.__setattr__(self, "provenance", ProvenanceCollection(self.provenance))

    def Reference(self) -> str:
        """Expose the identity reference used by relations, queries, and delta consumers.

        Returns:
            Canonical object identity reference.
        """

        return self.identity.Reference()


@dataclass(frozen=True, slots=True)
class Relation:
    """Store a typed, attributable edge without creating a second graph truth store."""

    kind: RelationKind
    source_reference: str
    target_reference: str
    attributes: Mapping[str, object] = field(default_factory=dict)
    provenance: tuple[ModelProvenance, ...] = ()

    def __post_init__(self) -> None:
        """Validate edge syntax; the enclosing snapshot validates endpoint existence."""

        if not isinstance(self.kind, RelationKind):
            raise ValueError("kind must be a RelationKind")

        for reference in (self.source_reference, self.target_reference):
            if not RequireModelReference(reference).startswith("object:"):
                raise ValueError("relation endpoints must be object references")

        object.__setattr__(self, "attributes", ModelAttributes(self.attributes))
        object.__setattr__(self, "provenance", ProvenanceCollection(self.provenance))

    def Reference(self) -> str:
        """Return a stable edge identity independent of mutable attributes and provenance.

        Returns:
            Canonical relation reference.
        """

        return ModelReference("relation", {
            "kind": self.kind.value, "source_reference": self.source_reference,
            "target_reference": self.target_reference,
        })


@dataclass(frozen=True, slots=True)
class Observation:
    """Preserve an immutable attributed fact separately from the current interpretation."""

    kind: str
    subject_reference: str
    attributes: Mapping[str, object]
    provenance: ModelProvenance

    def __post_init__(self) -> None:
        """Freeze a content-addressed observation with explicit subject and provenance."""

        RequireIdentifier(self.kind, "observation kind")
        RequireModelReference(self.subject_reference)

        if not isinstance(self.provenance, ModelProvenance):
            raise ValueError("provenance must be a ModelProvenance")

        object.__setattr__(self, "attributes", ModelAttributes(self.attributes))

    def Reference(self) -> str:
        """Identify an individual interpretation so exact replay does not duplicate evidence.

        Returns:
            Content-addressed observation reference including attributes and attribution.
        """

        return ModelReference("observation", self)


@dataclass(frozen=True, slots=True)
class ModelDelta:
    """Describe one immutable snapshot transition for future incremental UI consumers."""

    previous_revision: int
    revision: int
    created: tuple[str, ...] = ()
    updated: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Freeze canonical unique reference lists and validate the one-step transition."""

        RequireWorkspaceInteger(self.previous_revision, "previous_revision")
        RequireWorkspaceInteger(self.revision, "revision")

        for field_name in ("created", "updated"):
            references = tuple(RequireModelReference(value) for value in ModelSequence(
                getattr(self, field_name), field_name,
            ))

            if len(set(references)) != len(references):
                raise ValueError("delta references must be unique")

            object.__setattr__(self, field_name, tuple(sorted(references)))

        if set(self.created) & set(self.updated):
            raise ValueError("created and updated delta references must be disjoint")

        if self.revision != self.previous_revision + bool(self.created or self.updated):
            raise ValueError("delta revision must describe exactly one transition or a no-op")


@dataclass(frozen=True, slots=True)
class ModelState:
    """Own validated objects, relations, and observation history for one workspace."""

    workspace_id: str
    revision: int = 0
    objects: tuple[SecurityObject, ...] = ()
    relations: tuple[Relation, ...] = ()
    observations: tuple[Observation, ...] = ()

    def __post_init__(self) -> None:
        """Sort immutable state and reject duplicates, foreign objects, or dangling edges."""

        RequireIdentifier(self.workspace_id, "workspace_id")
        RequireWorkspaceInteger(self.revision, "revision")

        for field_name, expected in (
            ("objects", SecurityObject), ("relations", Relation), ("observations", Observation),
        ):
            records = ModelSequence(getattr(self, field_name), field_name)

            if any(not isinstance(record, expected) for record in records):
                raise ValueError(f"{field_name} must contain {expected.__name__} values")

            typed_records = cast(tuple[SecurityObject | Relation | Observation, ...], records)
            record_references = [record.Reference() for record in typed_records]

            if len(set(record_references)) != len(record_references):
                raise ValueError("model records must have unique references")

            object.__setattr__(self, field_name, tuple(sorted(
                typed_records, key=lambda record: record.Reference(),
            )))

        object_references = {item.Reference() for item in self.objects}

        if any(item.identity.workspace_id != self.workspace_id for item in self.objects):
            raise ValueError("objects must belong to the enclosing workspace")

        for relation in self.relations:
            if {relation.source_reference, relation.target_reference} - object_references:
                raise ValueError("relation endpoints must exist in the same model")

        subjects = object_references | {item.Reference() for item in self.relations}

        if any(item.subject_reference not in subjects for item in self.observations):
            raise ValueError("observation subject must be an existing object or relation")

    def Objects(self, kind: ObjectKind | None = None) -> tuple[SecurityObject, ...]:
        """Query a deterministic typed slice of the same authoritative snapshot.

        Args:
            kind: Optional object-family filter; None selects all objects.

        Returns:
            Objects ordered by canonical identity reference.

        Raises:
            ValueError: The filter is not a typed object kind.
        """

        if kind is not None and not isinstance(kind, ObjectKind):
            raise ValueError("kind must be an ObjectKind or None")

        return tuple(item for item in self.objects if kind is None or item.identity.kind is kind)

    def Apply(
        self, *, objects: tuple[SecurityObject, ...] = (), relations: tuple[Relation, ...] = (),
        observations: tuple[Observation, ...] = (),
    ) -> tuple[ModelState, ModelDelta]:
        """Apply attributable patches atomically in memory and preserve incoming fact history.

        Args:
            objects: Typed creations/attribute patches; supplied keys overwrite current values.
            relations: Typed edges/attribute patches with endpoints in the resulting model.
            observations: Explicit immutable facts with subjects in the resulting model.

        Returns:
            Validated new state and sorted created/updated references; exact replay is a no-op.

        Raises:
            ValueError: Input types, identity collisions, references, or final state are invalid.
        """

        entity_map: dict[str, SecurityObject | Relation] = {
            item.Reference(): item for item in self.objects
        }
        entity_map.update({item.Reference(): item for item in self.relations})
        observation_map = {item.Reference(): item for item in self.observations}
        created: set[str] = set()
        updated: set[str] = set()
        facts = list(ModelSequence(observations, "observations"))

        for incoming, expected in (
            (objects, SecurityObject), (relations, Relation),
        ):
            for item in ModelSequence(incoming, "patches"):
                if not isinstance(item, expected):
                    raise ValueError(f"patches must contain {expected.__name__} values")

                reference = item.Reference()
                current = entity_map.get(reference)
                merged = item

                if current is not None:
                    if isinstance(item, SecurityObject):
                        if (
                            not isinstance(current, SecurityObject)
                            or current.identity != item.identity
                        ):
                            raise ValueError("object reference collision")

                    elif not isinstance(current, Relation) or (
                        current.kind, current.source_reference, current.target_reference
                    ) != (item.kind, item.source_reference, item.target_reference):
                        raise ValueError("relation reference collision")

                    merged = replace(
                        item, attributes={**current.attributes, **item.attributes},
                        provenance=ProvenanceCollection((*current.provenance, *item.provenance)),
                    )

                if current != merged:
                    entity_map[reference] = merged
                    (created if current is None else updated).add(reference)

                for provenance in item.provenance:
                    facts.append(Observation(
                        "object-update" if isinstance(item, SecurityObject) else "relation-update",
                        reference, item.attributes, provenance,
                    ))

        for fact in facts:
            if not isinstance(fact, Observation):
                raise ValueError("observations must contain Observation values")

            reference = fact.Reference()
            current_fact = observation_map.get(reference)

            if current_fact is not None and current_fact != fact:
                raise ValueError("observation reference collision")

            if current_fact is None:
                observation_map[reference] = fact
                created.add(reference)

        updated -= created
        revision = self.revision + bool(created or updated)
        state = ModelState(
            self.workspace_id, revision,
            tuple(item for item in entity_map.values() if isinstance(item, SecurityObject)),
            tuple(item for item in entity_map.values() if isinstance(item, Relation)),
            tuple(observation_map.values()),
        )

        return state, ModelDelta(
            self.revision, revision, tuple(sorted(created)), tuple(sorted(updated)),
        )

    def ApplyAdapterResult(
        self, result: AdapterResult, bindings: Mapping[str, ObjectIdentity],
        provenance: ModelProvenance,
    ) -> tuple[ModelState, ModelDelta]:
        """Consume SDK envelopes through an explicit first-party identity/provenance boundary.

        Args:
            result: Normalized adapter result; findings remain outside this foundation.
            bindings: Provider subject references mapped explicitly to canonical identities.
            provenance: Caller-owned context matching adapter, target, version, evidence, outcome.

        Returns:
            Shared model update and delta; adapters cannot assign model IDs or write storage.

        Raises:
            ValueError: Context, envelopes, mapped kinds, or required identity bindings are invalid.
        """

        if not isinstance(result, AdapterResult) or not isinstance(provenance, ModelProvenance):
            raise ValueError("result and provenance must use typed contracts")

        report = result.report

        if not isinstance(report, AdapterReport) or not isinstance(bindings, Mapping):
            raise ValueError("report and bindings must use typed contracts")

        for values, expected in (
            (result.observations, NormalizedObservation),
            (result.object_enrichments, ObjectEnrichment),
            (result.relation_enrichments, RelationEnrichment),
        ):
            if any(not isinstance(value, expected) for value in values):
                raise ValueError("adapter enrichment envelopes must use typed contracts")

        report_evidence = tuple(sorted(report.evidence, key=CanonicalModelJson))

        if (
            provenance.source_id != report.invocation.adapter_id
            or provenance.target_reference != report.invocation.request.target_reference
            or provenance.provider_version != report.invocation.provider_version
            or provenance.execution != report.execution
            or provenance.evidence_references != report_evidence
        ):
            raise ValueError("adapter provenance must match the executor-owned report")

        identities: dict[str, ObjectIdentity] = {}

        for reference, identity in bindings.items():
            RequireWorkspaceText(reference, "provider reference")

            if (
                not isinstance(identity, ObjectIdentity)
                or identity.workspace_id != self.workspace_id
            ):
                raise ValueError("bindings must identify objects in this workspace")

            identities[reference] = identity

        try:
            objects = tuple(SecurityObject(
                identities[item.object_reference], item.attributes, (provenance,),
            ) for item in result.object_enrichments)

            for item in result.object_enrichments:
                if identities[item.object_reference].kind is not ObjectKind(item.object_kind):
                    raise ValueError("adapter object kind must match its first-party binding")

            relations = tuple(Relation(
                RelationKind(item.relation_kind), identities[item.source_reference].Reference(),
                identities[item.target_reference].Reference(), item.attributes, (provenance,),
            ) for item in result.relation_enrichments)
            observations = tuple(Observation(
                item.kind, identities[item.subject_reference].Reference(),
                item.attributes, provenance,
            ) for item in result.observations)

        except KeyError as error:
            raise ValueError(
                "adapter references require explicit first-party identity bindings"
            ) from error

        return self.Apply(objects=objects, relations=relations, observations=observations)

    def ToDict(self) -> dict[str, object]:
        """Render portable schema-versioned fields with recomputable identity references.

        Returns:
            Detached strict JSON-compatible snapshot containing no evidence bytes.
        """

        return {
            "schema_version": MODEL_SCHEMA_VERSION, "workspace_id": self.workspace_id,
            "revision": self.revision,
            "objects": [{"reference": item.Reference(), **cast(dict[str, object], JsonValue(item))}
                        for item in self.objects],
            "relations": [
                {"reference": item.Reference(), **cast(dict[str, object], JsonValue(item))}
                for item in self.relations
            ],
            "observations": [
                {"reference": item.Reference(), **cast(dict[str, object], JsonValue(item))}
                for item in self.observations
            ],
        }

    @classmethod
    def FromDict(cls, value: object) -> ModelState:
        """Validate a strict persisted snapshot rather than trusting serialized identities.

        Args:
            value: Supported JSON model document with duplicate keys already rejected.

        Returns:
            Validated immutable snapshot.

        Raises:
            ValueError: Schema, fields, IDs, types, attribution, or relationships are invalid.
        """

        record = WorkspaceFields(value, {
            "schema_version", "workspace_id", "revision", "objects", "relations", "observations",
        }, "model state")

        version = RequireWorkspaceInteger(record["schema_version"], "schema_version")

        if version != MODEL_SCHEMA_VERSION:
            raise ValueError("unsupported model schema version")

        objects: list[SecurityObject] = []
        relations: list[Relation] = []
        observations: list[Observation] = []

        for item in ModelSequence(record["objects"], "objects"):
            details = WorkspaceFields(
                item, {"reference", "identity", "attributes", "provenance"}, "security object"
            )
            identity = WorkspaceFields(
                details["identity"], {"workspace_id", "kind", "key"}, "identity"
            )
            parsed_object = SecurityObject(
                ObjectIdentity(
                    RequireWorkspaceText(identity["workspace_id"], "workspace_id"),
                    ObjectKind(RequireWorkspaceText(identity["kind"], "kind")),
                    RequireWorkspaceText(identity["key"], "key"),
                ),
                details["attributes"],  # type: ignore[arg-type]
                tuple(ModelProvenance.FromDict(value) for value in ModelSequence(
                    details["provenance"], "provenance"
                )),
            )
            RequireStoredReference(details["reference"], parsed_object.Reference())
            objects.append(parsed_object)

        for item in ModelSequence(record["relations"], "relations"):
            details = WorkspaceFields(item, {
                "reference", "kind", "source_reference", "target_reference",
                "attributes", "provenance",
            }, "relation")
            parsed_relation = Relation(
                RelationKind(RequireWorkspaceText(details["kind"], "kind")),
                RequireWorkspaceText(details["source_reference"], "source_reference"),
                RequireWorkspaceText(details["target_reference"], "target_reference"),
                details["attributes"],  # type: ignore[arg-type]
                tuple(ModelProvenance.FromDict(value) for value in ModelSequence(
                    details["provenance"], "provenance"
                )),
            )
            RequireStoredReference(details["reference"], parsed_relation.Reference())
            relations.append(parsed_relation)

        for item in ModelSequence(record["observations"], "observations"):
            details = WorkspaceFields(item, {
                "reference", "kind", "subject_reference", "attributes", "provenance",
            }, "observation")
            parsed_observation = Observation(
                RequireWorkspaceText(details["kind"], "kind"),
                RequireWorkspaceText(details["subject_reference"], "subject_reference"),
                details["attributes"],  # type: ignore[arg-type]
                ModelProvenance.FromDict(details["provenance"]),
            )
            RequireStoredReference(details["reference"], parsed_observation.Reference())
            observations.append(parsed_observation)

        return cls(
            RequireWorkspaceText(record["workspace_id"], "workspace_id"),
            RequireWorkspaceInteger(record["revision"], "revision"),
            tuple(objects), tuple(relations), tuple(observations),
        )


def RequireStoredReference(value: object, expected: str) -> None:
    """Reject a stored digest that does not reproduce from its declared identity fields.

    Args:
        value: Serialized canonical reference.
        expected: Recomputed reference from validated record fields.

    Raises:
        ValueError: The stored reference is malformed or disagrees with the record.
    """

    if RequireModelReference(value) != expected:
        raise ValueError("stored model reference disagrees with canonical identity")


@dataclass(frozen=True, slots=True)
class LocalModelStore:
    """Own a strict model snapshot beneath a validated operator-owned workspace.

    Construction performs no I/O. Hostile concurrent filesystem replacement is
    outside the portable path-based ownership contract.
    """

    root: Path

    def __post_init__(self) -> None:
        """Normalize the lexical workspace root without reading or mutating storage."""

        object.__setattr__(self, "root", LocalWorkspaceStore(self.root).root)

    def ValidatePaths(self) -> Path:
        """Validate workspace ownership and this subsystem's observed filesystem entries.

        Returns:
            Owned model directory beneath the current workspace root.

        Raises:
            ValueError: Workspace, model, lock, or document paths are unsafe.
            OSError: Path metadata or authoritative workspace metadata cannot be read.
        """

        LocalWorkspaceStore(self.root).Open()
        directory = self.root / "state" / "model"

        for path, directory_expected in (
            (directory, True), (directory / ".write-lock", True),
            (directory / "model.json", False),
        ):
            metadata = StoragePathInfo(path)

            if metadata is not None and (
                stat.S_ISDIR(metadata.st_mode) if directory_expected
                else stat.S_ISREG(metadata.st_mode)
            ) is False:
                raise ValueError("model paths have unsafe filesystem types")

            if metadata is not None and not directory_expected and metadata.st_nlink != 1:
                raise ValueError("authoritative model state must not be hard linked")

        return directory

    def Create(self) -> ModelState:
        """Initialize an empty model for an existing workspace without changing workspace metadata.

        Returns:
            Empty authoritative snapshot at revision zero.

        Raises:
            ValueError: Workspace or model storage is unsafe.
            OSError: The model namespace exists or creation/writing fails.
        """

        directory = self.ValidatePaths()
        workspace = LocalWorkspaceStore(self.root).Open()
        (self.root / "state").mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700)
        state = ModelState(workspace.workspace_id)
        self.WriteState(directory, state)
        SyncStorageDirectory(directory.parent)

        return state

    def Open(self) -> ModelState:
        """Read bounded model JSON and prove it belongs to the current workspace identity.

        Returns:
            Latest complete validated snapshot independent of cache/index availability.

        Raises:
            ValueError: State is corrupt, unsupported, oversized, foreign, or paths are unsafe.
            OSError: Authoritative state cannot be read.
        """

        directory = self.ValidatePaths()

        with (directory / "model.json").open("rb") as stream:
            payload = stream.read(MAX_MODEL_BYTES + 1)

        if len(payload) > MAX_MODEL_BYTES:
            raise ValueError("model state exceeds the size limit")

        try:
            document = json.loads(
                payload.decode("utf-8"), object_pairs_hook=UniqueWorkspaceObject,
                parse_constant=RejectWorkspaceConstant,
            )
            state = ModelState.FromDict(document)

        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise ValueError("model state must be bounded valid UTF-8 JSON") from error

        if state.workspace_id != LocalWorkspaceStore(self.root).Open().workspace_id:
            raise ValueError("model belongs to another workspace")

        return state

    def Save(self, state: ModelState, *, expected_revision: int) -> ModelState:
        """Commit one Apply transition under a fail-fast lock and expected-revision check.

        Args:
            state: Validated proposed snapshot returned by ModelState.Apply.
            expected_revision: Revision from which the proposed transition was computed.

        Returns:
            Committed snapshot; an exactly identical current-state replay does not write.

        Raises:
            WorkspaceConflictError: Identity or expected/proposed revision conflicts.
            WorkspaceBusyError: A live or abandoned writer owns the namespace lock.
            ValueError: State, revision, or observed paths are invalid.
            OSError: Writing/cleanup fails; reopen before retrying because commit may have occurred.
        """

        if not isinstance(state, ModelState):
            raise ValueError("state must be a ModelState")

        RequireWorkspaceInteger(expected_revision, "expected_revision")
        directory = self.ValidatePaths()
        lock = directory / ".write-lock"

        try:
            lock.mkdir(mode=0o700)

        except FileExistsError as error:
            raise WorkspaceBusyError(
                "model writer lock exists; never remove a live lock"
            ) from error

        try:
            current = self.Open()

            if current.workspace_id != state.workspace_id or current.revision != expected_revision:
                raise WorkspaceConflictError(
                    "model identity or revision changed; reopen before saving"
                )

            if current == state:
                return current

            if state.revision != current.revision + 1:
                raise WorkspaceConflictError("model save requires exactly one Apply transition")

            self.WriteState(directory, state)

            return state

        finally:
            lock.rmdir()

    def WriteState(self, directory: Path, state: ModelState) -> None:
        """Write private deterministic JSON; lifecycle callers own CAS and writer locking.

        Args:
            directory: Validated owned namespace directory.
            state: Validated proposed model snapshot.

        Raises:
            ValueError: The document exceeds its explicit size limit.
            OSError: Write, synchronization, replacement, or temporary-file cleanup fails.
        """

        payload = CanonicalModelJson(state.ToDict()) + b"\n"

        if len(payload) > MAX_MODEL_BYTES:
            raise ValueError("model state exceeds the size limit")

        temporary_path: Path | None = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=directory, prefix=".model-", suffix=".json", delete=False,
            ) as stream:
                temporary_path = Path(stream.name)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())

            os.replace(temporary_path, directory / "model.json")
            SyncStorageDirectory(directory)

        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
