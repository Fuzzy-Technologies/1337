# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental attributed offline transition projection and bounded candidate-path search."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from fuzzy1337.adapters import EvidenceReference, ExecutionState
from fuzzy1337.evidence import (
    EvidenceError,
    EvidenceRecord,
    LocalEvidenceStore,
    NormalizeEvidenceTime,
)
from fuzzy1337.model import (
    MAX_MODEL_BYTES,
    MODEL_SCHEMA_VERSION,
    CanonicalModelJson,
    LocalModelStore,
    ModelState,
    ObjectKind,
    Observation,
    RelationKind,
)

REACHABILITY_PROFILE_VERSION = 1
_ASSESSMENT_BYTES = 256 * 1024
_SUPPORT_BYTES = 64 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MODEL_REF = re.compile(r"(object|relation|observation):[0-9a-f]{64}\Z")
_MANIFEST_REF = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_ELIGIBLE = frozenset({ObjectKind.DOMAIN, ObjectKind.HOST, ObjectKind.ASSET, ObjectKind.PORT,
                      ObjectKind.SERVICE, ObjectKind.ENDPOINT, ObjectKind.TECHNOLOGY})
_VERIFIED = object()

__all__ = [
    "REACHABILITY_PROFILE_VERSION", "ReachabilityState", "ReachabilityModelVersion",
    "ReachabilityLimits", "ReadReachabilityClaims", "ProjectReachability",
    "SearchReachabilityPaths",
]


class ReachabilityState(StrEnum):
    """Summarize admitted supplied attestations without asserting network or execution authority."""

    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POTENTIAL = "POTENTIAL"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


def Integer(value: object, low: int, high: int) -> int:
    """Internal helper: validate exact integers before coercion or resource allocation.

    Args:
        value: Supplied bounded count or version.
        low: Inclusive minimum.
        high: Inclusive maximum.

    Returns:
        Unchanged valid integer.

    Raises:
        ValueError: A boolean, coerced number or out-of-range integer was supplied.
    """

    if type(value) is not int or not low <= value <= high:
        raise ValueError("reachability integers must use the exact supported range")

    return value


def Text(value: object) -> str:
    """Internal helper: require bounded non-secret caller metadata without reflecting its value.

    Args:
        value: Context, scope or workspace text.

    Returns:
        Unchanged bounded single-line UTF-8 text.

    Raises:
        ValueError: Text is absent, malformed, multiline or too large.
    """

    if not isinstance(value, str) or not value or len(value) > 256 or any(
        char in value for char in ("\x00", "\r", "\n")
    ):
        raise ValueError("reachability metadata must be bounded single-line text")

    try:
        value.encode("utf-8")

    except UnicodeError:
        raise ValueError("reachability metadata must be valid UTF-8") from None

    return value


def Reference(value: object, namespace: str) -> str:
    """Internal helper: check fixed-length references before an owned lookup.

    Args:
        value: Candidate digest reference.
        namespace: Required model namespace or sha256 manifest namespace.

    Returns:
        Exact canonical reference.

    Raises:
        ValueError: Namespace, grammar or reference length is unsupported.
    """

    pattern = _MANIFEST_REF if namespace == "sha256" else _MODEL_REF

    if not isinstance(value, str) or len(value) > 76 or not pattern.fullmatch(value) or (
        not value.startswith(namespace + ":")
    ):
        raise ValueError("reachability references must use the exact canonical namespace")

    return value


def Fields(value: object, names: set[str]) -> dict[str, object]:
    """Internal helper: refuse partial or extended version-one JSON record shapes.

    Args:
        value: Strictly decoded candidate object.
        names: Exact required fields.

    Returns:
        Supported JSON object.

    Raises:
        ValueError: The value has a wrong type, omitted field or extension.
    """

    if not isinstance(value, dict) or set(value) != names:
        raise ValueError("reachability records require exact version-one fields")

    return cast(dict[str, object], value)


def Items(value: object, maximum: int, minimum: int = 0) -> list[object]:
    """Internal helper: check list budgets before traversing declarations or proof joins.

    Args:
        value: Strictly decoded JSON list.
        maximum: Inclusive count bound.
        minimum: Inclusive minimum count.

    Returns:
        Original validated list.

    Raises:
        ValueError: Type or count does not fit the declared profile.
    """

    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValueError("reachability lists exceed the supported count range")

    return value


def Digest(value: object) -> str:
    """Internal helper: bind immutable query and declaration inputs by strict canonical JSON.

    Args:
        value: First-party supported identity fields.

    Returns:
        Prefixed lowercase SHA-256 identity.
    """

    return "sha256:" + hashlib.sha256(CanonicalModelJson(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class ReachabilityModelVersion:
    """Pin complete model contents independently of relation identity or revision alone."""

    schema_version: int
    workspace_id: str
    revision: int
    snapshot_sha256: str

    def __post_init__(self) -> None:
        """Refuse unsupported schemas, coercion and malformed complete snapshot pins."""

        Integer(self.schema_version, MODEL_SCHEMA_VERSION, MODEL_SCHEMA_VERSION)
        Text(self.workspace_id)

        if type(self.revision) is not int or self.revision < 0:
            raise ValueError("reachability model revision must be a nonnegative exact integer")

        if not isinstance(self.snapshot_sha256, str) or not _DIGEST.fullmatch(self.snapshot_sha256):
            raise ValueError("reachability model snapshot must use a lowercase SHA-256 digest")

    @classmethod
    def FromModel(cls, model: ModelState) -> ReachabilityModelVersion:
        """Derive a full snapshot pin through the existing canonical model serializer.

        Args:
            model: Exact immutable first-party model basis.

        Returns:
            Workspace, schema, revision and full content digest.

        Raises:
            ValueError: The basis is not a model or exceeds its owning size bound.
        """

        if not isinstance(model, ModelState):
            raise ValueError("reachability requires a first-party ModelState")

        try:
            payload = CanonicalModelJson(model.ToDict())

        except (ValueError, UnicodeError, RecursionError, OverflowError):
            raise ValueError("reachability basis must use its bounded canonical contract") from None

        if len(payload) > MAX_MODEL_BYTES:
            raise ValueError("reachability basis exceeds the owning model size limit")

        return cls(MODEL_SCHEMA_VERSION, model.workspace_id, model.revision,
                   hashlib.sha256(payload).hexdigest())


@dataclass(frozen=True, slots=True)
class ReachabilityLimits:
    """Bound deterministic search without coercing booleans or claiming unexplored completeness."""

    max_depth: int = 16
    max_paths: int = 64
    max_work: int = 4096
    max_frontier: int = 1024

    def __post_init__(self) -> None:
        """Validate the profile's exact inclusive positive query limits."""

        for name, maximum in (("max_depth", 32), ("max_paths", 256), ("max_work", 20000),
                              ("max_frontier", 4096)):
            Integer(getattr(self, name), 1, maximum)


@dataclass(frozen=True, slots=True)
class ReachabilityBasis:
    """Internal immutable output retaining an exact observation and verified support manifests."""

    observation_reference: str
    observation: Observation | None = field(repr=False)
    records: tuple[EvidenceRecord, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class ReachabilityControl:
    """Internal immutable output attributing a supplied barrier to one modeled control."""

    control_reference: str
    basis: ReachabilityBasis


@dataclass(frozen=True, slots=True)
class ReachabilityClaim:
    """Internal loader output preserving estimates even when admission is unusable or conflicted."""

    claim_reference: str
    relation_reference: str
    state: ReachabilityState
    confidence: int | float
    inference_rule: str | None
    model_version: ReachabilityModelVersion
    assessment: EvidenceRecord = field(repr=False)
    basis: tuple[ReachabilityBasis, ...] = field(repr=False)
    blocking_controls: tuple[ReachabilityControl, ...] = field(repr=False)
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReachabilityClaims:
    """Internal ephemeral owning-read output; construction alone verifies no source or raw bytes."""

    model_version: ReachabilityModelVersion
    context_reference: str
    scope_reference: str
    at: str
    max_age_seconds: int
    claims: tuple[ReachabilityClaim, ...] = field(repr=False)
    _seal: object = field(repr=False, compare=False)
    _proof_digest: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ReachabilityTransition:
    """Internal projection output retaining declarations and conservative per-hop resolution."""

    relation_reference: str
    source_reference: str
    target_reference: str
    state: ReachabilityState
    claims: tuple[ReachabilityClaim, ...] = field(repr=False)
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReachabilityProjection:
    """Internal frozen view of explicit model refs without storage or execution ownership."""

    model_version: ReachabilityModelVersion
    context_reference: str
    scope_reference: str
    at: str
    max_age_seconds: int
    nodes: tuple[str, ...]
    transitions: tuple[ReachabilityTransition, ...]
    projection_reference: str
    admitted_claims: int
    unusable_claims: int
    unassessed_transitions: int
    conflicting_transitions: int
    unknown_transitions: int
    _seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ReachabilityEstimate:
    """Retain one exact attributed numeric estimate without creating a path probability."""

    claim_reference: str
    relation_reference: str
    declared_state: ReachabilityState
    declared_confidence: int | float
    effective_confidence: int | float | None


@dataclass(frozen=True, slots=True)
class ReachabilityPath:
    """Internal path output with attested-hop-summary semantics and no aggregate confidence."""

    path_reference: str
    model_version: ReachabilityModelVersion
    nodes: tuple[str, ...]
    hops: tuple[ReachabilityTransition, ...]
    state: ReachabilityState
    confidence_estimates: tuple[ReachabilityEstimate, ...]
    decisive_blocking_claims: tuple[ReachabilityClaim, ...] = field(repr=False)
    semantics: str = "attested-hop-summary"


@dataclass(frozen=True, slots=True)
class ReachabilitySearch:
    """Internal query output distinguishing enumeration from proof and discovery completeness."""

    query_reference: str
    projection: ReachabilityProjection
    source_reference: str
    target_reference: str
    limits: ReachabilityLimits
    paths: tuple[ReachabilityPath, ...]
    complete: bool
    no_candidate_path: bool
    reasons: tuple[str, ...]
    examined_successors: int
    pending_prefixes: int
    unexamined_successors: int
    depth_cut_prefixes: int
    claim_scope: str = "selected-transition-subgraph-only"


def ClaimFields(claim: ReachabilityClaim) -> dict[str, object]:
    """Internal pure integrity helper: bind all admission fields and immutable proof identities.

    Args:
        claim: Owning-read output declaration with its exact retained attribution.

    Returns:
        Compact complete integrity fields without duplicating original support bytes or attributes.

    Raises:
        ValueError: An in-memory replacement no longer uses the declared typed state contract.
    """

    if not isinstance(claim, ReachabilityClaim) or not isinstance(claim.state, ReachabilityState):
        raise ValueError("reachability output declarations require exact typed admitted fields")

    Confidence(claim.confidence, claim.state)

    def BasisFields(proof: ReachabilityBasis) -> dict[str, object]:
        """Bind both declared and retained observation identities plus full immutable manifest IDs.

        Args:
            proof: Owning-read immutable basis or control support output.

        Returns:
            Compact complete proof identity fields.
        """

        return {"observation_reference": proof.observation_reference,
            "retained_observation_reference": (None if proof.observation is None
                                               else proof.observation.Reference()),
            "manifest_ids": [record.evidence_id for record in proof.records]}

    return {"claim_reference": claim.claim_reference,
        "relation_reference": claim.relation_reference, "state": claim.state,
        "confidence": claim.confidence, "inference_rule": claim.inference_rule,
        "model_version": claim.model_version,
        "assessment_manifest_id": claim.assessment.evidence_id,
        "basis": [BasisFields(proof) for proof in claim.basis],
        "blocking_controls": [{"control_reference": control.control_reference,
            "basis": BasisFields(control.basis)} for control in claim.blocking_controls],
        "reasons": claim.reasons}


def ClaimsDigest(claims: ReachabilityClaims) -> str:
    """Internal pure guard: detect changed fields on copied owning-read result wrappers.

    Args:
        claims: Ephemeral output of one owning verification read.

    Returns:
        Complete immutable output digest, never source authentication or execution permission.

    Raises:
        ValueError: Claims no longer fit the exact typed bounded output contract.
    """

    if not isinstance(claims.claims, tuple) or len(claims.claims) > 2048:
        raise ValueError("reachability output claims must retain their exact bounded tuple")

    return Digest({"model_version": claims.model_version,
        "context_reference": claims.context_reference, "scope_reference": claims.scope_reference,
        "at": claims.at, "max_age_seconds": claims.max_age_seconds,
        "claims": [ClaimFields(claim) for claim in claims.claims]})


def ProjectionDigest(projection: ReachabilityProjection) -> str:
    """Internal pure integrity helper: bind query-visible graph, proof and coverage fields.

    Args:
        projection: Complete immutable selected graph output.

    Returns:
        Canonical profile identity detecting changes on copied graph wrappers.
    """

    return Digest({"profile_version": REACHABILITY_PROFILE_VERSION,
        "model_version": projection.model_version,
        "context_reference": projection.context_reference,
        "scope_reference": projection.scope_reference, "at": projection.at,
        "max_age_seconds": projection.max_age_seconds, "nodes": projection.nodes,
        "transitions": [{"relation_reference": item.relation_reference,
            "source_reference": item.source_reference, "target_reference": item.target_reference,
            "claims": [ClaimFields(claim) for claim in item.claims], "state": item.state,
            "reasons": item.reasons} for item in projection.transitions],
        "coverage": {"admitted_claims": projection.admitted_claims,
            "unusable_claims": projection.unusable_claims,
            "unassessed_transitions": projection.unassessed_transitions,
            "conflicting_transitions": projection.conflicting_transitions,
            "unknown_transitions": projection.unknown_transitions}})


class BoundedEvidenceStore(LocalEvidenceStore):
    """Internal read facade keeping manifest ownership while guarding actual blob allocation."""

    def __init__(self, root: Path, maximum: int) -> None:
        """Retain an explicit read ceiling without touching the owning filesystem.

        Args:
            root: Existing operator-owned evidence directory.
            maximum: Assessment or support blob byte ceiling.
        """

        super().__init__(root)
        self.maximum = maximum

    def Read(self, reference: EvidenceReference) -> bytes:
        """Check the actual parsed size before Get delegates to the owning raw-byte reader.

        Args:
            reference: Caller or manifest's parsed original adapter evidence reference.

        Returns:
            Original bytes after complete owning integrity verification.

        Raises:
            ValueError: Actual reference size exceeds the selected profile budget.
            EvidenceError: The owner cannot verify immutable stored content.
        """

        if not isinstance(reference, EvidenceReference):
            raise ValueError("reachability evidence requires an adapter reference")

        Integer(reference.size_bytes, 0, self.maximum)

        return super().Read(reference)


def UniqueFields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Internal JSON hook: refuse duplicate keys at every depth without reflecting their names.

    Args:
        pairs: Parser-produced ordered object fields.

    Returns:
        Unique detached field mapping.

    Raises:
        ValueError: A duplicate field occurs.
    """

    result: dict[str, object] = {}

    for name, value in pairs:
        if name in result:
            raise ValueError("reachability JSON object fields must be unique")

        result[name] = value

    return result


def RejectConstant(value: str) -> object:
    """Internal JSON hook: refuse nonfinite named constants without reflecting their spelling.

    Args:
        value: Parser-supplied unsupported numeric constant.

    Returns:
        No value; this parser hook always raises instead of accepting a constant.

    Raises:
        ValueError: Named constants are outside strict JSON.
    """

    raise ValueError("reachability JSON forbids nonfinite constants")


def AssessmentJson(raw: bytes) -> dict[str, object]:
    """Internal parser: bound UTF-8 JSON bytes, depth and total nodes before interpretation.

    Args:
        raw: Owned verified assessment bytes.

    Returns:
        Strict finite top-level JSON object.

    Raises:
        ValueError: JSON, Unicode, numeric values or budgets violate the profile.
    """

    if not isinstance(raw, bytes) or len(raw) > _ASSESSMENT_BYTES:
        raise ValueError("reachability assessment exceeds the byte limit")

    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=UniqueFields,
                             parse_constant=RejectConstant)
        pending: list[tuple[object, int]] = [(payload, 1)]
        count = 0

        while pending:
            item, depth = pending.pop()
            count += 1

            if count > 8000 or depth > 16:
                raise ValueError("reachability JSON exceeds structural budgets")

            if isinstance(item, dict):
                pending.extend((value, depth + 1) for value in item.values())
                pending.extend((key, depth + 1) for key in item)

            elif isinstance(item, list):
                pending.extend((value, depth + 1) for value in item)

            elif isinstance(item, str):
                item.encode("utf-8")

            elif isinstance(item, float) and not math.isfinite(item):
                raise ValueError("reachability JSON numbers must be finite")

        if not isinstance(payload, dict):
            raise ValueError("reachability assessment must be a JSON object")

        return cast(dict[str, object], payload)

    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ValueError("reachability assessment requires strict bounded UTF-8 JSON") from None


def Version(value: object) -> ReachabilityModelVersion:
    """Internal parser: interpret the exact complete version-one model basis pin.

    Args:
        value: Strictly decoded model_version object.

    Returns:
        Validated full snapshot pin.

    Raises:
        ValueError: Fields, types or digest grammar are unsupported.
    """

    record = Fields(value, {"schema_version", "workspace_id", "revision", "snapshot_sha256"})

    return ReachabilityModelVersion(
        cast(int, record["schema_version"]), cast(str, record["workspace_id"]),
        cast(int, record["revision"]), cast(str, record["snapshot_sha256"]),
    )


def Confidence(value: object, state: ReachabilityState) -> int | float:
    """Internal validator: preserve inclusive supplied estimates without rounding or overflow.

    Args:
        value: Original JSON or direct caller numeric estimate.
        state: Explicit declared label, never derived from that number.

    Returns:
        Unchanged integer or float estimate in the state's literal inclusive band.

    Raises:
        ValueError: Type, finiteness or exact state band is invalid.
    """

    bands = {ReachabilityState.UNKNOWN: (0.0, 0.0), ReachabilityState.POTENTIAL: (0.40, 0.69),
             ReachabilityState.LIKELY: (0.70, 0.89), ReachabilityState.CONFIRMED: (0.90, 1.0),
             ReachabilityState.BLOCKED: (0.90, 1.0)}

    if type(value) not in (int, float):
        raise ValueError("reachability confidence must be a supplied finite numeric estimate")

    number = cast(int | float, value)
    low, high = bands[state]

    if not low <= number <= high or (type(number) is float and not math.isfinite(number)):
        raise ValueError("reachability confidence falls outside the literal inclusive state band")

    return number


def Time(value: str) -> str:
    """Internal helper: normalize explicit aware time without leaking malformed source literals.

    Args:
        value: Caller-provided timestamp text with an explicit offset.

    Returns:
        Canonical UTC timestamp without consulting a clock.

    Raises:
        ValueError: Time is malformed, naive or outside the supported datetime range.
    """

    try:
        return NormalizeEvidenceTime(Text(value))

    except (ValueError, OverflowError):
        raise ValueError("reachability time requires a bounded aware ISO timestamp") from None


def TimeReasons(record: EvidenceRecord, at: str, maximum_age: int, label: str) -> set[str]:
    """Internal helper: assess explicit source intervals against one fixed supplied query time.

    Args:
        record: Owned verified manifest with canonical source collection times.
        at: Fixed canonical assessment time.
        maximum_age: Inclusive allowed age in seconds.
        label: First-party support or assessment reason namespace.

    Returns:
        Stable unusability reason labels, with no probability or invented snapshot timestamp.
    """

    reasons: set[str] = set()
    current = datetime.fromisoformat(at)

    for timestamp in (record.provenance.started_at, record.provenance.finished_at):
        age = (current - datetime.fromisoformat(timestamp)).total_seconds()

        if age < 0:
            reasons.add("future-" + label)

        elif age > maximum_age:
            reasons.add("stale-" + label)

    return reasons


def VerifiedRecord(store: BoundedEvidenceStore, identity: str) -> EvidenceRecord:
    """Internal boundary: preserve owning evidence failure categories with sanitized tracebacks.

    Args:
        store: Existing owner with an allocation-bound Read facade.
        identity: Prevalidated immutable manifest ID.

    Returns:
        Owned record after manifest and original raw-byte verification.

    Raises:
        EvidenceError: Stored evidence cannot be verified.
        ValueError: An actual parsed reference exceeds its selected allocation budget.
    """

    try:
        return store.Get(identity)

    except EvidenceError as error:
        raise type(error)("reachability evidence verification failed") from None

    except (ValueError, OSError, OverflowError):
        raise ValueError("reachability evidence violates its bounded owning contract") from None


def CurrentBasis(model: ModelState, expected: ReachabilityModelVersion, root: Path) -> None:
    """Internal read boundary: prove the supplied basis equals one current owning snapshot read.

    Args:
        model: Immutable caller basis.
        expected: Complete required content pin.
        root: Existing operator-owned workspace.

    Raises:
        ValueError: Model, persisted basis or owning path validation fails.
    """

    if not isinstance(expected, ReachabilityModelVersion) or (
        ReachabilityModelVersion.FromModel(model) != expected
    ):
        raise ValueError("reachability requires the exact supplied model version")

    try:
        persisted = LocalModelStore(root).Open()

    except (ValueError, OSError, OverflowError, EvidenceError):
        raise ValueError("reachability current owning model could not be verified") from None

    if ReachabilityModelVersion.FromModel(persisted) != expected:
        raise ValueError("reachability basis differs from the current owning model read")


def ProofEntry(value: object, control: bool = False) -> dict[str, object]:
    """Internal parser: canonicalize one bounded proof entry without discarding identifiers.

    Args:
        value: Original decoded basis or control entry.
        control: Whether a modeled control_reference is mandatory.

    Returns:
        Exact fields with canonical unique manifest-ID ordering.

    Raises:
        ValueError: Shape, reference grammar or per-entry uniqueness is invalid.
    """

    names = {"observation_reference", "evidence_manifest_ids"}

    if control:
        names.add("control_reference")

    record = Fields(value, names)
    observation = Reference(record["observation_reference"], "observation")
    identities = [Reference(item, "sha256") for item in Items(
        record["evidence_manifest_ids"], 16, 1 if control else 0,
    )]

    if len(set(identities)) != len(identities):
        raise ValueError("reachability proof manifest IDs must be unique")

    result: dict[str, object] = {"observation_reference": observation,
                                "evidence_manifest_ids": sorted(identities)}

    if control:
        result["control_reference"] = Reference(record["control_reference"], "object")

    return result


def Declaration(value: object) -> dict[str, object]:
    """Internal parser: validate and canonicalize exact supplied state and proof grammar.

    Args:
        value: One original strict JSON declaration.

    Returns:
        Complete normalized declaration retaining its original numeric estimate.

    Raises:
        ValueError: State, estimate, rule, proof shape or identity is invalid.
    """

    record = Fields(value, {"relation_reference", "state", "confidence", "inference_rule",
                           "basis", "blocking_controls"})
    reference = Reference(record["relation_reference"], "relation")

    try:
        state = ReachabilityState(cast(str, record["state"]))

    except (ValueError, TypeError):
        raise ValueError("reachability state must be an exact profile label") from None

    confidence = Confidence(record["confidence"], state)
    rule = record["inference_rule"]

    if state is ReachabilityState.LIKELY:
        if not isinstance(rule, str) or not _IDENTIFIER.fullmatch(rule):
            raise ValueError("likely reachability requires a bounded supplied inference identifier")

    elif rule is not None:
        raise ValueError("only likely reachability accepts a supplied inference identifier")

    basis = [ProofEntry(entry) for entry in Items(record["basis"], 16)]
    controls = [ProofEntry(entry, control=True) for entry in Items(
        record["blocking_controls"], 16, 1 if state is ReachabilityState.BLOCKED else 0,
    )]

    if state is not ReachabilityState.BLOCKED and controls:
        raise ValueError("only blocked declarations accept modeled blocking controls")

    for entries, key in ((basis, "observation_reference"), (controls, "control_reference")):
        if len({cast(str, entry[key]) for entry in entries}) != len(entries):
            raise ValueError("reachability proof entries must be unique by their subject")

    return {"relation_reference": reference, "state": state.value, "confidence": confidence,
            "inference_rule": rule,
            "basis": sorted(basis, key=lambda entry: cast(str, entry["observation_reference"])),
            "blocking_controls": sorted(controls, key=lambda entry: cast(
                str, entry["control_reference"],
            ))}


@dataclass(slots=True)
class ProofReader:
    """Internal per-call join context; no durable proof cache or alternate model ownership."""

    model: ModelState
    store: BoundedEvidenceStore
    at: str
    maximum_age: int
    scope: str
    observations: dict[str, Observation]
    records: dict[str, EvidenceRecord] = field(default_factory=dict)

    def Basis(
        self, entry: dict[str, object], subject: str, assessment: EvidenceRecord,
    ) -> tuple[ReachabilityBasis, set[str]]:
        """Verify an exact retained observation and the complete manifest-backed support join.

        Args:
            entry: Canonical bounded proof record.
            subject: Explicit transition or control subject.
            assessment: Owning source attestation manifest.

        Returns:
            Immutable proof attribution and explicit temporal/missing/outcome reasons.

        Raises:
            ValueError: Provenance, subject or evidence coverage is substituted.
            EvidenceError: A selected manifest or original artifact cannot be verified.
        """

        reference = cast(str, entry["observation_reference"])
        observation = self.observations.get(reference)
        identities = cast(list[str], entry["evidence_manifest_ids"])
        reasons: set[str] = set()
        selected: list[EvidenceRecord] = []

        if not identities:
            reasons.add("missing-evidence")

        for identity in identities:
            if identity not in self.records:
                if len(self.records) >= 256:
                    raise ValueError("reachability supporting manifest count exceeds its bound")

                self.records[identity] = VerifiedRecord(self.store, identity)

            record = self.records[identity]
            selected.append(record)

            if record.provenance.workspace_id != self.model.workspace_id or (
                record.provenance.scope_reference != self.scope
            ):
                raise ValueError("reachability support belongs to a different workspace or scope")

            reasons.update(TimeReasons(record, self.at, self.maximum_age, "support"))

            if record.provenance.finished_at > assessment.provenance.started_at:
                reasons.add("time-order")

            if record.provenance.execution is not None and (
                record.provenance.execution.state is not ExecutionState.SUCCEEDED
            ):
                reasons.add("failed-support")

        if observation is None:
            reasons.add("missing-basis")

        else:
            if observation.kind != "reachability-support" or (
                observation.subject_reference != subject
            ):
                raise ValueError("reachability basis does not address the exact selected subject")

            provenance = observation.provenance

            if provenance.scope_reference != self.scope:
                raise ValueError("reachability observation belongs to a different scope")

            if selected:
                references = [CanonicalModelJson(record.reference) for record in selected]

                if len(set(references)) != len(references) or set(references) != {
                    CanonicalModelJson(reference) for reference in provenance.evidence_references
                }:
                    raise ValueError("reachability manifests must cover exact observation evidence")

            elif provenance.evidence_references:
                reasons.add("missing-evidence")

            for record in selected:
                actual = record.provenance

                if (actual.source_id, actual.tool_version, actual.scope_reference,
                    actual.finished_at, actual.execution) != (
                    provenance.source_id, provenance.provider_version, provenance.scope_reference,
                    provenance.observed_at, provenance.execution,
                ):
                    raise ValueError("reachability support provenance differs from retained basis")

            age = (datetime.fromisoformat(self.at)
                   - datetime.fromisoformat(provenance.observed_at)).total_seconds()

            if age < 0:
                reasons.add("future-support")

            elif age > self.maximum_age:
                reasons.add("stale-support")

            if provenance.observed_at > assessment.provenance.started_at:
                reasons.add("time-order")

        return ReachabilityBasis(reference, observation, tuple(selected)), reasons


def ReadReachabilityClaims(
    model: ModelState, assessment_records: tuple[EvidenceRecord, ...], *, workspace_root: Path,
    expected_model_version: ReachabilityModelVersion, context_reference: str,
    scope_reference: str, at: str, max_age_seconds: int = 3600,
) -> ReachabilityClaims:
    """Verify explicit offline source attestations against one exact current persisted model read.

    Args:
        model: Immutable current model basis with retained support observations.
        assessment_records: Explicit immutable assessment records, never retrieval URLs.
        workspace_root: Existing operator-owned workspace used through its storage owners.
        expected_model_version: Complete required schema/workspace/revision/content pin.
        context_reference: Exact non-secret assessment context, granting no identity authority.
        scope_reference: Exact attributable collection scope, granting no execution permission.
        at: Explicit offset-aware ISO timestamp; no clock is read.
        max_age_seconds: Inclusive allowed age, exact integer from zero to seven days.

    Returns:
        Frozen per-call verified attestations with exact attribution and unusability reasons.

    Raises:
        ValueError: Basis, bounds, grammar, scope, context or source joins are invalid.
        EvidenceError: A selected owning manifest or original blob cannot be verified.
    """

    current_at = Time(at)
    maximum_age = Integer(max_age_seconds, 0, 604800)
    context = Text(context_reference)
    scope = Text(scope_reference)

    if not isinstance(assessment_records, tuple) or len(assessment_records) > 32 or any(
        not isinstance(record, EvidenceRecord) for record in assessment_records
    ):
        raise ValueError("reachability assessments require an explicit bounded record tuple")

    for record in assessment_records:
        Reference(record.evidence_id, "sha256")
        Integer(record.reference.size_bytes, 0, _ASSESSMENT_BYTES)

    CurrentBasis(model, expected_model_version, workspace_root)
    directory = LocalModelStore(workspace_root).root / "evidence"
    assessment_store = BoundedEvidenceStore(directory, _ASSESSMENT_BYTES)
    reader = ProofReader(model, BoundedEvidenceStore(directory, _SUPPORT_BYTES), current_at,
                         maximum_age, scope,
                         {item.Reference(): item for item in model.observations})
    objects = {item.Reference(): item for item in model.objects}
    relations = {item.Reference(): item for item in model.relations}
    verified: dict[str, EvidenceRecord] = {}
    claims: list[ReachabilityClaim] = []

    for supplied in assessment_records:
        identity = supplied.evidence_id

        if identity in verified:
            if supplied != verified[identity]:
                raise ValueError("reachability replay differs from the verified immutable manifest")

            continue

        record = VerifiedRecord(assessment_store, identity)

        if record != supplied:
            raise ValueError("reachability supplied record differs from the stored manifest")

        verified[identity] = record
        provenance = record.provenance

        if record.reference.role != "reachability-claims" or (
            record.reference.media_type != "application/json" or provenance.source_version != "1"
            or provenance.invocation_sha256 is not None or provenance.execution is not None
        ):
            raise ValueError("reachability assessment manifest violates profile-one provenance")

        if provenance.workspace_id != model.workspace_id or provenance.scope_reference != scope:
            raise ValueError("reachability assessment belongs to another workspace or scope")

        try:
            raw = assessment_store.Read(record.reference)

        except EvidenceError as error:
            raise type(error)("reachability assessment bytes could not be verified") from None

        envelope = Fields(AssessmentJson(raw), {"profile_version", "assessment_kind",
                          "model_version", "context_reference", "scope_reference", "claims"})
        Integer(envelope["profile_version"], 1, 1)

        if envelope["assessment_kind"] != "supplied-transition-attestation":
            raise ValueError("reachability assessment requires the exact supplied-attestation kind")

        version = Version(envelope["model_version"])

        if version.workspace_id != model.workspace_id or Text(envelope["context_reference"]) != (
            context
        ) or Text(envelope["scope_reference"]) != scope:
            raise ValueError("reachability envelope substitutes workspace, context or scope")

        declarations = Items(envelope["claims"], 2048)

        if len(claims) + len(declarations) > 2048:
            raise ValueError("reachability total declaration count exceeds its bound")

        seen: set[str] = set()
        header = {key: value for key, value in envelope.items() if key != "claims"}

        for supplied_declaration in declarations:
            declaration = Declaration(supplied_declaration)
            claim_id = Digest({"assessment_manifest_id": identity, "envelope": header,
                               "declaration": declaration})

            if claim_id in seen:
                raise ValueError("reachability declaration identity repeats within one artifact")

            seen.add(claim_id)
            reference = cast(str, declaration["relation_reference"])
            relation = relations.get(reference)
            state = ReachabilityState(cast(str, declaration["state"]))
            reasons = TimeReasons(record, current_at, maximum_age, "assessment")

            if version != expected_model_version:
                reasons.add("stale-model")

            if relation is None:
                if version == expected_model_version:
                    raise ValueError("reachability declaration requires an existing relation")

                reasons.add("missing-transition")

            elif relation.kind is not RelationKind.RELATED_TO:
                raise ValueError("reachability declarations require explicit RELATED_TO edges")

            basis: list[ReachabilityBasis] = []

            for entry in cast(list[dict[str, object]], declaration["basis"]):
                proof, proof_reasons = reader.Basis(entry, reference, record)
                basis.append(proof)
                reasons.update(proof_reasons)

            if state is not ReachabilityState.UNKNOWN:
                if not basis:
                    reasons.add("missing-basis")

                if not any(proof.records for proof in basis):
                    reasons.add("missing-evidence")

            controls: list[ReachabilityControl] = []

            for entry in cast(list[dict[str, object]], declaration["blocking_controls"]):
                control_ref = cast(str, entry["control_reference"])
                control = objects.get(control_ref)

                if control is None:
                    reasons.add("missing-control")

                elif control.identity.kind is not ObjectKind.ASSET or (
                    control.attributes.get("asset_type") != "reachability-control"
                ):
                    raise ValueError("reachability barrier requires a modeled control asset")

                proof, proof_reasons = reader.Basis(entry, control_ref, record)
                reasons.update(proof_reasons)
                controls.append(ReachabilityControl(control_ref, proof))

            claims.append(ReachabilityClaim(
                claim_id, reference, state, cast(int | float, declaration["confidence"]),
                cast(str | None, declaration["inference_rule"]), version, record, tuple(basis),
                tuple(controls), tuple(sorted(reasons)),
            ))

    result = ReachabilityClaims(expected_model_version, context, scope, current_at, maximum_age,
                                tuple(sorted(claims, key=lambda claim: claim.claim_reference)),
                                _VERIFIED, "")

    return replace(result, _proof_digest=ClaimsDigest(result))


def ExactBasis(model: ModelState, expected: ReachabilityModelVersion) -> None:
    """Internal pure guard: refuse revision-only or equal-revision content substitution.

    Args:
        model: Caller-supplied exact immutable basis.
        expected: Complete pin retained by the derived output.

    Raises:
        ValueError: Snapshot schema, workspace, revision or contents differ.
    """

    if not isinstance(expected, ReachabilityModelVersion) or (
        ReachabilityModelVersion.FromModel(model) != expected
    ):
        raise ValueError("reachability derived view requires the exact pinned ModelState")


def ProjectReachability(
    model: ModelState, transition_references: tuple[str, ...], claims: ReachabilityClaims, *,
    expected_model_version: ReachabilityModelVersion,
) -> ReachabilityProjection:
    """Purely project explicitly selected transitions with conservative supplied-claim admission.

    Args:
        model: Exact current immutable basis previously verified through its owner.
        transition_references: Explicit distinct RELATED_TO refs; no relation is inferred.
        claims: Internal immutable output from ReadReachabilityClaims, never source authority.
        expected_model_version: Complete required basis pin.

    Returns:
        Frozen selected graph preserving every claim and separate proof-admission coverage.

    Raises:
        ValueError: Model, loaded output, selected kinds or resource bounds are invalid.
    """

    ExactBasis(model, expected_model_version)

    if not isinstance(claims, ReachabilityClaims) or claims._seal is not _VERIFIED or (
        claims.model_version != expected_model_version
        or claims._proof_digest != ClaimsDigest(claims)
    ):
        raise ValueError("reachability projection requires matching owning-read claim output")

    if not isinstance(transition_references, tuple) or len(transition_references) > 2048:
        raise ValueError("reachability selection requires a bounded explicit reference tuple")

    selected = [Reference(reference, "relation") for reference in transition_references]

    if len(set(selected)) != len(selected):
        raise ValueError("reachability selected transition references must be unique")

    nodes = tuple(sorted(item.Reference() for item in model.objects
                         if item.identity.kind in _ELIGIBLE))

    if len(nodes) > 512:
        raise ValueError("reachability eligible model node count exceeds its bound")

    eligible = set(nodes)
    relations = {item.Reference(): item for item in model.relations}
    by_relation: dict[str, list[ReachabilityClaim]] = {}

    for claim in claims.claims:
        by_relation.setdefault(claim.relation_reference, []).append(claim)

    transitions: list[ReachabilityTransition] = []

    for reference in sorted(selected):
        relation = relations.get(reference)

        if relation is None or relation.kind is not RelationKind.RELATED_TO or (
            relation.source_reference not in eligible or relation.target_reference not in eligible
        ):
            raise ValueError("reachability edges require eligible existing RELATED_TO endpoints")

        declarations = tuple(sorted(by_relation.get(reference, ()), key=lambda item:
                                    item.claim_reference))
        states = {claim.state for claim in declarations if not claim.reasons}
        reasons = {reason for claim in declarations for reason in claim.reasons}

        if not declarations:
            reasons.add("unassessed")

        if len(states) > 1:
            reasons.add("conflicting-states")

        state = (next(iter(states)) if len(states) == 1 and not reasons
                 else ReachabilityState.UNKNOWN)
        transitions.append(ReachabilityTransition(reference, relation.source_reference,
            relation.target_reference, state, declarations, tuple(sorted(reasons))))

    retained = [claim for transition in transitions for claim in transition.claims]

    result = ReachabilityProjection(expected_model_version, claims.context_reference,
        claims.scope_reference, claims.at, claims.max_age_seconds, nodes, tuple(transitions),
        "", sum(not claim.reasons for claim in retained),
        sum(bool(claim.reasons) for claim in retained),
        sum(not transition.claims for transition in transitions),
        sum("conflicting-states" in transition.reasons for transition in transitions),
        sum(transition.state is ReachabilityState.UNKNOWN for transition in transitions), _VERIFIED)

    return replace(result, projection_reference=ProjectionDigest(result))


def CandidatePath(
    projection: ReachabilityProjection, nodes: tuple[str, ...],
    hops: tuple[ReachabilityTransition, ...],
) -> ReachabilityPath:
    """Internal pure classifier: apply barrier precedence after conservative per-hop handling.

    Args:
        projection: Exact immutable selected graph.
        nodes: Simple ordered candidate node sequence.
        hops: Ordered admitted or uncertain selected transitions.

    Returns:
        Attested hop summary, per-claim estimates and exact decisive blocking declarations.
    """

    states = {hop.state for hop in hops}
    state = next(label for label in (ReachabilityState.BLOCKED, ReachabilityState.UNKNOWN,
        ReachabilityState.POTENTIAL, ReachabilityState.LIKELY, ReachabilityState.CONFIRMED)
        if label in states)
    estimates = tuple(ReachabilityEstimate(claim.claim_reference, hop.relation_reference,
        claim.state, claim.confidence, claim.confidence if not hop.reasons else None)
        for hop in hops for claim in hop.claims)
    blockers = tuple(claim for hop in hops if hop.state is ReachabilityState.BLOCKED
                     for claim in hop.claims if not claim.reasons)
    identity = Digest({"projection_reference": projection.projection_reference, "nodes": nodes,
                       "relations": [hop.relation_reference for hop in hops]})

    return ReachabilityPath(identity, projection.model_version, nodes, hops, state, estimates,
                            blockers)


def SearchReachabilityPaths(
    projection: ReachabilityProjection, model: ModelState, source_reference: str,
    target_reference: str, *, limits: ReachabilityLimits = ReachabilityLimits(),
) -> ReachabilitySearch:
    """Enumerate bounded deterministic simple candidate paths without I/O or physical-path claims.

    Args:
        projection: Internal frozen projection with its fixed verified basis/time/context.
        model: Exact immutable pinned model, rechecked before pure search.
        source_reference: Existing eligible source object, distinct from target.
        target_reference: Existing eligible target object, distinct from source.
        limits: Exact positive bounded depth, work, frontier and returned-path limits.

    Returns:
        Canonically ordered candidates and truthful selected-subgraph completeness/truncation.

    Raises:
        ValueError: Projection, basis, endpoints or limit contract is invalid.
    """

    if not isinstance(projection, ReachabilityProjection) or projection._seal is not _VERIFIED or (
        ProjectionDigest(projection) != projection.projection_reference
    ):
        raise ValueError("reachability search requires an owning-read derived projection")

    ExactBasis(model, projection.model_version)

    if not isinstance(limits, ReachabilityLimits):
        raise ValueError("reachability search requires typed exact bounded limits")

    source = Reference(source_reference, "object")
    target = Reference(target_reference, "object")

    if source == target or source not in projection.nodes or target not in projection.nodes:
        raise ValueError("reachability query requires distinct existing eligible endpoints")

    outgoing: dict[str, list[ReachabilityTransition]] = {}

    for transition in projection.transitions:
        outgoing.setdefault(transition.source_reference, []).append(transition)

    for successors in outgoing.values():
        successors.sort(key=lambda item: item.relation_reference)

    queue: deque[tuple[tuple[str, ...], tuple[ReachabilityTransition, ...]]] = deque([
        ((source,), ()),
    ])
    paths: list[ReachabilityPath] = []
    reasons: set[str] = set()
    work = 0
    unexamined = 0
    depth_cuts = 0
    stopped = False
    deferred_prefix = 0

    while queue and not stopped:
        nodes, hops = queue.popleft()
        successors = outgoing.get(nodes[-1], [])

        for index, transition in enumerate(successors):
            if work == limits.max_work:
                reasons.add("work-limit")
                unexamined = len(successors) - index
                deferred_prefix = 1
                stopped = True
                break

            work += 1

            if transition.target_reference in nodes:
                continue

            if len(hops) == limits.max_depth:
                reasons.add("depth-limit")
                depth_cuts += 1
                continue

            next_nodes = (*nodes, transition.target_reference)
            next_hops = (*hops, transition)

            if transition.target_reference == target:
                paths.append(CandidatePath(projection, next_nodes, next_hops))

                if len(paths) == limits.max_paths and (index + 1 < len(successors) or queue):
                    reasons.add("path-limit")
                    unexamined = len(successors) - index - 1
                    deferred_prefix = int(bool(unexamined))
                    stopped = True
                    break

            else:
                if len(queue) == limits.max_frontier:
                    reasons.add("frontier-limit")
                    unexamined = len(successors) - index - 1
                    deferred_prefix = 1 + int(bool(unexamined))
                    stopped = True
                    break

                queue.append((next_nodes, next_hops))

    paths.sort(key=lambda path: (len(path.hops), tuple(hop.relation_reference
                                                    for hop in path.hops)))
    identity = Digest({"projection_reference": projection.projection_reference,
        "source_reference": source, "target_reference": target, "limits": limits})

    return ReachabilitySearch(identity, projection, source, target, limits, tuple(paths),
        not reasons, not reasons and not paths, tuple(sorted(reasons)), work,
        len(queue) + deferred_prefix,
        unexamined, depth_cuts)
