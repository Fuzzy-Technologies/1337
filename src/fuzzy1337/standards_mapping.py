# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline versioned standards relations, accountable review, and explicit finding bindings."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from fuzzy1337.adapters.contracts import RequireIdentifier
from fuzzy1337.evidence import NormalizeEvidenceTime
from fuzzy1337.model import CanonicalModelJson, RequireModelReference
from fuzzy1337.workspace import (
    RejectWorkspaceConstant,
    RequireWorkspaceInteger,
    RequireWorkspaceText,
    UniqueWorkspaceObject,
    WorkspaceFields,
)

MAPPING_SCHEMA_VERSION = 1
MAX_MAPPING_BYTES = 1024 * 1024
MAX_MAPPING_RECORDS = 1024
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class MappingRelation(StrEnum):
    """Express classification or context, never a passed control or observed attack."""

    CLASSIFIED_BY = "classified-by"
    RELATED_ATTACK_PATTERN = "related-attack-pattern"
    RELATED_TECHNIQUE = "related-technique"
    RELEVANT_CONTROL = "relevant-control"


class MappingReviewState(StrEnum):
    """Keep unreviewed mappings distinct from externally recorded review decisions."""

    CANDIDATE = "candidate"
    APPROVED = "approved"
    REJECTED = "rejected"


def MappingText(value: object, field_name: str) -> str:
    """Require bounded non-secret metadata without coercion or hidden control characters.

    Args:
        value: Candidate metadata or decoded schema-v1 value; no type coercion occurs.
        field_name: Metadata label used in validation errors, never a secret value.

    Returns:
        Validated bounded printable metadata; callers remain responsible for secrets.
    """

    text = RequireWorkspaceText(value, field_name)

    if not text.strip() or len(text.encode("utf-8")) > 4096 or not text.isprintable():
        raise ValueError(f"{field_name} must be bounded printable metadata")

    return text


def MappingDigest(value: object) -> str:
    """Require a lowercase SHA-256 digest without accepting descriptive placeholders.

    Args:
        value: Candidate metadata or decoded schema-v1 value; no type coercion occurs.

    Returns:
        Validated lowercase SHA-256 digest without a namespace prefix.
    """

    digest = MappingText(value, "digest")

    if not _DIGEST_PATTERN.fullmatch(digest):
        raise ValueError("digest must be lowercase SHA-256")

    return digest


def MappingReference(namespace: str, value: object) -> str:
    """Hash versioned domain-separated canonical bytes without changing Security Object IDs.

    Args:
        namespace: Explicit digest domain such as mapping or mapping-pack.
        value: Candidate metadata or decoded schema-v1 value; no type coercion occurs.

    Returns:
        Namespace-prefixed SHA-256 of schema-versioned canonical content.
    """

    digest = hashlib.sha256(CanonicalModelJson({
        "namespace": namespace, "schema_version": MAPPING_SCHEMA_VERSION, "content": value,
    })).hexdigest()

    return f"{namespace}:{digest}"


@dataclass(frozen=True, slots=True)
class StandardIdentity:
    """Identify an external item by family, exact catalog version, and preserved external ID.

    National, regulatory, and vendor families use the same lowercase family grammar.
    The catalog version identifies upstream content, never the 1337 schema version.
    Syntax validation does not establish that an upstream item exists.
    """

    family: str
    catalog_version: str
    external_id: str

    def __post_init__(self) -> None:
        """Validate immutable identity without resolving a remote catalog."""

        RequireIdentifier(self.family, "family")
        MappingText(self.catalog_version, "catalog_version")
        MappingText(self.external_id, "external_id")

    def ToDict(self) -> dict[str, object]:
        """Return the complete identity fields for strict schema-v1 persistence.

        Returns:
            Complete schema-v1 fields without fetching or mutating any external state.
        """

        return {"family": self.family, "catalog_version": self.catalog_version,
                "external_id": self.external_id}

    @classmethod
    def FromDict(cls, value: object) -> StandardIdentity:
        """Reject unknown identity fields rather than guessing an upstream version.

        Args:
            value: Candidate metadata or decoded schema-v1 value; no type coercion occurs.

        Returns:
            Immutable validated contract preserving explicit version and attribution fields.
        """

        fields = WorkspaceFields(value, {"family", "catalog_version", "external_id"}, "standard")

        return cls(*(MappingText(fields[name], name) for name in (
            "family", "catalog_version", "external_id",
        )))


@dataclass(frozen=True, slots=True)
class MappingSource:
    """Attribute one source locator and content version; optional digest covers fetched bytes.

    A missing artifact digest explicitly means bytes were not pinned. A source URL is
    descriptive provenance and is never fetched by this module. No source is raw Evidence.
    Callers own secret-free metadata; syntax validation is not a secret detector.
    """

    publisher: str
    source_version: str
    source_url: str
    locator: str
    retrieved_at: str
    artifact_sha256: str | None = None

    def __post_init__(self) -> None:
        """Validate citation fields and normalize explicit acquisition time to UTC."""

        for name in ("publisher", "source_version", "source_url", "locator"):
            MappingText(getattr(self, name), name)

        parsed = urlsplit(self.source_url)
        parsed.port

        if (
            parsed.scheme != "https" or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or "\\" in self.source_url
            or any(character.isspace() for character in self.source_url)
        ):
            raise ValueError("source_url must be an absolute HTTPS URL without credentials")

        object.__setattr__(self, "retrieved_at", NormalizeEvidenceTime(
            MappingText(self.retrieved_at, "retrieved_at"),
        ))

        if self.artifact_sha256 is not None:
            MappingDigest(self.artifact_sha256)

    def ToDict(self) -> dict[str, object]:
        """Expose citation provenance including the honest absent-artifact-digest state.

        Returns:
            Complete schema-v1 fields without fetching or mutating any external state.
        """

        return {"publisher": self.publisher, "source_version": self.source_version,
                "source_url": self.source_url, "locator": self.locator,
                "retrieved_at": self.retrieved_at, "artifact_sha256": self.artifact_sha256}

    @classmethod
    def FromDict(cls, value: object) -> MappingSource:
        """Decode exact citation fields without coercing a hash or acquisition time.

        Args:
            value: Candidate metadata or decoded schema-v1 value; no type coercion occurs.

        Returns:
            Immutable validated contract preserving explicit version and attribution fields.
        """

        names = ("publisher", "source_version", "source_url", "locator", "retrieved_at")
        fields = WorkspaceFields(value, {*names, "artifact_sha256"}, "source")
        digest = fields["artifact_sha256"]

        return cls(
            MappingText(fields["publisher"], "publisher"),
            MappingText(fields["source_version"], "source_version"),
            MappingText(fields["source_url"], "source_url"),
            MappingText(fields["locator"], "locator"),
            MappingText(fields["retrieved_at"], "retrieved_at"),
            None if digest is None else MappingDigest(digest),
        )


@dataclass(frozen=True, slots=True)
class MappingReview:
    """Record a supplied accountable decision bound to exact mapping content.

    This validates provenance structure and freshness, not a reviewer's identity or
    signature. Callers must establish review authority outside this offline contract.
    Automation must never synthesize a human reviewer or an approval.
    """

    state: MappingReviewState
    reviewer: str
    reviewed_at: str
    mapping_reference: str
    decision_reference: str

    def __post_init__(self) -> None:
        """Reject candidate attestations and require decision provenance and content binding."""

        if (
            not isinstance(self.state, MappingReviewState)
            or self.state is MappingReviewState.CANDIDATE
        ):
            raise ValueError("review must record an approved or rejected decision")

        MappingText(self.reviewer, "reviewer")
        MappingText(self.decision_reference, "decision_reference")

        if not isinstance(self.mapping_reference, str) or not re.fullmatch(
            r"mapping:[0-9a-f]{64}", self.mapping_reference,
        ):
            raise ValueError("review must identify exact mapping content")

        object.__setattr__(self, "reviewed_at", NormalizeEvidenceTime(
            MappingText(self.reviewed_at, "reviewed_at"),
        ))

    def ToDict(self) -> dict[str, object]:
        """Preserve the external decision attribution without creating a new decision.

        Returns:
            Complete schema-v1 fields without fetching or mutating any external state.
        """

        return {"state": self.state.value, "reviewer": self.reviewer,
                "reviewed_at": self.reviewed_at, "mapping_reference": self.mapping_reference,
                "decision_reference": self.decision_reference}

    @classmethod
    def FromDict(cls, value: object) -> MappingReview:
        """Decode a supplied review; unsupported statuses and missing provenance fail closed.

        Args:
            value: Candidate metadata or decoded schema-v1 value; no type coercion occurs.

        Returns:
            Immutable validated contract preserving explicit version and attribution fields.
        """

        names = ("reviewer", "reviewed_at", "mapping_reference", "decision_reference")
        fields = WorkspaceFields(value, {*names, "state"}, "review")

        return cls(MappingReviewState(MappingText(fields["state"], "state")),
                   *(MappingText(fields[name], name) for name in names))


@dataclass(frozen=True, slots=True)
class StandardsMapping:
    """Relate two external versioned identities with rationale, sources, and review state."""

    mapping_id: str
    source: StandardIdentity
    target: StandardIdentity
    relation: MappingRelation
    rationale: str
    provenance: tuple[MappingSource, ...]
    review: MappingReview | None = None

    def __post_init__(self) -> None:
        """Freeze citations and reject stale decisions or source-free claims."""

        RequireIdentifier(self.mapping_id, "mapping_id")

        if (
            not isinstance(self.source, StandardIdentity)
            or not isinstance(self.target, StandardIdentity)
        ):
            raise ValueError("mapping endpoints must be StandardIdentity values")

        if self.source == self.target or not isinstance(self.relation, MappingRelation):
            raise ValueError("mapping needs distinct endpoints and a supported relation")

        MappingText(self.rationale, "rationale")

        if not isinstance(self.provenance, (list, tuple)) or not 1 <= len(self.provenance) <= 16:
            raise ValueError("mapping provenance must contain 1..16 citations")

        if any(not isinstance(item, MappingSource) for item in self.provenance):
            raise ValueError("mapping provenance must contain MappingSource values")

        provenance = tuple(sorted(set(self.provenance), key=lambda item: CanonicalModelJson(
            item.ToDict(),
        )))

        if len(provenance) != len(self.provenance):
            raise ValueError("mapping provenance must not contain duplicate citations")

        object.__setattr__(self, "provenance", provenance)

        if self.review is not None and (
            not isinstance(self.review, MappingReview)
            or self.review.mapping_reference != self.Reference()
        ):
            raise ValueError("review is stale or does not match exact mapping content")

    def Content(self) -> dict[str, object]:
        """Return reviewed content; review decisions themselves do not change its reference.

        Returns:
            Canonical identity-bearing fields before the outer content reference is added.
        """

        return {"mapping_id": self.mapping_id, "source": self.source.ToDict(),
                "target": self.target.ToDict(), "relation": self.relation.value,
                "rationale": self.rationale,
                "provenance": [item.ToDict() for item in self.provenance]}

    def Reference(self) -> str:
        """Identify exact relation content and provenance independently from object identity.

        Returns:
            Domain-separated SHA-256 reference for the exact content revision.
        """

        return MappingReference("mapping", self.Content())

    def ReviewState(self) -> MappingReviewState:
        """Expose candidate state unless a structurally valid supplied decision exists.

        Returns:
            Candidate when no decision exists, otherwise the supplied decision state.
        """

        return MappingReviewState.CANDIDATE if self.review is None else self.review.state

    def ToDict(self) -> dict[str, object]:
        """Include content, exact digest, and honest review provenance for portable consumers.

        Returns:
            Complete schema-v1 fields without fetching or mutating any external state.
        """

        return {**self.Content(), "reference": self.Reference(),
                "review": None if self.review is None else self.review.ToDict()}

    @classmethod
    def FromDict(cls, value: object) -> StandardsMapping:
        """Reject malformed or tampered relations and preserve externally recorded review.

        Args:
            value: Candidate metadata or decoded schema-v1 value; no type coercion occurs.

        Returns:
            Immutable validated contract preserving explicit version and attribution fields.
        """

        fields = WorkspaceFields(value, {
            "mapping_id", "source", "target", "relation", "rationale", "provenance",
            "reference", "review",
        }, "mapping")

        if not isinstance(fields["provenance"], list):
            raise ValueError("mapping provenance must be a JSON array")

        mapping = cls(
            MappingText(fields["mapping_id"], "mapping_id"),
            StandardIdentity.FromDict(fields["source"]),
            StandardIdentity.FromDict(fields["target"]),
            MappingRelation(MappingText(fields["relation"], "relation")),
            MappingText(fields["rationale"], "rationale"),
            tuple(MappingSource.FromDict(item) for item in fields["provenance"]),
            None if fields["review"] is None else MappingReview.FromDict(fields["review"]),
        )

        if fields["reference"] != mapping.Reference():
            raise ValueError("mapping content reference mismatch")

        return mapping


@dataclass(frozen=True, slots=True)
class MappingPack:
    """Own one finite offline mapping revision; pack content includes supplied review decisions."""

    pack_id: str
    pack_version: str
    mappings: tuple[StandardsMapping, ...]

    def __post_init__(self) -> None:
        """Normalize declaration order and reject duplicate identifiers or unbounded input."""

        RequireIdentifier(self.pack_id, "pack_id")
        MappingText(self.pack_version, "pack_version")

        if not isinstance(self.mappings, (list, tuple)) or len(self.mappings) > MAX_MAPPING_RECORDS:
            raise ValueError("mapping pack must contain a bounded mapping sequence")

        if any(not isinstance(item, StandardsMapping) for item in self.mappings):
            raise ValueError("mapping pack must contain StandardsMapping values")

        if len({item.mapping_id for item in self.mappings}) != len(self.mappings):
            raise ValueError("mapping pack has duplicate mapping IDs")

        object.__setattr__(self, "mappings", tuple(sorted(
            self.mappings, key=lambda item: item.mapping_id,
        )))

    def Content(self) -> dict[str, object]:
        """Return the strict versioned document content in deterministic mapping order.

        Returns:
            Canonical identity-bearing fields before the outer content reference is added.
        """

        return {"schema_version": MAPPING_SCHEMA_VERSION, "pack_id": self.pack_id,
                "pack_version": self.pack_version,
                "mappings": [item.ToDict() for item in self.mappings]}

    def Reference(self) -> str:
        """Identify the full pack revision including exact mapping review decisions.

        Returns:
            Domain-separated SHA-256 reference for the exact content revision.
        """

        return MappingReference("mapping-pack", self.Content())

    def ToDict(self) -> dict[str, object]:
        """Expose a portable document that cannot silently retain a stale pack digest.

        Returns:
            Complete schema-v1 fields without fetching or mutating any external state.
        """

        return {**self.Content(), "reference": self.Reference()}

    def ToBytes(self) -> bytes:
        """Serialize bounded canonical UTF-8 JSON without writing or fetching any file.

        Returns:
            Canonical UTF-8 JSON bytes within the 1 MiB interchange bound.
        """

        payload = CanonicalModelJson(self.ToDict())

        if len(payload) > MAX_MAPPING_BYTES:
            raise ValueError("mapping pack exceeds byte limit")

        return payload

    @classmethod
    def FromDict(cls, value: object) -> MappingPack:
        """Decode exact schema-v1 fields and reject version coercion or digest mismatch.

        Args:
            value: Candidate metadata or decoded schema-v1 value; no type coercion occurs.

        Returns:
            Immutable validated contract preserving explicit version and attribution fields.
        """

        fields = WorkspaceFields(value, {
            "schema_version", "pack_id", "pack_version", "mappings", "reference",
        }, "mapping pack")

        version = RequireWorkspaceInteger(fields["schema_version"], "schema_version")

        if version != MAPPING_SCHEMA_VERSION:
            raise ValueError("unsupported mapping schema version")

        if (
            not isinstance(fields["mappings"], list)
            or len(fields["mappings"]) > MAX_MAPPING_RECORDS
        ):
            raise ValueError("mappings must be a bounded JSON array")

        pack = cls(
            MappingText(fields["pack_id"], "pack_id"),
            MappingText(fields["pack_version"], "pack_version"),
            tuple(StandardsMapping.FromDict(item) for item in fields["mappings"]),
        )

        if fields["reference"] != pack.Reference():
            raise ValueError("mapping pack content reference mismatch")

        return pack

    @classmethod
    def FromBytes(cls, payload: bytes) -> MappingPack:
        """Parse bounded JSON offline, rejecting duplicate keys and nonstandard constants.

        Raises:
            ValueError: Bytes, JSON, versions, identities, attribution, or digests are invalid.

        Args:
            payload: Finite UTF-8 JSON bytes no larger than 1 MiB; no file or URL is read.

        Returns:
            Immutable validated pack with exact mapping and review provenance.
        """

        if not isinstance(payload, bytes) or len(payload) > MAX_MAPPING_BYTES:
            raise ValueError("mapping input must be bounded bytes")

        try:
            document = json.loads(
                payload.decode("utf-8"), object_pairs_hook=UniqueWorkspaceObject,
                parse_constant=RejectWorkspaceConstant,
            )

        except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
            raise ValueError("mapping input must be valid bounded UTF-8 JSON") from error

        return cls.FromDict(document)


@dataclass(frozen=True, slots=True)
class FindingMappingBinding:
    """Attach one explicit classified finding to an exact mapping and pack revision.

    A finding reference is opaque context. This relation neither creates a finding,
    establishes classifier correctness, verifies Evidence, nor proves compliance.
    """

    finding_reference: str
    classifier: StandardIdentity
    pack_reference: str
    mapping: StandardsMapping

    def __post_init__(self) -> None:
        """Reject ambiguous finding references, mismatched classifiers, or unpinned packs."""

        if not RequireModelReference(self.finding_reference).startswith("object:"):
            raise ValueError("finding_reference must be a canonical object reference")

        if (
            not isinstance(self.mapping, StandardsMapping)
            or not isinstance(self.classifier, StandardIdentity)
            or self.classifier != self.mapping.source
        ):
            raise ValueError("binding classifier must match the mapping source")

        if not isinstance(self.pack_reference, str) or not re.fullmatch(
            r"mapping-pack:[0-9a-f]{64}", self.pack_reference,
        ):
            raise ValueError("binding must pin a mapping pack content reference")


def BindFindingMappings(
    pack: MappingPack, finding_reference: str, classifier: StandardIdentity,
    *, include_candidates: bool = False,
) -> tuple[FindingMappingBinding, ...]:
    """Select exact source matches offline; reviewed mappings are the default.

    Args:
        pack: Explicit finite mapping revision; no catalog or network discovery occurs.
        finding_reference: Existing canonical object reference supplied by the finding owner.
        classifier: Explicit finding classification, including its exact catalog version.
        include_candidates: Opt in to candidate relations; rejected decisions are never selected.

    Returns:
        Bindings retaining exact sources and honest review states, without transitive inference.

    Raises:
        ValueError: Types or canonical references are invalid.
    """

    if not isinstance(pack, MappingPack) or not isinstance(classifier, StandardIdentity):
        raise ValueError("binding requires a MappingPack and explicit StandardIdentity")

    if not isinstance(include_candidates, bool):
        raise ValueError("include_candidates must be a boolean")

    if not RequireModelReference(finding_reference).startswith("object:"):
        raise ValueError("finding_reference must be a canonical object reference")

    allowed = {MappingReviewState.APPROVED}

    if include_candidates:
        allowed.add(MappingReviewState.CANDIDATE)

    return tuple(FindingMappingBinding(finding_reference, classifier, pack.Reference(), mapping)
                 for mapping in pack.mappings
                 if mapping.source == classifier and mapping.ReviewState() in allowed)


def CandidateBaseline() -> MappingPack:
    """Build a narrow sourced baseline awaiting owner review; it grants no certification.

    Sources were inspected on 2026-10-11. Live citation bytes are explicitly unpinned.
    NIST and ATT&CK relations are first-party contextual interpretations, not publisher
    crosswalks. ATLAS is supported by the contract but omitted pending exact source review.

    Returns:
        Five sourced candidate relations without any recorded human approval.
    """

    acquired = "2026-10-11T12:48:30+00:00"
    cwe = StandardIdentity("cwe", "4.20", "CWE-89")
    capec = StandardIdentity("capec", "3.9", "CAPEC-66")
    cwe_source = MappingSource("MITRE", "4.20", "https://cwe.mitre.org/data/definitions/89.html",
                               "CWE-89 definition", acquired)
    capec_source = MappingSource("MITRE", "3.9", "https://capec.mitre.org/data/definitions/66.html",
                                 "Related Weaknesses: CWE-89", acquired)
    asvs_source = MappingSource(
        "OWASP", "4.0.3",
        "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/"
        "0x13-V5-Validation-Sanitization-Encoding.md",
        "V5.3.4 CWE column: 89", acquired,
    )
    top10_source = MappingSource(
        "OWASP", "2021", "https://top10.owasp.org/2021/A03_2021-Injection/",
        "Overview and mapped CWEs: CWE-89", acquired,
    )
    nist_source = MappingSource(
        "NIST", "2.0", "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf",
        "Appendix A, ID.RA-01, printed page 18", acquired,
    )
    attack_source = MappingSource(
        "MITRE", "19", "https://attack.mitre.org/versions/v19/techniques/T1190/",
        "T1190 version 2.8, SQL injection procedure context", acquired,
    )
    mappings = (
        StandardsMapping("sql-injection.top10", cwe,
                         StandardIdentity("owasp-top10", "2021", "A03:2021"),
                         MappingRelation.CLASSIFIED_BY,
                         "OWASP lists CWE-89 within its injection category.",
                         (cwe_source, top10_source)),
        StandardsMapping("sql-injection.asvs", cwe,
                         StandardIdentity("owasp-asvs", "4.0.3", "V5.3.4"),
                         MappingRelation.RELEVANT_CONTROL,
                         "ASVS associates database injection protection with CWE-89.",
                         (cwe_source, asvs_source)),
        StandardsMapping("sql-injection.capec", cwe, capec,
                         MappingRelation.RELATED_ATTACK_PATTERN,
                         "CAPEC-66 explicitly lists CWE-89 as a related weakness.",
                         (cwe_source, capec_source)),
        StandardsMapping("sql-injection.nist", cwe,
                         StandardIdentity("nist-csf", "2.0", "ID.RA-01"),
                         MappingRelation.RELEVANT_CONTROL,
                         "1337 interpretation: recording a validated SQL injection finding can "
                         "inform vulnerability identification; it does not fulfill the outcome.",
                         (cwe_source, nist_source)),
        StandardsMapping("sql-injection.attack-context", capec,
                         StandardIdentity("attack", "19", "T1190"),
                         MappingRelation.RELATED_TECHNIQUE,
                         "1337 interpretation: SQL injection can be relevant to public-facing "
                         "application exploitation; exposure and exploitation require evidence.",
                         (capec_source, attack_source)),
    )

    return MappingPack("fuzzy1337.baseline", "0.1.0-candidate", mappings)
