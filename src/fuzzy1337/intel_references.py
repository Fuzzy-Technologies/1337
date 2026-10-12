# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental offline attack references, source attribution, and explicit review attestations.

Taxonomy records describe reference knowledge, never infrastructure, observed behavior,
authorization, reachability, or evidence that a finding actually matches a technique.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import cast
from urllib.parse import urlsplit

INTEL_REFERENCE_SCHEMA_VERSION = 1
MAX_CATALOG_BYTES = 4 * 1024 * 1024
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_REFERENCE_PATTERN = re.compile(r"^intel:[0-9a-f]{64}$")


class ReferenceNamespace(StrEnum):
    """Separate external identifier spaces without asserting official dataset membership."""

    CAPEC = "capec"
    ATTACK = "attack"
    ATLAS = "atlas"


class ReferenceKind(StrEnum):
    """Distinguish attack-pattern knowledge from behavior knowledge, not observed activity."""

    ATTACK_PATTERN = "attack-pattern"
    BEHAVIOR = "behavior"


class SourceOrigin(StrEnum):
    """Declare synthetic fixture or externally attributed source content explicitly."""

    SYNTHETIC = "synthetic"
    EXTERNAL = "external"


def RequireReferenceText(value: object, name: str, limit: int = 512) -> str:
    """Require bounded, nonempty UTF-8 text without control characters or hidden whitespace.

    Args:
        value: Untrusted candidate scalar.
        name: Field label for validation failures.
        limit: Maximum UTF-8 byte length.

    Returns:
        Unmodified validated string.

    Raises:
        ValueError: Type, encoding, control characters, whitespace, or size is invalid.
    """

    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be nonempty text without surrounding whitespace")

    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{name} must not contain control characters")

    try:
        encoded = value.encode("utf-8")

    except UnicodeError as error:
        raise ValueError(f"{name} must be valid UTF-8 text") from error

    if len(encoded) > limit:
        raise ValueError(f"{name} exceeds its byte limit")

    return value


def RequireReferenceDigest(value: object) -> str:
    """Require a lowercase SHA-256 digest without coercion or path syntax.

    Args:
        value: Candidate digest scalar.

    Returns:
        Unmodified validated lowercase digest.

    Raises:
        ValueError: The value is not exactly 64 lowercase hexadecimal characters.
    """

    if not isinstance(value, str) or not _DIGEST_PATTERN.fullmatch(value):
        raise ValueError("digest must be a lowercase SHA-256 value")

    return value


def NormalizeReferenceTime(value: object) -> str:
    """Normalize explicit offset-aware timestamps to UTC without consulting a clock.

    Args:
        value: Single-line ISO 8601 timestamp with an explicit UTC offset.

    Returns:
        UTC timestamp with fixed microsecond precision.

    Raises:
        ValueError: Text, offset, datetime syntax, or UTC range is invalid.
    """

    timestamp = datetime.fromisoformat(RequireReferenceText(value, "timestamp"))

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")

    try:
        return timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds")

    except OverflowError as error:
        raise ValueError("timestamp exceeds the UTC datetime range") from error


def RequireReferenceUrl(value: object) -> str:
    """Validate a non-credential HTTPS source locator offline; never resolve or fetch it.

    Args:
        value: Absolute HTTPS locator without credentials, query, or fragment.

    Returns:
        Unmodified locator without any external lookup.

    Raises:
        ValueError: Text or URL syntax is invalid or credential-bearing.
    """

    url = RequireReferenceText(value, "source URL", 2048)
    parsed = urlsplit(url)

    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
        or parsed.password is not None or parsed.query or parsed.fragment
        or any(character.isspace() for character in url) or "\\" in url
    ):
        raise ValueError(
            "source URL requires absolute HTTPS without credentials, query, or fragment"
        )

    # Reading port rejects malformed or out-of-range port syntax without network use.
    parsed.port

    return url


def ReferenceFields(value: object, names: set[str]) -> dict[str, object]:
    """Reject unknown, missing, or non-object fields rather than guessing schema meanings.

    Args:
        value: Candidate JSON object.
        names: Exact required field names.

    Returns:
        Validated dictionary for subsequent typed field decoding.

    Raises:
        ValueError: The object or exact field set is invalid.
    """

    if not isinstance(value, dict) or set(value) != names:
        raise ValueError(f"reference object requires exactly {sorted(names)}")

    return cast(dict[str, object], value)


def CanonicalReferenceJson(value: object) -> bytes:
    """Serialize first-party JSON data deterministically without nonstandard numeric values.

    Args:
        value: First-party JSON-compatible payload.

    Returns:
        Compact UTF-8 JSON bytes with sorted object keys.
    """

    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def UniqueReferenceObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON object keys at every nesting level.

    Args:
        pairs: Object members supplied by the standard JSON parser.

    Returns:
        Unique dictionary preserving the supplied values.

    Raises:
        ValueError: An object repeats a field name.
    """

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate reference field: {key}")

        result[key] = value

    return result


def RejectReferenceConstant(value: str) -> object:
    """Reject nonstandard JSON constants even in fields subsequently rejected by the schema.

    Args:
        value: Nonstandard constant token supplied by the JSON parser.

    Returns:
        No value; this rejection hook always raises.

    Raises:
        ValueError: The parser encountered NaN or an infinite-number token.
    """

    raise ValueError(f"nonstandard JSON constant: {value}")


@dataclass(frozen=True, slots=True)
class ReferenceIdentity:
    """Bind one opaque external ID to its exact namespace and external catalog version.

    External identifiers preserve case and are not checked against a downloaded catalog.
    Catalog version identifies the external source release, not the Core or JSON schema.
    """

    namespace: ReferenceNamespace
    external_id: str
    catalog_version: str

    def __post_init__(self) -> None:
        """Reject untyped namespaces and malformed identity strings without normalization."""

        if not isinstance(self.namespace, ReferenceNamespace):
            raise ValueError("namespace must be a ReferenceNamespace")

        RequireReferenceText(self.external_id, "external_id", 128)
        RequireReferenceText(self.catalog_version, "catalog_version", 128)

    def ToDict(self) -> dict[str, object]:
        """Return detached exact schema identity fields.

        Returns:
            Namespace, external identifier, and external release strings.
        """

        return {
            "namespace": self.namespace.value, "external_id": self.external_id,
            "catalog_version": self.catalog_version,
        }

    def Reference(self) -> str:
        """Return a domain-separated identity hash independent of content or installation paths.

        Returns:
            Canonical intel-prefixed lowercase SHA-256 identity.
        """

        digest = hashlib.sha256(CanonicalReferenceJson({
            "domain": "fuzzy1337.intel-reference.identity.v1", "identity": self.ToDict(),
        })).hexdigest()

        return f"intel:{digest}"

    @classmethod
    def FromDict(cls, value: object) -> ReferenceIdentity:
        """Decode only exact namespace/identifier/version fields without scalar coercion.

        Args:
            value: Detached JSON identity object.

        Returns:
            Validated immutable identity preserving external identifier case.

        Raises:
            ValueError: Fields, namespace, or identity strings are invalid.
        """

        fields = ReferenceFields(value, {"namespace", "external_id", "catalog_version"})

        return cls(
            ReferenceNamespace(RequireReferenceText(fields["namespace"], "namespace")),
            RequireReferenceText(fields["external_id"], "external_id", 128),
            RequireReferenceText(fields["catalog_version"], "catalog_version", 128),
        )


@dataclass(frozen=True, slots=True)
class ReferenceSource:
    """Retain explicit publisher, artifact, license, and importer attribution.

    Hashes describe the source artifact bytes supplied by the caller. The contract
    does not fetch those bytes, verify a publisher, or grant redistribution rights.
    """

    origin: SourceOrigin
    publisher: str
    source_url: str
    artifact_sha256: str
    license_name: str
    license_url: str
    acquired_at: str
    importer_id: str
    importer_version: str

    def __post_init__(self) -> None:
        """Validate source facts and freeze the supplied acquisition timestamp in UTC."""

        if not isinstance(self.origin, SourceOrigin):
            raise ValueError("origin must be a SourceOrigin")

        for name in ("publisher", "license_name", "importer_id", "importer_version"):
            RequireReferenceText(getattr(self, name), name)

        RequireReferenceUrl(self.source_url)
        RequireReferenceUrl(self.license_url)
        RequireReferenceDigest(self.artifact_sha256)
        object.__setattr__(self, "acquired_at", NormalizeReferenceTime(self.acquired_at))

    def ToDict(self) -> dict[str, object]:
        """Return detached source provenance without acquiring external content.

        Returns:
            Exact publisher, artifact, license, importer, and UTC acquisition fields.
        """

        return {
            "origin": self.origin.value, "publisher": self.publisher,
            "source_url": self.source_url, "artifact_sha256": self.artifact_sha256,
            "license_name": self.license_name, "license_url": self.license_url,
            "acquired_at": self.acquired_at, "importer_id": self.importer_id,
            "importer_version": self.importer_version,
        }

    @classmethod
    def FromDict(cls, value: object) -> ReferenceSource:
        """Decode exact source fields; trust and license decisions remain caller-owned.

        Args:
            value: Detached JSON source attribution object.

        Returns:
            Validated immutable source metadata with UTC acquisition time.

        Raises:
            ValueError: Exact fields, source text, URLs, digest, or timestamp are invalid.
        """

        fields = ReferenceFields(value, {
            "origin", "publisher", "source_url", "artifact_sha256", "license_name",
            "license_url", "acquired_at", "importer_id", "importer_version",
        })

        return cls(
            SourceOrigin(RequireReferenceText(fields["origin"], "origin")),
            *(RequireReferenceText(fields[name], name, 2048) for name in (
                "publisher", "source_url", "artifact_sha256", "license_name", "license_url",
                "acquired_at", "importer_id", "importer_version",
            )),
        )


@dataclass(frozen=True, slots=True)
class ReferenceReview:
    """Carry an explicit caller-supplied review attestation bound to exact record content.

    The contract cannot establish reviewer identity, human authority, or authenticity.
    Creating a catalog never creates an attestation automatically.
    """

    reviewer: str
    reviewed_at: str
    content_sha256: str

    def __post_init__(self) -> None:
        """Validate explicit review metadata without assigning or synthesizing a reviewer."""

        RequireReferenceText(self.reviewer, "reviewer")
        RequireReferenceDigest(self.content_sha256)
        object.__setattr__(self, "reviewed_at", NormalizeReferenceTime(self.reviewed_at))

    def ToDict(self) -> dict[str, object]:
        """Return detached review metadata tied to the exact reviewed content hash.

        Returns:
            Supplied reviewer, normalized review time, and reviewed content digest.
        """

        return {
            "reviewer": self.reviewer, "reviewed_at": self.reviewed_at,
            "content_sha256": self.content_sha256,
        }

    @classmethod
    def FromDict(cls, value: object) -> ReferenceReview:
        """Decode exact attestation fields without treating their presence as authentication.

        Args:
            value: Detached JSON attestation supplied explicitly by a caller.

        Returns:
            Validated claim; the caller remains responsible for reviewer authentication.

        Raises:
            ValueError: Exact fields, reviewer text, time, or digest are invalid.
        """

        fields = ReferenceFields(value, {"reviewer", "reviewed_at", "content_sha256"})

        return cls(*(RequireReferenceText(fields[name], name) for name in (
            "reviewer", "reviewed_at", "content_sha256",
        )))


@dataclass(frozen=True, slots=True)
class ReferenceRecord:
    """Immutable attributed reference knowledge with separate identity and content hashes.

    Review is optional and pinned to content. Updating title, summary, kind, identity,
    or source invalidates a previous attestation. No evidence or graph edges are inferred.
    """

    identity: ReferenceIdentity
    kind: ReferenceKind
    title: str
    summary: str
    source: ReferenceSource
    review: ReferenceReview | None = None

    def __post_init__(self) -> None:
        """Reject invalid typed records and review attestations for another content revision."""

        if (
            not isinstance(self.identity, ReferenceIdentity)
            or not isinstance(self.kind, ReferenceKind)
        ):
            raise ValueError("identity and kind must be typed reference values")

        if not isinstance(self.source, ReferenceSource):
            raise ValueError("source must be a ReferenceSource")

        RequireReferenceText(self.title, "title")
        RequireReferenceText(self.summary, "summary", 8192)

        if self.review is not None:
            if not isinstance(self.review, ReferenceReview):
                raise ValueError("review must be a ReferenceReview or None")

            if self.review.content_sha256 != self.ContentDigest():
                raise ValueError("review does not match the exact reference content")

            if self.review.reviewed_at < self.source.acquired_at:
                raise ValueError("review must not precede source acquisition")

    def ContentFields(self) -> dict[str, object]:
        """Return the canonical content payload excluding mutable review attestations.

        Returns:
            Detached identity, knowledge content, and source provenance fields.
        """

        return {
            "identity": self.identity.ToDict(), "kind": self.kind.value,
            "title": self.title, "summary": self.summary, "source": self.source.ToDict(),
        }

    def ContentDigest(self) -> str:
        """Hash exact source and interpretation content with an independent domain separator.

        Returns:
            Lowercase SHA-256 content digest, independent of review metadata.
        """

        return hashlib.sha256(CanonicalReferenceJson({
            "domain": "fuzzy1337.intel-reference.content.v1", "content": self.ContentFields(),
        })).hexdigest()

    def ToDict(self) -> dict[str, object]:
        """Return detached record content, validated hashes, and an optional review attestation.

        Returns:
            Exact JSON record fields including recomputed identity/content digests.
        """

        return {
            **self.ContentFields(), "reference_id": self.identity.Reference(),
            "content_sha256": self.ContentDigest(),
            "review": self.review.ToDict() if self.review is not None else None,
        }

    @classmethod
    def FromDict(cls, value: object) -> ReferenceRecord:
        """Decode strict fields and recompute both identity and content hashes before accepting.

        Args:
            value: Detached JSON record with mandatory identity and content hashes.

        Returns:
            Immutable attributed reference knowledge, never operational evidence.

        Raises:
            ValueError: Fields, types, source metadata, hashes, or review pinning are invalid.
        """

        fields = ReferenceFields(value, {
            "identity", "kind", "title", "summary", "source", "reference_id",
            "content_sha256", "review",
        })
        record = cls(
            ReferenceIdentity.FromDict(fields["identity"]),
            ReferenceKind(RequireReferenceText(fields["kind"], "kind")),
            RequireReferenceText(fields["title"], "title"),
            RequireReferenceText(fields["summary"], "summary", 8192),
            ReferenceSource.FromDict(fields["source"]),
            ReferenceReview.FromDict(fields["review"]) if fields["review"] is not None else None,
        )

        if fields["reference_id"] != record.identity.Reference():
            raise ValueError("reference_id does not match canonical identity")

        if RequireReferenceDigest(fields["content_sha256"]) != record.ContentDigest():
            raise ValueError("content_sha256 does not match canonical content")

        return record


@dataclass(frozen=True, slots=True)
class ReferenceCatalog:
    """A versioned offline collection preserving attributed records, never operational truth.

    Catalogs contain caller-supplied records only; no official data is bundled or
    synchronized. Duplicate identities are rejected even when content is identical.
    """

    records: tuple[ReferenceRecord, ...] = ()
    schema_version: int = INTEL_REFERENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Freeze deterministic ordering and reject versions, duplicates, and oversized content."""

        if (
            type(self.schema_version) is not int
            or self.schema_version != INTEL_REFERENCE_SCHEMA_VERSION
        ):
            raise ValueError("unsupported intel reference schema_version")

        if not isinstance(self.records, (tuple, list)):
            raise ValueError("records must be a tuple or list")

        records = tuple(self.records)

        if any(not isinstance(record, ReferenceRecord) for record in records):
            raise ValueError("records must contain ReferenceRecord values")

        references = [record.identity.Reference() for record in records]

        if len(set(references)) != len(references):
            raise ValueError("duplicate or colliding reference identities")

        object.__setattr__(self, "records", tuple(sorted(
            records, key=lambda record: record.identity.Reference(),
        )))

        if len(self.Serialize()) > MAX_CATALOG_BYTES:
            raise ValueError("reference catalog exceeds the byte limit")

    def Resolve(self, reference_id: str, content_sha256: str | None = None) -> ReferenceRecord:
        """Resolve an identity, optionally requiring exact content to avoid silent source drift.

        Args:
            reference_id: Canonical intel identity hash; no external lookup is performed.
            content_sha256: Optional pinned content revision for a consuming interpretation.

        Returns:
            Exact immutable reference record present in this catalog.

        Raises:
            ValueError: A supplied identifier or content digest is invalid or mismatched.
            KeyError: This catalog does not contain the supplied identity.
        """

        if not isinstance(reference_id, str) or not _REFERENCE_PATTERN.fullmatch(reference_id):
            raise ValueError("reference_id must be a canonical intel reference")

        if content_sha256 is not None:
            RequireReferenceDigest(content_sha256)

        for record in self.records:
            if record.identity.Reference() == reference_id:
                if content_sha256 is not None and content_sha256 != record.ContentDigest():
                    raise ValueError("reference content differs from the pinned revision")

                return record

        raise KeyError(reference_id)

    def ToDict(self) -> dict[str, object]:
        """Return detached schema-v1 records without touching model state, evidence, or files.

        Returns:
            Supported schema version and deterministically ordered record array.
        """

        return {
            "schema_version": self.schema_version,
            "records": [record.ToDict() for record in self.records],
        }

    def Serialize(self) -> bytes:
        """Return deterministic strict UTF-8 JSON; the caller owns storage and transport.

        Returns:
            Compact canonical schema-v1 bytes without a trailing newline.
        """

        return CanonicalReferenceJson(self.ToDict())

    @classmethod
    def FromDict(cls, value: object) -> ReferenceCatalog:
        """Decode an exact supported catalog schema, validating every nested record and hash.

        Args:
            value: Detached JSON catalog with an integer schema version and record array.

        Returns:
            Immutable, bounded catalog with unique identity references.

        Raises:
            ValueError: Version, fields, collections, nested records, hashes, or size is invalid.
        """

        fields = ReferenceFields(value, {"schema_version", "records"})
        version = fields["schema_version"]

        if type(version) is not int or version != INTEL_REFERENCE_SCHEMA_VERSION:
            raise ValueError("unsupported intel reference schema_version")

        if not isinstance(fields["records"], list):
            raise ValueError("records must be a JSON array")

        return cls(tuple(ReferenceRecord.FromDict(value) for value in fields["records"]), version)

    @classmethod
    def Deserialize(cls, payload: bytes) -> ReferenceCatalog:
        """Decode bounded strict JSON, rejecting duplicate keys and unsupported schema versions.

        Args:
            payload: UTF-8 JSON bytes within the catalog size bound.

        Returns:
            Validated immutable offline catalog; whitespace and object key order may vary.

        Raises:
            ValueError: Encoding, syntax, size, fields, hashes, or version are invalid.
        """

        if not isinstance(payload, bytes) or len(payload) > MAX_CATALOG_BYTES:
            raise ValueError("catalog payload must be bounded bytes")

        try:
            document = json.loads(
                payload.decode("utf-8"), object_pairs_hook=UniqueReferenceObject,
                parse_constant=RejectReferenceConstant,
            )

            return cls.FromDict(document)

        except (UnicodeError, RecursionError) as error:
            raise ValueError("catalog must contain bounded valid UTF-8 JSON") from error
