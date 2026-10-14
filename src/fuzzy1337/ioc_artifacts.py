# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental offline IOC candidates with original acquisition pins and exact evidence replay."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.evidence import (
    EvidenceProvenance,
    EvidenceRecord,
    LocalEvidenceStore,
    NormalizeEvidenceTime,
    ParseEvidenceManifest,
    RejectManifestConstant,
    UniqueManifestObject,
)
from fuzzy1337.workspace import LocalWorkspaceStore

__all__ = (
    "IocSource", "IocLimits", "IocCandidate", "IocRequest", "IocSnapshot", "IocAcquisition",
    "ParseIocArtifact", "AcquireIocArtifact", "ReplayIocArtifact", "LoadIocArtifact",
)

IOC_FAMILY = "explicit-ioc-artifact-v1"
IOC_PROFILE = "ascii-ioc-tsv-v1"
IOC_PARSER = "ioc-artifacts"
IOC_PARSER_VERSION = "1"
_ROLES = {
    "ioc-source": (64 * 1024, "text/tab-separated-values"),
    "ioc-acquisition": (8192, "application/json"),
    "ioc-snapshot": (512 * 1024, "application/json"),
}
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(Z|[+-][0-9]{2}:[0-9]{2})\Z"
)


def Text(value: object, name: str, maximum: int = 256) -> str:
    """Require explicit bounded printable ASCII attribution without interpreting locators.

    Args:
        value: Supplied field; exact string type is required.
        name: Field name for refusal diagnostics.
        maximum: Inclusive ASCII character/byte ceiling.

    Returns:
        Original nonempty printable value without whitespace coercion.
    """

    if type(value) is not str or not 1 <= len(value) <= maximum or value != value.strip() or (
        any(not 32 <= ord(character) <= 126 for character in value)
    ):
        raise ValueError(f"{name} requires bounded nonempty printable ASCII text")

    return value


def Identity(value: object) -> str:
    """Require a canonical immutable evidence manifest identifier without storage access.

    Args:
        value: Candidate immutable manifest pin, never a filesystem path.

    Returns:
        Exact validated sha256-prefixed lowercase manifest identity.
    """

    text = Text(value, "evidence identity")

    if not text.startswith("sha256:") or not _DIGEST.fullmatch(text[7:]):
        raise ValueError("IOC evidence identity requires a lowercase SHA-256 manifest pin")

    return text


def ObjectFields(value: object, expected: set[str]) -> dict[str, Any]:
    """Reject unknown, missing and non-object metadata rather than accepting defaults.

    Args:
        value: Previously bounded decoded metadata object.
        expected: Complete closed field set for this consumer.

    Returns:
        Exact dictionary after field verification without coercion.
    """

    if type(value) is not dict or set(value) != expected:
        raise ValueError("IOC metadata fields differ from the closed schema")

    return cast(dict[str, Any], value)


def JsonBytes(value: object) -> bytes:
    """Serialize detached plain metadata as finite canonical ASCII JSON.

    Args:
        value: Detached finite JSON-compatible first-party metadata.

    Returns:
        Sorted compact ASCII bytes, with non-ASCII strings escaped.
    """

    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def Metadata(payload: bytes, maximum: int) -> dict[str, Any]:
    """Bound bytes and depth before decoding canonical duplicate-free JSON metadata.

    Args:
        payload: Explicit stored metadata bytes, never a path to load.
        maximum: Consumer's finite metadata byte ceiling.

    Returns:
        Detached canonical JSON object of depth at most eight.

    Raises:
        ValueError: Bytes, depth, encoding, constants, duplicates or canonical form is invalid.
    """

    if type(payload) is not bytes or len(payload) > maximum:
        raise ValueError("IOC metadata exceeds its byte budget")

    depth = 0
    quoted = False
    escaped = False

    for byte in payload:
        if quoted:
            if escaped:
                escaped = False

            elif byte == 92:
                escaped = True

            elif byte == 34:
                quoted = False

        elif byte == 34:
            quoted = True

        elif byte in (91, 123):
            depth += 1

            if depth > 8:
                raise ValueError("IOC metadata exceeds its depth budget")

        elif byte in (93, 125):
            depth -= 1

    try:
        value = json.loads(payload.decode("ascii"), object_pairs_hook=UniqueManifestObject,
                           parse_constant=RejectManifestConstant)

        if type(value) is not dict or JsonBytes(value) != payload:
            raise ValueError("IOC metadata requires a canonical JSON object")

        return value

    except (UnicodeError, RecursionError, OverflowError) as error:
        raise ValueError("IOC metadata contains invalid bounded JSON") from error


@dataclass(frozen=True, slots=True)
class IocSource:
    """Caller-declared source/version/license and exact byte pin; authenticity is not assessed."""

    source_id: str
    source_version: str
    source_locator: str
    license_name: str
    license_locator: str
    expected_sha256: str

    def __post_init__(self) -> None:
        """Require explicit ASCII source facts and one exact lowercase content digest."""

        for item in fields(self):
            Text(getattr(self, item.name), item.name)

        if not _DIGEST.fullmatch(self.expected_sha256):
            raise ValueError("IOC source requires an exact lowercase SHA-256 byte pin")

    def ToDict(self) -> dict[str, object]:
        """Return detached declared attribution without resolving or reading a locator.

        Returns:
            Explicit declared source/version/license and expected content pin.
        """

        return {item.name: getattr(self, item.name) for item in fields(self)}


@dataclass(frozen=True, slots=True)
class IocLimits:
    """Finite caller parser limits bounded by the closed profile's hard ceilings."""

    max_bytes: int = 64 * 1024
    max_lines: int = 256
    max_items: int = 256
    max_line_bytes: int = 512
    max_token_bytes: int = 512

    def __post_init__(self) -> None:
        """Reject booleans, zero, negatives and limits above their independent hard ceilings."""

        for item, ceiling in zip(fields(self), (64 * 1024, 256, 256, 512, 512), strict=True):
            value = getattr(self, item.name)

            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError(f"{item.name} exceeds the finite IOC profile limit")

    def ToDict(self) -> dict[str, object]:
        """Return detached limits pinned in the original acquisition receipt.

        Returns:
            Exact independent byte/line/item/token limits without defaults.
        """

        return {item.name: getattr(self, item.name) for item in fields(self)}


def Checked(value: object, expected: type[IocSource] | type[IocLimits]) -> None:
    """Reject foreign/subclass objects and revalidate frozen replacements before any I/O.

    Args:
        value: Supplied frozen source or parser limits.
        expected: Exact first-party runtime type required by the consuming boundary.

    Raises:
        ValueError: Runtime type or reconstructed field validation fails.
    """

    if type(value) is not expected:
        raise ValueError("IOC boundaries require exact first-party source and limit types")

    expected(**{item.name: getattr(value, item.name) for item in fields(expected)})


def NormalizeToken(kind: str, token: str) -> str:
    """Normalize one explicit type without DNS/URL/hash inference or network access.

    Args:
        kind: Explicit ipv4, ipv6, dns or sha256 family from the closed profile.
        token: Original bounded printable ASCII candidate token.

    Returns:
        Deterministic normalized candidate value; no maliciousness or scope assertion.

    Raises:
        ValueError: Type, family, address zone or token grammar is unsupported.
    """

    Text(token, "IOC token", 512)

    if kind in {"ipv4", "ipv6"}:
        if "%" in token:
            raise ValueError("IOC literals cannot contain interface zone identifiers")

        address = ipaddress.ip_address(token)

        if address.version != (4 if kind == "ipv4" else 6):
            raise ValueError("IOC literal differs from its explicit address family")

        return NormalizeIpv6(int(address)) if address.version == 6 else str(address)

    if kind == "dns":
        name = token.removesuffix(".")
        labels = name.split(".")

        if len(name) > 253 or len(labels) < 2 or all(label.isdigit() for label in labels) or (
            any(not _DNS_LABEL.fullmatch(label) for label in labels)
        ):
            raise ValueError("IOC DNS requires a fully qualified ASCII label grammar")

        return name.lower()

    if kind == "sha256" and re.fullmatch(r"[A-Fa-f0-9]{64}", token):
        return token.lower()

    raise ValueError("IOC kind or explicit token grammar is unsupported")


def NormalizeIpv6(value: int) -> str:
    """Render fixed lowercase hextets, avoiding runtime-dependent mapped-address presentation.

    Args:
        value: Integer of a validated IPv6 literal produced by the explicit token parser.

    Returns:
        Eight lowercase hextets with the first longest zero run of at least two compressed.
    """

    hextets = [(value >> shift) & 65535 for shift in range(112, -1, -16)]
    best_start = 0
    best_length = 1
    start = 0

    while start < 8:
        end = start

        while end < 8 and hextets[end] == 0:
            end += 1

        if end - start > best_length:
            best_start = start
            best_length = end - start

        start = max(start + 1, end)

    parts = [f"{item:x}" for item in hextets]

    if best_length == 1:
        return ":".join(parts)

    return ":".join(parts[:best_start]) + "::" + ":".join(parts[best_start + best_length:])


def ObservationTime(observed_at: str | None, observation_timezone: str | None) -> str | None:
    """Preserve declared timestamp and exact offset suffix, deriving UTC without clock claims.

    Args:
        observed_at: Optional original ISO timestamp with seconds and an explicit offset.
        observation_timezone: Same original Z or numeric suffix, paired with the timestamp.

    Returns:
        Derived UTC timestamp, or None for an explicitly untimed candidate occurrence.

    Raises:
        ValueError: Declaration is unpaired, malformed, ambiguous or outside UTC bounds.
    """

    if observed_at is None and observation_timezone is None:
        return None

    Text(observed_at, "declared observation time", 64)
    Text(observation_timezone, "declared observation timezone", 6)
    match = _TIMESTAMP.fullmatch(cast(str, observed_at))

    if match is None or match[1] != observation_timezone or observation_timezone == "-00:00":
        raise ValueError("IOC declared timestamp requires its exact known timezone suffix")

    offset = cast(str, observation_timezone)

    if offset != "Z" and (int(offset[1:3]) > 23 or int(offset[4:6]) > 59):
        raise ValueError("IOC declared timezone requires valid offset hours and minutes")

    try:
        return NormalizeEvidenceTime(cast(str, observed_at))

    except OverflowError as error:
        raise ValueError("IOC declared time exceeds the UTC datetime range") from error


@dataclass(frozen=True, slots=True)
class IocCandidate:
    """One supplied occurrence, original token/source coordinates and declared observation time."""

    kind: str
    raw_token: str
    normalized_token: str
    source_locator: str
    line_number: int
    byte_offset: int
    byte_length: int
    observed_at: str | None
    observation_timezone: str | None
    observed_at_utc: str | None

    def __post_init__(self) -> None:
        """Validate closed candidate semantics without accepting inferred maliciousness."""

        Text(self.source_locator, "source_locator")

        if type(self.kind) is not str or NormalizeToken(self.kind, self.raw_token) != (
            self.normalized_token
        ) or ObservationTime(self.observed_at, self.observation_timezone) != self.observed_at_utc:
            raise ValueError("IOC candidate normalization or declared time differs")

        for name, value, minimum in (("line_number", self.line_number, 1),
            ("byte_offset", self.byte_offset, 0), ("byte_length", self.byte_length, 1)):
            if type(value) is not int or not minimum <= value <= 64 * 1024:
                raise ValueError(f"IOC {name} differs from its finite coordinate grammar")

        if self.byte_length != len(self.raw_token):
            raise ValueError("IOC token length differs from its original byte range")

    def ToDict(self) -> dict[str, object]:
        """Return detached candidate data without creating Core objects or Findings.

        Returns:
            Original token/locator/coordinates and separately derived normalization/time.
        """

        return {item.name: getattr(self, item.name) for item in fields(self)}


def ParseIocArtifact(payload: bytes, source: IocSource,
                     limits: IocLimits = IocLimits()) -> tuple[IocCandidate, ...]:
    """Parse the closed ASCII TSV profile as a pure ordered candidate transformation.

    Args:
        payload: Explicit authorized non-secret bytes; LF or CRLF, no blank physical lines.
        source: Exact declared source with matching SHA-256 pin and opaque logical locator.
        limits: Positive byte/line/item/token budgets at most the profile hard ceilings.

    Returns:
        Every supplied occurrence in original order, including duplicates. Two fields contain
        kind/token; four also contain original ISO timestamp and matching Z or numeric offset.

    Raises:
        ValueError: Pin, grammar, type, address family, time or budget is invalid. No I/O occurs.
    """

    Checked(source, IocSource)
    Checked(limits, IocLimits)

    if type(payload) is not bytes or not payload or len(payload) > limits.max_bytes or (
        hashlib.sha256(payload).hexdigest() != source.expected_sha256
    ):
        raise ValueError("IOC payload is empty, exceeds its byte budget or differs from its pin")

    line_count = payload.count(b"\n") + (not payload.endswith(b"\n"))

    if line_count > limits.max_lines or line_count > limits.max_items:
        raise ValueError("IOC artifact exceeds its line or item budget")

    candidates = []
    offset = 0
    lines = payload.split(b"\n")

    if lines[-1] == b"":
        lines.pop()

    for line_number, physical in enumerate(lines, 1):
        terminated = line_number < len(lines) or payload.endswith(b"\n")
        line = physical.removesuffix(b"\r") if terminated else physical

        if not line or len(line) > limits.max_line_bytes or b"\r" in line:
            raise ValueError("IOC physical line is empty, over budget or contains a bare CR")

        try:
            parts = line.decode("ascii").split("\t")

        except UnicodeError as error:
            raise ValueError("IOC profile requires ASCII without Unicode conversion") from error

        if len(parts) not in (2, 4) or len(parts[1]) > limits.max_token_bytes:
            raise ValueError("IOC TSV fields or token budget differ from the closed profile")

        kind, token = parts[:2]
        observed = parts[2] if len(parts) == 4 else None
        zone = parts[3] if len(parts) == 4 else None
        candidates.append(IocCandidate(kind, token, NormalizeToken(kind, token),
            source.source_locator, line_number, offset + len(kind) + 1, len(token),
            observed, zone, ObservationTime(observed, zone)))
        offset += len(physical) + 1

    return tuple(candidates)


@dataclass(frozen=True, slots=True)
class IocRequest:
    """Explicit caller-owned payload, declared source and finite parsing budgets."""

    payload: bytes
    source: IocSource
    limits: IocLimits = IocLimits()

    def __post_init__(self) -> None:
        """Revalidate exact nested types and reject oversize bytes before storage or truncation."""

        Checked(self.source, IocSource)
        Checked(self.limits, IocLimits)

        if type(self.payload) is not bytes or len(self.payload) > self.limits.max_bytes:
            raise ValueError("IOC acquisition requires explicit bytes within its byte budget")


@dataclass(frozen=True, slots=True)
class IocSnapshot:
    """Derived supplied candidates pinned to original raw and acquisition manifest identities."""

    raw_evidence_id: str
    acquisition_evidence_id: str
    source: IocSource
    limits: IocLimits
    candidates: tuple[IocCandidate, ...]

    def Serialize(self) -> bytes:
        """Return canonical snapshot metadata; original reparse is required before trusting it.

        Returns:
            Bounded schema-one metadata pinned to exact raw and acquisition manifest identities.

        Raises:
            ValueError: Exact typed source, budgets, candidates or serialization bound fails.
        """

        if type(self) is not IocSnapshot:
            raise ValueError("IOC serialization requires an exact first-party snapshot")

        Checked(self.source, IocSource)
        Checked(self.limits, IocLimits)
        Identity(self.raw_evidence_id)
        Identity(self.acquisition_evidence_id)

        if type(self.candidates) is not tuple or not 1 <= len(self.candidates) <= (
            self.limits.max_items
        ) or any(type(item) is not IocCandidate for item in self.candidates):
            raise ValueError("IOC snapshot requires bounded exact first-party candidates")

        for candidate in self.candidates:
            IocCandidate(**{item.name: getattr(candidate, item.name)
                            for item in fields(IocCandidate)})

        payload = JsonBytes({"schema_version": 1, "family": IOC_FAMILY, "profile": IOC_PROFILE,
            "parser_id": IOC_PARSER, "parser_version": IOC_PARSER_VERSION,
            "raw_evidence_id": self.raw_evidence_id,
            "acquisition_evidence_id": self.acquisition_evidence_id,
            "source": self.source.ToDict(), "limits": self.limits.ToDict(),
            "candidates": [item.ToDict() for item in self.candidates]})

        if len(payload) > _ROLES["ioc-snapshot"][0]:
            raise ValueError("IOC snapshot exceeds its metadata budget")

        return payload


@dataclass(frozen=True, slots=True)
class IocAcquisition:
    """Terminal original acquisition records; a refused parse supplies no usable snapshot."""

    state: str
    raw: EvidenceRecord
    receipt: EvidenceRecord
    snapshot_record: EvidenceRecord | None
    snapshot: IocSnapshot | None


class IocEvidenceStore(LocalEvidenceStore):
    """Apply closed consumer budgets before the evidence owner's eager blob verification."""

    def __init__(self, root: Path, source_max_bytes: int = 64 * 1024) -> None:
        """Retain the original receipt's source budget without accessing stored paths.

        Args:
            root: Existing operator-owned physical evidence directory.
            source_max_bytes: Original validated receipt's source ceiling in bytes.
        """

        super().__init__(root)
        self.source_max_bytes = source_max_bytes

    def Read(self, reference: EvidenceReference) -> bytes:
        """Read only original IOC roles/media within their finite owning consumer budgets.

        Args:
            reference: Exact first-party original bounded IOC artifact reference.

        Returns:
            Original bytes after consumer budget and canonical evidence integrity checks.

        Raises:
            ValueError: Role, media, runtime type or byte ceiling differs from the consumer.
            EvidenceError: Owning bytes are unavailable, unsafe or corrupt.
        """

        if type(reference) is not EvidenceReference or reference.role not in _ROLES:
            raise ValueError("IOC replay requires an exact original IOC evidence reference")

        maximum, media = _ROLES[reference.role]

        if reference.role == "ioc-source":
            maximum = min(maximum, self.source_max_bytes)

        if type(reference.size_bytes) is not int or not 0 <= reference.size_bytes <= maximum or (
            reference.media_type != media
        ):
            raise ValueError("IOC evidence role/media/size differs from its consumer budget")

        return super().Read(reference)


def AcquisitionClock() -> str:
    """Observe actual receiver UTC acquisition time independently of source-declared timestamps.

    Returns:
        Observed offset-aware UTC timestamp with fixed microsecond precision.
    """

    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def AcquireIocArtifact(workspace_root: Path, request: IocRequest, *,
                       scope_reference: str) -> IocAcquisition:
    """Store original explicit bytes, terminal receipt and successful derived candidates.

    Args:
        workspace_root: Existing operator-owned local workspace; no external source is read.
        request: Exact finite caller-owned payload/source/limits selection.
        scope_reference: Explicit non-secret collection attribution, never current authority.

    Returns:
        Immutable raw/receipt and, on success, snapshot. Digest/parse refusal preserves raw.

    Raises:
        ValueError: Request/budget/type or collection clock is invalid before publication.
        EvidenceError: Storage failed; immutable orphan records may remain, never success.
        OSError: Owning workspace could not be opened. No Core state mutation occurs.
    """

    if type(request) is not IocRequest:
        raise ValueError("IOC acquisition requires an exact first-party request")

    IocRequest(request.payload, request.source, request.limits)
    Text(scope_reference, "scope_reference")
    workspace = LocalWorkspaceStore(workspace_root)
    owner = workspace.Open()
    store = IocEvidenceStore(workspace.root / "evidence")
    started = AcquisitionClock()
    finished = AcquisitionClock()
    provenance = EvidenceProvenance(owner.workspace_id, scope_reference, IOC_PARSER,
        IOC_PARSER_VERSION, IOC_PARSER_VERSION, started, finished)
    raw = store.Put(request.payload, "ioc-source", _ROLES["ioc-source"][1], provenance)
    state = "succeeded"
    candidates = None

    try:
        candidates = ParseIocArtifact(request.payload, request.source, request.limits)

    except ValueError:
        state = "digest-rejected" if raw.reference.sha256 != (
            request.source.expected_sha256
        ) else "parse-rejected"

    envelope = {"schema_version": 1, "family": IOC_FAMILY, "profile": IOC_PROFILE,
        "parser_id": IOC_PARSER, "parser_version": IOC_PARSER_VERSION,
        "state": state, "transport": "caller-supplied-bytes", "authentication": "not-assessed",
        "raw_evidence_id": raw.evidence_id, "source": request.source.ToDict(),
        "limits": request.limits.ToDict(), "provenance": provenance.ToDict()}
    receipt = store.Put(JsonBytes(envelope), "ioc-acquisition", "application/json", provenance)
    snapshot = None
    snapshot_record = None

    if candidates is not None:
        snapshot = IocSnapshot(raw.evidence_id, receipt.evidence_id, request.source,
                               request.limits, candidates)
        snapshot_record = store.Put(snapshot.Serialize(), "ioc-snapshot", "application/json",
                                    provenance)

    return IocAcquisition(state, raw, receipt, snapshot_record, snapshot)


def OriginalRecord(record: EvidenceRecord, workspace_id: str, store: IocEvidenceStore,
                   role: str) -> bytes:
    """Require exact typed originals, canonical reconstruction and immutable owning manifests.

    Args:
        record: Exact original immutable first-party IOC acquisition record.
        workspace_id: Durable identity from authoritative owning workspace metadata.
        store: Owning evidence consumer with original finite budgets.
        role: Exact source, acquisition or snapshot role expected at this chain position.

    Returns:
        Verified original raw bytes without altering records or attribution.

    Raises:
        ValueError: Type, canonical reconstruction, owner, parser or manifest equality fails.
        EvidenceError: Original immutable manifests or blobs are unavailable or corrupt.
    """

    if type(record) is not EvidenceRecord or type(record.reference) is not EvidenceReference or (
        type(record.provenance) is not EvidenceProvenance
    ):
        raise ValueError("IOC replay requires exact first-party original evidence records")

    if ParseEvidenceManifest(record.Serialize()) != record or record.reference.role != role or (
        record.provenance.workspace_id != workspace_id
        or record.provenance.source_id != IOC_PARSER
        or record.provenance.source_version != IOC_PARSER_VERSION
        or record.provenance.tool_version != IOC_PARSER_VERSION
        or record.provenance.execution is not None
        or record.provenance.invocation_sha256 is not None
    ):
        raise ValueError("IOC record differs from its original owner/parser acquisition facts")

    if store.Get(record.evidence_id) != record:
        raise ValueError("IOC record differs from its immutable owning manifest")

    return store.Read(record.reference)


def Header(data: dict[str, Any], expected: set[str]) -> dict[str, Any]:
    """Require exact schema/family/profile/parser pins on detached stored IOC metadata.

    Args:
        data: Previously bounded decoded stored metadata.
        expected: Complete additional acquisition or snapshot field set.

    Returns:
        Exact detached object after all fixed consumer-owned profile pins agree.
    """

    value = ObjectFields(data, expected | {"schema_version", "family", "profile", "parser_id",
                                        "parser_version"})

    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or (
        value["family"] != IOC_FAMILY or value["profile"] != IOC_PROFILE
        or value["parser_id"] != IOC_PARSER or value["parser_version"] != IOC_PARSER_VERSION
    ):
        raise ValueError("IOC metadata differs from its original parser/profile/family pins")

    return value


def ReplayIocArtifact(workspace_root: Path, snapshot_record: EvidenceRecord) -> IocSnapshot:
    """Verify the original owning chain and reparse bytes after reopening or relocation.

    Args:
        workspace_root: Existing or relocated owning workspace; original source paths are unused.
        snapshot_record: Exact original immutable derived-record identity and provenance.

    Returns:
        Independently rebuilt supplied candidates, never scan authority or maliciousness proof.

    Raises:
        ValueError: Typed facts, original pins, source, budgets, time or reparse disagree.
        EvidenceError: Original manifests/blobs are unavailable, unsafe or corrupt.
        OSError: Owning workspace could not be opened. No writes, network or process calls occur.
    """

    if type(snapshot_record) is not EvidenceRecord:
        raise ValueError("IOC replay requires an exact first-party snapshot record")

    workspace = LocalWorkspaceStore(workspace_root)
    workspace_id = workspace.Open().workspace_id
    store = IocEvidenceStore(workspace.root / "evidence")
    payload = OriginalRecord(snapshot_record, workspace_id, store, "ioc-snapshot")
    data = Header(Metadata(payload, _ROLES["ioc-snapshot"][0]), {
        "raw_evidence_id", "acquisition_evidence_id", "source", "limits", "candidates"})
    receipt_record = store.Get(Identity(data["acquisition_evidence_id"]))
    receipt = Header(Metadata(OriginalRecord(receipt_record, workspace_id, store,
        "ioc-acquisition"), _ROLES["ioc-acquisition"][0]), {"state", "transport", "authentication",
            "raw_evidence_id", "source", "limits", "provenance"})

    if receipt["state"] != "succeeded" or receipt["transport"] != "caller-supplied-bytes" or (
        receipt["authentication"] != "not-assessed"
        or receipt["raw_evidence_id"] != data["raw_evidence_id"]
        or receipt["source"] != data["source"] or receipt["limits"] != data["limits"]
        or receipt["provenance"] != receipt_record.provenance.ToDict()
        or receipt_record.provenance != snapshot_record.provenance
    ):
        raise ValueError("IOC snapshot differs from its original successful acquisition receipt")

    source = IocSource(**ObjectFields(receipt["source"], {item.name for item in fields(IocSource)}))
    limits = IocLimits(**ObjectFields(receipt["limits"], {item.name for item in fields(IocLimits)}))
    store = IocEvidenceStore(workspace.root / "evidence", limits.max_bytes)
    raw_record = store.Get(Identity(receipt["raw_evidence_id"]))
    raw = OriginalRecord(raw_record, workspace_id, store, "ioc-source")

    if raw_record.provenance != receipt_record.provenance:
        raise ValueError("IOC raw manifest differs from its original acquisition provenance")

    reparsed = IocSnapshot(raw_record.evidence_id, receipt_record.evidence_id, source, limits,
                          ParseIocArtifact(raw, source, limits))

    if reparsed.Serialize() != payload:
        raise ValueError("IOC stored snapshot differs from independent original byte reparse")

    return reparsed


def LoadIocArtifact(workspace_root: Path, evidence_id: str) -> IocSnapshot:
    """Reopen a trusted snapshot manifest identity and verify its complete original evidence chain.

    Args:
        workspace_root: Existing or relocated owning workspace.
        evidence_id: Trusted immutable snapshot manifest pin; public hashes are not signatures.

    Returns:
        Verified supplied candidate snapshot with original attribution and declared timestamps.

    Raises:
        ValueError: Identity, pins, grammar or original reparse differs.
        EvidenceError: Original storage integrity/availability checks fail.
        OSError: Owning workspace is unavailable.
    """

    Identity(evidence_id)
    workspace = LocalWorkspaceStore(workspace_root)
    workspace.Open()
    store = IocEvidenceStore(workspace.root / "evidence")

    return ReplayIocArtifact(workspace.root, store.Get(evidence_id))
