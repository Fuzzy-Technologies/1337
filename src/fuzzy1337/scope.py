# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline target registration, explicit scope decisions, and portable owned persistence."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from fuzzy1337.adapters.contracts import RequireIdentifier
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    RejectWorkspaceConstant,
    RequireWorkspaceInteger,
    RequireWorkspaceText,
    StoragePathInfo,
    SyncStorageDirectory,
    UniqueWorkspaceObject,
    WorkspaceFields,
)

SCOPE_SCHEMA_VERSION = 1
MAX_SCOPE_BYTES = 1024 * 1024
_DOMAIN_LABEL_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_NUMERIC_HOST_LABEL_PATTERN = re.compile(r"(?:[0-9]+|0x[0-9a-f]+)")
_INVALID_PERCENT_PATTERN = re.compile(r"%(?![0-9a-fA-F]{2})")


class TargetKind(StrEnum):
    """Select a literal target namespace without DNS or redirect inference."""

    DOMAIN = "domain"
    IP = "ip"
    NETWORK = "network"
    URL = "url"


class AuthorizationState(StrEnum):
    """Record operator-supplied consent status without issuing execution authority."""

    UNKNOWN = "unknown"
    GRANTED = "granted"
    REVOKED = "revoked"


class ScopeDecisionReason(StrEnum):
    """Explain one deterministic membership decision, including fail-closed outcomes."""

    ALLOWED = "allowed"
    AUTHORIZATION_UNKNOWN = "authorization_unknown"
    AUTHORIZATION_REVOKED = "authorization_revoked"
    AUTHORIZATION_NOT_YET_VALID = "authorization_not_yet_valid"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    UNREGISTERED = "unregistered"
    EXCLUDED = "excluded"
    DENIED = "denied"
    NOT_ALLOWED = "not_allowed"


class ScopeConflictError(RuntimeError):
    """Reject an attempted identity change or a stale scope revision."""


class ScopeBusyError(RuntimeError):
    """Reject a live or abandoned scope writer lock without stealing ownership."""


def _NormalizeDomain(value: str) -> str:
    """Normalize IDNA DNS spelling without looking up or expanding the domain.

    Args:
        value: Literal domain, optionally with one trailing DNS root dot.

    Returns:
        Lowercase ASCII IDNA spelling without the trailing root dot.

    Raises:
        ValueError: Labels, length, or an address masquerading as a domain are invalid.
    """

    try:
        domain = value.removesuffix(".").encode("idna").decode("ascii").lower()

    except UnicodeError as error:
        raise ValueError("domain must have valid IDNA labels") from error

    labels = domain.split(".")

    if (
        len(domain) > 253
        or not all(_DOMAIN_LABEL_PATTERN.fullmatch(label) for label in labels)
        or all(_NUMERIC_HOST_LABEL_PATTERN.fullmatch(label) for label in labels)
    ):
        raise ValueError("domain must contain valid DNS labels, not an IP literal")

    return domain


def _NormalizeUrl(value: str) -> str:
    """Normalize an exact HTTP(S) request target while rejecting ambiguous addressing.

    Args:
        value: URL without credentials, fragments, escaped path separators, or dot segments.

    Returns:
        Canonical scheme/host/default port and encoded path/query; no authority expansion.

    Raises:
        ValueError: Parsing, authority, scheme, port, or path safety is invalid.
    """

    if "#" in value or "\\" in value or _INVALID_PERCENT_PATTERN.search(value):
        raise ValueError("URL must not contain fragments, backslashes, or invalid escapes")

    try:
        parsed = urlsplit(value)
        port = parsed.port
        hostname = parsed.hostname

    except ValueError as error:
        raise ValueError("URL authority is invalid") from error

    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or "%" in hostname
        or parsed.netloc.endswith(":")
        or port == 0
    ):
        raise ValueError("URL requires an explicit HTTP(S) authority without credentials")

    try:
        address = ipaddress.ip_address(hostname)

    except ValueError:
        host = _NormalizeDomain(hostname)

    else:
        host = f"[{address.compressed}]" if address.version == 6 else address.compressed

    path = parsed.path or "/"
    decoded_path = unquote(path)

    if (
        "//" in path
        or any(part in {".", ".."} for part in decoded_path.split("/"))
        or re.search(r"%(?:2f|5c)", path, re.IGNORECASE)
    ):
        raise ValueError("URL path must not contain ambiguous separators or dot segments")

    if port is not None and port != {"http": 80, "https": 443}[parsed.scheme]:
        host = f"{host}:{port}"

    path = quote(path, safe="/%:@!$&'()*+,;=-._~")
    query = quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~")
    path = re.sub(r"%[0-9a-fA-F]{2}", lambda match: match.group().upper(), path)
    query = re.sub(r"%[0-9a-fA-F]{2}", lambda match: match.group().upper(), query)

    return urlunsplit((parsed.scheme, host, path, query, ""))


def _NormalizeTarget(kind: TargetKind, value: str) -> str:
    """Validate and normalize one typed literal without any network or filesystem lookup.

    Args:
        kind: Explicit namespace, never inferred from a partially parsed string.
        value: Nonempty literal without whitespace, controls, or surrounding decoration.

    Returns:
        Canonical literal in the selected namespace.

    Raises:
        ValueError: Kind, literal, host bits, zone identifier, or normalization is invalid.
    """

    if not isinstance(kind, TargetKind):
        raise ValueError("kind must be a TargetKind")

    RequireWorkspaceText(value, "target value")

    if len(value) > 4096 or any(
        char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value
    ):
        raise ValueError("target value must be bounded text without whitespace or controls")

    if kind == TargetKind.DOMAIN:
        return _NormalizeDomain(value)

    if kind == TargetKind.URL:
        return _NormalizeUrl(value)

    if "%" in value:
        raise ValueError("IP and network targets must not contain interface zone identifiers")

    if kind == TargetKind.IP:
        return ipaddress.ip_address(value).compressed

    if "/" not in value:
        raise ValueError("network target must include an explicit prefix")

    return ipaddress.ip_network(value, strict=True).with_prefixlen


@dataclass(frozen=True, slots=True)
class Target:
    """A registered literal whose identity is derived from its normalized kind and value."""

    kind: TargetKind
    value: str

    def __post_init__(self) -> None:
        """Normalize explicit input once without inferring another target namespace."""

        object.__setattr__(self, "value", _NormalizeTarget(self.kind, self.value))

    def Reference(self) -> str:
        """Return the opaque SHA-256 identity of canonical compact JSON, without a newline.

        Returns:
            `target:<64 lowercase hex>` over UTF-8 sorted-key kind/value JSON.
        """

        payload = json.dumps(
            self.ToDict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

        return "target:" + hashlib.sha256(payload).hexdigest()

    def ToDict(self) -> dict[str, object]:
        """Return normalized version-owned fields without resolved addresses.

        Returns:
            Kind/value fields used both by target identity and scope serialization.
        """

        return {"kind": self.kind.value, "value": self.value}

    @classmethod
    def FromDict(cls, value: object) -> Target:
        """Decode an exact canonical stored target rather than silently repairing it.

        Args:
            value: Decoded kind/value object from a scope document.

        Returns:
            Validated immutable target retaining its persisted identity.

        Raises:
            ValueError: Fields, types, namespace, spelling, or literal are unsupported.
        """

        record = WorkspaceFields(value, {"kind", "value"}, "target")
        target = cls(
            TargetKind(RequireWorkspaceText(record["kind"], "kind")),
            RequireWorkspaceText(record["value"], "value"),
        )

        if target.value != record["value"]:
            raise ValueError("persisted target must already have canonical spelling")

        return target


def _NormalizeTime(value: str) -> str:
    """Normalize an explicit timezone-aware validity bound to UTC ISO 8601 text.

    Args:
        value: Offset-aware ISO 8601 timestamp, never a local implicit time.

    Returns:
        UTC ISO 8601 spelling with an explicit offset.

    Raises:
        ValueError: Text, timestamp, or timezone is invalid.
    """

    RequireWorkspaceText(value, "authorization time")
    parsed = datetime.fromisoformat(value)

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("authorization time must have an explicit timezone")

    return parsed.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class ScopeAuthorization:
    """Non-secret operator-recorded consent metadata; references are not verified signatures."""

    state: AuthorizationState = AuthorizationState.UNKNOWN
    authority_reference: str | None = None
    record_reference: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None

    def __post_init__(self) -> None:
        """Validate explicit consent and normalize optional validity bounds without I/O."""

        if not isinstance(self.state, AuthorizationState):
            raise ValueError("authorization state must be an AuthorizationState")

        for field_name in ("authority_reference", "record_reference"):
            value = getattr(self, field_name)

            if value is not None:
                RequireWorkspaceText(value, field_name)

        if self.state == AuthorizationState.GRANTED and (
            self.authority_reference is None or self.record_reference is None
        ):
            raise ValueError("granted authorization requires authority and record references")

        for field_name in ("valid_from", "valid_until"):
            value = getattr(self, field_name)

            if value is not None:
                object.__setattr__(self, field_name, _NormalizeTime(value))

        if self.valid_from is not None and self.valid_until is not None:
            if datetime.fromisoformat(self.valid_from) >= datetime.fromisoformat(self.valid_until):
                raise ValueError("authorization validity interval must be increasing")

    def ToDict(self) -> dict[str, object]:
        """Render explicit nullable metadata without loading the referenced consent record.

        Returns:
            Exact fields of the schema-v1 authorization object.
        """

        return {
            "state": self.state.value, "authority_reference": self.authority_reference,
            "record_reference": self.record_reference, "valid_from": self.valid_from,
            "valid_until": self.valid_until,
        }

    @classmethod
    def FromDict(cls, value: object) -> ScopeAuthorization:
        """Decode all consent fields, rejecting omitted, unknown, or noncanonical metadata.

        Args:
            value: Decoded authorization object, including explicit null fields.

        Returns:
            Validated operator-recorded consent metadata.

        Raises:
            ValueError: Fields, enum, references, or stored validity spelling are invalid.
        """

        record = WorkspaceFields(
            value,
            {"state", "authority_reference", "record_reference", "valid_from", "valid_until"},
            "authorization",
        )
        optional = {
            name: None if record[name] is None else RequireWorkspaceText(record[name], name)
            for name in ("authority_reference", "record_reference", "valid_from", "valid_until")
        }
        authorization = cls(
            state=AuthorizationState(RequireWorkspaceText(record["state"], "state")), **optional
        )

        if authorization.ToDict() != record:
            raise ValueError("persisted authorization must already have canonical time spelling")

        return authorization


def _Targets(value: object, field_name: str) -> tuple[Target, ...]:
    """Freeze one unique declaration-ordered sequence of typed targets.

    Args:
        value: List or tuple containing normalized Target values.
        field_name: Registration or rule list named in a validation failure.

    Returns:
        Immutable sequence, preserving explicit declaration order.

    Raises:
        ValueError: Sequence type, target type, or normalized identity uniqueness is invalid.
    """

    if not isinstance(value, (list, tuple)) or any(not isinstance(item, Target) for item in value):
        raise ValueError(f"{field_name} must be a Target sequence")

    targets = tuple(value)

    if len({target.Reference() for target in targets}) != len(targets):
        raise ValueError(f"{field_name} must have unique normalized targets")

    return targets


def _Matches(rule: Target, target: Target, *, denying: bool = False) -> bool:
    """Match literals/CIDRs and conservatively deny a URL's explicit known authority.

    Args:
        rule: Typed scope rule, including an optional CIDR network boundary.
        target: Registered candidate literal.
        denying: Reject overlapping networks and URLs whose explicit host is denied.

    Returns:
        Whether the rule covers the candidate or conservatively restricts it when denying.
    """

    if rule.kind == target.kind and rule.value == target.value:
        return True

    if denying and target.kind == TargetKind.URL and rule.kind != TargetKind.URL:
        hostname = urlsplit(target.value).hostname

        if hostname is None:
            raise ValueError("canonical URL must retain its explicit authority")

        try:
            authority = Target(TargetKind.IP, hostname)

        except ValueError:
            authority = Target(TargetKind.DOMAIN, hostname)

        return _Matches(rule, authority, denying=True)

    if (
        rule.kind not in {TargetKind.IP, TargetKind.NETWORK}
        or target.kind not in {TargetKind.IP, TargetKind.NETWORK}
    ):
        return False

    if rule.kind == TargetKind.IP and not denying:
        return False

    network = ipaddress.ip_network(rule.value)

    if target.kind == TargetKind.IP:
        address = ipaddress.ip_address(target.value)

        return address.version == network.version and address in network

    candidate = ipaddress.ip_network(target.value)

    if candidate.version != network.version:
        return False

    if denying:
        return candidate.overlaps(network)

    return candidate.prefixlen >= network.prefixlen and candidate.network_address in network


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    """Membership evidence for one registered literal; this is never an executor grant."""

    reason: ScopeDecisionReason
    scope_reference: str
    target_reference: str
    rule_reference: str | None = None

    def __post_init__(self) -> None:
        """Require typed reasons and explicit non-secret references without granting authority."""

        if not isinstance(self.reason, ScopeDecisionReason):
            raise ValueError("reason must be a ScopeDecisionReason")

        RequireWorkspaceText(self.scope_reference, "scope_reference")
        RequireWorkspaceText(self.target_reference, "target_reference")

        if self.rule_reference is not None:
            RequireWorkspaceText(self.rule_reference, "rule_reference")

    def Allowed(self) -> bool:
        """Return true only for the explicit allowed reason.

        Returns:
            Scope membership outcome; independent execution policy must still approve work.
        """

        return self.reason == ScopeDecisionReason.ALLOWED


@dataclass(frozen=True, slots=True)
class ScopeSnapshot:
    """Immutable registered targets, rules, and consent bound to one portable workspace."""

    scope_id: str
    workspace_id: str
    authorization: ScopeAuthorization = ScopeAuthorization()
    revision: int = 0
    targets: tuple[Target, ...] = ()
    allow: tuple[Target, ...] = ()
    deny: tuple[Target, ...] = ()
    exclusions: tuple[Target, ...] = ()

    def __post_init__(self) -> None:
        """Reject implicit consent, ambiguous target lists, and malformed identities/revisions."""

        RequireIdentifier(self.scope_id, "scope_id")
        RequireIdentifier(self.workspace_id, "workspace_id")
        RequireWorkspaceInteger(self.revision, "revision")

        if not isinstance(self.authorization, ScopeAuthorization):
            raise ValueError("authorization must be a ScopeAuthorization")

        for field_name in ("targets", "allow", "deny", "exclusions"):
            object.__setattr__(self, field_name, _Targets(getattr(self, field_name), field_name))

    def Reference(self) -> str:
        """Return the opaque workspace-local reference used by existing workspace metadata.

        Returns:
            `scope:<scope_id>`, without paths or a claim about current authorization.
        """

        return "scope:" + self.scope_id

    def Register(self, target: Target) -> ScopeSnapshot:
        """Add a normalized target idempotently without granting membership or writing files.

        Args:
            target: Typed literal to register before membership checks.

        Returns:
            Proposed snapshot at the same revision, or self for an existing target.

        Raises:
            ValueError: The candidate is not a Target.
        """

        if not isinstance(target, Target):
            raise ValueError("target must be a Target")

        if target in self.targets:
            return self

        return replace(self, targets=(*self.targets, target))

    def Check(self, target: Target, *, at: datetime) -> ScopeDecision:
        """Evaluate consent, registration, exclusion, deny, and allow in that order offline.

        Args:
            target: Explicit normalized literal; discovery never expands its authority.
            at: Caller-supplied timezone-aware decision time; no hidden clock is consulted.

        Returns:
            Deterministic reason and references. Allowed membership does not authorize a job.

        Raises:
            ValueError: Target or decision time is not explicitly typed and timezone-aware.
        """

        if not isinstance(target, Target):
            raise ValueError("target must be a Target")

        if not isinstance(at, datetime) or at.tzinfo is None or at.utcoffset() is None:
            raise ValueError("decision time must be a timezone-aware datetime")

        reason: ScopeDecisionReason | None = None
        authorization = self.authorization

        if authorization.state == AuthorizationState.UNKNOWN:
            reason = ScopeDecisionReason.AUTHORIZATION_UNKNOWN

        elif authorization.state == AuthorizationState.REVOKED:
            reason = ScopeDecisionReason.AUTHORIZATION_REVOKED

        elif authorization.valid_from is not None and at < datetime.fromisoformat(
            authorization.valid_from
        ):
            reason = ScopeDecisionReason.AUTHORIZATION_NOT_YET_VALID

        elif authorization.valid_until is not None and at >= datetime.fromisoformat(
            authorization.valid_until
        ):
            reason = ScopeDecisionReason.AUTHORIZATION_EXPIRED

        elif target not in self.targets:
            reason = ScopeDecisionReason.UNREGISTERED

        if reason is not None:
            return ScopeDecision(reason, self.Reference(), target.Reference())

        for rules, matched_reason in (
            (self.exclusions, ScopeDecisionReason.EXCLUDED),
            (self.deny, ScopeDecisionReason.DENIED),
            (self.allow, ScopeDecisionReason.ALLOWED),
        ):
            for rule in rules:
                if _Matches(rule, target, denying=matched_reason != ScopeDecisionReason.ALLOWED):
                    return ScopeDecision(
                        matched_reason, self.Reference(), target.Reference(), rule.Reference()
                    )

        return ScopeDecision(ScopeDecisionReason.NOT_ALLOWED, self.Reference(), target.Reference())

    def ToDict(self) -> dict[str, object]:
        """Render exact portable schema-v1 state without absolute paths or raw consent data.

        Returns:
            JSON-compatible snapshot retaining declaration order and explicit authorization.
        """

        return {
            "schema_version": SCOPE_SCHEMA_VERSION, "scope_id": self.scope_id,
            "workspace_id": self.workspace_id, "revision": self.revision,
            "authorization": self.authorization.ToDict(),
            "targets": [target.ToDict() for target in self.targets],
            "allow": [target.ToDict() for target in self.allow],
            "deny": [target.ToDict() for target in self.deny],
            "exclusions": [target.ToDict() for target in self.exclusions],
        }

    @classmethod
    def FromDict(cls, value: object) -> ScopeSnapshot:
        """Decode exact schema-owned fields and reject unknown versions or implicit defaults.

        Args:
            value: Decoded document whose JSON duplicate keys have already been rejected.

        Returns:
            Validated immutable portable scope snapshot.

        Raises:
            ValueError: Fields, schema, identities, targets, or authorization are invalid.
        """

        record = WorkspaceFields(
            value,
            {"schema_version", "scope_id", "workspace_id", "revision", "authorization",
             "targets", "allow", "deny", "exclusions"},
            "scope snapshot",
        )

        schema_version = RequireWorkspaceInteger(record["schema_version"], "schema_version")

        if schema_version != SCOPE_SCHEMA_VERSION:
            raise ValueError("unsupported scope schema version")

        lists: dict[str, tuple[Target, ...]] = {}

        for name in ("targets", "allow", "deny", "exclusions"):
            items = record[name]

            if not isinstance(items, list):
                raise ValueError(f"{name} must be a JSON array")

            lists[name] = tuple(Target.FromDict(item) for item in items)

        return cls(
            scope_id=RequireWorkspaceText(record["scope_id"], "scope_id"),
            workspace_id=RequireWorkspaceText(record["workspace_id"], "workspace_id"),
            revision=RequireWorkspaceInteger(record["revision"], "revision"),
            authorization=ScopeAuthorization.FromDict(record["authorization"]), **lists,
        )


@dataclass(frozen=True, slots=True)
class LocalScopeStore:
    """Own scope documents under an existing physical workspace's state/scopes namespace.

    Construction performs no I/O. The operator must exclude hostile filesystem writers;
    observed path checks do not defend against malicious concurrent directory replacement.
    """

    workspace_root: Path

    def __post_init__(self) -> None:
        """Reuse workspace lexical root validation without creating or reading local state."""

        object.__setattr__(self, "workspace_root", LocalWorkspaceStore(self.workspace_root).root)

    def _Paths(self, scope_id: str, *, initialize: bool = False) -> tuple[Path, Path, str]:
        """Validate owned paths and optionally initialize the missing authoritative namespace.

        Args:
            scope_id: Lowercase identifier used as one safe filename component.
            initialize: Create absent state/scopes directories only during explicit Create.

        Returns:
            Namespace, record path, and current workspace identity.

        Raises:
            ValueError: Workspace metadata, identity syntax, links, or file types are invalid.
            OSError: Workspace reading or namespace initialization fails.
        """

        RequireIdentifier(scope_id, "scope_id")
        workspace = LocalWorkspaceStore(self.workspace_root).Open()
        namespace = self.workspace_root / "state" / "scopes"

        for directory in (namespace.parent, namespace):
            metadata = StoragePathInfo(directory)

            if metadata is not None and not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("scope namespace must contain only physical directories")

            if metadata is None and initialize:
                directory.mkdir(mode=0o700, exist_ok=True)
                StoragePathInfo(directory)
                SyncStorageDirectory(directory.parent)

        path = namespace / f"{scope_id}.json"
        metadata = StoragePathInfo(path)

        if metadata is not None and (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
        ):
            raise ValueError("scope state must be a regular file without hard links")

        return namespace, path, workspace.workspace_id

    def Open(self, scope_id: str) -> ScopeSnapshot:
        """Read bounded authoritative state and enforce scope/workspace identity binding.

        Args:
            scope_id: Workspace-local lowercase identifier; never a path or raw reference.

        Returns:
            Latest validated snapshot independent of cache/index directories.

        Raises:
            ValueError: Paths, encoding, JSON, schema, canonical fields, or binding are invalid.
            OSError: The record or workspace cannot be read.
        """

        _, path, workspace_id = self._Paths(scope_id)

        with path.open("rb") as stream:
            payload = stream.read(MAX_SCOPE_BYTES + 1)

        if len(payload) > MAX_SCOPE_BYTES:
            raise ValueError("scope state exceeds the metadata size limit")

        try:
            value = json.loads(
                payload.decode("utf-8"), object_pairs_hook=UniqueWorkspaceObject,
                parse_constant=RejectWorkspaceConstant,
            )

        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
            raise ValueError("scope state must be valid bounded UTF-8 JSON") from error

        snapshot = ScopeSnapshot.FromDict(value)

        if snapshot.scope_id != scope_id or snapshot.workspace_id != workspace_id:
            raise ValueError("stored scope/workspace identity does not match its owner")

        return snapshot

    def Create(self, snapshot: ScopeSnapshot) -> ScopeSnapshot:
        """Publish a new scope at revision zero without registering it in workspace metadata.

        Args:
            snapshot: Typed revision-zero proposal bound to the existing workspace identity.

        Returns:
            Persisted initial snapshot.

        Raises:
            ScopeConflictError: Scope already exists or revision/identity is inappropriate.
            ScopeBusyError: An existing writer lock prevents safe publication.
            ValueError: Snapshot, paths, or metadata are invalid.
            OSError: Initialization, durable write, or cleanup fails; reopen before retrying.
        """

        return self._Commit(snapshot, create=True)

    def Save(self, snapshot: ScopeSnapshot) -> ScopeSnapshot:
        """Commit a matching identity/revision under a fail-fast exclusive writer lock.

        Args:
            snapshot: Proposed immutable state at the last observed revision.

        Returns:
            Committed snapshot with revision increased exactly once.

        Raises:
            ScopeConflictError: Revision or owner identity changed.
            ScopeBusyError: A live or abandoned writer owns the lock.
            ValueError: Snapshot, paths, or serialized metadata are invalid.
            OSError: Reading, writing, synchronization, or cleanup fails; reopen before retrying.
        """

        return self._Commit(snapshot, create=False)

    def _Commit(self, snapshot: ScopeSnapshot, *, create: bool) -> ScopeSnapshot:
        """Own publication/CAS and cleanup without touching independently owned workspace files.

        Args:
            snapshot: Validated proposed scope state.
            create: Publish new revision-zero state rather than replacing a matching revision.

        Returns:
            Complete committed snapshot.

        Raises:
            ScopeConflictError: Existence, identity, or revision does not match the operation.
            ScopeBusyError: The cooperating-writer lock already exists.
            ValueError: Proposal or path validation fails.
            OSError: I/O or cleanup fails, possibly after atomic replacement.
        """

        if not isinstance(snapshot, ScopeSnapshot):
            raise ValueError("snapshot must be a ScopeSnapshot")

        namespace, path, workspace_id = self._Paths(snapshot.scope_id, initialize=create)

        if snapshot.workspace_id != workspace_id or (create and snapshot.revision != 0):
            raise ScopeConflictError("scope workspace identity or initial revision differs")

        lock_path = namespace / f".{snapshot.scope_id}.write-lock"

        try:
            lock_path.mkdir(mode=0o700)

        except FileExistsError as error:
            raise ScopeBusyError("scope writer lock exists; never remove a live lock") from error

        try:
            if create:
                if path.exists():
                    raise ScopeConflictError("scope already exists; open before saving")

                committed = snapshot

            else:
                current = self.Open(snapshot.scope_id)

                if current.revision != snapshot.revision:
                    raise ScopeConflictError("scope revision changed; reopen before saving")

                committed = replace(snapshot, revision=current.revision + 1)

            self._Write(path, committed)

            return committed

        finally:
            lock_path.rmdir()

    def _Write(self, path: Path, snapshot: ScopeSnapshot) -> None:
        """Durably replace one owned record through a private same-directory temporary file.

        Args:
            path: Validated destination owned by a lock-holding scope lifecycle operation.
            snapshot: Validated snapshot selected by that operation.

        Raises:
            ValueError: Serialized state exceeds the explicit size limit.
            OSError: Writing, synchronization, replacement, or cleanup fails; reopening is required.
        """

        payload = json.dumps(
            snapshot.ToDict(), ensure_ascii=False, allow_nan=False,
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8") + b"\n"

        if len(payload) > MAX_SCOPE_BYTES:
            raise ValueError("scope state exceeds the metadata size limit")

        temporary_path: Path | None = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=path.parent, prefix=".scope-", suffix=".json", delete=False
            ) as stream:
                temporary_path = Path(stream.name)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())

            os.replace(temporary_path, path)
            SyncStorageDirectory(path.parent)

        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
