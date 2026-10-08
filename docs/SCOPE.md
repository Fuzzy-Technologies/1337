# Targets and Scope

`fuzzy1337.scope` is an Experimental Python library and persisted scope schema at
version `1`, defined by [ADR 0022](adr/0022-target-registration-and-scope.md).
It registers typed targets, evaluates explicit consent and membership offline,
and stores portable scope records in an existing [workspace](WORKSPACES.md).
It does not introduce a CLI, resolve DNS, contact targets, verify consent records,
follow redirects, or issue an [executor](EXECUTORS.md) authorization.

## Supported API

The Experimental surface consists of `TargetKind`, `Target`, `AuthorizationState`,
`ScopeAuthorization`, `ScopeDecisionReason`, `ScopeDecision`, `ScopeSnapshot`,
`LocalScopeStore`, `ScopeConflictError`, `ScopeBusyError`, `SCOPE_SCHEMA_VERSION`,
and `MAX_SCOPE_BYTES`. Supported operations are:

- `Target.Reference`, `.ToDict`, and `.FromDict`;
- `ScopeAuthorization.ToDict` and `.FromDict`;
- `ScopeDecision.Allowed`;
- `ScopeSnapshot.Reference`, `.Register`, `.Check`, `.ToDict`, and `.FromDict`;
- `LocalScopeStore.Create`, `.Open`, and `.Save`.

Underscore-prefixed helpers are Internal implementation details. Constructing
records or a store performs no filesystem or network I/O. Frozen records can be
changed by producing a proposal with `dataclasses.replace`; persistence is always
explicit. Rule and registration lists retain declaration order and reject
duplicate normalized identities within each list.

## Target literals and identity

`Target(kind, value)` requires an explicit `TargetKind`: `domain`, `ip`, `network`,
or `url`. The constructor normalizes the selected literal once. No kind inference,
wildcards, resolver-dependent short/hexadecimal IP notation, surrounding whitespace,
controls, or interface zone identifiers are accepted.

| Kind      | Canonical spelling and membership boundary                                   |
| --------- | ---------------------------------------------------------------------------- |
| `domain`  | Lowercase standard-library IDNA DNS labels; one trailing root dot is removed |
| `ip`      | Standard-library compressed IPv4/IPv6 literal                                |
| `network` | Explicit prefix, compressed CIDR; host bits are rejected rather than widened |
| `url`     | Exact HTTP(S) URL, normalized host/default port and UTF-8 encoded path/query |

URL credentials, fragments, invalid percent escapes, dot path segments (including
encoded dots), repeated path separators, and encoded slash/backslash separators
are rejected. Empty URL paths normalize to `/`. Path and query identity otherwise
remain exact; query changes, schemes, ports, subpaths, and redirects require
separate targets and explicit rules. Domain identity does not imply subdomain or
URL authority. IP rules do not authorize a domain that might resolve to that IP.
URL normalization is a literal identity contract, not a proof of how every remote
HTTP server interprets a request; later execution policy must bind actual actions
and handle redirects and resolved destinations separately.

`Target.Reference()` returns `target:<64 lowercase SHA-256 hex>`. The digest input
is exactly `json.dumps({"kind": kind.value, "value": canonical_value},
ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")`,
without a newline. This identity is shared as an opaque reference with model,
adapter, and evidence consumers. It contains no authorization assertion.

`ScopeSnapshot.Reference()` returns `scope:<scope_id>`. The scope identifier is a
lowercase machine identifier and is local to its declared `workspace_id`;
consumers retain the workspace context. A reference identifies the evolving
record, not one immutable revision. Jobs must later bind the checked revision and
invocation under their separate policy contract.

## Consent and deterministic membership

`ScopeAuthorization` records a typed `unknown`, `granted`, or `revoked` state.
`unknown` is the default. `granted` requires non-secret `authority_reference` and
`record_reference` values chosen by the operator. Optional `valid_from` and
`valid_until` bounds require explicit timezones and normalize to UTC. Both bounds
are explicit fields: null means no bound, never an inferred date. If both exist,
the interval must increase. Consent references are attribution metadata, not
signed grants or proof that the referenced approval is genuine. Operators must
exclude credentials and secret values from all persisted metadata.

`ScopeSnapshot.Register(target)` adds a target idempotently to a proposed
snapshot without changing its revision or granting membership. Separate `allow`,
`deny`, and `exclusions` lists contain typed target rules. Rules may be declared
before particular candidates are registered, for example an allowed CIDR network.

`Check(target, at=<timezone-aware datetime>)` uses only explicit input and returns
a frozen `ScopeDecision`. It consults no hidden clock. Evaluation order is:

1. Unknown or revoked consent, future validity, and expiry fail closed. Validity
   includes `valid_from` and excludes `valid_until`.
2. A candidate absent from `targets` is `unregistered`.
3. Matching `exclusions` win, then `deny`, then `allow`.
4. Without an allow rule the candidate is `not_allowed`.

Allow rules match exact domains and URLs. Allowing a network covers an IP or a
whole subnet only within the same IP version. Deny/exclusion address rules reject
any overlap with a proposed network: an allowed `/24` cannot authorize a scan
that includes an excluded `/32` or subnet. A deny/exclusion rule also restricts a
URL whose explicit authority is that exact canonical domain or literal IP/CIDR.
Thus an exact URL allow cannot bypass a denied host or network. This conservative
projection only restricts membership; it never grants cross-kind authority or
resolves domain/IP aliases. The implementation refuses the whole candidate; it
does not silently subtract addresses or rewrite an invocation.

Decision reasons are `allowed`, `authorization_unknown`, `authorization_revoked`,
`authorization_not_yet_valid`, `authorization_expired`, `unregistered`, `excluded`,
`denied`, and `not_allowed`. The decision retains scope/target references and,
where a membership rule matched, its target reference. `Allowed()` is true only
for `allowed`. This result is scope membership evidence; impact policy and
invocation-bound execution authorization remain separate work.

## Portable persistence and ownership

`LocalScopeStore(workspace_root)` requires an existing physical workspace for
operations and owns only `state/scopes/<scope_id>.json`. Each schema-v1 document
contains exact fields: `schema_version`, `scope_id`, `workspace_id`, `revision`,
`authorization`, `targets`, `allow`, `deny`, and `exclusions`. Nested target and
authorization fields are likewise exact. Unknown versions/fields, missing fields,
duplicate JSON keys, non-finite numbers, malformed types, noncanonical stored
literals/times, and mismatched workspace/scope identity fail closed. No document
contains an installation-specific absolute path.

`Create(snapshot)` initializes absent owned directories and writes a new scope at
revision zero. `Open(scope_id)` validates bounded UTF-8 JSON and owner binding.
`Save(snapshot)` acquires an exclusive per-scope directory lock, compares the
observed revision, and increments it once. Stale proposals raise
`ScopeConflictError`; live or abandoned locks raise `ScopeBusyError`. Reads remain
available while a cooperating writer owns the lock. Locks are never stolen; an
operator must establish no writer remains before manual recovery.

Writes use private same-directory temporary files, flush/fsync, atomic replacement,
and POSIX directory synchronization. Windows retains file synchronization and
atomic replacement without the POSIX directory durability guarantee. Pre-replace
failure retains the previous snapshot. A failure after replacement may leave the
new revision visible, so callers must reopen before retrying. Temporary files and
owned locks are cleaned after ordinary failures. Initial directory creation can
leave empty owned directories after a failed `Create`.

Scope metadata is limited to 1 MiB on both read and serialization. Traversal,
observed symlinks/reparse points, non-directory namespaces, non-regular records,
and hard-linked scope records are rejected. The operator owns the tree and must
exclude hostile concurrent filesystem writers; path checks do not prevent
malicious directory replacement between checks. Integrity and consent authenticity
are not established by this local mutable storage contract.

Scope operations never mutate workspace metadata, evidence, caches, indexes, or
another domain's state. The caller separately saves the returned scope reference
in existing `WorkspaceState.scope_references`; no workspace schema change is
required. These two owners do not share a transaction: failed workspace reference
registration can leave a valid unreferenced scope record. Moving the entire
workspace preserves its identity, records, and references. Copying a scope record
into a different workspace identity is rejected.

## Bounded library example

The following constructs a proposal and checks a documentation-only literal;
it performs no network or filesystem operation:

```python
from datetime import datetime, timezone

from fuzzy1337.scope import (
    AuthorizationState, ScopeAuthorization, ScopeSnapshot, Target, TargetKind,
)

target = Target(TargetKind.IP, "192.0.2.5")
consent = ScopeAuthorization(
    AuthorizationState.GRANTED,
    authority_reference="operator:synthetic-fixture",
    record_reference="consent:synthetic-fixture",
    valid_until="2026-11-01T00:00:00+00:00",
)
proposal = ScopeSnapshot(
    "synthetic-scope", "synthetic-workspace", consent,
    allow=(Target(TargetKind.NETWORK, "192.0.2.0/24"),),
).Register(target)
decision = proposal.Check(target, at=datetime(2026, 10, 5, tzinfo=timezone.utc))
assert decision.Allowed()  # Membership only; this does not approve an executor job.
```

Consent validation against an external authority, signed authorization, execution
policy issuance, credential storage, target discovery, network scanning, CLI,
remote storage, and automatic orphan/lock recovery are outside this initial
contract.
