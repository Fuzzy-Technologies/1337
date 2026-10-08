# ADR 0022: Offline target registration and portable scope membership

- Status: Accepted
- Date: 2026-10-05
- Decision owners: Fuzzy Technologies
- Related work: #21, #13

## Context

[ADR 0005](0005-scope-and-ai-neutral-knowledge-layer.md) requires first-class
scope and model-agnostic state. The [workspace contract](0019-portable-workspace-state-and-persistence.md)
already stores opaque scope references but cannot interpret consent or target
membership. Later adapters and workflows need literal identities and deterministic
membership decisions before a separate execution policy can issue invocation-bound
authorization. Neither registration nor an AI-selected target proves permission.

## Decision

Introduce the Experimental `fuzzy1337.scope` library and scope file schema `1`,
documented in [Targets and Scope](../SCOPE.md). Immutable `Target` records normalize
explicit domain, IP, network, or HTTP(S) URL literals offline. Target references are
`target:<SHA-256>` over compact sorted UTF-8 JSON containing exactly canonical
`kind` and `value`, without a newline. Other components consume those references
as opaque identities rather than reimplementing scope normalization.

An immutable `ScopeSnapshot` binds `scope_id` to `workspace_id`, registered targets,
allow/deny/exclusion lists, an explicit `ScopeAuthorization`, and a mutable-state
revision. `scope:<scope_id>` references retain the surrounding workspace context.
Registration is idempotent and grants nothing. Default consent is unknown; granted
consent needs non-secret operator/approval references and may have explicit UTC
validity bounds. Metadata attributes a declaration rather than cryptographically
verifying permission. Evaluation requires a caller-supplied timezone-aware time.

Unknown/revoked/future/expired consent fails closed before membership evaluation.
Unregistered candidates fail closed. Exclusions precede deny, which precedes allow.
Allow rules match exact typed domains and URLs; no implicit DNS, subdomain,
redirect, scheme, port, URL path-prefix, or cross-kind grant exists. IP/network
allow rules require complete same-version containment. Deny/exclusion IP/network
rules reject any overlap, including a broad network containing a denied host.
Deny/exclusion rules also restrict a URL's explicit literal IP/CIDR or exact
canonical domain authority, so an exact URL allow cannot bypass its denied host.
This projection only restricts membership and never resolves domain/IP aliases.
The whole candidate is rejected rather than silently rewriting it to skip addresses.

`ScopeDecision` preserves a reason and scope/target/matched-rule references. It is
membership evidence, not an `ExecutionAuthorization`. The governed executor keeps
its independent impact and invocation-bound authorization boundary. A later policy
owner must bind the decision, observed scope revision, actual resolved/redirected
destinations, and prepared invocation; this library issues no such grant.

## Storage boundary

`LocalScopeStore` owns `state/scopes/<scope_id>.json` inside an existing operator-owned
physical workspace. It reuses the workspace path/strict JSON validation primitives
and independently validates exact typed domain fields. Workspace metadata continues
to own opaque references only; consumers register the scope through the existing
`scope_references` field. Evidence and model storage remain separate owners.

Each record is bounded to 1 MiB, rejects noncanonical stored literals/times, unknown
versions/fields, duplicate JSON keys, malformed types, and wrong owner identities.
Constructing the store performs no I/O. Create/Open/Save are explicit. Create starts
at revision zero; Save uses an exclusive per-record lock and revision comparison,
then private temporary write, flush/fsync, atomic replacement, and POSIX directory
synchronization. Stale writers conflict; existing locks are never stolen. Readers
see complete snapshots while another writer holds its lock. Ordinary failures clean
resources; after a failure beyond replacement, callers reopen before retrying.

Reject lexical traversal, observed symlinks/reparse points, non-directory paths,
non-regular records, and hard-linked scope records. The operator excludes hostile
concurrent filesystem writers; this path-based implementation does not claim
resistance to malicious directory replacement. Moving the whole workspace preserves
portable identities and references. A record copied into another workspace identity
is invalid. Scope commit and workspace-reference commit are independent operations;
a failed reference update may leave a valid unreferenced record.

## Consequences and validation

- First security workflows can reuse typed targets and explainable offline scope
  decisions without changing workspace, adapter, executor, or evidence schemas.
- Missing consent and restrictive rule overlaps are directly testable and remain
  denied even if the operator registers the target or adds an allow rule.
- Unit and contract tests cover IDNA/IPv6/URL boundaries, canonical identity,
  strict schema decoding, consent validity, rule precedence, and address overlap.
- Real integration tests cover scope/reference persistence, relocation, independent
  ownership, foreign-workspace rejection, and private creation permissions.
- Writer tests cover stale proposals, contention, abandoned locks, size limits,
  unsafe paths, and write failures before/after replacement.
- No runtime dependency, CLI registration command, resolver, scanner, policy issuer,
  external consent authority, or implicit execution permission is introduced.
