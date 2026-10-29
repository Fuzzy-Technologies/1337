# ADR 0047: Attributed offline reachability projections

- Status: Accepted
- Date: 2026-10-13
- Decision owners: Fuzzy Technologies
- Related work: #55, #52, #54

## Context

The Security Object Model owns operational objects, directed typed relations and
retained attributed observations. Its relation identity excludes mutable contents.
A revision number alone cannot identify one exact snapshot. Discovery, findings
and attack-reference membership establish no pivot connectivity or attack path.
The data-only attack-path-mini lifecycle is an oracle, not a SOM transition sensor.

Task #55 needs deterministic candidate paths with explicit uncertainty and named
barriers. The current model has neither a reachability relation enum nor control,
identity or zone object enums. Adding them without their owning domain decisions
would change unrelated persisted contracts.

## Decision

Add Experimental `fuzzy1337.reachability`, profile version 1. Preserve existing
model/runtime/provider schemas. Select explicit existing RELATED_TO relation
references as directed candidate transitions; never select edges by discovering
an open port, a finding, catalog membership or cooccurrence. Use existing ASSET
objects for explicitly declared reachability controls. No new model enum, model
writer, claim store, query cache or executable policy is introduced.

Separate the read-only proof boundary from pure projection/search. Existing
workspace/model/evidence owners validate the current persisted basis and verify
selected immutable manifest identities, bytes, digests, lengths and provenance.
Externally supplied assessment artifacts pin the complete canonical basis model,
scope/context, retained observations and supporting manifests. Assessment artifacts
are acquired separately and are never added to the basis snapshot, avoiding a
circular hash. Only the current persisted basis is admitted by this first loader.
Current means the immutable snapshot returned by that owner read, not continuous
filesystem freshness or a transaction across model and evidence. Later basis or
assessment time requires new owning reads and proof verification.

The five labels summarize source-supplied transition attestations. CONFIRMED means
an admitted source declared a confirmed hop; it is not an independently validated
network measurement. A path's label summarizes admitted hop declarations in one
exact context. It does not prove end-to-end exploitability, credential continuity,
an attacker's behavior, authorization or physical infrastructure completeness.

Retain exact supplied confidence estimates and their attribution. Adopt the
attack-path-mini per-state admission bands, without deriving a state from a number
or composing probabilities. Path output retains per-claim estimates and decisive
blocking claims; it has no invented aggregate numeric confidence.

Missing, stale, future or conflicting declarations yield explicit UNKNOWN. Any
unusable supplied declaration quarantines its transition rather than permitting
last-writer, newest-source or highest-confidence selection. A valid BLOCKED hop
decisively blocks its candidate route even when other hops are unknown. A blocked
claim conflicting with another state on the same hop instead produces UNKNOWN.

Enumerate simple candidate paths deterministically by breadth-first search with
reference-ordered successors. Include blocked/unknown paths for explanation.
Refuse zero-hop queries. Bound depth, successor work, frontier and returned paths;
report the exact limits that leave unexplored work. A complete empty result means
only no candidate path in the exact selected subgraph, never network unreachability.

## Exact profile and evidence

[Reachability](../REACHABILITY.md) specifies interfaces, fields, time/version/proof
admission, state precedence and resource limits. Independent symbolic graph and
semantic oracle fixtures precede implementation. Fixture aliases resolve through
existing SOM constructors; they are not production object-reference spellings.

Use the existing real workspace, model and evidence producers for persistence,
reopening and integrity tests. Independently enumerate small graphs, exercise
cycles/ties/barriers/truncation and attempt to substitute equal-revision snapshots,
observation contents, scope, source version, acquisition times and manifests.
Private literals stay in raw evidence; parser/verification tracebacks omit them.

## Partial boundary

This advances #55 without completing the full #52 domain. No inferred transitions,
stateful credential/session reasoning, control-policy execution, historical basis
queries, validated network-transition producer, attack-path extraction from
findings, clustering, choke points or mitigation ranking is implemented. #55 stays
open while these semantics and their owning producers remain undefined.

## References

- [ADR 0003](0003-intelligence-first-security-workbench.md)
- [ADR 0010](0010-live-security-object-model-modular-tooling-and-lenses.md)
- [ADR 0020](0020-immutable-local-evidence-store.md)
- [ADR 0023](0023-provider-neutral-security-object-model.md)
- [ADR 0033](0033-offline-attributed-attack-references.md)
- [Attack-path mini](../../labs/targets/attack-path-mini/README.md)
