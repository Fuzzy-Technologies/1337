# ADR 0066: Explainable selected-graph path analysis

- Status: Accepted
- Date: 2026-10-13
- Decision owners: Fuzzy Technologies
- Related work: #56, #52, #55

## Context

The attributed offline reachability profile already verifies the exact persisted
model and supplied evidence, selects explicit directed transitions, and enumerates
bounded simple candidates. Its attested-hop summaries establish neither physical
exploitability nor a permission to execute. Task #56 needs explainable participation,
grouping, choke points and mitigation leverage without inventing those authorities.

## Decision

Add Experimental `fuzzy1337.path_analysis`, profile version 1, as a pure consumer
of the existing verified reachability projection and exact immutable model. Call
the existing public search interface rather than accepting caller-made path outputs.
Preserve its returned paths, admission coverage, limits and truncation reasons.

Count node and relation participation by each original path state. Single-removal
leverage counts the returned candidates that do not contain an admitted BLOCKED
hop and would disappear if the selected node or relation were removed. Preserve
their exact path references. This is structural scenario analysis, not an estimate
of remediation efficacy, calibrated risk, cost or expected attacks. Endpoints are
excluded from node-removal recommendations. Truncated enumeration remains a sample;
even complete enumeration is restricted to its explicit depth and selected graph.

Independently inspect the selected graph with admitted BLOCKED transitions omitted.
UNKNOWN, POTENTIAL, LIKELY and CONFIRMED transitions remain possible candidates.
Find one deterministic breadth-first witness, then test removal of each interior
node and relation on that witness. Every unavoidable element must lie on that
witness. Bounded breadth-first checks identify whether any alternative route still
exists, including routes deeper than the enumeration depth limit. A verified choke
point is an element whose removal disconnects source from target in this exact
selected nonblocked graph. It is never a claim about infrastructure completeness.
Count every examined successor against one separate shared cut-work budget. A
budget exhaustion yields explicit unverified candidates, never a false choke point
or an assertion that there is no route. Keep cut completeness independent from
simple-path enumeration completeness. Cycles and self-loops are finite graph work;
they do not require enumeration of all simple paths to verify a structural cut.

Semantic groups are explicit caller declarations over existing eligible model
object references. Reject overlapping, empty, duplicate or foreign memberships.
Keep ungrouped nodes as singleton presentation groups. Retain exact original
members and directed relation references in bundles, including internal edges and
uncertain or blocked states. Never run reachability on the grouped view: collapsing
distinct objects can create false continuity. No incidental attribute or finding
automatically creates a group, transition or attack path.

The module owns no model writes, evidence reads, execution, group persistence,
confidence composition or policy evaluation. Reverification at another time or
against another persisted model remains the reachability owner's responsibility.
No existing model, evidence, provider or reachability schema changes.

## Verification and remaining boundaries

Handwritten alias-based counts and cuts precede implementation. Exercise actual
workspace/model/evidence producers and reopen the stored basis before analysis;
verify both admitted source attestations and bare UNKNOWN selected transitions.
Compare small directed graphs against an independent reachability/removal oracle.
Test cycles, isolated nodes, all-BLOCKED paths, parallel presentation bundles,
truncated samples, depth-independent cuts, exact work bounds, grouping substitution,
equal-revision model substitution and pure-interface I/O tripwires.
Canonical RELATED_TO relations with the same original endpoints share one model
identity. Parallel-token Internal algorithm tests assert removal robustness;
they do not establish a producer of parallel original model relations.

This bounded slice advances #56. Large-environment partitioning, sensor-validated
attack semantics, automatic semantic clustering, multielement remediation planning,
cost/risk ranking and product UI/report wiring remain outside this decision.

## References

- [ADR 0047](0047-attributed-offline-reachability-projections.md)
- [Path analysis](../PATH_ANALYSIS.md)
- [Reachability](../REACHABILITY.md)
