# Explainable selected-graph path analysis

Experimental `fuzzy1337.path_analysis`, profile version 1, consumes an existing
verified reachability projection and its exact canonical immutable `ModelState`.
It writes no model/evidence, performs no I/O, runs no tools and grants no authority.
The original reachability owner still verifies persisted inputs and supplied
attestations before this pure consumer is called.

`AnalyzeReachabilityPaths` calls the existing bounded `SearchReachabilityPaths`
interface, rechecking the complete model pin and projection integrity. It returns
the original search result alongside participation, structural single-removal
leverage, independent choke-point checks and explicit presentation groups.
Original hop states, exact per-claim confidence estimates, named blocking-control
proofs and search/admission coverage remain available through the original paths
and projection. There is no aggregate probability or automatic finding-to-path
inference. Direct result construction and algorithm helpers are Internal.

## Participation and structural removal

Each participating node or relation retains its exact returned path references
and counts by CONFIRMED, LIKELY, POTENTIAL, BLOCKED and UNKNOWN hop summary.
Participation includes source/destination and blocked routes for explanation.
Unvisited elements receive no invented zero-or-positive estimate.

Removal leverage is the exact count/list of returned non-BLOCKED candidates that
contain an element, with the remaining returned non-BLOCKED denominator. Paths
are simple, so removing that original node or relation deletes each such returned
candidate once. Source and destination nodes are excluded from node-removal
recommendations. Relations retain their independent identity, including parallel
directed relations. Results are ordered by descending affected count, then kind
and canonical reference; this deterministic presentation is not cost/risk ranking.

The leverage scope is `complete-returned-candidates` when enumeration is complete
and `truncated-returned-candidates` otherwise. Preserve the original search's
limits, reasons and selected-subgraph scope in either case. Complete enumeration
means complete under that search's declared profile, not exhaustive physical
infrastructure, exploitability or validated mitigation efficacy. UNKNOWN,
POTENTIAL and LIKELY routes stay candidates, without promotion to confirmation.
Already BLOCKED paths retain their barriers but never inflate additional leverage.

## Independent selected-graph choke points

Cut analysis omits only transitions with an admitted BLOCKED state. A conflict
that resolves to UNKNOWN remains a possible candidate edge. It traverses the
full selected nonblocked directed graph, including paths deeper than the simple
enumeration depth bound. This independence prevents a shallow or truncated sample
from declaring a false unavoidable element.

One reference-ordered breadth-first walk finds an original-object/relation witness.
Every unavoidable element must occur on that witness. Remove each interior node
and each witness relation individually and run an independent breadth-first
reachability check. A verified choke point disconnects source from destination;
`alternatives_exist` records checked elements with another candidate route.
Endpoints are excluded from node checks. An absent original nonblocked route
produces no choke-point recommendation. Cycles and self-loops are bounded visited
graph work, and parallel original relations remain distinct.

`PathAnalysisLimits.max_cut_work` bounds all successor examinations across the
initial witness and every removal check together. Default: 100000; exact inclusive
range: 1..2000000, excluding boolean/string/float coercion. Every examined edge,
including a removed edge or previously visited destination, consumes work. Existing
projection ceilings remain 512 eligible nodes and 2048 selected transitions;
there is no unbounded frontier or all-simple-path enumeration in these graph walks.

The cut result separately exposes `candidate_route_exists` (true, false or unknown),
the witness, verified cuts, checked alternatives, unverified remaining candidates,
charged work, completeness and `cut-work-limit`. Exhaustion cannot prove absence or
a cut. If the initial witness check is unfinished, candidate existence is unknown
and there is no fabricated remaining-candidate list. Hitting the exact budget on
the final examination remains complete when no further graph work is required.
Cut completeness is independent from returned-path completeness. All cut claims
use `selected-nonblocked-transition-subgraph-only`, never a network-global claim.

## Explicit semantic presentation groups

`PathSemanticGroup` declares a bounded ASCII `group_key` (1..128 characters) and
1..512 distinct canonical object references in an immutable tuple. The public
consumer takes at most 512 groups and refuses duplicate keys, overlapping members
or objects outside the exact projection's eligible nodes. It infers no groups from
attributes, findings, catalog references or incidental cooccurrence.

Declared members are canonicalized; every ungrouped node remains a singleton.
Groups retain all original member references. Directed presentation bundles retain
each original transition, its state and its proof, including internal group edges.
They contain no synthetic transition, composed state or aggregate confidence.
Never traverse the grouped presentation: collapsing distinct original nodes can
create false continuity. Group/member ordering does not change the deterministic
analysis identity. Changing membership, key, cut budget or search inputs does.

## Verification and boundary

Handwritten counts and cuts in `tests/contract/fixtures/path-analysis.oracle.v1.json`
precede implementation and resolve aliases through existing model constructors.
Actual persisted model/evidence reopening, relocation and storage/network I/O
tripwires exercise the public consumer. An independent small-directed-graph oracle
checks individual node/relation removal, cycles, self-loops and exact work bounds.
An actual saved long-detour model verifies that shallow enumeration cannot create
a false choke point. Blocked, uncertain/conflicting, mixed and truncated candidates
keep separate denominators and explicit completeness.

This advances #56 and leaves it open for large-environment partitioning, automatic
semantic clustering, sensor-validated attack semantics, multielement remediation
planning, cost/risk ranking and product UI/report wiring. Model, evidence, provider
and reachability schemas stay unchanged. See
[ADR 0066](adr/0066-explainable-selected-graph-path-analysis.md).
