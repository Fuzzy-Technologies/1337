# Offline reachability projection

ADR 0047 proposes an Experimental version-1 projection and candidate-path profile
for #55. Implementation awaits explicit independent contract agreement.

## Ownership and interfaces

The canonical ModelState owns objects, relations and immutable observations.
Projection creates no model records, registers no targets and grants no execution
permission. Neither graph labels nor scope/context strings authorize an action.

| Proposed interface       | Responsibility                                                                       |
| ------------------------ | ------------------------------------------------------------------------------------ |
| ReachabilityModelVersion | Workspace ID, model schema version, revision and full canonical snapshot SHA-256     |
| ReadReachabilityClaims   | Read-only owning workspace/model/evidence verification and assessment interpretation |
| ProjectReachability      | Pure projection of explicit existing transitions and verified, attributed claims     |
| SearchReachabilityPaths  | Pure bounded deterministic simple-path enumeration and hop-summary classification    |

ReadReachabilityClaims takes ModelState, an explicit tuple of EvidenceRecord
assessment manifests and workspace_root, plus the expected model version,
context_reference, scope_reference, aware at and max_age_seconds. Its result is a
frozen ephemeral claim collection. Direct result constructors and parsing helpers
are Internal; a Python type alone is not proof or authenticated source authority.

The loader opens the existing workspace and persisted model through their owners.
Both must match the supplied workspace/schema/revision/full snapshot digest. It
reads no historical basis and writes nothing. LocalEvidenceStore.Get and Read
verify each manifest and original blob; a reference/hash alone does not verify
stored evidence. A forged caller record must match the canonical stored manifest.

ProjectReachability takes the exact ModelState, explicit selected relation refs,
the loaded claim collection and expected_model_version. It rechecks the full
canonical model pin and performs no I/O. Queries take that projection, the exact
ModelState, distinct source/target refs and explicit limits. Query time and scope
are those of the projection; a later time or model requires rereading/reprojection.
Queries recheck the exact model pin before using graph data.

## Model and context binding

ModelVersion includes schema_version, workspace_id, revision and snapshot_sha256.
The digest covers CanonicalModelJson(ModelState.ToDict()), including every current
attribute, provenance and retained observation. Reusing a revision with different
contents cannot substitute another basis. Query/graph identities also bind profile,
model pin, scope/context, assessment time, freshness limit and selected transitions.

Selected edges must exist and use RelationKind.RELATED_TO. Their ordered endpoints
define direction; no reverse edge is inferred. Eligible nodes are existing Domain,
Host, Asset, Port, Service, Endpoint and Technology objects. Workspace/Scope/Target
reference projections and Findings are not traversal nodes. Bare RELATED_TO edges
are UNKNOWN unless explicitly assessed. Other relation kinds and every incidental
attribute, finding or catalog association are ignored as reachability declarations.

All claims share the exact requested context_reference and scope_reference.
Context is an explicit non-secret caller identifier, not authenticated identity,
credential state or policy. Scope is attributable collection metadata only.

## Assessment artifact grammar

An assessment is strict UTF-8 JSON in an existing immutable evidence record:

| Envelope field    | Exact meaning                                        |
| ----------------- | ---------------------------------------------------- |
| profile_version   | Integer 1, excluding boolean/coercion                |
| assessment_kind   | Literal supplied-transition-attestation              |
| model_version     | Complete basis pin defined above                     |
| context_reference | Exact query context identifier                       |
| scope_reference   | Exact requested acquisition scope                    |
| claims            | Bounded list of explicit per-transition declarations |

Each claim has exactly relation_reference, state, confidence, inference_rule,
basis and blocking_controls. inference_rule is an explicit non-secret identifier
for LIKELY and null otherwise; the engine never evaluates a named rule. A basis
entry has observation_reference and evidence_manifest_ids. The observation must
be retained in the pinned model, address that exact relation and have kind
reachability-support. Its evidence references must be nonempty for known states.
The listed manifests cover its evidence references exactly, without omissions,
duplicates or substituted roles/content. They are verified through the owner.

Supporting provenance must match the retained observation's source ID, provider
version/tool version, scope, observed time/finished acquisition time and execution
outcome, including explicit None. Manifest workspace equals the model workspace.
Failed/cancelled/timed-out support acquisitions are unusable, not successful proof.
An execution outcome of None remains a supplied/imported assessment, never success.

Assessment manifests use role reachability-claims, application/json, source_version
1 and no invocation digest/execution. They retain the supplied source ID, tool
version and collection times. Manifest scope equals envelope/query scope. The
assessment is a verified source attestation; this boundary authenticates neither
the source actor nor the correctness of a measurement or inference.

BLOCKED additionally requires nonempty blocking_controls. Each entry identifies
an existing ASSET with asset_type reachability-control, an exact retained
reachability-support observation on that control and the complete supporting
manifest IDs. Controls have distinct references. Non-BLOCKED declarations have
an empty control list. The source explicitly asserts that those controls block
this transition; the engine does not execute or reconstruct their policy.

Unknown fields, wrong types/bands, duplicate declaration identity, malformed
references, unsupported versions, invalid Unicode/constants and byte/node/depth
violations refuse the entire input. Unsupported relation kinds refuse. Foreign
workspace/context/scope substitution refuses. Corrupt/missing/unsafe stored
manifests or bytes raise the existing evidence failure with sanitized diagnostics.
No partial verified claim set is returned after such a failure.

## Time, uncertainty and confidence

ModelState has no creation timestamp. The loader does not claim one. It checks
only measurable source times: every selected support observation equals its
verified manifest's finished_at; all support acquisition/observation times precede
the assessment manifest's started_at. All selected support and assessment times
are no later than at and their age is at most max_age_seconds (inclusive).
Freshness defaults to 3600 seconds and accepts an explicit integer 0..604800.
No implicit clock or arbitrary freshness inference is used.

A syntactically valid assessment pinned to an older/different same-workspace
model is stale. A missing retained basis observation, absent basis/evidence for a
known state, stale/future support or inconsistent time order makes its declaration
unusable and its transition UNKNOWN with an explicit reason. Assessment source
confidence and reference/provenance stay visible; effective numeric confidence
is absent. Do not use another declaration to conceal the unusable supplied one.

| Declared state | Admitted supplied confidence | Additional condition                     |
| -------------- | ---------------------------- | ---------------------------------------- |
| UNKNOWN        | 0.0                          | May omit basis; no assertion of reach    |
| POTENTIAL      | 0.40..0.69                   | Explicit verified retained basis         |
| LIKELY         | 0.70..0.89                   | Basis plus supplied inference rule       |
| CONFIRMED      | 0.90..1.0                    | Explicit verified retained basis         |
| BLOCKED        | 0.90..1.0                    | Basis and named verified modeled control |

These bands adopt the data-only attack-path-mini vocabulary; no source score
causes an automatic state change. Booleans, nonfinite values and scores outside
the declared state's band refuse. Scores are attributed estimates, never calibrated
probabilities or endorsements by this engine.

Different current states for one transition conflict and yield UNKNOWN. Multiple
admitted declarations of the same state retain all estimates/provenance/control
proofs; the engine chooses no winner and invents no combined estimate. Exact source
replay is deduplicated by canonical artifact/claim identity.

## Candidate path semantics

Queries require existing eligible distinct source and target object refs. A
source=target query refuses rather than manufacturing zero-hop confirmation.
Paths contain no repeated node. The selected graph includes every selected edge,
including UNKNOWN and BLOCKED transitions, so a blocked candidate stays explainable.

Classify a candidate only after transition claim admission/conflict handling:

1. Any admitted BLOCKED hop makes the route BLOCKED and names its decisive
   control/claim evidence. An unrelated UNKNOWN hop does not erase that barrier.
2. Otherwise any UNKNOWN hop makes the route UNKNOWN.
3. Otherwise any POTENTIAL hop makes it POTENTIAL.
4. Otherwise any LIKELY hop makes it LIKELY.
5. Otherwise every hop has admitted CONFIRMED declarations, so the hop summary
   is CONFIRMED. This does not validate the end-to-end route or exploit chain.

Retain every hop's claim/evidence/model/observation refs and exact supplied
confidence estimates. The path has no aggregate probability. Decisive BLOCKED
confidence is the attributed estimate of its blocking claims, not a minimum over
unrelated unknown hops. All records label semantics supplied-attestation / attested-
hop-summary. No scope, consent, impact or invocation authority is returned.

## Determinism and completeness

Use breadth-first simple-prefix enumeration. Sort outgoing edges by canonical
relation ref and return paths by (hop count, ordered relation-ref tuple). Claim and
input insertion order never decide ties. Count every examined successor against
max_work, including cycle/self-loop exclusions. Cycles are finite exclusions, not
proof that another route exists. Exclude a successor only when it repeats a node
in the current prefix; an edge participating in a cycle may be valid in another
simple candidate path. Do not prioritize a state or confidence score.

Limits are explicit per query. Stop without dropping undisclosed work when the
successor-work, frontier or path budget is reached; expose corresponding reasons.
A depth limit that leaves an unvisited successor is also incomplete. Hitting an
exact limit after the final successor with no unexamined successor or queued
prefix remaining is complete. A found path never
silently makes the remaining enumeration complete.

complete describes enumeration of the exact selected graph only. If complete is
true and paths is empty, no_candidate_path is true for that subgraph. With any
truncation it is false and incompleteness is explicit. Even a complete empty
candidate graph does not prove infrastructure unreachability, global absence of
attack paths, or exhaustive discovery. Proof admission coverage is reported
separately from search completeness.

| Resource                        | Hard bound                      |
| ------------------------------- | ------------------------------- |
| Full basis model                | Existing 8 MiB                  |
| Eligible projected nodes        | 512                             |
| Explicit selected transitions   | 2048                            |
| Assessment artifacts            | 32                              |
| Each assessment JSON            | 256 KiB / 8000 nodes / 16 depth |
| Total declarations              | 2048                            |
| Basis entries per claim/control | 16                              |
| Unique supporting manifests     | 256                             |
| Each supporting raw artifact    | 64 KiB                          |
| Query depth                     | Default 16 / maximum 32         |
| Returned candidate paths        | Default 64 / maximum 256        |
| Examined successors             | Default 4096 / maximum 20000    |
| Pending simple prefixes         | Default 1024 / maximum 4096     |

Check supplied/expected reference sizes before owned-store reads. Memoize verified
support manifests only within this call; there is no durable cache. Diagnostics
and tracebacks omit untrusted field values and raw bodies, even on owner failures.

## Acceptance and remaining boundaries

Independent symbolic fixtures and handwritten semantic oracles precede code.
Resolve aliases with existing SOM constructors; generate no expected paths from
the implementation. Enumerate small graph answers independently and exercise
every state, compatible/conflicting sources, barriers, ties, cycles, exact-limit
completion, no-path scope, missing/stale/future/substituted proof and corrupted
manifest/bytes. Test equal-revision content substitution and real model/evidence
save, reopen and relocation. An I/O tripwire verifies projection/search purity;
verification reads only the explicitly owned local workspace and evidence.

Validated sensor-to-transition semantics, historical queries, general graph domain
profiles, credential/precondition state, control-policy evaluation, probabilistic
reasoning, UI/report wiring and live traffic remain outside this slice. Task #55
and feature #52 remain open for those gaps.
