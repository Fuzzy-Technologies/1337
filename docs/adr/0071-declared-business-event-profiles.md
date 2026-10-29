# ADR 0071: Declared business-event profiles over the existing model

- Status: Accepted
- Date: 2026-10-14
- Decision owners: Fuzzy Technologies
- Related work: #66, #62

## Context

An unacceptable business outcome is an owner-declared scenario. It is neither an
observed incident nor a technical exploitability fact. The existing Core object
and persistence schemas must remain unchanged. Reachability already owns verified
technical transition attestations, and path analysis owns their explanations.

## Decision

Introduce an Experimental, bounded `fuzzy1337.business_events` profile. Original
owner-definition JSON is retained by the existing evidence owner. Its exact
manifest, workspace, scope, version, acquisition times and original bytes are
verified before use, against the current persisted model pin. A definition names
an owner, a versioned outcome and explicit existing critical Asset references.

The canonical Asset represents the **outcome declaration**, with an explicit
`business-event-definition` asset type. This follows ADR 0023's generic Asset
profile extension; it does not create a new Core kind. Identity includes the
declaration and its original evidence manifest, preventing unrelated provenance
from collapsing into one owner declaration. Replaying that manifest is idempotent.
Changing a definition or its source acquisition creates a separate declaration.

Descriptive `RELATED_TO` links connect each critical Asset to the declaration.
They explicitly mean declared impact membership, not a traversable technical hop.
Analysis refuses projections containing those links or declaration objects. It
uses existing verified technical projections from each explicitly selected
attacker position to each declared critical Asset, and retains the separate final
membership link in the explanation. Reaching an asset only identifies a candidate
scenario for its declared outcome; it never proves that outcome occurred.

The profile does not infer attacker positions, technical edges, financial loss,
risk probability, control effectiveness or execution permission. Existing hop
states, individual confidence estimates, evidence references, selected-subgraph
scope, independent cut-work bounds and enumeration truncation remain intact.
No confidence aggregation or transitive impact edge is introduced.

## Ownership and limits

The existing model/evidence owners remain authoritative. Applying a declaration
returns an immutable model and delta; the caller owns revision-checked persistence.
Analysis is pure after explicit owner reads. A definition has at most 16 critical
Assets and 64 KiB of original JSON. A query has at most 16 distinct explicit
attacker positions and 64 source/asset pairs. Existing bounded search and cut
limits apply separately to each pair; the pair ceiling bounds aggregate work.
Critical Assets must exist in the exact workspace and cannot be control or
business-event declaration profiles. Definitions and memberships are validated
again before analysis, including their retained original attribution.

## Verification

Tests exercise actual original-evidence acquisition, definition loading, model
application, CAS save, reopen, relocation and independently known candidate paths.
Failure paths cover foreign/missing source material, malformed and forged typed
records, stale model pins, changed representation, descriptive-edge misuse,
truncation, conflicting/stale hop attestations and unchanged findings/triage.
The profile adds no CLI, network operation, scanner invocation or publication.
