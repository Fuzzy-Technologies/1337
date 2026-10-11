# ADR 0035: Versioned offline standards mappings

- Status: Proposed for owner review
- Date: 2026-10-11
- Decision owners: Fuzzy Technologies
- Related work: #68, #63; ADR 0010, ADR 0023

## Context

Framework classifiers and controls describe interpretations of findings. Their
catalog versions and review provenance must survive reports without becoming
Security Object identity, raw Evidence, or certification claims. Publisher
crosswalks and first-party contextual interpretations have different authority.

## Decision

Introduce Experimental `fuzzy1337.standards_mapping` schema version 1. Immutable
`StandardIdentity` values preserve family, exact upstream catalog version, and
external item ID. Families are extensible lowercase machine identifiers; a new
national, regulatory, or vendor pack does not change canonical object identity.
Syntax validity never establishes upstream item existence.

Each `StandardsMapping` has explicit source and target identities, a finite typed
relation, rationale, and 1..16 source citations. Citations expose publisher,
source version, HTTPS URL, locator, acquisition time, and optional source-artifact
SHA-256. Absent hashes remain visibly absent. Metadata is trusted caller input;
validation is not a secret detector. No URL is fetched at runtime.

Content-addressed mapping references cover endpoints, relation, rationale, and
all citation metadata. A supplied `MappingReview` records an accountable reviewer,
time, external decision reference, and exact mapping reference. Without a review,
the mapping is `candidate`. Changed content invalidates the supplied review.
The contract validates structure and freshness, not reviewer identity or signatures.
Agents must never manufacture owner approval. Pack references additionally cover
review decisions; changing any decision creates another auditable pack revision.

`MappingPack` is an explicit finite offline interchange document. Imports reject
unsupported versions, coerced types, unknown or missing fields, duplicate JSON
keys, nonfinite constants, stale content references, duplicate mapping IDs,
overlarge documents, and excessive record collections. Equivalent declaration
orders produce the same canonical bytes. No persistence service or live sync is
introduced.

`BindFindingMappings` joins an explicit classified canonical object reference to
exact source matches from an explicit pack. Approved relations are selected by
default; candidate inclusion requires explicit opt-in and retains candidate
status. Rejected mappings are never selected. Lookup does not reverse relations,
expand transitively, infer classification, alter findings, inspect Evidence,
prove control fulfillment, or establish exploitation. The owning finding layer
must verify subject existence and supply its explicit classifier.

## Candidate baseline and remaining acceptance

The supplied baseline contains five narrow candidate relations sourced from
official OWASP, MITRE, and NIST publications. SQL-injection classifications and
controls use explicit OWASP/CAPEC associations. NIST and ATT&CK associations are
clearly labeled first-party contextual interpretations, not publisher crosswalks.
ATLAS item identifiers fit the contract, but no ATLAS relation is supplied until
an exact primary source is reviewed. The baseline is intentionally historical
and versioned; it is not a complete or automatically current framework catalog.

Owner review of the precise baseline and an exact sourced ATLAS relation remain
acceptance work for #68. The implementation must not close that task merely
because its contract and candidate data pass deterministic tests.

## Validation

Unit and contract tests exercise exact version matching, immutability, attribution,
human-review freshness, honest candidate defaults, no transitive inference,
strict JSON boundaries, malformed URL metadata, tampering, and finite limits.
The production module must satisfy the repository per-module branch coverage
gate. Canonical API inventory and locale records retain visibly marked English
fallbacks without invented translation approval.
