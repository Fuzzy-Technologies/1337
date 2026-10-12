# ADR 0033: Offline attributed attack references

- Status: Accepted
- Date: 2026-10-11
- Decision owners: Fuzzy Technologies
- Related work: #48

## Context

Findings need attributable attack-pattern and behavior references. CAPEC, ATT&CK,
and ATLAS identifiers describe external reference knowledge. Importing their
records must not invent infrastructure, evidence, reachable attack paths, observed
behavior, or execution authorization. The operational Security Object Model and
immutable raw-evidence store retain the ownership defined in ADRs 0010, 0020,
and 0023.

## Decision

Add the independent Experimental `fuzzy1337.intel_references` contract, schema
version 1. `ReferenceIdentity` binds a namespace (`capec`, `attack`, or `atlas`),
an opaque external identifier, and the exact external catalog version. IDs preserve
case; the contract does not assert that an identifier exists in an official dataset.
An `intel:<sha256>` identity uses domain-separated canonical UTF-8 JSON. Mutable
record descriptions, source metadata, paths, and review do not change that identity.

Each immutable `ReferenceRecord` retains a typed knowledge kind, title, summary,
and explicit `ReferenceSource` attribution: synthetic/external origin, publisher,
HTTPS source locator, artifact SHA-256, license name/locator, UTC acquisition time,
and importer identity/version. An independent domain-separated content hash binds
all of those fields and identity. Consumers pin both identity and content hash when
an interpretation must reject changed source content.

An optional caller-supplied `ReferenceReview` binds reviewer, UTC review time, and
the exact content hash. Parsing and catalog construction never create a review.
Changing reviewed content invalidates the attestation; review cannot precede source
acquisition. An attestation is a supplied claim, not authenticated proof of human
identity, approval authority, or the accuracy of a mapping.

`ReferenceCatalog` freezes deterministic ordering and rejects duplicate/colliding
identities, unsupported versions, unknown or missing fields, duplicate JSON keys,
invalid UTF-8, nonstandard constants, malformed hashes/timestamps, inconsistent
identity/content hashes, and oversized payloads. Serialization is strict JSON.
Source URLs are validated offline and exclude credential, query, and fragment
fields. The caller owns authorized source bytes and all storage/transport.

## Ownership and limits

- No official reference corpus, synchronization, fetching, or embedded third-party
  data/license assertion is introduced. All checked-in fixtures are explicit
  synthetic content with invented identifiers and `example.invalid` URLs.
- No dependency on Findings, mappings, the model, workspace, evidence store, CLI,
  or a provider is required. Later consumers can resolve a pinned reference without
  adding another authoritative operational store.
- Evidence backing a proposed finding-to-reference association remains in the
  consumer's evidence/provenance boundary. Catalog membership alone cannot prove
  a match, exploitability, reachability, or that an adversary performed a behavior.
- Hashes provide deterministic identity/integrity checks, not publisher signatures,
  source-artifact verification, license permission, or review authentication.
- No disk store, graph edges, execution, indexing service, network import, or
  automatic mapping algorithm is part of this contract.

## Validation

Owning unit and contract suites exercise all namespaces, immutable/detached
round trips, identity/content separation, source attribution, optional exact-content
review, lookup pinning, malformed runtime values, nested schema rejection,
duplicate/collision handling, byte bounds, and parser corruption. Canonical full
repository gates and per-module branch coverage apply before owner review.
