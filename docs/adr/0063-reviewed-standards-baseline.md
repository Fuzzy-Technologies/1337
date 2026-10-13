# ADR 0063: Reviewed offline standards baseline

- Status: Proposed for integration review
- Date: 2026-10-13
- Decision owners: Fuzzy Technologies
- Related work: #68, #63; ADR 0035

## Context

ADR 0035 introduced exact versioned relations and accountable externally supplied
reviews. Its historical `CandidateBaseline()` intentionally grants no default
finding bindings and does not include an ATLAS relation. Task #68 requires a
usable reviewed baseline covering every selected standards family, with actual
source acquisition and an independently recorded content decision.

## Decision

Add a separately versioned `fuzzy1337.baseline` revision `0.2.0` as a finite
schema-v1 package resource. Preserve `CandidateBaseline()`, its five mappings,
unpinned historical citations, and `0.1.0-candidate` semantics unchanged.

The new revision includes six selected relations, with raw SHA-256 pins for seven
actually acquired primary-source artifacts. CWE 4.20, CAPEC 3.9, OWASP Top 10
2021, ASVS 4.0.3, ATT&CK 19.0, ATLAS 2026.09, and NIST CSF 2.0 remain explicit
catalog identities. These are reproducible historical selections, not a claim
that all catalogs or controls are publication-current.

OWASP and CAPEC explicit publisher relationships remain distinguishable in the
rationale from 1337 contextual interpretations involving NIST, ATT&CK, and
ATLAS. CWE-1427 is associated with AML.T0051 only as contextual interpretation;
no unverified MITRE crosswalk, inferred classifier, attack occurrence, or general
equivalence between prompt injection and jailbreaking is claimed.

The coordinator independently reviews the six exact `mapping:` references and
records the actual owner-account decision in issue #68. Only then are the real
decision locator, account, and time attached to unchanged mapping content.
The pack reference changes because it includes those review decisions. Review
structure and SHA-256 do not authenticate upstream publishers or reviewer
identity; authority remains outside this offline contract.

`ReviewedBaseline()` reads only this bounded installed package resource,
validates the existing strict schema and exact expected pack reference, and
requires every relation to carry an approved decision. A missing or changed
resource is an observable failure. It never falls back to the candidate pack,
contacts a catalog, or manufactures a decision.

`BindFindingObjectMappings()` validates the supplied canonical finding shape
and fingerprint through `Finding.FromObject()` and delegates exact matching to
the existing approved-only selector. Finding/model membership, correct explicit
classification, raw evidence integrity, and review authority remain obligations
of their owners. It performs no model update, triage transition, reverse lookup,
transitive expansion, certification, or control-fulfillment inference.

## Consequences and validation

The baseline is immediately useful to explicit offline finding/report consumers
without changing Security Object identity or mapping interchange schema. Future
national, regulatory, or vendor packs still use the existing generic contract.

Tests cover actual packaged provenance and approvals, unchanged historical
candidates, exact version selection across all six relations, invalid finding
objects, triage preservation, exclusion of candidates/rejections/stale reviews,
finite resource reads, missing resources, and changed-pack rejection. An owned
workspace test exercises real evidence acquisition, verified finding ingestion,
model persistence/reopening, and portable reviewed bindings while proving that
model bytes and raw evidence remain unchanged. Wheel validation must demonstrate
that the installed package contains and can load the exact resource offline.
