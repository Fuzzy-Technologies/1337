# ADR 0027: Canonical evidence-linked findings

- Status: Accepted
- Date: 2026-10-11
- Decision owners: Fuzzy Technologies
- Related work: #46, #42

## Decision

Findings are typed `SecurityObject` records in the existing workspace-owned
Security Object Model, not a provider-specific store or a second model. Add the
Experimental `finding` object kind and `fuzzy1337.findings` normalization/query
boundary. Existing schema-version-1 snapshots remain valid and byte-identical
when they contain no findings. Older implementations reject the new object kind
rather than misinterpreting it. The finding attribute document has its own strict
version 1 schema. No Stable interface changes.

A fingerprint is a domain-separated SHA-256 of a canonical subject object
reference, a first-party check identifier, and an explicit first-party location
key. Provider names, summaries, severity, confidence, status, acquisition time,
and evidence bytes do not identify a finding. Check/location mappings belong to
the first-party ingestion owner; provider-specific check IDs are not silently
treated as equivalent. Different workspaces or locations remain distinct.
Subject references must resolve to a non-finding object in the same model.

Current normalized fields contain summary, typed severity, a finite numeric
confidence in `[0, 1]`, status/reason, and remediation text, steps, and references.
Confidence is an attributed interpretation, not a probability derived or endorsed
by core. Provenance reuses `ModelProvenance` and typed evidence references. Stored
findings require evidence linkage; normalization does not verify bytes or turn
failed/partial execution into success. A separate verified-ingestion boundary
checks workspace ownership and all incoming evidence through the existing local
evidence store before producing any model update.

Detector ingestion accepts only untriaged `open` findings and preserves existing
operator triage. Explicit attributed transitions allow open/confirmed findings
to become confirmed/open, dismissed, or resolved; dismissed/resolved findings
must reopen before another disposition. A reason accompanies every explicit
transition. Generic model updates enforce these same transitions. Initial
creation is open; persisted dispositions remain readable. Rediscovery never
automatically reopens a triaged finding or resolves an absent finding.

Deduplication uses existing SOM identity/attribute/provenance merging, revision
deltas, observation history, locking, and persistence. Exact replay is a no-op;
new acquisitions retain their evidence and incoming normalized interpretations.
Conflicting current metadata follows explicit batch order, as with other SOM
objects. Queries are projections of the same immutable snapshot. No scanner,
execution authorization, automatic remediation, taxonomy service, reporting
engine, or CLI command is introduced by this foundation.

## Validation

Unit and contract tests verify deterministic fingerprints, frozen fields, strict
schema rejection, lifecycle boundaries, evidence requirements, and triage-preserving
deduplication. Integration tests use real workspace/model/evidence stores, reopen
and relocate snapshots, retain competing-provider acquisition history, reject
foreign/missing/corrupt evidence, and check revision conflicts. No network target
or browser is used. Module branch coverage must remain strictly above 80%.
