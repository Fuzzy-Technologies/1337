# Canonical findings

`fuzzy1337.findings` is an **Experimental** library contract implementing
[ADR 0027](adr/0027-canonical-evidence-linked-findings.md). Findings are typed
objects in the existing [Security Object Model](SECURITY_MODEL.md), owned by the
same workspace and saved by the same `LocalModelStore`. This foundation adds
normalization, deduplication, evidence linkage, and disposition transitions; it
does not run scanners, remediate targets, authorize execution, or add a CLI.

## Identity and normalized fields

`Finding(subject_reference, check_id, location_key, summary, provenance, ...)`
describes one attributed interpretation. `subject_reference` must identify an
existing non-finding object in the same workspace model. The first-party ingestion
owner supplies the canonical `check_id` and `location_key`; provider IDs require
an explicit mapping rather than an assumed equivalence.

`Fingerprint()` hashes canonical UTF-8 JSON containing `namespace: "finding"`,
`subject_reference`, `check_id`, and `location_key`. It returns a lowercase SHA-256
digest. `ToObject(workspace_id)` uses that fingerprint as an `ObjectKind.FINDING`
natural key and obtains the existing SOM `object:<sha256>` reference. Distinct
subjects, checks, locations, and workspaces remain distinct. Provider names,
summaries, severity, confidence, disposition, acquisition time, and evidence
bytes do not change identity.

| Field         | Contract                                                                   |
| ------------- | -------------------------------------------------------------------------- |
| Summary       | Nonempty single-line normalized interpretation                             |
| Severity      | `unknown`, `informational`, `low`, `medium`, `high`, or `critical`         |
| Confidence    | Finite number in `[0, 1]`; booleans and numeric strings are rejected       |
| Status        | `open`, `confirmed`, `dismissed`, or `resolved`                            |
| Status reason | Explicit explanation for a triaged status or an attributed reopen decision |
| Remediation   | Optional summary, ordered advisory steps, canonical reference text         |
| Provenance    | Existing `ModelProvenance` records and typed evidence references           |

Confidence is an attributed estimate, not a probability computed by core. Core
does not upgrade confidence or terminal execution state during normalization.
Remediation is advisory data and is never executed. Fields are immutable and
bounded by the existing 64-KiB attribute limit. Raw bytes remain in the evidence
store. At least one evidence reference must remain linked to a stored finding.
An operator update may reuse the evidence already retained by the object.

`ToAttributes()` renders the independent version-1 finding attribute schema at
[`contracts/finding.schema.json`](../contracts/finding.schema.json).
`FromAttributes()` and generic SOM reads recompute its fingerprint and reject
unknown/missing fields, unsupported versions, untyped values, and identity
mismatches. The JSON Schema validates structural fields; runtime validation also
checks fingerprints, total attribute size, same-workspace subjects, evidence
linkage, and disposition transitions. The example attribute document at
[`contracts/examples/finding.json`](../contracts/examples/finding.json) is a
known-answer identity fixture, not a full evidence-backed workspace.

The existing model envelope remains at version 1. Previous valid snapshots remain
valid; snapshots without findings retain their existing serialization. Older
implementations reject the new object kind rather than silently interpreting it.

## Detector ingestion and deduplication

`ApplyFindings(state, findings)` consumes an ordered tuple of evidence-linked,
untriaged `open` detections. It returns a new immutable `ModelState` and
`ModelDelta`. Same-fingerprint detections update one canonical object. Different
acquisitions retain their provenance and actual incoming attribute documents as
`finding-detection` observations. Existing SOM patch observations are also
preserved. Current metadata follows the order of novel incoming interpretations.
Exact previously recorded detection replay does not overwrite newer metadata or
triage and does not create another revision. Rediscovery preserves existing
operator disposition; absent detections do not automatically resolve findings.

`ApplyVerifiedFindings(state, findings, workspace_root)` first validates workspace
ownership and checks every incoming artifact through `LocalEvidenceStore.Read`.
Missing, corrupt, incorrectly sized, or unsafe artifacts fail before any model
update is produced. A shared artifact is read once per batch. The function writes
nothing; save its returned transition using `LocalModelStore.Save` with the
returned previous revision. Scope/policy and executor authority remain upstream.

The pure `ApplyFindings` boundary validates evidence references without reading
bytes. A reference is not integrity proof. Use the verified boundary when ingesting
local acquisition evidence; reopening model state does not reverify every raw
artifact. Missing evidence remains an explicit evidence-store failure.

The existing SDK `NormalizedFinding` is a provider-neutral envelope. The
first-party ingestion owner maps its kind, subject, severity, confidence, and
location into the canonical contract. `ModelState.ApplyAdapterResult` continues
to consume observations/enrichments and leaves finding envelopes untouched.
Providers cannot choose canonical workspace identities or create a separate store.

## Explicit disposition transitions

`TransitionFinding(state, reference, status, provenance, reason)` applies one
explicit attributed operator decision. It keeps previous acquisition/evidence
history and records only the supplied decision attribution for its incoming
patch. The explanation is required; provenance does not grant authority. A
`finding-disposition` observation identifies the decision by subject, requested
status, reason, and provenance, independently of mutable detector metadata. Exact
decision replay preserves newer triage and metadata without another revision.
A deliberate repeated decision requires fresh attribution, such as a new
`run_reference` or observation time.

- New findings start `open`.
- Open and confirmed findings may become open/confirmed, dismissed, or resolved.
- Dismissed/resolved findings may retain their disposition or explicitly reopen.
  Reopen before changing them to another disposition.
- Detection ingestion cannot triage or automatically reopen a finding.

Generic `ModelState.Apply` updates enforce the same lifecycle and finding schema.
Persisted triaged findings remain readable. `Findings(state, status=None)` projects
typed findings from the same snapshot, optionally filtering by status. It creates
no secondary authoritative state, database, or provider cache.

## Focused verification

```bash
uv run --locked --extra dev pytest -o addopts='' \
  tests/unit/test_findings.py \
  tests/contract/test_finding_contract.py \
  tests/integration/test_finding_persistence.py
```

The tests exercise pure contracts and real workspace/evidence/model persistence,
provider deduplication, disposition preservation, moved workspaces, execution
failure attribution, stale-writer rejection, and missing/corrupt evidence. They
perform no browser checks, scanner execution, or external network testing.
