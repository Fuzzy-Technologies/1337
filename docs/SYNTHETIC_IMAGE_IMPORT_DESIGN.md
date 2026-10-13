# Separate verified synthetic image interpretation

This is the concrete consumer plan for the accepted [ADR 0048](adr/0048-closed-synthetic-image-operations.md)
and [operation contract](SYNTHETIC_IMAGE_OPERATIONS_DESIGN.md). It does not add an
importer, register a producer, authorize a process or complete Task #142. The
accepted initial artifact foundation remains separate from the proposed richer
operation API. Implementation waits for that producer API to be independently
reviewed and accepted. Native interpretation remains the ADR 0040 contract.

The owner accepted the narrow behavior-preserving native candidate factoring
decision on 2026-10-13. The synthetic live/replay boundaries below remain proposed
until their operation-aware SDK dependencies and independent review are accepted.

## Proposed live boundary

The proposed Experimental Python boundary is
`ApplyVerifiedSyntheticTrivyImages(state, version_proof, scan_outcome,
scan_prepared, scan_stage, records, workspace_root, *, context_provider)`.
The artifact SDK owner is preparing `ArtifactVersionProof`, the operation-aware
request and outcome types, and `GovernedArtifactExecutor.ValidatePair`. Their
final accepted signatures must be used directly; this plan does not define a
parallel SDK or a substitute verifier.

`version_proof` contains the actual original VERSION outcome, prepared request
and physical stage. SCAN supplies its own original typed outcome, request and
stage. A successful-looking AdapterReport or JSON file cannot substitute for
either actual operation. Both outcomes require SUCCEEDED, exit zero,
PROCESS_EXIT and an original acceptance receipt without refusal. The provider
is exactly `synthetic.trivy`, profile `synthetic.image-archive-offline.v1`, family
`owned-synthetic-image-wire-v1`, observed version `0.75.0-synthetic`, and reviewed
worker SHA256 `afb5b935f151fb9780feee28eda0fbf13ddc6d721e6f7cc55e753aa32e4cfa53`.
The SDK derives this closed family; the consumer does not accept a caller's
registration, source label, generic SAFE capability or native profile.
Rich SCAN issuance requires the immutable typed VERSION prerequisite. Its exact
original run/grant/receipt/request/stage identities and prerequisite digest must
participate in SCAN's schema-2 plan, intent and authorization binding; a later
version proof cannot be swapped into an already issued grant.
The SDK's agreed plan fields are `operation`, `producer_family`, `version_run_id`,
`version_grant_id` and `version_prerequisite_sha256`. The final three are absent
only as explicit null values for VERSION and lifecycle SCAN. The prerequisite
digest commits original VERSION metadata and exact prepared/stage payloads.

`context_provider` follows the first-party SDK's synchronous factual authority
contract. It supplies the current trusted owner and operator policy plus current
same-store scope. It does not return an approval boolean or verification result.
The consumer constructs and calls the canonical SDK facade itself, without a
caller-selected verifier, executor subclass or private policy-engine access.
The SDK refreshes its own decision clock and reads authoritative scope metadata.
This is operator-attributed authority, not principal or publisher authentication.

The consumer derives ModelProvenance from SCAN's actual run identifier,
collection finish, granted ARTIFACT target/scope, observed provider version and
execution. It retains all six verified references in canonical sorted order.
Caller-supplied ModelProvenance cannot replace those facts. Physical paths,
request argv, stage payloads and environment values remain solely in raw receipt
evidence. The function proposes an immutable ModelState and aggregate ModelDelta;
it does not save, launch, modify evidence or publish a delta.

## Six-role evidence and complete original binding

`records` is a tuple of exactly six original EvidenceRecord manifests, with one
record per role. Each manifest must equal `LocalEvidenceStore.Get(evidence_id)`
in the owning workspace, and its bytes are read and verified through that store.
Content-only references or metadata copied from another acquisition are refused.

| Role                     | Operation | Maximum bytes | Media type       |
| ------------------------ | --------- | ------------- | ---------------- |
| provider-version         | VERSION   | 16 KiB        | application/json |
| provider-version-stderr  | VERSION   | 16 KiB        | text/plain       |
| stdout                   | SCAN      | 4 MiB         | application/json |
| stderr                   | SCAN      | 1 MiB         | text/plain       |
| artifact-version-receipt | VERSION   | 1 MiB         | application/json |
| artifact-scan-receipt    | SCAN      | 1 MiB         | application/json |

Every role binds the same owning workspace, exact granted scope, source,
acquisition contract version `1` and observed tool version. Both VERSION streams
and its receipt retain VERSION's actual invocation digest, execution and capture
window. SCAN's three roles retain SCAN's own corresponding facts. Stream bytes
equal the matching original outcome; empty stderr is still a verified record.

Receipt capture envelopes have schema 1 and exactly six fields:
`schema_version`, `artifact_metadata`, `prepared_payload`, `stage_payload`,
`collection_started_at` and `collection_finished_at`. Their SDK metadata must
have schema 2 and equal the original typed outcome's canonical metadata.
Detached original prepared and stage payloads equal their live originals and
hash to the corresponding original plan's request and stage digests.
The receipt codec checks exact fields, duplicate keys, strict UTF-8, finite values,
depth 32 and 65,536 nodes. Unknown schema, injected defaults or added fields fail.
Parsing and diagnostics never echo raw private input or chained decoder text.

Check normalized offset-aware windows independently from process duration.
Each grant was issued before its capture started; original receipt acceptance
was checked within that window and before original grant expiry. VERSION capture
finishes before SCAN capture starts. The original VERSION receipt and actual
version JSON were accepted before SCAN grant issuance; both requests bind
distinct operations and original physical runs. No claimed duration manufactures
absolute launch timestamps. Request, lease, grant, run, marker, root and scratch
are distinct, while workspace/owner, profile/source/family, manifests, selected
executable identity and exact policy bytes agree across the pair.

Observed VERSION JSON has exactly `Version`, `VulnerabilityDB` and `Fixture`.
Require the reviewed version, exact fixed synthetic database metadata and fixed
raw-only fixture marker. SCAN has native-format schema 2 container_image output
with its provider version matching VERSION. Package/PURL classification,
architecture, installed version, PkgID correlation, parser bounds and whitelisted
field selection remain the strict existing image interpreter's rules.
The database values are fixture material, not real database freshness evidence.
Selected-input/scanner/material acquisitions retain separate governed evidence
and consent facts; they do not replace one of the six required records.

## Pure candidate construction and complete fixture isolation

The narrow native preparation is an Internal `TrivyCandidates` helper in
`fuzzy1337.images`. It takes the workspace identifier, already decoded scan and
version/database objects, and matching provenance, and returns the existing four
candidate lists: objects, relations, observations and Findings. It neither reads
evidence nor calls ModelState.Apply. The schema checks, construction order,
package matching, selected fields and diagnostic text remain unchanged.
It receives no caller-selected namespace, check identifier or authority setting.

`ApplyVerifiedTrivyImages` keeps its exact signature and its current guard order:
native source/capability/success, VerifyRecords, probe/scan chronology, supported
version/source envelope, observed database validation, strict scan decoding,
candidate construction, then the existing ApplyBatch. VerifyRecords still
requires exactly stdout, stderr and provider-version; provider-version still
requires invocation_sha256 and execution to be absent. CycloneDX, SPDX,
ImageIdentity, PackageIdentity and native ApplyBatch retain their existing API.

The future synthetic boundary calls the pure candidate helper only after its own
separate evidence and operation checks. Before application it rewrites every
asset natural key with the fixed literal prefix
`synthetic.trivy:owned-synthetic-image-wire-v1:`. The six permitted native-derived
key families are image-config, image-manifest, package-version, operating-system,
image-layer-diffid and license-declaration. An unexpected family rejects the
entire batch rather than silently entering the native namespace.

Build an exhaustive old-to-new object reference map. Rewrite all relation
endpoints, observation subjects, Finding subjects and the whitelisted
`image_reference` observation attribute. Each Finding check becomes the literal
`synthetic.supply-chain.vulnerability`; other detector identifiers are refused.
No native candidate is applied transiently. No digest/PURL hint creates a
cross-family relation, identity promotion or native metadata overlay. Synthetic
provenance and key/check namespaces remain explicit; image inventory observations
retain `scan_completeness: not-assessed`, including no_findings.

Verify and construct the complete candidate batch before the final authority
barrier. The SDK's ValidatePair performs the full original receipt/material checks
for both operations, then refreshes authority and clock after expensive work and
checks both original grants immediately before pure application. It never extends
VERSION validity to accommodate SCAN. Failure retains raw evidence and the
original model. After this barrier, application uses only already verified
immutable candidates and pure Finding ingestion; it performs no additional
evidence reads, physical hashing, callbacks or clock waits. Native ApplyBatch
keeps its existing verified Finding boundary.

## Separate read-only historical verification

`VerifySyntheticTrivyImageReplay(records, workspace_root)` is a proposed separate
read-only boundary. It verifies the original six records, capture windows,
detached payloads, complete original request/grant/receipt digests, actual stream
facts and cross-stage binding using the SDK's schema-specific replay codec.
It returns immutable original attribution facts, not a live acceptance token,
ModelDelta, grant or updated model. It does not inspect a current/relocated stage,
call ValidatePair, invoke live Apply, create a process or save anything.

Legacy SDK schema-1 replay keeps the original field shape and hashes and remains
legacy SCAN provenance. The richer importer requires actual schema-2 VERSION and
SCAN records; it never upgrades or relabels old lifecycle bytes. Replay of an
existing synthetic Finding cannot reopen its disposition or create new history.

## Required evidence before implementation acceptance

- Compare complete native graph/revision/triage bytes before and after factoring,
  preserving public signature, source guard, role count and version-no-execution.
- Exercise all eight unchanged handwritten image scenarios using actual separate
  SDK operations and the independent oracle; no model proposal on rejected runs.
- Mutate every role, manifest/source/window/request/stage/operation/family binding,
  replace original streams/receipts and refuse unsupported bounded JSON atomically.
- Revoke scope, change owner/policy or expire either grant during expensive pair
  verification; final fresh acceptance must refuse without altering prior state.
- Seed all six colliding native assets and a triaged native Finding from the
  independent oracle; compare their complete bytes after synthetic import and
  read-only replay, with no native references in the synthetic candidate graph.
- Retain synthetic disposition across later accepted collections; test explicit
  reopen separately, durable CAS save/reopen and verified workspace relocation.
- Run targeted, canonical locked offline, source/API/locale/Markdown gates and
  independently review exact source before publication. Real Windows execution
  and rendered documentation require exact-head repository CI.

The image workflow owner separately assembles VERSION/SCAN jobs, durable model
and workspace updates, reports and delta publication. Native capabilities remain
metadata-only until genuine supplied runtime/material compatibility is verified.
This plan claims no arbitrary image scan, registry access, real Trivy detection,
database completeness or OS process/network/write isolation. Task #142 stays open.
