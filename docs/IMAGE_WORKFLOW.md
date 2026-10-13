# Closed synthetic image workflow

`fuzzy1337.image_workflow` assembles the reviewed
`owned-synthetic-image-wire-v1` fixture through the canonical artifact SDK,
owned jobs, existing model/workspace stores and existing JSON/SARIF exporters.
It accepts only source `synthetic.trivy`, provider version `0.75.0-synthetic`
and the pinned first-party worker. Native profiles remain metadata-only.
Task #142 remains open for genuine supplied Trivy/runtime/material acceptance.

## Explicit selection and authority

`ImageScanSelection` requires absolute explicit archive, current trusted CPython,
reviewed worker and material-policy paths plus `ArtifactReadConsent`.
Construction performs no discovery or read. The operator selects an initialized
workspace and existing approved ARTIFACT scope; no image archive becomes an IP
or HTTP target. `approve_safe_image=True` grants the workflow's explicit SAFE
capability permission, while the canonical SDK still checks current scope,
consent, selected bytes, owner, policy and grant expiry at its actual boundaries.
Read consent alone never authorizes a process.

The synthetic archive is at most 128 KiB with the reviewed five inert regular
members. Each operation snapshots its own input/scanner/material partitions.
VERSION has the fixed three-second/16-KiB-per-stream wire. SCAN has an actual
integer deadline from one through sixty seconds, default thirty, and the fixed
4-MiB stdout/1-MiB stderr profile. The executor retains its output-limit detection
facts, including bounded partial output. These bounds do not establish OS CPU,
memory, network or write isolation.

## Ordered actual operations and evidence

The job publishes queued status before provider work. It verifies existing
workspace and model evidence, then creates a fresh VERSION stage, fixed request
and original grant. After actual subprocess cleanup it captures VERSION stdout,
stderr and its original schema-1 capture envelope containing schema-2 SDK facts.
Canonical fresh VERSION acceptance and strict observed version JSON precede the
typed `ArtifactVersionProof` and any SCAN grant.

SCAN has a separate fresh stage, lease, scratch/cache, invocation, grant, run and
marker. Its schema-2 request/plan bind the exact original VERSION run/grant and
prerequisite digest. Same-content alternative proofs cannot replace that original
prerequisite. After SCAN cleanup, both original grants and all paired selected
bytes/authority must remain freshly acceptable before normalization.

The exact interpretation roles are `provider-version`,
`provider-version-stderr`, `stdout`, `stderr`, `artifact-version-receipt` and
`artifact-scan-receipt`. Empty stderr remains a distinct original record.
Each role retains its operation's actual invocation, execution and observed
collection window; times are clock readings around `Execute` and owned cleanup,
not derived from durations or filenames. Three selected-byte/read-consent
manifest acquisitions per operation retain their separate `artifact-input-manifest`,
`artifact-scanner-manifest` and `artifact-material-manifest` roles.
They neither replace execution evidence nor authenticate a material publisher.

## Durable saves and truthful failures

The importer constructs the complete isolated synthetic candidate batch before
the canonical final pair authority/time barrier, then uses pure Finding
ingestion. The workflow rechecks the original pair immediately before model CAS
save with the original expected revision. It verifies all old/new raw references,
acquisition manifests, scope/object/job references and the actually saved model,
then CAS-saves the original workspace revision. Only then may it publish the
actual committed delta and complete the job.

Nonzero exit, timeout, output limit, cancellation, malformed/version/package wire,
proof substitution, authority/material refusal and CAS/storage failures remain
explicit. Rejected runs keep acquired raw bytes and the prior model. If a model
publication succeeds before its acknowledgement or a later workspace save fails,
the job remains a storage failure and its terminal summary reopens the actual
saved model revision. No successful delta is published for a failed durable job.
Supported caller cancellation requests cooperative owned-job cleanup and awaits
it before terminal cancellation. Presentation callback failure also waits for
owned cleanup before propagating.

Every fixture asset/Finding/reference remains in the fixed synthetic family.
Native assets, attribution and triage remain unchanged even with identical domain
digest/PURL/advisory hints. Later accepted collections preserve synthetic Finding
disposition; reopening is an explicit operator transition. Read-only historical
verification works after old stages disappear and after workspace relocation,
using original saved facts without grant issuance, live Apply or model writes.

## Separate report outcome

An optional `report_format` (`json` or `sarif`) and new `report_output` path request
export of the exact successfully saved snapshot through existing report owners.
Output publication remains atomic and does not clobber an existing destination.
Export failure returns a nonzero overall exit while retaining completed scan,
job and saved-model facts. A confirmed complete publication remains visible even
when a later acknowledgement fails. A failed scan job gives requested export an
explicit `not-run` outcome.

JSON is the existing report wrapper; only its embedded `model` uses the canonical
model decoder. SARIF keeps active interpretations, logical subjects, original
evidence and outcomes, without invented physical locations or successful scans.
Inventory observations, summary and reports keep `scan_completeness:
not-assessed`, including zero Findings. Synthetic fixture proposals prove no
genuine vulnerability detection or database freshness.

## SDK call

All path and authority variables below are explicit caller-owned selections.
No CLI spelling or source/runtime installation is introduced by this SDK slice.

```python
summary = await RunSyntheticImageScan(
    workspace_root,
    scope_id,
    owner_reference,
    ImageScanSelection(archive, trusted_cpython, reviewed_producer, material_policy,
                       ArtifactReadConsent(owner_reference, read_consent_reference)),
    approve_safe_image=True,
    timeout_seconds=30,
    report_format="sarif",
    report_output=new_output_file,
)
```

Targeted unit, contract, integration and SDK E2E tests use the unchanged reviewed
archive/worker/handwritten oracle. They exercise all eight original scenarios,
six-role and proof mutation, native collision/triage, final expiry/revocation,
durable failure acknowledgement, cancellation and separate report publication.
Cross-platform and full documentation acceptance remain exact-head CI gates.
