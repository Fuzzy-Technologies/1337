# Closed synthetic image workflow

`fuzzy1337.image_workflow` assembles the reviewed
`owned-synthetic-image-wire-v1` fixture through the canonical artifact SDK,
owned jobs, existing model/workspace stores and existing JSON/SARIF exporters.
Original capture production lives in `fuzzy1337.image_evidence`; the single
Experimental interpretation/replay owner is `fuzzy1337.synthetic_images`.
The workflow calls that owner's live importer and retains responsibility for
job events, original operation captures, durable saves and separate exports.
It accepts only source `synthetic.trivy`, provider version `0.75.0-synthetic`
and the pinned first-party worker. Native profiles remain metadata-only.
Task #142 remains open for genuine supplied Trivy/runtime/material acceptance.
The Experimental CLI entry is `1337 scan image --profile synthetic`; it directly
reuses this workflow and cannot select a native provider.

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
bytes/authority must remain freshly acceptable before model application.

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
Unreadable current scope storage remains `STORAGE` with exit code four;
typed current-owner or policy denial remains `AUTHORIZATION` with exit code three.
Supported caller cancellation requests cooperative owned-job cleanup and awaits
it before terminal cancellation. Presentation callback failure also waits for
owned cleanup before propagating.

Every fixture asset/Finding/reference remains in the fixed synthetic family.
Native assets, attribution and triage remain unchanged even with identical domain
digest/PURL/advisory hints. Later accepted collections preserve synthetic Finding
disposition; reopening is an explicit operator transition. Read-only historical
verification works after old stages disappear and after workspace relocation,
using original saved facts without grant issuance, live Apply or model writes.
The canonical replay API returns immutable `SyntheticImageReplay`, whose
`.provenance` holds the original SCAN attribution. It can retain actual failed
or malformed SCAN facts and its original refusal receipt without interpreting
wire output or granting live application. Original staged-copy identities and
run-marker device/inode observations must remain distinct across the two saved
operations; only the deliberately shared operator-selected source executable
identity is excluded from staged-copy separation.

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
No source/runtime installation is performed by the workflow or its CLI consumer.

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

## Explicit CLI and foreground shell

Select an initialized workspace and approved ARTIFACT scope. `scope create`
accepts `--allow-artifact` and `--exclude-artifact` with exactly
`manifest-sha256:<64 lowercase hex>` values. These are canonical artifact
manifest targets; an archive byte hash, OCI digest, pathname or URL is not a
substitute. Registration alone retains unknown consent. Existing
`--grant-consent`, `--owner`, `--consent-reference`, `--valid-from` and
`--valid-until` provide explicit scope authority metadata; selected-file read
consent and SAFE execution approval remain separate.

The approved manifest identity is produced by the existing canonical input
manifest API from explicitly selected archive bytes. For example, after the
operator has authorized reading their selected fixture archive:

```python
import hashlib
from fuzzy1337.artifact_inputs import ArtifactFile, ArtifactManifest, ArtifactProfile, ArtifactRole

payload = archive.read_bytes()
target = ArtifactManifest(
    ArtifactProfile.SYNTHETIC_IMAGE,
    ArtifactRole.INPUT,
    (ArtifactFile("image.tar", len(payload), hashlib.sha256(payload).hexdigest()),),
).Target()
print(target.value)
```

The manifest calculation grants no execution authority. Use that exact target
when registering the approved scope. An explicit command is:

```bash
1337 scan image /absolute/owned-workspace \
  --profile synthetic --scope image-scope --owner owner:operator \
  --archive /absolute/selected/input/image.tar \
  --executable /absolute/current-trusted-cpython \
  --producer /absolute/1337/tests/fixtures/image_scan/producer.py \
  --material /absolute/selected/material/policy.json \
  --read-consent-reference consent:explicit-selected-files \
  --approve-safe-image --timeout 30 \
  --report-format sarif --report-output /absolute/new-image-report.sarif \
  --json
```

Every selected source path must be absolute. The reviewed first-party
`tests/fixtures/image_scan/fixture_image.py` builder provides the bounded inert
archive/material fixture; genuine images and arbitrary producer scripts are not
admitted by this closed profile. The executable is the explicit current trusted
CPython, not an optional Trivy executable. No binary, database or fixture is
installed or discovered by the command.

`--profile synthetic` is required. Omitting `--approve-safe-image` denies process
authorization; the flag never bypasses current owner/scope/material or fresh
VERSION/SCAN pair acceptance. `--timeout` is an integer from 1 through 60 seconds,
default 30, and does not replace VERSION's fixed bounds. Report format/output must
be supplied together; existing destinations remain untouched.

`--json` prints one versioned synthetic workflow summary with actual operation,
model and separate report outcomes. Use `--events-json` for ordered canonical job
events followed by one terminal summary; these presentation modes cannot be
combined. Human output labels the workflow `Synthetic Image Scan`. The same
`scan image` command runs in the foreground interactive shell with identical
inputs and checks. Exit status is 0 for completed scan/export, 2 for invalid setup,
3 for authority denial, 4 for scan/storage/export failure and 130 for cancellation.
A failed requested export leaves completed scan/model facts visible.

See [ADR 0056](adr/0056-explicit-synthetic-image-cli.md) for the CLI boundary.
Synthetic inventory and fixture findings remain explicit, with
`scan_completeness: not-assessed`; genuine native Trivy acceptance remains open.

Targeted unit, contract, integration and SDK E2E tests use the unchanged reviewed
archive/worker/handwritten oracle. They exercise all eight original scenarios,
six-role and proof mutation, native collision/triage, final expiry/revocation,
durable failure acknowledgement, cancellation and separate report publication.
Cross-platform and full documentation acceptance remain exact-head CI gates.
