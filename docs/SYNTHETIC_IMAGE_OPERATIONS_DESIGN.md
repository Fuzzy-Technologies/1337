# Synthetic image VERSION and SCAN operation contract

[ADR 0048](adr/0048-closed-synthetic-image-operations.md) defines the accepted
future contract for Task #142. These are producer/consumer requirements, not an
implemented SDK API, importer or product command. The initial Task #278 foundation
must first be accepted with original-run/grant marker consistency; its initial
operation and execution metadata remain schema-1 SCAN.
The accepted reviewed worker and independent oracle are the unchanged files under
`tests/fixtures/image_scan`.

## Closed family and selected material

The only new operation family is `owned-synthetic-image-wire-v1`, profile
`synthetic.image-archive-offline.v1`, source `synthetic.trivy`, provider version
`0.75.0-synthetic`. The source SHA256 of its reviewed `producer.py` is
`afb5b935f151fb9780feee28eda0fbf13ddc6d721e6f7cc55e753aa32e4cfa53`.
Factory dispatch derives this family from its closed profile/source catalog and
verified bytes; no caller registration or arbitrary command selection exists.

Each stage selects exactly `input/image.tar`, `scanner/executable`,
`scanner/producer.py` and `material/policy.json`. The executable is the current
trusted running CPython at its canonical selected path, with its observed bytes
and physical identity pinned. Its staged copy contributes to scanner identity;
the original selected executable is invoked. No source file is found implicitly.
Inputs are explicitly consented and ARTIFACT-scoped under the accepted foundation.

The worker's archive ceiling is 128 KiB, each of its exactly five regular members
is at most 16 KiB, and its scenario is an enumerated inert value. VERSION stages
still bind the exact selected archive although that operation does not parse it.
Each material policy is at most 512 bytes, strict UTF-8 JSON, with exactly these
fields and values:

```json
{
  "schema_version": 1,
  "fixture_id": "owned-synthetic-image-wire-v1",
  "provider_version": "0.75.0-synthetic",
  "database_metadata": {
    "Version": 2,
    "UpdatedAt": "2026-10-01T00:00:00Z",
    "NextUpdate": "2026-10-02T00:00:00Z",
    "DownloadedAt": "2026-10-01T01:00:00Z"
  }
}
```

Both integer fields require actual integers, excluding booleans. Duplicate keys,
extra fields, non-finite values, unsupported text or changed nested metadata deny
preparation. These values are synthetic fixture material, not a real database or
an observed freshness claim. The richer parser is selected only for this exact
reviewed family; the lifecycle producer's different policy schema is preserved.

## Fixed operation argv and resources

`ArtifactOperation.VERSION` serializes as `version`; `ArtifactOperation.SCAN` as
`scan`. New requests default to SCAN. VERSION is offered only for this richer
synthetic image family. Native and configuration profiles do not acquire a VERSION
route from this change.

The common argv prefix is the following ordered tuple. Every path is an absolute
path fixed by that operation's accepted stage/factory:

```text
(selected_cpython, "-I", "-S", stage/scanner/producer.py,
 "--fixture-policy", stage/material/policy.json)
```

VERSION appends exactly:

```text
("--cache-dir", stage/scratch/cache, "--config=", "--version", "--format", "json")
```

Its executor deadline is exactly 3 seconds, stdout and stderr ceilings are each
16 KiB, and its finite cleanup grace uses the accepted executor contract. There
is no CLI timeout flag in the version wire. The fixed worker emits observed
version JSON on stdout; stderr, exit state, termination, duration and events are
preserved even when the probe is rejected. A stage version string, synthetic
policy field or scan JSON cannot manufacture this acquisition.

Successful version JSON has exactly `Version`, `VulnerabilityDB` and `Fixture`.
The version and database fields match the fixed observed family/policy values;
the Fixture marker remains raw-only. Supported workflow cancellation uses the
SDK's cooperative cancellation path. Direct caller-coroutine cancellation keeps
its raise-after-owned-cleanup contract and is not claimed to return a raw outcome.

SCAN appends exactly the reviewed richer worker's ordered wire:

```text
("--cache-dir", stage/scratch/cache, "--config=", "image",
 "--cache-backend", "memory", "--input", stage/input/image.tar,
 "--format", "json", "--scanners", "vuln", "--disable-telemetry", "--offline-scan",
 "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
 "--skip-version-check", "--skip-vex-repo-update", "--ignorefile=", "--list-all-pkgs",
 "--exit-code", "0", "--no-progress", "--timeout", "<deadline>s")
```

Its deadline is an actual integer from 1 through 60 seconds, excluding booleans,
floats, numeric strings and rounding; the consumer default is 30 seconds. VERSION
likewise requires its exact integer deadline and rejects conflicting overrides.
Stdout is bounded to 4 MiB and stderr to 1 MiB. The accepted executor
owns timeout, cancellation, output-limit detection and cleanup. These are
execution/capture bounds, not OS CPU, memory, network or write quotas.
The initial lifecycle image argv has a different ordering and remains unchanged;
the richer family needs its own fixed dispatcher. Caller-selected flag order,
extra flags or prefixes are refused, not silently rewritten.

## Separate stages and complete pairing

The VERSION stage and SCAN stage are each fresh and single-run. Neither shares a
physical root, scratch/cache, lease, request, grant, run identifier or launch
marker with the other. Input/scanner/material partitions are separate immutable
copies, and the accepted factory owns cwd, home, temp, XDG and environment values.
The original current CPython selection remains independently pinned for each.
Each physical marker and receipt bind that same original run and grant identifier;
swapping a grant or changing its chronology cannot reuse an earlier execution.

Compare the following original facts before accepting the pair:

| Binding                | Required relationship between VERSION and SCAN                          |
| ---------------------- | ----------------------------------------------------------------------- |
| Workspace/owner        | Same workspace and executing owner                                      |
| Profile/source/family  | Exact richer synthetic profile/source/family and version                |
| Input manifest         | Same schema/profile/role/names/lengths/content hashes and target        |
| Archive bytes          | Exact selected content hash and length; not an OCI image digest         |
| Scanner manifest       | Same executable/producer names, lengths and content hashes              |
| Selected executable    | Same canonical origin and observed executable identity/bytes            |
| Material manifest      | Same exact policy file bytes, names/lengths/hashes and closed schema    |
| Current authority      | Both grants match full fresh scope/policy/owner/consent bindings        |
| Operation/physical run | Distinct VERSION/SCAN operations, roots, leases, grants and run markers |
| Requests               | Each matches its own exact factory argv/cwd/environment/resources       |

Stage payloads commit consent and physical facts separately from content
manifests. Each original detached stage payload hashes to that grant's
`stage_sha256`; each detached prepared payload hashes to `request_sha256`.
An invocation digest is not a replacement for either complete binding. Physical
staged-copy identities differ; the selected original executable identity agrees.
VERSION and SCAN invocation digests are not compared for equality because their
operations and root-dependent paths differ.

Require successful, freshly accepted VERSION and valid observed version JSON
before issuing the SCAN grant. Re-read actual authority for SCAN issuance/launch,
then require both original outcomes to remain freshly acceptable before model
acceptance. Consent, policy, owner or grant validity is never extended implicitly
to make the second phase succeed. Expired VERSION after a successful SCAN denies
new normalization while retaining both actual process results.

## Operation-aware versioning and legacy verification

The new `PreparedArtifact.Payload` and `ArtifactPlan` include mandatory operation
and the derived closed producer family. Those fields participate in the intent,
request and authorization-envelope binding, preventing cross-operation grants.
Operation-aware execution metadata uses schema 2; manifest schema remains 1.
Existing lifecycle SCAN defaults and fixed wire remain supported.

Strict read-only schema-1 replay keeps the original schema-1 plan/intent/grant
field lists, canonical JSON and digest/envelope calculation. It does not hash a
new dataclass with injected defaults and compare that different shape to saved
digests. Schema-1 records identify legacy SCAN only; no operation is inferred
from output, argv or an asserted version. They cannot be upgraded into a new
schema-2 executable grant, richer source or VERSION receipt. Unknown schemas and
extra or missing fields reject.

## Six exact evidence roles and original capture facts

The consumer stores immutable original bytes and manifests in the existing
`LocalEvidenceStore` before interpretation. Its exact synthetic bundle contains:

| Role                       | Bytes                                     | Attributed actual operation |
| -------------------------- | ----------------------------------------- | --------------------------- |
| `provider-version`         | VERSION stdout                            | VERSION                     |
| `provider-version-stderr`  | VERSION stderr, including an empty stream | VERSION                     |
| `stdout`                   | SCAN stdout                               | SCAN                        |
| `stderr`                   | SCAN stderr, including an empty stream    | SCAN                        |
| `artifact-version-receipt` | Original VERSION capture envelope         | VERSION                     |
| `artifact-scan-receipt`    | Original SCAN capture envelope            | SCAN                        |

The consumer-owned capture envelope is strict schema 1 with exactly
`schema_version`, `artifact_metadata`, `prepared_payload`, `stage_payload`,
`collection_started_at` and `collection_finished_at`. `artifact_metadata` is
the original operation-aware SDK schema-2 metadata; the other payloads are exact
detached canonical copies of the original prepared/stage payloads. Their hashes
must agree with the original grant. Receipt-envelope schema and SDK-metadata
schema have distinct roles and are never interchanged.

Capture-envelope JSON is bounded to 1 MiB, depth 32 and 65536 nodes per role,
with unique fields, valid UTF-8, finite values and offset-aware increasing times.
Both version streams and their receipt manifest retain the VERSION invocation
digest and actual execution. Both scan streams and their receipt retain SCAN's
own invocation/execution. Each six-role record has the owning workspace, exact
scope/source/acquisition-version/tool attribution and the matching operation's
observed collection window. Record identities, source facts, sizes and bytes must
match the immutable store, not merely a content reference supplied by the caller.

Collection windows are clock readings around the actual `Execute` call and its
owned cleanup/original acceptance. The local raw result has duration and event
order, not absolute process timestamps; times are never inferred from duration,
stage.version, filenames or receipt text. Each original grant is issued before
its collection starts, and its receipt check occurs within that collection
window. VERSION collection completes before SCAN collection starts. New model
provenance uses SCAN's actual collection finish and run reference and retains all
six sorted verified evidence references.

Selected input/scanner/material acquisitions retain their own existing roles
and consent facts separately. They do not replace one of these six records.
Physical paths, argv and environment/stage details stay in original receipt
evidence, without copying them into normalized model attributes or report claims.
Saved metadata is operator-attributed provenance, not publisher authentication.

## Live interpretation and read-only historical verification

A separate future `ApplyVerifiedSyntheticTrivyImages` requires both original
typed outcomes, prepared requests and physical stages, the six verified records,
and canonical fresh authority validation. It checks explicit operation/family,
profile, worker SHA/policy, manifests/executable, actual raw stream/result hashes,
grant/run/marker/receipt chronology and cross-stage pairing. Both terminal results
must be SUCCEEDED, exit zero and PROCESS_EXIT with no acceptance refusal.
Version stdout is strict bounded JSON with exactly the supported observed
provider/database interpretation; it agrees with the fixed family and scan wire.
Changing version or package correlation rejects before any model write.

Build candidates only after all evidence/shape checks. Freshly validate both
original outcomes against current context/time/material, with a final fresh
authority/expiry guard after expensive verification immediately before live model
acceptance. A caller-supplied boolean or validation callback is not authority.
The first-party consumer uses the canonical artifact SDK validation path.
The workflow verifies and CAS-saves the original model/workspace revision, then
publishes the actual committed delta and projects the exact saved report.

The candidate graph gives every config/manifest image, package, OS, layer and
license key the fixed prefix `synthetic.trivy:owned-synthetic-image-wire-v1:` and
every Finding the check ID `synthetic.supply-chain.vulnerability`. Rewrite all
relation endpoints, observation/Finding subjects and reference-bearing attributes,
including `image_reference`, consistently. No synthetic-to-native association,
identity promotion or attribute overlay is inferred. Collision tests compare the
entire original six native asset families and triaged native Finding bytes.

Preserve the native `ApplyVerifiedTrivyImages` API, exact native source guard,
three evidence roles and native version's no-invocation/no-execution check.
Strict data-to-candidate logic may be shared after validation, but the synthetic
evidence boundary independently checks both real executions. It does not invoke
the legacy version-record verifier or erase/relabel original provenance.

Historical verification is a separate read-only verifier of saved original
capture envelopes, raw records and their bindings. It checks schema-specific
digests, original receipts and the exact pair without inspecting a current or
relocated physical stage. It does not call live Apply, issue/refresh a grant,
perform current acceptance, launch VERSION/SCAN or save model changes. Existing
saved synthetic triage remains unchanged. Any new collection requires fresh
stages, grants and live acceptance.

## Required future failure oracle

| Failure or mutation                            | Required result                                                    |
| ---------------------------------------------- | ------------------------------------------------------------------ |
| Unreviewed worker/family or wrong policy       | No preparation, grant or process                                   |
| VERSION using SCAN request/grant or vice versa | No launch under a cross-operation binding                          |
| Reused stage/lease/marker                      | No second process from a consumed physical run                     |
| Failed/malformed/limited/cancelled VERSION     | Raw truth retained; no SCAN grant or new model                     |
| Changed cross-stage input/executable/material  | Pair rejected; no successful normalization                         |
| Revocation/owner/policy/expiry change          | Launch or model acceptance denied at its fresh affected boundary   |
| Swapped stream/receipt/time/request payload    | Atomic sanitized refusal; raw bytes and prior model retained       |
| Nonzero SCAN with valid-looking JSON           | Actual failed execution retained; no candidate application         |
| Version/package/schema or private text error   | Atomic rejection; no untrusted values in errors/chained tracebacks |
| Synthetic/native key collision                 | Entire native objects/provenance/triage unchanged                  |
| Schema-1 digest checked with schema-2 shape    | Refuse that path; verify legacy provenance with original shape     |
| Replay/relocation                              | Original saved facts only; no launch, current grant or model save  |

The accepted independent image oracle's success/no_findings/provider_error/
malformed/version_mismatch/package_mismatch/output_limit/hold specimens remain
unchanged. These requirements await SDK, importer and assembled workflow tests;
this checkpoint does not claim they were executed. Scan completeness remains
`not-assessed`, including no_findings. Native VERSION/SCAN capabilities, real
scanner/database compatibility and full Task #142 acceptance remain open.
