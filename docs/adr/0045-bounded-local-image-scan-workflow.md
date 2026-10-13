# ADR 0045: Bounded local image scan workflow

## Status

Proposed consumer decision — 2026-10-13. This Task #142 design/fixture slice does
not implement image orchestration or claim genuine scanner acceptance.

## Context

Task #142 requires a bounded container-image path through the Community scan
workflow, predictable scope/resource limits and JSON/SARIF-compatible output.
ADRs 0013/0032 select the optional offline Trivy archive adapter. Accepted ADR 0040
owns verified image/package normalization through the existing model and Finding
lifecycle. ADR 0039 owns report projections; it assesses neither scan completeness
nor publisher authenticity. Task #278/ADR 0044 owns the shared local-artifact
identity, immutable staging and governed offline launch boundary.

The current literal-IP HTTP Quick Scan and its strict summary schema remain
their separate, usable ADR 0037 contract. A local archive is never a fake IP/URL
target. This consumer waits for accepted #278 and report producer APIs before
runtime implementation; no private producer history enters its eventual PR.
Reporting #271 is accepted. Initial artifact native profiles are metadata-only
and cannot authorize/launch; image runtime acceptance remains separate.

## Proposed decision

Offer one explicitly selected image archive through a distinct bounded image
profile in the product scan namespace. Preserve existing HTTP commands and SDK
behavior. CLI spelling and the image summary schema are finalized only against
the accepted artifact producer; this ADR does not advertise executable commands.

The owning operator supplies an existing workspace, current artifact scope,
explicit consent metadata, declared capability permission and trusted scanner
material. The SAFE capability is `image.archive-vulnerabilities`; it cannot issue
STANDARD approval, register network targets or acquire credentials. Missing
binary/cache, unsupported version, expired/changed/revoked authority and denied
material remain explicit failure/denial rather than an empty successful scan.

The assembled path must preserve this order:

1. Verify existing workspace/model and all retained evidence. Publish queued
   status immediately; do not invent an image model update before verification.
2. Obtain bounded input/scanner/cache receipts from the accepted #278 profile.
   Keep archive byte hashes, artifact manifest identities, OCI config identities,
   manifest digests and layer DiffIDs semantically separate.
3. Capture the exact independent bounded version probe before the image process.
   Bind actual version/cache material and current owner/scope/policy to the grant.
4. Execute only the exact governed offline profile, with final launch validation,
   controlled working directory/environment and portable time/output limits.
5. Retain actual stdout/stderr/version records and unchanged execution outcomes,
   including partial output on failure. After cleanup, require the producer's
   fresh post-run authority/material acceptance before interpreting any result.
6. Supply the image importer exactly its `stdout`, `stderr`, `provider-version`
   manifests, with matching workspace/source/scope/tool/invocation/time/outcome
   provenance. Input/material receipts retain their own roles and attribution;
   they cannot substitute for native image report roles.
7. For a genuinely accepted native run, call `ApplyVerifiedTrivyImages` on the
   reopened model, then save with the original
   expected revision through `LocalModelStore`. Verify and CAS-save all old/new
   workspace scope/object/job/evidence references before terminal success. Publish
   only the delta describing an actual committed model revision.
8. Project that exact saved snapshot through `ReportSnapshot` and
   `VerifyReportEvidence`, then the existing JSON/SARIF exporters. Byte verification
   does not authenticate input receipts, material publishers or scan claims.

One image job owns its cancellation and cleanup. Timeout, output exhaustion,
nonzero exit, parser/version/package mismatch, receipt refusal and storage/CAS
failure produce no new successful image/finding interpretation. Already retained
raw acquisitions and the previous committed model survive. A post-save workspace
failure remains a storage failure with the actually saved model revision visible.
Re-detection preserves operator Finding dispositions; reopening remains explicit.

Initial proposed product bounds are one archive at most 64 MiB, a 30-second
default/60-second maximum image deadline, 4 MiB stdout and 1 MiB stderr. Version
capture retains the existing 3-second/16-KiB bounds, and image JSON retains the
accepted 4-MiB/65,536-node/depth-32/4,096-item profile. These are input, elapsed-time
and capture bounds, not OS CPU/memory/network isolation. The image workflow emits
measured timing; it does not borrow native HTTP's nominal first-update budget.

Requested report export has its own explicit outcome. Export failure cannot
rewrite an already completed scanner execution or publish a partial output file.
The workflow returns nonzero while retaining the exact completed scan/model facts.
JSON is a report wrapper; only its embedded model uses the canonical model decoder.
SARIF contains active Finding interpretations and their original evidence/outcomes,
without invented physical locations, successful invocations or passed checks.
`scan_completeness` remains `not-assessed`, including zero Findings.

## Independent fixtures and acceptance boundary

`tests/fixtures/image_scan` contains a portable standalone Python wire producer,
tiny deterministic Docker-save-shaped archive generator, finite synthetic policy
and a separately committed domain/outcome oracle. A dedicated fixed synthetic
#278 profile pins both the absolute interpreter and producer script and invokes
`(interpreter, "-I", "-S", staged_script, "--fixture-policy", material_policy_path)`
with only the fixed archive/version flags and memory cache. `policy.json` has
exact synthetic schema/fixture/version/database metadata, not executable policy
or a real DB. Input is exactly `input/image.tar`, cwd is under `scratch`, and
cache is `scratch/cache`.
No arbitrary prefix, flag, environment overlay or source data becomes SAFE.
The scenario is an enumerated inert member in the hashed archive, read without
extracting paths or executing contents. The version is `0.75.0-synthetic` exactly
through the independent version report and invocation.

The initial factory admits only closed reviewed first-party producer identities,
with no caller registration. This richer worker's exact source hash needs separate
source review and an owner-controlled allowlist addition before governed use.
Its provider is `synthetic.trivy`; it cannot pass the native image importer's
`native.trivy` guard, and provenance is never relabelled to bypass that boundary.
A future explicit synthetic importer requires independent image-owner review
after #278. It must isolate every asset namespace and Finding check identity,
preserve native objects byte-exactly and prevent synthetic-to-native promotion.
Every config/manifest image, package, OS, layer and license natural key receives
the fixed prefix `synthetic.trivy:owned-synthetic-image-wire-v1:`; Findings use
`synthetic.supply-chain.vulnerability`. The independent oracle seeds all six
colliding native-namespace asset families and a dismissed native Finding.
Future collection and replay must preserve their complete canonical objects,
attributes, provenance and triage bytes; no cross-family relation or metadata
overlay is permitted. These seeds are owned test data, not discovery evidence.
Fresh authority validation applies to newly collected acceptance; historical
byte/provenance replay never revives a grant or relaunches the fixture.

Fixture tests establish reproducible raw/domain hashes, wire refusal, portable
process readiness and owned cleanup. They do not establish governed product
integration or actual Trivy decoding/detection accuracy. Future assembled E2E
must also cover owner/scope/material changes, durable storage/replay/relocation,
no-new-model failure cases and exact JSON/SARIF projection.

Real acceptance requires an explicitly supplied compatible native Trivy binary
and offline database material with repository-owned or explicitly supplied local
images. Neither is installed/downloaded by this work. Task #142 remains open
until the resulting capability and its actual acceptance evidence are reviewed.
Registry, daemon, multi-platform index selection, IaC scanning (#158), PyPI
publication and broader M2 release acceptance remain separate work.
