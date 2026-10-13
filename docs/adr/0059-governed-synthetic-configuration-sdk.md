# ADR 0059: Governed synthetic configuration SDK registration

## Status

Accepted implementation decision — 2026-10-13. This bounded slice advances Task
#158 and the offline artifact foundation. It does not complete native scanner
compatibility, configuration model projection, a durable configuration workflow
or the remaining Task #158 acceptance criteria.

## Context

[ADR 0046](0046-closed-offline-configuration-profiles.md) defines selected offline
configuration profiles and an independent hand-authored oracle.
[ADR 0051](0051-bounded-synthetic-configuration-wire.md) supplies the separately
reviewed closed configuration worker. The existing artifact SDK already owns
explicit read consent, immutable role-separated manifests, physical stage leases,
fixed invocation/environment/resources, SAFE approval, current authority checks,
actual local execution and immutable raw-result receipts.

The executable fixture must be registered as its own source family. A reviewed
hash or admitted source bytes cannot supply scope consent, native compatibility,
model write authority or an image/lifecycle VERSION prerequisite.

## Decision

Register exactly the existing frozen configuration worker SHA256
`af34b374fa49ce3048d3a7821df5ad8370849240a786dabc7311e14322476eb6`
as family `owned-synthetic-configuration-wire-v1`, provider `synthetic.trivy`,
version `0.75.0-synthetic`. Only `synthetic.dockerfile-offline.v1` and
`synthetic.kubernetes-offline.v1` admit that worker, and only operation `SCAN`.
VERSION and all non-null VERSION prerequisites reject before material verification.
The original lifecycle and image workers, argv, profiles and VERSION proofs remain
separate. Both native configuration profiles remain non-authorizable metadata.

Use the existing `ArtifactStage.Create`, `PrepareArtifact`,
`ArtifactPolicyEngine.Authorize`, `GovernedArtifactExecutor.Execute` and fresh
acceptance interfaces. No alternate command registry, scope owner, grant type,
executor, environment overlay, flag input or producer registration API is added.

Before approval the factory verifies the existing stage's selected bytes and
physical identities, then binds strict configuration policy to the one admitted
input manifest file. The exact five-case source catalog remains the reviewed
ADR 0051 name/length/SHA/profile catalog. Case-selected policy cannot supply
rules, findings, expected answers, code, resources or path expansion. Unknown or
changed source bytes, added input/control/material files, a swapped source-family
policy or mismatched profile/case fails closed. The worker and independent oracle
remain unchanged and the production SDK never reads the expected oracle.

Each configuration input selection contains one flat file of at most 4 KiB;
material is exactly `policy.json` of at most 1 KiB. Strict policy parsing rejects
extra/missing/duplicate fields, bool/float schema ambiguity, non-finite numbers,
excessive integer text, invalid UTF-8 and unsupported family/profile/case values.
The existing general snapshot stage retains its finite generic capture bounds;
configuration-specific bounds apply before request preparation, approval and each
live launch/acceptance reconstruction.

The exact ADR 0051 config argv runs selected current CPython with `-I -S` and the
frozen staged worker. Deadline is an actual integer from 1 through 60 seconds,
default 30. Stdout and stderr ceilings are each 16 KiB; caller limits can tighten
those bounds. Cleanup grace is at most five seconds. Fresh scratch cwd/home/temp,
empty ambient PATH and existing controlled platform environment remain required.
The worker interprets only owned admitted local bytes, creates no container or
workload, and performs no network or runtime reference resolution. These controls
are not an OS network/filesystem/CPU/memory sandbox or publisher authentication.

Input targets remain canonical whole-manifest ARTIFACT identities. Grants bind
owner, profile, source family, SCAN operation, capability, current scope and policy
content/revisions, manifest identities, stage lease, invocation, environment and
resources. Current authority and material are checked before launch and after the
actual process. Failure or post-run refusal retains original stdout/stderr and
terminal facts; it does not upgrade actual process truth or renew authority.

Historical schema-2 receipts use explicit configuration source-family hash and
closed input/material/stream bounds in `VerifyArtifactReplay`. This read-only
verifier preserves original successful or refused facts without current paths,
new grants or launches. Existing lifecycle schema-1/schema-2 and image historical
contracts retain their original identities. `VerifySyntheticImagePayloadReplay`
remains exclusively image-specific.

## Evidence and remaining boundaries

Portable tests execute the real frozen worker through the production governed
SDK on all five unchanged independent cases, including line 31/document 1 of the
second YAML document. They compare exact findings and actual file identities to
the independent oracle: three expected synthetic detections and two expected
no-finding cases, all with `scan_completeness=not-assessed`. Known fixture agreement
is not arbitrary Dockerfile/YAML detection accuracy or native Trivy acceptance.

Tests also cover strict material parsing, family/profile/operation/case mismatch,
resource expansion, selected source/worker/policy mutation, extra files, current
scope exclusion/revocation, changed owner/policy, post-run expiry/revocation and
real capture overflow. Actual raw streams and metadata are saved/read through the
existing evidence store and replayed against their original receipt. Existing
artifact/image/lifecycle regressions remain part of the focused validation set.

No configuration output importer, canonical model save, collision/triage update,
new graph edge or user CLI is introduced. Consequently synthetic source hints
cannot be promoted by this SDK slice to native assets or findings. Full consumer
namespace/collision and exact result normalization checks remain a separate
implementation under the previously proposed configuration natural-key namespace.
The independent oracle's future normalization/model cases remain open. No native
Trivy config compatibility or Task #158 closure is claimed.
