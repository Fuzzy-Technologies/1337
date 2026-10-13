# ADR 0044: Governed local artifact snapshots and offline authorization

## Status

Accepted — 2026-10-13. Experimental contract version 1; Task #278.

## Context

Image archives and explicitly selected configuration files are local inputs, not
network destinations. Tasks #142 and #158 need the same scope, consent, impact
policy, executor and evidence boundaries without inventing an IP address or a
second authorization store. A file read needs explicit selection authority before
its contents can be hashed. An archive hash does not identify an OCI manifest,
image configuration, layer DiffID, publisher or authenticated principal.

## Decision

Add `TargetKind.ARTIFACT` to the existing scope store with exactly
`manifest-sha256:<64 lowercase hexadecimal characters>`. The manifest binds a
version, closed profile identifier, input role, and sorted portable relative names
with exact byte lengths and SHA-256 hashes. Matching is exact and never crosses
target kinds. Existing scope schema 1 persists this additive Experimental kind;
readers without the kind reject it. Network `PolicyContext` and network issuance
explicitly reject artifact targets, including a target accompanied by allowed IPs.
Artifact grants are a distinct type and cannot authorize network operations.

### Selected reads and snapshots

Experimental `fuzzy1337.artifact_inputs` defines immutable `ArtifactReadConsent`,
`ArtifactSelection`, `ArtifactFile`, `ArtifactManifest`, `ArtifactSnapshot` and
`ArtifactStage` records. Consent records an explicit actor and non-secret read
authority reference; constructors perform no filesystem reads. `ArtifactStage.Create`
captures only finite, explicitly selected regular files. Capture grants no scan
authority. No recursive discovery or implicit files are selected.

Each manifest is domain-separated by profile and role: input, scanner or material.
Absolute source paths are excluded from manifest identity. The input manifest's
target is registered and allowed in the existing `LocalScopeStore`; there is no
artifact scope store. A one-file archive's content SHA remains distinct from the
input manifest SHA and every OCI digest.

Portable names have ASCII segments, no traversal, absolute path, backslash,
colon, trailing dot/space, reserved device name or case-fold collision. Capture
is bounded to 1,024 selected files, 512 MiB per file, 2 GiB total, 240 characters
per name and 16 segments. Physical checks reject observed symlinks, Windows
reparse points, non-regular files and multiply linked files, including ancestor
links. Streaming copies check identities, lengths and hashes before and after
reading. Unexpected files or directories in immutable stage partitions fail closed.

A fresh stage contains exactly `input`, `scanner`, `material` and `scratch`.
Input, scanner and material partitions are copied, read-only snapshots verified
before launch and before acceptance. The explicitly selected absolute executable
is also pinned and rehashed at both boundaries; it executes at its selected
location because copying an interpreter or dynamically linked executable can
change runtime resolution. Its staged copy binds the observed executable bytes.
Original input changes after capture do not change the approved snapshot. Reads
and execution require operator-exclusive control of the physical staging tree
and executable. Read-only permissions and before/after hashes cannot detect a
hostile writer changing and restoring bytes between checks, attest dynamic
libraries or establish OS immutability, isolation or publisher authenticity.

### Closed offline profiles

Experimental `fuzzy1337.artifact_policy` exposes only these profile identifiers:

| Profile                              | Input                                | Capability                            |
| ------------------------------------ | ------------------------------------ | ------------------------------------- |
| `trivy.image-archive-offline.v1`     | Exactly `image.tar`                  | `image.archive-vulnerabilities`       |
| `trivy.dockerfile-offline.v1`        | Exactly `Dockerfile`                 | `config.dockerfile-misconfigurations` |
| `trivy.kubernetes-offline.v1`        | Finite selected `.yaml`/`.yml` files | `config.kubernetes-misconfigurations` |
| `synthetic.image-archive-offline.v1` | Exactly `image.tar`                  | `image.archive-vulnerabilities`       |
| `synthetic.dockerfile-offline.v1`    | Exactly `Dockerfile`                 | `config.dockerfile-misconfigurations` |
| `synthetic.kubernetes-offline.v1`    | Finite selected `.yaml`/`.yml` files | `config.kubernetes-misconfigurations` |

The factory supplies a SAFE capability and exact argv, environment, workspace and
resource bounds. The three native IDs are metadata-only in this initial SDK:
planning, grant issuance and launch reject them even when operator version or
compatibility attestation text is supplied. Callers cannot register commands,
capability declarations, raw
flags, environment overlays, server/daemon/registry access, configuration files,
renderers, plugins or update operations. Configuration inputs exclude control
basenames, Rego, WASM, Helm and Terraform inputs. No rendering occurs.

Native image argv is the pinned Trivy 0.75 archive-only vulnerability profile,
with explicit empty config/ignore files, offline scan, all update/version/telemetry
operations disabled and memory cache. Its immutable material contains the
explicit `db/trivy.db` and `db/metadata.json` database snapshot. Native config argv
uses the independently documented `config` command, exactly one Dockerfile or
Kubernetes scanner, explicit empty config/ignore files, memory cache and disabled
check/version/telemetry updates. It does not copy image-only flags. Config's initial
check mode explicitly uses checks embedded in the pinned executable and an empty
immutable material manifest; it makes no external-check-bundle usage claim.

Synthetic counterparts have the exact prefix `(pinned interpreter, '-I', '-S',
staged 'scanner/producer.py')` and otherwise the same fixed profile arguments.
Both interpreter and producer bytes are pinned. An explicit `policy.json` material
fixture is pinned and passed through the fixed synthetic contract. This is a
bounded repository-owned oracle, not a general SAFE command registration or real
Trivy acceptance. The fixed synthetic prefix additionally supplies
`--fixture-policy <material/policy.json>` before the ordinary profile arguments.
The declared tool version is operator-attested metadata. Synthetic preparation
accepts only the current trusted running CPython interpreter at its canonical
path and a closed source-owned SHA-256 allowlist of reviewed repository producers.
There is no public producer or executable registration. Arbitrary scripts and
executable substitutes fail even when their bytes have been pinned. The initial
owned producer is a lifecycle oracle, not a finding detector. Adding a reviewed
image/config producer identity requires a separate source review. Native supplied
executable support requires later actual compatible-runtime acceptance.

Owned cwd, home, temp and XDG paths are under a fresh scratch partition. The facade
overrides the executor's inherited PATH, PATHEXT, locale and temp values, and binds
the remaining Windows platform values. Scratch starts empty and is single-run;
only bounded regular scratch outputs may appear afterward. This is an observed
post-run size/type bound, not an OS disk-write quota. No scratch output is
reused as an input or cache grant. Immutable material has no unlisted files.
Actual native behavior with a supplied compatible executable and database/check
material remains acceptance work in #140, #142 and #158. This foundation does not
install software, fetch databases or prove that a binary cannot use the network.

### Plans, grants and execution receipts

`ArtifactPolicyContext` carries current `ScopeSnapshot`, `ImpactPolicy` and the
explicit executing `owner_ref`. It has no network destinations. Scope attestation
and executor ownership are distinct operator metadata; consumers may additionally
require the recorded consent actor to equal their caller. The SDK is not an
authenticated principal system.

`ArtifactPolicyEngine.Plan/Authorize/Validate` bind the complete current scope
content and revision, consent, policy content and revision, owner, fixed profile,
input/scanner/material manifests, selected executable, physical stage lease,
exact invocation, workspace, controlled environment, privileges and resource
bounds. `InvocationDigest` alone is insufficient because it omits workspace,
environment and resources. Existing `ImpactPolicy` capability/impact/privilege
ceilings remain explicit, and SAFE is not an implicit permission.

The artifact grant is an immutable operator-attested metadata record with a
valid-until bound limited by policy and consent. It is not a signature. A fresh
synchronous context provider is evaluated before issuance and immediately before
the accepted `LocalExecutor` starts a process. Same-revision content changes,
exclusion, revocation, expiry, changed owner, executable, material or request deny.
Grant expiry also applies at result acceptance, including expiry during execution.
Live validation recomputes the same exact expiry from original issuance and the
bound policy/consent and checks that issuance was within recorded consent.
After full material hashing and again after scratch setup, a cheap final guard
reads the context provider and clock anew. It compares complete current authority
and request bindings, rather than only revisions, without restarting an expensive
hash cycle. Authority or expiry changes in either window prevent process launch.

`GovernedArtifactExecutor.Execute` returns a per-run immutable
`ArtifactExecutionOutcome` containing the actual `LocalExecutionResult` and a
separate `ArtifactAcceptance` receipt. Each receipt binds its exact run, stage,
grant and raw execution/termination/stream hashes/event identity. Replacing raw
bytes or swapping receipts cannot preserve acceptance. An accepted receipt binds
the original physical single-run marker containing both run and authorization
IDs and has a checked time within its grant and no later than fresh acceptance.
Missing, replaced or relinked markers deny. After full after-run hashing and marker
verification, the receipt decision also refreshes current context and time through
the same cheap final guards.
Post-run authority/material refusal is
recorded in that receipt; it never raises after discarding captured stdout/stderr,
uses a mutable last-result property, invents success, or changes the actual
process termination. Pre-launch denial starts no process and remains an
authorization failure. Cancellation, timeout, output limit and nonzero exit remain
actual executor outcomes. Unexpected executor cleanup failures retain the accepted
executor's provider-error classification.
Cooperative cancellation returns a raw terminal result. Caller coroutine
cancellation retains the existing executor's raise-after-owned-cleanup behavior;
this foundation does not promise a returned raw result for that distinct path.

Consumers capture raw streams in the existing evidence store with the original
plan/run provenance before any normalization. `ValidateAcceptance` freshly checks
the grant, current authority and all material immediately before a consumer
accepts normalized state; a previously successful receipt is not permanent
authority. Failed or cancelled processes are never accepted as a successful scan.
Historical replay verifies saved raw evidence and original provenance read-only;
it cannot reauthorize execution or relabel old bytes with a current grant.
Relocation preserves manifest identity but requires a new stage and fresh grant
for any launch. No authoritative grant store or parallel evidence store is added.

## Consequences and verification

Portable owned fixtures cover exact manifest identity, rejected physical/path
inputs, closed-world staging, mutations before launch/acceptance, missing/stale/
expired/revoked consent, same-revision changes, request/environment/resource
changes, network cross-kind denial, relocation/replay, raw failure preservation,
real cancellation and output limits through the existing executor. Real scanner
quality, implicit native material selection and OS sandboxing are not claimed.

## References

- [Existing scope contract](../SCOPE.md)
- [Existing policy contract](../POLICY.md)
- [Trivy 0.75 config CLI](https://trivy.dev/docs/v0.75/guide/references/configuration/cli/trivy_config/)
- [Trivy 0.75 image CLI](https://trivy.dev/docs/v0.75/guide/references/configuration/cli/trivy_image/)
- [Trivy built-in check selection](https://trivy.dev/docs/v0.75/guide/scanner/misconfiguration/check/builtin/)
