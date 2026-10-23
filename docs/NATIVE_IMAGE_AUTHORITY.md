# Native image authority

The Internal native IMAGE branch extends `ArtifactPolicyEngine` through explicit
typed methods backed by `native_image_policy`. Existing synthetic `Plan`,
`Authorize`, prepared records and replay schemas retain their original guards.
ADR 0093 defines the accepted boundary; SDK/CLI enrollment and genuine product
acceptance are separate work.

## Prepare and grant

`PrepareNativeImageOperation` accepts only the exact installed observer's original
issued proof and selected local archive, trusted executable and cache. It performs
cheap current physical checks, never selected-file content hashing or a provider
process. The canonical IMAGE/INPUT manifest names the archive `image.tar`; physical
selection paths and all four existing material facts are bound separately.

`PlanNativeImageOperation` describes the current fixed recipe and same-workspace
scope/policy authority. It issues no grant. `AuthorizeNativeImageOperation` also
requires explicit SAFE workflow approval and an independent current permission
for `native.trivy` / `image.archive-vulnerabilities`. Approval cannot manufacture
that permission. Scope/policy content and revisions, executing owner, read-consent
actor, selected facts and exclusive policy/consent-bounded expiry remain current.
The scope's recorded authority reference remains an independent attester.
The fixed native receipt profile requires an empty `granted_privileges` tuple;
surplus permission privileges are refused before issuing a grant.

VERSION retains the original three-second JSON command with unknown provider
version. SCAN requires an engine-registered original successful VERSION
prerequisite, including original grant, claim, request and receipt association.
It receives a distinct original grant. A fresh post-VERSION proof may have a
different observation nonce when its stable selected facts still agree.

## Consume and bind once

Call `ClaimNativeImageExecution` after structural/current authority validation and
before entering capture or inspecting that operation's cancellation signal.
An exclusive immutable private reservation under `native-image-claims` consumes
the grant. Later cancellation, unsupported ownership, setup/binding failure or
crash cannot release it. Reopened or concurrent attempts cannot reuse the grant.
Separate exclusive immutable indexes consume the operation and exact issued
observation identities too. A later grant cannot reuse either identity. Claim
creation consumes the observation index, then operation index, then per-grant
reservation; an existing or partially published index refuses without rollback.
Live and final claim checks authenticate all original index bytes and identities.

Each attempt owns a fresh private callback. Its first call unconditionally invokes
`BindNativeImageRequest` once. The second exclusive canonical file binds the full
actual request, including environment/resources, scratch identity, original claim
and exact issued proof. An existing or partial binding is refusal, even when its
bytes match. Later READY/publication callbacks only validate that binding.

`ValidateNativeImageClaim` always requires the live physical scratch directory.
After the collector removes scratch, `ValidateNativeImageCapture` authenticates
the persistent binding and original returned capture instead. Final
`ValidateNativeImagePairFresh` checks both original authorities/captures and the
latest issued proof before a separate model Save. Missing scratch never implicitly
selects a weaker validation phase.

## Evidence and limitations

Claims and bindings are separate from all six original evidence roles and their
unchanged receipts. Canonical custody checks bind original manifest IDs, exact
bytes and the full claimed request; constructing a dataclass is not execution
authentication. The trusted product owner supplies the actual collector return.
Offline historical replay neither reads current selected material nor requires
a current claim, and replay never grants new execution authority.

No API here launches Trivy, downloads a database, persists an image model or
authenticates a provider publisher. Filesystem checks are observations, not a
hostile-writer exclusion or operating-system sandbox. Bounded metadata writes
retain ordinary filesystem timing and acknowledgement uncertainty; there is no
new real-time or power-loss guarantee. Never remove or repair a consumed marker
to retry; obtain a new current plan, grant, operation and observation.
