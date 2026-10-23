# ADR 0093: Governed native image product workflow

## Status

Partially accepted — 2026-10-23, after independent architecture review.
ADR0094's isolated prerequisite, additive native authority/atomic-claim slice and
SDK/CLI integration below are implementation-authorized. Native enrollment
requires their own reviewed implementation and genuine paired product acceptance.
Refs M2 Tasks #140 and #142, Feature #138, and MVP acceptance #40. This decision
alone enrolls no executable native product profile.

## Context and accepted boundary

ADR 0013 selects Trivy as the first optional image/SBOM provider; Syft and Grype
remain deferred. The accepted offline archive adapter, original VERSION/SCAN
capture (ADR 0058), and canonical native admission (ADR 0067) already execute
the genuine selected engine against owned inert metadata in isolated CI.
They do not issue a current product grant. `scan image --profile synthetic`
still selects the separate synthetic family, while `ArtifactProfile.IMAGE`
(`trivy.image-archive-offline.v1`) remains metadata-only.

The proposal branch starts at `667027f`. The stronger Linux descendant owner
from PR358 is now accepted at `9b85ca9c71ed9b6bf5321812095dbbb8d24372a7` and is a
prerequisite of bounded material observation. PR359 offline Playwright/Chromium
still awaits its own genuine acceptance; this image design does not modify that
source or turn local optional skips into browser acceptance.

The smallest next first-party product capability is a governed native image
workflow over the existing Trivy producer, not a new scanner implementation or
a dependency-maintenance task. No new provider, archive decoder, payload profile,
registry transport, daemon target, environment profile, or automatic download is
proposed. Genuine tests reuse the two existing Docker-save archives. The OCI
digest in their original oracle identifies the pre-provisioned vulnerability
database; it does not establish OCI-image archive input support.

## Proposed product selection and material identity

Keep the adapter's single explicit local archive profile. The SDK requires an
existing physical workspace, explicit selected archive/cache paths beneath that
workspace, an absolute trusted optional Trivy executable, and independent
`ArtifactReadConsent`. No executable search, installation, file discovery, image
execution, registry access, DB update, or inherited scanner configuration occurs.

Preserve the four ordered `NativeFileFact` roles, bounds and representation from
`NativeTrivySelection.Material()`. The product path must obtain those facts from
the fixed bounded first-party observation owner proposed in
[ADR 0094](0094-bounded-native-image-material-observation.md). It must not call
the existing synchronous whole-file hasher on the event loop or final launch
hook. The historical `Material()` and capture defaults remain unchanged:

| Role              | Existing maximum | Required binding                                                |
| ----------------- | ---------------- | --------------------------------------------------------------- |
| archive           | 512 MiB          | Path, byte length/SHA256, device/inode/size/mtime/ctime         |
| executable        | 256 MiB          | Explicit trusted absolute path and the same physical facts      |
| database          | 2 GiB            | Selected cache's `db/trivy.db`, including explicit absence      |
| database-metadata | 16 KiB           | Selected cache's `db/metadata.json`, including explicit absence |

No missing DB or metadata becomes an empty successful scan. Source authenticity
is established separately by deployment/provisioning; a file checksum is not a
publisher signature. The product retains observed DB update time and selected
hashes without claiming freshness or complete vulnerability coverage.

Use the existing schema-one `ArtifactManifest` only for the archive's INPUT
identity: profile IMAGE, role INPUT, one canonical logical name `image.tar`, and
the selected archive's length/hash. Its exact
`Target(ARTIFACT, "manifest-sha256:" + manifest.Digest())` is the registered scope
target. It is distinct from the archive blob hash, image config digest, native
image identity, and database OCI digest. Physical source path facts remain bound
separately; changing that location or identity invalidates a live plan.

Do not force the native DB through the synthetic stage schema or raise its
global bounds: `ArtifactFile` permits 512 MiB per file, whereas native DB capture
already permits 2 GiB. The native authority record must bind the existing four
native facts directly. Historical selected paths are never reopened by replay.

A usable observation proof requires explicit read consent before any selected
file read, the exact four selected paths, an actual successful installed isolated
Python helper, complete private bounded output, matching selection/owner/nonce,
and confirmed owned cleanup. Timeout, cancellation or unknown cleanup supplies
no complete observation proof. Optional DB/metadata absence retains its original
all-None facts in a descriptive observation; it cannot supply executable material
or an accepted VERSION. At final synchronous launch and Save hooks,
perform only bounded no-follow physical-identity, current authority, expiry,
cancellation and claim checks; never rehash a multi-GiB database there.

These are filesystem observations at specified boundaries. They are not a
real-time snapshot, hostile-writer exclusion, publisher authentication or a
guarantee that bytes cannot change between an observation and use.

## Accepted native authority extension

The canonical artifact-policy owner must explicitly admit this one native IMAGE
branch. Do not remove the synthetic-only guards in `ValidateArtifactProfile`,
`PreparedArtifact`, `ArtifactPlan`, or `ArtifactVersionProof`, and do not use the
network `PolicyEngine` with a fabricated IP destination. Existing synthetic
plans/grants/replay schemas must retain their original bytes and identities.

Use a tagged native-image plan/grant variant owned by the
existing `ArtifactPolicyEngine`, with separate native prepare/authorize/validate
entry points. This is a typed extension of the existing authority subsystem, not
a new permission store or an authority issued by the capture/admission layer.
An additive `native_image_policy.py` owns the explicit native records and bounded
helpers; thin typed methods on the canonical engine delegate without broadening
its existing synthetic `Plan` or `Authorize` paths.

The native record binds at least:

- a native-image schema/family discriminator, IMAGE profile, SAFE impact, existing
  `native.trivy` / `image.archive-vulnerabilities` capability, and operation;
- workspace identity; current scope reference/revision/content digest and complete
  recorded consent; explicit executing owner and selected read-consent actor;
- current policy reference/revision/content digest, explicit permission and
  privileges, exclusive expiry bounded by both policy and recorded consent;
- canonical input-manifest digest/ARTIFACT target and exact ordered native
  selected-material facts/digest, including physical identities;
- exact adapter invocation digest, fixed capture resource/environment profile,
  and a fresh product operation identity correlated with an atomic execution
  claim; the operation identifier alone does not establish single use;
- for SCAN only: original VERSION capture digest, original VERSION authorization
  identifier, original receipt manifest identity and receipt blob digest, and
  the actually observed supported provider version.

Reuse existing `ExecutionAuthorization` with the artifact authority namespace and
the exact original invocation digest. VERSION and SCAN have different original
authorization identifiers. Product metadata must not retrofit a synthetic stage
lease/run identifier into a native capture or replace current raw receipt IDs.

Require the executing context owner, observer owner and read-consent actor to
agree. The scope's existing `authority_reference` remains an independent recorded
attester/reference, bound through the complete scope content; it is not a new
executing-actor field or verified signature.

### Atomic single-use native execution claim

Add explicit native `ClaimNativeImageExecution`, `BindNativeImageRequest` and
`ValidateNativeImageClaim`
operations to the canonical artifact
owner. Use a separate persistent native-image claim namespace under its owned
workspace metadata, with hash-of-grant filenames in `native-image-claims`, never
a synthetic stage's `scratch/run-lease.json`. Its
atomic exclusive-create marker/lease binds the native family/profile, workspace,
operation identity and VERSION/SCAN kind, grant identifier and digest, exact
request/invocation profile, selected observation proof and original prerequisite.
Verify non-following physical directory/marker ownership and bounded canonical
marker contents. The same grant can have only one successful claim, including
concurrent attempts or another process reopening that workspace.

Separate bounded immutable exclusive indexes consume the operation and exact
issued observation identities, not only the grant identifier. Consume the
observation index, then the operation index, then the per-grant reservation.
A later issuance cannot reuse an old operation or proof. Existing, partial or
unverifiable indexes refuse without rollback or repair; original claim validation
authenticates all index bytes and physical identities at live/final boundaries.

Validate the original grant and exact observer-issued proof, then exclusively
create the immutable reservation before calling bounded capture or checking that
operation's cancellation signal. Malformed or unauthorized requests fail before
reservation. Successful creation consumes the grant even if later cancellation,
unsupported ownership, setup refusal, request-binding failure or crash prevents
a worker from starting. Never delete or release a consumed reservation.

Each product attempt creates a fresh private callback. Its first invocation
unconditionally calls `BindNativeImageRequest` on the original opaque claim
handle. Before the first executor startup, bind verifies the fixed approved
recipe and exclusively creates, fsyncs and reads back a second bounded canonical
file containing the full actual `LocalExecutionRequest`, claim digest,
workspace/scratch physical identities and exact selected proof association.
`InvocationDigest` alone is insufficient because it excludes workspace,
environment and resources. The immutable reservation is never rewritten.
An existing binding is refusal, never a successful new bind or resumed attempt.

Only after that first bind succeeds may subsequent READY, post-execution and
publication callbacks validate the same original handle/request/binding. They
recheck current authority, exclusive expiry, cancellation and cheap selected
physical metadata without creating another claim or repairing partial state.
Launch and READY checks require the actual live scratch identity. The collector
legitimately removes scratch before returning; final Save instead authenticates
the persistent reservation/binding, original returned request/capture and fresh
selected proof. It must not require an already cleaned scratch directory.

Bind original opaque handles to their issuing engine and exact object identity.
Another product attempt cannot reuse an old callback or infer permission from an
existing marker. Existing, incomplete, replaced or unverifiable reservation or
binding files fail closed, including reopened or concurrent attempts. Retry
requires a new current plan, grant, operation and observation. The grant binds
stable selected facts and recipe; each claim additionally binds its exact
issuer-owned proof. A fresh post-VERSION proof may have a different nonce for
SCAN only when stable facts and the original VERSION prerequisite still agree.
Store claim metadata separately from the original six capture roles. Native
capture/replay schemas and original receipt identifiers remain unchanged, and
offline replay does not need a current physical claim to reopen old evidence.

Bounded metadata operations retain the existing soft filesystem timing limits;
this design adds no real-time or power-loss guarantee.

Current workspace/scope/consent/owner/policy and selected material are checked
before read-authorized preparation, through bounded observations at the defined
boundaries, cheaply at each final process launch callback, after cleanup, and
for both original grants immediately before model Save. Revocation,
expiry, changed material, changed policy or mismatched original VERSION refuses
success. A previous grant, checksum, provisioning receipt or canonical replay
never supplies current execution authority.

## Accepted planning and execution semantics

Add a first-party native-image SDK/workflow owner, reusing these existing owners:

| Concern             | Existing owner                                                      |
| ------------------- | ------------------------------------------------------------------- |
| Read/scope identity | `artifact_inputs`, `LocalScopeStore`, `ArtifactPolicyContext`       |
| Current authority   | Explicit native branch of `ArtifactPolicyEngine`                    |
| Exact commands      | `TrivyAdapter.PrepareVersionInvocation` / `PrepareInvocation`       |
| Original capture    | `CaptureNativeTrivyOperation` / `NativeTrivyOperationCapture`       |
| Canonical proposal  | `ApplyVerifiedNativeTrivyImages`                                    |
| Model/workspace     | `LocalModelStore.Save` CAS / `LocalWorkspaceStore`                  |
| Historical replay   | `VerifyNativeTrivyImageReplay`                                      |
| Jobs/events/export  | Existing `ScanJob`, canonical job/evidence events and report owners |

Keep VERSION's actual three-second JSON invocation with `provider_version=None`.
Never run an ungoverned health probe to create a substitute prerequisite. A
planning command may use the bounded read-authorized material helper and present
the exact VERSION plan plus a deferred SCAN recipe. It starts no Trivy process
and cannot claim an accepted original VERSION or fully bound final SCAN intent
before VERSION executes.

`PlanNativeImageScan` uses a separate planning-only twelve-second observation.
When both scope and policy are absent, explicit material preview returns the
canonical INPUT manifest and ARTIFACT target for ordinary operator registration.
It creates no scope, grant or Trivy process. When both are present, return the
strictly scoped VERSION plan; one missing input is invalid. A denied scoped plan
never falls back to preview. `ScanNativeImage` always requires both fresh sources
and explicit SAFE workflow approval. Native summaries are separate from existing
synthetic summaries and report overall coverage as `not-assessed`.

Recommended operator contract: retain SAFE semantics, explicit native selection,
explicit workflow approval and a fresh typed native-capability policy. Reuse the
existing `--approve-safe-image` concept as an explicit workflow opt-in; it must
not manufacture a policy permission. Do not label SAFE as STANDARD or fabricate
an exact confirmation digest for an unexecuted SCAN. Native CLI selection should
be explicit (proposed `scan image --profile native`) and leave the existing
synthetic command unchanged. Final CLI/registry edits belong to one integration
owner after SDK acceptance.

After a separately authorized original VERSION succeeds and its selected DB
metadata is verified, build the actual SCAN invocation using the observed version
and original prerequisite. Issue a fresh current SCAN grant. Reuse the unchanged
fixed offline argv, capture environments, scratch separation, output budgets and
original refusal handling. There is no registry/daemon target, arbitrary flags,
user-supplied environment, DB refresh, remote socket or credential path.

The previous `3 + scan_timeout_seconds + 30` asyncio timeout proposal is not
sufficient: it cannot interrupt synchronous hashing of approximately 2.75 GiB,
including hashing inside the final synchronous launch callback. An unowned
`to_thread` worker is not an acceptable fix.

The proposed replacement is the deadline ledger in ADR0094: at most three owned
material observations, each with an inclusive 12-second ceiling, plus nine
seconds reserved for custody/finalization, share one cumulative 45-second budget.
Each observation includes at most three seconds of owner readiness, six seconds
of material-worker execution and three seconds of owned cleanup. Startup,
cleanup, control parsing and finalization consume actual monotonic elapsed time
from that same budget; no observation receives a fresh 45 seconds. Reserve
cleanup before worker handoff and refuse before launch if no working time
remains. VERSION remains three seconds and SCAN keeps its selected deadline.
The additive VERSION/SCAN also select owned descendants and each reserve three
seconds READY plus three seconds cleanup outside the material ledger. The
provider bound is `3 + scan_timeout_seconds + 45 + 12`; the SDK/job backstop is at
least one second larger. The job deadline is a backstop, not the
mechanism that interrupts hashing or supplies missing cleanup proof. Slow
material may be unassessed rather than extending an approved deadline.

## Original custody and durable result

Preserve the existing six original roles unchanged:

- VERSION: `provider-version`, `provider-version-stderr`, `native-version-receipt`;
- SCAN: `stdout`, `stderr`, `native-scan-receipt`.

Keep original invocation digests, request/scratch/environment facts, collection
times, terminal state/termination/events, unknown-version VERSION invocation,
observed version, material before/after, refusal and original prerequisite digest.
Native replay verifies these exact current receipt/manifests; it does not invent
legacy health evidence or convert a refusal into success. Additional product
grant/job metadata is separate and cannot replace any original role.

The new additive bounded capture path must retain the original executor outcome
before its first await for post-run material or authority verification. The
historical path currently hashes/checks authority before its first stream Put;
that ordering cannot be reused as the new path's custody guarantee. Use bounded
private durable original-outcome journal of at most 32 MiB owned through
finalization, then publish the
existing three stream/receipt roles with a truthful existing refusal if later
observation or authority fails. Outer cancellation must not discard bytes already
acquired by the executor. Finalization and helper cleanup are awaited under the
same budget, never left as unowned background work. Unconfirmed publication
retains available staging and reports storage/acknowledgement uncertainty; it
cannot claim complete custody, usable material proof or canonical success.

Bridge original collector publication through a fixed private evidence-store
adapter to `JobContext.CaptureEvidence`, preserving exact role/media/provenance
and original IDs. The job itself uses the plain canonical evidence store to avoid
recursive publication. Enforce native role/media/size limits before eager blob
reads. If publication or event acknowledgement fails, bounded readback may retain
only independently verified exact original records in a private acquisition
ledger, then rethrow the original failure. It is not a retry or successful
acknowledgement; summaries expose verified evidence IDs, never private journal
paths. Reconcile this ledger and job artifacts for references-only retention even
after cancellation or authority revocation.

Freeze initial model and workspace revisions. Semantic success and finalization
share one workspace-save attempt state, so finalization does not repeat a stale
CAS or silently rebase. If model publication committed before acknowledgement or
a later authority/workspace/event failure, report failure and the independently
reopened actual revision without rollback or retry. Fresh authority still gates
semantic success; retention alone does not certify a successful scan. Emit the
model-change event only after both saves are acknowledged, and export only the
exact saved model with separate report-failure status.

Finite original event-count and event/control serialization limits must be
enforced while observing; bounded streams alone do not bound an original event
list. Retain the existing 256-KiB VERSION and 16-MiB SCAN receipt ceilings and
check exact final journal/receipt sizes. Overflow retains bounded exact originals
or fragments as incomplete, unassessed custody, never trimmed/rechunked events
presented as an accepted receipt.

The observer owns its separate per-observation private directory, and the
collector owns its per-Trivy-operation journal directory. Their exact proof,
nonce, workspace/owner/selection and parent identity bind the handoff; neither
owner can remove the other's live directory. The observation pair reference
spans VERSION/SCAN without replacing their distinct original request identities.

Only a successful currently accepted original pair may enter
`ApplyVerifiedNativeTrivyImages`. Its returned proposal is not persistence.
Revalidate both current grants/material associations and cancellation immediately
before a single expected-revision model CAS. Preserve existing image/package/
Finding identities and triage. Then verify and persist all actual acquisition,
object, job and scope references using the original expected workspace revision.
Available originals survive failure. Save/acknowledgement/event/export failures
must distinguish already committed state from uncommitted work; no false rollback
or blind retry is claimed.

## Independent acceptance before native enrollment

The proposed handwritten product oracle references the existing unchanged
`native_archive.py` and `native_oracle.json`. It introduces no executable test,
archive bytes, provider pin, or target. Use its exact two 20,480-byte Docker-save
cases and existing Trivy 0.75.0/official DB OCI pin. The 2.30.0 case must produce
the selected `CVE-2023-32681` correlation; 2.31.0 must omit that correlation.
The fixed case does not require zero unrelated Findings and is not a secure or
complete-scan assertion.

Acceptance must establish:

1. Actual paired SDK and installed isolated CLI runs in the existing separate
   no-egress Linux namespace, using the already pinned real binary/DB and owned
   inert archives. Planning starts no Trivy process; original source custody,
   current product grants and canonical saved results agree.
2. Exact six-role provenance and prerequisite binding; offline and relocated
   reopen after original archive/binary/cache removal; unchanged original capture
   IDs and byte identities, separate image/package/Finding identities and triage.
3. Denial before any operation for missing/revoked/expired scope, wrong owner,
   missing permission/read consent, changed archive/binary/DB/metadata or missing
   explicit approval. Failed/unverified VERSION never starts SCAN.
4. Separate grant and material rechecks at VERSION/SCAN launch and immediately
   before model/workspace persistence. Substituted same-content receipts or old
   grants cannot replace the original VERSION association. Concurrent/repeated
   claims for one grant fail; a cancelled or refused claimed launch stays consumed.
5. Actual delayed synthetic process timeout/cancellation/output-limit and failed
   genuine missing/invalid DB preserve available exact streams/refusals, produce
   no new successful inventory or Findings, and remain reopenable. Zero findings
   from a failed, refused, skipped or unexecuted operation are unassessed.
6. Required genuine CI explicitly selects this product oracle with all existing
   provisioning variables and isolation checks. Missing material fails the lane;
   local optional skips establish no native acceptance. Keep existing low-level
   adapter/capture/admission acceptance independently intact.
7. Actual owned observation-helper timeout/cancellation and unconfirmed cleanup
   produce no proof or scanner launch. A delayed post-run observer cannot erase
   already acquired VERSION/SCAN streams. Cumulative observation/finalization time
   stays within one budget rather than multiplying the allowance per operation.

## Minimum prerequisite and product follow-on

First, review and implement only ADR0094's bounded installed material observer,
private proof/control contract, deadline ledger and additive capture custody path
with closed deterministic owned-file/process acceptance. This prerequisite issues
no native product grants, enrolls no native profile, adds no native scan CLI and
changes no historical capture default or receipt schema. The accepted Linux
descendant owner is reused through its explicit opt-in, not modified or copied.

Only after that prerequisite is accepted may a separately reviewed product PR
add this ADR's native artifact authority variant, atomic native execution claim, paired
SDK/job/model integration and explicit CLI route. Its genuine two-archive/DB
acceptance remains mandatory before native enrollment is accepted. Both PRs
reference the existing #140/#142 metadata without closing broader remaining work.

Per-commit checks remain small and deterministic with bounded independent
workers. Full shared gates run at final review readiness only. No release,
master change, tag or PyPI publication is included.

## Design choices requiring root review

The proposed choices are a tagged native authority variant in the canonical
artifact-policy owner; existing INPUT manifest plus native material facts rather
than a widened synthetic stage; explicit SAFE approval rather than premature
exact SCAN confirmation; and the bounded observation/custody owner and ledger.
ADR0094 records the accepted prerequisite choices: fixed installed observer,
opaque proof, private 0700/0600 control files, additive typed capture facade,
durable bounded journal and finite cumulative ledger with separate provider
overhead. Only that prerequisite is authorized. Native artifact policy/claim
types and product integration require a separately reviewed follow-on. No
historical capture receipt/default or existing handwritten oracle changes here.
