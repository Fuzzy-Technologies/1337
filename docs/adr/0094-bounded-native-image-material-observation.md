# ADR 0094: Bounded native image material observation

## Status

Accepted prerequisite architecture — 2026-10-23. Root and independent review
authorize isolated PR360 implementation under existing M2 Tasks #140/#142,
subject to the finite event/control correction below. This does not authorize
native product enrollment or new grants. The accepted Linux descendant owner at
`9b85ca9c71ed9b6bf5321812095dbbb8d24372a7` is a prerequisite; browser PR359
remains a separate pending consumer.

## Problem

The existing `NativeTrivySelection.Material()` synchronously hashes archive,
executable, database and metadata before/after execution and in a synchronous
launch hook. Its maximum selected bytes exceed 2.75 GiB. An asyncio job timeout
cannot interrupt this work; putting it in an unowned thread would leave file
reads running after cancellation without cleanup proof.

The current native collector also observes post-run material and authority
before publishing original stdout/stderr. Reusing that ordering in a bounded
product workflow could discard acquired bytes when a post-run observation stalls
or the outer task is cancelled. Existing low-level default behavior and receipt
schemas are compatibility contracts, so the proposed path must be additive.

## Fixed first-party observation owner

`native_image_observation.py` owns `NativeImageMaterialObserver`, its opaque
instance-issued proof and deadline ledger. The fixed installed worker is
`native_image_material_worker.py`. The observer accepts only the typed native selection, its explicit
read consent, an owning budget and cooperative cancellation. Confirm the consent
actor/selected paths before any selected-file content read. The owner constructs
the fixed installed `sys.executable -I -m <packaged-material-worker>` command;
callers cannot supply worker code, argv, flags, environment or extra paths.

Launch through the accepted `LocalExecutor` with explicit
`own_descendants=True`. Unsupported platforms/kernel interfaces, setup failure,
timeout, cancellation, output overflow or unknown cleanup yield no usable proof.
The default executor path and the accepted descendant implementation are not
changed. This helper observes selected local files; its read authorization never
grants permission to execute Trivy or admit a model result.

The worker handles only the original four roles in their original order:
archive (512 MiB), executable (256 MiB), `db/trivy.db` (2 GiB), and
`db/metadata.json` (16 KiB). It uses the existing regular-file/no-follow,
link/physical-identity, before/opened/after and chunked-hash checks, preserving
the same `NativeFileFact` tuple representation and explicit missing DB facts.
It never enumerates directories or returns archive, executable or database
content. The metadata role may additionally supply its bounded strict parsed
schema-two DB metadata, bound to that role's exact hash/identity, for pure
VERSION-output comparison. This remains private control data, not raw Trivy
output or a freshness claim. Optional database/metadata absence retains its exact
original `(None, None, None)` fact fields and metadata returns `None`, never an
invented empty schema-two object. A complete descriptive observation of absence
is not usable successful VERSION/SCAN product material.

### Private bounded control and proof

Proposed request/result envelopes have a fixed version, observation nonce,
workspace/owner/read-consent binding, exact selected paths/roles/byte ceilings,
and fixed-shape ordered facts. Each private envelope is at most 64 KiB; duplicate
fields, unknown fields, extra paths, noncanonical numbers or mismatched nonce/
selection fail closed. Diagnostics contain fixed categories, not file content.

Use a private per-operation directory with mode 0700 and an exclusively created
`request.json` with mode 0600, finite bytes, digest and verified no-follow physical identity, referenced
only by the installed helper's fixed command. This requires no new executor FD
inheritance feature. The owner privately consumes bounded helper result bytes;
they are not forwarded as Trivy stdout, findings or public job stream content.
Request/result cleanup belongs to the same observation owner. The request-file
handoff is selected; no sealed-FD alternative or new executor inheritance is
introduced. Captured private result stdout is at most 64 KiB. Neither caller
argv/environment nor an arbitrary material callback can replace the fixed worker.

A complete observation requires an actual successful helper result, confirmed descendant
cleanup, exact private control association and complete finite facts. A digest
or caller-built tuple alone is not an executed observation proof. Only the exact
issuing observer instance accepts its original issued proof object. Bind the proof
to its source operation, selected physical identities and completed time; do not
promise a stable real-time filesystem snapshot or hostile-writer exclusion.

The typed observer's `operation_reference` binds the whole VERSION/SCAN owner
pair, not one invocation's request identifier. The same pair reference permits
the post-VERSION proof to serve as the SCAN pre-proof without a fourth hash;
the original VERSION and SCAN request identifiers remain separately bound.
It is a correlation, never execution authority.

Cheap current checks preserve observed optional absence through no-follow leaf
metadata checks; later presence or a symlink refuses reuse. Archive/executable
remain required. VERSION acceptance independently requires present DB/metadata
facts and strict selected metadata. The final worker-handoff hook rechecks the
complete current selection/consent digest, including the consent record, rather
than only comparing its actor.

## One cumulative budget

The proposed product invocation has one cumulative 45-second ledger for all
selected-material observation, helper startup/cleanup, control handling and
custody/finalization. It is not reset by VERSION, SCAN, rejection or retry.
It charges actual elapsed overhead phases; the separately approved Trivy process
windows are accounted for by the overall job bound, not deducted twice. Every
phase also respects that overall absolute deadline.

| Phase                        | Inclusive maximum | Shared use                                         |
| ---------------------------- | ----------------- | -------------------------------------------------- |
| Before VERSION observation   | 12 seconds        | Initial material and VERSION launch proof          |
| After VERSION observation    | 12 seconds        | VERSION acceptance and SCAN pre-launch proof       |
| After SCAN observation       | 12 seconds        | SCAN acceptance and final pair material proof      |
| Custody/finalization reserve | 9 seconds         | Both original role sets and final bounded handling |

Each inclusive observation slot is `3 readiness + 6 worker + 3 cleanup = 12`
seconds. Therefore `3 * 12 + 9 = 45` seconds includes all accepted owner READY
and cleanup allowances; it is not 12 seconds of work followed by extra cleanup.
These are ceilings, not delays: debit actual monotonic elapsed time for startup,
private control handling, execution, cleanup and finalization. Fast completion
does not wait for an allowance to expire.

Let `spent` be actual overhead seconds already charged, and `final_remaining`
the unused part of the nine-second finalization reserve. At observation entry
use the monotonic absolute phase end
`min(now + 12, now + 45 - spent - final_remaining, overall_deadline)`.
The unused finalization reserve is unavailable to observations. Reserve the
final three seconds of the resulting phase for owned cleanup; owner readiness
is capped at three seconds and charged from the same phase. Immediately before
worker handoff, recompute its working window as the lesser of six seconds and
the phase remainder excluding cleanup. Refuse handoff if that leaves no working
time. Control framing/result validation also consumes the phase remainder; it
cannot add time outside this calculation.

Set the cooperative execution deadline at that working-window end and cap the
executor request timeout accordingly. Cancellation, overflow and failed reads
use the same reserved cleanup window. Debit cleanup even when no proof results.
Do not cancel an outer 12-second await and then append three unaccounted seconds
of owner cleanup. If cleanup remains unknown at the inclusive phase end, there
is no usable proof; report the unassessed/failure outcome rather than renewing
the slot or treating the timeout as confirmed termination.

There are no implicit retries and no repeated full hash at a synchronous hook.
Planning uses its own one-call ledger with at most one observation and may launch
this read-only helper, but never a Trivy provider process.

The successful path needs at most these three full observations. The after-
VERSION proof can also be the SCAN pre-launch proof when the same selected facts
are retained and cheap current checks still match; the after-SCAN proof serves
final persistence under the same rule. An intervening mismatch refuses success,
rather than launching an unbudgeted fourth observation.

The scanner's original three-second VERSION and selected SCAN process deadlines
remain unchanged and separate from this 45-second ledger. The SDK/job and
provider bounds explicitly account for those process windows plus this total
overhead ceiling. The additive VERSION and SCAN executions also select
`own_descendants=True`; each receives six seconds outside this ledger for three
seconds READY and three seconds cleanup. The provider total is therefore
`3 + scan_timeout_seconds + 45 + 12`, with an outer job at least one second
larger. Neither selected process deadline changes, and startup/cleanup cannot
be hidden behind a process timeout. The
outer job backstop does not purport to interrupt an unbounded synchronous hasher,
imply realtime I/O guarantees or turn unconfirmed cleanup into success. If
filesystem/kernel/storage behavior
prevents confirmation in the allowance, retain available custody and report
unassessed/failure or acknowledgement uncertainty.

## Cheap synchronous launch and persistence checks

The new bounded path consumes only a verified owned observation proof. The
existing heavy `Material()` method is not called by its launch callback.
At the final process-owner hook, reread only bounded no-follow regular-file/
directory physical identities, missing-leaf state, read-consent association,
current scope/owner/policy, cancellation and exclusive grant expiry. Require the
exact operation/request and original claimed native execution marker. Repeat
these cheap checks immediately before model CAS; a hash proof never substitutes
for current permission or a single-use claim.

The old `ObserveVersion` function also rereads metadata synchronously. The new
path instead compares the bounded original VERSION JSON with helper-verified
metadata through a pure validator; it does not reopen selected file contents on
the event loop. Preserve the old function/default path for historical callers.

Facts establish observations at specific boundaries, not continuity between
them. A changed physical identity or missing expected proof refuses execution
or persistence. No callback schedules an awaitable or unowned read thread.

## Additive original-outcome custody path

Keep `CaptureNativeTrivyOperation` defaults, original receipt keys, role names,
digest algorithms, VERSION unknown-version invocation and historical replay
unchanged. Add `CaptureBoundedNativeTrivyOperation` in a new bounded implementation
module, with only an additive export in the historical facade. It accepts the
exact typed observer/ledger/proof and never a generic material callback.

The capture owner must bridge outer task cancellation into the executor's
cooperative cancellation event and await that owned execution to return its
actual terminal outcome. Do not cancel/abandon the executor task and then lose
partial captured streams. Any task used for this handoff remains tracked,
bounded and awaited by the capture owner; shielding is not permission for
background work to outlive it. If cleanup cannot supply a terminal outcome,
retain available private fragments and report incomplete custody rather than
inventing an original successful or cancelled receipt.

When the accepted executor returns an actual result, synchronously transfer the
complete bounded original outcome into the capture owner's private custody
before the first await for post-run observation or authority verification.
Retain original request, start/end time, terminal state/termination, exact raw
streams and ordered events. Proposed private staging has a fixed finite framing,
integrity digest, exclusive owner and no provider-selected interpretation; a
32-MiB per-operation ceiling is a hard admission limit, not a conclusion derived
only from stream limits. Use a synchronous durable exclusive integrity-checked
journal in the collector's private operation directory before any postverification
await. A transient unowned background task is not custody.

The observer independently owns a fresh private per-observation directory and
its cleanup after a verified terminal helper outcome. The collector owns a
separate private per-Trivy-operation directory/journal. Both remain beneath the
verified workspace and bind exact proof/nonce/workspace/owner/selection and parent
identity. This avoids coupled cleanup ownership; callers supply no arbitrary
operation directory or descriptor.

The additive collector must enforce finite event count and exact event/control
serialization byte limits while observing. Stream byte ceilings alone do not
bound the number or serialization overhead of original events. Keep original
VERSION receipts at most 256 KiB and SCAN receipts at most 16 MiB, and each
private journal at most 32 MiB. Check the exact final receipt/journal sizes too.
Overflow retains only bounded exact original bytes/fragments and declares
incomplete, unassessed custody. Never trim or rechunk original events into a
purportedly accepted receipt. The collector owner must publish its concrete
incremental event/control bounds before implementation; it may not defer that
check until an unbounded original event list has already been acquired.

Then await post-run observation under the same budget and publish the existing
three original roles for that operation with an existing truthful refusal when
material/authority is unverified. A failed helper supplies `material_after=None`
and no usable proof; it does not change original executor facts. Do not invent
new success, synthetic receipts or a successful empty inventory. VERSION's
observed version is accepted only when its selected metadata/proof is verified.

Outer cancellation must cancel and await any active helper, then finalize the
already retained outcome using the reserved allowance. Finalization remains
owned and awaited; it cannot be discarded by the same outer cancellation or
continue unobserved after the owner returns. Publication failure preserves
available private staging and honest storage/commit acknowledgement uncertainty,
without claiming complete canonical custody. Physical I/O and power-loss
guarantees are not strengthened by this proposal.

## Prerequisite acceptance and follow-on boundary

This first prerequisite PR should implement only the fixed observation owner,
private control/proof and budget contracts, and additive native capture path.
Use closed pytest-owned regular files and deterministic installed helper/wire
processes to verify actual reads, private bytes, overflow, timeout, cancellation,
unknown cleanup, identity substitution and original stream retention during a
delayed post-run observation. Unsupported ownership must refuse before the
material worker or scanner starts. No real large-file generation is needed;
byte limits and selected-role guards have bounded deterministic probes.

Existing synchronous native capture/replay acceptance must remain independently
intact. No production native-image grant, native CLI, general material registry,
new provider/environment, network operation or scanner profile is enrolled by
this prerequisite. ADR0093's product follow-on owns native policy types, atomic
single-use claims, paired SDK/jobs/model persistence, CLI and genuine two-archive
acceptance. Both stages reference #140/#142; neither claims full scanner or
release completion. Per-commit checks stay focused; shared full integration CI
waits for final readiness.

## Accepted handoff and deferred product owner

- Source owners coordinate the observer/proof/ledger signatures and private
  framing before the separate additive collector consumes them.
- The deadline ledger follows the exact 12/12/12/9 and per-observation 3/6/3
  deductions above; the provider's additional 12 seconds are outside that ledger.
- The future canonical artifact owner adds `ClaimNativeImageExecution` and
  `ValidateNativeImageClaim` in a separate `native-image-claims` namespace with
  hash-of-grant filenames and an atomic persistent marker. It binds grant,
  operation, exact request/profile, proof and prerequisite; consumption survives
  failure/cancellation/spawn refusal. Repeated hooks validate the original handle
  rather than reclaim. This remains product follow-on work and cannot borrow a
  synthetic stage lease or retrofit old receipts.
