# Bounded native image observation and custody

This Internal prerequisite supports the Experimental native Trivy product
design in ADR0093. It does not enroll a native product profile, issue an artifact
grant, expose a native image CLI or persist scanner model state. ADR0094 defines
the accepted observation and original-custody architecture.

## Fixed selected material

`NativeImageMaterialObserver` accepts an explicit `NativeTrivySelection`, matching
read consent, workspace identity and owner. Its installed Python worker reads
only these four selected roles, in order:

| Role | Inclusive byte limit | Absence |
| --- | ---: | --- |
| Archive | 512 MiB | Refused |
| Selected executable | 256 MiB | Refused |
| Vulnerability database | 2 GiB | Explicit missing fact |
| Database metadata | 16 KiB | Explicit missing fact |

The helper never runs the selected executable, discovers paths, opens a network
connection or enumerates directories. Original `NativeFileFact` hashes, lengths
and physical identities retain their existing representation. Bounded schema-2
metadata is returned privately and checked against its selected-file hash.

The observer creates its own private operation directory and exclusive request
file with modes 0700 and 0600. Request and result envelopes are each at most
64 KiB. Exact physical identity, canonical bytes, digest, nonce, read consent,
selection and owner bind the handoff. The fixed installed helper uses accepted
Linux descendant ownership; unavailable ownership refuses before selected-content
reads. Private helper output is not a scanner stream or Finding.

## Observation proof and time budget

Only an original proof object issued by the same observer instance is usable.
A tuple, digest, reconstructed object or another observer's proof is not an
executed observation. `CheckCurrent` checks the original context and current
physical metadata without reopening selected contents. These checks establish
observed filesystem boundaries; they do not exclude a hostile concurrent writer
or guarantee a continuous snapshot.

The operation reference identifies the whole VERSION/SCAN pair. Its first
observation precedes VERSION; the second follows VERSION and also supplies the
cheap pre-SCAN check; the third follows SCAN. There is no fourth full hash.

| Allowance | Bound and accounting |
| --- | --- |
| Planning | One 12-second observation, no scanner execution |
| Each of three operation observations | 12 seconds including readiness and cleanup |
| Worker portion | At most 6 seconds, with 3 seconds each reserved for readiness and cleanup |
| Journal and publication | One cumulative 9-second allowance across both operations |
| Total material and finalization | At most 45 seconds, charged by actual monotonic elapsed time |
| Scanner startup and cleanup | An additional 6 seconds per VERSION/SCAN outside the 45-second ledger |

Finalization may use multiple nonoverlapping slices. Writing an original journal
before a post-run observation and publishing its receipts afterward debit the
same remaining allowance. Neither an observation nor a finalization slice
renews the cumulative budget. VERSION retains its three-second process deadline;
SCAN retains its selected deadline. The future provider bound is
`3 + scan_timeout_seconds + 45 + 12`, with a job backstop at least one second
larger. Deadlines do not promise to preempt a kernel or synchronous storage stall.

## Additive bounded collection

`CaptureBoundedNativeTrivyOperation` consumes the typed observer, ledger and
proof. The historical `CaptureNativeTrivyOperation` remains available with its
existing defaults and receipt schema. VERSION's original invocation still has
unknown provider version; only verified observed JSON and selected metadata
establish the version used for the subsequent SCAN.

The collector owns a separate private directory and journal. It bridges outer
cancellation into cooperative executor cancellation and awaits owned cleanup.
Before the first post-execution await, it synchronously retains the exact
original request, timestamps, terminal result, streams and ordered events in a
bounded integrity-checked durable journal. Observer control files and collector
journals have separate cleanup owners.

Stream limits do not bound event count. The additive collector enforces finite
event and encoded-control limits while observing, then checks exact final sizes:
VERSION receipts stay within 256 KiB, SCAN receipts within 16 MiB and a private
journal within 32 MiB. Overflow preserves bounded exact fragments and reports
incomplete custody. It cannot trim or rechunk events into an accepted receipt.

Successful publication retains the existing three original roles per operation:
`provider-version`, `provider-version-stderr`, `native-version-receipt`, then
`stdout`, `stderr`, `native-scan-receipt`. A failed post-run observation gives no
usable proof and retains a truthful refusal with unknown post-run material.
Uncertain publication retains the private journal; it does not establish
canonical custody or scanner success.

## Verification boundary

Closed deterministic tests cover fixed role selection, wire identity, proof
substitution, cumulative deadlines, cancellation and incomplete custody.
Executor doubles establish those local contracts only. Genuine installed-helper
acceptance additionally requires supported Linux ownership; an optional local
skip is not a passing process-lifecycle result. Original native Trivy acceptance
and admission remain separate compatibility checks. Product grants, atomic
single-use claims, SDK/CLI enrollment and genuine two-archive product acceptance
remain the ADR0093 follow-on.
