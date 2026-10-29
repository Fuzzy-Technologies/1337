# ADR 0098: First-party offline check of original owned-response headers

- Status: Proposed source contract; independent review required before implementation
- Date: 2026-10-24
- Decision owners: Fuzzy Technologies
- Related work: #59, #53, #40; task metadata remains coordinator-owned

## Context

Accepted develop `250cfceeb3438ae47b9ed2ad800e520ce7fde9a6`, tree
`99d65a5a1c5ed13f250aa66f25599ceadf34af45`, includes PR #363 original owned-response
capture and offline replay. Those owners verify actual complete original request,
header/body/wire records, the original execution receipt and durable product
source/job association. They explicitly produce no assessment or Finding.

The three independently frozen response wires already distinguish a missing
X-Content-Type-Options field, an actual fixed header and body text that merely
mentions the header. A first-party interpretation can use those originals without
another target request, external scanner or runtime. Native crawl and Git-check
metadata cannot substitute for original header custody.

## Decision

Propose Experimental profile `owned-response-header-absence.v1`, source/provider
`native.response-passive`, capability `http.owned-response-header-check`, check
`native.response-header-xcto-absent`, maximum impact PASSIVE. The
[contract](../NATIVE_RESPONSE_HEADER_CHECK_CONTRACT.md) freezes the exact input,
authority prerequisite, source proof, provenance and storage semantics. These
identities are independent of ZAP rule 10021; no ZAP result or acceptance is claimed.

Select one existing workspace, original acknowledged capture receipt ID, exact
expected source URL Target, original owning scope, fixed executing-owner
attribution, fresh typed policy reader, separate explicit opt-in, analysis
reference and expected model/workspace revisions. A supplied trusted synchronous
current-owner reader must freshly equal the selected owner. Its absent-reader
default is selected attribution, not external authentication. The independent
scope consent attester is never substituted for the executing owner.

Use both existing product association replay and original custody replay. Require
all seven original records, successful captured execution, complete custody and
known source Endpoint/job association. Source URL, scope, workspace and original
role identities must match the selection. Refusal, failed/incomplete acquisition,
unknown original-custody acknowledgement, missing associations or corrupt originals
cannot create a Finding. Read no caller file/locator and perform no acquisition or re-Put.
Complete original source custody is distinct from any later product Save failure;
this operation never upgrades an earlier acquisition or persistence acknowledgement.

Only after source and current authority verification, inspect actual field names
in `owned-response-headers`. Match the complete case-insensitive field name
`x-content-type-options`, never a body substring, path/case label, catalog case
lookup or provider alert. Absence yields one LOW, OPEN, unknown-confidence
Finding; presence yields only a bounded negative assessment of this exact
predicate and captured response. Wrong values or other response forms are not
new profiles: the accepted acquisition/replayer still refuses unadmitted wires.

## Workflow-local offline admission

Current PolicyEngine authorizes AdapterInvocation/process intents; there is no
accepted no-process invocation owner to reuse here. Creating fake argv, a worker
stdout record, AdapterExecution, LocalExecutionResult or launch grant would
misrepresent this analysis. Artifact execution grants do not apply to retained
response receipts either.

Use a narrow local offline-authority guard in the new workflow, without a core
policy prerequisite or extension. It reuses unchanged ScopeSnapshot
checks, ImpactPolicy/CapabilityPermission values, aware exclusive consent expiry
and the accepted current-owner-reader precedent. It requires the exact new
provider/capability permission and explicit opt-in before analysis, then checks
the unchanged complete authority basis again immediately before each Save. A
capture permission or historical receipt grants no analysis permission. This is
an explicit local admission boundary, not an existing PolicyEngine grant, core-policy
change or proposal for a generic executor framework. Missing authority refuses.

At initial admission freeze aware `issued_at` and
`expires_at = min(initial consent expiry, issued_at + initial policy.max_authorization_seconds)`.
If consent has no expiry, use the policy deadline alone. Include both original
times in the immutable basis/assessment and fixed-basis equality. Every later
source, interpretation and pre-Save boundary requires
`issued_at <= fresh_time < expires_at`, current consent and the unchanged original
scope/policy/intent. Fresh times must not regress from earlier decision times.
Check again after synchronous reads before using their result; late return or
clock regression refuses without renewal, retry or another admission window.
Keep `checked_at` as the final fresh decision time, excluded from fixed-basis
equality. This is fail-on-late local admission, not preemption of blocking I/O or
a fabricated PolicyGrant. Preserve any actual earlier Save/ACK on later expiry.

Pure historical verification remains read-only and does not renew current
consent. Applying a new interpretation is separate work requiring current granted
URL and literal-IP registration/allow membership in the original owning scope.
No scope enrollment, permission rewrite, target request or external-principal
authentication is added.

## Canonical interpretation and acknowledgements

Use existing original evidence references and honest ModelProvenance with source
`native.response-passive`, version `1`, explicit analysis reference/time and
`execution=None`. Retain an assessment Observation linking original receipt,
source fact, role identities, header hash and fixed predicate, together with the
current attributed authority basis. Never reuse the acquisition job as a new
analysis run or represent analysis as tool execution. Original capture provenance
and actual execution remain unchanged in their original records.

The subject is the existing exact-URL Endpoint from owned-response capture.
Finding identity uses the new check ID and fixed response-header location;
ApplyVerifiedFindings preserves operator triage. A negative result never resolves
or deletes existing Findings. Structural request Endpoint identities are untouched.

Compose assessment and optional Finding into one model transition. Attempt at
most one expected-revision model Save, then at most one conditional original-basis
workspace CAS to retain newly created Finding object references. Publish no new
evidence, job or execution receipt. Skip unchanged reference retention. These
stores are not an atomic transaction: retain separate acknowledged, observed or
uncertain outcomes, preserve a committed model after later failure, and never
blindly retry, rebase, fabricate an ACK or claim rollback. Read-only relocated
replay rechecks original bytes and the retained interpretation without Save or
current execution authority.

## Acceptance and ownership

Keep the existing independent three-wire catalog byte-identical. Its actual
header facts require native detections missing/fixed/body-decoy = 1/0/1; ignore its
ZAP alert expectations. Independent acceptance must exercise genuine previously
accepted capture receipts, this offline application, durable Finding/report
consumption, triage, exact replay and relocated source verification. Static wire
examples alone are not genuine receipt or scanner acceptance.

Require zero new target/process/helper calls and refusal of failed/incomplete,
foreign, unattached or corrupted receipt/parts, owner-reader drift, absent opt-in,
scope/policy denial or expiry, replaced source association, revision conflicts,
Save refusal/lost ACK and partial reference retention. Independent review owns
the predicate/oracle and failure acceptance; coordinator owns any later SDK/CLI
enrollment and task metadata. Only new first-party analysis/workflow paths are
proposed. Existing receipts, catalogs, replayers, policy/scope/model cores and
external-runtime profiles remain unchanged. No implementation or runtime
verification is performed by this source contract.
