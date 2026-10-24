# Native offline owned-response header check

## Proposed boundary

[ADR0098](adr/0098-offline-owned-response-header-check.md) proposes one in-process
interpretation of existing verified originals. Profile
`owned-response-header-absence.v1`, source/provider `native.response-passive`,
capability `http.owned-response-header-check`, check
`native.response-header-xcto-absent`, impact PASSIVE and version `1` are distinct
from acquisition and ZAP identities. This contract authorizes no execution and
implements no provider. No socket, process, worker, helper, external engine or
new source acquisition belongs to the proposed analysis path.

The implemented SDK shape is:

```text
ApplyOwnedResponseHeaderCheck(
    workspace_root: Path, scope_id: str, original_receipt_id: str,
    source_target: Target, owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy], *, analysis_reference: str,
    expected_model_revision: int, expected_workspace_revision: int,
    approve_passive_header_check: bool = False,
    current_owner_provider: Callable[[], str] | None = None,
    clock: Callable[[], datetime] = UtcNow,
) -> OwnedResponseHeaderCheckSummary
```

The exact URL Target is a caller assertion to match against retained originals,
not an override or a new acquisition destination. Require a URL admitted by the
unchanged owned-response profile: anonymous HTTP at literal 127.0.0.1 or ::1,
its selected port and original catalog path, without query or fragment. One exact
`sha256:<64 lowercase hex>` receipt manifest ID is selected; accept no caller
EvidenceRecord wrapper, blob hash alone, raw headers, filename, locator, stage
directory or replacement role IDs. No discovery or adoption of matching files.

## Original source proof

Open the existing workspace/model, require the selected expected revisions and
verify source scope/workspace/URL membership through the authority guard below.
Use `owned_response_workflow.ReplayOwnedResponse` for the durable source/Endpoint,
workspace original-role and original-job association. Use
`owned_response_custody.ReplayOwnedResponseCapture` through
OwnedResponseEvidenceStore for the actual bounded original receipt/result/wire
verification. An equal body/header hash alone cannot establish that association.

Require `captured`, complete original custody, successful original worker exit 0,
all six part/stream records plus the receipt, and the unchanged accepted profile.
The original Endpoint must exist and already be retained by workspace object
references. Its exact URL, workspace and scope must match the explicit selection.
The original receipt and every role ID must already be retained by this workspace.
Do not accept a control-only/refused receipt, reconciliation candidates, guessed
IDs, re-Put copies, unbound SDK records or a hand-built result as a successful
source. A product workflow's later Save failure is not erased: source verification
establishes only its actual complete custody and durable source association,
never an unrecorded original terminal-job or Save acknowledgement.

Read the actual `owned-response-headers` record selected by those original IDs
through its owning store. Recheck its role, media, workspace/provenance, size/hash
and receipt association. The replayer verifies request, body and complete wire
for custody, but body bytes are not detector input. No original record is changed,
republished or upgraded. Preserve all original execution and provenance facts.

## Workflow-local offline admission

PolicyEngine.Plan/Authorize require a real AdapterInvocation and process intent.
There is no existing typed offline execution grant for this operation. Do not
invent an executable/argv or reuse artifact execution to obtain one. The local
guard needs no core policy prerequisite and extends neither PolicyContext nor
any generic executor/core policy. Exact contract review still precedes implementation.

The guard returns a local immutable basis containing current scope/policy
references, revisions and canonical digests, selected workspace/receipt/URL,
fixed executing owner, analysis reference, capability, PASSIVE impact and exact
opt-in. It performs all of these checks before original source interpretation,
again after source verification and immediately before each storage attempt:

- Exact boolean opt-in is true; neither source capture nor replay provides it.
- The fresh policy reader returns the exact typed ImpactPolicy. An explicit
  CapabilityPermission names this provider and capability, with PASSIVE covered
  by both policy and permission ceilings. This operation requires no privileges;
  a capture or ZAP capability never substitutes. Defaults remain deny.
- The current selected scope belongs to this workspace, matches the original
  source scope and grants current consent at an aware time, with exclusive expiry.
  Scope.Check allows the already registered exact URL AND actual original literal
  IP, honoring exclusion/deny precedence. No target or rule is enrolled.
- A supplied trusted synchronous current_owner_provider freshly returns an exact
  string equal to the fixed selected owner. Invalid return/failure/drift refuses.
  With no reader, use selected operator attribution only; it is not external
  authentication or detection of principal changes. The independent consent
  attester is neither replaced by nor required to equal that owner.
- Current source association, expected owner inputs and complete scope/policy
  basis equal the initially selected basis. Even newly permissive drift requires
  a new explicit attempt; do not silently adopt another policy or scope revision.

Compare fixed inputs, actor attribution and scope/policy revisions/digests, not
the fresh decision timestamp. At initial successful admission sample original
aware `issued_at` once. Freeze `policy_deadline = issued_at + timedelta(seconds=
initial_policy.max_authorization_seconds)` and `expires_at = min(policy_deadline,
initial_consent.valid_until)`; absent consent expiry means policy_deadline alone.
Normalize aware times consistently and require issued_at < expires_at.

Both original `issued_at` and `expires_at` belong to the immutable basis/assessment
and fixed-basis equality. Never recompute them from a later policy, consent or
clock reading. Every subsequent source-verification/read, interpretation and
pre-Save boundary checks `issued_at <= fresh_time < expires_at`, current consent
and the unchanged original scope/policy/intent. Fresh times must also be
nondecreasing from every earlier decision time, including within the window;
clock regression refuses. Check before and immediately after a synchronous read
or interpretation phase, before using its result. An unchanged scope/policy does
not extend the window. A late read cannot proceed to interpretation or Save.
No renewal, retry or new admission window exists within the attempt.

`checked_at` remains the final fresh decision time inside the same original
window and is excluded from fixed-basis equality. This is local fail-on-late
admission; it neither interrupts blocking storage nor creates a PolicyGrant.
Expiry after an actual earlier commit preserves its truthful ACK/partial state.
The persisted assessment uses its final pre-model-Save decision time; later
reference-retention checks do not rewrite that already committed assessment.

These are offline admission checks over existing typed owners, not an issued
PolicyGrant or evidence of a new network destination. Historical read-only replay
does not require current granted consent; applying a new interpretation does.
This operation-specific guard introduces no generic authority/execution framework.

## Exact predicate and canonical provenance

After complete source and authority verification, parse only the retained complete
header section: skip its status line/final empty line and compare complete token
field names case-insensitively with `x-content-type-options`. The version-1
predicate is complete field absence, not arbitrary-value validation. Existing
source admission continues to reject unsupported/different headers or wires.
Neither body text, `case_id`, path spelling, catalog selection, recorded expected
result nor ZAP rule count determines the native result.

| Original case | Actual header field | Native condition observed | New Finding |
| ------------- | ------------------- | ------------------------- | ----------- |
| missing       | Absent              | true                      | One         |
| fixed         | Present             | false                     | None        |
| body-decoy    | Absent              | true                      | One         |

Use existing exact-URL Endpoint identity, new native check ID and location key
`<source-url>#response-header:x-content-type-options`. This is a finding-location
description, never a request fragment. A positive is LOW, OPEN, confidence 0.0
(unknown), with a fixed bounded summary of the captured missing field. It asserts
no exploitability, general MIME-sniffing detection or absence of other issues.

Retain one `native.response-header-assessment` Observation on the source Endpoint.
Its closed version-1 attributes are `schema_version`, `profile`, `check_id`,
`analysis_reference`, `original_receipt_id`, `original_job_id`, `source_observation_reference`,
`original_role_ids`, `header_sha256`, `condition_observed` and `authority_basis`.
The basis has exactly `workspace_id`, `model_revision`, `workspace_revision`,
`scope_reference`, `scope_revision`, `scope_sha256`, `policy_reference`,
`policy_revision`, `policy_sha256`, `owner_reference`, `owner_attribution`,
`analysis_reference`, `original_receipt_id`, `source_target_reference`,
`literal_ip_reference`, `capability`, `impact`, `workflow_approved`, `issued_at`,
`expires_at` and `checked_at`.
Owner attribution is `selected` or `trusted-reader`, reflecting whether the
optional reader was actually supplied; neither value claims authentication.
Capability/profile/impact and all selected identity fields retain the fixed values
above; workflow_approved is exactly true. Issued/expiry times are the original
frozen aware admission window; checked_at is the final fresh aware time within it.
Model/workspace revisions here are the original selected CAS bases; post-model
checks compare the actual acknowledged model separately without replacing them.
It records attributed admission facts; hashes authenticate neither a person nor
an unrecorded historical grant. Do not retain raw header/body text or policy
secrets in normalized attributes. The complete attribute object must fit 16 KiB.

ModelProvenance has source_id `native.response-passive`, provider_version `1`,
run_reference equal to the explicit non-secret analysis reference, receiver
interpretation time, original scope and exact source Target reference, all seven
existing source EvidenceReferences and `execution=None`. No stdout, tool version,
invocation digest, AdapterExecution or LocalExecutionResult is manufactured.
The original capture's actual execution remains only with its original provenance.
ApplyVerifiedFindings verifies incoming original bytes before producing a proposal.
Preserve existing Finding triage and unrelated source/model attributes. Presence
never resolves/deletes an earlier Finding or becomes a whole-target clean result.

## One attempt per owner, partial state and replay

Compose assessment and optional Finding back into one Apply transition from the
original model basis. Reopen and reject changed original model/workspace content;
then revalidate fresh authority and call LocalModelStore.Save at most once with
the original expected model revision. Validate its exact returned acknowledgement.
No implicit rebase or retry is permitted.

After confirmed model Save, retain only newly required Finding object references
through at most one LocalWorkspaceStore.Save from the original selected revision.
Preserve every unrelated reference; add no job, raw evidence or manifest ID.
Skip workspace Save if its reference set is unchanged. Before this attempt check
fresh authority and the exact acknowledged model/original workspace basis again.
There are zero Evidence.Put calls, at most one model Save and at most one
conditional workspace Save. These are separate existing owners, not one atomic
transaction. A concurrent writer remains authoritative.

Track each store independently as not-attempted, acknowledged, observed-committed,
observed-unchanged or unconfirmed, following existing PersistenceStatus semantics.
Observed content does not manufacture a lost ACK. A model commit followed by
failed reference retention or later failure remains partial, never success or
rollback. Report only fixed safe failures and actual Finding/assessment references;
no raw source or rejected diagnostics. Never retry a Save within the same attempt.

Reusing an analysis_reference requires exactly one existing native assessment
with the same owner, receipt and fixed check/profile. Verify it and return
already-applied without reattribution or Save; conflicting reuse refuses. Caller
expected revisions must still match current snapshots. New explicit analyses use
new references. Neither reuse nor a negative assessment overrides later triage.
Already-applied additionally requires retained positive Finding object references
in workspace metadata. Missing retention is a prior partial outcome, never an
automatic repair, a second reference-save attempt or a complete replay claim.

Pure `ReplayOwnedResponseHeaderCheck(workspace_root, original_assessment_reference)`
selects the actual retained Observation reference, re-verifies its original source
association/headers and recomputes the fixed predicate. Verify original positive
Finding identity/detection provenance while allowing later valid operator triage.
It performs no Put, Save, new assessment, current grant or target/runtime access,
including after workspace relocation. It cannot certify an absent original ACK.
Missing required Finding retention refuses complete interpretation verification
while preserving the actual observable partial model state.
Historical replay verifies the recorded window/time consistency without issuing
a new window or treating its historical expiry as current application authority.
It does not compare the present wall clock against that historical expiry.

## Bounds, independent acceptance and ownership

One receipt per operation, seven original records, existing 2 MiB receipt and
3 MiB publication ceilings, 16 KiB header section/64 fields, and existing
workspace/model bounds remain unchanged. The new assessment metadata ceiling is
16 KiB; actor/reference values remain bounded non-secret metadata. The fixed local
window refuses late results; it provides no hard I/O preemption, filesystem sandbox,
asynchronous cancellation or blocking-read duration guarantee. Stronger timing
requires its own owner.

Keep `tests/contract/fixtures/zap-passive.oracle.v1.json` byte-identical, SHA-256
`fb57a1e31904e9904ef5501a6dc7721c9263e12ab55672405c5a70fb2c3798d7`.
Its independently authored original header bytes already distinguish all three
cases. No new descriptive fixture, copied body catalog or producer-derived oracle
is needed for this design. Native acceptance ignores its ZAP alert-count fields.

Independent validators must obtain genuine source receipts through the
accepted capture interface, then remove/disable the listener and prove native
application and relocated replay need no target or process. Verify missing/fixed/
body-decoy 1/0/1 from actual persisted Findings and original headers, with unchanged
fixed/missing bodies and body-only decoy text. Exercise explicit opt-in and separate
permission denial, actual supplied-owner-reader drift before analysis/pre-Save,
distinct consent attester, URL/IP exclusion/expiry, foreign/missing/rehashed source
parts, failed/control-only capture, stale revisions, triage, exact reuse, both
stores' conflicts/refusals/lost ACKs and committed-model/failed-reference partial
state. Cover policy-limited and earlier-consent expiry, absent consent expiry,
the exclusive expiry boundary, late synchronous Read and clock regression even
inside the window. Prove no renewed deadline/retry and no post-expiry Save while
scope/policy remain unchanged. Tripwire network/process/helper/new-capture/Put paths.
No static example or parser-only result is genuine receipt/Finding acceptance.

Implemented source ownership is `src/fuzzy1337/native_response_headers.py` for pure
verified-source header interpretation and `src/fuzzy1337/native_response_header_workflow.py`
for the reviewed local authority/persistence composition. Independent validation
owns functional expectations; coordinator owns SDK/CLI enrollment and task mapping.
Policy/scope/model/evidence cores, existing receipt/replay schemas, frozen wires,
external-runtime profiles and other scanner worktrees remain unchanged. The 37
focused SDK cases have passed at their recorded source checkpoints. Six additional
installed CLI/joined-pipeline cases passed in 15.47 seconds with zero failures,
errors or skips on required Linux at `b76805d8` / tree `8ede01a7`; the earlier SDK/crawler
passing cohorts were not repeated. Exact final shared CI and platform acceptance
remain pending. These finite results do not widen the frozen source catalog or
authorize a new capture, automatic assessment or external engine.

## Additive offline CLI enrollment

The `response check-headers` action supplies explicit workspace, `--receipt`,
`--target`, `--scope`, `--owner`, `--policy`, `--analysis-reference` and separate
`--approve-passive-header-check` to the existing SDK. Default missing opt-in refuses.
It selects one fresh original model/workspace revision pair, without a caller
revision override, CAS retry or rebase. Current policy is reread by the SDK callback;
CLI owner selection is attribution only, independent of the consent attester.

The `response replay-headers` action accepts only workspace and `--assessment`.
It requires no current target/authority or runtime. Both use the same foreground
shell dispatcher and optional global `--json`; neither provides a plan, events,
capture, job or execution grant. Original capture/replay grammar remains unchanged.
Zero means completed/already-applied check or verified historical replay; 2 is
invalid configuration/grammar, 3 denied admission and 4 failed/partial state or
historical integrity refusal. Preserve the unchanged SDK summary and independent
store ACK facts; a nonzero status never fabricates rollback or missing custody.
See the [operator guide](NATIVE_RESPONSE_HEADER_CHECK.md) for complete examples.
