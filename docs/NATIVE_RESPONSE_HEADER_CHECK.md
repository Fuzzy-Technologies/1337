# Native offline original-header assessment

The development SDK exposes synchronous `ApplyOwnedResponseHeaderCheck` and
read-only `ReplayOwnedResponseHeaderCheck`. Profile
`owned-response-header-absence.v1` interprets an existing original response; it
starts no capture, worker, helper, external engine or network request. The
`response check-headers` and `response replay-headers` commands expose these same
owners through the CLI and foreground shell. All 37 independent owned-original
cases have passed across focused runs, including saved missing/fixed/body-decoy
Findings, denial, partial persistence, triage and relocated offline replay.
Six new independent installed CLI/joined-pipeline cases also passed in 15.47 seconds
on the required Linux lane at source tree `8ede01a7`, with no failures/errors/skips.
Exact final shared integration and platform verification remain required.
See the [contract](NATIVE_RESPONSE_HEADER_CHECK_CONTRACT.md) and
[ADR0098](adr/0098-offline-owned-response-header-check.md).

## Select an acknowledged original

First obtain a successful original through the existing
[owned-response capture](OWNED_RESPONSE_CAPTURE.md). That live acquisition has its
own Linux runtime prerequisite, exact reviewed loopback response profile, current
scope/consent and separate SAFE permission/approval. Its permission does not
authorize this later PASSIVE interpretation. The offline interpretation itself
requires no Linux process or active listener.

Select the actual `original_receipt_id` returned by capture, an existing source
scope and the exact original URL Target. The initial source profile is anonymous
HTTP at literal loopback, port 1024..65535 and one of `/zap-passive/missing`,
`/zap-passive/fixed` or `/zap-passive/body-decoy`.
The original Endpoint, source Observation, original job and every original role
must already be associated with this workspace. The seven roles are `stdout`,
`stderr`, `owned-response-request`, `owned-response-headers`,
`owned-response-body`, `owned-response-wire` and `owned-response-receipt`.

Both original replay owners reverify actual bounded source bytes and associations.
The worker must have succeeded with exit 0 and complete captured custody.
Control-only/refused receipts, reconciliation candidates, guessed manifest IDs,
re-Put copies and supplied raw headers are not accepted sources. Digest-only crawl
reports do not provide the required original header/wire custody. Source
verification cannot invent a missing original job or Save acknowledgement.

## Explicit PASSIVE SDK admission

Use the development package; the tag-pinned v0.2.1 baseline does not include this
SDK. Supply a trusted synchronous current policy reader with explicit permission
for `native.response-passive` / `http.owned-response-header-check`. The example
below uses a fixed explicit typed configuration; replace the reader with your
current operator-policy source when permission can change.

```python
from pathlib import Path

from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_response_header_workflow import ApplyOwnedResponseHeaderCheck
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scope import Target, TargetKind
from fuzzy1337.workspace import LocalWorkspaceStore


def CurrentHeaderPolicy() -> ImpactPolicy:
    """Return this caller's explicit current native-header permission."""

    return ImpactPolicy("owned-header-check", maximum_impact=ImpactLevel.PASSIVE,
        permissions=(CapabilityPermission("http.owned-response-header-check",
            "native.response-passive", ImpactLevel.PASSIVE),),
        max_authorization_seconds=30)


def AssessOriginal(root: Path, scope_id: str, receipt_id: str,
                   original_url: str, analysis_reference: str):
    """Call only after selecting actual acknowledged originals and explicit analysis approval."""

    workspace = LocalWorkspaceStore(root).Open()
    model = LocalModelStore(root).Open()

    return ApplyOwnedResponseHeaderCheck(root, scope_id, receipt_id,
        Target(TargetKind.URL, original_url), "operator:local-lab", CurrentHeaderPolicy,
        analysis_reference=analysis_reference, expected_model_revision=model.revision,
        expected_workspace_revision=workspace.revision, approve_passive_header_check=True)
```

Choose an actual non-secret analysis reference distinct from the original job.
The source URL and actual literal IP must remain registered and allowed by the
original source scope, with current consent and exclusion/deny precedence. No
scope entry is created. Explicit `approve_passive_header_check=True` and the
separate permission are both required; an original capture or replay supplies neither.

The selected owner is operator attribution, independent of the consent attester.
An optional trusted `current_owner_provider: Callable[[], str]` is reread and must
return that original owner exactly. Without it, external principal changes cannot
be detected. Scope/policy revisions, digests and selected intent must remain equal
to the original admission basis even if a later policy is more permissive.

The local window freezes initial aware `issued_at` and the earlier of initial
policy TTL or consent expiry. Every later decision stays within that same exclusive
expiry and nondecreasing clock sequence. Late source reads, interpretation or
post-Save returns retain their truthful refusal/partial outcome; no renewed window
or hard blocking-I/O interruption is promised. Current authority is refreshed
after callback-time fencing before Save. This is bounded ordered admission,
not atomic protection against arbitrary mutually mutating trusted readers.

## CLI and foreground shell

Use the exact typed policy serialization for the separate native permission.
For example, an explicitly selected `header-policy.json` contains all fields:

```json
{
  "policy_id": "owned-header-check",
  "revision": 0,
  "maximum_impact": "PASSIVE",
  "permissions": [{
    "capability_id": "http.owned-response-header-check",
    "adapter_id": "native.response-passive",
    "maximum_impact": "PASSIVE",
    "granted_privileges": []
  }],
  "max_authorization_seconds": 30
}
```

Select an actual retained receipt, its exact source URL/scope and a new independent
analysis reference. Replace the receipt placeholder with the complete actual ID:

```bash
1337 response check-headers workspace --receipt sha256:ORIGINAL_RECEIPT_DIGEST \
  --target http://127.0.0.1:19008/zap-passive/missing --scope original-source-scope \
  --owner operator:local-lab --policy header-policy.json \
  --analysis-reference analysis:headers-001 --approve-passive-header-check --json
```

Missing PASSIVE opt-in refuses with exit 3. The CLI rereads the selected policy
at SDK admission boundaries and passes one freshly opened model/workspace revision
pair into the original-basis SDK attempt. It never retries a conflict or overrides
revisions. `--owner` remains selected operator attribution; the CLI supplies no
trusted current-principal reader or authentication claim. Source consent is still
required independently. No grant, new capture, job or event stream is created;
there is no `--plan`, runtime override or caller-header option for this action.

Completed or already-applied interpretation returns 0, denied admission 3, and
failed/partial interpretation 4. Invalid configuration or grammar returns 2.
JSON preserves the owning SDK summary, original references and separate commit
statuses. A nonzero result may follow an actual model commit; it is not a rollback.

Replay takes only the relocated workspace and actual retained assessment reference:

```bash
1337 response replay-headers relocated-workspace \
  --assessment observation:ACTUAL_ASSESSMENT_REFERENCE --json
```

Verified historical replay returns 0; unknown source/assessment integrity returns 4.
Current scope, owner, policy, target and approval inputs are rejected. Both commands
use the same grammar inside the foreground shell. Original `response capture` and
`response replay` keep their separate acquisition/custody contracts. Focused
installed CLI/pipeline acceptance passed six cases in 15.47 seconds; this is not
final shared integration or platform acceptance.

## Predicate, provenance and persistence

The pure predicate reads only complete verified original header field names,
case-insensitively. Missing `X-Content-Type-Options` creates one LOW, OPEN Finding
with confidence 0.0 (unknown), plus a
`native.response-header-assessment` Observation. Presence creates an assessment
with no new Finding. It does not resolve/delete an earlier Finding or certify
the target clean. Body text, path labels, `case_id` and ZAP counts never determine
the predicate. Value correctness and general MIME-sniffing detection are outside
this field-absence check.

New interpretation provenance uses the explicit analysis reference, original
scope/Target and all seven existing source references, with `execution=None`.
The original capture's execution stays unchanged with its own provenance. No
new job, raw evidence, stdout, tool version or executor outcome is manufactured.
Existing triage and unrelated model/reference state are preserved.

Each attempt uses the selected original model/workspace revisions. It performs
at most one model CAS and, only when a new Finding reference needs retention,
at most one workspace Save. A complete negative or an already-retained Finding
can legitimately need no workspace Save. Concurrent changes refuse without
rebase, repair or retry. These owners do not form one atomic transaction.

Inspect `state`, `model_commit`, `workspace_commit`, actual reopened revisions,
`condition_observed`, `assessment_reference`, `finding_reference` and `failure`.
Commit status distinguishes `not-attempted`, `acknowledged`, `observed-committed`,
`observed-unchanged` and `unconfirmed`. A committed model followed by failed or
late reference retention remains `partial`. Observed content does not create an
ACK, and denied/unverified source work is not a clean result. Malformed initial
configuration can raise `NativeResponseHeaderError` before an attempt exists.

Exact `analysis_reference` reuse verifies the existing owner/receipt/check
association and returns `already-applied` without another Save. Conflicting reuse
refuses. Missing required Finding retention remains prior partial state rather
than automatic repair; a new explicit analysis uses a new reference.

## Historical replay and verification status

Use the actual retained Observation reference, not the original receipt alone:

```python
from fuzzy1337.native_response_header_workflow import ReplayOwnedResponseHeaderCheck

# Values come from an actually retained assessment and its relocated workspace.
verified = ReplayOwnedResponseHeaderCheck(relocated_workspace, assessment_reference)
```

Replay rechecks original associations/headers and recomputes the fixed predicate,
including required positive Finding retention while allowing later valid triage.
Keep the canonical workspace and original evidence together when relocating.
Replay requires no current consent/policy, listener, capture runtime or Save.
It verifies recorded window consistency without treating historical expiry as
new application authority, and cannot certify a missing original ACK.

[Ordinary pytest verification](FUNCTIONAL_TESTING.md) separates pure/mock checks
from genuine receipt/Finding acceptance in
[the independent functional cases](../tests/functional/test_native_response_header_check.py).
Focused execution has verified actual original acquisition, offline missing/fixed/
body-decoy interpretation, current denial, TTL/CAS/ACK boundaries, preserved triage
and relocated replay. Results apply to the recorded focused source checkpoints;
all required cases must still pass on the exact final shared-CI revision before
merge. Unsupported acquisition platforms are explicitly unassessed rather than
positive runtime acceptance.

The [six new CLI/pipeline cases](../tests/functional/test_native_header_cli_pipeline.py)
are separate from those 37 SDK cases and the earlier 31 crawler cases; no passing
cohort was repeated for this checkpoint. Their terminal JUnit records six PASS,
zero failures/errors/skips and 15.47 seconds at `b76805d8` / tree `8ede01a7`.
The joined case used four crawl GETs and three separately approved capture GETs,
then offline header checks scored TP2/TN1/FP0/FN0 over the three original header
cases. Both denial cases made zero store reads/Saves/contacts; replay/reuse/report
made zero Saves. Distinct source identities and triage survived removed-root
relocation. These finite facts establish neither general target coverage nor
automatic workflow authority. The separately proposed content-response retention
contract remains unimplemented and is not part of this candidate.
