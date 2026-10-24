# Offline original-response header SDK

Experimental `ApplyOwnedResponseHeaderCheck` synchronously interprets one existing
acknowledged original-response receipt. It requires an explicit workspace/scope,
receipt manifest ID, exact original URL Target, selected owner, current typed
PASSIVE policy reader, separate opt-in, analysis reference and original expected
model/workspace revisions. A trusted optional actor reader is independent of the
scope consent attester; default selected attribution does not authenticate anyone.

The workflow verifies all seven retained original roles and the durable original
job/Endpoint/source association before its pure field-absence predicate. It
performs no capture, process launch, network access or Evidence.Put. The fixed
local admission window cannot renew; current authority is read after callback-time
fencing and repeated before original-basis saves. Trusted-reader ordering is
bounded local admission, not an atomic authority transaction.

`OwnedResponseHeaderCheckSummary` exposes `state`, original receipt/analysis/target,
nullable condition/assessment/Finding references, independent `model_commit` and
`workspace_commit` statuses, actual reopened revisions and a closed `failure`.
`ToDict()` preserves partial and lost-acknowledgement outcomes without retry or
rollback. A positive is a LOW missing-field Finding; presence creates no new
Finding and does not resolve an older one.

`ReplayOwnedResponseHeaderCheck(workspace_root, original_assessment_reference)`
returns `OwnedResponseHeaderReplaySummary` after verifying the retained Observation,
original headers and optional retained Finding. It needs no current permission,
listener or runtime and performs no Save. It verifies historical time consistency
without renewing a window or inventing a missing original acknowledgement.
See the [operator guide](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/NATIVE_RESPONSE_HEADER_CHECK.md)
for actual SDK inputs, source prerequisites, partial state and acceptance limits.

::: fuzzy1337.native_response_header_workflow
