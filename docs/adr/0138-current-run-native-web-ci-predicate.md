# ADR 0138: Current-run 1337Scope web CI predicate

## Status

Accepted design — 2026-11-03, partial implementation of #75.
Reachable-risk and wider native profiles remain separate.

## Decision

Add the Experimental `ci scan --profile native-web` selection using existing
Git HEAD and Prometheus checks. It reuses ordinary native planning/execution,
current scope and consent, explicit STANDARD policy and a separately supplied
exact plan digest plus confirmation reference. It introduces no blanket approval
switch, implicit scan grant, discovery or new target admission.

Evaluate the existing explicit severity/status/maximum-count criterion only
against detections from this successful current native job. Verify the original
stdout/stderr manifests, invocation, provider, execution, exact selected owner and
request/job deadlines, scope and exact saved
model/source/detection observations before selecting the retained Findings.
Re-normalize the original worker report through its existing owner and preserve
manual Finding triage. Same-reference contradictory current observations cannot
be collapsed into a set and silently accepted.

The distinct `native-web:<sha256>` result identity binds the exact original
job/invocation/report evidence. Recheck current authority and saved snapshot
identity before producing the ordinary JSON/SARIF/JUnit reports. Original body
bytes are not retained by these native checks: worker-report verification is
not a claim to replay a body predicate from unavailable bytes.

An earlier retained positive is still a report fact but cannot enter the
current-run predicate when absent from the current native detection. Zero
matches satisfies only the explicit acknowledged criterion. It establishes no
global clean state, scan completeness, contextual risk or reachability verdict.

## Compatibility and verification

Existing artifact-backed profiles retain their required inputs, errors,
evidence/triage semantics, report no-clobber and deterministic exit outcomes.
Native-web rejects irrelevant executable/artifact consent options. Conditional
parser requirements must retain the existing invalid-profile outcomes.

Use genuine owned-loopback installed SDK/CLI cases, prior-Finding exclusion,
manual-triage preservation, exact positive/negative current observations,
corrupt/swapped/stale original evidence, authority denial before contact and
report/cleanup failures. Focused regressions cover previous profiles; exact-head
shared CI and independent source review remain mandatory before integration.
