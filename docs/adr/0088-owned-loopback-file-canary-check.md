# ADR 0088: Owned loopback file-canary response check

- Status: Accepted for implementation
- Date: 2026-10-23
- Decision owners: Fuzzy Technologies
- Related work: #59, #53, #58

## Context

The first-party Git HEAD check establishes governed native execution, canonical
Findings and original worker-report custody. The independent `web-file-access`
pack additionally declares six actual file-read cases, one private non-secret
canary disclosure and five controls. Its query input is outside the accepted
query-free Git profile. A separate closed request profile is necessary.

## Decision

Add check `native.file-canary-disclosure`, capability `web.file-canary-check`,
profile version `1` and request profile `owned-loopback-file-canary-query-v1`.
This development capability is limited to the repository-owned loopback pack.
The adapter, worker and workflow all require a literal loopback destination,
one explicitly selected GET and one of the pack's three fixed paths. The sole
query key is `name`; the only concrete values are the three reviewed public,
private-canary and missing-file inputs. Exact canonical wire spelling is
required. Duplicate/extra pairs, alternate escapes, double decoding, credentials,
DNS, redirects, retries and generated candidates are unsupported.

Use the existing native adapter, isolated Python worker and governed workflow.
A finite immutable check registry owns identity, capability, request profile and
response predicate. The existing Git constants, default calls, query refusal,
invocation arguments and report shape remain compatible. Select capabilities by
identity instead of descriptor position. New SDK selection is the keyword
`check_id`; the CLI exposes the corresponding explicit `--check` choice.
Scope registration uses dedicated `--allow-canary-url` and `--exclude-canary-url`
flags with the same closed raw-URL validator. Generic `--allow-url` and
`--exclude-url` retain their existing query refusal.

The new request derives one anonymous #58 GET `RequestTemplate` with one QUERY
`InjectionPoint` named `name` and a structural non-secret `ValueBinding`.
No session or credential is admitted. The exact full URL, selected check,
canonical template, injection reference and request profile belong to the
invocation/confirmation intent. The worker recomputes structural references from
the same exact URL and owning workspace identifier. The bounded original report
must bind those references. A typed `Target` already canonicalizes percent
escapes; original-spelling rejection belongs at the raw CLI/parser boundary.

Current owner consent, explicit full URL and literal IP scope, STANDARD capability
permission and separate exact-plan confirmation remain mandatory. Authority is
reread at grant, actual launch and immediately before model Save. Loopback
membership never grants authority. No alternate executor, evidence or model store
is introduced.

## Result and model boundaries

The predicate requires HTTP 200, an admitted plain/octet media category and the
complete exact non-secret canary bytes. A route name, prior oracle label, response
status alone or body fragment cannot establish a match. A match becomes a LOW
Finding at the exact selected URL. Bodies and arbitrary headers stay transient;
the original report retains fixed metadata, byte length/digest and predicate.
Replay verifies that original report, not an absent response body.

Use the #58 template endpoint's existing model identity for this new profile and
merge its request template with existing templates without dropping operator data.
The Git model projection remains unchanged. Cancellation, malformed/incomplete
transport, 5xx, authority drift and persistence failure remain failed/unassessed
with truthful partial evidence/model state.

## Acceptance

Run the actual packaged worker through Plan/Run, scope/policy, evidence, canonical
Findings and durable reopen. Preserve original handwritten target/oracle bytes.
Score the six independent cases as TP 1 / TN 5 / FP 0 / FN 0; additionally alter
owned file contents to prove the predicate follows actual bytes. Cover remote
literal refusal, denied/mismatched authority before contact, exact query spelling,
reference joins, no body retention, timeout/cancellation and Git compatibility.
All tests use deterministic code and pytest-owned files/listeners. Full CI runs
only at final integration readiness. This finite local acceptance does not claim
general file traversal, remote assessment, browser execution or scanner completion.
