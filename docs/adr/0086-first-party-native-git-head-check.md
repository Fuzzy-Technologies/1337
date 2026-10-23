# ADR 0086: First-party native Git HEAD response check

- Status: Accepted for implementation
- Date: 2026-10-23
- Decision owners: Fuzzy Technologies
- Related work: #59, #53

## Context

The accepted Nuclei workflow establishes external-provider execution and three
reviewed response predicates. Native endpoint discovery deliberately retains only
status observations; closed HTML acquisition admits a finite reviewed body
catalog. Neither contract provides a first-party vulnerability check. Extending
their output implicitly would change existing evidence and authority assumptions.

## Decision

Add Experimental version-1 `fuzzy1337.adapters.native_web`, an Internal
`fuzzy1337.native_web_worker` and the Experimental `fuzzy1337.native_web` workflow.
The initial capability is `web.git-head-check` from provider `native.web-check`.
It executes one explicitly selected, canonical, query-free literal-IP HTTP(S) URL
through the existing governed local executor. No Nuclei binary, template download,
browser, DNS, target expansion, redirect following, retry, credential or session
is needed. HTTPS preserves ordinary certificate verification.

The worker evaluates a bounded Git HEAD response predicate: HTTP 200, an admitted
plain/octet-stream media type and a complete supported symbolic-reference body.
This finite grammar does not claim every Git reference representation or source
code recovery. A match becomes check `native.git-head-exposure`, severity LOW,
status OPEN and unknown confidence, through the existing canonical Finding owner.
No match means only that the selected predicate was not observed at this URL.

STANDARD policy permission and separate exact-plan confirmation are mandatory.
Planning returns the exact invocation and current policy intent without contacting
the target. Current owner consent, exact URL/IP scope and policy are rechecked at
authorization, final governed launch and immediately before canonical model Save.
Policy/grant expiry or drift must deny even when the worker already returned a
positive result. Existing scope, policy, executor and persistence owners retain
their contracts; no second truth store or special authorization shortcut exists.

## Data and failure boundaries

Header/body parsing shares a finite request deadline and fixed byte limits.
Unsupported framing or encoding, truncated/oversized input, HTTP 5xx, TLS,
connection, timeout and cancellation remain failed or unassessed work. They must
not become successful negative results. An admitted 3xx response is observed
without acquiring its destination and cannot satisfy the positive predicate.

HTTP bodies, header values, symbolic-reference text and exception messages stay
transient. The worker emits only a strict bounded versioned execution report:
selected URL/destination, fixed check/profile identity, status, normalized media
category, actual body length/digest and a boolean result, or a fixed failure code.
The existing job retains the original stdout/stderr report with exact invocation,
scope, provider/version, time and execution provenance. Normalization verifies
this original report and its bindings before it can enter the model.

This is replay verification of the original execution report. A retained digest
does not independently prove or reconstruct the absent original HTTP body; no
such claim is made. Genuine worker acceptance against independently authored
owned targets establishes the observed predicate behavior for its finite cases.

Evidence precedes model application. Endpoint/check identities are deterministic;
recollection preserves existing operator triage and appends actual provenance.
The model owner performs one expected-revision Save; workspace references and
evidence are verified before terminal success. Failed or ambiguous Save/event
acknowledgements remain failures and expose actual persisted partial state.

## Product interface

Add `1337 scan web --check git-head-exposure` to the installed CLI and foreground
shell. The operator supplies an existing workspace/scope, owner, exact URL and
serialized existing ImpactPolicy. `--plan` and execution confirmation are
mutually exclusive. Human output, JSON summary and JSON-line events reuse existing
presentation conventions. No release, PyPI publication or implicit installation
of external scanners is part of this change.

## Validation

Preserve the existing independent target/oracle bytes. Run the actual first-party
worker through Plan/Run, policy, executor, evidence, Finding, model/workspace
reopen and report verification. The Git cases are one exposure positive and three
fixed/HTML-decoy/redirect negatives; derive metrics from saved Findings and the
handwritten oracle. Cover complete-body grammar, media/status controls, secret
non-retention, exact single request, denied/expired/drifted authority before
contact or Save, resource limits, malformed output, cancellation and truthful
failure outcomes. CLI and foreground-shell tests exercise the same workflow.

Shared exact-head quality/documentation/provider checks and per-module branch
coverage remain required before integration. #59/#53 stay open for broader native
checks, crawling, browser execution and complete Web Scanner NG acceptance.
