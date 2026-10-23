# First-party native web checks

The development checkout provides `1337 scan web --check git-head-exposure`.
The first-party Python worker performs the HTTP request and response check;
Nuclei and other external scanners are optional separate workflows. This
Experimental version-1 interface is defined by
[ADR 0086](adr/0086-first-party-native-git-head-check.md).

## Select an owned endpoint

Select one explicit canonical literal-IP HTTP(S) URL and an existing workspace
and scope. Register and allow both that exact URL and its literal IP; keep current
owner-attributed consent. The command does not discover or append `/.git/HEAD`:
the operator selects the complete endpoint. Queries, credentials, fragments,
sessions, DNS resolution, redirects and retries are unsupported. HTTPS uses
ordinary verified trust. Initial development tests use only pytest-owned loopback
targets; no Internet target is required.

The check recognizes a supported complete symbolic Git HEAD response at HTTP 200
with an admitted plain/octet-stream media type. It reports metadata exposure,
with severity LOW, disposition OPEN and unknown confidence. It does not download
a repository or assert source recovery, credential exposure or exploitability.
A fixed denial, HTML documentation example or redirect must not produce a Finding.
No findings means this finite predicate was not observed, not that the target is
secure. HTTP 5xx and incomplete/invalid transport are failed, unassessed work.

## Plan and explicitly confirm

Use `uv run --locked 1337` from the development checkout. The immutable v0.2.1
installation baseline does not contain this new workflow. For an existing owned
workspace/scope, store an explicit existing policy as `native-web-policy.json`:

```json
{
  "policy_id": "owned-native-web",
  "revision": 0,
  "maximum_impact": "STANDARD",
  "permissions": [{
    "capability_id": "web.git-head-check",
    "adapter_id": "native.web-check",
    "maximum_impact": "STANDARD",
    "granted_privileges": []
  }],
  "max_authorization_seconds": 300
}
```

This permission alone does not confirm execution. Inspect the complete plan:

```bash
1337 scan web owned-workspace --check git-head-exposure \
  --scope local --owner operator:demo \
  --target http://127.0.0.1:8000/.git/HEAD \
  --policy native-web-policy.json --plan
```

Planning makes no target request. After reviewing the actual intent, execute the
same selected operation using its printed digest and your approval-record reference:

```bash
1337 scan web owned-workspace --check git-head-exposure \
  --scope local --owner operator:demo \
  --target http://127.0.0.1:8000/.git/HEAD \
  --policy native-web-policy.json \
  --confirm-plan EXACT_INTENT_SHA256 \
  --confirmation-reference approval:actual-record --events-json
1337 workspace open owned-workspace --json
```

The reference is an operator attestation, not authenticated identity or a signature.
Changed URL, invocation/request timeout, owner, scope or policy requires a fresh exact plan.
Authority is checked again at launch and model Save. Existing scope and policy
controls apply even when the selected target or check is known to the project.

`--request-timeout` defaults to three seconds and `--timeout` to ten seconds.
The SDK validates hard upper/lower limits and startup budget. There is one
request, no automatic URL expansion and no arbitrary worker flags. `--json`
emits a terminal summary; `--events-json` emits actual events followed by a summary.
Planning rejects confirmation/event-stream combinations. Exit codes are 0 for
completed assessment, 2 invalid setup, 3 authority denial, 4 failed execution or
evidence/storage integrity, and 130 cancellation. Exit 0 does not assert a clean
target; inspect the saved Findings and operation state.
The whole-job timeout bounds orchestration separately; it is not part of the
network-invocation intent and cannot expand the worker's request deadline.

## Evidence and independent acceptance

Transient response bodies, arbitrary headers and Git reference text are not
retained. Immutable evidence contains the original bounded first-party execution
report and streams, with invocation/version/scope/outcome provenance. The report
retains status, fixed media category, body length/digest and the predicate outcome.
Reopening verifies that original report and durable model/evidence bindings;
it cannot independently re-evaluate an HTTP body that was not retained.

The same canonical model/Finding/report owners serve native and external checks.
Recollection keeps logical Finding identity and operator triage. Earlier evidence
or a published model transition may remain after a later failure; the job and
summary preserve that partial-state truth rather than relabeling the run complete.

Run ordinary owned-target acceptance without installing an external scanner:

```bash
uv run --locked --extra dev pytest --no-cov -q \
  tests/functional/test_native_web_checks.py tests/e2e/test_native_web_cli.py
```

The handwritten Git oracle declares one positive and three negatives. Metrics
come from actual saved native Findings after the first-party worker runs, with
target-side file/read/request observations and offline reopen. Target/transport
failures are unscored. This finite matrix does not establish broader crawler,
browser, SQL injection, XSS or file-traversal coverage.
