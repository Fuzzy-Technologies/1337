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

## Owned loopback file-canary profile

`1337 scan web --check file-canary-disclosure` adds the Experimental version-1
profile in [ADR 0088](adr/0088-owned-loopback-file-canary-check.md). This closed
development check accepts only literal loopback addresses and the repository's
`/files/vulnerable`, `/files/fixed` and `/files/decoy` paths. Its sole `name` query
has exactly one of these canonical wire values: `hello.txt`,
`..%2Fprivate%2Fcanary.txt` or `..%2Fprivate%2Fmissing.txt`. It does not discover
files, generate candidates or assess arbitrary remote file access.

Register the exact URL using `scope create --allow-canary-url URL`, alongside
`--allow-ip` and the existing explicit owner/consent fields. Use
`--exclude-canary-url URL` for an explicit exclusion. These flags apply the same
closed raw-input validator as planning; generic `--allow-url` and `--exclude-url`
still reject all queries. Registration and loopback membership confer no consent.

Select `web.file-canary-check` instead of `web.git-head-check` in the explicit
STANDARD policy above. Plan and confirm the exact operation through the same CLI:

```bash
1337 scan web owned-workspace --check file-canary-disclosure \
  --scope local --owner operator:demo \
  --target 'http://127.0.0.1:8000/files/vulnerable?name=..%2Fprivate%2Fcanary.txt' \
  --policy native-web-policy.json --plan
```

The SDK's `PlanNativeWebScan` and `RunNativeWebScan` accept the keyword
`check_id="native.file-canary-disclosure"`; omitted selection preserves Git
behavior. The selected check, full URL, anonymous GET request template, query
injection reference and profile bind the exact confirmation intent. Current
authority is rechecked at grant, launch and Save. The new model projection uses
the existing request endpoint identity and preserves other request templates.

A LOW Finding requires HTTP 200, an admitted plain/octet media category and the
complete exact non-secret fixture marker. Bodies stay transient. Original worker
reports retain byte length/digest, predicate and structural references; reopening
cannot reconstruct the discarded body. Actual worker acceptance in
`tests/functional/test_native_file_canary.py` covers one positive and five controls,
denied/mismatched authority, durable reopening and independent file-content
changes that prove detection follows actual bytes rather than route labels.
This finite local acceptance does not establish general file traversal coverage.
