# Native HTTP discovery

The Experimental version-1 native producer supplies a bounded SAFE sensor to
Quick Scan. It uses the packaged Python worker and needs no external scanner.
It observes explicitly supplied literal-IP HTTP(S) endpoints and updates the
existing durable Security Object Model. Preparing a producer grants no authority.

## Prerequisites and approved input

The consumer must create/open the workspace and its model, register and explicitly
allow both each exact URL and its literal IP in a current consented scope, and
supply an `ImpactPolicy` permission for `native.http` / `http.endpoint-discovery`.
Missing, expired, excluded, revoked or changed scope denies execution. Consent,
authorization and policy limits are shared by human, agent and CI consumers.

Only a finite tuple of exact HTTP(S) URLs with unicast literal IP hosts is accepted.
Broadcast, IPv6 zones and IPv4-mapped IPv6 aliases are unsupported.
Hostnames, queries, credentials, fragments and implicit target expansion are
rejected. One GET observes each supplied endpoint. Redirects are recorded by status
without following them. HTTPS requires a valid ordinary certificate for the literal
IP; there is no certificate-verification bypass. Authenticated sessions, DNS,
crawling, arbitrary port scanning and vulnerability detection are separate work.

## Producer API

`NativeDiscoveryProvider(workspace_root, targets, scope_id, policy, *, limits, clock,
context_validator)`
implements `JobProvider.Run(context)`. The caller binds a `ScanJob` whose provider ID
is `NATIVE_HTTP_PROVIDER_ID`, scope reference matches `scope:<scope_id>` and workspace
identity matches the persisted workspace. The job's evidence store must use the
same workspace's `evidence` partition. The injected authority clock must be aware;
the default uses UTC. The provider validates current scope immediately before each
governed worker launch and stops after the first failed endpoint.

`context_validator` is an optional trusted synchronous consumer guard. It receives
the current immutable `PolicyContext` before grant issuance and again immediately
before governed launch, and must return None or raise to deny. Non-None/awaitable
returns fail closed; bare coroutines are closed. The guard cannot replace the
ordinary scope/impact/invocation `PolicyEngine` checks. Consumers may impose their
own expected consent-actor binding without making the generic SDK equate an
attester with the executing job owner or claim identity-provider authentication.

`DiscoveryLimits` defaults to eight endpoints, three seconds per request, 0.2 seconds
between requests and thirty seconds total. Hard maxima are sixteen endpoints, ten
seconds per request and sixty seconds total. The minimum interval is 0.05 seconds.
The native record output is at most 4096 bytes, the endpoint input at most 2048 UTF-8
bytes and transient HTTP-header parsing at most 16384 bytes. The consumer also
supplies the existing job event budget. Requests execute sequentially.

`limits.FirstUpdateBudgetSeconds` gives the nominal per-request timeout plus one
second of worker startup, capped by the total timeout. Quick Scan should measure
the actual elapsed time to its first observed model delta. Input registration
alone is not an observed network update, and this budget is not a real-time promise
about operating-system scheduling or storage.

## Evidence and model semantics

The versioned wire grammar is `contracts/native-http-record.schema.json`. Successful
output contains only schema version, approved URL, observed peer IP, port, scheme
and integer HTTP status. Failure output contains only a fixed category. No response
headers, reason strings, cookies, credential headers or bodies enter evidence,
model, logs or job events. The parent checks the strict grammar before preserving
the exact raw record; oversized or malformed output is not eligible for persistence.

Verified evidence supports canonical Host, Port, Service and Endpoint objects,
`has-port`, `hosts-service` and `exposes` relations, and attributable observations.
Port/service natural keys are `host:<address>/tcp/<port>` and endpoint keys are exact
canonical URLs. The model is saved before publishing `MODEL_DELTA`; later providers
can bind to those same identities. Repeated acquisition preserves logical identity
and adds observation history. Exact evidence/provenance replay is idempotent.

Denial, normalization, provider failure, storage failure, output overflow and timeout
remain explicit job failures. Cancellation reaps the owned worker before terminal
state. Earlier verified evidence and saved objects survive later failure. A redirect
or HTTP error status is an observed endpoint response, not a vulnerability finding.
The subprocess boundary does not provide an OS network or memory sandbox.

## Reproducible acceptance

Run the focused suites with the locked developer environment:

```bash
uv run --locked --extra dev pytest tests/unit/test_native_http.py tests/unit/test_discovery.py
uv run --locked --extra dev pytest tests/contract/test_native_discovery_contract.py
uv run --locked --extra dev pytest tests/integration/test_native_discovery.py
```

The localhost fixture owns its listener and teardown. It runs the actual installed
worker through policy, executor, job, evidence and model interfaces; proves repeat,
reopen, event ordering, redirect containment, denial, timeout, cancellation and
retained partial state; and never targets the Internet. The full repository gate
and per-module branch-coverage requirement remain mandatory.
