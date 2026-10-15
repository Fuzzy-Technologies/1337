# Owned plaintext reverse-proxy regression

The `owned-plaintext-proxy.v1` first-party test pack advances #97 by exercising
the actual existing Quick Scan through a finite server-side intermediary. It adds
no scanner flag, proxy configuration, runtime capability, authentication, transport,
Finding rule or reachability inference. NativeHTTP and all existing scope/policy,
job/executor, evidence and model contracts stay unchanged. No third-party proxy,
ModSecurity/OWASP CRS, WAF fingerprint, HTTPS/TLS or bypass claim is made.

## Independent target and source oracle

[`oracle.v1.json`](../labs/targets/proxy-regression/oracle.v1.json) is handwritten
before product interpretation. It records the exact first-party profile,
frontend/backend versions, plaintext/literal-loopback configuration, fixed backend
route and expected status/request/job/model facts. The standard-library helper
owns two different ephemeral `127.0.0.1` listeners. Backend hits are counted at the
backend handler, independently of the scanner's status, summary or saved model.
No real credentials are used. Known synthetic header, reason, cookie and body
markers test the existing discard-only privacy contract.

| Case        | Frontend status     | Independently observed backend hits               | Product outcome                                                 |
| ----------- | ------------------- | ------------------------------------------------- | --------------------------------------------------------------- |
| Transparent | 200                 | One fixed `/owned-resource` request returning 200 | Completed endpoint observation                                  |
| Deny        | 403                 | None                                              | Completed endpoint observation, no Finding or BLOCKED inference |
| Redirect    | 302                 | None, including no redirected request             | Completed frontend observation; Location is not followed        |
| Rewrite     | 429                 | One fixed request actually returning 200          | Record frontend 429 without inventing a backend fact            |
| Stall       | No complete headers | None                                              | Failed timeout with original fixed-code acquisition             |

The frontend never interprets a request as an upstream URL or forwards an arbitrary
path. Only the transparent/rewrite routes issue the one fixed backend GET. Its
destination is the listener created by this test. The redirect points to the
separately counted backend listener so accidental redirect following is observable.
The stalled handler is released during teardown, with a finite fallback wait.
Unknown fixture routes do not create a new forwarding target.

Fixture-only direct requests independently verify the four finite response/hit
cases alongside actual installed product runs. Those requests establish
test ground truth; they are not product acquisitions or authorization records.
Test-only backend counters never become Core observations or execution grants.

## Actual product boundaries

Create the workspace and explicit scope through ordinary `1337 workspace create`
and `1337 scope create`. Only the caller-selected frontend URLs and literal IP are
registered/allowed, with explicit owner, consent reference and validity interval.
`1337 scan quick` requires ordinary `--approve-safe-http`, exact `--target` values
and existing finite request/overall/interval limits. No proxy-specific flag or
ambient proxy setting is involved. Ordinary unknown-consent, exclusion and missing
SAFE-permission cases must contact neither frontend nor backend.

The installed console uses the unchanged chain:

```text
QuickScan → NativeDiscoveryProvider → PolicyEngine/GovernedLocalExecutor
         → packaged NativeHTTP worker → original safe stdout evidence
         → canonical model Save → workspace references → verified reopen
```

Each successful response produces only the frontend's existing Host, Port, Service
and Endpoint identities and attributable status observation. Preserve the strict
schema-one native HTTP record, original `native.http` source/version/execution
manifest, job state/event cursor, full model revision and workspace evidence pins.
No response header/reason/body/cookie marker may enter stdout, original acquisition
bytes, saved model, workspace metadata or events. The endpoint remains observed
when its status is 403, 302 or 429. That does not confirm a vulnerability, backend
access or BLOCKED technical reachability, and creates no `RELATED_TO` transition.

A timeout retains the actual safe failure record and failed job, with no fabricated
successful endpoint. In a two-frontend sequence, an earlier actually persisted
response survives a later timeout; both original acquisitions remain independently
verifiable. Reopening the workspace verifies saved model/evidence without contacting
either listener. Error/redirect status is never a reason to widen registered scope,
request another URL, retry or assert global completeness.

Each installed-console case writes a uniquely named, no-clobber test evidence
packet under the existing ignored `functional-evidence/proxy-regression/` directory,
retained by the existing CI evidence upload. It records the exact oracle and
helper/production source SHA-256 digests, first-party frontend/backend versions
and full configuration, Python runtime version, original product
summary/manifests/safe records and explicitly labelled test-only hit observations.
Packets are retained before oracle comparisons, including a test that deliberately
fails a comparison and verifies the preserved actual result. There are no
fabricated WAF versions, fingerprints or scanner findings.

## Focused execution and lifecycle

```bash
uv run --locked --extra dev python -m pytest -n 2 --no-cov -q \
  tests/contract/test_proxy_regression_contract.py \
  tests/integration/test_proxy_regression_workflow.py \
  tests/e2e/test_proxy_regression_cli.py
```

Every case owns separate ephemeral ports, local workspace, server/handler threads
and product subprocesses. Listeners are shut down and closed, waiting handlers
are released and all owning threads are joined even on failure. The existing
governed executor owns worker termination/reaping. This pack shares no Compose
lifecycle, fixed port or mutable target and can run with the independent xdist
pool; no shared-resource `serial` marker is required. Nothing targets the Internet,
LAN services or a pre-existing proxy. No Docker/provider download is needed.

This is ordinary regression coverage under existing ADRs
[0036](adr/0036-bounded-native-http-discovery.md) and
[0037](adr/0037-bounded-quick-scan-cli.md), not a new runtime architecture.
Task #97 stays open for TLS/redirect variants beyond the existing no-follow
boundary, reviewed version-pinned CRS/ModSecurity and broader transport/control
interpretation. Scope expansion, scanner proxy transport, real WAF identification,
attack-path source support and TLS trust changes need separate accepted contracts.

See [Native discovery](NATIVE_DISCOVERY.md), [Quick Scan](QUICK_SCAN.md),
[functional testing](FUNCTIONAL_TESTING.md) and the existing
[wire contract](../contracts/native-http-record.schema.json).
