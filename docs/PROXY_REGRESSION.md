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

## Owned TLS negotiation failures

The companion [`tls-oracle.v1.json`](../labs/targets/proxy-regression/tls-oracle.v1.json)
defines `owned-tls-negotiation-failures.v1`. It exercises the real installed native
worker's default verifying TLS context against a finite loopback wire fixture.
The fixture receives one bounded ClientHello and either sends the fixed fatal
`handshake_failure` alert or waits until teardown/deadline. It owns no certificate,
completes no TLS handshake and handles no HTTPS application request. No production
TLS context, certificate store, authorization or executor environment is modified.

| Case                   | Independent target observation         | Original product outcome                                   |
| ---------------------- | -------------------------------------- | ---------------------------------------------------------- |
| Fatal handshake alert  | One connection and one ClientHello     | Failed provider job, exit 4, safe worker error `tls`       |
| Stalled ClientHello    | One connection and one ClientHello     | Failed timeout job, exit 4, safe worker error `timeout`    |
| HTTP to HTTPS redirect | HTTP 302, zero TLS/backend connections | Completed HTTP frontend observation, exit 0, no TLS object |

The two failures retain the exact original fixed-code record and source/version/
execution manifest without creating model objects, Findings or inferred BLOCKED
reachability. A successful HTTP acquisition preceding either TLS failure remains
saved alongside both original evidence records. Workspace reopen verifies those
records without another connection. Unknown consent, excluded scope and missing
SAFE permission deny before TCP connection or ClientHello.

Direct fixture checks use an independent ordinary verifying TLS client. Installed
CLI checks exercise the actual policy/executor/worker/evidence chain, with a two-
second request budget and the existing eight-second overall limit. This allows
normal platform trust-store initialization while keeping deliberate stalls bounded.
Evidence packets retain the versioned wire configuration, Python/OpenSSL versions,
source digests, original product summary and acquisitions, and explicitly test-only
connection/ClientHello counts. TLS payloads and exception text are not retained.

The listener uses a single three-second deadline for the complete bounded initial
record, short stop-aware read polling and explicit accepted-socket shutdown.
Exception, partial-header and startup-failure tests verify listener/thread cleanup;
unexpected wire/listener failures become fixed fixture-error observations.
These independent fixtures need no installed OpenSSL executable, certificate files,
new dependencies, external host, shared port or retry and use the same focused
pytest selection above.

This profile proves negotiation failure handling and redirect containment only.
It does not establish successful trusted HTTPS, certificate-chain or literal-IP
identity validation, WAF behavior, or a TLS compatibility matrix. Those acceptance
boundaries and the remaining version-pinned CRS/ModSecurity work stay open in #97.

## Owned untrusted certificate rejection

The separate [`tls-certificate-oracle.v1.json`](../labs/targets/proxy-regression/tls-certificate-oracle.v1.json)
defines `owned-tls-untrusted-certificate.v1`. The same finite listener offers an
actual self-signed RSA-2048 certificate with an IP SAN matching `127.0.0.1` and a
pinned validity interval. Its committed key is deliberately public, non-secret
synthetic test material; generation and rotation provenance are documented in the
[fixture README](../labs/targets/proxy-regression/README.md).

An independent default-verifying client must reject this certificate with
`SSLCertVerificationError` code `18`. The owned server separately records one
handshake attempt, one certificate-rejection alert and zero completed handshakes.
It has no HTTPS application handler. The installed Quick Scan must fail with exit
`4`, provider failure and the original safe `tls` acquisition, without successful
endpoint objects or Findings. No trust store, production TLS context, executor
environment or authorization rule changes.

The existing focused test command covers this profile too. Unknown consent,
excluded scope and missing SAFE permission deny before any connection. An earlier
successful HTTP result survives later certificate rejection with both original
acquisitions retained; verified workspace reopen remains offline. Evidence
packets pin the certificate/key bytes, oracle, source and Python/OpenSSL versions.
Invalid certificate configuration fails before listener allocation, and partial
handshake and startup-failure cases verify complete socket/thread cleanup.

This establishes rejection of the particular untrusted certificate. Successful
trusted HTTPS, hostname-specific and expiry-specific rejection, revocation and
broader TLS interoperability remain separate acceptance work under #97.
