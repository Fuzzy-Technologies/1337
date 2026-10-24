# ADR 0095: Owned response capture and optional offline ZAP analysis

## Status

Proposed contract — 2026-10-23. The integration coordinator accepts the finite
design intent below for independent review under M4 #59/#53. This document does
not enroll a provider, authorize a Java launch, or establish genuine acceptance.
Runtime isolation, bounded file custody and the complete supported runtime pins
remain explicit prerequisite decisions. Existing execution defaults stay intact.

## Product boundary

1337 owns current scope/impact authority, one explicit HTTP acquisition, evidence,
jobs, canonical Endpoint/Finding identities, triage, model CAS and reporting.
An optional operator-provisioned ZAP analyses one derived HAR entry offline.
The initial profile enables only released passive rule 10021, the missing
`X-Content-Type-Options: nosniff` hardening condition. It establishes neither an
exploitable browser vulnerability nor general web-security coverage.

The complete live workflow is SAFE: its first-party GET contacts a target even
though the subsequent ZAP rule is passive. Planning contacts no target. Execution
requires explicit workflow approval and two distinct current capabilities:
`native.loopback-response` / `http.synthetic-response-capture` for acquisition and
`zap` / `http.synthetic-response-passive` for offline analysis. Neither permission
substitutes for the other or broadens an accepted page-capture permission. Bind
each exact invocation to the canonical source URL and its actual literal IP,
matching current owner/consent and exclusive expiry. The analysis binding also
includes original capture references, exact derived HAR/plan and runtime facts.
Refresh source scope, independent consent attestation, executing owner and policy
at each launch/READY boundary and Save. Reuse the canonical PolicyEngine and
job/evidence/model owners; do not create a provider-owned authority store.

The initial target is an explicitly selected anonymous HTTP/1.1 URL at
`127.0.0.1` or `::1`, without DNS, query, credentials, redirects or session reuse.
There is exactly one GET, no retry and no provider-originated target request.
Only reviewed repository-owned non-secret response fixtures are supported.

## Acquisition prerequisite

The accepted `page_capture_worker.ParseHeaders` deliberately discards unknown
header values and the status reason. Its record retains measured metadata and a
closed body, not the original header section. Native HTTP discovery likewise
does not retain a complete response. Neither record can prove the presence or
absence of `X-Content-Type-Options`, or be presented as original HAR header
custody. Do not infer an absent header from absent retained metadata.

Add a distinct explicit response-retention profile under the existing governed
acquisition/evidence owners. Preserve the accepted page/discovery schemas,
non-retention promises, defaults and receipt identities. Do not widen their
existing body catalog or silently retain additional material.

The independently handwritten static response catalog is
[`zap-passive.oracle.v1.json`](../../tests/contract/fixtures/zap-passive.oracle.v1.json),
SHA-256 `fb57a1e31904e9904ef5501a6dc7721c9263e12ab55672405c5a70fb2c3798d7`.
It freezes three original response/header/body byte sequences and expected
selected-rule counts 1/0/1, with identical missing/fixed bodies. Byte changes
require renewed independent review; this is an oracle, not actual ZAP evidence.

Before implementation, independently review a fixed non-secret response catalog
and exact header grammar for `/zap-passive/missing`, `/zap-passive/fixed` and
`/zap-passive/body-decoy`. The initial status line is exactly `HTTP/1.1 200 OK`;
the catalog freezes header order/spacing, explicit UTF-8 HTML, one canonical
Content-Length, Connection close and the optional exact nosniff header. Other
header values, unknown headers, cookies/auth material, folded
or duplicate headers, transfer/content encoding, redirects, partial body and
trailing bytes refuse admission. Raw byte retention is permitted only for the
explicitly reviewed non-secret request/response grammar and body catalog.

Acquire complete original request/header/body bytes with one shared monotonic
request deadline and fixed byte limits. Publish response originals only after
complete closed-profile admission. On failure retain safe selected request facts
and a typed refusal, without rejected headers/body or diagnostic echoes. Bind
source URL/IP, actual original
evidence IDs, body/header facts and the worker execution receipt. A derived
single-entry HAR references those originals and preserves header names/values
from them; it is a transformation, not byte-identical original traffic.

The separate versioned retention record, evidence roles and pure historical
replayer still require exact schema review before source implementation. A raw
base64 field added to an old record is not an accepted retention contract.
That review must also freeze the actual request wire bytes, including the Host
grammar for IPv4 and bracketed IPv6, explicit selected-port substitution and a
prohibition on automatic headers. The catalog's descriptive request fields alone
do not establish those original bytes or authorize a general HTTP client.

Candidate admission ceilings are 16 KiB headers, 64 KiB body and 128 KiB derived
HAR. These are proposed limits, not measured engine guarantees. The existing
closed-acquisition limits do not automatically authorize this new profile.

## Fixed optional analysis

Generate one closed Automation Framework plan; accept no caller YAML, scripts,
arbitrary flags, URL lists, environment interpolation or add-on installation.
The intended plan has exactly these jobs:

1. Passive configuration disables all rules, then enables only 10021 at Medium
   threshold, scans only the exact in-scope URL and applies finite body/alert caps.
2. HAR import uses `sendRequests: false` and `maxMessages: 1`. Independently
   validate exactly one entry before launch rather than relying on this setting.
3. Passive queue wait has a finite nonzero duration and verified completion.
4. Traditional JSON report writes one fixed private file without display.

Use an escaped, anchored exact URL include expression. Context descendants and
the report's substring site filter are not scope authority. Independently reject
foreign URLs/methods, additional rules and incomplete queue/report state.
Zero alerts alone proves nothing: the fixed case requires actual one-message
import, enabled rule 10021 and completed processing without warnings or timeout.
Passive queue-wait durations are minutes; a ceiling does not prove completion.

Official import documentation says request replay follows redirects and makes
the message limit soft. It is excluded. No spider, active scan, fuzzer, OpenAPI
import, browser, remote API, traffic proxying, custom rules or model judgment is
part of this profile. Failure/warning, cancellation or incomplete output remains
unassessed; it must not become a successful zero-Finding result.

## Runtime and file-custody prerequisite

ZAP's `-cmd` mode still starts its main proxy. `-silent` and a generated plan do
not establish network isolation, and invalid configuration keys may be ignored.
Before Java launch, require a reviewed supported Linux ownership/isolation
boundary with actual no-egress/private-listener acceptance. Do not claim that
LocalExecutor descendant ownership is a network or filesystem sandbox.

Accepted GovernedLocalExecutor already exposes explicit `own_descendants=True`
and forwards the existing fresh pre-launch validator; the accepted browser path
uses that composition. Reuse it with actual pre-launch and READY authority checks,
cooperative cancellation and awaited cleanup rather than adding a parallel
governed executor. If namespace setup occurs inside a bootstrap worker, its
verified setup requires a separate bounded READY/authority/ACK boundary before
Java; executor READY alone predates it.

Stream limits do not bound ZAP report/session/home files. A post-exit size check
is only an admission bound. A reviewed private work-area owner must bound bytes
and metadata/inodes across every writable Java/ZAP home/session/tmp/report path,
prevent escapes under its stated trust model and prevent later remount or new
namespace creation from bypassing the quota. Preserve originals through cleanup
and verify the final physical report identity. Worker finally blocks cannot
preserve a tmpfs report after an owned tree is killed. A parent-held directory-FD
lease transferred by the fixed bootstrap before Java is a candidate custody
boundary, requiring a separate genuine inert-worker proof; no generic payload FD
API is accepted. Rootless namespace/tmpfs feasibility is under review; plain
namespace creation or an unverified tmpfs mount is not accepted as sufficient.
Unsupported capabilities refuse before Java. There is no host-root/SUID default.

Select absolute trusted Java, core and add-on material explicitly. Provisioning
is separate from scanning. Pin a compatible complete runtime/dependency set and
retain its observed provenance; a launcher checksum does not attest the JRE.
ZAP 2.17.0 is a research candidate. HAR request/message controls were added in
Import/Export 0.22.0 after that core bundle; do not assume stock bundled add-ons
implement current documentation. No candidate pin is accepted until compatibility
and actual execution are proved together.

Whole-workflow budgets include acquisition, material observation, version probe,
setup, engine execution, original-file custody and cleanup. Proposed engine/report
caps require real pinned acceptance before being frozen; unlimited defaults and
renewing a deadline on progress are excluded.

## Canonical custody and persistence

Retain permitted original acquisition, derived HAR, generated plan, runtime
observations, actual streams, complete report and execution/cleanup receipt as
distinct immutable canonical evidence. Bound and authenticate the report's
physical read; establish original custody before later parsing/authority checks
can refuse semantic success. Uncertain publication retains available owned
staging and reports incomplete custody without a fabricated acknowledgement.

Parse only the pinned strict bounded JSON grammar, rejecting duplicates,
nonfinite values and excessive nodes/counts. A report observation must bind exact
original URL/method, rule 10021 and source references. Preserve provider severity
and confidence as attributed source facts; reviewed canonical mapping is Low,
with no exploit-confidence claim. Stable Endpoint/check Finding identity preserves
operator triage and repeated evidence.

Refresh current scope/policy/owner, material, clock and cancellation before one
model CAS and workspace-reference persistence. Preserve original revisions and
truthful already-committed state on lost acknowledgement or later failure.
Historical relocated replay consumes retained originals and requires neither
current ZAP material nor target access nor reconstructed launch authority.

## Required independent acceptance

Independently authored deterministic fixtures must cover a real missing-header
positive, the same response corrected with the actual nosniff header, and a body
text decoy that mentions the header while it remains absent. The decoy stays a
positive for this specific predicate. Original server records prove one approved
GET and zero ZAP target requests. Refusals cover headers/framing/body/catalog,
foreign URL/redirect, scope/policy/owner/expiry, changed material and cancellation.

Required Linux CI uses the genuine pinned Java/ZAP/add-on set inside the accepted
isolation/file owner. Prove rule output, queue completion, report/source custody,
no unintended listener/egress, timeout/cancellation/cleanup, bounded file failures,
canonical Findings/triage and relocated replay after source/runtime removal.
SDK and installed isolated CLI must share these semantics before enrollment.
Missing required prerequisites fail; optional local skips are not acceptance.

Keep deterministic feature checks small and parallel where independent. Run one
shared full gate only for the complete final integration. No live LLM checks,
release, tag or publication is introduced by this design.

## Primary references

- [HAR import automation](https://www.zaproxy.org/docs/desktop/addons/import-export/automation/)
- [Import/Export changelog](https://www.zaproxy.org/docs/addons/exim/changelog/)
- [Rule 10021](https://www.zaproxy.org/docs/alerts/10021/)
- [Passive configuration](https://www.zaproxy.org/docs/desktop/addons/passive-scanner/job-pscanconf/)
- [Passive queue wait](https://www.zaproxy.org/docs/desktop/addons/passive-scanner/job-pscanwait/)
- [Network command line](https://www.zaproxy.org/docs/desktop/addons/network/cmdline/)
- [Automation environment](https://www.zaproxy.org/docs/desktop/addons/automation-framework/environment/)
- [Report automation](https://www.zaproxy.org/docs/desktop/addons/report-generation/automation/)
