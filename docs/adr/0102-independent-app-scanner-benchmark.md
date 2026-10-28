# ADR 0102: Independent application scanner benchmark

## Status

Accepted architecture — 2026-10-28, Task #40. Runtime acceptance remains unrun.

## Context

The pinned Juice Shop pack in ADR 0021 checks provenance, health, version, root,
and search responses. It does not run a production scanner. Its incomplete
application oracle cannot establish vulnerability detection accuracy. The owner
requires comparisons of the native engine, assembled 1337 product, and external
scanners against real isolated applications using independently known cases.

## Decision

Start with three finite cases from the existing immutable Juice Shop release:
unauthenticated `/metrics` exposition, `/rest/admin/application-version` JSON as
a negative control, and `/` HTML as a negative control. The controls exercise
the same response classification with different real media/body content. They
are not patched versions of `/metrics`, and do not establish absence of other
vulnerabilities. Application-wide oracle completeness remains false.

The independent [case inventory](../../labs/external/benchmark/juice-shop-cases.v1.json)
pins upstream commit and file blob identities before consuming scanner results.
At that commit, `server.ts` registers `/metrics` without authentication;
`routes/metrics.ts` returns the Prometheus registry; upstream API tests expect
HTTP 200, text/plain, and metric samples; the upstream challenge inventory
identifies the exposure. Fetching the route can change request counters and
challenge bookkeeping. Restore a fresh application instance for each scanner
track, recording the reset contract and distinct instance identity.

The native mapping is `native.prometheus-exposition` with capability
`web.prometheus-exposition-check`, implemented separately under ADR 0103.
The lab-local Nuclei candidate checks the standard process CPU metric's HELP,
TYPE counter, and numeric sample. It can be supplied as a finite reviewed profile
to the existing real `PlanNucleiScan`/`RunNucleiScan` workflow. Standalone Nuclei
uses the same artifact as an orchestration baseline. That baseline is narrower
than the native associated-name predicate and is not a second independent
detector algorithm. The inventory records these differences explicitly.

Mappings are planned/candidate until source review accepts their implementations.
Neither a template, schema, nor synthetic contract fixture constitutes scanner
execution. An unavailable capability is a coverage gap. It cannot change an
application-positive case to not-applicable. Manual and app-inapplicable cases
require independent reasons and remain unscored.

The comparison envelope keeps prerequisites separate from executed outcomes.
Disabled execution is not-run; enabled missing Docker/provider is a prerequisite
failure. A real provider failure or empty required output cannot become success.
Only successful completed cases with required hash-verified raw evidence receive
finite TP/FP/FN/TN classifications. Unknown rules and off-case findings remain
unadjudicated, never automatic false positives. A failed/timed-out run keeps its
partial findings and evidence without receiving a completed-case score.

Retain scanner binary, rule artifact, product revision, target index/platform
digests, source revision, exact arguments, effective budgets, exit status,
duration, request observations, target provenance, stdout/stderr, and findings.
Metadata validation checks consistency; CI acquisition and review establish
whether actual scanner execution occurred. JSON/Markdown/HTML product reports
may later consume these records, without changing the core metrics contract.

## Runtime prerequisites and remaining gaps

No runtime is introduced by this source-only slice. The accepted target has no
published ports and is reachable only within its fixture-owned internal network.
The existing Node `docker exec` HTTP probe is not a scanner transport. A later
pytest fixture must install the actual product and pinned providers in a
separate runner on that owned network, use the exact inspected literal target
address, and retain original workspace/evidence artifacts. No Docker socket,
host networking, public demo, proxy, Internet scan, or default host port is
permitted. Pull/build prerequisites occur before isolated execution; runner
and target teardown must execute on all outcomes.

Source facts do not prove compatible HTTP framing. The metrics handler calls
`res.end` without explicit Content-Length and global compression is enabled.
The existing native worker rejects transfer encodings and requires a declared
length; the real image must establish framing compatibility or a separately
reviewed bounded transport change is necessary. Its 4096-byte legacy body
ceiling also does not establish that real metrics fit; ADR 0103 owns the new
check-specific bound without widening existing checks.

Compare exact case inputs, reset configuration, request counts, timeouts,
response/resource limits, and provider configuration. Record every effective
budget instead of equating requested limits with enforcement. Current Nuclei
uses a coupled invocation/request timeout and a fixed 1 MiB response ceiling;
native execution separates request/job timeouts and its proposed metrics body
ceiling is 256 KiB. These differences block a claim of equal-budget performance.
Per-case outcomes remain useful; comparisons expose budget/reset differences.
No whole-application accuracy or competitive ranking is emitted.

## Consequences

The first slice supplies a real-app source inventory, finite oracle, candidate
single-GET template, and deterministic record/comparison contracts. Existing
smoke and core metrics stay intact. Actual installed scanner execution and
isolated CI wiring remain explicit downstream acceptance, with unrun outcomes
until that evidence exists. Confidential-document exposure is recorded as a
source-pinned next candidate, requiring its own detector and controls.

## Native-only installed runner addendum

The first executable lane owns only the three native cases. Each case gets a
fresh existing `ExternalTargetLab`; a separate nonroot, read-only runner joins
that exact owned target container's network namespace. It has no host ports,
mounts, Docker socket, copied host environment, or route outside the internal
target network. CPU, memory, PID, tmpfs, process, startup, and cleanup budgets
are finite. Build/install happens before isolated execution. A derived image
builds the current product wheel and installs it without dependencies or an
index into a clean venv; isolated Python must import that installed package.

The runner invokes actual native planning, exact confirmation, execution, saved
Findings, and original evidence readers. It exports a JSON/base64 bundle with
at most 8 MiB of original bytes, finite file count, safe relative paths, per-file
hashes, sizes, and media types. This avoids host mounts and copying a tmpfs after
the container exits. The host preserves unchanged raw Docker command streams,
exit state, lifecycle records, and the validated original workspace bytes.
Scanner image/config, installed wheel, module hashes, and source revision stay
with the result. No Docker execution is established by mocked contract tests.

An invocation plus successful worker record establishes an approved HTTP
attempt. It is not independent server-contact telemetry, so request evidence
must name that provenance explicitly and may not claim exactly one observed
server contact. Health/version probes are separate. Actual failed request count
may be unknown. Enabled missing prerequisites fail; disabled execution skips
before Docker discovery. Docker enrollment waits for accepted detector source
integration and an explicitly available tracked native mapping; source presence
cannot promote that mapping. Other scanner tracks remain
unrun. Effective limits and deviations remain visible without cross-engine
performance aggregation.

After independent source review accepted ADR 0103's detector, the native track
is marked available alongside that integrated implementation. This does not
change any runtime outcome. The existing ready-only `external-targets` job in
`python-quality.yml` retains its target smoke and adds a separate native
three-case pytest step, JUnit result, and original scanner evidence directory.
Enabled missing prerequisites fail. The job keeps its original check/artifact
identity, bounded execution, and unconditional evidence retention. Actual
Docker acceptance remains unrun until the final proposed revision executes
successfully in shared CI; the other two scanner tracks remain candidates.

An explicit draft-only `[native-external-checkpoint]` marker can run the existing
external job's installed native three cases for supported-runtime diagnosis.
The previous target smoke and all other complete integration jobs remain
readiness-gated for this marker. Preserve the same finite execution, original
evidence and JUnit. A checkpoint is separate from final integration acceptance;
the stable proposed revision must still pass the full shared readiness gate.
