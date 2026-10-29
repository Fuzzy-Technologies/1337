# Finite real-application scanner comparison

This is the finite oracle and execution contract for
[ADR 0102](../../../docs/adr/0102-independent-app-scanner-benchmark.md),
[ADR 0106](../../../docs/adr/0106-comparative-nuclei-external-benchmark.md) and
Task #40. Actual scanner evidence is separate from the existing target health smoke;
the declared response cases do not establish whole-application accuracy.

| Case              | Exact path                        | Expected bounded property |
| ----------------- | --------------------------------- | ------------------------- |
| Metrics exposure  | `/metrics`                        | Present                   |
| Real JSON control | `/rest/admin/application-version` | Absent                    |
| Real HTML control | `/`                               | Absent                    |

The property is unauthenticated Prometheus exposition, not arbitrary injection,
browser execution, general exploitability, or every vulnerability in Juice Shop.
The JSON and HTML endpoints are causal media/body controls, not remediated
metrics endpoints. No application code is patched to create these expectations.

`juice-shop-cases.v1.json` freezes target/source references, case truth, provider
mappings, requested budgets, and detector differences. Its source references
resolve under this exact upstream commit:

<https://github.com/juice-shop/juice-shop/tree/5658473cf8814459bf89000ce373b20ed0b4eb37>

`server.ts` exposes the route; `routes/metrics.ts` returns actual registry data;
`test/api/metrics.test.ts` independently asserts the response format. The
version/root controls reuse the existing target contract. Source inspection
does not prove what the running image returns; preserve actual status, media,
body attribution, and transfer framing in the eventual scanner evidence.

| Track           | Mapping                                       | Current state                 |
| --------------- | --------------------------------------------- | ----------------------------- |
| Native engine   | `native.prometheus-exposition`                | Available; three cases passed |
| Whole 1337      | Governed Nuclei workflow + candidate template | Candidate                     |
| External Nuclei | Standalone real binary + same template        | Candidate                     |

The candidate checks a standard process CPU metric family; the native detector
associates generic HELP/TYPE/sample names. They assess the same application
property with different recognition coverage. The two Nuclei tracks compare
orchestration, not independent detector algorithms. The template is lab-local,
not an addition to the packaged scanner registry. Review and pin its digest
and the genuine binary before enabling execution.

`tests/functional/external_benchmark.py` validates observations and generates
finite comparison data only. Required acquisition files stay under an explicit
evidence root with byte hashes. Planned/candidate mappings cannot accept a
completed run; source acceptance must first mark their implementation available.
Missing observations produce not-run cells. Explicit unsupported capability
produces a coverage gap, never application-inapplicability. Prerequisite failure,
crash, timeout, manual, and unknown results receive no completed-case score.
Unexpected/off-case findings remain visible for adjudication.

Required runtime acquisition roles are stdout, stderr, invocation, findings,
target-provenance, and requests. Preserve original product workspace/evidence
files alongside the envelope; normalized JSON cannot replace source custody.
Finite completed TP/FP/FN/TN counts cover only the declared response cases.
`whole_application_accuracy` is always null.

`result.schema.json` preserves native/v1 observation semantics. The additive
Nuclei-only `result.v2.schema.json` distinguishes a successful invocation from a
proven case outcome. Exit zero with empty JSONL is executed `unproven`; it receives
no TN, FN, response-success or completed-case credit. Only an explicit raw match
bound to the exact case URL and declared rule can produce a completed TP or FP.
V2 Findings retain `target_url` as well as `rule_id` and `path`; unknown/off-case
records stay visible and unscored. Failed execution retains available bytes and
partial matches. Mixed reports preserve the original native v1 observations.

The v2 consumer checks retained stdout match identities against the acquired
Findings projection; it does not establish genuine execution or product custody.
Its required `attempt-provenance` role identifies the approved single configured
invocation and leaves independent server contacts unknown. Artifact reads enforce
the unchanged 2 MiB per-file ceiling and reject oversize bytes without truncation
or splitting. These schema and inert contract fixtures do not establish
application execution. The bounded standalone and governed producers, fresh
target host loop and complete original v2 assembly now have reviewed source.
Both track implementations are available for explicit selection; application
runtime remains **UNRUN** until the six actual comparative cases execute.

## Installed Nuclei image prerequisite

The implemented prerequisite is independently usable before application
comparison: it copies a clean committed source tree, builds the current wheel
and pinned official binary into an inspected image, then runs only the exact
3.4.10 version probe and Go validation of the one candidate template. The
nonroot runtime has a read-only root filesystem, no network, bounded private
tmpfs and an explicit private HOME. Original process streams, source/installed
inventories, image/container readbacks and separate daemon cleanup facts are
retained. Wrong identities, overflow, incomplete execution and unconfirmed
cleanup refuse acceptance. No application target is configured.

```bash
FUZZY1337_EXTERNAL_NUCLEI_PREREQUISITES=linux-amd64 uv run --locked --extra dev pytest \
  tests/functional/test_external_nuclei_prerequisites.py --no-cov -n 0
```

With the variable unset, this test skips before Docker discovery. An enabled
unsupported platform or missing Docker fails. The source must be clean and
include the accepted base in its history. Final ready-PR CI checks out its exact
head with full history, executes this prerequisite and requires one genuine
pass with the original evidence gate; stable pushes use their exact revision.
The draft marker admits only this prerequisite and suppresses the older target
smoke, native cases and metrics diagnostic in that mode.

The original target-free checkpoint on head `3a8285b2` completed with one pass,
zero skips in 35.11 seconds. Its
[original artifact](https://github.com/Fuzzy-Technologies/1337/actions/runs/40826818942/artifacts/12877415385)
has SHA-256
`952e2325fc4279a72a359f29654663361b57c84091a12bfa7846ac880b6f4044`.
Independent original-byte review accepted version/Go validation with explicit
HOME only. This does not prove governed no-HOME initialization, application
contacts, Findings, six-case comparison or final integration. The earlier failed
checkpoint remains separate failure evidence.

## Native application acceptance

The native-only runner source builds the current wheel into a clean venv in a
repo-built image, then joins each fresh owned target's exact network namespace.
It runs nonroot with a read-only root filesystem, bounded tmpfs/CPU/memory/PIDs,
no host mounts, no Docker socket, and no published ports. Actual original
workspace/evidence bytes are exported in a hash-verified JSON/base64 bundle
limited to 128 files, 2 MiB per file, and 8 MiB total. Raw Docker stdout/stderr
and exit metadata remain separate and byte-exact. Module, wheel, image, source,
authority, plan, worker and Findings identities are retained.

The installed native lane includes the independently reviewed detector from
ADR 0103 and its available native mapping. Availability records accepted source,
not scanner execution. With the variable unset it skips before Docker discovery;
enabling it while prerequisites or accepted mapping are missing fails. The other
two scanner tracks remain unrun. The ordinary fixture-owned invocation is:

```bash
FUZZY1337_EXTERNAL_NATIVE_BENCHMARK=juice-shop uv run --locked --extra dev pytest \
  tests/functional/test_external_native_benchmark.py --no-cov -n 0
```

`request_count` in this native lane counts the approved single-worker attempt
corroborated by its successful record. `attempt-provenance.json` explicitly
records that independent server contact count is unknown; no target telemetry
is invented. Fixture HTTP/version probes and Docker healthchecks are separate.
The Node health probe cannot stand in for scanner execution. Native response
framing/body compatibility and isolation must be proven by genuine Docker CI.

Effective budgets must be measured honestly. Nuclei currently fixes a 1 MiB
response ceiling and couples its request/process timeout; native metrics uses
separate request/job limits and a 256 KiB body ceiling. The comparison
retains budget deviations and refuses to imply identical performance inputs.
The verified native checkpoint at PR head `f22e3c29` completed these finite
cases with **TP 1 / FP 0 / FN 0 / TN 2** and zero skipped cases. Each case used
a distinct fresh target with the same reset contract. The metrics response was
HTTP 200, text/plain and 25,986 bytes; the installed detector created the expected
Finding, and both real negative controls produced no exposition Finding. Original evidence is
retained in
[artifact 12830144211](https://github.com/Fuzzy-Technologies/1337/actions/runs/40723123569/artifacts/12830144211)
with archive SHA-256
`cb01d7f040c14802143396adb6561093c51a63b5f49cfff1b498c22cfcb0e281`.
PR #371 subsequently merged as `503ff06a` after final shared integration
acceptance. This earlier checkpoint archive remains separately identified.

The original false negative is preserved separately in
[artifact 12828328221](https://github.com/Fuzzy-Technologies/1337/actions/runs/40717160124/artifacts/12828328221).
The corrected predicate admits valid unsigned NaN casing, including `Nan`;
the original oracle and prior evidence are unchanged. The two candidate Nuclei
tracks still have no runtime acceptance.

The existing `external-targets` job in `.github/workflows/python-quality.yml`
runs the original target smoke followed by these three installed native cases
on final PR readiness. Each native case restores a fresh pinned application.
The job preserves both evidence directories, including the native JUnit result,
raw Docker streams, original product workspace, and finite comparison report.
It fails on missing enabled prerequisites and retains evidence on failures.
The smoke result does not substitute for scanner acceptance. Local implementation
preflight found no Docker; the genuine shared checkpoint supplies the separate
runtime evidence. Source and offline tests alone do not establish that result.

The explicit draft marker `[native-external-checkpoint]` enables only this
job's installed native three-case step for supported-runtime diagnosis. The
already separate target smoke and other complete integration jobs wait for
final readiness. This checkpoint preserves original evidence and JUnit; it
does not establish final integration acceptance.

The additional draft-only marker `[native-external-metrics-diagnostic]` selects
one separately authorized GET of `/metrics` on a fresh pinned target. It
requests identity encoding and retains returned bytes with their own hash, headers,
provenance and finite 256 KiB/2.25-second child/3-second exec bounds. This later
body is independent of the earlier scanner response. The diagnostic skips
native case execution; final readiness always requires the actual native lane.
Production response-retention behavior is unchanged.

Focused offline contract checks:

```bash
uv run --locked --extra dev pytest tests/contract/test_external_benchmark.py --no-cov -n 2
```

## Finite two-track Nuclei application source

The installed image now has a finite application mode for the existing
`whole1337` and `external-nuclei` tracks, over the same three unchanged cases.
[ADR 0106](../../../docs/adr/0106-comparative-nuclei-external-benchmark.md) and
[nuclei-provider.v1.json](nuclei-provider.v1.json) retain the official binary,
reviewed rule, empty configuration and effective-limit provenance. Track
availability records source acceptance; it never supplies runtime acceptance.

The separate genuine no-HOME prerequisite passed on source `5887666f`, tree
`9079e87f`, in [run 40879355362](https://github.com/Fuzzy-Technologies/1337/actions/runs/40879355362).
It establishes exact version/Go validation with unchanged PATH/LANG and a private
working directory. The earlier explicit-HOME prerequisite and native three-case
results remain independently identified above. Neither supplies new application
case credit. The six application invocations remain UNRUN until supported-runtime
CI executes their exact final source.

After independent source acceptance, select only the six new cases with:

```bash
FUZZY1337_EXTERNAL_NUCLEI_BENCHMARK=juice-shop uv run --locked --extra dev pytest \
  tests/functional/test_external_nuclei_benchmark.py --no-cov -n 0
```

Each track/case owns a fresh unchanged target. Before any target starts, the
shared immutable current-wheel image must pass its genuine target-free no-HOME
probe. Original target/image/container readback, internal network, fixed-local
Docker routing, original process streams and independent cleanup remain retained.
The owned runner is removed before its target namespace/network teardown.

Original evidence and the v2 comparison are beneath
`functional-evidence/external-nuclei-prerequisites/run-*/`; a comparison host is
identified by `kind: finite-nuclei-application-comparison`. Each source invocation
remains byte-exact. Whole-product provider duration and whole-product/image wall
time remain separate. A valid mapped match may score TP/FP for the selected case;
empty matching output stays `unproven`, with no TN/FN, successful-response or
independent server-contact credit.

Actual launch/capture/timeout/cancellation/export failures stay unscored. If
provider custody is unavailable, a failed v2 row requires original hashed host
start/capture/source/case/target/cleanup proof and retains null provider execution;
before-start errors remain prerequisite-failed. Unknown cleanup never becomes
confirmed termination. The original bundle limits remain 128 files, two MiB per
file and eight MiB total; failed export never truncates originals into a passing
comparison. Existing native and target-free selections remain separate from this
new six-case step.

The focused draft marker `[nuclei-application-product-checkpoint]` selects only
the same six ordinary product cases and their read-only original-evidence gate.
It enrolls no older smoke, native three-case or standalone prerequisite test.
Its own current-image initialization still precedes target creation. The case
step has a twenty-minute bound with a 900-second pytest signal deadline, followed
by a one-minute gate; the twenty-five-minute job includes setup and evidence
retention. Final readiness runs these six cases inside the original external job
with its prior forty-minute allocation plus twenty-one minutes for the new work.
