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
or splitting. These schema and inert contract fixtures do not enable either
Nuclei runner: both tracks remain candidates with runtime **UNRUN**, pending a
later reviewed runner and actual six-case shared CI evidence.

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
