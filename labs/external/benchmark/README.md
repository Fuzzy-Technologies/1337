# Finite real-application scanner comparison

This is the source contract for [ADR 0102](../../../docs/adr/0102-independent-app-scanner-benchmark.md)
and Task #40. It complements the existing external target health smoke. It
does not start Docker, execute a scanner, or claim vulnerability acceptance.

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

| Track           | Mapping                                       | Current state                   |
| --------------- | --------------------------------------------- | ------------------------------- |
| Native engine   | `native.prometheus-exposition`                | Available; native checkpoint FN |
| Whole 1337      | Governed Nuclei workflow + candidate template | Candidate                       |
| External Nuclei | Standalone real binary + same template        | Candidate                       |

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
The genuine native checkpoint at PR head `84311559` completed these finite
cases with **TP 0 / FP 0 / FN 1 / TN 2**. The metrics response was HTTP 200,
text/plain and 25,982 bytes, but the installed detector returned false. The
JSON and HTML controls passed. Native acceptance remains unmet, and the
positive oracle is unchanged. Original evidence is retained in
[artifact 12828328221](https://github.com/Fuzzy-Technologies/1337/actions/runs/40717160124/artifacts/12828328221)
with archive SHA-256
`64718e982b7d9fa6b959e6cfd9d088695cdb5ce4b2bfe09948ef5662d107e1b8`.

The existing `external-targets` job in `.github/workflows/python-quality.yml`
runs the original target smoke followed by these three installed native cases
on final PR readiness. Each native case restores a fresh pinned application.
The job preserves both evidence directories, including the native JUnit result,
raw Docker streams, original product workspace, and finite comparison report.
It fails on missing enabled prerequisites and retains evidence on failures.
The smoke result does not substitute for scanner acceptance. Local Docker is
unavailable in the implementation environment; source and offline tests do not
establish runtime acceptance.

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
