# ADR 0106: Finite comparative Nuclei application observations

## Status

Accepted architecture — 2026-10-28, Task #40. Independent review approved the
proposal with SHA-256
`cdc0a17fa4b8710fd1d4db9bae606582448d863c6d03a28451fb299ae60859e2`.
PR #371 subsequently merged as `503ff06a` after actual final shared CI and
three-case native acceptance. This decision preserves the approved design;
those prerequisites are satisfied.

The current implementation supplies the lab v2 observation schema/consumer,
bounded standalone and governed producer sources, verified material preparation,
and an owned target-free Docker prerequisite. The genuine pinned Nuclei 3.4.10
version probe and strict Go template validation passed in the inspected offline
image with an explicit private HOME. Original artifact review accepted that
prerequisite boundary; it establishes no application case or scanner comparison.

Both application tracks remain candidates with runtime **UNRUN**. Fresh target
orchestration, complete v2 observation assembly, governed initialization without
HOME, and the six comparative application invocations remain future Task #40
work. This implementation is the comparison groundwork, not completion of the
whole decision. Final readiness enrolls the implemented target-free prerequisite
alongside the existing native application acceptance in shared CI.

## Context

ADR 0102 defines three independently known response cases on pinned Juice Shop:
`/metrics` is positive; the real version JSON and root HTML are negative
controls. Its whole-application oracle remains incomplete. PR #371 supplies
the reviewed native detector and installed-wheel lane, with genuine acceptance
completed before this implementation. The existing Nuclei adapter and governed
SDK already support an explicitly reviewed, exact-URL single-GET profile. The lab-local Prometheus
template is a candidate and is not a packaged scanner registry entry.

Add only the existing `whole1337` and `external-nuclei` tracks over these same
three inputs. Both use the same Nuclei binary and template. Their comparison
assesses orchestration, custody, normalization, and persisted product behavior;
they are one detector algorithm, not two independent engines. The native
predicate is a second, different recognizer. This slice adds no applications,
route discovery, credential workflows, or whole-application accuracy claim.

## Frozen inputs and source interpretation

The initial reviewed repository snapshot is public commit
`ca73fb44606a40301db3a3d466235094aafad4c7`, exact tree
`baad14888c6ef6c4d22b89c2c3f65ab9d996bbb0`. A later implementation records its
actual final source revision; it must not label a different tree with this pin.

| Input                      | Immutable identity                                                                                                                                                                  | Interpretation                                                                                                                             |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Lab template               | `templates/prometheus-exposition.yaml`; SHA-256 `dff3e6ea0821ba769cf63575ad685b8c1def939ed24f790f42d2fde924d55c74`; 1215 bytes; Git blob `3a16d5a09784a07ceb8c2cc1c24a60fe68c2c347` | One GET to `{{BaseURL}}`; redirects false; AND of HTTP 200, text/plain header, and adjacent standard process CPU HELP/TYPE/sample lines    |
| Existing adapter           | `src/fuzzy1337/adapters/nuclei.py`; Git blob `a9c0c533e9cb92277cee3647d065f9c8ba529903`                                                                                             | Fixed HTTP-only argv; explicit local reviewed profile/config; STANDARD `web.http-template-check`; strict raw JSONL normalization           |
| Governed workflow          | `src/fuzzy1337/nucleiscan.py`; Git blob `ff23b476306739a48a7449e45686dcfdb08e1976`                                                                                                  | Actual Plan/confirm/Run, current URL/IP authority, durable evidence and Findings; no default grant                                         |
| Nuclei release             | v3.4.10; tag resolves to commit `5bff7a2a90965a0ed8b03f2ff557f3220624dd57`                                                                                                          | Freeze this version for this comparison; do not resolve a latest release                                                                   |
| Official Linux amd64 asset | `nuclei_3.4.10_linux_amd64.zip`; 33657343 bytes; SHA-256 `234c12cc5288af071abdcd6f854245b6067345556e1235cf96b76725c1004357`                                                         | Existing genuine-provider CI pin agrees with upstream release asset metadata; extracted executable hash remains an actual acquisition fact |
| Juice Shop                 | 20.2.0; source `5658473cf8814459bf89000ce373b20ed0b4eb37`; OCI index `sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b`                                      | Reuse unchanged target/case manifests and their independent source blob inventory                                                          |
| Executed target platform   | Linux amd64 manifest `sha256:7f7539921b046863f2fc48b84061f957e50b3aa4652ae0a62014a2fc25654d0b`                                                                                      | Actual inspected platform/config/container IDs must agree; no emulation or alternate platform substitution in this first lane              |

The template recognizes nonnegative decimal/exponent process counter tokens,
excluding literal NaN/Inf. It does not parse numeric representability.
It requires its three body lines in one order and adjacent, admits optional
labels without validating the full Prometheus label grammar, and does not
validate every other response line. It can therefore miss valid exposition
recognized by native or match a text/plain document containing this triple
that the native complete-document predicate rejects. These differences stay
explicit; agreement on three cases cannot establish detector equivalence.
The fixed application truth is not changed to match either recognizer.

Pinned primary upstream implementation sources:

| Source at Nuclei commit `5bff7a2a90965a0ed8b03f2ff557f3220624dd57` | Git blob                                   | Relevant fact                                                                                                          |
| ------------------------------------------------------------------ | ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `pkg/operators/matchers/compile.go`                                | `5a99347c550fce6e402a70956ab6cffe25b8e12f` | Regexes compile with Go regexp; Python regex fixtures alone do not prove genuine compatibility                         |
| `pkg/operators/operators.go`                                       | `ed2f0c4d23af258f236ea3d421b59876476c7f95` | The declared AND combines the three matchers                                                                           |
| `pkg/protocols/http/request.go`                                    | `381f4d385f2a554e6b2132e2b97647fe7295ee55` | Configured response-read size overrides template max-size; request success/failure accounting is separate from matches |
| `pkg/output/output.go`                                             | `f7909320eb310310381a5fe1d3c4637408604fab` | No-match events are suppressed without matcher-status; request trace requires an explicit trace/error output or hook   |
| `internal/runner/runner.go`                                        | `2a3c2c470b4926593efa894c11fce4f31b22b537` | Initialization/update behavior and exact-template validation must be considered before isolated execution              |

Primary references:

- [Exact Nuclei source](https://github.com/projectdiscovery/nuclei/tree/5bff7a2a90965a0ed8b03f2ff557f3220624dd57).
- [Official release asset metadata](https://api.github.com/repos/projectdiscovery/nuclei/releases/tags/v3.4.10).
- [Exact existing candidate rule](https://github.com/Fuzzy-Technologies/1337/blob/ca73fb44606a40301db3a3d466235094aafad4c7/labs/external/benchmark/templates/prometheus-exposition.yaml).
- [Independent target/case inventory](https://github.com/Fuzzy-Technologies/1337/blob/ca73fb44606a40301db3a3d466235094aafad4c7/labs/external/benchmark/juice-shop-cases.v1.json).

## Authority and real execution boundary

Each new track/case restores one fresh existing `ExternalTargetLab`. It reuses
the internal target network, inspected namespace identity, absence of host
ports/mounts/socket, nonroot read-only runner, finite resources, and unconditional
cleanup from ADR 0102. Preparation, release acquisition, exact template validation,
and image provisioning happen before target execution. Runtime receives only
its exact literal URL and fixed case/profile; no host environment is forwarded.
Provide a private owned writable HOME/cache under bounded tmpfs if Nuclei needs
it. Preserve its exact initialized configuration inventory and fail incompatible
offline initialization rather than silently download rules or widen egress.

For `whole1337`, install/import the actual current wheel and invoke the existing
`PlanNucleiScan` / `RunNucleiScan`. Create explicit current consent for the exact
URL and loopback IP, matching owner, STANDARD maximum impact and only
`web.http-template-check` for `native.nuclei`. Supply the exact plan confirmation.
Case metadata's `web.prometheus-exposition-check` describes the compared property;
it does not substitute for or grant the Nuclei execution capability. Preserve
scope/policy/plan/confirmation, current launch decisions, job/events, original
paired acquisitions, model, saved Findings and verified reopen. A negative
control is still a STANDARD network operation requiring the same authority.

For `external-nuclei`, launch the genuine pinned executable directly, without
the product planner, policy executor, ingestion, or model. The fixture retains
its explicit lab authorization and exact allowed URL/profile as a standalone
execution manifest; it must not pretend to possess a product grant. Construct
the finite standalone argv directly and compare its documented detection flags
to the governed argv; allow only declared artifact-path differences. Never use
a fake executable or wrapper that silently adds flags. Binary version probes
are bounded local prerequisites and do not count as target contacts.

Both tracks use one copied, singly linked, digest-verified template and exactly
`{}\n` operator config (SHA-256
`ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356`).
Review provenance is explicit and must name the actual
accepted review/revision, not the contract-fixture reference. Preserve profile
serialization/digest and actual executable SHA-256. Version output must report
3.4.10; accepting any 3.x is insufficient for this benchmark pin. Archive hash,
extracted binary hash, version and image digest are distinct facts. Do not claim
the upstream binary was independently reproducibly built from the tagged source.

## Effective limits and fair comparison

Keep the existing production/provider API and flags unchanged. The proposed
Nuclei profile sets `NucleiScanLimits(timeout_seconds=3, rate_limit=1)`. Both
Nuclei tracks use HTTP-only `-u` exact URL, one `-t`, `-jsonl -silent -nc`, omitted
raw/template output, disabled update checks/Interactsh/redirects/stdin/fallback/
clustering, bulk/concurrency one, retries zero, host error ceiling one, timeout
three, and fixed `-rsr 1048576 -rss 1048576`. Preserve the full actual argv rather
than relying on this prose summary. Do not add trace, matcher-status, proxies,
credentials, callbacks, another template, or an endpoint probe to the scan.

| Limit or evidence window           | Native lane                        | Both Nuclei lanes                                                                         | Consequence                                                                  |
| ---------------------------------- | ---------------------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Intended exact HTTP operations     | One GET                            | One GET                                                                                   | Configured attempt is not independently observed server contact              |
| Requested request timeout          | 3 seconds                          | 3 seconds                                                                                 | Same numeric request setting, not proof of equal transport behavior          |
| Provider invocation deadline       | 10 seconds                         | 3 seconds                                                                                 | Existing Nuclei timeout is coupled to its process deadline                   |
| Product wrapper deadline           | Existing native contract           | Nuclei job is provider deadline + 5 seconds                                               | Record separately; do not call wrapper grace extra provider time             |
| Response read/save ceiling         | 256 KiB decoded body               | 1 MiB response flags                                                                      | Requested equal 256 KiB is not enforced by current Nuclei API                |
| Provider stdout/stderr             | Existing native record limits      | Existing whole-product 4 MiB / 64 KiB; standalone uses the same declared capture ceilings | No output-limit equality claim across engines                                |
| Original bundle                    | 128 files, 2 MiB/file, 8 MiB total | Same unchanged transport ceilings                                                         | Oversize raw capture/export fails unscored; never truncate or secretly split |
| HTTP rate/bulk/concurrency/retries | One admitted worker attempt        | 1 per second / 1 / 1 / 0                                                                  | Preserve actual flags and raw lifecycle evidence                             |
| Wall time                          | Existing native job window         | Record provider/window attribution plus whole-product and container wall time separately  | No aggregate speed/resource ranking from different windows                   |

Keep requested budgets and every effective deviation. Sharing the same official
binary, template bytes, exact input, rate and Nuclei provider deadline makes the
two Nuclei invocation configurations comparable. Their authority/ingestion and
wall-time paths differ by design. Native versus Nuclei results are finite case
observations with disclosed recognizer/body/deadline differences; they do not
establish equal-budget accuracy, throughput, latency, or general superiority.

## Invocation completion and unproven case outcomes

The existing native success record includes URL, HTTP status, body hash and a
boolean after its bounded response reader. The existing Nuclei contract exposes
raw matching JSONL plus process completion, not a success record for every
nonmatching response. Under pinned upstream semantics, empty JSONL can be a
normal no-match result. Exit zero and empty output alone cannot prove a completed
GET, a successful response, or response-level absence of the property.

Root's selected boundary is truthful attempt-only accounting. Do not add a
provider API, request trace role, matcher-status flag, packet capture, proxy,
server instrumentation, or hidden wrapper to fill the matrix. Record one
approved configured invocation and explicitly unknown actual server contacts.
Retain the native attempt basis separately; the two evidence strengths differ.
The inherited `request_count`/`requests` role names record this approved
configured attempt; a separate attempt-provenance artifact must identify that
basis and the unknown independent server contact count. They are not telemetry.

Introduce a lab-only versioned v2 result schema/consumer distinction:

- Preserve v1 decoding and native interpretation unchanged.
- A valid successful genuine match, with exact rule/input binding and required
  raw provenance, may produce completed mapped TP or FP for that finite case.
- Successful invocation with no observed Finding produces executed `unproven`,
  retaining exit zero, empty raw stdout, stderr, arguments, actual duration,
  provenance and reason. It receives no TN, FN or response-success credit.
- Missing enabled prerequisites fail as prerequisites. Actual crash, timeout,
  invalid output, authority denial, failed export or missing evidence is failed
  and unscored; retain available partial matches and original bytes.
- Unknown/off-case records remain visible for adjudication. Unmapped or
  unsupported capabilities never change an application-positive case to
  not-applicable. Missing execution stays not-run.

The v2 distinction changes the lab observation envelope, not the production
Nuclei provider or core functional-metrics contracts. Keep v1 source fixtures
and existing native rows valid. Do not relabel an invocation-only empty result
as completed-case absence in a renderer, summary, metric denominator or export.

| Case truth           | Native after genuine accepted response           | Nuclei valid matching record | Nuclei exit zero, no Finding |
| -------------------- | ------------------------------------------------ | ---------------------------- | ---------------------------- |
| `/metrics`: present  | TP if detected; FN if completed and not detected | TP                           | Unproven; no FN              |
| Version JSON: absent | TN if completed and not detected; FP if detected | FP                           | Unproven; no TN              |
| Root HTML: absent    | TN if completed and not detected; FP if detected | FP                           | Unproven; no TN              |

A future explicitly reviewed trace contract may support stronger absence
assessment. That is not an implicit prerequisite or part of this slice.

## Evidence and acceptance matrix

All outputs preserve raw bytes separately from normalized observations. A
strict standalone JSONL reader only projects explicit input/rule/path identity;
it does not call the product planner, normalize through a product model, or
invent a Finding. The whole-product projection must come from actual saved
Findings and retain the original enclosing acquisitions. Different prefix
forms are declared (`fuzzy1337-...` versus `nuclei.fuzzy1337-...`), not inferred
through substring matching. Report both actual outcome strength and scores.

| Evidence/gate          | Whole 1337                                                                                      | Standalone Nuclei                                                            | Required review/acceptance                                                                                           |
| ---------------------- | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Rule                   | Same exact 1215-byte candidate                                                                  | Same exact candidate                                                         | Independent semantic review plus genuine pinned Go template validation; a YAML/Python fixture is not execution proof |
| Binary/provisioning    | Official archive, extracted binary hash, exact version, image ID, installed wheel/module hashes | Same official binary/version and source-owned runner/image hashes            | Acquire before isolated execution; mismatch/missing material fails                                                   |
| Target/reset           | Fresh unchanged pinned target per case                                                          | Fresh unchanged pinned target per case                                       | Exact image index/platform/config/container IDs; reset hash; no ports, mounts or egress                              |
| Authority              | Exact current scope, policy, plan/confirmation and launch evidence                              | Explicit standalone fixture authorization/allowed input manifest             | No implicit capability, credential or scope expansion                                                                |
| Invocation             | Actual provider argv and governed job/executor result                                           | Actual direct argv and bounded process result                                | Return codes, timeout/cancellation, capture exhaustion and cleanup remain truthful                                   |
| Detection              | Original paired evidence, actual saved Findings/model/reopen                                    | Original matching JSONL and strict independent lab projection                | Exact rule/input binding; unknown/off-case records unadjudicated                                                     |
| Absence/accounting     | Empty output is invocation-only unproven                                                        | Empty output is invocation-only unproven                                     | No invented TN/FN, contact count or success response                                                                 |
| Transport              | Original workspace plus bounded bundle and raw Docker streams                                   | Original raw streams/provisioning/manifests plus same bounded bundle         | Per-file oversize or byte/hash mismatch fails unscored, preserving available raw host streams                        |
| Negative/failure gates | Existing authority failures plus absent binary, invalid template/output, failed custody         | Absent binary, wrong pin/version, invalid output, timeout and failed cleanup | Focused deterministic contracts first; genuine six new case invocations only after runtime enrollment                |
| Final integration      | Separate six-case Nuclei pytest selection in existing external-target job                       | Same selection, separate fresh instances/evidence                            | Final-head shared CI must execute, preserve JUnit and v2 comparison; draft skips are not acceptance                  |

Do not rerun the current three native cases as a local next-wave prerequisite.
Preserve their accepted evidence and the normal final shared job. A combined
historical comparison may include native v1 observations only with their exact
revision, reset and budget differences visible; never pretend independently
acquired runs are simultaneous equal-environment performance measurements.

## Implementation ownership and file boundaries

Implementation begins on a new branch from then-current accepted `develop`;
PR #371 remains clean. Keep the change confined to the lab/oracle and its new
transports. Accepted paths are:

- `docs/adr/0106-comparative-nuclei-external-benchmark.md`: accepted decision.
- `labs/external/benchmark/nuclei-provider.v1.json`: frozen upstream binary/source,
  candidate-rule review, profile and effective-budget provenance; a lab schema
  accompanies it if consumer validation requires a new file contract.
- Existing case pack/template: preserve truth and rule bytes; mark only accepted
  track implementations available after source acceptance, never from execution
  request alone. No packaged rule/registry expansion.
- `labs/external/benchmark/result.v2.schema.json` and
  `tests/functional/external_benchmark.py`: additive v2 unproven-state consumer,
  preserving v1/native handling and explicit unsupported/not-run rows.
- `labs/external/benchmark/nuclei-runner.Dockerfile` plus
  `tests/functional/external_nuclei_runner.py` and `external_nuclei_runtime.py`:
  finite official provisioning, actual two-mode execution and original-byte
  custody. Reuse existing owned target/bundle helpers without broad refactoring.
- `tests/contract/test_external_nuclei_benchmark.py` and existing comparison
  contract tests: exact source/profile/argv, strict hostile evidence, unproven
  semantics, refusal and cleanup contracts; inert fixtures are clearly labeled.
- `tests/functional/test_external_nuclei_benchmark.py`: ordinary serial pytest,
  two tracks times three cases, explicit opt-in and enabled prerequisite failure.
- Existing `.github/workflows/python-quality.yml` `external-targets` job: one
  coordinated later enrollment of this separate six-case step and evidence;
  preserve native three-case selection, smoke, check identity and readiness gate.
- `labs/external/benchmark/README.md`: actual supported inference and evidence.
  Shared changelog/registries/locales remain root-owned and coordinated.

No production source, public API, capability registry, provider flag/default,
dependency/lock file, release or PyPI change is proposed. Architecture review
accepted v2 unproven semantics and the honest incomplete matrix. The existing
native acceptance remains separate from both unrun Nuclei tracks.
