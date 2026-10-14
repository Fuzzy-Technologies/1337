# ADR 0075: Explicit configuration CI predicate

## Status

Accepted first-profile implementation decision — 2026-10-14. Advances #75;
reachable-risk and native profiles remain separate work.

## Decision

The first `1337 ci scan` profile reuses the accepted SCAN-only synthetic
configuration workflow. The caller selects every source/runtime/worker/material,
scope, owner, read consent, SAFE opt-in, severity set, finding disposition set,
count limit and three new report destinations explicitly. An explicit
acknowledgement of unassessed global completeness is required before launch.

The required JSON export is produced by the existing workflow against its exact
saved model. CI reopens the canonical report owners and compares the complete
snapshot digest. It verifies the original four acquisitions, unchanged original
capture and current grant acceptance. The configuration evidence owner's exact
normalization identifies the processed asset, inventory and finding detections.
Those exact current-run records must exist in the saved model. Saved operator
triage remains authoritative; unrelated and absent historical detections do not
enter the predicate and remain unchanged in the full reports.

The gate applies the explicitly selected severity/disposition conjunction and
count limit. Unknown selected-source severity requires explicit inclusion or
evaluation fails. This is a caller-selected predicate, with no severity ranking,
weights, probability aggregation or implicit risk threshold. A satisfied
criterion describes only `selected-profile-finding-predicate` facts. All
artifacts and the command summary retain `scan_completeness: not-assessed`.

JSON, SARIF and JUnit use existing serializers and publication owners. All
destinations are checked before launch; existing files are never replaced.
Additional formats use the same saved model digest. Changed snapshots, missing
proof, failed storage acknowledgements, rendering/publication failure and current
authority refusal cannot produce exit zero. Partial output publication is
reported per artifact without changing original scan facts.

## Terminal status

| Exit | Meaning                                                             |
| ---- | ------------------------------------------------------------------- |
| 0    | Acknowledged selected predicate satisfied; completeness not assessed |
| 1    | Selected predicate violated after successful workflow and artifacts  |
| 2    | Invalid explicit configuration; no successful criterion claim         |
| 3    | Current authorization or selected material refused                    |
| 4    | Execution, evidence, storage, basis or report outcome failed/uncertain |
| 130  | Cancelled or interrupted execution/publication                        |

## Boundaries

No scanner, subprocess bypass, authorization policy, schema, remote executor,
REST contract or inferred reachability is added. Configuration profiles produce
no reachability transitions. Reachable-risk gating requires a separate explicit
selected-graph/assessment/basis contract. This slice does not close #75 and does
not implement the owner architecture decision for #67.
