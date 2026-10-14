# Explicit configuration CI scan

`1337 ci scan` runs one explicitly selected accepted synthetic configuration
profile, saves its canonical model and evidence, evaluates a caller-selected
finding predicate, and publishes JSON, SARIF and JUnit from the same saved
snapshot. The first profiles are `synthetic-dockerfile` and
`synthetic-kubernetes`. They use the reviewed closed fixture family; they do not
provide native configuration or reachable-risk acceptance.

The workspace and artifact scope must already exist. The current recorded owner,
selected input-manifest target, scope consent and SAFE capability opt-in are
verified by the existing artifact workflow. Select the original source, trusted
current CPython executable, reviewed first-party configuration worker and exact
closed material policy explicitly. Paths for these selected inputs are absolute.
The command performs no source discovery, Dockerfile build, Kubernetes workload
creation or remote contact.

For an already initialized and approved owned workspace, the explicit command
shape is:

```bash
1337 ci scan /owned/workspace \
  --profile synthetic-dockerfile --logical-path Dockerfile \
  --source /owned/selected/Dockerfile \
  --executable /owned/runtime/python \
  --producer /owned/reviewed/configuration-producer.py \
  --material /owned/selected/policy.json \
  --scope configuration-scope --owner owner:local \
  --read-consent-reference read:configuration \
  --approve-safe-configuration \
  --severity high --severity critical --status open --status confirmed \
  --max-matches 0 --acknowledge-unassessed-completeness \
  --report-json /owned/reports/configuration.json \
  --report-sarif /owned/reports/configuration.sarif \
  --report-junit /owned/reports/configuration.xml --json
```

The severity and disposition sets are required, nonempty and unique. Their
conjunction selects matching current source findings. `--max-matches` explicitly
allows from zero through 1024 matches. No severity ranking, score, weighted
aggregation or default risk threshold is inferred. The existing saved operator
disposition remains authoritative when this source is detected again.

Gate selection requires verified original acquisitions, original receipt and
capture equality, current original-grant acceptance, exact saved processed-source
inventory and current-run detection proof. Namespace prefixes and finding counts
alone are insufficient. Unrelated retained findings and historical detections
absent from this execution remain in the full snapshot reports and keep their
saved disposition; they do not enter this source predicate. A proven processed
source with no detections can satisfy the explicit predicate.

Every output destination must be a distinct new file in an existing physical
parent outside the source workspace. All three destinations are checked before
launch. The existing publication owner publishes complete bytes without replacing
existing files. JSON establishes the exact saved snapshot pin; SARIF and JUnit
retain the same digest and revision. JUnit represents retained findings using
the existing report adapter and may contain failures even when the selected CI
predicate is satisfied. Report test cases are retained finding interpretations,
not a claim that security checks passed.

| Exit | Terminal meaning                                                        |
| ---- | ----------------------------------------------------------------------- |
| 0    | Explicit acknowledged source predicate satisfied and artifacts complete |
| 1    | Source predicate violated; completed scan and artifacts remain retained |
| 2    | Invalid configuration, including missing completeness acknowledgement   |
| 3    | Current authorization or selected material refused                      |
| 4    | Failed or uncertain execution, evidence, storage, basis or report       |
| 130  | Cancelled or interrupted operation                                      |

`--json` emits one safe schema-one command outcome with independent scan,
criterion and per-artifact truth. Lost storage or publication acknowledgements
remain nonzero even if a saved revision or complete artifact is actually present.
Confirmed partial publication is retained per artifact. A later current-authority
refusal cannot erase original scan or artifact facts, and cannot return zero.

The required acknowledgement and all machine artifacts retain
`scan_completeness: not-assessed`. Exit zero means only that the explicit
`selected-profile-finding-predicate` criterion was satisfied; it establishes no
universal clean result, discovery completeness, native scanner accuracy,
exploitability or network reachability. Reachable-risk profiles require a
separate selected-graph, assessment and complete model-basis decision.
