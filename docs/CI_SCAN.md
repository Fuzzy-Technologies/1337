# Explicit governed CI scan

`1337 ci scan` runs one explicitly selected governed configuration or image
profile, saves its canonical model and evidence, evaluates a caller-selected
finding predicate, and publishes JSON, SARIF and JUnit from the same saved
snapshot. Profiles are `synthetic-dockerfile`, `synthetic-kubernetes`,
`synthetic-image`, and the explicit `native-trivy` image profile. Synthetic
profiles use reviewed closed fixture families. Native configuration and
reachable-risk acceptance remain outside these profiles.

The workspace and artifact scope must already exist. The current recorded owner,
selected input-manifest target, scope consent and SAFE capability opt-in are
verified by the existing artifact workflow. For synthetic profiles select the
original source, trusted current CPython executable, reviewed first-party configuration worker and exact
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

The image profile selects an existing owned archive and uses the accepted
separate VERSION then SCAN workflow. Its explicit command shape is:

```bash
1337 ci scan /owned/workspace \
  --profile synthetic-image --archive /owned/selected/image.tar \
  --executable /owned/runtime/python \
  --producer /owned/reviewed/image-producer.py \
  --material /owned/selected/policy.json \
  --scope image-scope --owner owner:local \
  --read-consent-reference read:image --approve-safe-image \
  --severity high --severity critical --status open --status confirmed \
  --max-matches 0 --acknowledge-unassessed-completeness \
  --report-json /owned/reports/image.json \
  --report-sarif /owned/reports/image.sarif \
  --report-junit /owned/reports/image.xml --json
```

For `synthetic-image`, `--archive` and the explicit image SAFE opt-in belong to
this profile. Configuration profiles require `--source`, `--logical-path` and
their independent configuration SAFE opt-in. Cross-profile source/approval
arguments fail before launch. The image gate uses both original typed captures,
six original execution acquisitions, exact original VERSION prerequisite, and
current paired grant acceptance. Detached operation summaries cannot substitute
for this proof. Exact source-derived image inventory, relationships and
observations must exist in the complete saved model. No image build, daemon,
registry contact, implicit database update or reachability rule is
introduced. The final output barrier verifies current paired acceptance again.

The native profile reuses the existing governed Trivy VERSION/SCAN workflow over
one explicitly selected owned local archive. Its archive and cache spellings are
canonical workspace-relative paths; the trusted executable and strict policy
file are explicitly selected absolute paths. The policy permits the existing
`native.trivy` / `image.archive-vulnerabilities` SAFE capability. Recorded scope
consent, executing-owner read consent, policy permission and
`--approve-safe-image` remain independent requirements. The exact input manifest
target must already be registered in the selected scope.

```bash
1337 ci scan /owned/workspace \
  --profile native-trivy --archive inputs/image.tar \
  --executable /owned/pinned/trivy --cache-directory pinned/trivy-cache \
  --policy /owned/policies/image.json \
  --scope native-image-scope --owner actor:local \
  --read-consent-reference read:native-image --approve-safe-image \
  --severity high --severity critical --status open --status confirmed \
  --max-matches 0 --acknowledge-unassessed-completeness \
  --report-json /owned/reports/native-image.json \
  --report-sarif /owned/reports/native-image.sarif \
  --report-junit /owned/reports/native-image.xml --json
```

Native selection excludes synthetic `--producer`, `--material`, `--source`,
`--logical-path` and configuration approval. Synthetic selection excludes native
`--cache-directory` and `--policy`. CI retains its existing one-through-sixty
second selected scan timeout; the native workflow's bounded observation,
VERSION and owned cleanup allowances remain separate and unchanged. Executable,
archive and selected database/metadata identities are bound by that workflow;
provisioning the trusted pinned binary and database remains the operator's task.
No installation, executable discovery, download or database update is performed.

Native gating verifies the original six owning acquisitions and candidate
inventory/detections in the saved snapshot. It also requires the original
in-process identity-bound acceptance handle before the predicate and after the
actual exports. This handle invokes the original pair's existing fresh
scope/policy, expiry, claim, control and material checks with the original clock.
It cannot be reconstructed from saved receipts and is never serialized. Report
publication does not renew grants or start another material observation. A late
authority or source-proof failure returns nonzero while retaining actual scan
facts and already published report files. The native result's original run
reference is `native-scan:<receipt SHA256>`; synthetic run identities are unchanged.

The implementation decision and required genuine acceptance boundary are recorded
in [ADR 0101](adr/0101-native-trivy-ci-predicate.md). Deterministic provider and
observer doubles verify CI contracts; they do not establish genuine Trivy
execution, native scanner accuracy or required isolated acceptance.
The required assembled acceptance target is
`tests/functional/test_ci_native_image_product.py`, run in the existing pinned
no-egress native runtime with `FUZZY1337_RUN_NATIVE_IMAGE_PRODUCT_ACCEPTANCE=1`.
It exercises the installed isolated CLI, both unchanged inert archive cases,
no-opt-in refusal, three real artifacts and a deliberately injected late policy
refusal after publication. Missing required runtime prerequisites fail this lane.

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
