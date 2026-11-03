# Owned local Workbench demos

The development source provides two command-owned loopback workflows over the
ordinary workspace, scope, scanner, evidence and report interfaces:

| Action            | Separate approval         | Actual result                                                                                                   |
| ----------------- | ------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `demo local`      | `--approve-safe-http`     | SAFE status-only discovery of three fixed endpoints; JSON/SARIF and no vulnerability Finding                    |
| `demo assessment` | `--approve-standard-http` | Two STANDARD 1337Scope Git HEAD checks; one actual open LOW Finding, a distinct 404 control and JSON/HTML/SARIF |

[ADR 0054](adr/0054-owned-local-workbench-demo.md) defines the existing local
discovery composition; [ADR 0137](adr/0137-command-owned-native-assessment-demo.md)
defines the additive assessment. Each action accepts its own approval flag.
The complete M4 attack-path-mini showcase #118–#125 remains separate work.
Use a reviewed source checkout or wheel containing the selected action;
these development instructions do not establish a new published release.

## Run SAFE discovery from the development source

Use a current accepted `develop` checkout with the project's locked developer
environment (`uv sync --locked --extra dev`). No PyPI installation is needed.
From the checkout root, first display the exact plan without granting consent:

```bash
mkdir -p artifacts
uv run --locked python -m fuzzy1337 demo local artifacts/local-demo
```

The plan-only invocation returns status 3. It starts no target, sends no request
and creates no demo output root. The plan owns a synthetic service bound only to
`127.0.0.1` on an ephemeral port, retaining that numeric service identity without
a reverse DNS lookup; native discovery issues exactly three anonymous
GETs to `/`, `/health` and `/redirect`. Request timeout is two seconds, the total
scan deadline is fifteen seconds and consent is valid for two minutes. Nothing
follows the redirect or reads response bodies/cookies.

Approve that finite owned plan explicitly:

```bash
uv run --locked python -m fuzzy1337 demo local artifacts/local-demo --approve-safe-http
uv run --locked python -m fuzzy1337 workspace open artifacts/local-demo/workspace --json
```

Default terminal output streams actual job state, progress and saved model deltas.
Use `--json` on the demo command for one final schema-v1 outcome; the exact ordered
events still go to the journal. Keep the command's actual exit status: the presence
of report files alone does not establish demo success.

The output root must be new beneath an existing physical parent. Use a different
root for another run. Existing roots, symlinks/reparse points, traversal and
control-bearing paths reject before server startup and preserve all prior bytes.
No browser, Docker target, external scanner executable or external service is
needed. The command stops its target after success, failure or Ctrl+C and retains
whatever actual evidence/model state was acquired before interruption.

## Inspect actual retained material

| Material                | Meaning                                                               |
| ----------------------- | --------------------------------------------------------------------- |
| `workspace/`            | Ordinary authoritative workspace, model, scopes and evidence stores   |
| `events.jsonl`          | Unchanged ordered product job events and its actual terminal summary  |
| `scan-summary.json`     | Actual Quick Scan terminal summary, including measured first update   |
| `workspace-open.json`   | Independent owner-read model and retained evidence verification       |
| `reports/model.json`    | Saved-model JSON projection with checked evidence references          |
| `reports/model.sarif`   | SARIF 2.1.0 from the same saved model                                 |
| `reports/*-export.json` | Export receipts, including status/digests/publication acknowledgement |
| `evidence-index.json`   | Real acquisition IDs, root-relative material paths and byte digests   |
| `target.json`           | Actual bind port, received request order/status and teardown receipt  |
| `demo-summary.json`     | Final retained demo outcome and actual product command receipts       |
| `workspace-create.json` | Actual workspace creation receipt                                     |
| `scope-create.json`     | Explicit short-lived command-owned synthetic consent receipt          |

A normal successful run retains one Host, one Port, one Service and three
Endpoints at model revision 3, with three actual acquisitions. Findings remain
empty: response status is discovery evidence, not a vulnerability judgment.
The empty SARIF `results` list preserves that fact and never means a clean target.
Both report formats retain `scan_completeness: not-assessed` under their existing
format contracts. Evidence-index material paths use the same ordinary
`workspace/evidence/blobs/sha256/<digest>` partition as the acquisition references.
The index is a derived navigation aid, not another evidence owner.

Reopening and exporting are offline and remain usable after the ephemeral target
stops and consent expires. For a fresh additional export, choose a new filename
outside the source workspace:

```bash
uv run --locked python -m fuzzy1337 report export artifacts/local-demo/workspace \
  --format json --output artifacts/local-demo/reports/reopened-model.json --json
```

The foreground shell can explicitly open the saved model and display a lens:

```text
model artifacts/local-demo/workspace
view model --json
lens pentest --json
```

Inspection uses an explicit saved snapshot. Reopen the model after further scans;
neither lens selection nor inspection silently launches a scanner.

## Run a real 1337Scope finding assessment

The assessment needs Python 3.13 or newer and the pinned FuzzyRoutines runtime
dependency. It starts its own service on `127.0.0.1` at an ephemeral port.
The two routes contain only constant nonsecret data:

| Selected route     | Actual response                                                   | Expected detector result              |
| ------------------ | ----------------------------------------------------------------- | ------------------------------------- |
| `/.git/HEAD`       | HTTP 200, plain text `ref: refs/heads/main` followed by a newline | One LOW Git metadata-exposure Finding |
| `/fixed/.git/HEAD` | HTTP 404, plain text `Not Found` followed by a newline            | No additional Finding                 |

The second URL is a different negative control. The first endpoint's Finding
remains open; this workflow does not demonstrate remediation of that endpoint.
Neither route reads the local filesystem or contacts another service. The check
performs one GET per endpoint, follows no redirects and expands no targets.
Each request has a two-second timeout, each scan job a ten-second deadline and
the ordinary recorded consent lasts two minutes.

### Inspect the finite plan

First create an ordinary parent for the new demo output, then display the plan.
Planning returns **3** for missing explicit approval. It does not create the demo
root, start the fixture or send a request.

Bash on Linux or macOS:

```bash
mkdir -p artifacts
uv run --locked python -m fuzzy1337 demo assessment artifacts/assessment-demo --json
```

PowerShell on Windows:

```powershell
New-Item -ItemType Directory -Force artifacts | Out-Null
uv run --locked python -m fuzzy1337 demo assessment artifacts/assessment-demo --json
```

The schema-one outcome identifies `command: demo.assessment`, `state: denied`,
`failure: approval_required`, `plan.impact: standard` and `plan.max_requests: 2`.
The closed command accepts no target URL. The SAFE flag belongs to `demo local`;
supplying it for this action returns configuration status **2** before execution.

### Approve and run the owned assessment

The following one-line command works in either shell:

```text
uv run --locked python -m fuzzy1337 demo assessment artifacts/assessment-demo --approve-standard-http
```

This explicit STANDARD approval covers only the fixed command-owned two-request
plan. The composition records ordinary current scope/consent and a policy for
`web.git-head-check` through `native.web-check`. For each endpoint it obtains and
retains the actual read-only product plan, then supplies that endpoint's own
exact confirmation intent. Reusing the first endpoint's confirmation for the
fixed endpoint is denied by the ordinary policy owner.

Successful human output reports `Assessment demo completed (exit 0)`, confirmed
target teardown, the retained output root and `One actual open LOW Finding`.
Add `--json` to receive one final machine-readable outcome instead. Keep the
actual exit status (`echo $?` in Bash or `$LASTEXITCODE` in PowerShell) before
running dependent commands. A nonzero result retains its actual partial work
and must be diagnosed before continuation.

### Inspect the offline result

Both native jobs must complete. The demo verifies the original registered
acquisition bytes and metadata, binds the Finding to the exact exposed endpoint,
successful provider job and scope, then checks that the separate control left
that Finding unchanged. It stops the fixture before reopening and exporting.
Every successful report receipt must match the same pinned model revision and
snapshot; concurrent changes refuse continuation without overwriting earlier
complete files.

| Material                                                          | Meaning                                                                              |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `workspace/`                                                      | Ordinary retained workspace, scopes, model and registered acquisitions               |
| `policy.json`                                                     | Single-capability STANDARD policy, separate from invocation confirmation             |
| `exposed-plan.json`, `fixed-plan.json`                            | Different actual per-endpoint policy/confirmation intents                            |
| `exposed-scan.json`, `fixed-scan.json`                            | Actual successful or refused native workflow receipts and job events                 |
| `assessment-checks.json`                                          | Original Finding reference, attribution, unchanged disposition and selected snapshot |
| `workspace-open.json`                                             | Actual offline workspace reopen after target shutdown                                |
| `reports/model.json`, `reports/model.html`, `reports/model.sarif` | Three exports of the same verified saved-model state                                 |
| `reports/*-export.json`                                           | Actual independent export, digest and publication acknowledgements                   |
| `evidence-index.json`                                             | Verified original material paths, digests and acquisition metadata                   |
| `target.json`                                                     | Actual two received routes/statuses and owned service teardown                       |
| `demo-summary.json`                                               | Final retained command outcome, subject to its publication acknowledgement           |

A successful run retains two Endpoints and one open LOW Finding at model
revision **2**, with four acquisitions: original native-worker stdout and stderr
for each job. These contain response metadata and hashes; HTTP response bodies
are not retained. The fixed control adds no Finding. The assessment outcome and reports
retain `scan_completeness: not-assessed`; no CVE applicability, attack path or
complete-scanner assessment is inferred.

Open `artifacts/assessment-demo/reports/model.html` in a browser after the
command exits. It is self-contained and needs no running target or network.
In PowerShell, use:

```powershell
Start-Process artifacts/assessment-demo/reports/model.html
```

Use `open artifacts/assessment-demo/reports/model.html` on macOS or
`xdg-open artifacts/assessment-demo/reports/model.html` on desktop Linux.
The installed workspace remains independently inspectable after shutdown:

```text
uv run --locked python -m fuzzy1337 workspace open artifacts/assessment-demo/workspace --json
```

For a later HTML export, select a fresh filename outside the saved workspace:

```text
uv run --locked python -m fuzzy1337 report export artifacts/assessment-demo/workspace --format html --output artifacts/assessment-demo/reports/reopened-model.html --json
```

An existing demo root returns **2** before another fixture starts and preserves
every prior byte. Select a new root for another complete run. Existing export
destinations are also refused. Successful files can remain after a later
failure: inspect the original command receipts, `output_published` and the
terminal outcome rather than treating file presence as successful completion.

## Failure and interruption truth

| Exit status | Meaning                                                                   |
| ----------- | ------------------------------------------------------------------------- |
| `0`         | Selected discovery/assessment, reopen, exports, index and teardown passed |
| `2`         | Invalid arguments/path or an ordinary product configuration error         |
| `3`         | Missing explicit opt-in or actual scope/consent/capability denial         |
| `4`         | Actual scan, evidence/storage, export/publication or teardown error       |
| `130`       | Interrupted demo after owned cleanup                                      |

Partial roots remain available for inspection. A preflight scan failure can
produce `scan-failure.json` instead of a Quick Scan job summary for `demo local`.
An interrupted local discovery may retain only its actual journal prefix and
saved model/evidence, without a fabricated terminal scan summary. An interrupted
assessment preserves completed per-endpoint receipts and actual retained model
state. Saved events and receipts do not add job restart, resumable scans or
persistent executor recovery.

Each export receipt retains the report owner's `output_published` flag. A report
may have been published before synchronization or cleanup failed; the demo keeps
that file and reports failure. Likewise, a final summary may have been published
before its publication acknowledgement failed: the terminal outcome/exit status
remains authoritative for that invocation and exposes
`summary_output_published`. No failure path rewrites acquired workspace state or
removes earlier complete material to suggest an atomic rollback.

Accepted sockets are owned and closed before service shutdown. Continuous partial
request progress cannot extend target lifetime indefinitely. Only bounded known
route names enter the target receipt; unsupported client paths are replaced by a
fixed marker. Cleanup failures prevent demo success even after scans and exports
completed.

## Reproducible verification and current limits

```bash
uv run --locked python -m pytest tests/unit/test_demo.py tests/e2e/test_demo_cli.py --no-cov
uv run --locked python -m pytest tests/unit/test_demo_assessment.py tests/e2e/test_demo_assessment_cli.py --no-cov
```

The E2E suite executes the real governed worker, jobs, saved model/evidence and
offline reports. It verifies denied current consent, no-clobber output, a real
published-report failure, Ctrl+C after the first actual saved delta, a continuing
partial HTTP request and teardown failure truth. Tests never scan Internet hosts.

`demo local` remains status-only discovery. `demo assessment` adds one finite
1337Scope metadata-exposure check with a real Finding and a separate negative
control. Its installed acceptance covers exact original custody, expired consent,
changed confirmation, corruption, interruption, no-clobber, lost publication
acknowledgement and real saved-model drift between report exports. Both actions
use owned local targets. Neither invokes an external scanner, browser rendering,
link traversal, authentication journey, CVE matching or attack-path inference.
PyPI publication, release acceptance and the complete M4 showcase remain separate
work.

See [Quick Scan](QUICK_SCAN.md), [offline report export](REPORT_EXPORT.md) and
[evidence](EVIDENCE.md) for the owning contracts.
