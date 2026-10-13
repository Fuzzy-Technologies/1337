# Owned local Workbench demo

The current development candidate provides one reproducible command-owned local
demo, defined by [ADR 0054](adr/0054-owned-local-workbench-demo.md). It composes the
existing native SAFE Quick Scan and saved-workspace report export interfaces.
This command is not present in the immutable v0.2.1 release. It is one local
onboarding slice of #40; the M4 attack-path-mini showcase #118–#125 remains separate.

## Run from the accepted development source

Use a current accepted `develop` checkout with the project's locked developer
environment (`uv sync --locked --extra dev`). No PyPI installation is needed.
From the checkout root, first display the exact plan without granting consent:

```bash
mkdir -p artifacts
uv run --locked python -m fuzzy1337 demo local artifacts/local-demo
```

The plan-only invocation returns status 3. It starts no target, sends no request
and creates no demo output root. The plan owns a synthetic service bound only to
`127.0.0.1` on an ephemeral port; native discovery issues exactly three anonymous
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

## Failure and interruption truth

| Exit status | Meaning                                                             |
| ----------- | ------------------------------------------------------------------- |
| `0`         | Discovery, independent reopen, exports, index and teardown passed   |
| `2`         | Invalid arguments/path or an ordinary product configuration error   |
| `3`         | Missing explicit opt-in or actual scope/consent/capability denial   |
| `4`         | Actual scan, evidence/storage, export/publication or teardown error |
| `130`       | Interrupted demo after owned cleanup                                |

Partial roots remain available for inspection. A preflight scan failure can
produce `scan-failure.json` instead of a Quick Scan job summary. An interruption
before the scan returned may leave only the actual journal prefix and saved
model/evidence, without a fabricated terminal scan summary. Saved event history
does not add job restart, resumable scans or persistent executor recovery.

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
```

The E2E suite executes the real governed worker, jobs, saved model/evidence and
offline reports. It verifies denied current consent, no-clobber output, a real
published-report failure, Ctrl+C after the first actual saved delta, a continuing
partial HTTP request and teardown failure truth. Tests never scan Internet hosts.

The current command demonstrates status-only endpoint discovery and evidence-led
offline export. It does not run Nuclei, Trivy or Nmap, collect HTML, traverse links,
render a browser, authenticate a user journey, perform native vulnerability
checks or assert attack paths. Webengine page capture and later scanner/demo
integration require their own accepted implementation and evidence. PyPI
publication, release acceptance and the complete M4 showcase are separate work.

See [Quick Scan](QUICK_SCAN.md), [offline report export](REPORT_EXPORT.md) and
[evidence](EVIDENCE.md) for the owning contracts.
