# Human quickstart — 0.3.0

Start with one owned local target, retain its evidence, then inspect the saved
model after the target has stopped. Version 0.3.0 supports the same workflow for
[AI agents](AGENT_QUICKSTART.md) and [CI](CI_QUICKSTART.md).
The immutable v0.2.1 release lacks these scan/demo commands; use its
[tag-pinned guide](https://github.com/Fuzzy-Technologies/1337/blob/v0.2.1/docs/QUICKSTART.md)
when running that release. Use the documentation from the same installed version
or reviewed development source revision.

## Install a reviewed wheel

CPython 3.11 or newer is required. Install the exact distribution in a clean
environment:

```bash
python -m venv .venv-demo
source .venv-demo/bin/activate
python -m pip install 1337==0.3.0
1337 --version
1337 doctor
```

Expect `1337 0.3.0`; do not silently install a different version. For development
builds, use the reviewed source-wheel path below and retain the full source SHA.
Git is needed only for that source build. The base wheel
has no runtime dependencies. Docker, Nmap, Trivy, browsers and a model API are
unnecessary for the first recipe.

```bash
git clone https://github.com/Fuzzy-Technologies/1337.git
cd 1337
git checkout YOUR_REVIEWED_COMMIT
git rev-parse HEAD
python -m pip install uv==0.11.33
uv build --wheel --out-dir dist
python -m venv .venv-demo
.venv-demo/bin/python -m pip install --no-deps dist/1337-*.whl
source .venv-demo/bin/activate
1337 --version
1337 doctor
```

Build into a fresh directory and retain the exact commit/wheel identity. On
Windows use `.venv-demo\Scripts\python.exe` and activate with
`.venv-demo\Scripts\Activate.ps1`. Select the exact wheel filename in PowerShell.
`doctor` checks local health; missing optional Docker is a warning.
For development instead, use `uv sync --locked --extra dev` and prefix commands
with `uv run --locked`; do not confuse an editable checkout with clean wheel proof.

## Preview, approve and run

Create an artifact parent and display the actual plan:

```bash
mkdir artifacts
1337 demo local artifacts/first-run --json
```

This returns **3**, `state: denied`, `phase: approval` and
`failure: approval_required`. No target starts and no `first-run` root is created.
Review the returned plan before continuing. It owns one ephemeral loopback service
and exactly three GETs (`/`, `/health`, `/redirect`), with two seconds per request,
fifteen seconds for scanning, a 0.1-second interval and two-minute consent. It
follows no redirects and collects no response bodies or cookies.

If you approve this exact owned plan:

```bash
1337 demo local artifacts/first-run --approve-safe-http --json
1337 workspace open artifacts/first-run/workspace --json
1337 report export artifacts/first-run/workspace \
  --format html --output artifacts/first-run.html --json
1337 report export artifacts/first-run/workspace \
  --format json --output artifacts/first-run-reopened.json --json
```

Each command should return **0**. Demo success includes
`target_teardown_completed: true`. Reopen reports `model_revision: 3`, three
`verified_evidence_records`, one Host, one Port, one Service, three Endpoints and
zero Findings. Exports report `output_published: true`; the fresh JSON represents
the same snapshot as `first-run/reports/model.json` and `model.sarif`.
Open the HTML report to read the discovered objects and evidence references.

Keep the complete `first-run/` directory, including `workspace/`, `events.jsonl`,
`target.json`, `evidence-index.json`, reports and command receipts. The index points
to original acquired bytes and digests. Reopen and export need no running target
or unexpired scan consent. A successful discovery is not a vulnerability assessment:
zero Findings and `scan_completeness: not-assessed` never establish a clean target.

Existing roots/files are refused. Repeating the approved demo against `first-run`
returns **2** without replacing evidence. Choose a new root for a new approved run.
On failure retain partial material and the actual process status; do not delete
it to make a rerun succeed. [Demo recovery](DEMO.md#failure-and-interruption-truth)
distinguishes configuration 2, denied 3, failed 4 and cancelled 130.

## Inspect through the shell

Run `1337 shell`, then enter:

```text
model artifacts/first-run/workspace
view model --json
lens pentest --json
context
history
quit
```

The shell opens a saved snapshot; reopen it after later scans. Lens selection
changes the view without starting discovery or granting permission. The full
concurrent split-pane workbench remains separate roadmap work.

## Produce one real Finding

Follow the [complete owned Git HEAD recipe](OWNED_GIT_HEAD_RECIPE.md) with the
same installed core. Copy its stdlib loopback fixture and explicit policy, create
scope, inspect and approve the actual STANDARD plans, then observe one LOW Git
metadata exposure Finding. A separately approved fixed HTTP 404 control adds no
Finding. The fixture stops after those two requests; inspect JSON/HTML/SARIF and
verified workspace state offline. This recipe requires no optional scanner,
browser, Docker, model API or checkout at runtime.

## Choose the next recipe

| Recipe                                                              | Actual prerequisites and limits                                                                                                     | Follow-through                                                                   |
| ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| [Owned HTTP endpoint](QUICK_SCAN.md#run-an-owned-localhost-example) | Python local service; selected literal-IP URLs and IP, current consent, independent SAFE opt-in; status only                        | Create scope, run `scan quick`, reopen saved model                               |
| [First-party web check](OWNED_GIT_HEAD_RECIPE.md)                   | Owned explicit endpoint and existing scope; selected STANDARD policy; printed exact confirmation intent                             | Plan `scan web`, approve unchanged selection, inspect attributable Findings      |
| [TCP ports](PORT_SCAN.md#consent-and-exact-confirmation)            | Trusted absolute Nmap executable, owned literal IP, 1–1024 explicit ports, STANDARD policy and exact confirmation                   | Plan `scan ports`, confirm, retain original XML and reopen                       |
| [Native image](NATIVE_IMAGE_WORKFLOW.md#preview-register-and-plan)  | Supported Linux descendant ownership; provisioned Trivy, local archive/cache/database, explicit read consent, scope and SAFE policy | Preview material, register exact ARTIFACT target, plan/run image workflow        |
| [Local image reference](LOCAL_IMAGE_REFERENCE.md)                   | Supported Linux ownership; explicitly selected Docker executable/socket/reference; export scope, consent and SAFE policy            | Export immutable archive/config pin, then independently authorize native scan    |
| [Native configuration](NATIVE_CONFIGURATION.md)                     | Linux amd64; selected pinned Trivy and UTF-8 Dockerfile/rendered Kubernetes file up to 4096 bytes; consent, scope and SAFE policy   | Preview exact material, register target, scan and inspect source-linked Findings |
| [Saved image packages](IMAGE_SBOM_VIEW.md)                          | Existing saved image and verified original SBOM/image evidence; exact config or manifest digest and kind                            | Inspect nested inventory and supplied Docker associations without execution      |
| [Native Nmap arguments](RAW_CLI.md)                                 | Trusted Nmap executable, one literal IP, explicit ports, finite supported flags, STANDARD policy and separate intent confirmation   | Preserve native argv/output/status, then verify original receipt offline         |
| [Finding gate](CI_SCAN.md)                                          | Already approved source/workspace plus explicit severities/statuses/threshold and completeness acknowledgement                      | Save JSON/SARIF/JUnit, interpret predicate separately from execution failure     |

These are separate selected operations. The first demo does not run the optional
providers, assess exploitability, authenticate a user journey or assert attack paths.
Configuration scanning supplies no Helm, Kustomize or template renderer. Saved
license declarations are facts, not license-policy decisions; runtime reachability
remains unknown. These broader SBOM/runtime semantics are deferred to M4.
For offline export formats and no-clobber destinations, see [report export](REPORT_EXPORT.md).
