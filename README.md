# 1337 Security Workbench

![1337 Security Workbench by Fuzzy Technologies](docs/site/content/en/assets/images/1337-logo.png)

**1337 Security Workbench by Fuzzy Technologies** is a local-first security
workbench for human operators, CLI-capable AI agents and CI. Run explicitly
approved checks, keep the original evidence in a portable workspace, reopen its
Security Object Model, and export reports without contacting the target again.

> Models reason. 1337 keeps state, governs execution, and preserves evidence.

This branch prepares the **0.3.0 Community pre-alpha candidate**. It contains
workflows absent from the immutable [v0.2.1 release](https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.2.1).
A candidate is not a published release: retain the exact source revision, and see
[release delivery](docs/RELEASE_WORKFLOW.md) for the actual publication gates.
Apache-2.0 Community core; CPython 3.11 and newer; no mandatory runtime dependencies.

## What you can use now

| Task                             | Current interface                                                                | What you keep                                                                            |
| -------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| First local run                  | [`1337 demo local`](docs/DEMO.md)                                                | Owned loopback target, live events, saved model, three acquisitions, JSON/SARIF          |
| Discover selected HTTP endpoints | [`1337 scan quick`](docs/QUICK_SCAN.md)                                          | Status-only Host/Port/Service/Endpoint objects; explicit scope and SAFE approval         |
| Discover selected TCP ports      | [`1337 scan ports`](docs/PORT_SCAN.md)                                           | Governed optional Nmap TCP-connect output and original XML; exact STANDARD confirmation  |
| Check an owned web endpoint      | [`1337 scan web`](docs/NATIVE_WEB_CHECKS.md)                                     | Selected first-party checks, attributable Findings and evidence; exact plan confirmation |
| Scan an owned image archive      | [`1337 scan image --profile native`](docs/NATIVE_IMAGE_WORKFLOW.md)              | Optional offline Trivy inventory/Findings with explicit material, scope and policy       |
| Inspect and report offline       | [`workspace open`](docs/WORKSPACES.md), [`report export`](docs/REPORT_EXPORT.md) | Verified saved evidence; JSON, SARIF, HTML and JUnit from one model snapshot             |
| Gate a selected source           | [`1337 ci scan`](docs/CI_SCAN.md)                                                | Explicit finding predicate and separate execution/report outcomes                        |

Checks are bounded and selected; 1337 does not infer permission from a reachable
service. Discovery creates no vulnerability Finding merely because a port is open
or an endpoint responds. `scan_completeness: not-assessed` remains explicit.

The interactive `1337 shell` offers command discovery, history, model inspection
and lens context over the same state. The complete split-pane TUI, general MCP
service, autonomous target discovery, broad workflow lenses and M4 attack-path
showcase remain roadmap work. Experimental interfaces and compatibility classes
are documented in [Compatibility](docs/COMPATIBILITY.md).

## Install the candidate and do useful work

Until 0.3.0 is published, build a wheel from a reviewed checkout rather than
installing a differently versioned public package. Use a clean virtual environment:

```bash
git clone https://github.com/Fuzzy-Technologies/1337.git
cd 1337
git checkout YOUR_REVIEWED_COMMIT
git rev-parse HEAD
python -m pip install uv==0.11.33
uv build --wheel --out-dir dist
python -m venv .venv-demo
.venv-demo/bin/python -m pip install --no-deps dist/1337-*.whl
.venv-demo/bin/1337 --version
.venv-demo/bin/1337 doctor
```

On Windows use `.venv-demo\Scripts\python.exe` and
`.venv-demo\Scripts\1337.exe`. Build one selected revision in a fresh output
directory; select its exact wheel if other files are present. Version metadata
alone does not identify an unreleased source revision.

Activate the environment (`source .venv-demo/bin/activate`, or
`.venv-demo\Scripts\Activate.ps1` in PowerShell), then preview the demo:

```bash
mkdir artifacts
1337 demo local artifacts/first-run --json
```

Expected: exit **3**, `failure: approval_required`, and no `first-run` directory.
Review the printed plan: three anonymous status-only GETs to the command's own
`127.0.0.1` service; no external target, browser, Docker, model API or scanner needed.
If you approve that plan, execute it and inspect its durable result:

```bash
1337 demo local artifacts/first-run --approve-safe-http --json
1337 workspace open artifacts/first-run/workspace --json
1337 report export artifacts/first-run/workspace \
  --format html --output artifacts/first-run.html --json
```

Expected: exit **0** for each command, confirmed target teardown, model revision
**3**, one Host, one Port, one Service, three Endpoints, zero Findings and three
verified evidence records. Open `artifacts/first-run.html`; retain the whole
`first-run/` bundle. Reopen/export run offline after the owned target stops.
Every output must be new: an existing destination is refused, preserving its bytes.

## Choose your operator path

- **Human:** [Quickstart](docs/QUICKSTART.md) — installation, first result, shell inspection and next recipes.
- **AI agent:** [Agent quickstart](docs/AGENT_QUICKSTART.md) — copyable EN prompt, RU/zh-cn draft prompts, explicit operator approval and evidence-linked JSON.
- **CI:** [CI quickstart](docs/CI_QUICKSTART.md) — Docker wheel install, GitHub Actions/GitLab templates, predeclared local-demo approval and retained diagnostics.

All three use the same scope/policy, jobs, evidence and persisted model owners.
No mandatory check calls a paid LLM or grades model output.

## Next hands-on workflows

Use [the owned HTTP recipe](docs/QUICK_SCAN.md#run-an-owned-localhost-example)
for your own explicitly selected local endpoint. For optional tools and checks,
start with [prerequisites and bounded recipes](docs/QUICKSTART.md#choose-the-next-recipe):
Nmap needs an operator-supplied executable and STANDARD policy; native web checks
need an exact approved plan; native Trivy needs Linux ownership support, a selected
local archive and pre-provisioned offline database. None is installed implicitly.

[Documentation and API reference](https://fuzzy-technologies.github.io/1337/)
follow published `master`. Candidate commands belong to the same source revision's
`docs/`; [v0.2.1 documentation](https://github.com/Fuzzy-Technologies/1337/tree/v0.2.1/docs)
remains the reproducible older release guide. English is canonical; API RU/zh-cn
routes currently identify English fallback content explicitly.

## Direction

1337 organizes security work around the Security Object Model: tools contribute
observations and evidence; operators inspect relationships, Findings and reports.
The intended lenses are Pentest, DFIR, DevSecOps and Purple Team. A lens changes
focus over shared state and never grants execution permission.

| Milestone                                                                                                                  | Focus                                                                              |
| -------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| [M0](https://github.com/Fuzzy-Technologies/1337/milestone/1), [M1](https://github.com/Fuzzy-Technologies/1337/milestone/2) | Completed foundation, Community Core and Shell                                     |
| [M2](https://github.com/Fuzzy-Technologies/1337/milestone/3)                                                               | Execution, Discovery and Security Object Model MVP; release acceptance in progress |
| [M3](https://github.com/Fuzzy-Technologies/1337/milestone/4)                                                               | Evidence, Intelligence and Mapping                                                 |
| [M4](https://github.com/Fuzzy-Technologies/1337/milestone/5)                                                               | Advanced Discovery and Attack Paths                                                |
| M5–M9                                                                                                                      | Analytical UX, integrations/AI, validation, DFIR and enterprise contracts          |

Detailed scope and acceptance live in GitHub issues. See [Vision](docs/VISION.md),
[architecture decisions](docs/adr/), [Development protocol](DEVELOPMENT_PROTOCOL.md)
and [Security policy](SECURITY.md) before contributing or reporting a vulnerability.
