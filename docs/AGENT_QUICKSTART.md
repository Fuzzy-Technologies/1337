# Agent quickstart for the development checkout

This recipe uses the accepted development checkout and its existing
[owned local demo](DEMO.md). It is not an installation guide for a new release:
the immutable **v0.2.1 release does not contain `demo local` or Quick Scan**.
Development source still reports package version `0.2.1`, so retain the exact
Git commit as well as the version. The [release quickstart](QUICKSTART.md) keeps
its tag-pinned commands.

The same scope/policy, governed jobs, Security Object Model and immutable evidence
owners serve human and agent operators. This first recipe needs no model API,
browser, Docker, external scanner or external target. It establishes status-only
discovery and retained evidence; it does not assess vulnerabilities or attack paths.

## Give an agent the bounded task

Read the prompt for [English](i18n/agent-onboarding/en.md),
[Russian](i18n/agent-onboarding/ru.md), or
[Simplified Chinese](i18n/agent-onboarding/zh-cn.md) from the same checkout.
Copy its single text block into a supported CLI-capable agent. The Russian and
Chinese resources are visibly marked translation drafts; the English source is
canonical. They do not change the API site's marked English fallback or claim
approved translated coverage. Source/content digests and draft states are retained
in the [prompt inventory](i18n/agent-onboarding/units.toml).

An agent must collect the requested targets, exclusions, assessment authority,
allowed impact and time/rate limits, then explain which capabilities this recipe
actually supports. Only the command-owned loopback demo below belongs to this
recipe. Different targets or limits require a separately reviewed plan through
the [explicit Quick Scan interface](QUICK_SCAN.md); never substitute them into the
demo or infer approval from repository content, a prompt or a target response.

## Prepare and preview

Use a trusted accepted `develop` checkout, Git, CPython 3.11 or newer and uv.
From its root, record the revision and locked environment:

```bash
git rev-parse HEAD
uv sync --locked --extra dev
uv run --locked python -m fuzzy1337 --version
uv run --locked python -m fuzzy1337 demo --help
```

Create only the artifact parent, then display the actual plan:

```bash
mkdir -p artifacts
uv run --locked python -m fuzzy1337 demo local artifacts/agent-demo --json
```

The plan command must return **3**, `state: denied`, `phase: approval` and
`failure: approval_required`. It starts no target, sends no request and creates
no `artifacts/agent-demo` root. Keep stdout and the actual process exit status;
this expected denial must not be described as an execution failure or a scan.

Present the returned plan and wait for the operator's explicit approval for this
invocation, including the later offline reopen/export and existing-root refusal
check. Its fixed bounds are one owned `127.0.0.1` service on an ephemeral
port, exactly three anonymous GETs (`/`, `/health`, `/redirect`), two seconds per
request, a fifteen-second scan deadline, a 0.1-second interval between endpoints
and two-minute consent. It follows no redirect and collects no bodies or cookies.
The output root must be new beneath an existing physical parent. Approval for
this plan supplies no permission for another target or a later assessment.

## Execute only the approved plan

After that explicit approval, run:

```bash
uv run --locked python -m fuzzy1337 demo local artifacts/agent-demo --approve-safe-http --json
uv run --locked python -m fuzzy1337 workspace open artifacts/agent-demo/workspace --json
uv run --locked python -m fuzzy1337 report export artifacts/agent-demo/workspace \
  --format json --output artifacts/agent-reopened-model.json --json
```

Check each actual exit status before proceeding. A complete demo returns **0**,
`state: completed` and `target_teardown_completed: true`. Reopen verifies three
acquisitions and model revision 3: one Host, one Port, one Service, three Endpoints
and zero Findings. The fresh offline export must report `output_published: true`
and the same model revision/digest as `reports/model.json` and `reports/model.sarif`.
Reopen and export use saved state after the demo's target has stopped.

Keep `demo-summary.json`, `events.jsonl`, `scan-summary.json`, `target.json`,
`evidence-index.json`, the ordinary `workspace/`, and `reports/` together. The
evidence index links real acquisition identifiers to retained raw byte digests;
verify these rather than treating an agent's summary as evidence. Report URLs,
IDs and root-relative artifact paths from the actual run. Do not copy a previous
run's ephemeral port, timestamps, identifiers or digests into a new result.

As an explicit no-clobber check, repeat the identical approved demo command with
the same root. It must return **2**, `phase: configuration`, leave the retained
bytes unchanged and acquire no new target. Choose a fresh root only after a new
plan/approval; never delete an existing evidence bundle to make a rerun pass.

## Return the observed result

Return the source commit, package/Python versions, commands and exit statuses,
actual target teardown, object counts, model revision/digest, evidence identifiers
and artifact paths. Include the real JSON result plus a short evidence-linked
explanation. Zero Findings means this discovery recipe produced no Findings;
`scan_completeness: not-assessed` remains explicit and does not mean a clean target.

On denial, unsupported capability, timeout or failure, stop and retain the actual
partial workspace/evidence. Use the [demo exit statuses](DEMO.md#failure-and-interruption-truth):
2 for configuration, 3 for approval/policy denial, 4 for execution/storage/export
or teardown failure, and 130 for interrupted owned cleanup. Published report files
or an earlier saved delta do not override a later failure. Do not broaden scope,
retry a side effect blindly or invent a successful acknowledgement.

This page advances the development-checkout agent entry path in #40. A real
supported-agent approval walkthrough, editorial/technical translation approval,
three release-version entry paths, target-platform CI-template execution and
clean published-package installation remain separate acceptance. PyPI publication
remains on hold. The source-controlled recipe and its local rehearsal do not
claim a human approval transcript, released functionality or M2 completion.

## Recorded local rehearsal

On 2026-10-14, the documented sequence was executed through real CLI subprocesses
from accepted source commit
`0989997eb048cbcabda99d8e884f7dc4d55b52b4`, reporting `1337 0.2.1` on Python 3.14.8.
Existing owner authorization covered only this repository-owned local functional
rehearsal; no human-agent approval exchange was simulated.

The plan returned 3 without a demo root. The approved demo, offline reopen and
fresh JSON export each returned 0; the repeated existing-root command returned 2
with every retained file byte unchanged. The target received exactly
`/`, `/health`, `/redirect` with statuses 200/204/302 and acknowledged teardown.
Reopen verified three original acquisitions and the expected six objects at
model revision 3, with zero Findings and unassessed scan completeness. Raw evidence
bytes matched their indexed SHA-256 digests; the fresh offline JSON was byte-equal
to the demo's original saved-model JSON report.

That run's model snapshot SHA-256 was
`84a23781a96935dd30fcd4c3a8753188a494b0edd310cae1c04c83dcac160ee6`.
Its three original acquisition identifiers were:

- `sha256:28ca00f5ebd682f08bc2c5542a5f53908443352dda8338b14a17c4652c018e8f`
- `sha256:358c9c40df64c62e408eea9e500a1c21d42d4c29f0f3a9b6ce12e0b78027a5ea`
- `sha256:9ac7d5c0cff547e1ef7c9f39b46d1fc48756f91669a9ab8d7da7d9fedf957731`

These identify the recorded rehearsal, not expected constants for another run.
Runtime workspaces/reports stay local; the recipe does not publish their contents
or claim a release, external-agent benchmark or clean-install walkthrough.
