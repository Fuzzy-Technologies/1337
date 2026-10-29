# AI agent quickstart — 0.3.0

Use a CLI-capable external agent with installed 1337 0.3.0.
The [human quickstart](QUICKSTART.md#install-a-reviewed-wheel) supplies installation;
[CI onboarding](CI_QUICKSTART.md) uses the same local scenario non-interactively.
No model API, MCP server, browser, Docker or external scanner is needed by 1337.
The immutable v0.2.1 lacks this recipe; retain the source commit, wheel identity
and actual installed package version.

This guide targets **1337 0.3.0**. Use
`python -m pip install 1337==0.3.0` in a clean environment and require
`1337 --version` to report `1337 0.3.0`. For development builds, use the exact
reviewed source-wheel path in the human guide. Never substitute an older package
when these commands are unavailable. For the release, retain the installed wheel hash
and use [tag-pinned instructions](https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/AGENT_QUICKSTART.md);
development work must retain its full reviewed source commit instead.

Human and agent operators use the same scope/policy, jobs, immutable evidence
and durable model. The first task establishes status-only discovery; it does not
assess vulnerabilities or attack paths.

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

Install the reviewed wheel as described in the human quickstart, activate that
environment, and record the source commit alongside these installed commands:

```bash
1337 --version
1337 doctor
1337 demo --help
```

Create only the artifact parent, then display the actual plan:

```bash
mkdir -p artifacts
1337 demo local artifacts/agent-demo --json
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
1337 demo local artifacts/agent-demo --approve-safe-http --json
1337 workspace open artifacts/agent-demo/workspace --json
1337 report export artifacts/agent-demo/workspace \
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

Release validation distinguishes actual supported-agent walkthroughs, installed
artifact checks, target-platform CI runs and localization review states.
A prompt or local rehearsal alone does not establish all those outcomes.
See the [CI quickstart](CI_QUICKSTART.md#acceptance-evidence) for the honest
execution boundary. RU/zh-cn resources remain explicitly marked drafts until
editorial and technical review provenance is recorded for their exact digests.

After the first discovery, the installed core can also produce a useful
attributable Finding through the [owned Git HEAD recipe](OWNED_GIT_HEAD_RECIPE.md).
Its STANDARD policy and two exact positive/fixed plans require their own approval;
approval for this demo does not carry over. For optional Nmap, Trivy, configuration
or offline inventory work, collect the stated prerequisites and follow the
[human recipe index](QUICKSTART.md#choose-the-next-recipe). Reject unsupported
requests instead of inventing commands or silently running a raw shell scanner.

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

## Recorded delegated 0.3.0 walkthrough

On 2026-10-29, a CLI-capable Codex agent built source
`9f5bb04270fb81f42db4c0140f02f9cd591b9fc5`, installed its `0.3.0` wheel in a clean
environment outside the checkout, and executed this entry path on Python 3.12.14.
The wheel SHA-256 was
`676ee604e325bb0459366bb4a60727ab977bd84e8b5c4dd4913a2ab6c5a661b0`.

The agent first returned the actual denied plan, then waited for and received
explicit integration-coordinator approval under the owner's finite development
mandate. This was a real delegated-agent approval boundary; it was not a direct
human approval exchange. Plan/demo/reopen/export/existing-root statuses were
**3/0/0/0/2**. The three original acquisitions were independently hash-verified;
the fresh JSON export matched the saved report. The owned target acknowledged
teardown and its exact loopback port refused a subsequent connection. The refused
repeat preserved all 21 retained files.

The model retained revision 3, six objects, zero Findings and unassessed scan
completeness. Its observed snapshot SHA-256 was
`6e80ecd25f2a869d301c4cee1631f8dff7179192343aa0105110afa2b0f68a6b`.
Original command receipts, approval text and the verification summary were
retained together. This candidate-wheel walkthrough is separate from final
composed-source CI and clean installation of the published PyPI artifacts.
