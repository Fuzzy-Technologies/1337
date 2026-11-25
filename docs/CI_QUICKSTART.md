# CI quickstart — 0.3.0

Run the same [owned local demo](DEMO.md) as the [human](QUICKSTART.md) and
[agent](AGENT_QUICKSTART.md) paths. Build a wheel from one immutable reviewed
revision, install only that wheel in Docker and retain its actual JSON, saved
workspace, original evidence and reports. No model API or paid LLM is involved.
This verifies a selected local recipe; production target selection requires its
own explicit scope, consent, policy and limits.

## Copy the platform template

- [GitHub Actions YAML](examples/ci/github-actions.yml): copy to `.github/workflows/1337-demo.yml` in the invoking repository; start with `workflow_dispatch`.
- [GitLab CI YAML](examples/ci/gitlab-ci.yml): copy/include in `.gitlab-ci.yml`; use a trusted Linux shell runner tagged `docker-shell`, with Git, Python 3 and Docker available. Start an authenticated manual web/API pipeline.

Select `RELEASE_COMMIT` / `release_commit` as the reviewed full 40-character commit
for the intended release. Resolve `v0.3.0` to its full commit before configuring
the template; do not substitute a moving `develop` or an unverified tag string.
For development builds use the full reviewed source commit. Fetch verifies that
exact commit.
Select `PYTHON_IMAGE` / `python_image` as an approved Python 3.13-or-newer slim
image pinned by `@sha256:<64 hex>`. Do not use an unpinned image tag. Keep these
non-secret inputs in pipeline configuration; add no credential to the demo bundle.

The included [Dockerfile](examples/ci/Dockerfile) builds with locked project tools,
then installs the resulting wheel without runtime dependencies in a separate
image stage. Runtime uses `--network none`, drops capabilities and enables
`no-new-privileges`; loopback remains available for the command-owned service.
No target port is published. Build may download trusted packaging dependencies;
the demo container makes no external contact.

Set the GitHub dispatch input `approved_local_demo` to true or the GitLab
pipeline variable `F1337_APPROVED_LOCAL_DEMO=1` only after reviewing the plan.
Neither template grants approval when that operator input is absent. This is approval
only for the fixed local plan documented in [Demo](DEMO.md): one owned ephemeral
loopback service, three anonymous status-only GETs, two-second request timeout,
fifteen-second scan bound, 0.1-second interval, two-minute consent, no redirect
following or bodies/cookies. Review that declaration before enabling the template.
It grants no authority for an arbitrary target. Leave the GitHub input false or omit the GitLab variable to verify
fail-closed refusal before any target or demo output root is created.

## What the runner actually checks

The [stdlib harness](examples/ci/run_demo.py) calls the installed package through
`python -I -m fuzzy1337`; it does not import the checkout or run fixture providers.
It records the actual installed version, Python runtime and `doctor` output,
then preserves stdout, stderr and process status for each workflow invocation:

| Step                           | Expected result                                                                |
| ------------------------------ | ------------------------------------------------------------------------------ |
| Unapproved `demo local --json` | Exit 3, schema 1, `approval_required`, no target/output root                   |
| Approved demo                  | Exit 0, `completed`, confirmed target teardown                                 |
| Offline `workspace open`       | Exit 0, revision 3, three verified acquisitions, six objects and zero Findings |
| Fresh offline JSON export      | Exit 0, acknowledged publication, bytes equal to original saved-model JSON     |
| Repeat existing root           | Exit 2, configuration refusal, identical retained file digests                 |

The harness independently verifies indexed raw byte lengths/SHA-256 digests and
exact target requests/statuses (200/204/302). [`ci-result.json` schema](examples/ci/ci-result.schema.json) is version 1
and records counts, snapshot digest, teardown and no-clobber verification. Keep
the complete artifact, including all product command receipts and partial state.
Both templates upload available diagnostics even if execution fails. This recipe
uses synthetic public material only; for real work, raw evidence may be sensitive
and requires an explicitly reviewed artifact retention/access policy.

Harness exit 0 means the recipe matched these observations; 3 means predeclared
approval is missing; 4 means a command or independent verification failed.
The original command status remains in each `*-process.json`. Invalid harness
arguments return 2. A runner/container failure can prevent a final summary;
missing summary is never success.

The GitHub template runs an unconditional teardown readback after its bounded
owned cleanup trap. It queries only the exact run-ID/attempt container name and
image tag; either remaining resource or a failed Docker query fails that step.
Only successful readback writes `artifacts/owned-teardown.json`. Retain that
original alongside the product receipts; a best-effort cleanup trap or green
workflow header alone does not prove teardown.

## Optional GitLab report from a saved workspace

The [retained-report template](examples/ci/gitlab-retained-report.yml) exports an
**existing** saved workspace. It starts no target or scanner, installs nothing,
and needs no token. Including its hidden `.1337-retained-report` job schedules
nothing. Copy the file into your repository from a reviewed immutable revision,
then explicitly opt in with a concrete job:

```yaml
include:
  - local: ci/gitlab-retained-report.yml

retained-security-report:
  extends: .1337-retained-report
  needs:
    - job: saved-workspace
      artifacts: true
  variables:
    F1337_SAVED_WORKSPACE: retained-workspace
```

Here `saved-workspace` is your existing artifact producer, not a new scan recipe.
Provide a trusted runner/runtime with Python 3.13 or newer and an already
installed approved 1337 wheel. Retain the complete workspace and evidence at the
selected project-relative path; freeze it while exporting. The hidden job does
not inherit default setup, services or cleanup. Configure your own stage, runtime,
runner and artifact access/retention policy before enabling it. Exported JSON
contains retained model/provenance facts and may contain sensitive information.

The job invokes the existing offline CLI entry point for JSON and JUnit, checks
both receipts describe the same snapshot and verification counts, and publishes
one complete bundle only after both exports succeed. It retains the original
CLI receipts and full canonical `report.json` alongside `report.junit.xml`.
The JSON retains evidence references and integrity facts, not raw evidence bytes;
keep the producer's complete saved workspace separately for later reopening.
Missing/corrupt evidence, mismatched snapshots or an oversized JUnit projection
fail the job without publishing a partial bundle. The numeric
`1337-retained-report-$CI_JOB_ID` directory is reserved exclusively for this job;
never put a workspace there or select the project root as input. Every invocation
first retires any older bundle outside artifact selection, before validating the
source; the reserved namespace is moved even when selected as an invalid input.
GitLab uploads report artifacts regardless of job status, so `when: on_success`
alone cannot prevent an older JUnit report from being uploaded after a failure. GitLab retries normally receive a new job ID. Temporary staging is
removed on normal failure; interrupted staging is outside artifact paths.

GitLab's [Tests UI](https://docs.gitlab.com/ci/testing/unit_test_reports/) displays
this existing JUnit **finding adapter**: one fingerprint-named case per retained
finding, grouped by check ID; open/confirmed findings are failures and
resolved/dismissed findings are skipped. These are saved interpretations, not
newly executed tests. Zero findings means zero cases, not a clean scan. Export
success exits zero even when JUnit has failures; this job adds no finding threshold
to the caller's pipeline. GitLab's MR comparison needs a target-branch baseline.
GitLab ignores JUnit properties: snapshot identity, evidence verification,
unknown severity, original execution failures and full provenance remain in the
JSON/receipts and XML download, not a GitLab security dashboard.

This is not a Code Quality or vulnerability report. GitLab's
[Code Quality format](https://docs.gitlab.com/ci/testing/code_quality/) requires
repository-relative source paths, actual line numbers and its own severity enum;
generic saved findings do not establish those facts. This template invents no
file/line, severity conversion or repository binding. Local template/fixture
checks do not establish acceptance by a live GitLab runner.

## Optional GitHub artifact from a saved workspace

The [saved-model composite action](examples/ci/github-retained-report/action.yml)
exports an already retained workspace in the **same existing job** that has your
approved installed runtime and complete saved files. Copy its directory from a
reviewed immutable revision to `ci/1337-retained-report` in the invoking
repository. After your existing setup/download steps, explicitly call it:

```yaml
# Under your existing trusted Linux job:
permissions:
  contents: read
steps:
  # Keep your existing runtime/workspace provisioning steps here.
  - name: Export retained model
    id: retained
    uses: ./ci/1337-retained-report
    with:
      saved_workspace: retained-workspace
      report_key: retained-main-model
```

This is a job fragment, not a new automatic workflow. Copying the composite adds
no trigger or job. The caller controls scheduling, trusted setup and artifact
access/retention; the action starts no scanner/container, installs/downloads
nothing and requests no repository write permission or `GITHUB_TOKEN`. Use
Python 3.13 or newer with an approved installed wheel that contains the Internal
`fuzzy1337.retained_report_ci` helper. Both retained examples share this packaged
owner; the GitLab include needs no checkout of a separate script. Existing
`1337` entry points and JSON/JUnit/receipt schemas are unchanged.

`saved_workspace` selects complete input inside `github.workspace`; the project
root and reserved output namespace are refused. Freeze the input during export.
`report_key` is required and must be unique across callers and matrix jobs in a
run: 1–64 letters, digits, underscores or hyphens, starting with a letter or digit.
The action reserves `1337-retained-report-<run-id>-<attempt>-<key>` for output,
retires older local output before package import, and rechecks report bytes and
original receipts after both CLI exports. Only a complete bundle is published;
the upload step also requires the export step to finish successfully. Unsafe keys,
missing/corrupt source, changed snapshots and altered staged outputs fail closed.

One pinned `upload-artifact` step uploads only that complete bundle, with
`if-no-files-found: error`, no overwrite and seven-day retention. A hosted name
collision is an error. The `artifact-id`, `artifact-url` and `artifact-digest`
outputs are the original acknowledgements from that action. Its digest identifies
the uploaded archive; the original `json-export.json` and `junit-export.json`
receipts separately identify each report's byte length, SHA-256 and canonical
snapshot. Download the artifact and compare those facts when reviewing it.

GitHub presents **one downloadable artifact**. This sample does not publish JUnit
into Checks, annotations, code scanning or a security dashboard. The retained
finding dispositions and original source failures have the same JSON/JUnit
meaning described above; export success adds no finding threshold. Preserve the
complete producer workspace separately, including original evidence. Local
installed-wheel/shell checks establish export and upload selection only; an actual
hosted run and its upload acknowledgement remain separate acceptance evidence.

## Optional finding thresholds

The demo creates no Findings and has no vulnerability threshold. For a selected
configuration/image gate, use [the explicit `1337 ci scan` interface](CI_SCAN.md)
with its required source authority, severity/status sets, `--max-matches` and
completeness acknowledgement. Its exit **1** means a completed source predicate
was violated; exits **2/3/4/130** mean configuration/denial/failure/cancellation.
Do not convert those execution errors to a finding-threshold pass. Report JUnit
failure counts and the selected source predicate are separate facts.

## Acceptance evidence

Source-wheel rehearsals and deterministic tests validate the product/harness
contracts. They do not establish GitHub-hosted or GitLab runner acceptance.
The release gate must run each copied YAML on its named platform with a digest-
pinned image and final release commit, retain job URLs/artifacts and validate the
approved and missing-approval cases. Platform execution is an explicit gate.
The PyPI smoke must install the published artifact rather than this source
build. Unexecuted YAML is not completed M2 onboarding acceptance.

### GitHub pre-tag platform gate

The repository carries an [exact workflow copy](../.github/workflows/ci-onboarding-demo.yml)
of the public GitHub template. Its only trigger is `workflow_dispatch`, with
read-only contents permission. GitHub requires that manual workflow to exist on
the default branch before it can be dispatched. Complete normal release-branch
review, merge to `master` and pass the actual master CI first; do not bypass that
flow with a temporary branch, workflow or tag.

Before creating the annotated release tag, dispatch **two fresh runs** on that
same accepted `master` SHA. Set `release_commit` to the full SHA and `python_image`
to the same reviewed official Linux amd64 base in both runs:

```text
python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f
```

Set `approved_local_demo` to false in the first run and true in the second. The
unapproved run must **fail** at the installed-wheel execution step with actual
exit **3**; its original artifact must prove approval refusal before target/demo
root creation. Do not turn this expected negative workflow into green. The
approved run must succeed and retain the actual demo, offline reopen/export,
unchanged-root refusal and three verified acquisitions. Both runs must execute
and pass `Verify owned container/image teardown`, retain the exact source commit
and original `owned-teardown.json`, and upload their available receipts even if
execution fails. Download and independently reopen the approved artifact's saved
workspace; verify its original evidence and snapshot digest rather than accepting
the workflow conclusion alone.

Record both run/job URLs, exact source and Python image identities, artifact
identities/hashes and independently observed outcomes before dispatching the
release finalizer. Its ordinary master-check selector does not establish these
manual positive/negative platform outcomes. This paragraph is a required
pre-tag acceptance procedure; its required original results must be recorded
separately from these instructions.
