# CI quickstart — 0.3.0 candidate

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
for the intended release. The candidate has no published 0.3.0 tag yet; do not
substitute an assumed tag or moving `develop`. Fetch verifies the exact commit.
Select `PYTHON_IMAGE` / `python_image` as an approved Python 3.11-or-newer slim
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

## Optional finding thresholds

The demo creates no Findings and has no vulnerability threshold. For a selected
configuration/image gate, use [the explicit `1337 ci scan` interface](CI_SCAN.md)
with its required source authority, severity/status sets, `--max-matches` and
completeness acknowledgement. Its exit **1** means a completed source predicate
was violated; exits **2/3/4/130** mean configuration/denial/failure/cancellation.
Do not convert those execution errors to a finding-threshold pass. Report JUnit
failure counts and the selected source predicate are separate facts.

## Acceptance evidence

Candidate wheel rehearsals and deterministic tests validate the product/harness
contracts. They do not establish GitHub-hosted or GitLab runner acceptance.
The release gate must run each copied YAML on its named platform with a digest-
pinned image and final release commit, retain job URLs/artifacts and validate the
approved and missing-approval cases. This environment currently has no Docker
binary or configured GitLab runner; platform execution remains an explicit gate.
The later PyPI smoke must install the published artifact rather than this source
build. Unexecuted YAML is not completed M2 onboarding acceptance.
