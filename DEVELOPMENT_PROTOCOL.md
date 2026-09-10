# DEVELOPMENT_PROTOCOL.md

## Status and authority

Protocol version: `0.3`  
Project: **1337 Security Workbench by Fuzzy Technologies**

This file is the persistent development contract for the repository. AI agents, Codex sessions, IDE assistants, scripts, CI jobs, and human contributors are expected to follow it.

This protocol is owner-controlled. Automated agents must not modify it unless the project owner explicitly asks to change this file.

## 1. Core principle

The development order is:

```text
architecture/contract
→ implementation
→ tests
→ evidence
→ documentation/changelog
→ review
```

Do not damage an already working source of truth or public contract merely to simplify an intermediate refactor.

A change is not complete because the code looks correct. Completion requires the applicable tests and evidence.

## 2. Repository identity and language

The repository identity is **1337 Security Workbench by Fuzzy Technologies**.

Canonical repository language is English:

- source code;
- comments and docstrings;
- Markdown documentation;
- commit messages;
- prompts and agent instructions;
- schemas;
- CLI commands;
- API names;
- machine-readable identifiers.

Localization resources are the only normal exception. Canonical commands and APIs remain English.

## 3. Branching, project tracking, and release flow

Canonical branches:

- `master` — stable public state; tagged commits identify product releases, while qualifying documentation/site publications may be untagged;
- `develop` — integration branch for the next release;
- `feature/<name>` — feature/work-item branches from `develop`;
- `fix/<name>` — non-release fixes from `develop`;
- `release/<version>` — release stabilization;
- `hotfix/<name-or-version>` — urgent fix from `master`.

Normal flow:

```text
feature/* or fix/* → develop → release/X.Y.Z → master → tag vX.Y.Z
                                           └──────────→ develop (back-merge)
```

Hotfix flow:

```text
master → hotfix/* → master → tag
                    └──────→ develop
```

Detailed protected-branch, merge, release, tag, hotfix, and documentation/site publication rules are defined in [`docs/RELEASE_WORKFLOW.md`](docs/RELEASE_WORKFLOW.md).

Until real customer support obligations exist, do not create multiple parallel supported release lines without an explicit owner decision.

### Project planning and traceability

GitHub planning follows this hierarchy:

```text
Milestone
└── Feature issue          native Type: Feature
    ├── Task issue         native Type: Task + native sub-issue
    ├── Task issue         native Type: Task + native sub-issue
    └── Pull request(s)
```

Rules:

- A milestone represents a major roadmap outcome and owns its feature/issues for planning and delivery tracking.
- The milestone's GitHub due date is the canonical schedule. Do not duplicate target dates in issue bodies when they can drift from the milestone.
- Native GitHub Issue Type is the canonical work classification: `Feature`, `Task`, or `Bug`.
- Native GitHub Sub-issues are the canonical Feature → Task hierarchy. Do not maintain duplicate `Parent feature: #NN` or `Child tasks: #NN` lists in issue bodies.
- Issue labels are supplementary metadata only. Do not duplicate native Issue Type with `feature`, `task`, or `bug` labels on issues.
- Pull requests may continue to use the owner-approved labels because PRs do not have Issue Type.
- Do not create new issue labels merely for convenience; use the owner-approved repository label set unless the owner explicitly requests a new label.
- Feature and task titles should include the roadmap identifier while milestones are active, for example `M2 Feature: Tool Adapter SDK` and `M2 Task: Implement typed ToolAdapter contract`.
- Every feature and task must belong to the appropriate GitHub milestone.
- Backlog feature/task issues remain unassigned. Assignment means active work, not roadmap ownership.
- When work on one or more task issues actually begins, assign the project owner (`Tim55667757`) to those active task issues. If work is explicitly returned to the backlog before completion, remove the assignee.
- Pull requests must reference the task(s) and feature(s) they implement and should use the milestone of the primary owning task/feature unless the PR is explicitly cross-milestone.
- A pull request that fully completes a task may use `Closes #NN` or `Fixes #NN` in the PR body. Do not use closing keywords when the PR only partially advances the task.
- Ordinary intermediate commits reference their owning issue without closing it.
- When a task implementation is ready for owner review, add a short plain-English issue comment describing what changed, what the change enables, and how it was actually verified. Keep it readable for a human; use a small Markdown table only when it improves clarity.
- A task remains open while its completing PR is in review. Normal completion is PR merge → Task closed.
- A feature is closed only after its required native sub-issues are complete and its feature-level acceptance criteria are satisfied.
- Before feature closure, add a concise feature-level acceptance comment when useful to summarize the completed capability and evidence.
- Milestone target dates are planning targets, not evidence of completion. A milestone is complete only when the tracked work and applicable acceptance evidence are actually complete.
- The public README contains only a high-level roadmap. Detailed implementation planning belongs in GitHub milestones/issues and internal planning artifacts.
- Public repository issues and documentation must describe public contracts and generic extension boundaries only; do not expose proprietary implementation details, secrets, or confidential roadmap internals.

### Pull request labels

Use only the owner-approved repository label set. PR labels describe the actual content of the PR rather than merely mirroring the parent issue type.

- `feature` — new product/subsystem capability or meaningful extension of an existing capability;
- `bug` — defect correction;
- `documentation` — documentation-only or materially documentation-dominant work;
- `task` — engineering infrastructure, testing, maintenance, refactoring, packaging, or another implementation task not better represented by `feature`, `bug`, or `documentation`;
- `duplicate` — only when the item is genuinely a duplicate; normally not an implementation-PR label.

Multiple existing labels may be used when each is materially true. Do not create a new label simply to describe one PR.

### Pull requests

- No normal direct push to `master` or `develop`.
- Open work PRs against `develop` unless a release/hotfix workflow or the documentation/site publication exception in `docs/RELEASE_WORKFLOW.md` explicitly requires another base.
- Draft PRs are the normal place for work still being implemented or validated.
- CI and relevant tests must pass before merge once those checks exist.
- Human owner review is the normal merge gate.
- Automated agents must not self-merge unless explicitly instructed for that specific PR.
- Force-push and history rewriting on protected branches are prohibited.
- Default merge method for ordinary work PRs is Squash and merge; exceptions are defined in `docs/RELEASE_WORKFLOW.md`.

## 4. Commit messages

Do not use Conventional Commits prefixes such as `feat:`, `fix:`, or `chore:`.

For cross-project/shared work:

```text
1337: concise English description (#NN)
```

For module-owned work, use the module name as the prefix:

```text
1337 Scope: concise English description (#NN)
1337 Scan: concise English description (#NN)
1337 Intel: concise English description (#NN)
1337 Report: concise English description (#NN)
1337 Trace: concise English description (#NN)
Fuzzy Striker: concise English description (#NN)
```

Release-specific product work may include the release version when useful:

```text
1337 vX.Y.Z: concise English description (#NN)
```

Issue references normally appear at the end of the subject as `(#NN)` so the human-readable action remains first and GitHub still creates the link.

If one coherent commit legitimately contributes to several issues, either list the references in the subject when concise or use the commit body:

```text
Refs #45
Refs #46
```

Do not use `Closes #NN`, `Fixes #NN`, or equivalent closing keywords in ordinary intermediate commits. Closing semantics belong in the pull request that actually completes the task.

A commit should represent one coherent logical change. Infrastructure repair, behavior changes, broad refactoring, and unrelated documentation cleanup should not be mixed.

### Work slicing and commit cadence

- Commit after a coherent logical implementation slice has been completed and the applicable targeted tests/evidence for that slice have been checked.
- A non-trivial task should normally contain multiple small logical commits when that improves reviewability, diagnosis, or rollback.
- Avoid both one giant catch-all commit and mechanical commit spam for every touched file or trivial edit.
- Related tiny edits may be combined into one coherent commit; unrelated work must remain separate.
- Do not fabricate, backdate, randomize, or deliberately delay commit timestamps to imitate a human contributor. Repository history must reflect real execution time and real work boundaries.

## 5. Change discipline and public compatibility

- Keep each change narrow and reviewable.
- Architecture-impacting work requires an ADR/design decision before or together with implementation.
- Refactoring is behavior-preserving unless the task explicitly says otherwise.
- Style-only changes must not alter identifiers, evaluation order, expressions, conditions, call order, public contracts, or runtime behavior.
- Before deleting a module, function, file, field, command, schema member, or compatibility layer, inspect references and prove that the removal is safe.
- Do not silently remove fallbacks, guards, validation, logging, audit evidence, or tests.
- Do not add `TODO`, `FIXME`, `TEMP`, or `HACK` to tracked source.
- Avoid speculative abstractions. Introduce a layer when it has a concrete contract or at least two credible consumers.
- Public compatibility boundaries, stability classes, schema-version rules, and extension-consumer expectations are defined in [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md).
- A source symbol, import path, JSON field, route, or file format is not automatically public/stable merely because it is visible. Stability must be explicitly declared.
- Changes to Stable public contracts require compatibility impact review and the version/schema transition required by the compatibility policy.

## 6. Python house style

Python is the primary orchestration, CLI, automation, adapter, API, testing, and data-pipeline language.

### 6.1. General style

- Use 4-space indentation.
- Use modern Python with explicit, readable control flow.
- Use type hints for public interfaces and important internal contracts.
- Prefer `dataclass`, `Protocol`, `TypedDict`, enums, or validated models where a real data contract exists.
- Prefer `pathlib.Path` over ad-hoc string path manipulation.
- Use context managers for files, locks, temporary resources, and managed processes.
- Keep imports grouped as standard library, third-party, then project-local imports.
- Avoid wildcard imports.
- Avoid hidden global mutable state unless it is a deliberate, tested process-wide registry.
- Do not use bare `except:`.
- Exceptions should preserve the original cause and add actionable context.
- Security or validation boundaries fail closed unless a documented contract explicitly defines degradation/fallback behavior.
- Do not use `eval`/`exec` for configuration or plugin dispatch.
- For subprocesses, prefer argument arrays and `shell=False`; shell invocation requires an explicit justified boundary.
- JSON written by project code must be standards-compliant; do not emit `NaN`, `Infinity`, or `-Infinity`.

### 6.2. Naming

Default Python naming:

- modules/functions/variables: `snake_case`;
- classes/protocols/enums: `PascalCase`;
- constants: `UPPER_CASE`;
- private implementation details: leading `_`.

Preserve externally defined naming where it is part of a contract. Do **not** mechanically rename:

- CLI arguments and command names;
- JSON/TOML/YAML fields;
- archive member names;
- external schemas;
- dynamic import entry points;
- callback names;
- third-party API fields;
- compatibility contracts.

External contract correctness has priority over cosmetic naming normalization.

### 6.3. Formatting

`ruff format` is **not** the canonical formatter contract.

Ruff may be used for lint/static checks, but style-only work must not mechanically rewrite protected interfaces or behavior.

Specific house rule retained from existing Fuzzy Technologies Python projects:

> After a completed multi-line `for` block, insert a blank line before the next independent statement or block when that line is no longer part of the loop/control flow.

Do not mechanically insert blank lines inside a logically continuous construct.

Prefer readable source over clever compression. A dense one-liner or nested comprehension should not replace straightforward control flow when it reduces debuggability or evidence clarity.

### 6.4. Functions and modules

- Keep one clear responsibility per function/module.
- Avoid wrapper functions that add no contract, validation, or abstraction value.
- Separate pure parsing/transformation from I/O when practical.
- Keep security decisions, scope checks, impact classification, and authorization logic explicit and testable.
- Do not hide important side effects in property accessors or object construction.
- Prefer deterministic output for the same input where the domain permits it.

### 6.5. Async and concurrency

- Use async/concurrency where it provides measurable benefit, especially I/O-bound scanning and orchestration.
- Do not introduce concurrency only to make code look modern.
- Define ownership, cancellation, timeout, and cleanup behavior.
- Shared mutable state requires an explicit synchronization/ownership contract.
- A timeout, cancellation, or partial worker failure must not be silently reported as success.

## 7. Markdown and documentation style

- Documentation is English-only except localization assets.
- Markdown source should be readable before rendering.
- Keep Markdown tables visibly aligned in source form; do not rely solely on renderer alignment.
- Prefer precise technical language over marketing claims in development documentation.
- README describes current product state, not a historical diary.
- Historical changes belong in `CHANGELOG.md`.
- Do not regenerate or broadly rewrite README/CHANGELOG during an unrelated patch.
- Documentation changes should be localized to the affected sections.
- Qualifying documentation and GitHub Pages updates may be published to `master` between product releases without a version tag only under the explicit documentation/site publication rules in `docs/RELEASE_WORKFLOW.md`.

## 8. CHANGELOG contract

`CHANGELOG.md` uses a strict Fuzzy Technologies hierarchy:

```text
# <Product> Changelog

# Major N

## Minor N.M

### Patch P — vN.M.P — YYYY-MM-DD

#### Digest
#### Added
#### Fixed
#### Changed
#### Removed
#### Security
```

Only sections relevant to the patch need to be present, but their relative order is fixed as shown above.

Rules:

- newest Patch first inside the active Minor;
- newest Minor first inside the active Major;
- newest Major first;
- do not reorder or rewrite historical entries;
- add a new Patch section rather than editing old history, except to correct a proven factual error with explicit owner approval;
- every patch starts with `Digest`;
- `Digest` is concise and describes the purpose/result, not a duplicate of every bullet below;
- use `Security` for security-boundary, authorization, hardening, secret-handling, or safety-contract changes;
- do not use an `Unreleased` free-form area unless this protocol is explicitly changed.

## 9. Test organization

`pytest` is the canonical test runner for Python-backed project tests. Test layers are separated by purpose while files inside each layer remain grouped/named by stable subsystem rather than by roadmap stage, patch, or incident.

Canonical layout:

```text
tests/
├── unit/
├── contract/
├── functional/
├── integration/
└── e2e/
```

Layer responsibilities:

- `tests/unit/` — fast deterministic tests of isolated first-party units; no Docker, network, external service, or real tool dependency;
- `tests/contract/` — CLI/API/schema/adapter/evidence/plugin/state-machine compatibility contracts;
- `tests/functional/` — black-box product behavior against repository-defined isolated synthetic or explicitly pinned vulnerable targets;
- `tests/integration/` — real first-party components and adapters communicating through their actual boundaries;
- `tests/e2e/` — user-level workflows through the assembled product.

Good subsystem-oriented names inside these layers include:

```text
test_shell.py
test_scope.py
test_evidence.py
test_adapters.py
test_reporting.py
test_security_policy.py
```

Avoid roadmap/incident-oriented names:

```text
test_g0.py
test_patch_12.py
test_hotfix.py
test_temp.py
```

Create a new test file only for a distinct subsystem or a new block with no correct existing owner.

### Contract-first rule

For a change to a public or cross-module contract:

1. inspect the current schema/interface and consumers;
2. add or update contract tests;
3. implement the producer/consumer change;
4. execute the real producer/consumer path where feasible;
5. validate failure behavior as well as the happy path.

Protected boundaries include:

- CLI contracts;
- API/OpenAPI schemas;
- JSON/TOML/YAML;
- plugin manifests;
- evidence/finding schemas;
- archive/package formats;
- executor/tool-adapter contracts;
- callbacks/dynamic imports;
- state machines;
- error codes and machine-readable statuses.

### Functional-test contract

Functional tests are reproducible pytest suites, not ad-hoc manual scanner runs.

- `tests/functional/` owns functional scenarios and should use a stable scenario/oracle/fixture structure (for example `scenarios/`, `oracles/`, `fixtures/`, and runner helpers where useful).
- Pytest fixtures/hooks own target lifecycle: startup, deterministic readiness/health checks, test metadata, cleanup, and teardown even after failures.
- Session/module/scenario fixture scope should be chosen to minimize startup cost without leaking state between tests.
- Functional tests must run the same way locally and in CI.
- Automated functional tests must never depend on Internet-hosted demo targets or arbitrary external systems.
- First-party micro-targets are the primary deterministic known-answer oracle. Each relevant route/scenario declares what must and must not be discovered or reported.
- External intentionally vulnerable applications such as OWASP Juice Shop, WebGoat, crAPI, or Benchmark-style targets complement the micro-targets. Pin their versions/digests and record the exact target provenance in results.
- A realistic vulnerable application without a complete machine-readable oracle must not be presented as an absolute scanner-accuracy benchmark.
- Preserve raw scan/tool evidence together with normalized functional assertions so every regression can be explained.
- Where a known-answer oracle exists, measure TP/FP/FN/TN and derived accuracy/regression metrics rather than relying only on a binary smoke result.
- Security-sensitive scenarios such as command execution, file upload, file inclusion, callback behavior, or SSRF should use isolated markers/canaries and bounded postconditions in ordinary CI rather than deploying a reusable general-purpose shell.
- Proxy/WAF variants are explicit versioned functional profiles and must preserve the intermediary configuration/provenance with the result.

### Scanner capability coverage matrix

Functional-test metadata is also the canonical source for a scanner capability coverage matrix.

- Rows represent vulnerability/check capabilities.
- Columns represent target packs/scenarios such as first-party synthetic targets, OWASP Juice Shop, WebGoat, crAPI, Benchmark-style targets, and future packs.
- Each cell records applicability plus expected/detected/not-detected (or an equivalent explicit machine-readable state).
- The matrix must be generated from test/oracle metadata rather than maintained as a disconnected hand-edited marketing table.
- Provide machine-readable output plus readable Markdown/HTML views.
- Design the schema so future comparative scanner/tool columns can be added for controlled competitive analysis without rewriting the functional-test oracle model.

### Coverage contract

Test coverage is a release/merge contract, not an informational metric.

- Coverage must be measured with branch coverage enabled.
- Every first-party production Python module must remain **strictly above 80%** combined statement/branch coverage once the coverage gate is enabled.
- New modules must meet the threshold before they are considered complete.
- A change must not reduce an existing module below the threshold.
- Generated code, vendored third-party code, localization/data-only files, and other non-executable artifacts may be excluded only through an explicit documented coverage configuration; exclusions must not be used to hide untested production logic.
- Security-critical boundaries such as scope/authorization policy, executor control, evidence integrity, parser/normalization logic, and failure-state handling require direct tests of both allowed/success and denied/failure paths; satisfying the numeric threshold alone is not sufficient evidence.
- CI must fail when the configured per-module coverage contract is violated. Coverage warnings without a failing gate do not satisfy this protocol.
- If a non-Python production component is introduced, an equivalent coverage contract must be defined for that component before it becomes release-critical.

## 10. Test gates and evidence

During implementation:

- run the smallest relevant pytest layer/subsystem for fast feedback;
- run functional/integration/E2E suites when the change crosses those boundaries;
- after the final tracked change, run the canonical full repository gate;
- any later tracked-file edit invalidates the full gate and requires it again before commit/release.

Expected baseline gates once bootstrap tooling exists:

```text
python -m pytest -q
python -m compileall -q src tests tools
python -m ruff check .
```

The canonical pytest/coverage gate must additionally collect branch coverage and enforce the per-module `>80%` contract defined above once coverage tooling is configured.

Functional-test commands must remain ordinary pytest invocations (for example a `tests/functional` selection and/or pytest markers), with Docker target setup performed by fixtures/hooks rather than by a separate unverifiable manual procedure.

Add the configured type checker and security/package checks when the repository introduces them.

If a command is not yet available in the bootstrap stage, report it as **not available/not run**. Never invent PASS.

For an important cross-module change, a string search or isolated unit test is not sufficient evidence by itself.

## 11. Security-development rules

1337 is security software and must be safer than the tools it orchestrates.

- Active tests run only against repository-defined synthetic/local targets or targets explicitly authorized by the owner for the task.
- Scope and impact-level checks are first-class contracts.
- Never make an intrusive action the hidden default.
- Fail closed when authorization/scope cannot be proven.
- Never treat a tool's presence as success when installation or healthcheck failed.
- Never swallow a scanner/tool failure and report a successful scan.
- External command execution must preserve exact invocation metadata and exit status for evidence.
- Raw evidence and normalized findings remain distinct.
- Secrets are never stored in source, logs, reports, fixtures, model prompts, or committed configuration.
- Synthetic fixtures must use non-sensitive test credentials and deterministic local targets.

## 12. Generated/local state

Do not commit machine-local or reproducible runtime state.

Typical ignored state includes:

- virtual environments;
- IDE metadata;
- caches;
- coverage output;
- local SQLite/runtime databases;
- generated reports;
- raw evidence;
- logs;
- temporary workspaces;
- local secrets/environment files;
- build/package outputs;
- downloaded third-party tool caches.

A generated artifact may be committed only when it is intentionally part of a stable test fixture or source-controlled contract.

## 13. AI and automation

- AI is an optional intelligence/implementation layer, not the source of truth for deterministic security evidence.
- Prefer deterministic parsers, validators, tests, and scripts whenever they can answer the question.
- Agents operate through the same project contracts as humans and automation.
- Agents must not bypass scope/security rules with raw shell access.
- Model-generated conclusions must be traceable to evidence when they affect findings, risk, or security decisions.
- Keep model context bounded; do not upload unrestricted archives or unrelated repository content.

## 14. Definition of done

A change is done only when all applicable items are true:

- scope is understood;
- implementation is complete;
- relevant unit/contract tests pass;
- applicable production modules satisfy the test-coverage contract;
- functional/integration/E2E evidence exists where the changed behavior crosses those layers;
- functional scanner behavior is reflected in the capability/oracle metadata when applicable;
- failure behavior was considered;
- no secret or unrelated file entered the diff;
- documentation is updated;
- changelog is updated when the change is user-visible, security-relevant, or release-relevant, except a qualifying documentation/site-only publication that explicitly requires no product version under `docs/RELEASE_WORKFLOW.md`;
- exact diff was reviewed;
- required CI/local gates pass;
- a human-readable completion comment is present on the task when the implementation is being handed to the owner for review.

If a required check is missing, timed out, or was not executed, report that fact and do not label the result complete.

## 15. Owner escalation

Stop and ask the owner before an action that is:

- destructive;
- ambiguous in scope;
- an expansion to another repository or system;
- a change to authorization/security policy;
- a public API/schema break;
- a license change;
- a release/trademark/product decision;
- a change to this protocol or `AGENTS.md`;
- an intrusive security test without already explicit authorization.
