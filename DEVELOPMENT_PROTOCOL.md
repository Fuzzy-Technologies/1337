# DEVELOPMENT_PROTOCOL.md

## Status and authority

Protocol version: `0.1`  
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

## 3. Branching and release flow

Canonical branches:

- `master` — latest stable/released state;
- `develop` — integration branch for the next release;
- `feature/<name>` — feature work from `develop`;
- `fix/<name>` — non-release fixes from `develop`;
- `release/<version>` — release stabilization;
- `hotfix/<name-or-version>` — urgent fix from `master`.

Normal flow:

```text
feature/* → develop → release/X.Y.Z → master → tag vX.Y.Z
                              └──────────────→ develop (back-merge)
```

Hotfix flow:

```text
master → hotfix/* → master → tag
                    └──────→ develop
```

Until real customer support obligations exist, do not create multiple parallel supported release lines without an explicit owner decision.

### Project planning and traceability

GitHub planning follows this hierarchy:

```text
Milestone
└── Feature issue
    ├── Task issue
    ├── Task issue
    └── Pull request(s)
```

Rules:

- A milestone represents a major roadmap outcome and owns its feature/issues for planning and delivery tracking.
- A feature issue describes one coherent product/subsystem capability and uses the existing `feature` label.
- A task issue describes an implementable unit of work and uses the existing `task` label.
- Do not create new issue labels merely for convenience; use the owner-approved repository label set unless the owner explicitly requests a new label.
- Feature and task titles should include the roadmap identifier while milestones are active, for example `M2 Feature: Tool Adapter SDK` and `M2 Task: Implement typed ToolAdapter contract`.
- Every task must reference its parent feature using the GitHub issue number, for example `Parent feature: #28`.
- A feature should list or otherwise link its child tasks when practical so the hierarchy is navigable in both directions.
- Pull requests must reference the task(s) and feature(s) they implement.
- A pull request that fully completes a task may use `Closes #NN` or `Fixes #NN` in the PR body. Do not use closing keywords when the PR only partially advances the task.
- Ordinary intermediate commits reference their owning issue without closing it.
- A feature is closed only after its required child tasks are complete and its acceptance criteria are satisfied.
- Milestone target dates are planning targets, not evidence of completion. A milestone is complete only when the tracked work and applicable acceptance evidence are actually complete.
- The public README contains only a high-level roadmap. Detailed implementation planning belongs in GitHub milestones/issues and internal planning artifacts.
- Public repository issues and documentation must describe public contracts and generic extension boundaries only; do not expose private repository names, proprietary implementation details, secrets, or confidential roadmap internals.

### Pull requests

- No normal direct push to `master`.
- Prefer pull requests for `develop` as soon as the bootstrap supports them.
- CI and relevant tests must pass before merge.
- Human owner review is the normal merge gate.
- Automated agents must not self-merge unless explicitly instructed for that specific PR.
- Force-push and history rewriting on protected branches are prohibited.

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

## 5. Change discipline

- Keep each change narrow and reviewable.
- Architecture-impacting work requires an ADR/design decision before or together with implementation.
- Refactoring is behavior-preserving unless the task explicitly says otherwise.
- Style-only changes must not alter identifiers, evaluation order, expressions, conditions, call order, public contracts, or runtime behavior.
- Before deleting a module, function, file, field, command, schema member, or compatibility layer, inspect references and prove that the removal is safe.
- Do not silently remove fallbacks, guards, validation, logging, audit evidence, or tests.
- Do not add `TODO`, `FIXME`, `TEMP`, or `HACK` to tracked source.
- Avoid speculative abstractions. Introduce a layer when it has a concrete contract or at least two credible consumers.

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

Tests are grouped by stable subsystem, not by temporary roadmap stage, patch, or incident.

Good:

```text
test_shell.py
test_scope.py
test_evidence.py
test_adapters.py
test_reporting.py
test_security_policy.py
```

Avoid:

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

- run targeted tests for fast feedback;
- after the final tracked change, run the canonical full repository gate;
- any later tracked-file edit invalidates the full gate and requires it again before commit/release.

Expected baseline gates once bootstrap tooling exists:

```text
python -m pytest -q
python -m compileall -q src tests tools
python -m ruff check .
```

The canonical pytest/coverage gate must additionally collect branch coverage and enforce the per-module `>80%` contract defined above once coverage tooling is configured.

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
- integration/E2E evidence exists where needed;
- failure behavior was considered;
- no secret or unrelated file entered the diff;
- documentation is updated;
- changelog is updated when the change is user-visible, security-relevant, or release-relevant;
- exact diff was reviewed;
- required CI/local gates pass.

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
