# Source Documentation Remediation

This remediation implements the source hardening in Task #220 under the
[source documentation contract](SOURCE_DOCUMENTATION.md). It changes authored
documentation and ownership metadata; runtime behavior, annotations, API names,
import paths and expressions remain unchanged.

## Resolved findings

All 42 existing Python files in `src/` and `tests/` receive the declared 2026
ownership and Apache-2.0 SPDX headers. The new regression test carries the same
headers. None is a directly executed script, so no shebang is added. The branch
does not contain baseline `tools/` Python; the regression inventory also covers
that optional root when it is present, including tooling introduced by Task #219.

The 102 existing source callable/property contracts now document actual input
meaning and non-None return semantics. Security and resource boundaries also
describe caller-visible validation failures and material side effects:

- Adapter contracts distinguish declaration, health, preparation, normalization
  and authority. JSON freezing/serialization reject unsupported values and keep
  deterministic representations separate from persistence.
- Executor contracts explain exact invocation binding, provider-loader ownership,
  privilege metadata, environment syntax and workspace containment. Local process
  documentation records bounded retained output, timeout/cancellation cleanup,
  observer failure propagation and platform process-group behavior. These controls
  are not claimed as an OS sandbox or upstream scope authorization.
- CLI, developer gates, doctor, test orchestration and performance APIs document
  exit status, subprocess/file side effects and the meaning of their evidence.
- Shell APIs describe local context and cached actions without implying execution
  authority. The update producer remains responsible for bounding queue volume
  between drains; the source no longer calls that unbounded queue a bounded one.
- The executor's local event emitter and stream pump retain explicit typed
  contracts and now document their important resource and payload invariants.

`tests/unit/test_source_documentation_headers.py` rejects conflicting/missing
SPDX declarations, missing authored module/class/function docstrings, invalid
syntax, missing public parameter/return annotations, incomplete parameter
descriptions and empty return/yield sections. Validation uses AST parsing and
never imports or executes inspected modules. Private/nested scopes still require
authored docstrings. No-return APIs do not gain redundant `Returns` sections.

## Reviewed advisory applicability

The Task #219 auditor distinguishes source interfaces from test/helper roles.
The remediation does not suppress findings, alter that classifier, hide files,
or convert advisory findings into a completeness claim.

| Finding role                   | Disposition and rationale                                                        |
| ------------------------------ | -------------------------------------------------------------------------------- |
| Public `src/` callable contract | Remediated: explicit annotations and meaningful applicable Args/Returns sections. |
| Executor nested helpers        | Remediated: typed boundaries and explicit Args for event/stream ownership.         |
| Test fixture arguments         | Concise test intent is accepted; pytest owns fixture injection and test setup.     |
| Test helper annotations        | Advisory: adding/changing annotations is outside documentation-only hardening.    |
| Test helper return sections    | Advisory: concise local helper docs are accepted where the assertion/setup shows usage. |
| Ownership and docstring absence | Mandatory for all roles; no applicability exemption is granted.                  |

Test-role recommendations remain visible in the generated inventory. They do not
represent waived production API contracts. Public/important future tooling must
meet source-role completeness; test wrappers may keep concise English docstrings.
Annotation cleanup should be separately scoped if a concrete test contract needs
it, because annotations can change runtime semantics and must not be added as a
mechanical documentation edit.

Documentation review also identified an existing executor lifecycle limitation:
the initial `STARTED` observer is invoked after process launch and before the
process-wait cleanup guard and timeout enforcement. Observer failure or task
cancellation at that handoff does not have guaranteed process cleanup. The
source contract records that limitation; this documentation-only task does not
change or claim to repair that runtime path. It requires a separately scoped
executor implementation and regression test.

## Verification

The ownership-only commit was checked with exact AST equality across all 42
existing files. For the source-docstring changes, ASTs before/after are identical
after removing authored docstring expression nodes. This comparison retains
decorators, annotations, declarations, constants, statements and expression order.
Executable behavior equivalence is therefore checked independently of successful
tests.

Run the same regression and canonical gates used for review:

```bash
uv sync --locked --extra dev
uv run --locked --extra dev python -m pytest tests/unit/test_source_documentation_headers.py --no-cov -q
uv run --locked --extra dev 1337-dev check
```

After Task #219's standalone auditor is available in the integration tree, retain
the reproducible role inventory as generated local evidence:

```bash
uv run --locked --extra dev python tools/source_documentation_audit.py --check --root . --output .tmp/source-documentation-audit
```

The auditor reports structural evidence and review candidates. It does not prove
semantic documentation quality, human language review, API stability, runtime
authorization or documentation publication. Docker-backed tests require Docker;
an unavailable local Docker gate remains an explicit skip rather than PASS.
