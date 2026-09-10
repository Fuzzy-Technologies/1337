# Python packaging and quality-gate baseline

Status: implemented for owner review in issue #8.

The project needs an installable package and a reproducible quality gate before
workspace, scanner, and interactive-shell implementation begins.

- Keep distribution `1337` and internal import namespace `fuzzy1337`.
- Retain Python 3.11 as the minimum; exercise 3.11 through 3.14 in CI.
- Use Hatchling with explicit wheel/sdist file selection. The runtime has no
  third-party dependencies. Package metadata is the version source of truth.
- Use uv 0.11.33 and a committed `uv.lock`; normal setup uses `uv sync --locked
  --extra dev`. Build tooling is installed from that same lock and builds run
  with `--no-isolation`. Editable-build dependencies are additionally pinned by
  build constraints; the editable path is explicitly `src`. Ordinary pip
  installation of built wheels remains valid.
- `1337` provides bootstrap help/version only. It does not start an interactive
  shell or execute security tools. `1337-dev` owns repository quality commands.
- One command registry drives developer command descriptions and execution.
  Child processes use argument arrays, the current interpreter, bounded waits,
  and explicit exit-status propagation. The gate stops on the first failure.
- `1337-dev test` runs pytest with branch coverage and validates every production
  Python file under `src/fuzzy1337`. Each module's combined statement/branch
  coverage must be strictly greater than 80%, using integer counts, not rounded
  display percentages. Missing/invalid reports and missing modules fail closed.
- There are no production coverage exclusions. Test code is outside the
  production source inventory. Files with no executable statements or branches
  are reported as non-executable rather than counted as covered logic.
- `1337-dev check` runs compile, lint, type checking, tests/coverage, and build.
  Plain pytest is a diagnostic test invocation; it is not the full quality gate.
- Ruff checks are explicit and non-mutating. No formatter command is registered.

The bootstrap CLI and development helpers remain Experimental/Internal under
the existing compatibility policy. The full command-descriptor model, interactive
shell, broader developer UX, and expanded unit-suite foundation retain their
separate issue ownership. No protected policy file is changed by this decision.

References: [Hatch wheel selection](https://hatch.pypa.io/latest/plugins/builder/wheel/),
[uv locked synchronization](https://docs.astral.sh/uv/concepts/projects/sync/),
and [Python version lifecycle](https://devguide.python.org/versions/).
