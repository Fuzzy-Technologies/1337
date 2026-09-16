# Python development

Use CPython 3.11 or newer and uv 0.11.33. The CI matrix exercises Python 3.11,
3.12, 3.13, and 3.14 across Linux, Windows, and macOS. PyCharm can use the local
`.venv` interpreter; all operations below also run from an ordinary terminal.

Run these commands from the repository root:

```bash
python -m pip install uv==0.11.33
uv run --locked 1337-dev setup
uv run --locked 1337 --version
uv run --locked 1337 doctor
uv run --locked 1337-dev unit
uv run --locked 1337-dev check
```

`uv.lock` records exact dependency versions and artifact hashes. `--locked`
rejects stale dependency metadata instead of rewriting the lock. Build backend
constraints also pin the editable-build environment. Update dependency pins and
the lock together in a reviewed change; do not regenerate them during CI.

`1337-dev setup` is the repeatable CLI entry point for the locked development
environment. It invokes `uv sync --locked --extra dev` with `shell=False` and
fails if the pinned `uv` executable is unavailable. The initial one-time
prerequisite is installing `uv==0.11.33` as shown above.

The current `1337` entry point provides help, installed-version output, the
interactive shell foundation, and local diagnostics. Scanner workflows belong
to subsequent product work.

| Command                              | Behavior                                                                   |
|--------------------------------------|----------------------------------------------------------------------------|
| `uv run --locked 1337-dev setup`     | Synchronize the locked development environment                             |
| `uv run --locked 1337-dev lint`      | Non-mutating Ruff checks                                                   |
| `uv run --locked 1337-dev typecheck` | Strict mypy checks for production Python                                   |
| `uv run --locked 1337-dev compile`   | Compile source and tests                                                   |
| `uv run --locked 1337 doctor`        | Inspect the local runtime, package, workspace permissions, and optional lab support |
| `uv run --locked 1337-dev unit`      | Process-isolated unit tests plus mandatory per-module coverage validation  |
| `uv run --locked 1337-dev test`      | All test layers in process-isolated workers plus mandatory coverage validation |
| `uv run --locked 1337-dev build`     | Build sdist and wheel using locked build tools                             |
| `uv run --locked 1337-dev check`     | Compile, lint, typecheck, test/coverage, then build; stop on first failure |

Each child step has a 300-second limit. Normal child exit codes are propagated;
timeouts return 124, process-start failures return 127, and POSIX signal exits
are mapped to 128 plus the signal number. Run gates from the repository root.

For the canonical fast feedback run:

```bash
uv run --locked 1337-dev unit
```

Plain `pytest` also defaults to `tests/unit`. The `1337-dev unit` command additionally
enforces the per-module contract; `1337-dev test` runs all test layers, and
`1337-dev check` is the full repository gate. A stale coverage JSON file is removed
before tests. Missing reports/modules, disabled branch measurement, invalid counts,
and undocumented exclusions fail the gate. Every executable production module must
exceed 80% combined statement/branch coverage. Exactly 80% fails. There are no
production exclusions. Source modules not imported by the tests still belong to the
required source inventory.

`1337-dev unit` and `1337-dev test` use `pytest-xdist` process workers by default.
Automatic scheduling uses `--dist=loadscope` and caps workers at
`min(os.cpu_count(), 12)`. Tests that own a shared resource must use the explicit
`@pytest.mark.serial` marker; the runner executes them separately with `-n 0` after
the parallel pool. No automatic retry is configured or permitted.

The runner accepts these controlled diagnostics:

```bash
uv run --locked 1337-dev unit --jobs auto --timeout 120
uv run --locked 1337-dev unit --jobs 4 --fail-fast
uv run --locked 1337-dev unit --serial
```

`--timeout` sets the per-test timeout and bounds each pytest worker process. The
terminal summary is deterministic: `total`, `passed`, `failed`, `skipped`, `timeout`,
and `duration`. Any failure, timeout, or process-start error produces a non-zero exit.

`1337 doctor` is non-mutating. It checks the Python runtime, installed package,
current-directory read/write access, and optional Docker Compose support. Missing
optional Compose support is reported as `WARN`; a missing required runtime or
package returns a non-zero exit. Workspace configuration is reported as an
explicit future boundary until its M1 model is implemented.

Tests are organized by subsystem in `tests/unit`, `tests/contract`, and
`tests/integration`; `tests/functional` retains the future synthetic-target
boundary. Unit tests are deterministic and carry an automatic fail-closed guard
against real network connections, including local or Docker service sockets. The
packaging integration test builds an sdist, builds its wheel, installs that wheel
into a clean virtual environment without an index or dependencies, then invokes
both installed entry points outside the checkout. It does not contact scan targets
or external services.

Generated evidence is under `coverage/`; distributable packages are under
`dist/`. Both are ignored by Git. Dependencies must be installed before gates
run; package validation itself installs only the locally built wheel.

Runtime dependencies: none. Initial direct development/build dependency review:

| Component  | Version | Role                         | License metadata |
| ---------- | ------- | ---------------------------- | ---------------- |
| Hatchling  | 1.32.0  | Build backend                | MIT              |
| editables  | 0.5     | Editable development install | MIT              |
| build      | 1.6.0   | sdist/wheel frontend         | MIT              |
| pytest     | 9.1.1   | Test runner                  | MIT              |
| pytest-cov | 7.1.0   | Coverage integration         | MIT              |
| coverage   | 7.16.0  | Branch/statement measurement | Apache-2.0       |
| Ruff       | 0.16.6  | Linting                      | MIT              |
| mypy       | 2.3.1   | Type checking                | MIT              |
| jsonschema | 4.26.0  | Public contract validation   | MIT              |

These tools add no dependency to the installed runtime. Transitive versions and
hashes are recorded in the lock. Broader supply-chain/release inventory remains
part of the M0/release acceptance process.

Architecture decision: [Python toolchain baseline](adr/0001-python-toolchain.md).

For the repository-owned container workflow, see
[Container development](CONTAINERS.md). It provides `docker compose` commands
for the same locked quality gate and a persistent interactive workbench service.
