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
interactive shell foundation, local diagnostics, and read-only component-health
inspection. Scanner workflows belong to subsequent product work. See
[Component health and update inspection](COMPONENT_HEALTH.md) for the explicit
non-mutation boundary and experimental JSON report.
Current development workflows additionally expose
[bounded Quick Scan](QUICK_SCAN.md) and [Offline report export](REPORT_EXPORT.md).
The latter reads an explicitly selected existing workspace and publishes new
JSON/SARIF output without a job, provider process or target contact.

| Command                                | Behavior                                                                            |
| -------------------------------------- | ----------------------------------------------------------------------------------- |
| `uv run --locked 1337-dev setup`       | Synchronize the locked development environment                                      |
| `uv run --locked 1337-dev lint`        | Run non-mutating Ruff checks                                                        |
| `uv run --locked 1337-dev typecheck`   | Run strict mypy checks for production Python                                        |
| `uv run --locked 1337-dev compile`     | Compile source and tests                                                            |
| `uv run --locked 1337-dev performance` | Enforce implemented shell latency budgets and write JSON evidence                   |
| `uv run --locked 1337 doctor`          | Inspect the local runtime, workspace permissions, package, and optional lab support |
| `uv run --locked 1337 update [--json]` | Inspect local component health and manual update boundaries without changing state  |
| `uv run --locked 1337-dev unit`        | Run process-isolated unit tests and mandatory per-module coverage validation        |
| `uv run --locked 1337-dev test`        | Run all test layers in process-isolated workers and mandatory coverage validation   |
| `uv run --locked 1337-dev build`       | Build the sdist and wheel using locked tools                                        |
| `uv run --locked 1337-dev check`       | Compile, lint, typecheck, measure performance, test coverage, and build             |

Non-test child steps have a 300-second limit. Complete pytest invocations use the
independent 600-second default suite budget described below. Normal child exit codes are propagated;
timeouts return 124, process-start failures return 127, and POSIX signal exits
are mapped to 128 plus the signal number. Run gates from the repository root.

For fast feedback before a routine commit, select the changed feature's tests and
its regression paths explicitly. For example, a developer-runner change uses:

```bash
uv run --locked --extra dev pytest tests/unit/test_dev_commands.py tests/unit/test_test_runner.py --no-cov -m 'not serial' -n auto --dist=loadscope --timeout=120 -q
```

If the selected files contain shared-resource tests, run their serial cases in a
separate invocation:

```bash
uv run --locked --extra dev pytest tests/unit/test_dev_commands.py tests/unit/test_test_runner.py --no-cov -m serial -n 0 --timeout=120 -q
```

Replace those file paths with the feature's actual unit, contract and boundary
tests. Include relevant failure/regression paths. `--no-cov` disables the full
source-inventory coverage threshold for this partial run; mandatory branch and
per-module coverage still applies in the full PR gate. Pytest exit code 5 means
no selected tests were collected; it is not a passing test run.

Do not run `1337-dev unit`, `1337-dev test` or `1337-dev check` before every
implementation commit. Run the full gate when opening a PR and after fixing a bug
or review/CI defect in the same PR, preferably once through shared PR CI. Routine
tracked-file edits require relevant focused validation rather than a duplicate
local full gate. Full-gate evidence belongs to its tested revision; required CI
must validate the proposed PR revision before review readiness or merge.

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

The same automatic worker cap applies to focused pytest commands that use
`-n auto`. Plain `pytest` without `-n` runs sequentially. When several development
agents run tests on one host, use an explicit smaller `-n` budget for each agent
to avoid multiplying the automatic CPU allocation.

The runner accepts these controlled diagnostics:

```bash
uv run --locked 1337-dev unit --jobs auto --timeout 120
uv run --locked 1337-dev test --timeout 120 --suite-timeout 600
uv run --locked 1337-dev unit --jobs 4 --fail-fast
uv run --locked 1337-dev unit --serial
```

`--timeout` sets the per-test pytest deadline (default 120 seconds).
`--suite-timeout` independently bounds each complete parallel or serial pytest
invocation (default 600 seconds); it is not derived from the number of per-test
deadlines. Both accept only integers in the supported 1–3600-second range, enforced
by `MAX_TIMEOUT_SECONDS` before dispatch, report deletion or child startup. This
keeps operating-system wait/timer conversion bounded and rejects oversized values
through fixed configuration diagnostics. The default suite budget leaves
time for later gates and evidence upload within the existing 15-minute quality
job limit. It is a per-invocation budget rather than a deadline for all quality-gate
phases together. A separate collection probe remains bounded at 300 seconds.

The terminal summary is deterministic: `total`, `passed`, `failed`, `skipped`,
`timeout`, and `duration`. Any failure, timeout, or process-start error produces
a non-zero exit. Each invocation discards its stale JUnit report before starting;
an exit-zero child without fresh JUnit evidence still fails. Suite timeouts are
reported as failure with status 124 and are never retried automatically.

The performance gate measures only capabilities that are implemented today. It
starts fresh processes for CLI cold start and interactive readiness, then measures
local command-palette search and lens/view state transitions in process. Every case
has an explicit median latency budget:

| Case                       | Median budget |
| -------------------------- | ------------- |
| CLI cold start             | 2,000 ms      |
| Interactive readiness      | 2,000 ms      |
| Command-palette search     | 2 ms          |
| Lens/view state transition | 2 ms          |

Raw samples, the maximum observation, environment metadata, and the pass/fail
decision are written to
`performance/performance.json`. This generated file is local/CI evidence and is not
committed. Future SOM, scanner, and full TUI paths require their own budgets when
those capabilities exist.

`1337 doctor` is non-mutating. It checks the Python runtime, installed package,
current-directory read/write access, and optional Docker Compose support. Missing
optional Compose support is reported as `WARN`; a missing required runtime or
package returns a non-zero exit. Workspace/configuration persistence is available
through the Experimental library; `doctor` does not automatically load or certify
a selected workspace. See [the quickstart](QUICKSTART.md) for the supported entry points.

Tests are organized by subsystem in `tests/unit`, `tests/contract`, and
`tests/integration`; `tests/functional` owns isolated synthetic-target lifecycle
and finite-oracle regression checks. Unit tests are deterministic and carry an
automatic fail-closed guard against real network connections, including local
or Docker service sockets. The
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
