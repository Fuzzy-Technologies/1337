# Try 1337 v0.2.1

This pre-alpha provides an interactive shell and Experimental Python foundations.
Use CPython 3.11 or newer and Git. Core runtime dependencies are empty. Docker and
Nmap are optional components; a missing optional component is not a broken installation.

## Install and inspect

```bash
git clone --branch v0.2.1 --depth 1 https://github.com/Fuzzy-Technologies/1337.git
cd 1337
python -m pip install uv==0.11.33
uv sync --locked
uv run --locked 1337 --version
uv run --locked 1337 help
uv run --locked 1337 doctor
uv run --locked 1337 update --json
uv run --locked 1337 shell
```

Version output is `1337 0.2.1`. `doctor` checks local runtime/package/path health;
missing optional Docker Compose is reported as a warning. `update --json` reports
`mutationsPerformed: false` and `updateAvailability: not_checked`. It installs
nothing and performs no remote version lookup.

## Explore the shell

Type the following inside the interactive shell:

```text
help
commands
lens devsecops
select asset:demo
context
palette
history
view updates
updates
quit
```

`context` reports the selected lens and opaque object reference. `palette` searches
local commands and cached contextual actions; completion uses deterministic fuzzy
matching. `history` searches recent in-memory commands. `updates` drains queued
messages and can be empty. Lens/view context is a foundation for later workflows;
the shell does not yet expose workspace management or a `scan` command, and does
not render the full split-pane Security Object Model.

## Create a temporary workspace and check scope

Save the following as `demo.py` in the checkout and run `uv run --locked python demo.py`.
It creates and removes only its own temporary workspace. No target is contacted.

```python
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from fuzzy1337.scope import ScopeSnapshot, Target, TargetKind
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

with TemporaryDirectory(prefix="1337-demo-") as directory:
    store = LocalWorkspaceStore(Path(directory) / "workspace")
    initial = store.Create(WorkspaceConfiguration("Synthetic demo"), "synthetic-demo")
    store.Save(initial)
    reopened = store.Open()
    print(reopened.workspace_id, reopened.revision)

    target = Target(TargetKind.IP, "127.0.0.1")
    scope = ScopeSnapshot("demo-scope", reopened.workspace_id).Register(target)
    decision = scope.Check(target, at=datetime(2026, 10, 8, tzinfo=timezone.utc))
    print(decision.Allowed(), decision.reason.value)
```

Expected output:

```text
synthetic-demo 1
False authorization_unknown
```

Registering a target never grants consent. Unknown consent fails closed, and even
an allowed offline scope decision does not issue execution authorization. See
[workspace lifecycle](WORKSPACES.md), [scope contracts](SCOPE.md),
[Security Object Model](SECURITY_MODEL.md), [evidence storage](EVIDENCE.md) and
[Nmap adapter](NMAP_ADAPTER.md) for supported API examples and limitations.

## Run an isolated lab example

With Docker Compose v2 available, execute the repository-owned micro-target test:

```bash
uv run --locked --extra dev python -m pytest tests/functional/test_web_micro.py -q -o addopts=''
```

Pytest owns startup, checks and teardown; the target publishes no host port.
Raw lifecycle evidence is retained under `functional-evidence/`. Docker-backed
tests explicitly skip when Docker is unavailable. This verifies the synthetic
target contract; it is not a production scanner-accuracy claim.

For a small feedback run without Docker:

```bash
uv run --locked --extra dev python -m pytest tests/unit/test_cli.py tests/unit/test_shell.py -q -o addopts=''
```

See [functional testing](FUNCTIONAL_TESTING.md) for the micro-target oracle,
attack-path mini lab and optional pinned Juice Shop pack, and
[container development](CONTAINERS.md) for the Compose workbench.

## Documentation

The [generated English API reference](https://fuzzy-technologies.github.io/1337/api/latest/en/)
contains the introductory examples and all documented modules. It is built from a
clean-installed wheel without importing security providers and published after a
validated push to protected `master`. The Russian and Simplified Chinese API routes
currently contain explicitly marked English fallback content.

The `latest` URL follows published `master`. For this exact release, use
[the v0.2.1 README](https://github.com/Fuzzy-Technologies/1337/blob/v0.2.1/README.md)
and [tag-pinned documentation](https://github.com/Fuzzy-Technologies/1337/tree/v0.2.1/docs).
