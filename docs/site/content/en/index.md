# 1337 API reference

![1337 Security Workbench by Fuzzy Technologies](assets/images/1337-logo.png)

This reference documents the current Community Python interfaces. Symbol visibility
is not a stability promise: consult the repository compatibility policy before
building an extension against a specific contract.

API pages are authored in English and rendered through static analysis of the
clean-installed wheel. The build never imports the security runtime.
Russian and Simplified Chinese routes currently show explicit English fallback
content. No translation has been marked approved.

The v0.2.0 pre-alpha includes commands, workspace/scope, Security Object Model,
evidence, adapter and executor interfaces. Search covers every documented module.

## Try the release

Use CPython 3.11 or newer and Git:

```bash
git clone --branch v0.2.0 --depth 1 https://github.com/Fuzzy-Technologies/1337.git
cd 1337
python -m pip install uv==0.11.33
uv sync --locked
uv run --locked 1337 --version
uv run --locked 1337 doctor
uv run --locked 1337 update --json
uv run --locked 1337 shell
```

Inside the shell, try `help`, `commands`, `lens devsecops`, `select asset:demo`,
`context`, `palette`, `history`, and `quit`. The shell maintains local context;
it does not yet provide a `scan` command or the full split-pane model view.

The [tag-pinned quickstart](https://github.com/Fuzzy-Technologies/1337/blob/v0.2.0/docs/QUICKSTART.md)
includes expected output and isolated-lab commands. For a local API example:

```python
from pathlib import Path
from tempfile import TemporaryDirectory

from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

with TemporaryDirectory(prefix="1337-demo-") as directory:
    store = LocalWorkspaceStore(Path(directory) / "workspace")
    initial = store.Create(WorkspaceConfiguration("Synthetic demo"), "synthetic-demo")
    store.Save(initial)
    print(store.Open().revision)
```

This prints `1` and removes its own temporary workspace. It contacts no target.
See the [workspace API](api/fuzzy1337.workspace.md), [scope API](api/fuzzy1337.scope.md),
[model API](api/fuzzy1337.model.md), [evidence API](api/fuzzy1337.evidence.md), and
[Nmap API](api/fuzzy1337.adapters.nmap.md). These surfaces are Experimental;
offline scope membership does not grant execution authority.

## Coverage rule

For each first-party module, the manifest declares an authored reference surface
or a documented exclusion. A new module requires a manifest decision before the
strict build succeeds. The representative inline formula $x$ and block formula
below verify the locally hosted MathJax SVG renderer:

$$
x^2
$$

## Product site and language routes

- [Product overview](/1337/)
- [English API reference](/1337/api/latest/en/)
- [Russian route with explicit English fallback](/1337/api/latest/ru/)
- [Simplified Chinese route with explicit English fallback](/1337/api/latest/zh-cn/)
