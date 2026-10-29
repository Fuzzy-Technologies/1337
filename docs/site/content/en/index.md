# 1337 API reference

![1337 Security Workbench by Fuzzy Technologies](assets/images/1337-logo.png)

This reference documents the 0.3.0 Community Python interfaces. Symbol visibility
is not a stability promise: consult the repository compatibility policy before
building an extension against a specific contract.

API pages are authored in English and rendered through static analysis of the
clean-installed wheel. The build never imports the security runtime.
Russian and Simplified Chinese routes currently show explicit English fallback
content. No translation has been marked approved.

Version 0.3.0 includes commands, workspace/scope, Security Object Model, evidence,
adapter and executor interfaces. The installed core supports an owned local demo,
selected first-party checks with attributable Findings, durable reopen and offline
reports. Optional Nmap, Nuclei and Trivy providers have their own explicit
prerequisites and approvals. Search covers every documented module.

## Try the release

Use CPython 3.11 or newer and a clean environment:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install 1337==0.3.0
1337 --version
1337 doctor
mkdir artifacts
1337 demo local artifacts/first-run --json
```

On Windows activate `.venv\Scripts\Activate.ps1` in PowerShell. The version command
must report `1337 0.3.0`. The demo preview must return exit **3** and
`approval_required` without starting a target. Read that actual finite loopback
plan; only if you approve exactly that invocation, run:

```bash
1337 demo local artifacts/first-run --approve-safe-http --json
1337 workspace open artifacts/first-run/workspace --json
1337 report export artifacts/first-run/workspace \
  --format html --output artifacts/first-run.html --json
```

Expect exit **0**, confirmed target teardown, model revision **3**, six objects,
zero Findings and three verified acquisitions. Reopen/export use saved state
after the target stops. Discovery and zero Findings do not establish a clean
target. Existing outputs are refused rather than overwritten.

The [tag-pinned quickstart](https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/QUICKSTART.md)
includes expected output, prerequisites and further recipes. To produce one LOW
Finding and verify its fixed negative control with only the installed core, copy
the complete [owned Git HEAD recipe](https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/OWNED_GIT_HEAD_RECIPE.md).
It supplies a nonsecret loopback fixture and explicit scope/policy; each STANDARD
positive/fixed plan requires its own exact confirmation. Human,
[AI-agent](https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/AGENT_QUICKSTART.md)
and [CI](https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/CI_QUICKSTART.md)
entry paths share these authority and evidence contracts. No model API, Docker or
external scanner is needed by these first recipes.

For development builds, clone the repository, select one full reviewed source
commit and use the quickstart's explicit source-wheel alternative. Retain that
commit and exact wheel identity; a package version alone does not identify a
development revision. For a local API example:

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
