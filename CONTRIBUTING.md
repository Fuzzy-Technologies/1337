# Contributing

Thanks for helping improve 1337 Security Workbench.

Before making changes, read [DEVELOPMENT_PROTOCOL.md](DEVELOPMENT_PROTOCOL.md). It is the canonical engineering and Git workflow for this repository.

For a normal contribution:

1. Start from an existing issue or open one first.
2. Create a focused branch from `develop`.
3. Keep the change small and include the relevant tests or documentation.
4. Run `uv run --locked --extra dev 1337-dev check` when applicable.
5. Open a pull request to `develop` and link the owning issue.

The Python naming audit in CI checks function and method names, parameters, and
function-scope local bindings. Module-level bindings and class fields require
separate review. See the [naming audit implementation](tools/python_naming.py).

Do not report security vulnerabilities in public issues. Follow [SECURITY.md](SECURITY.md) instead.
