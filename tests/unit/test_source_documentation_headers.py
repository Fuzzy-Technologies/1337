# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Fail closed on ownership and authored public source-documentation regressions."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COPYRIGHT_HEADER = "# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies"
LICENSE_HEADER = "# SPDX-License-Identifier: Apache-2.0"
HEADERS = f"{COPYRIGHT_HEADER}\n{LICENSE_HEADER}\n\n"
PYTHON_ROOTS = ("src", "tests", "tools")
SECTION_PATTERN = re.compile(r"^(Args|Returns|Yields|Raises|Attributes):$")
ARGUMENT_PATTERN = re.compile(r"^\s+\*{0,2}([A-Za-z_]\w*)(?:\s*\([^)]*\))?:\s*\S")


def Sections(docstring: str) -> dict[str, list[str]]:
    """Collect nonempty Google-style section bodies for contract assertions.

    Args:
        docstring: Authored text normalized by ast.get_docstring.

    Returns:
        Section names mapped to their nonempty indented lines.
    """

    sections: dict[str, list[str]] = {}
    current: str | None = None

    for line in docstring.splitlines():
        match = SECTION_PATTERN.fullmatch(line)

        if match:
            current = match.group(1)
            sections.setdefault(current, [])

        elif current is not None and line.strip():
            if line.startswith(" "):
                sections[current].append(line)

            else:
                current = None

    return sections


def DocumentationFailures(source: str, require_contracts: bool) -> tuple[str, ...]:
    """Check authored scopes without importing or executing inspected source.

    Args:
        source: Python text with the required ownership and license prefix.
        require_contracts: Require complete public interfaces for source/tool roles.

    Returns:
        Header, syntax, authored-docstring and applicable public-contract violations.
    """

    lines = source.splitlines()
    start = 1 if lines and lines[0].startswith("#!") else 0
    failures = []

    if lines[start:start + 2] != [COPYRIGHT_HEADER, LICENSE_HEADER]:
        failures.append("ownership/license headers must match the source contract")

    try:
        tree = ast.parse(source)

    except SyntaxError:
        return (*failures, "source must parse before documentation can pass")

    def Inspect(node: ast.AST, public: bool, nested_function: bool = False) -> None:
        """Walk authored scopes while distinguishing public and nested callables.

        Args:
            node: AST node to inspect without evaluating its contents.
            public: Whether all enclosing names have a public spelling.
            nested_function: Whether a function ancestor makes this a local helper.
        """

        is_scope = isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        )
        is_function = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        name = getattr(node, "name", "module") if is_scope else "module"
        public = public and not name.startswith("_")
        docstring = ast.get_docstring(node) if is_scope else None

        if is_scope and not docstring:
            failures.append(f"{name}: missing authored docstring")

        if is_function and require_contracts and public and not nested_function:
            assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)), (
                "Callable contract checks require a function AST node."
            )
            sections = Sections(docstring or "")
            described = {
                match.group(1)
                for line in sections.get("Args", [])
                if (match := ARGUMENT_PATTERN.match(line)) is not None
            }
            parameters = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]

            for variadic in (node.args.vararg, node.args.kwarg):
                if variadic is not None:
                    parameters.append(variadic)

            for parameter in parameters:
                if parameter.arg in {"self", "cls"}:
                    continue

                if parameter.arg not in described:
                    failures.append(f"{name}: missing Args description for {parameter.arg}")

                if parameter.annotation is None:
                    failures.append(f"{name}: missing annotation for {parameter.arg}")

            if node.returns is None:
                failures.append(f"{name}: missing return annotation")

            elif not (isinstance(node.returns, ast.Constant) and node.returns.value is None):
                if not (sections.get("Returns") or sections.get("Yields")):
                    failures.append(f"{name}: missing nonempty Returns or Yields section")

        for child in ast.iter_child_nodes(node):
            Inspect(child, public, nested_function or is_function)

    Inspect(tree, True)

    return tuple(failures)


def test_SourceDocumentationAndHeadersMatchContract() -> None:
    """Require headers and docstrings everywhere, and complete public source contracts."""

    violations = []

    for root in PYTHON_ROOTS:
        directory = REPOSITORY_ROOT / root

        if root in {"src", "tests"}:
            assert directory.is_dir(), f"Required Python inventory root is absent: {root}"

        if directory.is_symlink():
            violations.append(f"{root}: inventory roots must not be symlinks")
            continue

        for path in sorted(directory.rglob("*.py")):
            relative = path.relative_to(REPOSITORY_ROOT).as_posix()

            if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
                violations.append(f"{relative}: Python source must not follow symlinks")
                continue

            failures = DocumentationFailures(path.read_text(encoding="utf-8"), root != "tests")
            violations.extend(f"{relative}: {failure}" for failure in failures)

    assert not violations, "Source documentation/header contract failed:\n" + "\n".join(violations)


@pytest.mark.parametrize("header", ["", LICENSE_HEADER, COPYRIGHT_HEADER,
                                      HEADERS.replace("2026", "2025"),
                                      HEADERS.replace("Apache-2.0", "MIT")])
def test_MissingOrDifferentOwnershipFails(header: str) -> None:
    """Reject missing, partial, stale or conflicting license/ownership declarations."""

    failures = DocumentationFailures(header + '\n"""Fixture module."""\n', False)

    assert failures, "Incomplete or conflicting SPDX declarations must fail the source gate."


@pytest.mark.parametrize("source", [
    "value = 1\n",
    '"""Module."""\nclass Record:\n    pass\n',
    '"""Module."""\ndef Hidden() -> None:\n    pass\n',
    '"""Module."""\ndef Invalid(\n',
])
def test_MissingDocstringsAndInvalidSyntaxFail(source: str) -> None:
    """Reject absent authored scopes and syntax errors without importing source."""

    failures = DocumentationFailures(HEADERS + source, False)

    assert failures, "Absent authored docstrings or invalid syntax must fail the source gate."


@pytest.mark.parametrize("body", [
    '"""Describe input.\n\n    Returns:\n        Output.\n    """',
    '"""Describe input.\n\n    Args:\n        other: Wrong parameter.\n'
    '    Returns:\n        Output.\n    """',
    '"""Describe input.\n\n    Args:\n        value:\n    Returns:\n        Output.\n    """',
    '"""Describe input.\n\n    Args:\n        value: Input.\n    Returns:\n    """',
])
def test_IncompletePublicContractsFail(body: str) -> None:
    """Reject missing parameters, empty descriptions and empty return sections."""

    source = HEADERS + '"""Fixture module."""\ndef Parse(value: str) -> str:\n    '
    failures = DocumentationFailures(source + body + "\n    return value\n", True)

    assert failures, "Every public parameter and non-None return needs a nonempty description."


def test_TestHelpersAllowConciseDocstrings() -> None:
    """Preserve concise test docs without imposing repetitive fixture-argument boilerplate."""

    source = HEADERS + '"""Fixture module."""\ndef test_Example(tmp_path):\n'
    source += '    """Verify fixture behavior."""\n    return tmp_path\n'

    assert not DocumentationFailures(source, False), (
        "Test documentation requires authored intent, not public API argument sections."
    )


def test_PublicContractsDescribeVariadicsAndYieldValues() -> None:
    """Accept described variadic parameters and generator yields without importing them."""

    source = HEADERS + '"""Fixture module."""\ndef Collect(*values: str):\n'
    source += '    """Collect values.\n\n    Args:\n        *values: Input values.\n'
    source += '    Yields:\n        Each input value.\n    """\n    yield from values\n'
    source = source.replace("(*values: str):", "(*values: str) -> object:")

    assert not DocumentationFailures(source, True), (
        "Nonempty Yields and described variadic arguments must satisfy the API contract."
    )


def test_UnannotatedPublicContractsFail() -> None:
    """Reject unannotated public parameters and returns even with prose present."""

    source = HEADERS + '"""Fixture module."""\ndef Parse(value):\n'
    source += '    """Parse input.\n\n    Args:\n        value: Input.\n'
    source += '    Returns:\n        Output.\n    """\n    return value\n'
    failures = DocumentationFailures(source, True)

    assert len(failures) == 2, "Public parameter and return annotations must both be enforced."


def test_NoneReturnAndNestedHelpersAvoidRedundantSections() -> None:
    """Permit summary-only no-return APIs and locally scoped helper documentation."""

    source = HEADERS + '"""Fixture module."""\ndef Notify() -> None:\n'
    source += '    """Notify an observer."""\n\n    def Local(value):\n'
    source += '        """Keep local value."""\n        return value\n\n    Local(1)\n'

    assert not DocumentationFailures(source, True), (
        "None-return APIs and nested helpers do not require redundant Returns sections."
    )


def test_InspectionDoesNotExecuteModuleBodies() -> None:
    """Inspect malicious-looking source text without executing its module statements."""

    source = HEADERS + '"""Fixture module."""\nraise RuntimeError("never execute")\n'

    assert not DocumentationFailures(source, True), (
        "Documentation validation must remain static even when module bodies would raise."
    )
