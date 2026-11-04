# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Check project-owned Python naming while retaining documented compatibility debt."""

from __future__ import annotations

import ast
import json
import re
import symtable
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

PYTHON_ROOTS = ("src", "tests", "tools", "labs", "docs")
BASELINE = Path("contracts/python-naming-baseline.json")
SNAKE_IDENTIFIER = re.compile(r"_?[a-z][a-z0-9]*(?:_[a-z0-9]+)+\Z")
PASCAL_IDENTIFIER = re.compile(r"_?[A-Z][A-Za-z0-9]*\Z")
Finding = tuple[str, str, str, str]


def SourceFiles(root: Path) -> Iterator[Path]:
    """Yield source files across production, tests, developer tools, examples and labs.

    Args:
        root: Repository root containing the declared source directories.

    Yields:
        Candidate Python files in deterministic directory and path order.
    """

    for directory in PYTHON_ROOTS:
        yield from sorted((root / directory).rglob("*.py"))


def ScopeFindings(
    table: symtable.SymbolTable, file: str, parents: tuple[str, ...] = (),
) -> Iterator[Finding]:
    """Use compiler bindings to distinguish locals and parameters from external names.

    Args:
        table: Compiler scope to inspect, including any nested scopes.
        file: Repository-relative Python source path.
        parents: Qualified ancestor scope names.

    Yields:
        Stable records for owned binding names that require review.
    """

    scope = parents + (table.get_name(),)

    if table.get_type() == symtable.SymbolTableType.FUNCTION:
        for symbol in table.get_symbols():
            name = symbol.get_name()

            if not SNAKE_IDENTIFIER.fullmatch(name) or symbol.is_imported():
                continue

            if symbol.is_parameter():
                if not (file.startswith("tests/") and table.get_name().startswith("test_")):
                    yield file, "parameter", ".".join(scope), name

            elif symbol.is_local() and symbol.is_assigned() and not symbol.is_namespace():
                yield file, "local", ".".join(scope), name

    for child in table.get_children():
        yield from ScopeFindings(child, file, scope)


def CallableFindings(
    node: ast.AST, file: str, parents: tuple[str, ...] = (),
) -> Iterator[Finding]:
    """Inspect definitions without classifying call-site keyword or attribute names.

    Args:
        node: Current Python syntax node.
        file: Repository-relative Python source path.
        parents: Qualified ancestor definition names.

    Yields:
        Callable naming candidates outside the declared spelling conventions.
    """

    scope = parents

    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        name = node.name
        test = file.startswith("tests/") and name.startswith("test_")
        spelling = name.removeprefix("test_") if test else name

        if not PASCAL_IDENTIFIER.fullmatch(spelling) and not (
            name.startswith("__") and name.endswith("__")
        ):
            yield file, "callable", ".".join(parents), name

        scope = parents + (name,)

    elif isinstance(node, ast.ClassDef):
        scope = parents + (node.name,)

    for child in ast.iter_child_nodes(node):
        yield from CallableFindings(child, file, scope)


def CheckSource(source: str, file: str) -> Counter[Finding]:
    """Return naming candidates keyed independently of line movement.

    Args:
        source: Complete Python module text.
        file: Repository-relative Python source path.

    Returns:
        Multiset of stable binding and definition findings.
    """

    tree = ast.parse(source, filename=file)
    table = symtable.symtable(source, file, "exec")

    return Counter((*ScopeFindings(table, file), *CallableFindings(tree, file)))


def Inventory(root: Path) -> Counter[Finding]:
    """Inventory names from all declared Python source roots.

    Args:
        root: Repository root to scan.

    Returns:
        Multiset of naming findings across the declared roots.
    """

    findings: Counter[Finding] = Counter()

    for path in SourceFiles(root):
        findings.update(CheckSource(path.read_text(encoding="utf-8"),
                                    path.relative_to(root).as_posix()))

    return findings


def ReadBaseline(root: Path) -> Counter[Finding]:
    """Read the finite reviewed naming inventory kept with the source.

    Args:
        root: Repository root owning the baseline file.

    Returns:
        Multiset of recorded naming exceptions.
    """

    return Counter(tuple(record) for record in json.loads((root / BASELINE).read_text(
        encoding="utf-8")))


def Main() -> int:
    """Fail CI on new drift and require obsolete baseline entries to be removed.

    Returns:
        Zero when the checked inventory matches or one when it differs.
    """

    root = Path(__file__).resolve().parents[1]
    current = Inventory(root)
    baseline = ReadBaseline(root)
    added, obsolete = current - baseline, baseline - current

    for label, records in (("new naming drift", added), ("obsolete naming exception", obsolete)):
        for file, kind, scope, name in sorted(records.elements()):
            print(f"{file}: {label}: {kind} {scope}:{name}")

    return int(bool(added or obsolete))


if __name__ == "__main__":
    raise SystemExit(Main())
