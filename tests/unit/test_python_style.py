"""Executable checks for the accepted Fuzzy Technologies Python style."""

from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOTS = ("src", "tests", "labs")
CYRILLIC_PATTERN = re.compile(r"[\u0400-\u04FF]")
PASCAL_PATTERN = re.compile(r"[A-Z][A-Za-z0-9]*")
SNAKE_PATTERN = re.compile(r"_?[a-z][a-z0-9]*(?:_[a-z0-9]+)*")
UPPER_SNAKE_PATTERN = re.compile(r"_?[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*")
TEST_FUNCTION_PATTERN = re.compile(r"test_[A-Z][A-Za-z0-9]*")
FRAMEWORK_FUNCTIONS = {
    "completenames",
    "default",
    "log_message",
    "onecmd",
    "precmd",
    "pytest_collection_modifyitems",
    "pytest_configure",
    "pytest_sessionfinish",
    "pytest_xdist_auto_num_workers",
}
EXTERNAL_PARAMETERS = {
    "server_version",
    "sys_version",
    "tmp_path",
    "tmp_path_factory",
    "unused_tcp_port",
    "worker_id",
}


def PythonFiles() -> tuple[Path, ...]:
    """Return every project Python source in deterministic order."""

    return tuple(
        sorted(
            path
            for root in PYTHON_ROOTS
            for path in (REPOSITORY_ROOT / root).rglob("*.py")
        )
    )


def Relative(path: Path) -> str:
    """Return a stable repository-relative diagnostic path."""

    return path.relative_to(REPOSITORY_ROOT).as_posix()


def IsFrameworkFunction(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether Python or a framework owns a callback name."""

    name = node.name
    is_pytest_fixture = any(
        (isinstance(decorator, ast.Name) and decorator.id == "fixture")
        or (isinstance(decorator, ast.Attribute) and decorator.attr == "fixture")
        or (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr == "fixture"
        )
        for decorator in node.decorator_list
    )
    return (
        is_pytest_fixture
        or
        name in FRAMEWORK_FUNCTIONS
        or name.startswith("do_")
        or (name.startswith("__") and name.endswith("__"))
    )


def DocstringNodes(tree: ast.Module) -> tuple[ast.AST, ...]:
    """Return nodes governed by the repository docstring contract."""

    return (
        tree,
        *(
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        ),
    )


def ModuleConstants(tree: ast.Module) -> tuple[ast.Name, ...]:
    """Return module-level names whose uppercase spelling marks constants."""

    constants = []
    for statement in tree.body:
        targets: tuple[ast.expr, ...] = ()
        if isinstance(statement, ast.Assign):
            targets = tuple(statement.targets)

        elif isinstance(statement, ast.AnnAssign):
            targets = (statement.target,)

        for target in targets:
            if isinstance(target, ast.Name) and target.id.isupper():
                constants.append(target)

    return tuple(constants)


def test_ProjectOwnedIdentifiersFollowStyleContract():
    """Verify callable, parameter, class, and constant naming."""

    violations = []
    for path in PythonFiles():
        tree = ast.parse(path.read_text(encoding="utf-8"))

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("test_"):
                    valid_name = TEST_FUNCTION_PATTERN.fullmatch(node.name)

                else:
                    valid_name = IsFrameworkFunction(node) or PASCAL_PATTERN.fullmatch(
                        node.name
                    )
                if not valid_name:
                    violations.append(f"{Relative(path)}:{node.lineno}: function {node.name}")

                arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
                for argument in arguments:
                    if argument.arg in {"self", "cls", *EXTERNAL_PARAMETERS}:
                        continue
                    if not SNAKE_PATTERN.fullmatch(argument.arg):
                        violations.append(
                            f"{Relative(path)}:{argument.lineno}: parameter {argument.arg}"
                        )

            elif isinstance(node, ast.ClassDef) and not PASCAL_PATTERN.fullmatch(node.name):
                violations.append(f"{Relative(path)}:{node.lineno}: class {node.name}")

        for constant in ModuleConstants(tree):
            if not UPPER_SNAKE_PATTERN.fullmatch(constant.id):
                violations.append(
                    f"{Relative(path)}:{constant.lineno}: constant {constant.id}"
                )

    assert not violations, (
        "Project-owned identifier style invariant failed:\n" + "\n".join(violations)
    )


def test_DocstringsCommentsAndAssertionsAreEnglishAndActionable():
    """Require English documentation and diagnostic assertion messages."""

    violations = []
    for path in PythonFiles():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        for node in DocstringNodes(tree):
            docstring = ast.get_docstring(node, clean=False)
            line = getattr(node, "lineno", 1)
            name = getattr(node, "name", "module")
            if docstring is None:
                violations.append(f"{Relative(path)}:{line}: missing docstring for {name}")

            elif CYRILLIC_PATTERN.search(docstring):
                violations.append(f"{Relative(path)}:{line}: non-English docstring")

        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type != tokenize.COMMENT:
                continue
            comment = token.string.removeprefix("#").strip()
            if comment and CYRILLIC_PATTERN.search(comment):
                violations.append(f"{Relative(path)}:{token.start[0]}: non-English comment")

        for node in ast.walk(tree):
            if isinstance(node, ast.Assert) and node.msg is None:
                violations.append(f"{Relative(path)}:{node.lineno}: assert without message")

    assert not violations, (
        "Python documentation invariant failed:\n" + "\n".join(violations)
    )


def test_NoCyrillicTextAppearsInPythonSources():
    """Keep all Python code and embedded source text English-only."""

    violations = []
    for path in PythonFiles():
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if CYRILLIC_PATTERN.search(line):
                violations.append(f"{Relative(path)}:{line_number}")

    assert not violations, "Cyrillic text found in Python sources:\n" + "\n".join(violations)
