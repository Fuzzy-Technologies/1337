"""Executable checks for the accepted Fuzzy Technologies Python style."""

from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path

REPOSITORYROOT = Path(__file__).resolve().parents[2]
PYTHONROOTS = ("src", "tests", "labs")
CYRILLICPATTERN = re.compile(r"[А-Яа-яЁё]")
PASCALPATTERN = re.compile(r"[A-Z][A-Za-z0-9]*")
LOWERCAMELPATTERN = re.compile(r"[a-z][A-Za-z0-9]*")
TESTFUNCTIONPATTERN = re.compile(r"test_[A-Z][A-Za-z0-9]*")
BRANCHPATTERN = re.compile(r"^\s*(elif\b|else\s*:|except\b|finally\s*:)")
FRAMEWORKFUNCTIONS = {
    "completenames",
    "default",
    "do_EOF",
    "do_GET",
    "do_POST",
    "log_message",
    "onecmd",
    "precmd",
    "pytest_collection_modifyitems",
    "pytest_configure",
    "pytest_sessionfinish",
    "pytest_xdist_auto_num_workers",
}
EXTERNALNAMES = {
    "server_version",
    "sys_version",
    "tmp_path",
    "tmp_path_factory",
    "unused_tcp_port",
    "worker_id",
}
EXTERNALATTRIBUTES = {
    "BAD_REQUEST",
    "NOT_FOUND",
    "REQUEST_ENTITY_TOO_LARGE",
    "R_OK",
    "W_OK",
    "add_argument",
    "as_posix",
    "assert_called_once",
    "assert_called_once_with",
    "assert_not_called",
    "call_count",
    "check_schema",
    "col_offset",
    "cpu_count",
    "create_connection",
    "end_col_offset",
    "end_headers",
    "end_lineno",
    "generate_tokens",
    "get_docstring",
    "is_absolute",
    "is_dir",
    "is_file",
    "is_relative_to",
    "kwonlyargs",
    "parse_args",
    "posonlyargs",
    "print_help",
    "read_text",
    "relative_to",
    "run_module",
    "send_error",
    "send_header",
    "send_response",
    "serve_forever",
    "write_text",
    "version_info",
}


def PythonFiles() -> tuple[Path, ...]:
    """Return every tracked-area Python source in deterministic order."""

    return tuple(
        sorted(
            path
            for root in PYTHONROOTS
            for path in (REPOSITORYROOT / root).rglob("*.py")
        )
    )


def Relative(path: Path) -> str:
    """Return a stable repository-relative diagnostic path."""

    return path.relative_to(REPOSITORYROOT).as_posix()


def ExternalBindings(tree: ast.Module) -> set[str]:
    """Return names imposed by Python or third-party imports."""

    bindings = set(EXTERNALNAMES)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            bindings.update(item.asname or item.name.split(".")[0] for item in node.names)

        elif (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and not (node.module or "").startswith("fuzzy1337")
        ):
            bindings.update(item.asname or item.name for item in node.names)

    return bindings


def IsFrameworkFunction(name: str) -> bool:
    """Return whether an external framework owns a callback name."""

    return (
        name in FRAMEWORKFUNCTIONS
        or name.startswith("do_")
        or (name.startswith("__") and name.endswith("__"))
    )


def DocstringNodes(tree: ast.Module) -> tuple[ast.AST, ...]:
    """Return all nodes governed by the repository docstring contract."""

    return (
        tree,
        *(
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        ),
    )


def test_ProjectOwnedIdentifiersFollowStyleContract():
    """Verify project-owned names follow PascalCase, lowerCamelCase, and compact constants."""

    violations = []
    for path in PythonFiles():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        externalBindings = ExternalBindings(tree)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("test_"):
                    validName = TESTFUNCTIONPATTERN.fullmatch(node.name)

                else:
                    validName = IsFrameworkFunction(node.name) or PASCALPATTERN.fullmatch(
                        node.name
                    )
                if not validName:
                    violations.append(f"{Relative(path)}:{node.lineno}: function {node.name}")

                arguments = (
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                )
                for argument in arguments:
                    if argument.arg in {"_", "self", "cls", *EXTERNALNAMES}:
                        continue
                    if not LOWERCAMELPATTERN.fullmatch(argument.arg):
                        violations.append(
                            f"{Relative(path)}:{argument.lineno}: parameter {argument.arg}"
                        )

            if isinstance(node, ast.Name):
                if (
                    "_" in node.id
                    and node.id != "_"
                    and node.id not in externalBindings
                    and not (node.id.startswith("__") and node.id.endswith("__"))
                    and not node.id.isupper()
                ):
                    violations.append(f"{Relative(path)}:{node.lineno}: name {node.id}")

            if isinstance(node, ast.Attribute):
                if (
                    "_" in node.attr
                    and node.attr not in EXTERNALATTRIBUTES
                    and not (node.attr.startswith("__") and node.attr.endswith("__"))
                ):
                    violations.append(f"{Relative(path)}:{node.lineno}: field {node.attr}")

    assert not violations, (
        "Project-owned identifier style invariant failed:\n" + "\n".join(violations)
    )


def test_DocstringsCommentsAndAssertionsFollowLanguageContract():
    """Verify required documentation and assertion diagnostics use the correct language."""

    violations = []
    for path in PythonFiles():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        isTest = "tests" in path.parts

        for node in DocstringNodes(tree):
            docstring = ast.get_docstring(node, clean=False)
            line = getattr(node, "lineno", 1)
            name = getattr(node, "name", "module")
            if docstring is None:
                violations.append(f"{Relative(path)}:{line}: missing docstring for {name}")

            elif isTest and CYRILLICPATTERN.search(docstring):
                violations.append(f"{Relative(path)}:{line}: non-English test docstring")

            elif not isTest and not CYRILLICPATTERN.search(docstring):
                violations.append(f"{Relative(path)}:{line}: non-Russian production docstring")

        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type != tokenize.COMMENT:
                continue
            comment = token.string.removeprefix("#").strip()
            if not comment or comment.startswith(("noqa", "type:")):
                continue
            if isTest and CYRILLICPATTERN.search(comment):
                violations.append(f"{Relative(path)}:{token.start[0]}: non-English comment")
            if not isTest and not CYRILLICPATTERN.search(comment):
                violations.append(f"{Relative(path)}:{token.start[0]}: non-Russian comment")

        for node in ast.walk(tree):
            if isinstance(node, ast.Assert) and node.msg is None:
                violations.append(f"{Relative(path)}:{node.lineno}: assert without message")

    assert not violations, (
        "Python documentation language invariant failed:\n" + "\n".join(violations)
    )


def test_VerticalSpacingFollowsControlFlowContract():
    """Verify docstrings and control-flow transitions use the required blank lines."""

    violations = []
    for path in PythonFiles():
        source = path.read_text(encoding="utf-8")
        lines = source.splitlines()
        tree = ast.parse(source)

        for node in DocstringNodes(tree):
            if not getattr(node, "body", None):
                continue
            firstStatement = node.body[0]
            if not isinstance(firstStatement, ast.Expr):
                continue
            if not isinstance(firstStatement.value, ast.Constant):
                continue
            if not isinstance(firstStatement.value.value, str):
                continue
            endIndex = firstStatement.end_lineno
            if endIndex < len(lines) and lines[endIndex].strip():
                violations.append(
                    f"{Relative(path)}:{endIndex + 1}: missing blank after docstring"
                )
            if endIndex + 1 < len(lines) and not lines[endIndex + 1].strip():
                violations.append(
                    f"{Relative(path)}:{endIndex + 2}: extra blank after docstring"
                )

        for index, line in enumerate(lines):
            if not BRANCHPATTERN.match(line):
                continue
            hasOneBlank = (
                index > 0
                and not lines[index - 1].strip()
                and (index < 2 or lines[index - 2].strip())
            )
            if not hasOneBlank:
                violations.append(
                    f"{Relative(path)}:{index + 1}: branch needs exactly one leading blank"
                )
            if index + 1 < len(lines) and not lines[index + 1].strip():
                violations.append(
                    f"{Relative(path)}:{index + 2}: blank immediately after branch"
                )

        for node in ast.walk(tree):
            if not isinstance(
                node,
                (
                    ast.ClassDef,
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.If,
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.With,
                    ast.AsyncWith,
                    ast.Try,
                    ast.ExceptHandler,
                    ast.Match,
                ),
            ):
                continue
            if node.body and node.body[0].lineno > 1:
                lineBeforeBody = lines[node.body[0].lineno - 2]
                if not lineBeforeBody.strip():
                    violations.append(
                        f"{Relative(path)}:{node.body[0].lineno}: blank after block header"
                    )

    assert not violations, (
        "Python vertical-spacing invariant failed:\n" + "\n".join(violations)
    )
