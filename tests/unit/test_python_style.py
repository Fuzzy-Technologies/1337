# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Executable checks for the accepted Fuzzy Technologies Python style."""

from __future__ import annotations

import ast
import io
import re
import sys
import tokenize
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOTS = ("src", "tests", "labs")
CYRILLIC_PATTERN = re.compile(r"[\u0400-\u04FF]")
PASCAL_PATTERN = re.compile(r"[A-Z][A-Za-z0-9]*")
# The compiler-backed naming gate owns the finite snake_case baseline.
PARAMETER_PATTERN = re.compile(r"_?(?:[a-z][A-Za-z0-9]*|[a-z][a-z0-9]*(?:_[a-z0-9]+)+)")
UPPER_SNAKE_PATTERN = re.compile(r"_?[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*")
TEST_FUNCTION_PATTERN = re.compile(r"test_[A-Z][A-Za-z0-9]*")
FRAMEWORK_FUNCTIONS = {
    "completenames",
    "default",
    # StringIO/TextIO owns these callbacks; DemoEventOutput implements their exact interface.
    "flush",
    # socketserver.BaseRequestHandler owns the request-dispatch callback spelling.
    "handle",
    # HTMLParser owns these exact markup and text callbacks.
    "handle_data",
    "handle_comment",
    "handle_decl",
    "handle_endtag",
    "handle_pi",
    "handle_startendtag",
    "handle_starttag",
    "unknown_decl",
    "log_message",
    "onecmd",
    "precmd",
    # Pytest owns these exact plugin hook callback names.
    "pytest_addoption",
    "pytest_runtest_logstart",
    "pytest_runtest_logreport",
    "pytest_collection_modifyitems",
    "pytest_configure",
    "pytest_sessionfinish",
    "pytest_sessionstart",
    "pytest_xdist_auto_num_workers",
    "write",
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
        sorted(path for root in PYTHON_ROOTS for path in (REPOSITORY_ROOT / root).rglob("*.py"))
    )


def Relative(path: Path) -> str:
    """Return a stable repository-relative diagnostic path."""

    return path.relative_to(REPOSITORY_ROOT).as_posix()


def IsFrameworkFunction(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether Python or a framework owns a callback name."""

    name = node.name
    isPytestFixture = any(
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
        isPytestFixture
        or name in FRAMEWORK_FUNCTIONS
        or name.startswith("do_")
        or (name.startswith("__") and name.endswith("__"))
    )


def test_TextIoOverridesRetainFrameworkNamesWithoutExemptingOwnedHelpers():
    """Recognize real StringIO callbacks while ordinary project-owned helpers retain PascalCase."""

    tree = ast.parse((REPOSITORY_ROOT / "src/fuzzy1337/demo.py").read_text(encoding="utf-8"))
    recorder = next(node for node in tree.body
                    if isinstance(node, ast.ClassDef) and node.name == "DemoEventOutput")
    assert any(isinstance(base, ast.Name) and base.id == "StringIO" for base in recorder.bases), (
        "The demo recorder must implement its actual standard-library StringIO boundary."
    )
    callbacks = [node for node in recorder.body
                 if isinstance(node, ast.FunctionDef) and node.name in {"write", "flush"}]
    assert {node.name for node in callbacks} == {"write", "flush"}, (
        "The recorder must preserve both framework-owned TextIO callback names."
    )
    assert all(IsFrameworkFunction(node) for node in callbacks), (
        "The style checker must recognize the recorder's genuine StringIO overrides."
    )
    helper = ast.parse("def retain_events():\n    pass\n").body[0]
    assert isinstance(helper, ast.FunctionDef) and not IsFrameworkFunction(helper), (
        "Adding TextIO callbacks must not exempt unrelated lowercase project-owned helpers."
    )


def test_SocketServerOverridesRetainFrameworkNamesWithoutExemptingOwnedHelpers():
    """Preserve the actual StreamRequestHandler callback without renaming its dispatch boundary."""

    source = REPOSITORY_ROOT / "tests/functional/test_native_prometheus.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    handler = next(node for node in ast.walk(tree)
                   if isinstance(node, ast.ClassDef) and node.name == "Handler")
    assert any(isinstance(base, ast.Attribute) and base.attr == "StreamRequestHandler"
               for base in handler.bases), "The owned fixture must use the real server boundary."
    callback = next(node for node in handler.body
                    if isinstance(node, ast.FunctionDef) and node.name == "handle")
    assert IsFrameworkFunction(callback), "The server callback must retain its external name."
    helper = ast.parse("def serve_request():\n    pass\n").body[0]
    assert isinstance(helper, ast.FunctionDef) and not IsFrameworkFunction(helper), (
        "Recognizing the server callback must not exempt ordinary project-owned helpers."
    )


def test_HtmlParserCallbacksRetainFrameworkNamesWithoutExemptingOwnedHelpers():
    """Preserve actual stdlib markup callbacks while requiring PascalCase for owned helpers."""

    from html.parser import HTMLParser

    source = REPOSITORY_ROOT / "src/fuzzy1337/adapters/directory_listing.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    parser = next(node for node in tree.body
                  if isinstance(node, ast.ClassDef) and node.name == "DirectoryIndexParser")
    assert any(isinstance(base, ast.Name) and base.id == "HTMLParser" for base in parser.bases), (
        "The parser must implement the actual standard-library dispatch interface."
    )
    callbacks = [node for node in parser.body if isinstance(node, ast.FunctionDef)
                 and node.name in {"handle_startendtag", "handle_comment", "handle_decl",
                                   "handle_pi", "unknown_decl"}]
    assert len(callbacks) == 5 and all(hasattr(HTMLParser, node.name)
                                      and IsFrameworkFunction(node) for node in callbacks), (
        "Every new callback exemption must correspond to the inherited HTMLParser contract."
    )
    helper = ast.parse("def parse_directory():\n    pass\n").body[0]
    assert isinstance(helper, ast.FunctionDef) and not IsFrameworkFunction(helper), (
        "HTMLParser callbacks must not exempt an unrelated lowercase project-owned helper."
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


def SourceViolations(path: Path, source: str) -> tuple[str, ...]:
    """Check every existing style rule in one source read, parse and AST walk."""

    tree = ast.parse(source)
    violations = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("test_"):
                validName = TEST_FUNCTION_PATTERN.fullmatch(node.name)

            else:
                validName = IsFrameworkFunction(node) or PASCAL_PATTERN.fullmatch(node.name)

            if not validName:
                violations.append(f"{Relative(path)}:{node.lineno}: function {node.name}")

            arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)

            for argument in arguments:
                if argument.arg in {"_", "self", "cls", *EXTERNAL_PARAMETERS}:
                    continue

                if not PARAMETER_PATTERN.fullmatch(argument.arg):
                    violations.append(
                        f"{Relative(path)}:{argument.lineno}: parameter {argument.arg}"
                    )

        elif isinstance(node, ast.ClassDef) and not PASCAL_PATTERN.fullmatch(node.name):
            violations.append(f"{Relative(path)}:{node.lineno}: class {node.name}")

        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            docstring = ast.get_docstring(node, clean=False)
            line = getattr(node, "lineno", 1)
            name = getattr(node, "name", "module")
            if docstring is None:
                violations.append(f"{Relative(path)}:{line}: missing docstring for {name}")

            elif CYRILLIC_PATTERN.search(docstring):
                violations.append(f"{Relative(path)}:{line}: non-English docstring")

        if isinstance(node, ast.Assert) and node.msg is None:
            violations.append(f"{Relative(path)}:{node.lineno}: assert without message")

    for constant in ModuleConstants(tree):
        if not UPPER_SNAKE_PATTERN.fullmatch(constant.id):
            violations.append(f"{Relative(path)}:{constant.lineno}: constant {constant.id}")

    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type != tokenize.COMMENT:
            continue

        comment = token.string.removeprefix("#").strip()

        if comment and CYRILLIC_PATTERN.search(comment):
            violations.append(f"{Relative(path)}:{token.start[0]}: non-English comment")

    for lineNumber, line in enumerate(source.splitlines(), start=1):
        if CYRILLIC_PATTERN.search(line):
            violations.append(f"{Relative(path)}:{lineNumber}: Cyrillic text")

    return tuple(violations)


def test_RepositoryPythonSourcesFollowCompleteStyleContract():
    """Validate all source naming, documentation and language rules in one uncached traversal."""

    violations = []

    for path in PythonFiles():
        violations.extend(SourceViolations(path, path.read_text(encoding="utf-8")))

    assert not violations, "Python source style invariant failed:\n" + "\n".join(violations)


def AssertRejectedSource(temporaryPath, monkeypatch, source, expected):
    """Run the real repository traversal on a selected inert source and require its diagnostic."""

    selected = temporaryPath / "src" / "owned.py"
    selected.parent.mkdir()
    selected.write_text(source, encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "REPOSITORY_ROOT", temporaryPath)

    with pytest.raises(AssertionError, match=re.escape(expected)) as caught:
        test_RepositoryPythonSourcesFollowCompleteStyleContract()

    assert "src/owned.py:" in str(caught.value), "Refusal must identify the actual selected source"


@pytest.mark.parametrize("source,expected", [
    ('"""Owned module."""\ndef owned_helper():\n    """Owned helper."""\n',
     "function owned_helper"),
    ('"""Owned module."""\nasync def owned_helper():\n    """Owned helper."""\n',
     "function owned_helper"),
    ('"""Owned module."""\ndef test_lowercase():\n    """Owned test."""\n',
     "function test_lowercase"),
    ('"""Owned module."""\nclass bad_class:\n    """Owned class."""\n', "class bad_class"),
    ('"""Owned module."""\nclass _Hidden:\n    """Owned class."""\n', "class _Hidden"),
    ('"""Owned module."""\ndef Owned(BadArgument):\n    """Owned helper."""\n',
     "parameter BadArgument"),
    ('"""Owned module."""\ndef Owned(BadPositional, /):\n    """Owned helper."""\n',
     "parameter BadPositional"),
    ('"""Owned module."""\ndef Owned(*, BadKeyword):\n    """Owned helper."""\n',
     "parameter BadKeyword"),
    ('"""Owned module."""\nBAD__VALUE = 1\n', "constant BAD__VALUE"),
    ('"""Owned module."""\nBAD__VALUE: int = 1\n', "constant BAD__VALUE"),
])
def test_IdentifierMatcherRejectsInertViolations(tmp_path, monkeypatch, source, expected):
    """Every naming category remains a failing rule, including private and asynchronous helpers."""

    AssertRejectedSource(tmp_path, monkeypatch, source, expected)


@pytest.mark.parametrize("source,expected", [
    ("value = 1\n", "missing docstring for module"),
    ('"""Owned module."""\ndef Owned():\n    pass\n', "missing docstring for Owned"),
    ('"""Owned module."""\nasync def Owned():\n    pass\n', "missing docstring for Owned"),
    ('"""Owned module."""\nclass Owned:\n    pass\n', "missing docstring for Owned"),
    ('"""\u0410."""\n', "non-English docstring"),
    ('"""Owned module."""\n# \u0410\n', "non-English comment"),
    ('"""Owned module."""\nassert True\n', "assert without message"),
])
def test_DocumentationMatcherRejectsInertViolations(
    tmp_path, monkeypatch, source, expected,
):
    """Prove documentation and assertion regressions fail through the full source validator."""

    AssertRejectedSource(tmp_path, monkeypatch, source, expected)


@pytest.mark.parametrize("source", [
    '"""Owned module."""\nvalue = "\u0410"\n',
    '"""Owned module."""\n# \u0410\n',
    '"""\u0410."""\n',
    '"""Owned module."""\n\u0410 = 1\n',
])
def test_CyrillicMatcherRejectsInertSourceContexts(tmp_path, monkeypatch, source):
    """Reject Cyrillic in literals, comments, docstrings and identifiers without executing it."""

    AssertRejectedSource(tmp_path, monkeypatch, source, "Cyrillic text")


def test_RepeatedValidationSeesChangedAndNewFilesWithoutAProcessCache(tmp_path, monkeypatch):
    """A second traversal sees new files and same-length edits instead of trusting stale results."""

    selected = tmp_path / "src" / "owned.py"
    selected.parent.mkdir()
    valid = '"""Owned module."""\ndef Owned():\n    """Owned helper."""\n'
    selected.write_text(valid, encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "REPOSITORY_ROOT", tmp_path)
    test_RepositoryPythonSourcesFollowCompleteStyleContract()
    selected.write_text(valid.replace("def Owned", "def owned"), encoding="utf-8")

    with pytest.raises(AssertionError, match="function owned"):
        test_RepositoryPythonSourcesFollowCompleteStyleContract()

    selected.write_text(valid, encoding="utf-8")
    test_RepositoryPythonSourcesFollowCompleteStyleContract()
    added = tmp_path / "labs" / "added.py"
    added.parent.mkdir()
    added.write_text('"""Owned module."""\nassert True\n', encoding="utf-8")

    with pytest.raises(AssertionError, match="labs/added.py:2: assert without message"):
        test_RepositoryPythonSourcesFollowCompleteStyleContract()
