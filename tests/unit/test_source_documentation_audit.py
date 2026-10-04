# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0
"""Negative and boundary tests for import-free source documentation auditing."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from tools import source_documentation_audit as audit

HEADER = f"{audit.COPYRIGHT_HEADER}\n{audit.LICENSE_HEADER}\n"
CLEAN_MODULE = HEADER + '''"""A minimal structural contract fixture."""
__all__ = ["Transform"]


def Transform(value: int, *, factor: int = 1) -> int:
    """Scale the caller's value.

    Args:
        value: Original integer.
        factor: Multiplication factor.

    Returns:
        Scaled integer.
    """

    return value * factor
'''


def Repository(tmp_path: Path, source: str = CLEAN_MODULE, area: str = "src") -> Path:
    """Create explicit audit roots and one controlled Python source.

    Args:
        tmp_path: Temporary fixture boundary.
        source: Literal authored source text.
        area: Owned source area containing the fixture.

    Returns:
        Temporary repository boundary.
    """

    tmp_path.mkdir(parents=True, exist_ok=True)

    for name in audit.SOURCE_ROOTS:
        (tmp_path / name).mkdir(exist_ok=True)

    (tmp_path / area / "fixture.py").write_text(source, encoding="utf-8")

    return tmp_path


def Link(link: Path, target: Path, *, directory: bool = False) -> None:
    """Create a controlled link or explicitly skip platforms denying symlink privileges."""

    try:
        link.symlink_to(target, target_is_directory=directory)

    except (OSError, NotImplementedError):
        pytest.skip("Controlled symlink tests require filesystem symlink support and privileges.")


def test_CleanInventoryIsDeterministicAndDoesNotImport(tmp_path: Path) -> None:
    """Prove source analysis never executes inspected module statements."""

    root = Repository(tmp_path, CLEAN_MODULE + '\nraise RuntimeError("must never execute")\n')
    first = audit.Audit(root)
    second = audit.Audit(root)
    assert first == second, "Audit changed for identical source inputs."
    assert first["status"] == "PASS", "Complete structural fixture unexpectedly failed."
    assert first["files"][0]["exports"] == ["Transform"], "Explicit exports were not honored."
    assert len(first["files"][0]["sha256"]) == 64, "Source digest is missing or malformed."
    assert first["limitations"], "Inventory must preserve semantic-review limitations."


@pytest.mark.parametrize(("source", "rule"), [
    ('value = 1\n', "DOCSTRING_MISSING"),
    ('"""Purpose."""\n', "SPDX_LICENSE"),
    (CLEAN_MODULE.replace("value: int", "value"), "PARAMETER_ANNOTATION"),
    (CLEAN_MODULE.replace(" -> int", ""), "RETURN_ANNOTATION"),
    (CLEAN_MODULE.replace("        value: Original integer.\n", ""), "ARGS_DOCUMENTATION"),
    (CLEAN_MODULE.replace("    Returns:\n        Scaled integer.\n", ""), "RETURN_DOCUMENTATION"),
    (CLEAN_MODULE + '\n__all__ = BuildExports()\n', "EXPORT_REVIEW"),
    (CLEAN_MODULE + '\ndef Broken(:\n', "SOURCE_UNREADABLE"),
])
def test_NegativeContractsFailClosed(tmp_path: Path, source: str, rule: str) -> None:
    """Reject incomplete or unparseable source instead of silently passing."""

    root = Repository(tmp_path, source)
    report = audit.Audit(root)
    assert report["status"] == "FAIL", f"Malformed {rule} fixture escaped fail-closed auditing."
    assert rule in report["counts"], f"Expected structural {rule} diagnosis was absent."


def test_TestAndPrivateContractsAreAdvisory(tmp_path: Path) -> None:
    """Keep test purpose docs sufficient without redundant Google-style sections."""

    source = HEADER + '''"""Test fixture scope."""


def test_Example(tmp_path):
    """Verify a controlled temporary boundary."""

    return tmp_path
'''
    root = Repository(tmp_path, source, "tests")
    report = audit.Audit(root)
    assert report["status"] == "PASS", "Test contract recommendations became mandatory errors."
    assert report["role_counts"]["tests"]["review"] == 3, "Test annotation reviews were lost."
    (root / "src" / "private.py").write_text(source.replace("test_Example", "_Example"))
    assert audit.Audit(root)["status"] == "PASS", "Private contracts must stay review findings."


def test_LanguageAndStalenessAreBoundedHeuristics(tmp_path: Path) -> None:
    """Report script/debt evidence without certifying prose or semantic staleness."""

    non_latin = chr(0x0410)
    source = CLEAN_MODULE + f"\n# {non_latin}\n# TO" + "DO: pending contract\n"
    report = audit.Audit(Repository(tmp_path, source))
    assert report["counts"]["LANGUAGE_REVIEW"] == 1, "Script heuristic failed to flag review."
    assert report["counts"]["COMMENT_DEBT_MARKER"] == 1, "Debt marker policy was not diagnosed."
    assert report["status"] == "FAIL", "Forbidden debt markers must remain enforcement errors."
    assert any("cannot certify" in text for text in report["limitations"]), (
        "Report omitted the explicit English detection limitation."
    )


def test_ShebangMatchesExecutableOwnership(tmp_path: Path) -> None:
    """Require executable/shebang consistency and an accepted interpreter."""

    root = Repository(tmp_path)
    path = root / "src" / "fixture.py"
    original_stat = Path.stat
    mode = 0o755

    def SourceMode(candidate: Path, **kwargs: object) -> os.stat_result:
        """Emulate executable mode bits independently of the host platform."""

        result = original_stat(candidate, **kwargs)

        if candidate != path:
            return result
        fields = list(result)
        fields[0] = (fields[0] & ~0o777) | mode

        return os.stat_result(fields)

    with patch.object(Path, "stat", SourceMode):
        assert "SHEBANG_MISSING" in audit.Audit(root)["counts"], (
            "Executable lacked required shebang."
        )
        path.write_text("#!/usr/bin/env python3\n" + CLEAN_MODULE)
        assert audit.Audit(root)["status"] == "PASS", "Valid executable source failed audit."
        mode = 0o644
        assert "SHEBANG_NONEXECUTABLE" in audit.Audit(root)["counts"], (
            "Nonexecutable shebang escaped."
        )
        path.write_text("#!/bin/sh\n" + CLEAN_MODULE)
        assert "SHEBANG_INTERPRETER" in audit.Audit(root)["counts"], "Wrong interpreter escaped."


def test_SymlinksMissingRootsAndExclusionsAreExplicit(tmp_path: Path) -> None:
    """Refuse linked sources and required-root omissions without reading their targets."""

    root = Repository(tmp_path)
    Link(root / "tests" / "linked.py", root / "src" / "fixture.py")
    Link(root / "tools" / "linked", root / "src", directory=True)
    cache = root / "tests" / "__pycache__"
    cache.mkdir()
    (cache / "ignored.py").write_text("invalid source !")
    report = audit.Audit(root)
    assert report["counts"]["SYMLINK_REFUSED"] == 2, "Linked file/directory was traversed."
    assert report["excluded_paths"] == ["tests/__pycache__"], "Cache exclusion was not recorded."
    assert len(report["files"]) == 1, "Linked or excluded source leaked into inventory."
    (root / "tools" / "linked").unlink()
    (root / "tools").rmdir()
    assert audit.Audit(root)["absent_optional_roots"] == ["tools"], (
        "Legitimately absent tools root must be explicit rather than a false error."
    )
    (root / "tests" / "linked.py").unlink()
    (cache / "ignored.py").unlink()
    cache.rmdir()
    (root / "tests").rmdir()
    assert "ROOT_UNSAFE" in audit.Audit(root)["counts"], "Missing required root silently passed."


def test_ParseFailureAndTraversalFailureRemainErrors(tmp_path: Path) -> None:
    """Preserve deterministic diagnoses for unavailable or unreadable source trees."""

    root = Repository(tmp_path)
    missing = audit.AuditFile(root / "src" / "missing.py", root)
    assert missing["findings"][0]["rule"] == "SOURCE_UNREADABLE", "Read failure was not preserved."
    real_walk = audit.os.walk

    def FailingWalk(directory: Path, **kwargs: object) -> object:
        """Emulate denied traversal without depending on local privilege levels."""

        callback = kwargs["onerror"]
        assert callable(callback), "Traversal must install a fail-closed error callback."
        callback(PermissionError(13, "denied"))

        return real_walk(directory, **kwargs)

    with patch.object(audit.os, "walk", FailingWalk):
        report = audit.Audit(root)

    assert report["counts"]["TRAVERSAL_FAILED"] == 3, "Traversal failures disappeared from report."


def test_VariadicNestedMethodsAndNoReturnDocumentation(tmp_path: Path) -> None:
    """Keep receiver exclusions and nested/private review applicability predictable."""

    source = HEADER + '''"""Scoped fixture."""


class Example:
    """Expose a public method and an internal helper."""

    def Apply(self, *values: int, **options: int) -> None:
        """Consume caller configuration.

        Args:
            *values: Input values.
            **options: Configuration values.
        """

        def Nested(value):
            """Return the inner value."""

            return value

        Nested(1)
'''
    report = audit.Audit(Repository(tmp_path, source))
    assert report["status"] == "PASS", "None returns or nested functions incorrectly required docs."
    assert report["role_counts"]["src"]["review"] == 3, "Nested callable suggestions were lost."
    parameters = audit.Parameters(ast.parse(source).body[1].body[1])
    assert [argument.arg for argument in parameters] == ["values", "options"], (
        "Implicit method receiver polluted the authored parameter contract."
    )


def test_InventoryModeCheckModeAndIOFailure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Separate review inventory from enforcement and preserve nonzero I/O failures."""

    root = Repository(tmp_path)
    output = root / "output"
    argv = ["--root", str(root), "--output", str(output)]
    assert audit.Main(["--check", *argv]) == 0, "Clean structural fixture failed check mode."
    report = json.loads((output / "inventory.json").read_text())
    assert (output / "inventory.md").read_text() == audit.Markdown(report), "Output views diverged."
    (root / "src" / "fixture.py").write_text("missing = 1\n")
    assert audit.Main(["--inventory", *argv]) == 0, "Inventory mode must retain gap reports."
    assert audit.Main(["--check", *argv]) == 1, "Check mode silently accepted structural gaps."
    assert audit.Main(["--check", "--root", str(root / "absent"), "--output", str(output)]) == 2, (
        "Root I/O failure did not return the documented failure code."
    )
    blocked = root / "blocked"
    blocked.write_text("cannot be a directory")
    assert audit.Main(["--inventory", "--root", str(root), "--output", str(blocked)]) == 2, (
        "Output I/O failure did not return the documented failure code."
    )
    assert "Source audit" in capsys.readouterr().out, "CLI result summary was absent."


def test_OutputBoundaryRefusesSymlinksAndParentEscape(tmp_path: Path) -> None:
    """Ensure report generation cannot write through links or outside its selected root."""

    root = Repository(tmp_path / "repository")
    external = tmp_path / "external"
    external.mkdir()
    Link(root / "linked-output", external, directory=True)
    argv = ["--inventory", "--root", str(root)]
    assert audit.Main([*argv, "--output", "linked-output"]) == 2, (
        "Linked report output crossed the selected repository boundary."
    )
    assert audit.Main([*argv, "--output", "../external"]) == 2, (
        "Parent-relative output crossed the selected repository boundary."
    )
    assert not (external / "inventory.json").exists(), "External report output was written."
    alias = tmp_path / "alias"
    Link(alias, root, directory=True)
    assert audit.Main(["--inventory", "--root", str(alias)]) == 2, (
        "A linked repository root was silently followed."
    )
