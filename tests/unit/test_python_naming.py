# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Check the naming gate against owned and externally imposed spellings."""

import json

from tools import python_naming
from tools.python_naming import CheckSource


def test_OwnedLocalParameterAndCallableNamesAreDistinguished() -> None:
    """Recognize compiler-owned names while leaving call labels and wire keys alone."""

    source = """
from subprocess import run as run_command

module_setting = 1


class ReportState:
    stored_value = 2


def CollectReport(working_directory, *, maxItems):
    installed_version = 1
    _pendingValue = working_directory
    REPORT_LIMIT = maxItems
    report = {"installed_version": installed_version}
    run_command(["x"], capture_output=True)
    return report, _pendingValue, REPORT_LIMIT

def legacy_name():
    return None
"""
    findings = CheckSource(source, "src/example.py")

    assert {(kind, name) for _, kind, _, name in findings} == {
        ("parameter", "working_directory"), ("local", "installed_version"),
        ("callable", "legacy_name"),
    }, "Only first-party bindings and definitions may be reported."


def test_PytestInjectionAndDunderNamesRemainFrameworkOwned() -> None:
    """Keep pytest's injected parameters and Python protocol methods intact."""

    source = """
class Context:
    def __enter__(self):
        return self

def test_CollectReport(tmp_path, mock_server):
    scratchDirectory = tmp_path
    return scratchDirectory, mock_server
"""

    assert not CheckSource(source, "tests/unit/test_example.py"), (
        "Framework-owned signatures and camelCase locals must pass."
    )


def test_RepositoryGateRejectsNewAndObsoleteEntries(tmp_path, monkeypatch, capsys) -> None:
    """Check the CLI's real baseline comparison against a bounded temporary repository."""

    monkeypatch.setattr(python_naming, "__file__", str(tmp_path / "tools/python_naming.py"))
    baselinePath = tmp_path / python_naming.BASELINE
    baselinePath.parent.mkdir()
    baselinePath.write_text("[]", encoding="utf-8")
    sourcePath = tmp_path / "src/example.py"
    sourcePath.parent.mkdir()
    sourcePath.write_text("def CollectReport():\n    cacheValue = 1\n    return cacheValue\n",
                         encoding="utf-8")
    assert python_naming.Main() == 0, "A conforming source tree must pass the gate."

    source = "def CollectReport():\n    cache_value = 1\n    return cache_value\n"
    sourcePath.write_text(source, encoding="utf-8")
    assert python_naming.Main() == 1, "A new snake_case local must fail the gate."
    assert "new naming drift" in capsys.readouterr().out, "The reason must be explicit."

    baselinePath.write_text(json.dumps(list(CheckSource(source, "src/example.py").elements())),
                            encoding="utf-8")
    assert python_naming.Main() == 0, "The exact existing exception is accounted for."

    sourcePath.write_text(source.replace("cache_value", "cacheValue"), encoding="utf-8")
    assert python_naming.Main() == 1, "Obsolete exceptions must be removed."
    assert "obsolete naming exception" in capsys.readouterr().out, "Report the stale exception."
