# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Check the naming gate against owned and externally imposed spellings."""

from tools.python_naming import CheckSource


def test_OwnedLocalParameterAndCallableNamesAreDistinguished() -> None:
    """Recognize compiler-owned names while leaving call labels and wire keys alone."""

    source = """
from subprocess import run as run_command

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
