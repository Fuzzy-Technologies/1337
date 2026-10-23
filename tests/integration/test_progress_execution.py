# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real two-case pytest/xdist smoke for the fixed partial-diagnostic plugin."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

from fuzzy1337 import test_progress, test_runner


def test_InstalledPluginPersistsTwoActualCasesWithoutChangingFailureEvidence(
    tmp_path, monkeypatch,
):
    """Real worker hooks retain bounded progress while JUnit alone establishes a failed run."""

    source = tmp_path / "test_owned.py"
    source.write_text(
        'import ast\n'
        'from pathlib import Path\n'
        'import coverage\n'
        'import pytest\n'
        'import fuzzy1337\n'
        'from fuzzy1337 import test_progress\n'
        '@pytest.mark.parametrize("value", [1, 2], ids=["PRIVATE-PASS", "PRIVATE-FAIL"])\n'
        'def test_Owned(value):\n'
        '    active = coverage.Coverage.current()\n'
        '    assert active is not None, "Each worker must have active coverage."\n'
        '    for module in (fuzzy1337, test_progress):\n'
        '        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))\n'
        '        first = next(node for node in tree.body\n'
        '                     if isinstance(node, (ast.Assign, ast.AnnAssign)))\n'
        '        data = active.get_data()\n'
        '        suffix = "fuzzy1337/" + Path(module.__file__).name\n'
        '        name = next((entry for entry in data.measured_files()\n'
        '                     if entry.replace(chr(92), "/").endswith(suffix)), "")\n'
        '        measured = data.lines(name) or []\n'
        '        assert first.lineno in measured, "Worker startup must be measured."\n'
        '    assert value == 1, "Owned deterministic failure."\n',
        encoding="utf-8",
    )
    report = tmp_path / "owned.xml"
    assert test_progress.PrepareProgress(report), "The owned subprocess needs a fresh directory."
    root = Path(__file__).resolve().parents[2]
    coverage_path = tmp_path / "startup-coverage.json"
    arguments = [sys.executable, "-m", "pytest", str(source), "-o", "addopts=", "-q",
                 "-p", "tools.pytest_progress", "--1337-progress", "--junitxml", str(report),
                 "-n", "2", "--dist=load", "--cov=fuzzy1337", "--cov-branch",
                 f"--cov-report=json:{coverage_path}"]
    ambient_data = tmp_path / "parent.coverage"
    ambient_data.write_bytes(b"owned-parent-coverage-marker")
    monkeypatch.setenv("COVERAGE_FILE", str(ambient_data))
    environment = dict(os.environ, COVERAGE_FILE=str(tmp_path / "owned.coverage"))
    result = subprocess.run(arguments, cwd=root, check=False, shell=False, timeout=30,
                            capture_output=True, text=True, env=environment)
    assert ambient_data.read_bytes() == b"owned-parent-coverage-marker", (
        "The nested coverage run must never purge or overwrite its parent's measurement data."
    )
    assert result.returncode == 1, "The actual failing test must retain pytest's failure status."
    authoritative = test_runner.ReadJunitSummary(report)
    assert (authoritative.total, authoritative.passed, authoritative.failed) == (2, 1, 1), (
        "The real JUnit report must establish both actual case outcomes independently."
    )
    summary = test_progress.SaveProgressSummary(report, timed_out=False)
    assert (summary["completed"], summary["passed"], summary["failed"]) == (2, 1, 1), (
        "The actual worker plugin must retain both complete phase protocols exactly once."
    )
    assert set(summary["workers"]) == {"gw0", "gw1"}, (
        "Both real workers must produce separate bounded streams without controller duplicates."
    )
    assert summary["partial"] and summary["diagnostic_only"], (
        "Even a finished invocation's progress artifact remains explicitly diagnostic-only."
    )
    raw = json.dumps(summary)
    assert "PRIVATE" not in raw and str(tmp_path) not in raw, (
        "Progress diagnostics must exclude parameter values and full paths."
    )

    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    entries = {key.replace("\\", "/"): entry for key, entry in coverage["files"].items()}
    for name, wanted in (("__init__.py", {"__all__"}),
                         ("test_progress.py", {"KIND", "ProgressRecorder", "ConfigureProgress"})):
        source_path = root / "src" / "fuzzy1337" / name
        expected = set()
        for node in ast.parse(source_path.read_text(encoding="utf-8")).body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in wanted:
                expected.add(node.lineno)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if node.target.id in wanted:
                    expected.add(node.lineno)
            elif isinstance(node, ast.Assign):
                if any(isinstance(target, ast.Name) and target.id in wanted
                       for target in node.targets):
                    expected.add(node.lineno)
        entry = next(value for key, value in entries.items()
                     if key.endswith("src/fuzzy1337/" + name))
        assert len(expected) == len(wanted) and expected <= set(entry["executed_lines"]), (
            "Actual -p startup must measure package initialization and recorder definitions."
        )
    captured = result.stdout + result.stderr
    assert "module-not-measured" not in captured and "already-imported" not in captured, (
        "The bootstrap must not import the measured application before worker coverage starts."
    )
