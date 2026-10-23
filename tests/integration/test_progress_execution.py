# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real two-case pytest/xdist smoke for the fixed partial-diagnostic plugin."""

from __future__ import annotations

import json
import subprocess
import sys

from fuzzy1337 import test_progress, test_runner


def test_InstalledPluginPersistsTwoActualCasesWithoutChangingFailureEvidence(tmp_path):
    """Real worker hooks retain bounded progress while JUnit alone establishes a failed run."""

    source = tmp_path / "test_owned.py"
    source.write_text(
        'import pytest\n'
        '@pytest.mark.parametrize("value", [1, 2], ids=["PRIVATE-PASS", "PRIVATE-FAIL"])\n'
        'def test_Owned(value):\n'
        '    assert value == 1, "Owned deterministic failure."\n',
        encoding="utf-8",
    )
    report = tmp_path / "owned.xml"
    assert test_progress.PrepareProgress(report), "The owned subprocess needs a fresh directory."
    arguments = [sys.executable, "-m", "pytest", str(source), "-o", "addopts=", "-q",
                 "-p", "fuzzy1337.test_progress", "--1337-progress", "--junitxml", str(report),
                 "-n", "2", "--dist=load", "--no-cov"]
    result = subprocess.run(arguments, cwd=tmp_path, check=False, shell=False, timeout=30,
                            capture_output=True, text=True)
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
