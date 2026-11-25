# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real two-case pytest/xdist smoke for the fixed partial-diagnostic plugin."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

from fuzzy1337 import test_progress, test_runner


def test_DefaultRunnerPartitionsCasesAcrossOverlappingWorkersThenAppendsSerialCoverage(
    tmp_path, monkeypatch,
):
    """Exercise actual scheduling, exact-once partitions and appended branch measurements."""

    root = Path(__file__).resolve().parents[2]
    monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join((str(tmp_path), str(root), str(root / "src"))))
    monkeypatch.setenv("COVERAGE_FILE", str(tmp_path / ".coverage"))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\nmarkers = serial: owns shared state\n"
        "addopts = --strict-markers --cov=subject --cov-branch "
        "--cov-report=json:coverage/coverage.json\n", encoding="utf-8",
    )
    (tmp_path / "subject.py").write_text(textwrap.dedent('''\
        """Measure different branches in the parallel and serial partitions."""

        def Select(mode):
            """Expose one branch owned by each partition."""

            if mode == "parallel":
                return 1

            return 2
        '''), encoding="utf-8")
    (tmp_path / "rendezvous.py").write_text(textwrap.dedent('''\
        """Require two genuinely overlapping workers without timing-based speed claims."""

        import json
        import os
        import time
        from pathlib import Path

        def Arrive():
            """Wait for a second worker while this worker still owns an active test."""

            worker = os.environ["PYTEST_XDIST_WORKER"]
            Path("ready-" + worker).write_text(str(os.getpid()), encoding="utf-8")
            deadline = time.monotonic() + 10

            while len(list(Path(".").glob("ready-*"))) < 2:
                assert time.monotonic() < deadline, "Two active workers never overlapped."
                time.sleep(0.01)

        def Record(name):
            """Create exactly one receipt, rejecting repeat execution of any case."""

            with Path("case-" + name).open("x", encoding="utf-8") as stream:
                json.dump({"worker": os.environ.get("PYTEST_XDIST_WORKER", "controller"),
                           "pid": os.getpid()}, stream)
        '''), encoding="utf-8")

    for name in ("alpha", "beta"):
        (tmp_path / f"test_{name}.py").write_text(textwrap.dedent(f'''\
            """Independent module with bounded deterministic cases."""

            import pytest
            import subject
            from rendezvous import Arrive, Record

            @pytest.mark.parametrize("value", range(4))
            def test_Parallel(value):
                """All cases must run once across two actual worker processes."""

                Arrive()
                assert subject.Select("parallel") == 1
                Record("{name}-" + str(value))
            '''), encoding="utf-8")

    (tmp_path / "test_serial.py").write_text(textwrap.dedent('''\
        """Shared-state exception must execute after every independent case."""

        import os
        from pathlib import Path
        import pytest
        import subject
        from rendezvous import Record

        @pytest.mark.serial
        def test_Serial():
            """Refuse early, worker-owned or repeated serial execution."""

            assert "PYTEST_XDIST_WORKER" not in os.environ
            assert len(list(Path(".").glob("case-*"))) == 8
            assert subject.Select("serial") == 2
            Record("serial")
        '''), encoding="utf-8")
    assert test_runner.RunTests(str(tmp_path), test_runner.TestOptions(jobs="2")) == 0, (
        "The actual default parallel/serial orchestration must succeed without retries."
    )
    receipts = {path.name.removeprefix("case-"): json.loads(path.read_text(encoding="utf-8"))
                for path in tmp_path.glob("case-*")}
    assert set(receipts) == {"serial"} | {
        f"{name}-{value}" for name in ("alpha", "beta") for value in range(4)
    }, "All nine cases must execute exactly once in disjoint partitions."
    workers = {receipt["worker"]: receipt["pid"] for name, receipt in receipts.items()
               if name != "serial"}
    assert set(workers) == {"gw0", "gw1"} and len(set(workers.values())) == 2, (
        "Both overlapping workers must be distinct operating-system processes."
    )
    assert receipts["serial"]["worker"] == "controller", "Serial work must not own an xdist worker."
    assert receipts["serial"]["pid"] not in workers.values(), (
        "Serial work must run in its own interpreter after the pool completes."
    )

    for name, count in (("parallel", 8), ("serial", 1)):
        summary = test_runner.ReadJunitSummary(tmp_path / "coverage" / f"{name}-tests.xml")
        assert (summary.total, summary.passed, summary.failed, summary.skipped) == (
            count, count, 0, 0,
        ), "JUnit must independently establish both actual partition counts without skips."

    measured = json.loads((tmp_path / "coverage" / "coverage.json").read_text(encoding="utf-8"))
    assert measured["meta"]["branch_coverage"] is True, "Both partitions must measure branches."
    subject = next(value for name, value in measured["files"].items()
                   if Path(name).name == "subject.py")
    assert subject["summary"]["num_branches"] == 2 and subject["missing_branches"] == [], (
        "Serial coverage must append its branch to the parallel measurement without overwriting it."
    )


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
    coveragePath = tmp_path / "startup-coverage.json"
    arguments = [sys.executable, "-m", "pytest", str(source), "-o", "addopts=", "-q",
                 "-p", "tools.pytest_progress", "--1337-progress", "--junitxml", str(report),
                 "-n", "2", "--dist=load", "--cov=fuzzy1337", "--cov-branch",
                 f"--cov-report=json:{coveragePath}"]
    ambientData = tmp_path / "parent.coverage"
    ambientData.write_bytes(b"owned-parent-coverage-marker")
    monkeypatch.setenv("COVERAGE_FILE", str(ambientData))
    environment = dict(os.environ, COVERAGE_FILE=str(tmp_path / "owned.coverage"))
    result = subprocess.run(arguments, cwd=root, check=False, shell=False, timeout=30,
                            capture_output=True, text=True, env=environment)
    assert ambientData.read_bytes() == b"owned-parent-coverage-marker", (
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

    coverage = json.loads(coveragePath.read_text(encoding="utf-8"))
    entries = {key.replace("\\", "/"): entry for key, entry in coverage["files"].items()}
    for name, wanted in (("__init__.py", {"__all__"}),
                         ("test_progress.py", {"KIND", "ProgressRecorder", "ConfigureProgress"})):
        sourcePath = root / "src" / "fuzzy1337" / name
        expected = set()
        for node in ast.parse(sourcePath.read_text(encoding="utf-8")).body:
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
