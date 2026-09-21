"""Tests for coverage gate behavior."""

import copy
import json

import pytest

from fuzzy1337.coverage_gate import Main, ValidateReport


@pytest.fixture(name="sample")
def Sample(tmp_path):
    """Provide the sample test fixture."""

    source = tmp_path / "src"
    source.mkdir()
    module = source / "example.py"
    module.write_text("value = 1\n", encoding="utf-8")
    report = {
        "meta": {"branch_coverage": True},
        "files": {
            module.as_posix(): {
                "summary": {
                    "covered_lines": 8,
                    "num_statements": 8,
                    "covered_branches": 1,
                    "num_branches": 2,
                    "excluded_lines": 0,
                },
            },
        },
    }
    return source, report


@pytest.mark.parametrize(
    "covered, total, fails",
    [(4, 5, True), (81, 100, False), (800001, 1000000, False), (0, 0, False)],
)
def test_StrictThresholdUsesExactCounts(sample, covered, total, fails):
    """Verify strict threshold uses exact counts."""

    source, report = sample
    summary = next(iter(report["files"].values()))["summary"]
    summary.update(covered_lines=covered, num_statements=total, covered_branches=0, num_branches=0)
    assert bool(ValidateReport(report, source)) is fails, (
        "strict threshold uses exact counts invariant failed."
    )


def test_CombinedScoreIncludesBranches(sample):
    """Verify combined score includes branches."""

    source, report = sample
    summary = next(iter(report["files"].values()))["summary"]
    summary["covered_branches"] = 0
    assert "80.00%" in ValidateReport(report, source)[0], (
        "combined score includes branches invariant failed."
    )


def test_WindowsStyleReportPathsAreAccepted(sample):
    """Verify windows style report paths are accepted."""

    source, report = sample
    module = next(iter(report["files"]))
    report["files"][module.replace("/", "\\")] = report["files"].pop(module)
    assert ValidateReport(report, source) == [], (
        "windows style report paths are accepted invariant failed."
    )


def test_HighTotalCannotHideLowModule(sample):
    """Verify high total cannot hide low module."""

    source, report = sample
    weak = source / "weak.py"
    weak.write_text("value = 1\n", encoding="utf-8")
    report["files"][weak.as_posix()] = {
        "summary": {
            "covered_lines": 4,
            "num_statements": 5,
            "covered_branches": 0,
            "num_branches": 0,
            "excluded_lines": 0,
        },
    }
    failures = ValidateReport(report, source)
    assert len(failures) == 1 and "weak.py" in failures[0], (
        "high total cannot hide low module invariant failed."
    )


def test_UnimportedOrOmittedModuleCannotDisappear(sample):
    """Verify unimported or omitted module cannot disappear."""

    source, report = sample
    (source / "unimported.py").write_text("value = 1\n", encoding="utf-8")
    assert "unimported.py: missing coverage" in ValidateReport(report, source)[0], (
        "unimported or omitted module cannot disappear invariant failed."
    )


@pytest.mark.parametrize(
    "field, value",
    [
        ("num_branches", None),
        ("covered_lines", True),
        ("covered_lines", -1),
        ("covered_lines", 99),
        ("covered_branches", 3),
        ("excluded_lines", 1),
    ],
)
def test_InvalidOrExcludedCountsFailClosed(sample, field, value):
    """Verify invalid or excluded counts fail closed."""

    source, report = sample
    next(iter(report["files"].values()))["summary"][field] = value
    with pytest.raises(ValueError):
        ValidateReport(report, source)


@pytest.mark.parametrize("replacement", [None, [], "malformed"])
def test_InvalidModuleEntriesFailClosed(sample, replacement):
    """Verify invalid module entries fail closed."""

    source, report = sample
    module = next(iter(report["files"]))
    report["files"][module] = replacement
    with pytest.raises(ValueError):
        ValidateReport(report, source)


@pytest.mark.parametrize("change", ["no_branches", "no_files", "empty_source"])
def test_RequiredInputsCannotBeSkipped(sample, change):
    """Verify required inputs cannot be skipped."""

    source, report = sample
    if change == "no_branches":
        report["meta"]["branch_coverage"] = False

    elif change == "no_files":
        del report["files"]

    else:
        (source / "example.py").unlink()

    with pytest.raises(ValueError):
        ValidateReport(report, source)


def test_CliSuccessAndModuleFailure(sample, tmp_path, capsys):
    """Verify cli success and module failure."""

    source, report = sample
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    assert Main([str(path), str(source)]) == 0, "cli success and module failure invariant failed."
    assert "strictly above 80%" in capsys.readouterr().out, (
        "cli success and module failure invariant failed."
    )
    broken = copy.deepcopy(report)
    broken["files"] = {}
    path.write_text(json.dumps(broken), encoding="utf-8")
    assert Main([str(path), str(source)]) == 1, "cli success and module failure invariant failed."
    assert "missing coverage" in capsys.readouterr().err, (
        "cli success and module failure invariant failed."
    )


@pytest.mark.parametrize("content", [None, "invalid json", "[]", '{"meta": []}'])
def test_MissingOrMalformedReportReturnsFailure(sample, tmp_path, content, capsys):
    """Verify missing or malformed report returns failure."""

    source, _ = sample
    path = tmp_path / "coverage.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    assert Main([str(path), str(source)]) == 1, (
        "missing or malformed report returns failure invariant failed."
    )
    assert "Coverage gate failed" in capsys.readouterr().err, (
        "missing or malformed report returns failure invariant failed."
    )
