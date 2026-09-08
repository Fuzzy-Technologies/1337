import copy
import json

import pytest

from fuzzy1337.coverage_gate import main, validate_report


@pytest.fixture
def sample(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    module = source / "example.py"
    module.write_text("value = 1\n", encoding="utf-8")
    report = {
        "meta": {"branch_coverage": True},
        "files": {
            module.as_posix(): {"summary": {
                "covered_lines": 8, "num_statements": 8,
                "covered_branches": 1, "num_branches": 2, "excluded_lines": 0,
            }},
        },
    }
    return source, report


@pytest.mark.parametrize("covered, total, fails", [(4, 5, True), (81, 100, False), (800001, 1000000, False), (0, 0, False)])
def test_strict_threshold_uses_exact_counts(sample, covered, total, fails):
    source, report = sample
    summary = next(iter(report["files"].values()))["summary"]
    summary.update(covered_lines=covered, num_statements=total, covered_branches=0, num_branches=0)
    assert bool(validate_report(report, source)) is fails


def test_combined_score_includes_branches(sample):
    source, report = sample
    summary = next(iter(report["files"].values()))["summary"]
    summary["covered_branches"] = 0
    assert "80.00%" in validate_report(report, source)[0]


def test_windows_style_report_paths_are_accepted(sample):
    source, report = sample
    module = next(iter(report["files"]))
    report["files"][module.replace("/", "\\")] = report["files"].pop(module)
    assert validate_report(report, source) == []


def test_high_total_cannot_hide_low_module(sample):
    source, report = sample
    weak = source / "weak.py"
    weak.write_text("value = 1\n", encoding="utf-8")
    report["files"][weak.as_posix()] = {"summary": {
        "covered_lines": 4, "num_statements": 5, "covered_branches": 0,
        "num_branches": 0, "excluded_lines": 0,
    }}
    failures = validate_report(report, source)
    assert len(failures) == 1 and "weak.py" in failures[0]


def test_unimported_or_omitted_module_cannot_disappear(sample):
    source, report = sample
    (source / "unimported.py").write_text("value = 1\n", encoding="utf-8")
    assert "unimported.py: missing coverage" in validate_report(report, source)[0]


@pytest.mark.parametrize("field, value", [
    ("num_branches", None), ("covered_lines", True), ("covered_lines", -1),
    ("covered_lines", 99), ("covered_branches", 3), ("excluded_lines", 1),
])
def test_invalid_or_excluded_counts_fail_closed(sample, field, value):
    source, report = sample
    next(iter(report["files"].values()))["summary"][field] = value
    with pytest.raises(ValueError):
        validate_report(report, source)


@pytest.mark.parametrize("replacement", [None, [], "malformed"])
def test_invalid_module_entries_fail_closed(sample, replacement):
    source, report = sample
    module = next(iter(report["files"]))
    report["files"][module] = replacement
    with pytest.raises(ValueError):
        validate_report(report, source)


@pytest.mark.parametrize("change", ["no_branches", "no_files", "empty_source"])
def test_required_inputs_cannot_be_skipped(sample, change):
    source, report = sample
    if change == "no_branches":
        report["meta"]["branch_coverage"] = False
    elif change == "no_files":
        del report["files"]
    else:
        (source / "example.py").unlink()
    with pytest.raises(ValueError):
        validate_report(report, source)


def test_cli_success_and_module_failure(sample, tmp_path, capsys):
    source, report = sample
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    assert main([str(path), str(source)]) == 0
    assert "strictly above 80%" in capsys.readouterr().out
    broken = copy.deepcopy(report)
    broken["files"] = {}
    path.write_text(json.dumps(broken), encoding="utf-8")
    assert main([str(path), str(source)]) == 1
    assert "missing coverage" in capsys.readouterr().err


@pytest.mark.parametrize("content", [None, "invalid json", "[]", '{"meta": []}'])
def test_missing_or_malformed_report_returns_failure(sample, tmp_path, content, capsys):
    source, _ = sample
    path = tmp_path / "coverage.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    assert main([str(path), str(source)]) == 1
    assert "Coverage gate failed" in capsys.readouterr().err
