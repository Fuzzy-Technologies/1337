"""Проверяет совокупное покрытие ветвей и строк каждого production-модуля."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def ValidateReport(report: dict[str, Any], source: Path) -> list[str]:
    """Возвращает нарушения и отклоняет пропущенные модули или неверные счётчики."""

    meta = report.get("meta")
    if not isinstance(meta, dict) or meta.get("branch_coverage") is not True:
        raise ValueError("Branch coverage must be enabled.")
    files = report.get("files")
    if not isinstance(files, dict):
        raise ValueError("Coverage report must contain a files object.")
    modules = sorted(source.rglob("*.py"))
    if not modules:
        raise ValueError("The production source inventory is empty.")

    failures = []
    for path in modules:
        name = path.as_posix()
        # coverage.py сохраняет платформенный разделитель в относительных путях.
        reportKey = next(
            (key for key in (name, str(path), name.replace("/", "\\")) if key in files),
            None,
        )
        if reportKey is None:
            failures.append(f"{name}: missing coverage")
            continue

        entry = files[reportKey]
        if not isinstance(entry, dict):
            raise ValueError(f"{name}: invalid coverage entry")

        summary = entry.get("summary")
        if not isinstance(summary, dict):
            raise ValueError(f"{name}: invalid coverage summary")

        keys = (
            "covered_lines",
            "num_statements",
            "covered_branches",
            "num_branches",
            "excluded_lines",
        )
        counts = [summary.get(key) for key in keys]
        if any(type(value) is not int or value < 0 for value in counts):
            raise ValueError(f"{name}: invalid coverage counts")

        coveredLines, statements, coveredBranches, branches, excluded = (
            int(summary[key]) for key in keys
        )
        if coveredLines > statements or coveredBranches > branches or excluded:
            raise ValueError(f"{name}: inconsistent counts or undocumented exclusions")

        covered = coveredLines + coveredBranches
        total = statements + branches
        if total and covered * 5 <= total * 4:
            failures.append(
                f"{name}: {covered}/{total} = {100 * covered / total:.2f}% (must be >80%)"
            )

    return failures


def Main(argv: Sequence[str] | None = None) -> int:
    """Сверяет свежий JSON-отчёт покрытия с исходными модулями на диске."""

    parser = argparse.ArgumentParser(
        description=__doc__,
    )
    parser.add_argument("report", type=Path)
    parser.add_argument("source", type=Path)
    arguments = parser.parse_args(argv)
    try:
        report = json.loads(arguments.report.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ValueError("Coverage report must be a JSON object.")
        failures = ValidateReport(report, arguments.source)

    except (OSError, ValueError, TypeError, AttributeError) as error:
        print(f"Coverage gate failed: {error}", file=sys.stderr)
        return 1

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1

    print("Coverage gate passed: every executable production module is strictly above 80%.")
    return 0

if __name__ == "__main__":
    raise SystemExit(Main())
