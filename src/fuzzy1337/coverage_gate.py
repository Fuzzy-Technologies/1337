# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Enforce the production per-module combined branch/statement coverage contract."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def ValidateReport(report: dict[str, Any], source: Path) -> list[str]:
    """Return failures; missing modules and invalid counts cannot pass the gate.

    Reads the source inventory without importing modules. Missing coverage fails; empty
    nonexecutable modules are accepted.

    Args:
        report: coverage.py JSON with branch coverage and unexcluded per-file counts
        source: Production module directory to require in the report.

    Returns:
        Diagnostics for missing modules or combined coverage at or below 80%.

    Raises:
        ValueError: Metadata, source inventory or per-file counts are invalid.
    """

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
        # coverage.py keeps the platform separator in relative filenames.
        report_key = next(
            (key for key in (name, str(path), name.replace("/", "\\")) if key in files),
            None,
        )
        if report_key is None:
            failures.append(f"{name}: missing coverage")
            continue

        entry = files[report_key]
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

        covered_lines, statements, covered_branches, branches, excluded = (
            int(summary[key]) for key in keys
        )
        if covered_lines > statements or covered_branches > branches or excluded:
            raise ValueError(f"{name}: inconsistent counts or undocumented exclusions")

        covered = covered_lines + covered_branches
        total = statements + branches
        if total and covered * 5 <= total * 4:
            failures.append(
                f"{name}: {covered}/{total} = {100 * covered / total:.2f}% (must be >80%)"
            )

    return failures


def Main(argv: Sequence[str] | None = None) -> int:
    """Validate a fresh coverage JSON report against the on-disk source inventory.

    Reads the JSON report and writes diagnostics. Malformed inputs cannot produce PASS.

    Args:
        argv: Coverage-report and source paths, or None for process arguments.

    Returns:
        Zero when all modules pass, otherwise one for gate failure.

    Raises:
        SystemExit: Argument parsing rejects input or handles help.
    """

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
