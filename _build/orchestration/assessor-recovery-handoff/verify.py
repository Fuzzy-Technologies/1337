# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify frozen synthetic assessor cases without repository or service access."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

JsonObject = dict[str, Any]


def LoadModule(path: Path, name: str) -> ModuleType:
    """Import one explicitly selected standalone assessor source file.

    Args:
        path: Frozen Python source file.
        name: Distinct module identity for current and historical code.

    Returns:
        Imported assessor module.

    Raises:
        RuntimeError: Python cannot construct a source loader.
    """

    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError("Cannot load the selected assessor")

    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)

    return module


def CheckCase(module: ModuleType, case: JsonObject, now: datetime) -> JsonObject:
    """Check one fixed input and its independent expected outcomes.

    Args:
        module: Current frozen assessor.
        case: Synthetic controller, tasks, explicit roster and expectations.
        now: Fixed injected assessment time.

    Returns:
        Named successful outcome and observed assessment.

    Raises:
        AssertionError: An observed result differs from an expected result.
    """

    observed = module.Assess(case["controller"], case["tasks"], now, case.get("owners"))
    codes = sorted(item["code"] for item in observed["findings"])
    assert codes == sorted(case["codes"]), (case["name"], codes, case["codes"])

    for field in ("assessment", "owner_coverage_checked"):
        if field in case:
            assert observed[field] == case[field], (case["name"], field)

    if "coverage" in case:
        assert observed["owner_coverage_checked"] == case["coverage"], case["name"]

    if "reason" in case:
        assert observed["findings"][0]["reason"] == case["reason"], case["name"]

    if "finding_owner" in case:
        assert case["finding_owner"] in [
            item.get("owner") for item in observed["findings"]
        ], case["name"]

    if "recommendation_contains" in case:
        assert case["recommendation_contains"] in str(observed["tasks"]), case["name"]

    if "child_state" in case:
        children = [item for item in observed["tasks"] if ":" in item["task"]]
        assert children[0]["state"] == case["child_state"], case["name"]

    if "excluded_historical_owner" in case:
        assert case["excluded_historical_owner"] not in observed[
            "covered_active_owners"
        ], case["name"]

    return {"name": case["name"], "assessment": observed["assessment"], "codes": codes}


def Verify(assessor: Path, baseline: Path, fixture: Path) -> JsonObject:
    """Check the frozen source identities, 29 cases and the historical counterexample.

    Args:
        assessor: Current standalone source.
        baseline: Historical source used only for the omission counterexample.
        fixture: Synthetic fixed JSON inputs and expected outcomes.

    Returns:
        Source-bound verification result containing no operational checkpoint data.

    Raises:
        AssertionError: Source hashes or case outcomes differ from the frozen fixture.
    """

    data = json.loads(fixture.read_text(encoding="utf-8"))
    current_hash = hashlib.sha256(assessor.read_bytes()).hexdigest()
    old_hash = hashlib.sha256(baseline.read_bytes()).hexdigest()
    assert current_hash == data["current_source_sha256"], "Current source hash mismatch"
    assert old_hash == data["baseline_source_sha256"], "Baseline source hash mismatch"

    current = LoadModule(assessor, "frozen_current_assessor")
    historical = LoadModule(baseline, "frozen_historical_assessor")
    now = current.ParseTime(data["now"])
    results = [CheckCase(current, case, now) for case in data["cases"]]
    assert len(results) == 29, "The complete frozen fixture must contain 29 cases"

    counterexample = next(
        case for case in data["cases"] if case["name"] == data["baseline_counterexample"]
    )
    old_result = historical.Assess(
        counterexample["controller"], counterexample["tasks"], now,
        counterexample["owners"],
    )
    assert old_result["findings"] == [], "Historical omission no longer reproduced"
    assert old_result["assessment"] == "active_or_handoff", "Unexpected old assessment"
    fixed = next(item for item in results if item["name"] == counterexample["name"])
    assert fixed["assessment"] == "attention", "Omitted owner must require reconciliation"
    assert fixed["codes"] == ["registered_active_owner_not_in_roster"]

    return {
        "passed": len(results), "current_source_sha256": current_hash,
        "baseline_source_sha256": old_hash,
        "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
        "python": sys.version.split()[0], "injected_now": data["now"],
        "verified_at": datetime.now(timezone.utc).isoformat(), "cases": results,
        "historical_counterexample": {
            "old_assessment": old_result["assessment"], "old_findings": [],
            "new_assessment": fixed["assessment"], "new_codes": fixed["codes"],
        },
    }


def Main() -> int:
    """Run the standalone finite fixture and optionally save its result.

    Returns:
        Zero after all frozen checks pass; failed assertions abort with nonzero status.
    """

    directory = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assessor", type=Path, default=directory / "assess.py")
    parser.add_argument("--baseline", type=Path, default=directory / "baseline_assess.py")
    parser.add_argument("--cases", type=Path, default=directory / "cases.json")
    parser.add_argument("--result", type=Path)
    arguments = parser.parse_args()
    result = Verify(arguments.assessor, arguments.baseline, arguments.cases)
    if arguments.result is not None:
        arguments.result.write_text(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print(json.dumps(result, ensure_ascii=False, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
