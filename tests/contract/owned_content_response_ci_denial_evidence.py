# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Require actual policy refusal after valid capture; denial never establishes negative truth."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from xml.etree import ElementTree

from tests.contract.owned_content_response_sdk_oracle import Canonical
from tests.contract.owned_content_response_sdk_pipeline import AssertOffline

CASE_NAME = (
    "test_InstalledFreshPolicyDeniedContentHeaderPipelinePreservesAcquiredStateWithoutAssessment")
CASE_CLASS = "tests.functional.test_owned_content_response_sdk_pipeline"


def ReadJson(path: Path) -> dict:
    """Read only a bounded original CI observation without repairing or defaulting its fields."""

    with path.open("rb") as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)

    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Policy refusal observation exceeds its fixed evidence bound")

    value = json.loads(raw)

    if type(value) is not dict:
        raise ValueError("Policy refusal evidence must be an original object")

    return value


def RequireOutcome(junit: Path, retained: Path) -> dict:
    """Verify this single unassessed refusal and original no-write, policy and state observations.

    Args:
        junit: Original JUnit from only the required policy-denied functional identity.
        retained: Existing original installation/process/source/offline evidence upload root.

    Returns:
        Original checked-authority-refusal result; no scan-negative or broader acceptance claim.
    """

    with junit.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)

    if len(raw) > 1024 * 1024:
        raise ValueError("Single policy refusal JUnit exceeds its evidence bound")

    document = ElementTree.fromstring(raw)
    suites, cases = list(document.iter("testsuite")), list(document.iter("testcase"))

    if len(suites) != 1 or any(suites[0].get(key) != expected for key, expected in (
        ("tests", "1"), ("failures", "0"), ("errors", "0"), ("skipped", "0"))) or (
        len(cases) != 1 or cases[0].get("name") != CASE_NAME or cases[0].get(
            "classname") != CASE_CLASS or any(list(document.iter(kind)) for kind in (
                "failure", "error", "skipped"))
    ):
        raise ValueError("Required policy refusal must execute once with no failures or skips")

    paths = list(retained.glob("run-*/policy-denied/pipeline-result.json"))

    if len(paths) != 1:
        raise ValueError("One original policy refusal result is required")

    case = paths[0].parent
    result = ReadJson(paths[0])

    if result != {"state": "checked-authority-refusal", "expected_findings": 0,
        "runtime_acceptance": "passed", "source_delivery": "normal-eof"} or type(
            result.get("expected_findings")) is not int:
        raise ValueError("Policy denial is unassessed, never a completed clean-negative scan")

    plan = ReadJson(case / "pipeline-plan.json")
    selected = ReadJson(case / "stage-04-input.json")["selection"]
    setups = list(case.glob("process-*-sdk-fresh-setup/stdout.bin"))

    if len(setups) != 1:
        raise ValueError("Original separately granted capture setup is required")

    setup = ReadJson(setups[0])["summary"]
    policy = setup["policies"]["analysis-denied"]

    if plan["selection"]["scenario"] != "policy-denied" or plan["selection"]["case"] != (
        "missing") or selected["authority_scenario"] != "policy-denied":
        raise ValueError("Only the separately selected missing-header policy refusal is admitted")

    if selected["approve_passive_header_check"] is not True or selected["policy"] != policy[
        "path"] or policy["document"]["permissions"] != [] or setup["scope"][
            "authorization"]["state"] != "granted":
        raise ValueError("Missing PASSIVE permission after granted capture must cause this refusal")

    consumer = ReadJson(case / "sdk-analyze-offline-consumer.json")
    summary = consumer["summary"]

    if consumer["exception_type"] is not None or summary["state"] != "denied" or summary[
        "failure"] != "authorization" or any(summary[key] is not None for key in (
            "condition_observed", "assessment_reference", "finding_reference")):
        raise ValueError("An actual authorization refusal cannot create interpretation identities")

    guard = ReadJson(case / "sdk-analyze-offline-guard.json")
    AssertOffline(guard["guard"], historical=False)

    if guard["authority_scenario"] != "policy-denied" or guard["guard"]["saves"] != []:
        raise ValueError("The refused analysis must not attempt any Save")

    inspections = sorted(case.glob("process-*-sdk-inspect/stdout.bin"))

    if len(inspections) != 2:
        raise ValueError("Both original postcapture and postdenial inspections are required")

    before, after = [ReadJson(path)["summary"]["original_inspection"] for path in inspections]

    if Canonical(before) != Canonical(after) or (case / "physical-relocation.json").exists() or (
        list(case.glob("process-*-sdk-replay-offline"))
    ):
        raise ValueError("Refusal must preserve acquired state and stop before relocation/replay")

    return result


def Main(arguments: list[str] | None = None) -> int:
    """Check only original paths for this one policy-denied identity, without another runtime."""

    selected = sys.argv[1:] if arguments is None else arguments

    if len(selected) != 2:
        raise ValueError("Expected original policy-refusal JUnit and evidence paths")

    RequireOutcome(Path(selected[0]), Path(selected[1]))
    print("Required genuine policy refusal: 1 passed, 0 skipped; unassessed, zero analysis Saves")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
