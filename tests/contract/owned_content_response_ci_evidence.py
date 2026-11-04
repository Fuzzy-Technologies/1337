# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Require executed single-case CI evidence; this checker never runs the product or target."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from xml.etree import ElementTree

CASE_NAME = "test_InstalledFreshContentHeaderPipelineRetainsAcknowledgedFindingAndRelocatedReplay"
FIXED_CASE_NAME = (
    "test_InstalledFreshFixedContentHeaderPipelineRetainsNegativeAssessmentAndRelocatedReplay")
CASE_CLASS = "tests.functional.test_owned_content_response_sdk_pipeline"


def RequireOutcome(junit: Path, retained: Path, *, fixed: bool = False) -> dict:
    """Admit only this genuine pytest pass with its one separately retained runtime result.

    Args:
        junit: Original JUnit from the exact single-case pytest command.
        retained: Existing original installation/process/source/offline evidence upload root.
        fixed: Exact opt-in to the separate fixed-header case; false preserves the positive gate.

    Returns:
        Checked pipeline result; a missing, skipped, failed or ambiguous result raises.
        Original custody and state assertions remain owned by the actual functional case.
    """

    if type(fixed) is not bool:
        raise ValueError("CI outcome selection is closed to the positive and fixed identities")

    selected_name = FIXED_CASE_NAME if fixed else CASE_NAME

    with junit.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)

    if len(raw) > 1024 * 1024:
        raise ValueError("Single-case JUnit exceeds its evidence bound")

    document = ElementTree.fromstring(raw)
    suites = list(document.iter("testsuite"))
    cases = list(document.iter("testcase"))

    if len(suites) != 1 or any(suites[0].get(key) != expected for key, expected in (
        ("tests", "1"), ("failures", "0"), ("errors", "0"), ("skipped", "0"))) or (
        len(cases) != 1 or cases[0].get("name") != selected_name or
        cases[0].get("classname") != CASE_CLASS or any(
            list(document.iter(kind)) for kind in ("failure", "error", "skipped"))
    ):
        raise ValueError("Required genuine content pipeline must execute once with no skips")

    role = "fixed-positive" if fixed else "missing-positive"
    results = list(retained.glob("run-*/" + role + "/pipeline-result.json"))

    if len(results) != 1:
        raise ValueError("Exactly one original pipeline result must accompany the genuine pass")

    with results[0].open("rb") as stream:
        raw = stream.read(65537)

    if len(raw) > 65536:
        raise ValueError("Single-case pipeline result exceeds its evidence bound")

    result = json.loads(raw)

    expected_findings = 0 if fixed else 1

    if type(result) is not dict or result.get("runtime_acceptance") != "passed" or result.get(
        "state") != "checked-header-replay" or type(result.get("expected_findings")) is not int or (
        result["expected_findings"] != expected_findings or result.get(
            "source_delivery") != "normal-eof" or type(result.get("identities")) is not dict
    ):
        raise ValueError("Original result must confirm the selected relocated header replay")

    identities = result["identities"]

    if fixed:
        if set(identities) != {"original_receipt_id", "analysis_reference", "assessment_reference",
            "finding_reference", "condition_observed"}:
            raise ValueError("Fixed result identities must explicitly retain the original fields")

        if identities["finding_reference"] is not None or identities.get(
            "condition_observed") is not False or type(identities.get(
                "assessment_reference")) is not str or not identities["assessment_reference"]:
            raise ValueError("Fixed headers require an actual negative assessment and no Finding")

    elif type(identities.get("finding_reference")) is not str or not identities[
        "finding_reference"]:
        raise ValueError("Original positive result must confirm its Finding")

    return result


def Main(arguments: list[str] | None = None) -> int:
    """Check explicit CI evidence paths and only the two fixed identities, without another run."""

    selected = sys.argv[1:] if arguments is None else arguments

    if len(selected) not in (2, 3) or (len(selected) == 3 and selected[2] != "fixed"):
        raise ValueError("Expected original evidence paths and only the optional fixed identity")

    fixed = len(selected) == 3
    RequireOutcome(Path(selected[0]), Path(selected[1]), fixed=fixed)
    label = "fixed content" if fixed else "content"
    print(f"Required genuine {label} pipeline: 1 passed, 0 skipped; original result retained")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
