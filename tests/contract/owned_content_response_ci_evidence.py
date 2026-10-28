# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Require executed single-case CI evidence; this checker never runs the product or target."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from xml.etree import ElementTree

CASE_NAME = "test_InstalledFreshContentHeaderPipelineRetainsAcknowledgedFindingAndRelocatedReplay"
CASE_CLASS = "tests.functional.test_owned_content_response_sdk_pipeline"


def RequireOutcome(junit: Path, retained: Path) -> dict:
    """Admit only this genuine pytest pass with its one separately retained runtime result.

    Args:
        junit: Original JUnit from the exact single-case pytest command.
        retained: Existing original installation/process/source/offline evidence upload root.

    Returns:
        Checked pipeline result; a missing, skipped, failed or ambiguous result raises.
        Original custody and state assertions remain owned by the actual functional case.
    """

    with junit.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)

    if len(raw) > 1024 * 1024:
        raise ValueError("Single-case JUnit exceeds its evidence bound")

    document = ElementTree.fromstring(raw)
    suites = list(document.iter("testsuite"))
    cases = list(document.iter("testcase"))

    if len(suites) != 1 or any(suites[0].get(key) != expected for key, expected in (
        ("tests", "1"), ("failures", "0"), ("errors", "0"), ("skipped", "0"))) or (
        len(cases) != 1 or cases[0].get("name") != CASE_NAME or
        cases[0].get("classname") != CASE_CLASS or any(
            list(document.iter(kind)) for kind in ("failure", "error", "skipped"))
    ):
        raise ValueError("Required genuine content pipeline must execute once with no skips")

    results = list(retained.glob("run-*/missing-positive/pipeline-result.json"))

    if len(results) != 1:
        raise ValueError("Exactly one original pipeline result must accompany the genuine pass")

    with results[0].open("rb") as stream:
        raw = stream.read(65537)

    if len(raw) > 65536:
        raise ValueError("Single-case pipeline result exceeds its evidence bound")

    result = json.loads(raw)

    if type(result) is not dict or result.get("runtime_acceptance") != "passed" or result.get(
        "state") != "checked-header-replay" or type(result.get("expected_findings")) is not int or (
        result["expected_findings"] != 1 or result.get("source_delivery") != "normal-eof" or
        type(result.get("identities")) is not dict or type(result["identities"].get(
            "finding_reference")) is not str or not result["identities"]["finding_reference"]
    ):
        raise ValueError("Original result must confirm Finding and relocated header replay")

    return result


def Main(arguments: list[str] | None = None) -> int:
    """Check only two explicit CI-owned evidence paths, without inference or another test run."""

    selected = sys.argv[1:] if arguments is None else arguments

    if len(selected) != 2:
        raise ValueError("Expected original JUnit and retained content evidence paths")

    RequireOutcome(Path(selected[0]), Path(selected[1]))
    print("Required genuine content pipeline: 1 passed, 0 skipped; original result retained")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
