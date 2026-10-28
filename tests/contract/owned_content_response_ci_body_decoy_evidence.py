# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Admit one body-decoy pipeline only from original HTTP parts and persisted header truth."""

from __future__ import annotations

import sys
from pathlib import Path
from xml.etree import ElementTree

from tests.contract.owned_content_response_ci_denial_evidence import ReadJson
from tests.contract.owned_content_response_header_v2_oracle import (
    AssertContentHeaderV2,
    AssertHistoricalContentHeaderReplay,
)
from tests.contract.owned_content_response_sdk_oracle import Canonical
from tests.contract.owned_content_response_sdk_pipeline import AssertOffline

CASE_NAME = "test_InstalledFreshBodyDecoyContentHeaderPipelineRetainsFindingAndRelocatedReplay"
CASE_CLASS = "tests.functional.test_owned_content_response_sdk_pipeline"


def RequireOutcome(junit: Path, retained: Path) -> dict:
    """Require this exact pass and reconcile its original body, headers, Finding and replay.

    Args:
        junit: Original JUnit from only the required body-decoy functional identity.
        retained: Original installation/process/source/offline evidence upload root.

    Returns:
        Original checked replay result. No product, source or process is executed here.
    """

    with junit.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)

    if len(raw) > 1024 * 1024:
        raise ValueError("Single body-decoy JUnit exceeds its fixed evidence bound")

    document = ElementTree.fromstring(raw)
    suites, cases = list(document.iter("testsuite")), list(document.iter("testcase"))

    if len(suites) != 1 or any(suites[0].get(key) != expected for key, expected in (
        ("tests", "1"), ("failures", "0"), ("errors", "0"), ("skipped", "0"))) or (
        len(cases) != 1 or cases[0].get("name") != CASE_NAME or cases[0].get(
            "classname") != CASE_CLASS or any(list(document.iter(kind)) for kind in (
                "failure", "error", "skipped"))
    ):
        raise ValueError("Required body-decoy pipeline must execute once with no failures or skips")

    paths = list(retained.glob("run-*/body-decoy-positive/pipeline-result.json"))

    if len(paths) != 1:
        raise ValueError("One separately retained original body-decoy result is required")

    case = paths[0].parent
    result = ReadJson(paths[0])

    if set(result) != {"state", "expected_findings", "runtime_acceptance", "source_delivery",
        "identities"} or result["state"] != "checked-header-replay" or result[
            "runtime_acceptance"] != "passed" or result["source_delivery"] != "normal-eof" or (
                type(result["expected_findings"]) is not int or result["expected_findings"] != 1
    ):
        raise ValueError("Original body-decoy result must confirm one Finding and relocated replay")

    identities = result["identities"]

    if type(identities) is not dict or set(identities) != {"original_receipt_id",
        "analysis_reference", "assessment_reference", "finding_reference", "condition_observed"
    } or identities["condition_observed"] is not True or any(
        type(identities[key]) is not str or not identities[key] for key in (
            "original_receipt_id", "analysis_reference", "assessment_reference",
            "finding_reference")
    ):
        raise ValueError("Body text cannot suppress the actual absent-header assessment or Finding")

    plan = ReadJson(case / "pipeline-plan.json")

    if plan["selection"]["case"] != "body-decoy" or plan["selection"]["scenario"] != (
        "positive") or plan["expected_state"] != "completed" or type(
            plan["expected_findings"]) is not int or plan["expected_findings"] != 1:
        raise ValueError("Only the independently selected body-decoy positive is admitted")

    setups = list(case.glob("process-*-sdk-fresh-setup/stdout.bin"))
    inspections = sorted(case.glob("process-*-sdk-inspect/stdout.bin"))

    if len(setups) != 1 or len(inspections) != 4:
        raise ValueError("Original setup and four original state inspections are required")

    setup = ReadJson(setups[0])["summary"]
    acquired, interpreted, relocated, replayed = [ReadJson(path)["summary"][
        "original_inspection"] for path in inspections]
    analysis = ReadJson(case / "sdk-analyze-offline-consumer.json")
    guard = ReadJson(case / "sdk-analyze-offline-guard.json")
    AssertOffline(guard["guard"], historical=False)

    if analysis["exception_type"] is not None or guard["authority_scenario"] != "positive":
        raise ValueError("Body-decoy assessment requires the actual approved offline consumer")

    verified = AssertContentHeaderV2(acquired, interpreted, analysis["summary"],
        guard["guard"]["saves"], case="body-decoy", url=plan["selection"]["url"],
        receipt_id=identities["original_receipt_id"], analysis=plan["analysis_reference"],
        authority={"scope": setup["scope"], "policy": setup["policies"]["analysis"]["document"],
            "owner_reference": plan["owner_reference"], "owner_attribution": "trusted-reader"})

    if Canonical(verified) != Canonical(identities) or Canonical(interpreted) != Canonical(
        relocated) or ReadJson(case / "physical-relocation.json") != {
            "original_root_absent": True, "relocated_root_present": True}:
        raise ValueError("Original Finding identities and unchanged relocated state are required")

    replay = ReadJson(case / "sdk-replay-offline-consumer.json")
    historical = ReadJson(case / "sdk-replay-offline-guard.json")
    AssertOffline(historical["guard"], historical=True)

    if replay["exception_type"] is not None or historical["authority_scenario"] is not None:
        raise ValueError("Original historical replay must verify without a new analysis scenario")

    AssertHistoricalContentHeaderReplay(relocated, replayed, replay["summary"], verified)

    return result


def Main(arguments: list[str] | None = None) -> int:
    """Check only original body-decoy evidence paths without executing another runtime."""

    selected = sys.argv[1:] if arguments is None else arguments

    if len(selected) != 2:
        raise ValueError("Expected original body-decoy JUnit and evidence paths")

    RequireOutcome(Path(selected[0]), Path(selected[1]))
    print("Required genuine body-decoy pipeline: 1 passed, 0 skipped; absent-header Finding")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
