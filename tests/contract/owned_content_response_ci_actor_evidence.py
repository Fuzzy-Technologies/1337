# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Require revalidation of a controlled trusted actor fixture, without authentication claims."""

from __future__ import annotations

import sys
from pathlib import Path
from xml.etree import ElementTree

from tests.contract.owned_content_response_ci_denial_evidence import ReadJson
from tests.contract.owned_content_response_sdk_oracle import Canonical
from tests.contract.owned_content_response_sdk_pipeline import AssertOffline

CASE_NAME = (
    "test_InstalledFreshActorDriftContentHeaderPipelinePreservesAcquiredStateWithoutAssessment")
CASE_CLASS = "tests.functional.test_owned_content_response_sdk_pipeline"
ACTOR_HELPER = "owned_content_response_sdk_entrypoint.py"
ACTOR_HELPER_SHA256 = "9f8bd64c8cd0cc3502ff20e5650eb1687bfa2b3296075bb7dee03a3a81076452"
PERMISSION = {"capability_id": "http.owned-response-header-check",
    "adapter_id": "native.response-passive", "maximum_impact": "PASSIVE", "granted_privileges": []}


def RequireOutcome(junit: Path, retained: Path) -> dict:
    """Verify one controlled actor mismatch with otherwise granted authority and original no-writes.

    Args:
        junit: Original JUnit from only the required actor-drift functional identity.
        retained: Existing original installation/process/source/offline evidence upload root.

    Returns:
        Original unassessed refusal. The fixture reader proves product revalidation only.
    """

    with junit.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)

    if len(raw) > 1024 * 1024:
        raise ValueError("Single actor refusal JUnit exceeds its fixed evidence bound")

    document = ElementTree.fromstring(raw)
    suites, cases = list(document.iter("testsuite")), list(document.iter("testcase"))

    if len(suites) != 1 or any(suites[0].get(key) != expected for key, expected in (
        ("tests", "1"), ("failures", "0"), ("errors", "0"), ("skipped", "0"))) or (
        len(cases) != 1 or cases[0].get("name") != CASE_NAME or cases[0].get(
            "classname") != CASE_CLASS or any(list(document.iter(kind)) for kind in (
                "failure", "error", "skipped"))
    ):
        raise ValueError("Required actor refusal must execute once with no failures or skips")

    paths = list(retained.glob("run-*/actor-denied/pipeline-result.json"))

    if len(paths) != 1:
        raise ValueError("One original controlled actor-refusal result is required")

    case = paths[0].parent
    result = ReadJson(paths[0])

    if result != {"state": "checked-authority-refusal", "expected_findings": 0,
        "runtime_acceptance": "passed", "source_delivery": "normal-eof"} or type(
            result.get("expected_findings")) is not int:
        raise ValueError("Actor refusal is unassessed, never a completed clean-negative scan")

    plan = ReadJson(case / "pipeline-plan.json")
    selected = ReadJson(case / "stage-04-input.json")["selection"]
    setups = list(case.glob("process-*-sdk-fresh-setup/stdout.bin"))
    children = list(case.glob("process-*-sdk-analyze-offline/stdout.bin"))

    if len(setups) != 1 or len(children) != 1:
        raise ValueError("Original granted setup and actual offline child are required")

    setup = ReadJson(setups[0])["summary"]
    policy = setup["policies"]["analysis"]
    child = ReadJson(children[0])
    helpers = ReadJson(case / "pipeline-helper-sources.json")

    if helpers[ACTOR_HELPER]["sha256"] != ACTOR_HELPER_SHA256 or child["consumer_sources"][
        ACTOR_HELPER] != helpers[ACTOR_HELPER]:
        raise ValueError("The exact reviewed actor fixture helper must own the actual child")

    if plan["selection"]["scenario"] != "owner-drift" or plan["selection"]["case"] != (
        "missing") or selected["authority_scenario"] != "owner-drift" or selected[
            "owner_reference"] != plan["owner_reference"]:
        raise ValueError("The original selected actor and owner-drift scenario must remain exact")

    if selected["approve_passive_header_check"] is not True or selected["policy"] != policy[
        "path"] or policy["document"]["maximum_impact"] != "PASSIVE" or policy["document"][
            "permissions"] != [PERMISSION] or setup["scope"]["authorization"]["state"] != "granted":
        raise ValueError("Actor mismatch requires otherwise valid permission, scope and approval")

    consumer = ReadJson(case / "sdk-analyze-offline-consumer.json")
    summary = consumer["summary"]

    if consumer["exception_type"] is not None or Canonical(child["summary"]) != Canonical(
        summary) or summary["state"] != "denied" or summary["failure"] != "authorization" or any(
            summary[key] is not None for key in (
                "condition_observed", "assessment_reference", "finding_reference")):
        raise ValueError("Actual actor refusal cannot create interpretation identities")

    guard = ReadJson(case / "sdk-analyze-offline-guard.json")
    AssertOffline(guard["guard"], historical=False)

    if guard["authority_scenario"] != child["authority_scenario"] or guard[
        "authority_scenario"] != "owner-drift" or type(guard["owner_reads"]) is not int or guard[
            "owner_reads"] != 2 or child["owner_reads"] != 2 or Canonical(child["guard"]) != (
                Canonical(guard["guard"])) or guard["guard"]["saves"] != []:
        raise ValueError("Two observed controlled actor reads must refuse without analysis Saves")

    inspections = sorted(case.glob("process-*-sdk-inspect/stdout.bin"))

    if len(inspections) != 2:
        raise ValueError("Original postcapture and post-actor-refusal inspections are required")

    before, after = [ReadJson(path)["summary"]["original_inspection"] for path in inspections]

    if Canonical(before) != Canonical(after) or (case / "physical-relocation.json").exists() or (
        list(case.glob("process-*-sdk-replay-offline"))
    ):
        raise ValueError("Actor refusal must preserve owner state and stop before later stages")

    return result


def Main(arguments: list[str] | None = None) -> int:
    """Check original paths for this exact controlled actor fixture, without another runtime."""

    selected = sys.argv[1:] if arguments is None else arguments

    if len(selected) != 2:
        raise ValueError("Expected original controlled-actor JUnit and evidence paths")

    RequireOutcome(Path(selected[0]), Path(selected[1]))
    print("Required genuine actor refusal: 1 passed, 0 skipped; two reads, zero analysis Saves")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
