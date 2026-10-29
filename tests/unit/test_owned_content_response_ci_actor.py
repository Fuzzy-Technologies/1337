# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Controlled actor-refusal CI tampering checks; no product, target or runtime is executed."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
import yaml

from tests.contract import owned_content_response_ci_actor_evidence as evidence
from tests.contract.owned_content_response_ci_denial_evidence import CASE_NAME as POLICY_CASE_NAME
from tests.unit.test_owned_content_response_ci_denial import Fixture as PolicyFixture


def Fixture(tmp_path):
    """Select only the synthetic actor identity with valid authority and a pinned fixture helper."""

    junit, retained, _policy_case, documents = PolicyFixture(tmp_path)
    junit.write_text(junit.read_text().replace(POLICY_CASE_NAME, evidence.CASE_NAME))
    case = retained / "run-mock-only/actor-denied"
    plan = documents["pipeline-plan.json"]
    plan["selection"]["scenario"] = "owner-drift"
    plan["owner_reference"] = "actor:mock-selected-original"
    selected = documents["stage-04-input.json"]["selection"]
    selected.update(authority_scenario="owner-drift", policy="/mock-only/passive-policy.json",
        owner_reference=plan["owner_reference"])
    setup = documents["process-003-sdk-fresh-setup/stdout.bin"]["summary"]
    setup["policies"] = {"analysis": {"path": selected["policy"], "document": {
        "maximum_impact": "PASSIVE", "permissions": [copy.deepcopy(evidence.PERMISSION)]}}}
    guard = documents["sdk-analyze-offline-guard.json"]
    guard.update(authority_scenario="owner-drift", owner_reads=2)
    helpers = {evidence.ACTOR_HELPER: {"path": "/mock-only/" + evidence.ACTOR_HELPER,
        "sha256": evidence.ACTOR_HELPER_SHA256}}
    documents["pipeline-helper-sources.json"] = helpers
    documents["process-006-sdk-analyze-offline/stdout.bin"] = {
        "summary": copy.deepcopy(documents["sdk-analyze-offline-consumer.json"]["summary"]),
        "consumer_sources": copy.deepcopy(helpers), **copy.deepcopy(guard)}

    return junit, retained, case, documents


@pytest.mark.parametrize("mutation", [None, "wrong-case", "one-read", "bool-read", "helper-hash",
    "scenario", "missing-permission", "approval-denied", "owner-basis", "clean-negative",
    "assessment", "save", "changed-state", "guard-call", "late-stage"])
def test_ActorRefusalRequiresRevalidationWithOtherwiseGrantedAuthority(tmp_path, mutation):
    """Self-consistent records cannot replace two actual reads of the exact controlled fixture."""

    junit, retained, case, documents = Fixture(tmp_path)
    guard = documents["sdk-analyze-offline-guard.json"]
    child = documents["process-006-sdk-analyze-offline/stdout.bin"]
    selected = documents["stage-04-input.json"]["selection"]
    consumer = documents["sdk-analyze-offline-consumer.json"]["summary"]

    if mutation == "wrong-case":
        junit.write_text(junit.read_text().replace(evidence.CASE_NAME, POLICY_CASE_NAME))

    elif mutation in ("one-read", "bool-read"):
        guard["owner_reads"] = child["owner_reads"] = 1 if mutation == "one-read" else True

    elif mutation == "helper-hash":
        documents["pipeline-helper-sources.json"][evidence.ACTOR_HELPER]["sha256"] = "0" * 64
        child["consumer_sources"][evidence.ACTOR_HELPER]["sha256"] = "0" * 64

    elif mutation == "scenario":
        documents["pipeline-plan.json"]["selection"]["scenario"] = "positive"

        for record in (selected, guard, child):
            record["authority_scenario"] = "positive"

    elif mutation == "missing-permission":
        documents["process-003-sdk-fresh-setup/stdout.bin"]["summary"]["policies"][
            "analysis"]["document"]["permissions"] = []

    elif mutation == "approval-denied":
        selected["approve_passive_header_check"] = False

    elif mutation == "owner-basis":
        selected["owner_reference"] = "actor:foreign-selection"

    elif mutation == "clean-negative":
        consumer.update(state="completed", failure=None, condition_observed=False)
        child["summary"] = copy.deepcopy(consumer)

    elif mutation == "assessment":
        consumer["assessment_reference"] = "assessment:unexpected"
        child["summary"] = copy.deepcopy(consumer)

    elif mutation == "save":
        guard["guard"]["saves"] = child["guard"]["saves"] = [{"owner": "model"}]

    elif mutation == "changed-state":
        documents["process-007-sdk-inspect/stdout.bin"]["summary"]["original_inspection"][
            "model"]["revision"] = 4

    elif mutation == "guard-call":
        guard["guard"]["calls"]["LocalEvidenceStore.Put"] = 1
        child["guard"] = copy.deepcopy(guard["guard"])

    elif mutation == "late-stage":
        documents["physical-relocation.json"] = {"original_root_absent": True}

    for name, value in documents.items():
        path = case / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    if mutation is None:
        assert evidence.RequireOutcome(junit, retained) == documents["pipeline-result.json"], (
            "The exact synthetic controlled actor refusal must remain admissible")
        assert evidence.Main([str(junit), str(retained)]) == 0, (
            "The dedicated actor entrypoint must enforce this same original-evidence gate")

    else:
        with pytest.raises((AssertionError, ValueError)):
            evidence.RequireOutcome(junit, retained)


def test_ActorCheckpointPreservesEarlierJobsAndPinsTheReviewedFixtureHelper():
    """Only the new marker may activate the actor case, whose fixed callback bytes stay pinned."""

    root = Path(__file__).resolve().parents[2]
    workflow = root / ".github/workflows/owned-content-header-acceptance.yml"
    jobs = yaml.safe_load(workflow.read_text())["jobs"]
    actor = jobs["actor-denied-content-header"]
    marker = "[owned-content-header-actor-denied-checkpoint]"
    assert marker in actor["if"] and all(marker not in jobs[name]["if"] for name in (
        "installed-content-header", "fixed-content-header", "policy-denied-content-header")), (
            "The actor checkpoint must not repeat any accepted runtime cohort")
    raw = (root / "tests/contract" / evidence.ACTOR_HELPER).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == evidence.ACTOR_HELPER_SHA256, (
        "A changed actor callback needs a separate reviewed contract")
    executions = [step for step in actor["steps"] if "pytest" in step.get("run", "")]
    assert len(executions) == 1 and "::" + evidence.CASE_NAME in executions[0]["run"] and all(
        option in executions[0]["run"] for option in ("-n0", "--no-cov", "--timeout=150")), (
            "Only one bounded serial controlled actor case may run")
    upload = actor["steps"][-1]
    assert upload["if"] == "always()" and upload["with"]["if-no-files-found"] == "error", (
        "Original controlled refusal evidence must survive unsuccessful acceptance")
