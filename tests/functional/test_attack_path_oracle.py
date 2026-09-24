"""Deterministic lifecycle oracle for attack-path mini."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ATTACK_PATH_MINI = Path(__file__).resolve().parents[2] / "labs" / "targets" / "attack-path-mini"
CANONICAL_PATH_ID = "path.internet-to-business-event"


def LoadJson(name: str) -> dict[str, Any]:
    """Load one attack-path mini fixture document."""

    return json.loads((ATTACK_PATH_MINI / name).read_text(encoding="utf-8"))


def IndexById(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Index one deterministic fixture collection."""

    return {item["id"]: item for item in items}


def CanonicalAssessments(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the canonical path assessment from every ordered phase."""

    assessments = []

    for phase in scenario["phases"]:
        matching = [
            assessment
            for assessment in phase["assessments"]
            if assessment["path_id"] == CANONICAL_PATH_ID
        ]

        assert len(matching) == 1, "each phase must assess the canonical path exactly once."
        assessments.append(matching[0])

    return assessments


def test_CanonicalAttackPathOracleIsExact():
    """Match exactly Internet to Portal to Identity to Billing API to Business Event."""

    scenario = LoadJson("scenario.v1.json")
    oracle = LoadJson("oracle.v1.json")
    paths = IndexById(scenario["attack_paths"])
    canonical = paths[CANONICAL_PATH_ID]

    assert oracle["canonical_path"] == {
        "path_id": CANONICAL_PATH_ID,
        "labels": ["Internet", "Portal", "Identity", "Billing API", "Business Event"],
        "node_ids": canonical["node_ids"],
        "relation_ids": canonical["relation_ids"],
    }, "canonical attack-path oracle changed unexpectedly."


def test_AttackPathLifecycleOracleIsExact():
    """Match the deterministic UNKNOWN to BLOCKED lifecycle without skipping phases."""

    scenario = LoadJson("scenario.v1.json")
    oracle = LoadJson("oracle.v1.json")
    assessments = CanonicalAssessments(scenario)
    actual = [
        {
            "phase_id": phase["id"],
            "canonical_state": assessment["state"],
            "confidence": assessment["confidence"],
        }
        for phase, assessment in zip(scenario["phases"], assessments, strict=True)
    ]

    assert actual == oracle["phase_oracle"], "attack-path phase oracle changed unexpectedly."
    assert [transition["id"] for transition in scenario["transitions"]] == oracle[
        "transition_oracle"
    ], "attack-path transition oracle changed unexpectedly."


def test_BlockedNegativePathOracleIsExact():
    """Prove the signing-key path is denied by its named effective control."""

    scenario = LoadJson("scenario.v1.json")
    oracle = LoadJson("oracle.v1.json")
    paths = IndexById(scenario["attack_paths"])
    relations = IndexById(scenario["relations"])
    controls = IndexById(scenario["controls"])
    expected = oracle["blocked_negative_path"]
    path = paths[expected["path_id"]]
    blocking_relation = relations[path["relation_ids"][-1]]

    assert path["node_ids"] == expected["node_ids"], "blocked negative path changed."
    assert blocking_relation["reachability"] is False, "negative path edge must be unreachable."
    assert blocking_relation["blocking_control_id"] in expected["blocking_control_ids"], (
        "negative path must name the exact blocking control."
    )
    assert controls[blocking_relation["blocking_control_id"]]["status"] == "effective", (
        "negative path control must be effective."
    )


def test_RemediationBreaksCanonicalPathAtDeclaredRelation():
    """Prove remediation changes the confirmed canonical path to BLOCKED."""

    scenario = LoadJson("scenario.v1.json")
    oracle = LoadJson("oracle.v1.json")
    relations = IndexById(scenario["relations"])
    phases = IndexById(scenario["phases"])
    expected = oracle["remediation_path_break"]
    relation = relations[expected["relation_id"]]
    assessments = {
        assessment["path_id"]: assessment
        for assessment in phases[expected["phase_id"]]["assessments"]
    }
    remediated = assessments[expected["path_id"]]

    assert relation["remediated_by_control_id"] == expected["control_id"], (
        "remediation must act on the declared path relation."
    )
    assert remediated["state"] == expected["resulting_state"] == "BLOCKED", (
        "remediation must leave the canonical path blocked."
    )
    assert expected["control_id"] in remediated["blocking_control_ids"], (
        "remediation assessment must attribute the path break to its control."
    )


def test_AttackPathSafetyOracleIsExact():
    """Match the non-executing synthetic safety boundary exactly."""

    scenario = LoadJson("scenario.v1.json")
    oracle = LoadJson("oracle.v1.json")
    safety = scenario["safety"]

    assert oracle["safety_oracle"] == {
        "data_only": safety["data_only"],
        "external_targets": safety["external_targets"],
        "network_actions": safety["network_actions"],
        "validation_scope": safety["authorized_validation"]["scope"],
    }, "attack-path safety oracle changed unexpectedly."
