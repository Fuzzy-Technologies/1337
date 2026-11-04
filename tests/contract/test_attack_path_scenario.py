# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Contract tests for the versioned attack-path mini lifecycle fixture."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError

ATTACK_PATH_MINI = Path(__file__).resolve().parents[2] / "labs" / "targets" / "attack-path-mini"
ENTITY_COLLECTIONS = (
    "zones",
    "assets",
    "services",
    "endpoints",
    "identities",
    "controls",
    "business_impacts",
    "findings",
    "evidence",
    "relations",
    "attack_paths",
    "phases",
    "transitions",
)
PATH_STATES = {"CONFIRMED", "LIKELY", "POTENTIAL", "BLOCKED", "UNKNOWN"}
PROVENANCE_KINDS = {"seeded", "discovered", "inferred"}
LEXICALLY_ORDERED_COLLECTIONS = set(ENTITY_COLLECTIONS) - {"phases", "transitions"}


def LoadJson(name: str) -> dict[str, Any]:
    """Load one attack-path mini contract document."""

    return json.loads((ATTACK_PATH_MINI / name).read_text(encoding="utf-8"))


def IndexById(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Index one entity collection after checking stable identifier uniqueness."""

    indexed = {item["id"]: item for item in items}

    assert len(indexed) == len(items), "attack-path entity identifiers must be unique."

    return indexed


def test_AttackPathDocumentsMatchPublishedSchemas():
    """Validate the scenario and oracle against their versioned schemas."""

    for documentName in ("scenario", "oracle"):
        schema = LoadJson(f"{documentName}.schema.json")
        document = LoadJson(f"{documentName}.v1.json")
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)


def test_AttackPathSchemasRejectUnknownVersionsAndFields():
    """Reject unsupported versions and undeclared root fields instead of guessing."""

    for documentName in ("scenario", "oracle"):
        schema = LoadJson(f"{documentName}.schema.json")
        document = LoadJson(f"{documentName}.v1.json")
        validator = Draft202012Validator(schema)

        invalidVersion = copy.deepcopy(document)
        invalidVersion["schema_version"] = 2
        with pytest.raises(ValidationError):
            validator.validate(invalidVersion)

        unexpectedField = copy.deepcopy(document)
        unexpectedField["unexpected"] = True
        with pytest.raises(ValidationError):
            validator.validate(unexpectedField)

        if documentName == "scenario":
            unexpectedNestedField = copy.deepcopy(document)
            unexpectedNestedField["zones"][0]["unexpected"] = True
            with pytest.raises(ValidationError):
                validator.validate(unexpectedNestedField)


def test_AttackPathInventoryHasStableTypedIdentifiers():
    """Require every contract object to expose a unique stable identifier and type."""

    scenario = LoadJson("scenario.v1.json")
    allIds: list[str] = []

    for collectionName in ENTITY_COLLECTIONS:
        collection = scenario[collectionName]
        identifiers = [item["id"] for item in collection]

        if collectionName in LEXICALLY_ORDERED_COLLECTIONS:
            assert identifiers == sorted(identifiers), (
                f"{collectionName} must use deterministic identifier ordering."
            )
        assert all(item.get("type") for item in collection), (
            f"{collectionName} must expose stable object types."
        )
        allIds.extend(identifiers)

    assert len(allIds) == len(set(allIds)), "stable identifiers must be globally unique."


def test_AttackPathNodesAndEdgesDeclareProvenance():
    """Distinguish seeded, discovered, and inferred graph facts explicitly."""

    scenario = LoadJson("scenario.v1.json")
    graphCollections = (
        "zones",
        "assets",
        "services",
        "endpoints",
        "identities",
        "relations",
        "attack_paths",
    )
    observed = set()

    for collectionName in graphCollections:
        for item in scenario[collectionName]:
            provenance = item.get("provenance")

            assert provenance in PROVENANCE_KINDS, (
                f"{collectionName} object must declare canonical provenance."
            )
            observed.add(provenance)

    assert observed == PROVENANCE_KINDS, (
        "graph facts must exercise seeded, discovered, and inferred provenance."
    )


def test_AttackPathReferencesAreClosedAndPathsAreContinuous():
    """Resolve every reference and require relation-continuous attack paths."""

    scenario = LoadJson("scenario.v1.json")
    indexes = {name: IndexById(scenario[name]) for name in ENTITY_COLLECTIONS}
    nodeIds = set().union(
        indexes["zones"],
        indexes["assets"],
        indexes["services"],
        indexes["identities"],
    )
    evidenceIds = set(indexes["evidence"])
    controlIds = set(indexes["controls"])

    for asset in scenario["assets"]:
        assert asset["zone_id"] in indexes["zones"], "asset zone must resolve."

    for service in scenario["services"]:
        assert service["zone_id"] in indexes["zones"], "service zone must resolve."

    for endpoint in scenario["endpoints"]:
        assert endpoint["service_id"] in indexes["services"], "endpoint service must resolve."

    for identity in scenario["identities"]:
        assert identity["service_id"] in indexes["services"], "identity service must resolve."

    for evidence in scenario["evidence"]:
        assert evidence["phase_id"] in indexes["phases"], "evidence phase must resolve."
        assert evidence["provenance"] in PROVENANCE_KINDS, "evidence provenance must be allowed."

    for relation in scenario["relations"]:
        assert relation["source_id"] in nodeIds, "relation source must resolve."
        assert relation["target_id"] in nodeIds, "relation target must resolve."
        assert set(relation["evidence_ids"]) <= evidenceIds, "relation evidence must resolve."
        assert relation["provenance"] in PROVENANCE_KINDS, "relation provenance must be allowed."

        if relation["provenance"] == "inferred":
            assert relation.get("inference_rule"), "inferred relation must name its rule."

        for field in ("blocking_control_id", "remediated_by_control_id"):
            if field in relation:
                assert relation[field] in controlIds, "relation control must resolve."

    for path in scenario["attack_paths"]:
        assert path["source_id"] == path["node_ids"][0], "path source must be its first node."
        assert path["target_id"] == path["node_ids"][-1], "path target must be its final node."
        assert len(path["node_ids"]) == len(path["relation_ids"]) + 1, (
            "path node and relation counts must describe one continuous route."
        )

        for index, relationId in enumerate(path["relation_ids"]):
            relation = indexes["relations"][relationId]

            assert relation["source_id"] == path["node_ids"][index], (
                "path relation source must match the preceding node."
            )
            assert relation["target_id"] == path["node_ids"][index + 1], (
                "path relation target must match the following node."
            )

        assert set(path["finding_ids"]) <= set(indexes["findings"]), (
            "path finding references must resolve."
        )
        assert set(path["business_impact_ids"]) <= set(indexes["business_impacts"]), (
            "path business-impact references must resolve."
        )


def test_AttackPathMetadataIsAttributableAndBusinessRelevant():
    """Require attributable MITRE metadata and explicit business impact."""

    scenario = LoadJson("scenario.v1.json")
    endpointIds = set(IndexById(scenario["endpoints"]))
    evidenceIds = set(IndexById(scenario["evidence"]))
    impactIds = set(IndexById(scenario["business_impacts"]))
    assetIds = set(IndexById(scenario["assets"]))

    for finding in scenario["findings"]:
        mitre = finding["mitre"]

        assert finding["endpoint_id"] in endpointIds, "finding endpoint must resolve."
        assert set(finding["evidence_ids"]) <= evidenceIds, "finding evidence must resolve."
        assert set(finding["business_impact_ids"]) <= impactIds, (
            "finding business impact must resolve."
        )
        assert mitre["framework"] == "MITRE ATT&CK Enterprise", (
            "finding must identify the MITRE framework."
        )
        assert mitre["technique_id"].startswith("T"), "MITRE technique identifier is required."
        assert mitre["source_url"].startswith("https://attack.mitre.org/"), (
            "MITRE technique attribution URL is required."
        )

    for impact in scenario["business_impacts"]:
        assert impact["asset_id"] in assetIds, "business-impact asset must resolve."
        assert impact["business_process"], "business process must be explicit."
        assert impact["consequence"], "business consequence must be explicit."


def test_AttackPathStatesMeetConfidenceEvidenceAndInferenceRules():
    """Apply the declared state contract to every phase assessment."""

    scenario = LoadJson("scenario.v1.json")
    requirements = scenario["state_requirements"]
    evidenceIds = set(IndexById(scenario["evidence"]))
    controlIds = set(IndexById(scenario["controls"]))
    pathIds = set(IndexById(scenario["attack_paths"]))
    observedStates = {
        assessment["state"]
        for phase in scenario["phases"]
        for assessment in phase["assessments"]
    }
    observedProvenance = {
        assessment["provenance"]
        for phase in scenario["phases"]
        for assessment in phase["assessments"]
    }

    assert set(requirements) == PATH_STATES, "state requirements must cover the canonical set."
    assert observedStates == PATH_STATES, "fixture lifecycle must exercise every path state."
    assert observedProvenance == PROVENANCE_KINDS, (
        "fixture lifecycle must exercise seeded, discovered, and inferred provenance."
    )

    for phase in scenario["phases"]:
        for assessment in phase["assessments"]:
            state = assessment["state"]
            requirement = requirements[state]

            assert assessment["path_id"] in pathIds, "assessment path must resolve."
            assert assessment["provenance"] in PROVENANCE_KINDS, (
                "assessment provenance must be allowed."
            )
            assert requirement["minimum_confidence"] <= assessment["confidence"], (
                "assessment confidence is below its state minimum."
            )
            assert assessment["confidence"] <= requirement["maximum_confidence"], (
                "assessment confidence exceeds its state maximum."
            )
            assert len(assessment["evidence_ids"]) >= requirement["minimum_evidence"], (
                "assessment does not meet its evidence requirement."
            )
            assert set(assessment["evidence_ids"]) <= evidenceIds, (
                "assessment evidence must resolve."
            )

            if requirement["inference_required"]:
                assert assessment.get("inference_rule"), "state requires an inference rule."

            if assessment["provenance"] == "inferred":
                assert assessment.get("inference_rule"), (
                    "inferred assessment must name its inference rule."
                )

            if requirement["blocking_control_required"]:
                blockingControls = set(assessment.get("blocking_control_ids", []))

                assert blockingControls, "blocked assessment must name a control."
                assert blockingControls <= controlIds, "blocking controls must resolve."


def test_AttackPathTransitionsAreContiguousEvidenceBackedAndAuthorized():
    """Validate every lifecycle transition, evidence rule, and authorization boundary."""

    scenario = LoadJson("scenario.v1.json")
    phases = scenario["phases"]
    phaseIds = [phase["id"] for phase in phases]
    evidence = IndexById(scenario["evidence"])
    transitions = scenario["transitions"]

    assert [phase["sequence"] for phase in phases] == list(range(5)), (
        "phase sequence must be contiguous."
    )

    for index, transition in enumerate(transitions):
        assert transition["from_phase_id"] == phaseIds[index], (
            "transition source must match lifecycle order."
        )
        assert transition["to_phase_id"] == phaseIds[index + 1], (
            "transition target must match lifecycle order."
        )
        assert transition["evidence_ids"], "transition must be evidence-backed."
        assert set(transition["evidence_ids"]) <= set(evidence), (
            "transition evidence must resolve."
        )

        targetEvidence = {
            evidenceId
            for evidenceId in transition["evidence_ids"]
            if evidence[evidenceId]["phase_id"] == transition["to_phase_id"]
        }
        assert targetEvidence, "transition must add evidence attributable to its target phase."

        if transition["to_phase_id"] == "phase.finding-confirmation":
            assert transition.get("inference_rule"), (
                "finding confirmation transition must name its inference rule."
            )

        if transition["requires_authorization"]:
            authorizationId = transition.get("authorization_evidence_id")

            assert authorizationId in transition["evidence_ids"], (
                "authorized transition must include its authorization evidence."
            )
            assert evidence[authorizationId]["type"] == "authorization-record", (
                "authorized transition must reference an authorization record."
            )


def test_AttackPathSafetyContractFailsClosed():
    """Keep the fixture data-only, network-free, and synthetically authorized."""

    safety = LoadJson("scenario.v1.json")["safety"]

    assert safety == {
        "data_only": True,
        "external_targets": False,
        "network_actions": False,
        "impact": "passive",
        "authorized_validation": {
            "required": True,
            "scope": "synthetic-fixture-only",
        },
    }, "attack-path mini safety boundary changed unexpectedly."
