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

    for document_name in ("scenario", "oracle"):
        schema = LoadJson(f"{document_name}.schema.json")
        document = LoadJson(f"{document_name}.v1.json")
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)


def test_AttackPathSchemasRejectUnknownVersionsAndFields():
    """Reject unsupported versions and undeclared root fields instead of guessing."""

    for document_name in ("scenario", "oracle"):
        schema = LoadJson(f"{document_name}.schema.json")
        document = LoadJson(f"{document_name}.v1.json")
        validator = Draft202012Validator(schema)

        invalid_version = copy.deepcopy(document)
        invalid_version["schema_version"] = 2
        with pytest.raises(ValidationError):
            validator.validate(invalid_version)

        unexpected_field = copy.deepcopy(document)
        unexpected_field["unexpected"] = True
        with pytest.raises(ValidationError):
            validator.validate(unexpected_field)

        if document_name == "scenario":
            unexpected_nested_field = copy.deepcopy(document)
            unexpected_nested_field["zones"][0]["unexpected"] = True
            with pytest.raises(ValidationError):
                validator.validate(unexpected_nested_field)


def test_AttackPathInventoryHasStableTypedIdentifiers():
    """Require every contract object to expose a unique stable identifier and type."""

    scenario = LoadJson("scenario.v1.json")
    all_ids: list[str] = []

    for collection_name in ENTITY_COLLECTIONS:
        collection = scenario[collection_name]
        identifiers = [item["id"] for item in collection]

        if collection_name in LEXICALLY_ORDERED_COLLECTIONS:
            assert identifiers == sorted(identifiers), (
                f"{collection_name} must use deterministic identifier ordering."
            )
        assert all(item.get("type") for item in collection), (
            f"{collection_name} must expose stable object types."
        )
        all_ids.extend(identifiers)

    assert len(all_ids) == len(set(all_ids)), "stable identifiers must be globally unique."


def test_AttackPathNodesAndEdgesDeclareProvenance():
    """Distinguish seeded, discovered, and inferred graph facts explicitly."""

    scenario = LoadJson("scenario.v1.json")
    graph_collections = (
        "zones",
        "assets",
        "services",
        "endpoints",
        "identities",
        "relations",
        "attack_paths",
    )
    observed = set()

    for collection_name in graph_collections:
        for item in scenario[collection_name]:
            provenance = item.get("provenance")

            assert provenance in PROVENANCE_KINDS, (
                f"{collection_name} object must declare canonical provenance."
            )
            observed.add(provenance)

    assert observed == PROVENANCE_KINDS, (
        "graph facts must exercise seeded, discovered, and inferred provenance."
    )


def test_AttackPathReferencesAreClosedAndPathsAreContinuous():
    """Resolve every reference and require relation-continuous attack paths."""

    scenario = LoadJson("scenario.v1.json")
    indexes = {name: IndexById(scenario[name]) for name in ENTITY_COLLECTIONS}
    node_ids = set().union(
        indexes["zones"],
        indexes["assets"],
        indexes["services"],
        indexes["identities"],
    )
    evidence_ids = set(indexes["evidence"])
    control_ids = set(indexes["controls"])

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
        assert relation["source_id"] in node_ids, "relation source must resolve."
        assert relation["target_id"] in node_ids, "relation target must resolve."
        assert set(relation["evidence_ids"]) <= evidence_ids, "relation evidence must resolve."
        assert relation["provenance"] in PROVENANCE_KINDS, "relation provenance must be allowed."

        if relation["provenance"] == "inferred":
            assert relation.get("inference_rule"), "inferred relation must name its rule."

        for field in ("blocking_control_id", "remediated_by_control_id"):
            if field in relation:
                assert relation[field] in control_ids, "relation control must resolve."

    for path in scenario["attack_paths"]:
        assert path["source_id"] == path["node_ids"][0], "path source must be its first node."
        assert path["target_id"] == path["node_ids"][-1], "path target must be its final node."
        assert len(path["node_ids"]) == len(path["relation_ids"]) + 1, (
            "path node and relation counts must describe one continuous route."
        )

        for index, relation_id in enumerate(path["relation_ids"]):
            relation = indexes["relations"][relation_id]

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
    endpoint_ids = set(IndexById(scenario["endpoints"]))
    evidence_ids = set(IndexById(scenario["evidence"]))
    impact_ids = set(IndexById(scenario["business_impacts"]))
    asset_ids = set(IndexById(scenario["assets"]))

    for finding in scenario["findings"]:
        mitre = finding["mitre"]

        assert finding["endpoint_id"] in endpoint_ids, "finding endpoint must resolve."
        assert set(finding["evidence_ids"]) <= evidence_ids, "finding evidence must resolve."
        assert set(finding["business_impact_ids"]) <= impact_ids, (
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
        assert impact["asset_id"] in asset_ids, "business-impact asset must resolve."
        assert impact["business_process"], "business process must be explicit."
        assert impact["consequence"], "business consequence must be explicit."


def test_AttackPathStatesMeetConfidenceEvidenceAndInferenceRules():
    """Apply the declared state contract to every phase assessment."""

    scenario = LoadJson("scenario.v1.json")
    requirements = scenario["state_requirements"]
    evidence_ids = set(IndexById(scenario["evidence"]))
    control_ids = set(IndexById(scenario["controls"]))
    path_ids = set(IndexById(scenario["attack_paths"]))
    observed_states = {
        assessment["state"]
        for phase in scenario["phases"]
        for assessment in phase["assessments"]
    }
    observed_provenance = {
        assessment["provenance"]
        for phase in scenario["phases"]
        for assessment in phase["assessments"]
    }

    assert set(requirements) == PATH_STATES, "state requirements must cover the canonical set."
    assert observed_states == PATH_STATES, "fixture lifecycle must exercise every path state."
    assert observed_provenance == PROVENANCE_KINDS, (
        "fixture lifecycle must exercise seeded, discovered, and inferred provenance."
    )

    for phase in scenario["phases"]:
        for assessment in phase["assessments"]:
            state = assessment["state"]
            requirement = requirements[state]

            assert assessment["path_id"] in path_ids, "assessment path must resolve."
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
            assert set(assessment["evidence_ids"]) <= evidence_ids, (
                "assessment evidence must resolve."
            )

            if requirement["inference_required"]:
                assert assessment.get("inference_rule"), "state requires an inference rule."

            if assessment["provenance"] == "inferred":
                assert assessment.get("inference_rule"), (
                    "inferred assessment must name its inference rule."
                )

            if requirement["blocking_control_required"]:
                blocking_controls = set(assessment.get("blocking_control_ids", []))

                assert blocking_controls, "blocked assessment must name a control."
                assert blocking_controls <= control_ids, "blocking controls must resolve."


def test_AttackPathTransitionsAreContiguousEvidenceBackedAndAuthorized():
    """Validate every lifecycle transition, evidence rule, and authorization boundary."""

    scenario = LoadJson("scenario.v1.json")
    phases = scenario["phases"]
    phase_ids = [phase["id"] for phase in phases]
    evidence = IndexById(scenario["evidence"])
    transitions = scenario["transitions"]

    assert [phase["sequence"] for phase in phases] == list(range(5)), (
        "phase sequence must be contiguous."
    )

    for index, transition in enumerate(transitions):
        assert transition["from_phase_id"] == phase_ids[index], (
            "transition source must match lifecycle order."
        )
        assert transition["to_phase_id"] == phase_ids[index + 1], (
            "transition target must match lifecycle order."
        )
        assert transition["evidence_ids"], "transition must be evidence-backed."
        assert set(transition["evidence_ids"]) <= set(evidence), (
            "transition evidence must resolve."
        )

        target_evidence = {
            evidence_id
            for evidence_id in transition["evidence_ids"]
            if evidence[evidence_id]["phase_id"] == transition["to_phase_id"]
        }
        assert target_evidence, "transition must add evidence attributable to its target phase."

        if transition["to_phase_id"] == "phase.finding-confirmation":
            assert transition.get("inference_rule"), (
                "finding confirmation transition must name its inference rule."
            )

        if transition["requires_authorization"]:
            authorization_id = transition.get("authorization_evidence_id")

            assert authorization_id in transition["evidence_ids"], (
                "authorized transition must include its authorization evidence."
            )
            assert evidence[authorization_id]["type"] == "authorization-record", (
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
