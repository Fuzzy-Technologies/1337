# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent schema-v1 consumer fixtures and explicit runtime-only semantic boundaries."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from fuzzy1337.journeys import JourneyScenario

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/contract/fixtures/synthetic-journey.v1.json"
SCHEMA = ROOT / "contracts/journey-scenario.schema.json"


def Fixture() -> dict[str, object]:
    """Load the literal mixed-operation fixture independently of its typed producer."""

    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def Validator() -> Draft202012Validator:
    """Use only the standalone schema and local references without remote resolution."""

    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)

    return Draft202012Validator(schema)


def test_IndependentScenarioFixtureMatchesTypedProducerAndSchema():
    """A hand-written scenario keeps finite fields and opaque references across consumers."""

    document = Fixture()
    validator = Validator()
    validator.validate(document)
    scenario = JourneyScenario.FromDict(document)
    canonical = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    assert scenario.ToDict() == document, "Typed producer changed exact fixture fields"
    assert scenario.ToJson() == canonical, (
        "Canonical producer JSON diverged from independent consumer"
    )
    assert scenario.Digest() == "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(), (
        "Scenario content binding changed independently of serialization"
    )
    assert [item.operation.value for item in scenario.steps] == [
        "navigate", "fill", "click", "api_request",
    ], "Mixed browser/API declaration order changed"
    assert set(document) == {
        "schema_version", "scenario_id", "workspace_id", "scope_id", "allowed_targets", "steps",
        "workload", "test_data_reference", "session_reference",
    }, "Scenario contract silently added fields"


@pytest.mark.parametrize("owner", ["scenario", "workload", "step", "assertion", "target"])
@pytest.mark.parametrize("mutation", ["unknown", "missing"])
def test_ExactFieldsRejectSecretScriptAndMissingMetadata(owner, mutation):
    """Both independent schema and runtime refuse undeclared fields at every object boundary."""

    document = Fixture()
    record = {
        "scenario": document,
        "workload": document["workload"],
        "step": document["steps"][0],
        "assertion": document["steps"][0]["assertions"][0],
        "target": document["allowed_targets"][0],
    }[owner]

    if mutation == "unknown":
        record["script"] = "synthetic rejected expression"

    else:
        del record[next(iter(record))]

    assert not Validator().is_valid(document), "Schema accepted unknown or missing fields"

    with pytest.raises(ValueError):
        JourneyScenario.FromDict(document)


@pytest.mark.parametrize("boundary", [
    "operation", "method", "assertion", "declared-target", "step-target",
])
def test_InvalidEnumFieldsNeverEchoCapturedInput(boundary):
    """Invalid untrusted scenario fields cannot disclose private values in diagnostics."""

    document = Fixture()
    marker = "synthetic-private-value-not-for-output"

    if boundary == "operation":
        document["steps"][0]["operation"] = marker

    elif boundary == "method":
        document["steps"][-1]["method"] = marker

    elif boundary == "assertion":
        document["steps"][0]["assertions"][0]["kind"] = marker

    elif boundary == "declared-target":
        document["allowed_targets"][0]["kind"] = marker

    else:
        document["steps"][0]["target"]["kind"] = marker

    with pytest.raises(ValueError) as caught:
        JourneyScenario.FromDict(document)

    assert marker not in str(caught.value), "Scenario validation leaked captured input"


@pytest.mark.parametrize("change", [
    {"operation": "evaluate"}, {"operation": "navigate", "selector": "#unexpected"},
    {"operation": "click", "selector": "button", "method": "GET"},
    {"operation": "fill", "selector": "input", "test_data_key": None},
    {"operation": "api_request", "method": None},
    {"operation": "api_request", "method": "TRACE"},
    {"operation": "api_request", "method": "GET", "assertions": [
        {"kind": "element_present", "expected": "input"},
    ]},
    {"selector": "{{selector}}"}, {"think_time_ms": True}, {"think_time_ms": 60001},
])
def test_SchemaAndRuntimeRejectInvalidActionCombinations(change):
    """Finite operations and operation-specific fields agree at both consumer boundaries."""

    document = Fixture()
    document["steps"][0].update(change)

    assert not Validator().is_valid(document), "Schema accepted an invalid operation combination"

    with pytest.raises(ValueError):
        JourneyScenario.FromDict(document)


@pytest.mark.parametrize("change", [
    {"iterations": 0}, {"concurrency": 17}, {"requests_per_second": 101},
    {"max_requests": 100001}, {"max_duration_seconds": 3601}, {"iterations": True},
])
def test_SchemaAndRuntimeRejectUnlimitedWorkloadFields(change):
    """Schema validation never substitutes for finite workload ceilings."""

    document = Fixture()
    document["workload"].update(change)

    assert not Validator().is_valid(document), "Schema accepted an excessive workload field"

    with pytest.raises(ValueError):
        JourneyScenario.FromDict(document)


@pytest.mark.parametrize("field, value", [
    ("scenario_id", "valid\n"), ("session_reference", "session:valid\n"),
    ("test_data_reference", "test-data:valid\n"),
])
def test_SchemaReferencePatternsCannotAcceptTrailingNewlines(field, value):
    """Regex end-of-string semantics cannot admit control characters into identifiers."""

    document = Fixture()
    document[field] = value

    assert not Validator().is_valid(document), "Schema pattern accepted a trailing newline"

    with pytest.raises(ValueError):
        JourneyScenario.FromDict(document)


@pytest.mark.parametrize("boundary", [
    "canonical-url", "duplicate-step-id", "undeclared-target", "missing-data-reference",
    "concurrency-iterations", "aggregate-actions", "float-integer",
])
def test_RuntimeAddsExplicitSemanticChecksBeyondStructuralSchema(boundary):
    """Schema-valid objects still require runtime canonical identity and cross-field checks."""

    document = Fixture()

    if boundary == "canonical-url":
        document["allowed_targets"][0]["value"] = "http://LOCALHOST/"

    elif boundary == "duplicate-step-id":
        document["steps"][1]["step_id"] = document["steps"][0]["step_id"]

    elif boundary == "undeclared-target":
        document["steps"][0]["target"]["value"] = "http://127.0.0.1:19001/outside"

    elif boundary == "missing-data-reference":
        document["test_data_reference"] = None

    elif boundary == "concurrency-iterations":
        document["workload"]["iterations"] = 1

    elif boundary == "aggregate-actions":
        original = document["steps"][0]
        document["steps"] = [dict(copy.deepcopy(original), step_id=f"step-{i}") for i in range(11)]
        document["workload"]["iterations"] = 1000

    else:
        document["workload"]["iterations"] = 2.0

    assert Validator().is_valid(document), "Fixture no longer demonstrates runtime-only validation"

    with pytest.raises(ValueError):
        JourneyScenario.FromDict(document)
