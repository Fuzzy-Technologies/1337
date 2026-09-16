"""Public contract checks for the provider-neutral ToolAdapter SDK."""

from __future__ import annotations

import json
from collections.abc import Mapping

import pytest

from fuzzy1337.adapters import (
    ADAPTER_CONTRACT_VERSION,
    AdapterDescriptor,
    AdapterExecution,
    AdapterHealth,
    AdapterHealthState,
    AdapterInvocation,
    AdapterReport,
    AdapterRequest,
    AdapterResult,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
    NormalizedFinding,
    NormalizedObservation,
    ObjectEnrichment,
    RelationEnrichment,
    ToolAdapter,
    serialize_contract,
)


def _descriptor() -> AdapterDescriptor:
    return AdapterDescriptor(
        adapter_id="scanner.example",
        display_name="Example Scanner",
        version="1.2.3",
        capabilities=("network.port_scan", "service.enumerate"),
        maximum_impact=ImpactLevel.SAFE,
        required_privileges=("network.raw-socket",),
    )


def _request() -> AdapterRequest:
    return AdapterRequest(
        capability="network.port_scan",
        target_reference="target:synthetic-lab",
        impact=ImpactLevel.SAFE,
        parameters={"ports": [443, 80], "options": {"fast": True}},
        credential_references=("credential:lab-readonly",),
    )


def _invocation() -> AdapterInvocation:
    return AdapterInvocation(
        adapter_id="scanner.example",
        request=_request(),
        argv=("example-scanner", "--target", "target:synthetic-lab"),
        timeout_seconds=30,
        provider_version="7.4",
    )


def _evidence() -> EvidenceReference:
    return EvidenceReference(
        role="stdout",
        locator="runs/0001/example.json",
        sha256="a" * 64,
        media_type="application/json",
        size_bytes=42,
    )


class ExampleAdapter:
    """Minimal structural implementation used to prove the public protocol."""

    @property
    def descriptor(self) -> AdapterDescriptor:
        return _descriptor()

    def check_health(self) -> AdapterHealth:
        return AdapterHealth(
            adapter_id="scanner.example",
            state=AdapterHealthState.AVAILABLE,
            provider_version="7.4",
        )

    def prepare_invocation(self, request: AdapterRequest) -> AdapterInvocation:
        assert request.capability in self.descriptor.capabilities
        return _invocation()

    def normalize_report(self, report: AdapterReport) -> AdapterResult:
        return AdapterResult(report=report)


def test_contract_version_and_protocol_surface_are_explicit():
    adapter = ExampleAdapter()

    assert ADAPTER_CONTRACT_VERSION == 1
    assert isinstance(adapter, ToolAdapter)
    assert adapter.descriptor.supports("network.port_scan")
    assert not adapter.descriptor.supports("web.crawl")
    assert adapter.check_health().state is AdapterHealthState.AVAILABLE


def test_request_metadata_is_recursively_immutable_and_serialized_deterministically():
    request = _request()

    assert isinstance(request.parameters, Mapping)
    assert request.parameters["ports"] == (443, 80)
    assert request.parameters["options"] == {"fast": True}
    with pytest.raises(TypeError):
        request.parameters["new"] = "value"  # type: ignore[index]
    with pytest.raises(TypeError):
        request.parameters["options"]["fast"] = False  # type: ignore[index]

    first = serialize_contract(request)
    second = serialize_contract(
        AdapterRequest(
            capability="network.port_scan",
            target_reference="target:synthetic-lab",
            impact=ImpactLevel.SAFE,
            parameters={"options": {"fast": True}, "ports": [443, 80]},
            credential_references=("credential:lab-readonly",),
        )
    )

    assert first == second
    assert json.loads(first)["parameters"] == {"options": {"fast": True}, "ports": [443, 80]}


@pytest.mark.parametrize(
    ("factory", "message"),
    [
        (
            lambda: AdapterDescriptor(
                adapter_id="scanner.example",
                display_name="Example",
                version="1",
                capabilities=("network.port_scan", "network.port_scan"),
                maximum_impact=ImpactLevel.SAFE,
            ),
            "unique",
        ),
        (
            lambda: AdapterDescriptor(
                adapter_id="scanner.example",
                display_name="Example",
                version="1",
                capabilities=(),
                maximum_impact=ImpactLevel.SAFE,
            ),
            "capabilities",
        ),
        (
            lambda: AdapterRequest(
                capability="Network.Scan",
                target_reference="target:lab",
                impact=ImpactLevel.SAFE,
            ),
            "identifier",
        ),
        (
            lambda: AdapterInvocation(
                adapter_id="scanner.example",
                request=_request(),
                argv=("example-scanner",),
                timeout_seconds=0,
            ),
            "timeout",
        ),
        (
            lambda: EvidenceReference(
                role="stdout",
                locator="../unsafe.json",
                sha256="a" * 64,
                media_type="application/json",
                size_bytes=1,
            ),
            "relative",
        ),
    ],
)
def test_invalid_contract_inputs_fail_closed(factory, message):
    with pytest.raises(ValueError, match=message):
        factory()


@pytest.mark.parametrize(
    ("state", "exit_code", "message"),
    [
        (ExecutionState.SUCCEEDED, 1, "successful"),
        (ExecutionState.FAILED, 0, "failed"),
        (ExecutionState.TIMED_OUT, 0, "timed-out"),
        (ExecutionState.CANCELLED, 0, "cancelled"),
    ],
)
def test_execution_state_validation_preserves_failure_truth(state, exit_code, message):
    with pytest.raises(ValueError, match=message):
        AdapterExecution(state=state, exit_code=exit_code, duration_seconds=0.1)


def test_normalized_result_keeps_evidence_distinct_from_generic_enrichment():
    report = AdapterReport(
        invocation=_invocation(),
        execution=AdapterExecution(
            state=ExecutionState.SUCCEEDED,
            exit_code=0,
            duration_seconds=0.125,
        ),
        evidence=(_evidence(),),
    )
    result = AdapterResult(
        report=report,
        observations=(
            NormalizedObservation(
                kind="network.port",
                subject_reference="service:443",
                attributes={"protocol": "tcp"},
            ),
        ),
        findings=(
            NormalizedFinding(
                kind="service.exposed",
                subject_reference="service:443",
                summary="Synthetic service is reachable.",
            ),
        ),
        object_enrichments=(
            ObjectEnrichment(
                object_kind="service",
                object_reference="service:443",
                attributes={"name": "https"},
            ),
        ),
        relation_enrichments=(
            RelationEnrichment(
                relation_kind="endpoint.exposes-service",
                source_reference="endpoint:https://example.test",
                target_reference="service:443",
            ),
        ),
    )

    payload = json.loads(serialize_contract(result))

    assert payload["report"]["evidence"][0]["locator"] == "runs/0001/example.json"
    assert payload["observations"][0]["attributes"] == {"protocol": "tcp"}
    assert payload["findings"][0]["kind"] == "service.exposed"
    assert payload["object_enrichments"][0]["object_kind"] == "service"
    assert payload["relation_enrichments"][0]["relation_kind"] == "endpoint.exposes-service"
