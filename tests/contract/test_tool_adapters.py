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
    SerializeContract,
    ToolAdapter,
)


def Descriptor() -> AdapterDescriptor:
    """Provide deterministic test support for descriptor."""

    return AdapterDescriptor(
        adapter_id="scanner.example",
        display_name="Example Scanner",
        version="1.2.3",
        capabilities=("network.port_scan", "service.enumerate"),
        maximum_impact=ImpactLevel.SAFE,
        required_privileges=("network.raw-socket",),
    )


def Request() -> AdapterRequest:
    """Provide deterministic test support for request."""

    return AdapterRequest(
        capability="network.port_scan",
        target_reference="target:synthetic-lab",
        impact=ImpactLevel.SAFE,
        parameters={"ports": [443, 80], "options": {"fast": True}},
        credential_references=("credential:lab-readonly",),
    )


def Invocation() -> AdapterInvocation:
    """Provide deterministic test support for invocation."""

    return AdapterInvocation(
        adapter_id="scanner.example",
        request=Request(),
        argv=("example-scanner", "--target", "target:synthetic-lab"),
        timeout_seconds=30,
        provider_version="7.4",
    )


def Evidence() -> EvidenceReference:
    """Provide deterministic test support for evidence."""

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
    def Descriptor(self) -> AdapterDescriptor:
        """Provide deterministic test support for descriptor."""

        return Descriptor()

    def CheckHealth(self) -> AdapterHealth:
        """Provide deterministic test support for check health."""

        return AdapterHealth(
            adapter_id="scanner.example",
            state=AdapterHealthState.AVAILABLE,
            provider_version="7.4",
        )

    def PrepareInvocation(self, request: AdapterRequest) -> AdapterInvocation:
        """Provide deterministic test support for prepare invocation."""

        assert request.capability in self.Descriptor.capabilities, (
            "prepare invocation invariant failed."
        )
        return Invocation()

    def NormalizeReport(self, report: AdapterReport) -> AdapterResult:
        """Provide deterministic test support for normalize report."""

        return AdapterResult(report=report)


def test_ContractVersionAndProtocolSurfaceAreExplicit():
    """Verify contract version and protocol surface are explicit."""

    adapter = ExampleAdapter()

    assert ADAPTER_CONTRACT_VERSION == 1, (
        "contract version and protocol surface are explicit invariant failed."
    )
    assert isinstance(adapter, ToolAdapter), (
        "contract version and protocol surface are explicit invariant failed."
    )
    assert adapter.Descriptor.Supports("network.port_scan"), (
        "contract version and protocol surface are explicit invariant failed."
    )
    assert not adapter.Descriptor.Supports("web.crawl"), (
        "contract version and protocol surface are explicit invariant failed."
    )
    assert adapter.CheckHealth().state is AdapterHealthState.AVAILABLE, (
        "contract version and protocol surface are explicit invariant failed."
    )


def test_RequestMetadataIsRecursivelyImmutableAndSerializedDeterministically():
    """Verify request metadata is recursively immutable and serialized deterministically."""

    request = Request()

    assert isinstance(request.parameters, Mapping), (
        "request parameters must expose an immutable mapping."
    )
    assert request.parameters["ports"] == (443, 80), (
        "request port metadata must preserve immutable ordering."
    )
    assert request.parameters["options"] == {"fast": True}, (
        "nested request options must remain immutable."
    )
    with pytest.raises(TypeError):
        request.parameters["new"] = "value"  # type: ignore[index]
    with pytest.raises(TypeError):
        request.parameters["options"]["fast"] = False  # type: ignore[index]

    first = SerializeContract(request)
    second = SerializeContract(
        AdapterRequest(
            capability="network.port_scan",
            target_reference="target:synthetic-lab",
            impact=ImpactLevel.SAFE,
            parameters={"options": {"fast": True}, "ports": [443, 80]},
            credential_references=("credential:lab-readonly",),
        )
    )

    assert first == second, "equivalent requests must serialize identically."
    assert json.loads(first)["parameters"] == {"options": {"fast": True}, "ports": [443, 80]}, (
        "serialized request parameters must preserve JSON values."
    )


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
                request=Request(),
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
def test_InvalidContractInputsFailClosed(factory, message):
    """Verify invalid contract inputs fail closed."""

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
def test_ExecutionStateValidationPreservesFailureTruth(state, exit_code, message):
    """Verify execution state validation preserves failure truth."""

    with pytest.raises(ValueError, match=message):
        AdapterExecution(state=state, exit_code=exit_code, duration_seconds=0.1)


def test_NormalizedResultKeepsEvidenceDistinctFromGenericEnrichment():
    """Verify normalized result keeps evidence distinct from generic enrichment."""

    report = AdapterReport(
        invocation=Invocation(),
        execution=AdapterExecution(
            state=ExecutionState.SUCCEEDED,
            exit_code=0,
            duration_seconds=0.125,
        ),
        evidence=(Evidence(),),
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

    payload = json.loads(SerializeContract(result))

    assert payload["report"]["evidence"][0]["locator"] == "runs/0001/example.json", (
        "normalized result keeps evidence distinct from generic enrichment invariant failed."
    )
    assert payload["observations"][0]["attributes"] == {"protocol": "tcp"}, (
        "normalized result keeps evidence distinct from generic enrichment invariant failed."
    )
    assert payload["findings"][0]["kind"] == "service.exposed", (
        "normalized result keeps evidence distinct from generic enrichment invariant failed."
    )
    assert payload["object_enrichments"][0]["object_kind"] == "service", (
        "normalized result keeps evidence distinct from generic enrichment invariant failed."
    )
    assert payload["relation_enrichments"][0]["relation_kind"] == "endpoint.exposes-service", (
        "normalized result keeps evidence distinct from generic enrichment invariant failed."
    )
