"""Public contract checks for the provider-neutral ToolAdapter SDK."""

from __future__ import annotations

import json
from collections.abc import Mapping

import pytest

from fuzzy1337.adapters import (
    ADAPTERCONTRACTVERSION,
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
        adapterId="scanner.example",
        displayName="Example Scanner",
        version="1.2.3",
        capabilities=("network.port_scan", "service.enumerate"),
        maximumImpact=ImpactLevel.SAFE,
        requiredPrivileges=("network.raw-socket",),
    )


def Request() -> AdapterRequest:
    """Provide deterministic test support for request."""

    return AdapterRequest(
        capability="network.port_scan",
        targetReference="target:synthetic-lab",
        impact=ImpactLevel.SAFE,
        parameters={"ports": [443, 80], "options": {"fast": True}},
        credentialReferences=("credential:lab-readonly",),
    )


def Invocation() -> AdapterInvocation:
    """Provide deterministic test support for invocation."""

    return AdapterInvocation(
        adapterId="scanner.example",
        request=Request(),
        argv=("example-scanner", "--target", "target:synthetic-lab"),
        timeoutSeconds=30,
        providerVersion="7.4",
    )


def Evidence() -> EvidenceReference:
    """Provide deterministic test support for evidence."""

    return EvidenceReference(
        role="stdout",
        locator="runs/0001/example.json",
        sha256="a" * 64,
        mediaType="application/json",
        sizeBytes=42,
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
            adapterId="scanner.example",
            state=AdapterHealthState.AVAILABLE,
            providerVersion="7.4",
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

    assert ADAPTERCONTRACTVERSION == 1, (
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
        "request metadata immutability invariant failed."
    )
    assert request.parameters["ports"] == (443, 80), (
        "request metadata immutability invariant failed."
    )
    assert request.parameters["options"] == {"fast": True}, (
        "request metadata immutability invariant failed."
    )
    with pytest.raises(TypeError):
        request.parameters["new"] = "value"  # type: ignore[index]
    with pytest.raises(TypeError):
        request.parameters["options"]["fast"] = False  # type: ignore[index]

    first = SerializeContract(request)
    second = SerializeContract(
        AdapterRequest(
            capability="network.port_scan",
            targetReference="target:synthetic-lab",
            impact=ImpactLevel.SAFE,
            parameters={"options": {"fast": True}, "ports": [443, 80]},
            credentialReferences=("credential:lab-readonly",),
        )
    )

    assert first == second, (
        "request metadata immutability invariant failed."
    )
    assert json.loads(first)["parameters"] == {"options": {"fast": True}, "ports": [443, 80]}, (
        "request metadata immutability invariant failed."
    )


@pytest.mark.parametrize(
    ("factory", "message"),
    [
        (
            lambda: AdapterDescriptor(
                adapterId="scanner.example",
                displayName="Example",
                version="1",
                capabilities=("network.port_scan", "network.port_scan"),
                maximumImpact=ImpactLevel.SAFE,
            ),
            "unique",
        ),
        (
            lambda: AdapterDescriptor(
                adapterId="scanner.example",
                displayName="Example",
                version="1",
                capabilities=(),
                maximumImpact=ImpactLevel.SAFE,
            ),
            "capabilities",
        ),
        (
            lambda: AdapterRequest(
                capability="Network.Scan",
                targetReference="target:lab",
                impact=ImpactLevel.SAFE,
            ),
            "identifier",
        ),
        (
            lambda: AdapterInvocation(
                adapterId="scanner.example",
                request=Request(),
                argv=("example-scanner",),
                timeoutSeconds=0,
            ),
            "timeout",
        ),
        (
            lambda: EvidenceReference(
                role="stdout",
                locator="../unsafe.json",
                sha256="a" * 64,
                mediaType="application/json",
                sizeBytes=1,
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
    ("state", "exitCode", "message"),
    [
        (ExecutionState.SUCCEEDED, 1, "successful"),
        (ExecutionState.FAILED, 0, "failed"),
        (ExecutionState.TIMEDOUT, 0, "timed-out"),
        (ExecutionState.CANCELLED, 0, "cancelled"),
    ],
)
def test_ExecutionStateValidationPreservesFailureTruth(state, exitCode, message):
    """Verify execution state validation preserves failure truth."""

    with pytest.raises(ValueError, match=message):
        AdapterExecution(state=state, exitCode=exitCode, durationSeconds=0.1)


def test_NormalizedResultKeepsEvidenceDistinctFromGenericEnrichment():
    """Verify normalized result keeps evidence distinct from generic enrichment."""

    report = AdapterReport(
        invocation=Invocation(),
        execution=AdapterExecution(
            state=ExecutionState.SUCCEEDED,
            exitCode=0,
            durationSeconds=0.125,
        ),
        evidence=(Evidence(),),
    )
    result = AdapterResult(
        report=report,
        observations=(
            NormalizedObservation(
                kind="network.port",
                subjectReference="service:443",
                attributes={"protocol": "tcp"},
            ),
        ),
        findings=(
            NormalizedFinding(
                kind="service.exposed",
                subjectReference="service:443",
                summary="Synthetic service is reachable.",
            ),
        ),
        objectEnrichments=(
            ObjectEnrichment(
                objectKind="service",
                objectReference="service:443",
                attributes={"name": "https"},
            ),
        ),
        relationEnrichments=(
            RelationEnrichment(
                relationKind="endpoint.exposes-service",
                sourceReference="endpoint:https://example.test",
                targetReference="service:443",
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
    assert payload["objectEnrichments"][0]["objectKind"] == "service", (
        "normalized result keeps evidence distinct from generic enrichment invariant failed."
    )
    assert payload["relationEnrichments"][0]["relationKind"] == "endpoint.exposes-service", (
        "normalized result keeps evidence distinct from generic enrichment invariant failed."
    )
