"""Contract checks for the experimental executor SDK."""

from __future__ import annotations

import pytest

from fuzzy1337.adapters import (
    AdapterDescriptor,
    AdapterInvocation,
    AdapterRequest,
    ImpactLevel,
)
from fuzzy1337.executors import (
    EXECUTORCONTRACTVERSION,
    CapabilityDescriptor,
    CapabilityDescriptors,
    ExecutionAuthorization,
    ExecutionResources,
    InvocationDigest,
    LazyAdapterRegistry,
    LocalExecutionRequest,
)


def ExampleDescriptor() -> AdapterDescriptor:
    """Build a deterministic adapter declaration for contract tests."""

    return AdapterDescriptor(
        adapterId="scanner.example",
        displayName="Example Scanner",
        version="1.0",
        capabilities=("network.port-scan", "service.enumerate"),
        maximumImpact=ImpactLevel.SAFE,
        requiredPrivileges=("network.raw-socket",),
    )


def Invocation() -> AdapterInvocation:
    """Build the immutable invocation shared by executor contract tests."""

    return AdapterInvocation(
        adapterId="scanner.example",
        request=AdapterRequest(
            capability="network.port-scan",
            targetReference="target:synthetic-lab",
            impact=ImpactLevel.SAFE,
        ),
        argv=("example-scanner", "--target", "synthetic-lab"),
        timeoutSeconds=30,
        providerVersion="1.0",
    )


def Authorization(invocation: AdapterInvocation) -> ExecutionAuthorization:
    """Authorize exactly one prepared test invocation."""

    return ExecutionAuthorization(
        authorizationId="authorization:unit-test",
        scopeReference="scope:synthetic-lab",
        policyReference="policy:unit-test",
        invocationSha256=InvocationDigest(invocation),
        grantedPrivileges=("network.raw-socket",),
    )


def test_ExecutorContractVersionAndCapabilitiesAreExplicit():
    """Keep the contract version and expanded capabilities explicit."""

    capabilities = CapabilityDescriptors(ExampleDescriptor())

    assert EXECUTORCONTRACTVERSION == 1, (
        "executor contract version and capabilities are explicit invariant failed."
    )
    assert capabilities == (
        CapabilityDescriptor(
            identifier="network.port-scan",
            adapterId="scanner.example",
            maximumImpact=ImpactLevel.SAFE,
            requiredPrivileges=("network.raw-socket",),
        ),
        CapabilityDescriptor(
            identifier="service.enumerate",
            adapterId="scanner.example",
            maximumImpact=ImpactLevel.SAFE,
            requiredPrivileges=("network.raw-socket",),
        ),
    ), "executor contract version and capabilities are explicit invariant failed."


def test_LocalRequestBindsAuthorizationCapabilityAndInvocation():
    """Bind authorization, capability, and invocation immutably."""

    invocation = Invocation()
    request = LocalExecutionRequest(
        invocation=invocation,
        capability=CapabilityDescriptors(ExampleDescriptor())[0],
        authorization=Authorization(invocation),
        workspace="runs/scan-1",
        environment={"LC_ALL": "C"},
        resources=ExecutionResources(maxStdoutBytes=1024, maxStderrBytes=512),
    )

    assert request.environment == {"LC_ALL": "C"}, (
        "local request binds authorization capability and invocation invariant failed."
    )
    assert request.workspace == "runs/scan-1", (
        "local request binds authorization capability and invocation invariant failed."
    )
    with pytest.raises(TypeError):
        request.environment["LC_ALL"] = "en_US.UTF-8"  # type: ignore[index]


@pytest.mark.parametrize(
    ("replace", "message"),
    [
        ({"workspace": "../outside"}, "workspace"),
        ({"environment": {"INVALID-NAME": "value"}}, "environment"),
        ({"environment": {"TOKEN": "bad\x00value"}}, "environment"),
    ],
)
def test_LocalRequestRejectsUnsafeWorkspaceAndEnvironment(replace, message):
    """Reject unsafe paths and environment values before execution."""

    invocation = Invocation()
    arguments = {
        "invocation": invocation,
        "capability": CapabilityDescriptors(ExampleDescriptor())[0],
        "authorization": Authorization(invocation),
        "workspace": ".",
        "environment": {},
    }
    arguments.update(replace)

    with pytest.raises(ValueError, match=message):
        LocalExecutionRequest(**arguments)


def test_RequestRejectsMismatchedAuthorizationAndMissingPrivileges():
    """Reject mismatched authorization and missing privileges."""

    invocation = Invocation()
    capability = CapabilityDescriptors(ExampleDescriptor())[0]
    wrongAuthorization = ExecutionAuthorization(
        authorizationId="authorization:wrong",
        scopeReference="scope:synthetic-lab",
        policyReference="policy:unit-test",
        invocationSha256="0" * 64,
        grantedPrivileges=("network.raw-socket",),
    )

    with pytest.raises(ValueError, match="invocation"):
        LocalExecutionRequest(
            invocation=invocation,
            capability=capability,
            authorization=wrongAuthorization,
        )

    withoutPrivilege = ExecutionAuthorization(
        authorizationId="authorization:missing-privilege",
        scopeReference="scope:synthetic-lab",
        policyReference="policy:unit-test",
        invocationSha256=InvocationDigest(invocation),
    )
    with pytest.raises(ValueError, match="privilege"):
        LocalExecutionRequest(
            invocation=invocation,
            capability=capability,
            authorization=withoutPrivilege,
        )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ExecutionAuthorization(
            authorizationId="authorization:invalid-digest",
            scopeReference="scope:synthetic-lab",
            policyReference="policy:unit-test",
            invocationSha256="not-a-digest",
        ),
        lambda: ExecutionResources(maxStdoutBytes=0),
        lambda: ExecutionResources(maxStderrBytes=True),
        lambda: ExecutionResources(terminateGraceSeconds=float("inf")),
    ],
)
def test_InvalidAuthorizationAndResourceBoundsFailClosed(factory):
    """Reject malformed authorization and resource limits."""

    with pytest.raises(ValueError):
        factory()


def test_LazyRegistryDoesNotLoadAdaptersUntilResolution():
    """Load registered adapters only when a capability is resolved."""

    descriptor = ExampleDescriptor()
    loads: list[str] = []

    class Adapter:
        """Implement the minimal adapter protocol used by registry tests."""

        @property
        def Descriptor(self):
            """Expose the provider declaration required by ToolAdapter."""

            return descriptor

        def CheckHealth(self):
            """Fail if registry resolution performs a health check."""

            raise AssertionError("health is not part of registry resolution")

        def PrepareInvocation(self, request):
            """Fail if registry resolution prepares an invocation."""

            raise AssertionError("preparation is not part of registry resolution")

        def NormalizeReport(self, report):
            """Fail if registry resolution normalizes a report."""

            raise AssertionError("normalization is not part of registry resolution")

    registry = LazyAdapterRegistry()
    registry.Register(descriptor, lambda: loads.append("loaded") or Adapter())

    assert registry.Capabilities == ("network.port-scan", "service.enumerate"), (
        "registry must expose declared capabilities"
    )
    assert loads == [], "registration must not load an adapter"
    assert registry.Resolve("network.port-scan").Descriptor == descriptor, (
        "resolution must return the declared adapter"
    )
    assert loads == ["loaded"], "first resolution must load once"
    assert registry.Resolve("service.enumerate").Descriptor == descriptor, (
        "all declared capabilities must resolve to the same adapter"
    )
    assert loads == ["loaded"], "subsequent resolutions must reuse the adapter"


def test_LazyRegistryFailsClosedForUnknownOrMisdeclaredProvider():
    """Fail closed for unknown capabilities and invalid providers."""

    descriptor = ExampleDescriptor()
    registry = LazyAdapterRegistry()
    registry.Register(descriptor, lambda: object())

    with pytest.raises(LookupError, match="Unknown capability"):
        registry.Resolve("web.crawl")
    with pytest.raises(TypeError, match="ToolAdapter"):
        registry.Resolve("network.port-scan")
