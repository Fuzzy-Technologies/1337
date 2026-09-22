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
    EXECUTOR_CONTRACT_VERSION,
    CapabilityDescriptor,
    CapabilityDescriptors,
    ExecutionAuthorization,
    ExecutionResources,
    InvocationDigest,
    LazyAdapterRegistry,
    LocalExecutionRequest,
)


def ExampleDescriptor() -> AdapterDescriptor:
    """Provide deterministic test support for example descriptor."""

    return AdapterDescriptor(
        adapter_id="scanner.example",
        display_name="Example Scanner",
        version="1.0",
        capabilities=("network.port-scan", "service.enumerate"),
        maximum_impact=ImpactLevel.SAFE,
        required_privileges=("network.raw-socket",),
    )


def Invocation() -> AdapterInvocation:
    """Provide deterministic test support for invocation."""

    return AdapterInvocation(
        adapter_id="scanner.example",
        request=AdapterRequest(
            capability="network.port-scan",
            target_reference="target:synthetic-lab",
            impact=ImpactLevel.SAFE,
        ),
        argv=("example-scanner", "--target", "synthetic-lab"),
        timeout_seconds=30,
        provider_version="1.0",
    )


def Authorization(invocation: AdapterInvocation) -> ExecutionAuthorization:
    """Provide deterministic test support for authorization."""

    return ExecutionAuthorization(
        authorization_id="authorization:unit-test",
        scope_reference="scope:synthetic-lab",
        policy_reference="policy:unit-test",
        invocation_sha256=InvocationDigest(invocation),
        granted_privileges=("network.raw-socket",),
    )


def test_ExecutorContractVersionAndCapabilitiesAreExplicit():
    """Verify executor contract version and capabilities are explicit."""

    capabilities = CapabilityDescriptors(ExampleDescriptor())

    assert EXECUTOR_CONTRACT_VERSION == 1, (
        "executor contract version and capabilities are explicit invariant failed."
    )
    assert capabilities == (
        CapabilityDescriptor(
            identifier="network.port-scan",
            adapter_id="scanner.example",
            maximum_impact=ImpactLevel.SAFE,
            required_privileges=("network.raw-socket",),
        ),
        CapabilityDescriptor(
            identifier="service.enumerate",
            adapter_id="scanner.example",
            maximum_impact=ImpactLevel.SAFE,
            required_privileges=("network.raw-socket",),
        ),
    ), "executor contract version and capabilities are explicit invariant failed."


def test_LocalRequestBindsAuthorizationCapabilityAndInvocation():
    """Verify local request binds authorization capability and invocation."""

    invocation = Invocation()
    request = LocalExecutionRequest(
        invocation=invocation,
        capability=CapabilityDescriptors(ExampleDescriptor())[0],
        authorization=Authorization(invocation),
        workspace="runs/scan-1",
        environment={"LC_ALL": "C"},
        resources=ExecutionResources(max_stdout_bytes=1024, max_stderr_bytes=512),
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
    """Verify local request rejects unsafe workspace and environment."""

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
    """Verify request rejects mismatched authorization and missing privileges."""

    invocation = Invocation()
    capability = CapabilityDescriptors(ExampleDescriptor())[0]
    wrong_authorization = ExecutionAuthorization(
        authorization_id="authorization:wrong",
        scope_reference="scope:synthetic-lab",
        policy_reference="policy:unit-test",
        invocation_sha256="0" * 64,
        granted_privileges=("network.raw-socket",),
    )

    with pytest.raises(ValueError, match="invocation"):
        LocalExecutionRequest(
            invocation=invocation,
            capability=capability,
            authorization=wrong_authorization,
        )

    without_privilege = ExecutionAuthorization(
        authorization_id="authorization:missing-privilege",
        scope_reference="scope:synthetic-lab",
        policy_reference="policy:unit-test",
        invocation_sha256=InvocationDigest(invocation),
    )

    with pytest.raises(ValueError, match="privilege"):
        LocalExecutionRequest(
            invocation=invocation,
            capability=capability,
            authorization=without_privilege,
        )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ExecutionAuthorization(
            authorization_id="authorization:invalid-digest",
            scope_reference="scope:synthetic-lab",
            policy_reference="policy:unit-test",
            invocation_sha256="not-a-digest",
        ),
        lambda: ExecutionResources(max_stdout_bytes=0),
        lambda: ExecutionResources(max_stderr_bytes=True),
        lambda: ExecutionResources(terminate_grace_seconds=float("inf")),
    ],
)
def test_InvalidAuthorizationAndResourceBoundsFailClosed(factory):
    """Verify invalid authorization and resource bounds fail closed."""

    with pytest.raises(ValueError):
        factory()


def test_LazyRegistryDoesNotLoadAdaptersUntilResolution():
    """Verify lazy registry does not load adapters until resolution."""

    descriptor = ExampleDescriptor()
    loads: list[str] = []

    class Adapter:
        """Group adapter test cases."""

        @property
        def Descriptor(self):
            """Provide deterministic test support for descriptor."""

            return descriptor

        def CheckHealth(self):
            """Provide deterministic test support for check health."""

            raise AssertionError("health is not part of registry resolution")

        def PrepareInvocation(self, request):
            """Provide deterministic test support for prepare invocation."""

            raise AssertionError("preparation is not part of registry resolution")

        def NormalizeReport(self, report):
            """Provide deterministic test support for normalize report."""

            raise AssertionError("normalization is not part of registry resolution")

    registry = LazyAdapterRegistry()
    registry.Register(descriptor, lambda: loads.append("loaded") or Adapter())

    assert registry.Capabilities == ("network.port-scan", "service.enumerate"), (
        "lazy registry does not load adapters until resolution invariant failed."
    )
    assert loads == [], "lazy registry does not load adapters until resolution invariant failed."
    assert registry.Resolve("network.port-scan").Descriptor == descriptor, (
        "lazy registry does not load adapters until resolution invariant failed."
    )
    assert loads == ["loaded"], (
        "lazy registry does not load adapters until resolution invariant failed."
    )
    assert registry.Resolve("service.enumerate").Descriptor == descriptor, (
        "lazy registry does not load adapters until resolution invariant failed."
    )
    assert loads == ["loaded"], (
        "lazy registry does not load adapters until resolution invariant failed."
    )


def test_LazyRegistryFailsClosedForUnknownOrMisdeclaredProvider():
    """Verify lazy registry fails closed for unknown or misdeclared provider."""

    descriptor = ExampleDescriptor()
    registry = LazyAdapterRegistry()
    registry.Register(descriptor, lambda: object())

    with pytest.raises(LookupError, match="Unknown capability"):
        registry.Resolve("web.crawl")

    with pytest.raises(TypeError, match="ToolAdapter"):
        registry.Resolve("network.port-scan")
