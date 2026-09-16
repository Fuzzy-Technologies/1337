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
    ExecutionAuthorization,
    ExecutionResources,
    LazyAdapterRegistry,
    LocalExecutionRequest,
    capability_descriptors,
    invocation_digest,
)


def _adapter_descriptor() -> AdapterDescriptor:
    return AdapterDescriptor(
        adapter_id="scanner.example",
        display_name="Example Scanner",
        version="1.0",
        capabilities=("network.port-scan", "service.enumerate"),
        maximum_impact=ImpactLevel.SAFE,
        required_privileges=("network.raw-socket",),
    )


def _invocation() -> AdapterInvocation:
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


def _authorization(invocation: AdapterInvocation) -> ExecutionAuthorization:
    return ExecutionAuthorization(
        authorization_id="authorization:unit-test",
        scope_reference="scope:synthetic-lab",
        policy_reference="policy:unit-test",
        invocation_sha256=invocation_digest(invocation),
        granted_privileges=("network.raw-socket",),
    )


def test_executor_contract_version_and_capabilities_are_explicit():
    capabilities = capability_descriptors(_adapter_descriptor())

    assert EXECUTOR_CONTRACT_VERSION == 1
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
    )


def test_local_request_binds_authorization_capability_and_invocation():
    invocation = _invocation()
    request = LocalExecutionRequest(
        invocation=invocation,
        capability=capability_descriptors(_adapter_descriptor())[0],
        authorization=_authorization(invocation),
        workspace="runs/scan-1",
        environment={"LC_ALL": "C"},
        resources=ExecutionResources(max_stdout_bytes=1024, max_stderr_bytes=512),
    )

    assert request.environment == {"LC_ALL": "C"}
    assert request.workspace == "runs/scan-1"
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
def test_local_request_rejects_unsafe_workspace_and_environment(replace, message):
    invocation = _invocation()
    arguments = {
        "invocation": invocation,
        "capability": capability_descriptors(_adapter_descriptor())[0],
        "authorization": _authorization(invocation),
        "workspace": ".",
        "environment": {},
    }
    arguments.update(replace)

    with pytest.raises(ValueError, match=message):
        LocalExecutionRequest(**arguments)


def test_request_rejects_mismatched_authorization_and_missing_privileges():
    invocation = _invocation()
    capability = capability_descriptors(_adapter_descriptor())[0]
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
        invocation_sha256=invocation_digest(invocation),
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
def test_invalid_authorization_and_resource_bounds_fail_closed(factory):
    with pytest.raises(ValueError):
        factory()


def test_lazy_registry_does_not_load_adapters_until_resolution():
    descriptor = _adapter_descriptor()
    loads: list[str] = []

    class Adapter:
        @property
        def descriptor(self):
            return descriptor

        def check_health(self):
            raise AssertionError("health is not part of registry resolution")

        def prepare_invocation(self, request):
            raise AssertionError("preparation is not part of registry resolution")

        def normalize_report(self, report):
            raise AssertionError("normalization is not part of registry resolution")

    registry = LazyAdapterRegistry()
    registry.register(descriptor, lambda: loads.append("loaded") or Adapter())

    assert registry.capabilities == ("network.port-scan", "service.enumerate")
    assert loads == []
    assert registry.resolve("network.port-scan").descriptor == descriptor
    assert loads == ["loaded"]
    assert registry.resolve("service.enumerate").descriptor == descriptor
    assert loads == ["loaded"]


def test_lazy_registry_fails_closed_for_unknown_or_misdeclared_provider():
    descriptor = _adapter_descriptor()
    registry = LazyAdapterRegistry()
    registry.register(descriptor, lambda: object())

    with pytest.raises(LookupError, match="Unknown capability"):
        registry.resolve("web.crawl")
    with pytest.raises(TypeError, match="ToolAdapter"):
        registry.resolve("network.port-scan")
