# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Public contract checks for the provider-neutral ToolAdapter SDK."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field, make_dataclass, replace

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
from fuzzy1337.model import ModelProvenance


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


@pytest.mark.parametrize("duration", [True, False, None, "0", [], 1j])
def test_ExecutionDurationRejectsValuesOutsideTheCanonicalNumericContract(duration):
    """Reject records that the canonical provenance consumer cannot deserialize."""

    with pytest.raises(ValueError, match="duration_seconds"):
        AdapterExecution(ExecutionState.SUCCEEDED, 0, duration)


@pytest.mark.parametrize("state,exit_code", [
    (ExecutionState.SUCCEEDED, 0), (ExecutionState.FAILED, 7),
    (ExecutionState.TIMED_OUT, None), (ExecutionState.CANCELLED, None),
])
@pytest.mark.parametrize("duration", [0, 1, 0.125])
def test_SerializedExecutionRoundTripsThroughCanonicalProvenance(state, exit_code, duration):
    """Preserve supported SDK outcomes and durations through the real JSON consumer."""

    execution = AdapterExecution(state, exit_code, duration)
    document = {
        "source_id": "synthetic.sdk", "run_reference": "retained:one",
        "observed_at": "2026-11-25T00:00:00Z", "scope_reference": "scope:owned",
        "target_reference": "target:owned", "provider_version": None,
        "evidence_references": [], "execution": json.loads(SerializeContract(execution)),
    }
    decoded = ModelProvenance.FromDict(document)
    assert decoded.execution == execution, "Canonical decoding changed the retained SDK outcome"
    assert json.loads(SerializeContract(decoded))["execution"] == document["execution"], (
        "Canonical provenance serialization changed the original numeric execution metadata"
    )


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


@dataclass
class MutableEvidenceShape:
    """Represent an untyped mutable record with the two attributes the old report reader used."""

    locator: str = "owned/report.json"
    role: str = "stdout"


@pytest.mark.parametrize("field,value", [
    pytest.param("request", {}, id="invocation-mutable-request"),
    pytest.param("request", None, id="invocation-null-request"),
    pytest.param("invocation", {}, id="report-mutable-invocation"),
    pytest.param("execution", {}, id="report-mutable-execution"),
    pytest.param("evidence", [MutableEvidenceShape()], id="report-duck-evidence"),
    pytest.param("evidence", None, id="report-null-evidence"),
    pytest.param("evidence", {}, id="report-object-evidence"),
    pytest.param("report", {}, id="result-mutable-report"),
    pytest.param("observations", [{}], id="result-mutable-observation"),
    pytest.param("findings", [{}], id="result-mutable-finding"),
    pytest.param("object_enrichments", [{}], id="result-mutable-object"),
    pytest.param("relation_enrichments", [{}], id="result-mutable-relation"),
    pytest.param("findings", None, id="result-null-collection"),
    pytest.param("findings", {}, id="result-object-collection"),
    pytest.param("findings", "", id="result-text-collection"),
])
def test_NestedSdkEnvelopesRefuseMutableAndUntypedMachineContracts(field, value):
    """A frozen outer DTO cannot retain caller-owned mutable children or non-array collections."""

    invocation = Invocation()
    report = AdapterReport(invocation, AdapterExecution(ExecutionState.FAILED, 7, 0), (Evidence(),))

    with pytest.raises(ValueError, match=field):
        if field == "request":
            replace(invocation, request=value)

        elif field in {"invocation", "execution", "evidence"}:
            replace(report, **{field: value})

        else:
            AdapterResult(**{"report": report, field: value})


@pytest.mark.parametrize("member,base,arguments", [
    pytest.param("request", AdapterRequest,
                 ("retained.inspect", "saved:owned", ImpactLevel.PASSIVE), id="request"),
    pytest.param("invocation", AdapterInvocation,
                 ("retained.example", Request(), ("inert-provider",), 10), id="invocation"),
    pytest.param("execution", AdapterExecution, (ExecutionState.FAILED, 7, 0.125), id="execution"),
    pytest.param("evidence", EvidenceReference,
                 ("stdout", "saved/report.json", "a" * 64, "application/json", 1), id="evidence"),
    pytest.param("report", AdapterReport,
                 (Invocation(), AdapterExecution(ExecutionState.FAILED, 7, 0), ()), id="report"),
    pytest.param("observations", NormalizedObservation, ("retained.note", "saved:owned"),
                 id="observation"),
    pytest.param("findings", NormalizedFinding, ("retained.review", "saved:owned", "Saved note"),
                 id="finding"),
    pytest.param("object_enrichments", ObjectEnrichment, ("asset", "saved:owned"), id="object"),
    pytest.param("relation_enrichments", RelationEnrichment,
                 ("contains", "saved:parent", "saved:owned"), id="relation"),
    pytest.param("result", AdapterResult,
                 (AdapterReport(Invocation(), AdapterExecution(ExecutionState.FAILED, 7, 0), ()),),
                 id="outer-result"),
])
def test_SdkWireEnvelopesRefuseFrozenSubclassMutableFields(member, base, arguments):
    """Frozen subclass fields must not retain mutable state inside SDK wire envelopes."""

    derived = make_dataclass("Derived" + base.__name__,
                             [("extra", dict, field(default_factory=dict))],
                             bases=(base,), frozen=True)
    invocation = Invocation()
    report = AdapterReport(invocation, AdapterExecution(ExecutionState.FAILED, 7, 0), ())

    with pytest.raises(ValueError, match="concrete"):
        child = derived(*arguments, extra={"values": [1]})

        if member == "request":
            replace(invocation, request=child)

        elif member in {"invocation", "execution", "evidence"}:
            replace(report, **{member: (child,) if member == "evidence" else child})

        elif member != "result":
            AdapterResult(**{"report": report, member: child if member == "report" else (child,)})


@pytest.mark.parametrize("container", [tuple, list, iter], ids=["tuple", "list", "iterator"])
def test_TypedSdkResultPreservesValidCollectionsWireAndDetachedInputOwnership(container):
    """Valid SDK calls keep their exact wire shape while input collections are detached."""

    attributes = {"kind": "owned", "nested": {"values": [1, 2]}}
    evidence = [Evidence()]
    report = AdapterReport(Invocation(), AdapterExecution(ExecutionState.FAILED, 7, 0.125),
                           container(evidence))
    observations = [NormalizedObservation("inventory.note", "saved:owned", attributes)]
    findings = [NormalizedFinding("inventory.review", "saved:owned", "Owned source note",
                                  attributes)]
    objects = [ObjectEnrichment("asset", "saved:owned", attributes)]
    relations = [RelationEnrichment("contains", "saved:parent", "saved:owned", attributes)]
    result = AdapterResult(report, container(observations), container(findings),
                           container(objects), container(relations))
    original = SerializeContract(result)
    attributes["nested"]["values"].append(3)
    evidence.clear()
    observations.clear()
    findings.clear()
    objects.clear()
    relations.clear()
    assert SerializeContract(result) == original, (
        "A valid SDK result must retain its typed children after caller input collections change"
    )
    payload = json.loads(original)
    assert payload["report"]["execution"] == {
        "state": "failed", "exit_code": 7, "duration_seconds": 0.125,
    }, "Typed nested records must preserve original terminal failure metadata"
    assert payload["observations"][0]["attributes"] == {
        "kind": "owned", "nested": {"values": [1, 2]},
    }, "Typed contract serialization must preserve the original immutable JSON attributes"
    assert set(payload) == {"report", "observations", "findings", "object_enrichments",
                            "relation_enrichments"}, "The version-one result shape must not change"
