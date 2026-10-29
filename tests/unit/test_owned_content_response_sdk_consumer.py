# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Mocked consumer handoffs only; no installed acquisition, stores, policies or target runtime."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from fuzzy1337 import (
    executors,
    native_response_header_workflow,
    nucleiscan,
    owned_response_workflow,
)
from tests.contract import owned_content_response_sdk_consumer as consumer


@pytest.fixture(scope="module")
def consumer_runner():
    """Initialize portable loop resources before the unchanged function unit network guard."""

    with asyncio.Runner() as runner:
        runner.get_loop()
        yield runner


def CaptureSelection(root):
    """Select clearly mocked acquisition inputs with no actual workspace or policy contents."""

    return {"workspace": str(root), "scope_id": "scope:mock", "url": (
        "http://127.0.0.1:15432/research/content"), "owner_reference": "actor:mock",
        "policy": str(root / "acquire-policy.json"), "approve_safe_content_response_capture": False,
        "retain_response": False}


@pytest.mark.parametrize("state", ["refused", "partial", "completed", "exception"])
def test_CaptureRetainsOriginalReturnAndFailureWithoutAutomaticAnalysis(
    state, tmp_path, monkeypatch, consumer_runner,
):
    """The observer returns the original result unchanged and never manufactures later analysis."""

    config = CaptureSelection(tmp_path / "workspace")
    original_result = object()
    document = {"state": state, "original_receipt_id": None,
        "model_persistence_status": "unconfirmed"}
    original_execute = executors.LocalExecutor.Execute

    def Actor():
        """Expose only the explicitly mocked current actor, never a derived attester identity."""

        return "actor:mock"

    async def Execute(_executor, request, **options):
        """Return one explicitly mocked executor object without process or worker execution."""

        return original_result

    async def Capture(root, scope, url, owner, policy, **options):
        """Observe exact independent selection forwarding, including false opt-ins."""

        assert root == tmp_path / "workspace" and scope == config["scope_id"], "No hidden selection"
        assert url == config["url"] and owner == config["owner_reference"], "Source/actor are exact"
        assert options == {"approve_safe_content_response_capture": False, "retain_response": False,
            "current_owner_provider": Actor}, "Acquisition may not invent approvals or retention"
        assert policy() == "mock-policy", "The actual SDK receives a current policy reader"
        assert await executors.LocalExecutor.Execute(None, "mock-request") is original_result, (
            "Observing the executor must not replace its original result")

        if state == "exception":
            raise RuntimeError("mock SDK failure")

        return SimpleNamespace(ToDict=lambda: document)

    def Original(request, result):
        """Detach only the known mocked original while proving its identity was preserved."""

        assert request == "mock-request" and result is original_result, "No replacement observation"

        return {"mock_original_observed": True}

    def Unexpected(*args, **kwargs):
        """Refuse any implicit interpretation in acquisition, even for a completed mock result."""

        raise AssertionError("Capture must never enroll PASSIVE analysis")

    monkeypatch.setattr(executors.LocalExecutor, "Execute", Execute)
    monkeypatch.setattr(owned_response_workflow, "RunOwnedContentResponseCapture", Capture)
    monkeypatch.setattr(native_response_header_workflow, "ApplyOwnedResponseHeaderCheck",
        Unexpected)
    monkeypatch.setattr(nucleiscan, "ReadNucleiPolicy", lambda _path: "mock-policy")
    monkeypatch.setattr(consumer, "OriginalExecution", Original)
    operation = consumer.Capture(config, tmp_path / "observations", enabled=True,
        current_owner_provider=Actor)

    if state == "exception":
        with pytest.raises(RuntimeError):
            consumer_runner.run(operation)

    else:
        assert consumer_runner.run(operation) is document, "Actual summary values remain unchanged"

    observed = json.loads((tmp_path / "observations/capture.json").read_bytes())
    assert observed["executions"] == [{"mock_original_observed": True}], "Original fact is retained"
    assert observed["exception_type"] == ("RuntimeError" if state == "exception" else None), (
        "Unexpected failure remains observable and is reraised")
    assert executors.LocalExecutor.Execute is Execute, "The original observer owner is restored"
    assert original_execute is not Execute, "This test substitutes the executor without running it"


@pytest.mark.parametrize("state", ["denied", "partial", "completed"])
def test_AnalysisUsesSeparatePassiveOptInExplicitCasAndContentV2(state, tmp_path, monkeypatch):
    """Analysis forwards explicit current authority and CAS, without inheriting SAFE approval."""

    config = CaptureSelection(tmp_path / "workspace")
    del config["approve_safe_content_response_capture"], config["retain_response"]
    config.update(original_receipt_id="mock-original-receipt", analysis_reference="analysis:mock",
        expected_model_revision=7, expected_workspace_revision=11,
        approve_passive_header_check=False)
    document = {"state": state, "profile": "owned-response-header-absence.v2",
        "source_profile": consumer.CONTENT_PROFILE, "model_commit": "unconfirmed"}

    def Analyze(root, scope, receipt, target, owner, policy, **options):
        """Observe only mocked actual SDK handoff, never create model or evidence stores."""

        assert receipt == config["original_receipt_id"] and target.value == config["url"], (
            "Only the explicitly selected original source may be interpreted")
        assert options["source_profile"] == consumer.CONTENT_PROFILE and options[
            "approve_passive_header_check"] is False, "The family and PASSIVE opt-in are explicit"
        assert (options["expected_model_revision"], options["expected_workspace_revision"]) == (
            7, 11), "Actual selected CAS bases must not be refreshed or retried by the consumer"

        return SimpleNamespace(ToDict=lambda: document)

    monkeypatch.setattr(native_response_header_workflow, "ApplyOwnedResponseHeaderCheck", Analyze)
    assert consumer.Analyze(config, tmp_path / "observations", enabled=True) is document, (
        "Partial/unconfirmed actual states cannot become successful acknowledgements")


@pytest.mark.parametrize("kind", ["source", "header", "old-header"])
def test_ReplaySelectsOnlyExplicitContentSourceOrV2HistoricalOwner(kind, tmp_path, monkeypatch):
    """Historical dispatch never supplies a current policy/runtime or falls back to v1."""

    calls = []
    document = {"state": "verified", "profile": "owned-response-header-absence.v2",
        "source_profile": consumer.CONTENT_PROFILE}

    if kind == "old-header":
        document = {"state": "verified", "profile": "owned-response-header-absence.v1"}

    def Source(root, reference):
        """Observe only the explicitly selected original content replay owner."""

        calls.append(("source", root, reference))

        return SimpleNamespace(ToDict=lambda: document)

    def Header(root, reference):
        """Observe only the historical assessment owner with its actual profile unchanged."""

        calls.append(("header", root, reference))

        return SimpleNamespace(ToDict=lambda: document)

    monkeypatch.setattr(owned_response_workflow, "ReplayOwnedContentResponse", Source)
    monkeypatch.setattr(native_response_header_workflow, "ReplayOwnedResponseHeaderCheck", Header)
    config = {"workspace": str(tmp_path / "relocated"), "kind": "source" if kind == (
        "source") else "header", "reference": "mock-original-reference"}

    if kind == "old-header":
        with pytest.raises((AssertionError, KeyError)):
            consumer.Replay(config, tmp_path / "observations", enabled=True)

    else:
        assert consumer.Replay(config, tmp_path / "observations", enabled=True) is document, (
            "Historical SDK facts remain unchanged after explicit relocation selection")

    assert len(calls) == 1 and calls[0][0] == config["kind"], "Cross-family fallback is forbidden"


@pytest.mark.parametrize("enabled", [False, None, 1, "yes"])
def test_ConsumerDefaultDenialPrecedesConfigWorkspaceAndPolicyReads(enabled, consumer_runner):
    """Truthiness cannot enroll acquisition, interpretation or historical consumer operations."""

    with pytest.raises(PermissionError):
        consumer_runner.run(consumer.Capture(None, None, enabled=enabled))

    for callback in (consumer.Analyze, consumer.Replay):
        with pytest.raises(PermissionError):
            callback(None, None, enabled=enabled)


@pytest.mark.parametrize("operation", ["capture", "analyze", "replay-source-to-header"])
@pytest.mark.parametrize("first_failure", [False, True])
def test_ObservationOwnerReuseRefusesBeforeSdkAndPreservesOriginalFailure(
    operation, first_failure, tmp_path, monkeypatch, consumer_runner,
):
    """An already owned attempt cannot overwrite either a successful or failed original record."""

    calls = []
    document = {"state": "partial", "profile": "owned-response-header-absence.v2",
        "source_profile": consumer.CONTENT_PROFILE}

    def Summary(*args, **kwargs):
        """Record only a mocked SDK handoff, proving whether a forbidden second call occurred."""

        calls.append("sdk")

        if first_failure:
            raise RuntimeError("original mocked SDK failure")

        return SimpleNamespace(ToDict=lambda: document)

    async def Capture(*args, **kwargs):
        """Delegate only to the mocked handoff counter, never an acquisition runtime."""

        return Summary(*args, **kwargs)

    monkeypatch.setattr(owned_response_workflow, "RunOwnedContentResponseCapture", Capture)
    monkeypatch.setattr(native_response_header_workflow, "ApplyOwnedResponseHeaderCheck", Summary)
    monkeypatch.setattr(owned_response_workflow, "ReplayOwnedContentResponse", Summary)
    monkeypatch.setattr(native_response_header_workflow, "ReplayOwnedResponseHeaderCheck", Summary)
    config = CaptureSelection(tmp_path / "workspace")
    observation_owner = tmp_path / "one-attempt"

    if operation == "analyze":
        del config["approve_safe_content_response_capture"], config["retain_response"]
        config.update(original_receipt_id="mock-original", analysis_reference="analysis:mock",
            expected_model_revision=1, expected_workspace_revision=2,
            approve_passive_header_check=False)

    elif operation == "replay-source-to-header":
        config = {"workspace": str(tmp_path / "workspace"), "kind": "source",
            "reference": "mock-original"}

    def Attempt():
        """Invoke exactly one separately selected consumer operation with controlled SDK doubles."""

        if operation == "capture":
            return consumer_runner.run(consumer.Capture(config, observation_owner, enabled=True))

        callback = consumer.Analyze if operation == "analyze" else consumer.Replay

        return callback(config, observation_owner, enabled=True)

    if first_failure:
        with pytest.raises(RuntimeError):
            Attempt()

    else:
        Attempt()

    name = "replay" if operation == "replay-source-to-header" else operation
    original = (observation_owner / (name + ".json")).read_bytes()

    if operation == "replay-source-to-header":
        config["kind"] = "header"

    with pytest.raises(FileExistsError):
        Attempt()

    assert calls == ["sdk"], "A reused observation owner must refuse before any second SDK effect"
    assert (observation_owner / (name + ".json")).read_bytes() == original, (
        "The first original outcome and failure record must remain byte-identical")


def test_ObservationFinalWriteIsExclusiveAndReservationIsImmutable(tmp_path):
    """Neither a second final write nor a later reservation can erase an earlier original."""

    owner = tmp_path / "one-attempt"
    consumer.ReserveObservation(owner, "capture")
    reservation = (owner / "attempt.json").read_bytes()
    consumer.Observation(owner, "capture", {"mock_original_failure": True})
    original = (owner / "capture.json").read_bytes()

    with pytest.raises(FileExistsError):
        consumer.Observation(owner, "capture", {"replacement": True})

    with pytest.raises(FileExistsError):
        consumer.ReserveObservation(owner, "replay")

    assert (owner / "attempt.json").read_bytes() == reservation, "Attempt ownership remains intact"
    assert (owner / "capture.json").read_bytes() == original, "Original final facts remain intact"
