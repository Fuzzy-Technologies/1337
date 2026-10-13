# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual governed owned configuration executions and fresh artifact acceptance boundaries."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import stat
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from artifact_helpers import AT
from configuration_helpers import CASES, FAMILY, ORACLE, OwnedConfiguration

from fuzzy1337.adapters import ExecutionState, SerializeContract
from fuzzy1337.artifact_policy import (
    ArtifactDenialReason,
    ArtifactDeniedError,
    ArtifactPolicyEngine,
    GovernedArtifactExecutor,
    PrepareArtifact,
    VerifyArtifactReplay,
)
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.executors import ExecutionEventKind, ExecutionResources, ExecutionTermination
from fuzzy1337.policy import Digest
from fuzzy1337.scope import AuthorizationState, LocalScopeStore


@pytest.mark.parametrize("case_id", list(CASES), ids=list(CASES))
def test_RealGovernedConfigurationMatchesIndependentOracleAndDurableRaw(tmp_path, case_id):
    """Execute the frozen worker through actual SDK grants and preserve exact raw provenance."""

    workspace, stage, context = OwnedConfiguration(tmp_path, case_id)
    prepared = PrepareArtifact(stage, workspace)
    grant = ArtifactPolicyEngine().Authorize(prepared, stage, context, at=AT)
    executor = GovernedArtifactExecutor(workspace, clock=lambda: AT)
    outcome = asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))
    executor.ValidateAcceptanceFresh(outcome, prepared, stage, lambda: context)
    result = outcome.raw_result
    assert result.execution.state is ExecutionState.SUCCEEDED and result.execution.exit_code == 0, (
        "The actual governed configuration worker must terminate successfully"
    )
    assert result.termination is ExecutionTermination.PROCESS_EXIT and result.stderr == b"", (
        "A timeout/capture/cancellation/failure must never become an accepted configuration scan"
    )
    assert outcome.acceptance.refusal is None and outcome.grant == grant, (
        "Fresh governed authority must accept only this original successful execution"
    )
    wire = json.loads(result.stdout)
    expected = [dict(item, outcome="failed") for item in CASES[case_id]["expected_findings"]]
    assert wire["findings"] == expected and wire["fixture_id"] == FAMILY, (
        "Actual worker detections and coordinates must match the unchanged independent oracle"
    )
    selected = stage.input.manifest.files[0]
    document_count = None if case_id.startswith("dockerfile.") else (
        2 if case_id == "kubernetes.second-document" else 1
    )
    assert wire["file_outcomes"] == [{
        "logical_path": selected.name, "sha256": selected.sha256, "size_bytes": selected.size_bytes,
        "configuration_type": "dockerfile" if case_id.startswith("dockerfile.") else "kubernetes",
        "document_count": document_count, "outcome": "processed",
    }], "A processed outcome must retain the actual selected source byte identity"
    assert wire["provider_id"] == "synthetic.trivy" and (
        wire["profile_id"] == stage.input.manifest.profile.value
        and wire["scan_completeness"] == "not-assessed"
        and wire["provider_version"] == "0.75.0-synthetic"
    ), "Owned configuration fixtures cannot be native compatibility or a clean-scan claim"
    assert ORACLE["raw_only_marker"].encode() not in result.stdout and (
        b"owned.invalid" not in result.stdout and str(workspace).encode() not in result.stdout
    ), "Private source comments, resource hints and physical paths must remain outside result wire"
    provenance = EvidenceProvenance(
        context.scope.workspace_id, context.scope.Reference(), "synthetic.trivy", "1",
        "0.75.0-synthetic", AT.isoformat(), (AT + timedelta(seconds=1)).isoformat(),
        grant.plan.invocation_sha256, result.execution,
    )
    store = LocalEvidenceStore(workspace / "evidence")
    records = tuple(store.Put(payload, role, media_type, provenance)
        for payload, role, media_type in (
            (result.stdout, "stdout", "application/json"),
            (result.stderr, "stderr", "text/plain"),
            (SerializeContract(outcome.Metadata()).encode(), "artifact-scan-receipt",
             "application/json"),
        ))
    stdout, stderr, metadata = (store.Read(record.reference) for record in records)
    assert stdout == result.stdout and stderr == result.stderr, "Durable raw stream bytes changed"
    assert VerifyArtifactReplay(json.loads(metadata), stdout, stderr) == outcome.acceptance, (
        "Historical configuration replay must retain exact original per-run receipt facts"
    )
    assert records[0].reference.sha256 == hashlib.sha256(result.stdout).hexdigest(), (
        "Original raw evidence digest must identify actual executor output"
    )

    with pytest.raises(ArtifactDeniedError):
        asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))


@pytest.mark.parametrize("change", ["source", "producer", "policy", "extra-input", "extra-material",
                                    "owner", "policy-revoke", "scope-revoke", "excluded"])
def test_ConfigurationDriftDeniesBeforeActualProcessLaunch(tmp_path, monkeypatch, change):
    """Changed selected files, family material or current authority cannot use a stale approval."""

    from fuzzy1337.executors import LocalExecutor

    workspace, stage, context = OwnedConfiguration(tmp_path)
    prepared = PrepareArtifact(stage, workspace)
    grant = ArtifactPolicyEngine().Authorize(prepared, stage, context, at=AT)

    if change in {"source", "producer", "policy"}:
        file_path = {"source": stage.input.directory / "Dockerfile",
                     "producer": stage.scanner.directory / "producer.py",
                     "policy": stage.material.directory / "policy.json"}[change]
        file_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        file_path.write_bytes(file_path.read_bytes() + b"\n")

    elif change.startswith("extra-"):
        directory = stage.input.directory if change == "extra-input" else stage.material.directory
        (directory / "trivy.yaml").write_bytes(b"owned-control-file")

    elif change == "owner":
        context = replace(context, owner_ref="owner:changed")

    elif change == "policy-revoke":
        context = replace(context, policy=replace(context.policy, permissions=()))

    else:
        if change == "excluded":
            scope = replace(context.scope, exclusions=context.scope.targets)

        else:
            scope = replace(context.scope, authorization=replace(
                context.scope.authorization, state=AuthorizationState.REVOKED
            ))

        context = replace(context, scope=LocalScopeStore(workspace).Save(scope))

    async def Forbidden(*_args, **_kwargs):
        """Trip an attempted executor call after the configuration approval drifted."""

        raise AssertionError("Rejected configuration must not reach the process executor")

    monkeypatch.setattr(LocalExecutor, "Execute", Forbidden)

    with pytest.raises(ArtifactDeniedError):
        asyncio.run(GovernedArtifactExecutor(workspace, clock=lambda: AT).Execute(
            prepared, stage, grant, lambda: context,
        ))


@pytest.mark.parametrize("change", ["revoked", "expired", "owner", "policy"])
def test_ConfigurationPostRunAuthorityRefusalRetainsActualRaw(tmp_path, change):
    """Successful raw output survives post-run refusal without receiving renewed authority."""

    workspace, stage, context = OwnedConfiguration(tmp_path)
    prepared = PrepareArtifact(stage, workspace)
    grant = ArtifactPolicyEngine().Authorize(prepared, stage, context, at=AT)
    finished = False

    def OnEvent(event):
        """Change authority only after the real executor's completed event."""

        nonlocal finished

        if event.kind is ExecutionEventKind.COMPLETED:
            finished = True

    def Context():
        """Read the original context before launch and the changed authority after completion."""

        if not finished or change == "expired":
            return context

        if change == "owner":
            return replace(context, owner_ref="owner:changed")

        if change == "policy":
            return replace(context, policy=replace(context.policy, permissions=()))

        current_scope = LocalScopeStore(workspace).Open(context.scope.scope_id)

        if current_scope.authorization.state is AuthorizationState.REVOKED:
            return replace(context, scope=current_scope)

        scope = LocalScopeStore(workspace).Save(replace(
            current_scope, authorization=replace(
                context.scope.authorization, state=AuthorizationState.REVOKED,
            ),
        ))

        return replace(context, scope=scope)

    def Clock():
        """Advance only the post-run decision time for the explicit expiry scenario."""

        return AT + timedelta(hours=1) if finished and change == "expired" else AT

    executor = GovernedArtifactExecutor(workspace, clock=Clock)
    outcome = asyncio.run(executor.Execute(prepared, stage, grant, Context, on_event=OnEvent))
    assert outcome.raw_result.execution.state is ExecutionState.SUCCEEDED, (
        "Post-run authority changes must preserve the actual successful child exit"
    )
    assert json.loads(outcome.raw_result.stdout)["fixture_id"] == FAMILY and (
        outcome.acceptance.refusal is not None and outcome.grant == grant
    ), "Raw successful fixture output survives refusal with its original grant provenance"
    assert VerifyArtifactReplay(outcome.Metadata(), outcome.raw_result.stdout,
                                outcome.raw_result.stderr) == outcome.acceptance, (
        "Historical refused raw evidence remains replayable without creating new authority"
    )

    with pytest.raises(ArtifactDeniedError):
        executor.ValidateAcceptance(outcome, prepared, stage, Context(), at=Clock())


def test_ActualConfigurationCaptureLimitKeepsPartialOutputAndRefusesAcceptance(tmp_path):
    """A tighter actual capture limit cannot turn truncated configuration JSON into acceptance."""

    workspace, stage, context = OwnedConfiguration(tmp_path)
    prepared = PrepareArtifact(stage, workspace, resources=ExecutionResources(
        max_stdout_bytes=16, max_stderr_bytes=16,
    ))
    grant = ArtifactPolicyEngine().Authorize(prepared, stage, context, at=AT)
    executor = GovernedArtifactExecutor(workspace, clock=lambda: AT)
    outcome = asyncio.run(executor.Execute(prepared, stage, grant, lambda: context))
    assert outcome.raw_result.termination is ExecutionTermination.OUTPUT_LIMIT and (
        len(outcome.raw_result.stdout) == 16
        and outcome.acceptance.refusal is ArtifactDenialReason.EXECUTION_FAILED
    ), "Actual truncated stdout must remain raw evidence with output-limit refusal"

    with pytest.raises(ArtifactDeniedError):
        executor.ValidateAcceptance(outcome, prepared, stage, context, at=AT)


def test_ConfigurationHistoricalReplayCannotRefreshGrantOrReadCurrentHost(tmp_path, monkeypatch):
    """Replay checks saved exact source family facts without granting or launching any operation."""

    workspace, stage, context = OwnedConfiguration(tmp_path)
    prepared = PrepareArtifact(stage, workspace)
    grant = ArtifactPolicyEngine().Authorize(prepared, stage, context, at=AT)
    outcome = asyncio.run(GovernedArtifactExecutor(workspace, clock=lambda: AT).Execute(
        prepared, stage, grant, lambda: context,
    ))
    metadata = outcome.Metadata()
    before = copy.deepcopy(metadata)

    def Forbidden(*_args, **_kwargs):
        """Trip any accidental current filesystem read, grant issuance or process entry."""

        raise AssertionError("Read-only configuration replay touched current authority")

    monkeypatch.setattr(ArtifactPolicyEngine, "Authorize", Forbidden)
    monkeypatch.setattr(Path, "open", Forbidden)
    monkeypatch.setattr(GovernedArtifactExecutor, "Execute", Forbidden)
    assert VerifyArtifactReplay(metadata, outcome.raw_result.stdout,
                                outcome.raw_result.stderr) == outcome.acceptance, (
        "Original config replay must use saved provenance and actual raw bytes only"
    )
    assert metadata == before, "Read-only config replay mutated original saved facts"
    metadata["grant"]["plan"]["producer_family"] = "owned-artifact-lifecycle-v1"
    plan = metadata["grant"]["plan"]
    plan["intent_sha256"] = Digest({key: value for key, value in plan.items()
                                     if key != "intent_sha256"})

    with pytest.raises(ValueError):
        VerifyArtifactReplay(metadata, outcome.raw_result.stdout, outcome.raw_result.stderr)


def test_ConfigurationRejectsActualImageProofAndVersionBeforeMaterialIo(tmp_path, monkeypatch):
    """An actually accepted image VERSION proof cannot authorize the configuration source family."""

    from artifact_helpers import OwnedImageArtifact

    from fuzzy1337.artifact_inputs import ArtifactOperation, ArtifactStage
    from fuzzy1337.artifact_policy import ArtifactVersionProof

    image_root = tmp_path / "image"
    image_root.mkdir()
    image_workspace, image_stage, image_prepared, image_context, image_grant = OwnedImageArtifact(
        image_root,
    )
    image_outcome = asyncio.run(GovernedArtifactExecutor(image_workspace, clock=lambda: AT).Execute(
        image_prepared, image_stage, image_grant, lambda: image_context,
    ))
    proof = ArtifactVersionProof(image_outcome, image_prepared, image_stage)
    config_root = tmp_path / "configuration"
    config_root.mkdir()
    workspace, stage, _ = OwnedConfiguration(config_root)

    def Forbidden(*_args, **_kwargs):
        """Trip material verification after a forbidden operation or extraneous proof."""

        raise AssertionError("Config VERSION/proof denial must precede material I/O")

    monkeypatch.setattr(ArtifactStage, "Verify", Forbidden)

    with pytest.raises(ValueError):
        PrepareArtifact(stage, workspace, version_proof=proof)

    with pytest.raises(ArtifactDeniedError) as error:
        PrepareArtifact(stage, workspace, operation=ArtifactOperation.VERSION)

    assert error.value.reason is ArtifactDenialReason.UNTRUSTED_PRODUCER, (
        "The configuration worker has no VERSION operation regardless of accepted image proof"
    )


@pytest.mark.parametrize("change", ["producer-family", "input-bytes", "policy-name", "policy-size",
                                    "stdout-bound", "stderr-bound"])
def test_RehashedConfigurationReplayStillEnforcesOriginalFamilyAndBounds(tmp_path, change):
    """Rehashed facts cannot bypass the original source/material/stream dispatch."""

    from fuzzy1337.artifact_inputs import ArtifactManifest

    workspace, stage, context = OwnedConfiguration(tmp_path)
    prepared = PrepareArtifact(stage, workspace)
    grant = ArtifactPolicyEngine().Authorize(prepared, stage, context, at=AT)
    outcome = asyncio.run(GovernedArtifactExecutor(workspace, clock=lambda: AT).Execute(
        prepared, stage, grant, lambda: context,
    ))
    metadata = copy.deepcopy(outcome.Metadata())
    plan = metadata["grant"]["plan"]
    stdout, stderr = outcome.raw_result.stdout, outcome.raw_result.stderr

    if change == "producer-family":
        metadata["manifests"][1]["files"][1]["sha256"] = (
            "afb5b935f151fb9780feee28eda0fbf13ddc6d721e6f7cc55e753aa32e4cfa53"
        )

    elif change == "input-bytes":
        metadata["manifests"][0]["files"][0]["sha256"] = "0" * 64

    elif change == "policy-name":
        metadata["manifests"][2]["files"][0]["name"] = "trivy.yaml"

    elif change == "policy-size":
        metadata["manifests"][2]["files"][0]["size_bytes"] = 1025

    elif change == "stdout-bound":
        stdout = b"a" * 16385

    else:
        stderr = b"a" * 16385

    input_manifest, scanner_manifest, material_manifest = (
        ArtifactManifest.FromDict(item) for item in metadata["manifests"]
    )
    plan["input_manifest_sha256"] = input_manifest.Digest()
    plan["scanner_manifest_sha256"] = scanner_manifest.Digest()
    plan["material_manifest_sha256"] = material_manifest.Digest()
    plan["target_reference"] = input_manifest.Target().Reference()
    plan["intent_sha256"] = Digest({key: value for key, value in plan.items()
                                     if key != "intent_sha256"})
    authorization_id = "artifact-authorization:" + Digest((
        plan, metadata["grant"]["issued_at"], metadata["grant"]["valid_until"],
    ))
    metadata["grant"]["authorization"]["authorization_id"] = authorization_id
    metadata["acceptance"]["grant_id"] = authorization_id
    facts = metadata["raw_facts"]
    facts["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
    facts["stdout_bytes"] = len(stdout)
    facts["stderr_sha256"] = hashlib.sha256(stderr).hexdigest()
    facts["stderr_bytes"] = len(stderr)
    metadata["acceptance"]["raw_sha256"] = Digest(facts)

    with pytest.raises(ValueError) as error:
        VerifyArtifactReplay(metadata, stdout, stderr)

    assert "original" in str(error.value), (
        "Rehashed config mutations must reach the explicit original-family/material dispatch"
    )
