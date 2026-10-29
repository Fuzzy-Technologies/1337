# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Native configuration composition with explicit doubles, never genuine scanner acceptance."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import stat
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from fuzzy1337 import native_configuration_evidence as replay_module
from fuzzy1337 import native_configuration_material_worker as worker
from fuzzy1337 import native_configuration_policy as policy_module
from fuzzy1337.adapters import AdapterExecution, ExecutionState, ImpactLevel
from fuzzy1337.artifact_inputs import (
    ArtifactFile,
    ArtifactManifest,
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactRole,
    PhysicalIdentity,
)
from fuzzy1337.artifact_policy import (
    ArtifactDeniedError,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
)
from fuzzy1337.executors import (
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    LocalExecutionResult,
    LocalExecutor,
)
from fuzzy1337.findings import Findings
from fuzzy1337.jobs import JobEventKind, JobFailureCode, JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_configuration import NativeConfigurationSelection
from fuzzy1337.native_configuration_evidence import VerifyNativeConfigurationReplay
from fuzzy1337.native_configuration_material import (
    NativeConfigurationMaterialObserver,
    NativeConfigurationMaterialProof,
)
from fuzzy1337.native_configuration_policy import (
    AuthorizeNativeConfigurationOperation,
    ClaimNativeConfigurationExecution,
    NativeConfigurationExecutionClaim,
    PrepareNativeConfigurationOperation,
    ValidateNativeConfigurationOperation,
)
from fuzzy1337.native_configuration_workflow import (
    PlanNativeConfigurationScan,
    ScanNativeConfiguration,
)
from fuzzy1337.native_image_observation import NativeImageObservationBudget
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scope import AuthorizationState, LocalScopeStore, ScopeAuthorization, ScopeSnapshot
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration


@pytest.fixture(scope="module")
def configuration_runner():
    """Create loop resources before the unchanged isolated unit network guard."""

    with asyncio.Runner() as runner:
        runner.get_loop()
        yield runner


@pytest.fixture
def controlled_runtime(tmp_path, monkeypatch, request):
    """Supply tiny explicitly doubled material/provider facts without native execution."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Configuration unit owner"),
                                     "native-unit")
    root.chmod(0o700)
    LocalModelStore(root).Create()
    source = tmp_path / "source"
    source.write_bytes(b"FROM scratch\nUSER root\n")
    executable = tmp_path / "inert-provider"
    executable.write_bytes(b"Inert bytes; this unit file must never execute\n")
    pin = hashlib.sha256(executable.read_bytes()).hexdigest()
    monkeypatch.setattr(worker, "NATIVE_CONFIGURATION_EXECUTABLE_SHA256", pin)
    monkeypatch.setattr(replay_module, "NATIVE_CONFIGURATION_EXECUTABLE_SHA256", pin)
    monkeypatch.setattr(worker, "RequirePlatform", lambda: None)
    import fuzzy1337.native_configuration_material as material_module

    monkeypatch.setattr(material_module, "RequirePlatform", lambda: None)
    stages = []

    if os.name == "nt" or getattr(request, "param", False):
        selected_os = SimpleNamespace(**vars(os))
        selected_os.O_NOFOLLOW = 0
        selected_os.O_DIRECTORY = 0
        selected_os.fchmod = lambda descriptor, mode: None
        monkeypatch.setattr(policy_module, "os", selected_os)
        monkeypatch.setattr(policy_module, "stat", SimpleNamespace(S_IMODE=lambda mode:
            0o700 if stat.S_ISDIR(mode) else 0o600))
        monkeypatch.setattr(policy_module, "SyncDirectory", lambda path: None)
        original_unlink = Path.unlink

        def Unlink(path, missing_ok=False):
            """Model POSIX unlink only after the real owner reaches exact known snapshot bytes."""

            known = {snapshot.directory / name: identity for stage in stages for snapshot in
                (stage.input, stage.scanner, stage.material)
                for name, identity in snapshot.identities}

            if path in known:
                assert PhysicalIdentity(worker.ArtifactPathInfo(path)) == known[path], (
                    "Portable unit unlink may remove only unchanged original staged bytes"
                )
                path.chmod(0o600)

            return original_unlink(path, missing_ok=missing_ok)

        monkeypatch.setattr(Path, "unlink", Unlink)

    selection = NativeConfigurationSelection(ArtifactProfile.DOCKERFILE, "Dockerfile", source,
        executable, ArtifactReadConsent("owner:unit", "read:unit"))
    manifest = ArtifactManifest(selection.profile, ArtifactRole.INPUT,
        (ArtifactFile("Dockerfile", len(source.read_bytes()),
                      hashlib.sha256(source.read_bytes()).hexdigest()),))
    target = manifest.Target()
    now = datetime.now(UTC)
    scope = LocalScopeStore(root).Create(ScopeSnapshot("native-scope", "native-unit",
        targets=(target,), allow=(target,), authorization=ScopeAuthorization(
            AuthorizationState.GRANTED, "attester:unit", "consent:unit",
            (now - timedelta(minutes=1)).isoformat(), (now + timedelta(hours=1)).isoformat())))
    policy = ImpactPolicy("native-configuration-unit", permissions=(CapabilityPermission(
        selection.Capability(), "native.trivy", ImpactLevel.SAFE),))
    settings = {"termination": ExecutionTermination.PROCESS_EXIT, "bad_wire": False,
                "bad_version": False, "calls": [], "cancel": False, "uncertain": False}

    async def Create(self, budget, *, operation_reference, cancellation=None):
        """Issue a declared observer proof after real tiny stage mechanics, without child proof."""

        stage_root = self.workspace_root / ("native-configuration-stage-" + uuid4().hex)
        stage = worker.CreateStage(stage_root, self.selection)
        stages.append(stage)
        self._stage = stage
        self._stage_root = stage_root
        scratch = (stage.root / "scratch").stat()
        self._scratch_identity = scratch.st_dev, scratch.st_ino

        return await Renew(self, budget, operation_reference=operation_reference)

    async def Renew(self, budget, *, operation_reference):
        """Register an explicit proof double from unchanged owned physical metadata."""

        workspace = self.workspace_root.stat()
        proof = NativeConfigurationMaterialProof(self._stage, uuid4().hex, operation_reference,
            self.workspace_id, self.owner_reference, self._selection_sha256, "a" * 64,
            (1, 2, 3, 4, 5), (1, 2), (workspace.st_dev, workspace.st_ino),
            self._scratch_identity, 0.0)
        self._proofs.clear()
        self._proofs[proof.observation_id] = proof

        return proof

    async def Verify(self, proof, budget, *, operation_reference, cancellation=None):
        """Keep real staged-byte verification while explicitly replacing subprocess observation."""

        self.CheckCurrent(proof, operation_reference=operation_reference)
        worker.VerifyStage(proof.stage, self.selection)

        return await Renew(self, budget, operation_reference=operation_reference)

    async def Execute(self, request, *, on_event=None, cancellation=None, pre_launch=None,
                      own_descendants=False):
        """Return declared provider rows through the actual collector callback path."""

        assert own_descendants, "Native configuration must explicitly own Linux descendants"
        pre_launch(request)
        pre_launch(request)
        operation = request.invocation.request.parameters["operation"]
        settings["calls"].append(operation)
        stdout = b'{"Version":"wrong"}' if settings["bad_version"] else b'{"Version":"0.75.0"}'
        stderr = b""

        if operation == "scan":
            report = {"SchemaVersion": 2, "Results": [{"Target": "Dockerfile", "Class": "config",
                "Type": "dockerfile", "Misconfigurations": [{"ID": "DS-0002", "Status": "FAIL",
                    "Severity": "HIGH", "Title": "Root user", "Resolution": "Select a user",
                    "CauseMetadata": {"StartLine": 2, "EndLine": 2}}]}]}
            stdout = b"{}" if settings["bad_wire"] else json.dumps(report).encode()
            stderr = b"Embedded libraries are loaded count=4\nEmbedded checks are loaded count=20\n"

        termination = settings["termination"]
        succeeded = termination is ExecutionTermination.PROCESS_EXIT
        state = ExecutionState.SUCCEEDED if succeeded else ExecutionState.TIMED_OUT
        events = [ExecutionEvent(0, ExecutionEventKind.STARTED),
                  ExecutionEvent(1, ExecutionEventKind.STDOUT, stdout)]

        if stderr:
            events.append(ExecutionEvent(len(events), ExecutionEventKind.STDERR, stderr))

        events.append(ExecutionEvent(len(events), ExecutionEventKind.COMPLETED,
                                     termination=termination))

        for event in events:
            on_event(event)

        if settings["uncertain"]:
            raise RuntimeError("Explicit unit terminal cleanup uncertainty")

        if settings["cancel"]:
            cancellation.set()

        return LocalExecutionResult(AdapterExecution(state, 0 if succeeded else None, 0.01),
                                    termination, stdout, stderr, tuple(events))

    monkeypatch.setattr(NativeConfigurationMaterialObserver, "Create", Create)
    monkeypatch.setattr(NativeConfigurationMaterialObserver, "Verify", Verify)
    monkeypatch.setattr(LocalExecutor, "Execute", Execute)

    return root, selection, ArtifactPolicyContext(scope, policy, "owner:unit"), settings


def Run(runner, runtime, **options):
    """Exercise actual public SDK job composition using explicit process/proof doubles."""

    root, selection, context, settings = runtime
    summary = runner.run(ScanNativeConfiguration(root, "native-scope", "owner:unit", selection,
        lambda: context.policy, approve_safe_configuration=True, **options))

    return summary


def test_ActualConsumersSaveNativeFindingsAndReplayAfterRelocation(
    controlled_runtime, configuration_runner, tmp_path
):
    """Declared native rows compose through original grants, replay, save and export."""

    root, selection, context, settings = controlled_runtime
    output = tmp_path / "report.json"
    events = []
    summary = Run(configuration_runner, controlled_runtime, report_format="json",
                  report_output=output, on_event=events.append)
    VerifyNativeConfigurationReplay(summary.retained_records, root)
    assert summary.snapshot.state is JobState.COMPLETED, summary.ToDict()
    assert summary.ExitCode() == 0 and summary.model_revision == 1, (
        "Only accepted original pairs may produce a successful saved model"
    )
    assert settings["calls"] == ["version", "scan"] and len(summary.retained_records) == 7, (
        "The product must retain the original pair and seven exact acquisitions"
    )
    saved = LocalModelStore(root).Open()
    assert [item.check_id for item in Findings(saved)] == ["configuration.native.ds-0002"], (
        "Canonical Findings must map original native check IDs to lowercase machine identifiers"
    )
    assert output.is_file() and summary.report.output_published, "Saved report must export"
    assert len([item for item in events if item.kind is JobEventKind.MODEL_DELTA]) == 1, (
        "Only the acknowledged saved model may publish a delta"
    )
    relocated = tmp_path / "relocated"
    shutil.copytree(root, relocated)
    source = selection.source
    source.unlink()
    facts = VerifyNativeConfigurationReplay(summary.retained_records, relocated)
    assert facts.checks[0].check_id == "DS-0002", (
        "Historical replay must work without the original selected source or stage"
    )


@pytest.mark.parametrize("failure,code,calls", [
    ("bad_version", JobFailureCode.AUTHORIZATION, ["version"]),
    ("bad_wire", JobFailureCode.NORMALIZATION, ["version", "scan"]),
    ("timeout", JobFailureCode.TIMEOUT, ["version"]),
])
def test_ProviderAndInterpretationFailuresRetainEvidenceWithoutSaving(
    controlled_runtime, configuration_runner, failure, code, calls
):
    """A successful process alone, bad VERSION or timeout cannot publish canonical success."""

    root, selection, context, settings = controlled_runtime

    if failure == "timeout":
        settings["termination"] = ExecutionTermination.TIMEOUT

    else:
        settings[failure] = True

    summary = Run(configuration_runner, controlled_runtime)
    assert summary.snapshot.state is JobState.FAILED and summary.snapshot.failure.code is code, (
        "The job must retain its actual provider/normalization failure classification"
    )
    assert summary.model_revision == 0 and not Findings(LocalModelStore(root).Open()), (
        "Failure must not save native Findings"
    )
    assert settings["calls"] == calls and summary.retained_records, (
        "Available original acquisitions must survive every failed operation"
    )


def test_PreviewDoesNotRunProviderOrRegisterTarget(controlled_runtime, configuration_runner):
    """Read-authorized preview returns a manifest target without issuing execution authority."""

    root, selection, context, settings = controlled_runtime
    preview = configuration_runner.run(PlanNativeConfigurationScan(root, "owner:unit", selection))
    assert preview.Target == context.scope.targets[0] and not settings["calls"], (
        "Material preview must remain descriptive without launching VERSION"
    )
    assert preview.ToDict()["execution_authorized"] is False, "Planning cannot grant execution"
    scoped = configuration_runner.run(PlanNativeConfigurationScan(root, "owner:unit", selection,
        scope_id="native-scope", policy_provider=lambda: context.policy))
    assert scoped.authority_plan.scope_reference == context.scope.Reference() and (
        not settings["calls"]
    ), (
        "The canonical facade may describe VERSION authority without launching a provider"
    )


def test_CopiedForeignExpiredAndRepeatedAuthorityIsRefused(
    controlled_runtime, configuration_runner
):
    """Original issuer identity, approval and persistent consumption cannot be reconstructed."""

    root, selection, context, settings = controlled_runtime
    observer = NativeConfigurationMaterialObserver(selection, root, "native-unit", "owner:unit")
    pair = "native-configuration-pair:" + uuid4().hex
    proof = configuration_runner.run(observer.Create(NativeImageObservationBudget(),
                                                      operation_reference=pair))
    prepared = PrepareNativeConfigurationOperation("version", selection, observer=observer,
        material_proof=proof, operation_reference=pair)
    engine = ArtifactPolicyEngine()
    now = datetime.now(UTC)

    with pytest.raises(ArtifactDeniedError):
        AuthorizeNativeConfigurationOperation(engine, prepared, context, observer=observer,
            material_proof=proof, at=now)

    grant = AuthorizeNativeConfigurationOperation(engine, prepared, context, observer=observer,
        material_proof=proof, at=now, approve_safe_configuration=True)

    for supplied_engine, supplied_grant, at in (
        (engine, replace(grant), now), (ArtifactPolicyEngine(), grant, now),
        (engine, grant, now + timedelta(hours=2)),
    ):
        with pytest.raises(ArtifactDeniedError):
            ValidateNativeConfigurationOperation(supplied_engine, supplied_grant, prepared, context,
                observer=observer, material_proof=proof, at=at)

    claim = ClaimNativeConfigurationExecution(engine, grant, prepared, context, observer=observer,
                                             material_proof=proof, at=now)
    assert type(claim) is NativeConfigurationExecutionClaim, (
        "Only the original engine issues claims"
    )

    with pytest.raises(FileExistsError):
        ClaimNativeConfigurationExecution(engine, grant, prepared, context, observer=observer,
                                           material_proof=proof, at=now)

    with pytest.raises(ValueError):
        NativeConfigurationExecutionClaim()

    observer.Close()


def test_ApprovalAndMissingPolicyRefuseBeforeProvider(controlled_runtime, configuration_runner):
    """Explicit workflow approval and separate policy permission remain independently necessary."""

    root, selection, context, settings = controlled_runtime

    with pytest.raises(ArtifactDeniedError):
        configuration_runner.run(ScanNativeConfiguration(root, "native-scope", "owner:unit",
            selection, lambda: context.policy))

    summary = configuration_runner.run(ScanNativeConfiguration(root, "native-scope", "owner:unit",
        selection, lambda: ImpactPolicy("empty-policy"), approve_safe_configuration=True))
    assert summary.ExitCode() == 3 and not settings["calls"], (
        "Workflow opt-in cannot replace independent current capability permission"
    )


@pytest.mark.parametrize("failure", ["cancel", "uncertain", "output-limit"])
def test_CancelledOverflowAndUnknownTerminalCustodyNeverSaveSuccess(
    controlled_runtime, configuration_runner, failure
):
    """Owned cancellation, stream overflow and unknown terminal cleanup preserve failure truth."""

    root, selection, context, settings = controlled_runtime

    if failure == "output-limit":
        settings["termination"] = ExecutionTermination.OUTPUT_LIMIT

    else:
        settings[failure] = True

    summary = Run(configuration_runner, controlled_runtime)
    assert summary.model_revision == 0 and not Findings(LocalModelStore(root).Open()), (
        "Cancelled or uncertain original work must never save model success"
    )

    if failure == "cancel":
        assert summary.ExitCode() == 130 and summary.snapshot.state is JobState.CANCELLED, (
            "Actual cooperative cancellation must preserve its canonical terminal classification"
        )

    elif failure == "uncertain":
        assert summary.custody_uncertain and summary.ExitCode() == 4, (
            "Unknown original terminal cleanup must remain an explicit custody refusal"
        )
        assert tuple(root.glob("native-configuration-stage-*")), (
            "Unknown custody must retain original staged material for recovery"
        )
        assert tuple((root / ".native-configuration-claims").glob("*/event-*.json")), (
            "Actual original event fragments must remain durably retained on uncertain cleanup"
        )

    else:
        assert summary.snapshot.failure.code is JobFailureCode.OUTPUT_LIMIT, (
            "Output overflow cannot be reclassified as successful empty provider output"
        )


def test_ExportFailureDoesNotRewriteSuccessfulScanTruth(controlled_runtime, configuration_runner):
    """Existing report publication failure remains separate from the original saved native scan."""

    root, selection, context, settings = controlled_runtime
    existing = root.parent / "already-existing.json"
    existing.write_bytes(b"Unrelated prior output")
    summary = Run(configuration_runner, controlled_runtime,
                  report_format="json", report_output=existing)
    assert summary.snapshot.state is JobState.COMPLETED and summary.model_revision == 1, (
        "A failed requested publication cannot erase acknowledged saved scan facts"
    )
    assert summary.ExitCode() == 4 and not summary.report.output_published, (
        "A failed report destination must remain a separate nonzero outcome"
    )
    assert existing.read_bytes() == b"Unrelated prior output", "Publication cannot replace data"


def test_OriginalCaptureRecipeHasNoMutableStageAliases(controlled_runtime, configuration_runner):
    """Returned original metadata remains recursively immutable after publication and model save."""

    summary = Run(configuration_runner, controlled_runtime)
    prepared = summary.captures[-1].prepared
    original_digest = summary.captures[-1].Digest()

    with pytest.raises(TypeError):
        prepared.stage_metadata["lease_id"] = "changed"

    with pytest.raises(TypeError):
        prepared.stage_metadata["partitions"]["input"]["manifest"]["files"][0]["name"] = "other"

    assert summary.captures[-1].Digest() == original_digest, (
        "Original receipt identity must remain stable after a caller attempts metadata mutation"
    )


@pytest.mark.parametrize("owner", ["model", "workspace"])
@pytest.mark.parametrize("failure", ["suppressed", "lost-ack", "changed-ack"])
def test_UnacknowledgedWritesNeverEmitSuccessfulModelDelta(
    controlled_runtime, configuration_runner, monkeypatch, owner, failure
):
    """Suppressed writes and changed/lost acknowledgements cannot publish proposed success."""

    root, selection, context, settings = controlled_runtime
    store = LocalModelStore if owner == "model" else LocalWorkspaceStore
    original_save = store.Save
    calls = []

    def Save(self, proposal, **options):
        """Model a causal storage failure at the actual irreversible save/ACK boundary."""

        calls.append(proposal)

        if failure == "suppressed":
            return None

        committed = original_save(self, proposal, **options)

        return None if failure == "lost-ack" else replace(committed,
                                                         revision=committed.revision + 1)

    monkeypatch.setattr(store, "Save", Save)
    summary = Run(configuration_runner, controlled_runtime)
    assert summary.snapshot.state is JobState.FAILED and summary.snapshot.failure.code is (
        JobFailureCode.STORAGE
    ), "Unconfirmed writes must remain storage failures after successful provider execution"
    assert len(calls) == 1 and not any(
        item.kind is JobEventKind.MODEL_DELTA for item in summary.events
    ), (
        "One irreversible save attempt cannot be retried or advertised as an acknowledged delta"
    )
    expected_revision = 0 if owner == "model" and failure == "suppressed" else 1
    assert summary.model_revision == expected_revision and len(summary.retained_records) == 7, (
        "Actual saved model and retained original acquisitions remain separate truthful facts"
    )


@pytest.mark.parametrize("controlled_runtime", [True], indirect=True, ids=["portable-posix-model"])
def test_PortableLogicalControlsRetainCanonicalOrchestration(
    controlled_runtime, configuration_runner
):
    """Declared mode/fsync/unlink projections exercise units without native platform claims."""

    summary = Run(configuration_runner, controlled_runtime)
    assert summary.ExitCode() == 0 and len(summary.retained_records) == 7, (
        "Portable protocol projections must preserve real first-party state-machine guards"
    )


def test_UnsupportedPlatformRefusesSelectedReadsBeforeHelperStart(
    tmp_path, monkeypatch, configuration_runner
):
    """Real unsupported-platform admission must remain separate from every portable proof double."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Unsupported platform unit"),
                                     "unsupported-native")
    LocalModelStore(root).Create()
    selection = NativeConfigurationSelection(ArtifactProfile.DOCKERFILE, "Dockerfile",
        tmp_path / "must-not-read-source", tmp_path / "must-not-read-executable",
        ArtifactReadConsent("owner:unit", "read:explicit-unit"))

    def Forbidden(*args, **options):
        """Expose any selected-byte read or owned process reached after platform refusal."""

        pytest.fail("Unsupported native platform reached selected IO or helper execution")

    monkeypatch.setattr(worker, "NATIVE_CONFIGURATION_PLATFORM", ("unsupported", "unsupported"))
    monkeypatch.setattr(worker, "ReadArtifactFile", Forbidden)
    monkeypatch.setattr(LocalExecutor, "Execute", Forbidden)

    with pytest.raises(ValueError, match="platform is unsupported"):
        configuration_runner.run(PlanNativeConfigurationScan(root, "owner:unit", selection))
