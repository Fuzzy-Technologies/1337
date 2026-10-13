# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual governed image captures, separate live interpretation and historical evidence replay."""

from __future__ import annotations

import asyncio
import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from shutil import copytree
from traceback import format_exception

import pytest
from artifact_helpers import AT, OwnedImageArtifact

from fuzzy1337 import artifact_policy, synthetic_images
from fuzzy1337.adapters import ExecutionState, SerializeContract
from fuzzy1337.artifact_inputs import ArtifactOperation, ArtifactStage
from fuzzy1337.artifact_policy import (
    ArtifactDenialReason,
    ArtifactDeniedError,
    ArtifactExecutionOutcome,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
    ArtifactStagePayload,
    ArtifactVersionProof,
    GovernedArtifactExecutor,
    PrepareArtifact,
    PreparedArtifact,
)
from fuzzy1337.evidence import (
    EvidenceIntegrityError,
    EvidenceProvenance,
    EvidenceRecord,
    LocalEvidenceStore,
    NormalizeEvidenceTime,
)
from fuzzy1337.executors import ExecutionTermination, InvocationDigest
from fuzzy1337.findings import (
    ApplyFindings,
    Finding,
    Findings,
    FindingSeverity,
    FindingStatus,
    Remediation,
    TransitionFinding,
)
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.policy import Digest
from fuzzy1337.scope import AuthorizationState, LocalScopeStore
from fuzzy1337.synthetic_images import (
    ApplyVerifiedSyntheticTrivyImages,
    VerifySyntheticTrivyImageReplay,
)


class DecisionDateTime(datetime):
    """Deterministic SDK decision clock; the production consumer still selects its own facade."""

    current_time = AT + timedelta(seconds=60)

    @classmethod
    def Now(cls, tz=None):
        """Return the current aware test decision time without replacing any verifier."""

        return cls.current_time


@pytest.fixture(autouse=True)
def decision_clock(monkeypatch):
    """Keep the canonical SDK's own clock within the original owned fixture consent window."""

    monkeypatch.setattr(DecisionDateTime, "current_time", AT + timedelta(seconds=60))
    # datetime owns the external callback name; keep its bound PascalCase implementation.
    monkeypatch.setattr(DecisionDateTime, "now", DecisionDateTime.Now)
    monkeypatch.setattr(artifact_policy, "datetime", DecisionDateTime)


@dataclass(frozen=True)
class ImagePair:
    """Original actual two-operation facts and six immutable owned evidence manifests."""

    root: Path
    state: ModelState
    context: ArtifactPolicyContext
    proof: ArtifactVersionProof
    outcome: ArtifactExecutionOutcome
    prepared: PreparedArtifact
    stage: ArtifactStage
    records: tuple[EvidenceRecord, ...]


def CaptureRecords(root, outcome, prepared, stage, started, finished):
    """Store actual streams and complete original payloads around the observed call window."""

    is_version = prepared.operation == ArtifactOperation.VERSION
    roles = ("provider-version", "provider-version-stderr", "artifact-version-receipt") if (
        is_version
    ) else ("stdout", "stderr", "artifact-scan-receipt")
    source = EvidenceProvenance(
        outcome.grant.plan.workspace_id, outcome.grant.plan.scope_reference, "synthetic.trivy", "1",
        "0.75.0-synthetic", started.isoformat(), finished.isoformat(),
        InvocationDigest(prepared.invocation), outcome.raw_result.execution,
    )
    envelope = {
        "schema_version": 1, "artifact_metadata": outcome.Metadata(),
        "prepared_payload": json.loads(SerializeContract(prepared.Payload())),
        "stage_payload": json.loads(SerializeContract(ArtifactStagePayload(stage))),
        "collection_started_at": source.started_at, "collection_finished_at": source.finished_at,
    }
    store = LocalEvidenceStore(root / "evidence")

    return tuple(store.Put(payload, role, media, source) for role, payload, media in (
        (roles[0], outcome.raw_result.stdout, "application/json"),
        (roles[1], outcome.raw_result.stderr, "text/plain"),
        (roles[2], SerializeContract(envelope).encode(), "application/json"),
    ))


def CollectImagePair(tmp_path, *, scenario="success", workspace=None, prefix="owned",
                     cancelled=False):
    """Execute reviewed VERSION and SCAN workers through their actual canonical SDK path."""

    root, version_stage, version_prepared, context, version_grant = OwnedImageArtifact(
        tmp_path, workspace=workspace, stage_name=prefix + "-version", scenario=scenario,
    )
    model_store = LocalModelStore(root)
    state = model_store.Create() if workspace is None else model_store.Open()
    version_started = AT
    version_executor = GovernedArtifactExecutor(root, clock=lambda: version_started)
    version = asyncio.run(version_executor.Execute(
        version_prepared, version_stage, version_grant, lambda: context,
    ))
    version_finished = AT + timedelta(milliseconds=1)
    proof = ArtifactVersionProof(version, version_prepared, version_stage)
    version_records = CaptureRecords(
        root, version, version_prepared, version_stage, version_started, version_finished,
    )
    _, stage, prepared, _, _ = OwnedImageArtifact(
        tmp_path, workspace=root, stage_name=prefix + "-scan", scenario=scenario,
        operation=ArtifactOperation.SCAN, version_proof=proof,
    )

    if scenario == "hold":
        prepared = PrepareArtifact(stage, root, timeout_seconds=1, version_proof=proof)

    scan_started = AT + timedelta(milliseconds=10)
    grant = ArtifactPolicyEngine().Authorize(prepared, stage, context, at=scan_started)
    cancellation = asyncio.Event() if cancelled else None

    if cancellation is not None:
        cancellation.set()

    executor = GovernedArtifactExecutor(root, clock=lambda: scan_started)
    outcome = asyncio.run(executor.Execute(
        prepared, stage, grant, lambda: context, cancellation=cancellation,
    ))
    scan_finished = AT + timedelta(milliseconds=11)
    records = version_records + CaptureRecords(
        root, outcome, prepared, stage, scan_started, scan_finished,
    )

    return ImagePair(root, state, context, proof, outcome, prepared, stage, records)


@pytest.fixture(scope="module")
def pair(tmp_path_factory):
    """Share immutable successful actual-process facts across record-only consumer assertions."""

    return CollectImagePair(tmp_path_factory.mktemp("image-capture"))


def Apply(pair, *, state=None, records=None, context_provider=None):
    """Call the public live boundary with actual original runs and factual current context."""

    return ApplyVerifiedSyntheticTrivyImages(
        pair.state if state is None else state, pair.proof, pair.outcome, pair.prepared, pair.stage,
        pair.records if records is None else records, pair.root,
        context_provider=(lambda: pair.context) if context_provider is None else context_provider,
    )


def ReplaceRecord(pair, role, *, payload=None, provenance=None, media_type=None):
    """Persist one new explicit acquisition for adversarial record-identity/attribution checks."""

    store = LocalEvidenceStore(pair.root / "evidence")
    original = next(record for record in pair.records if record.reference.role == role)
    replacement = store.Put(
        store.Read(original.reference) if payload is None else payload, role,
        original.reference.media_type if media_type is None else media_type,
        original.provenance if provenance is None else provenance,
    )

    return tuple(replacement if record.reference.role == role else record
                 for record in pair.records)


def test_ActualPairReplayPreservesSixOriginalRecordsAndExecutionFacts(pair):
    """Historical facts retain both actual runs, all manifests and the exact prerequisite digest."""

    replay = VerifySyntheticTrivyImageReplay(pair.records, pair.root)
    assert replay.version_acceptance == pair.proof.outcome.acceptance, (
        "Read-only verification replaced the original VERSION receipt"
    )
    assert replay.scan_acceptance == pair.outcome.acceptance, (
        "Read-only verification replaced the original SCAN receipt"
    )
    assert replay.version_prerequisite_sha256 == pair.proof.Digest(), (
        "Read-only pair verification lost its exact original prerequisite"
    )
    assert set(replay.records) == set(pair.records), "Original immutable acquisitions were replaced"
    assert replay.provenance.run_reference == pair.outcome.run_id, "SCAN run attribution changed"
    assert replay.provenance.observed_at == NormalizeEvidenceTime(
        (AT + timedelta(milliseconds=11)).isoformat()
    ), "Model attribution must use the actual observed SCAN collection finish"
    assert replay.provenance.execution == pair.outcome.raw_result.execution, (
        "Model attribution lost the actual unchanged terminal SCAN execution"
    )
    assert len(replay.provenance.evidence_references) == 6, "One original source role was discarded"


def test_LiveActualPairCreatesIsolatedInMemoryGraphWithoutSavingOrWritingEvidence(pair):
    """Actual capture enables an isolated model proposal while durable stores remain unchanged."""

    original = CanonicalModelJson(pair.state.ToDict())
    records_before = {path.name for path in (pair.root / "evidence/records").iterdir()}
    state, delta = Apply(pair)
    assets = state.Objects(ObjectKind.ASSET)
    prefix = "synthetic.trivy:owned-synthetic-image-wire-v1:"
    assert len(assets) == 6 and all(item.identity.key.startswith(prefix) for item in assets), (
        "Every image, package, OS, layer and license interpretation must remain fixture-isolated"
    )
    assert len(Findings(state)) == 1, "Owned wire must match the independent known answer"
    assert Findings(state)[0].check_id == "synthetic.supply-chain.vulnerability", (
        "Synthetic detection borrowed the native detector identity"
    )
    assert delta.revision == pair.state.revision + 1, "One proposal needs one aggregate revision"
    assert CanonicalModelJson(pair.state.ToDict()) == original, "Proposal mutated its input model"
    assert LocalModelStore(pair.root).Open() == pair.state, "Pure import unexpectedly saved state"
    assert {path.name for path in (pair.root / "evidence/records").iterdir()} == records_before, (
        "The interpretation boundary wrote or replaced raw evidence"
    )
    assert b"producer.py" not in CanonicalModelJson(state.ToDict()), (
        "Physical request/stage facts escaped receipt evidence into the normalized model"
    )
    replayed, no_change = Apply(pair, state=state)
    assert replayed == state and no_change.revision == state.revision, (
        "Repeated live acceptance duplicated identical interpretations or history"
    )


@pytest.mark.parametrize("scenario", [
    "no_findings", "provider_error", "malformed", "version_mismatch", "package_mismatch",
    "output_limit", "hold",
])
def test_ActualScenarioFailuresRetainRawReplayAndNeverSaveInterpretation(tmp_path, scenario):
    """The independent eight-scenario oracle governs owned process and wire failures."""

    selected = CollectImagePair(tmp_path, scenario=scenario)
    replay = VerifySyntheticTrivyImageReplay(selected.records, selected.root)
    assert replay.scan_acceptance == selected.outcome.acceptance, "Replay rewrote raw refusal"
    previous = CanonicalModelJson(selected.state.ToDict())

    if scenario == "no_findings":
        state, _ = Apply(selected)
        assert not Findings(state), "Empty valid raw findings became a manufactured vulnerability"
        assert all(item.attributes.get("scan_completeness") == "not-assessed" for item in (
            state.observations
        ) if item.kind == "image-inventory"), "Zero findings cannot establish scanner completeness"

    else:
        with pytest.raises((ValueError, ArtifactDeniedError)):
            Apply(selected)

        assert selected.outcome.raw_result.stdout, "Rejected SCAN discarded its bounded stdout"

    assert CanonicalModelJson(LocalModelStore(selected.root).Open().ToDict()) == previous, (
        "Failed or pure synthetic interpretation altered the durable original model"
    )


def test_ActualCancelledScanRetainsExecutionRefusalAndCannotApply(tmp_path):
    """Pre-launch cancellation remains its actual raw termination and refuses findings."""

    selected = CollectImagePair(tmp_path, cancelled=True)
    assert selected.outcome.raw_result.termination == ExecutionTermination.CANCELLATION, (
        "Cancellation was relabelled as successful provider completion"
    )
    replay = VerifySyntheticTrivyImageReplay(selected.records, selected.root)
    assert replay.scan_acceptance.refusal == selected.outcome.acceptance.refusal, (
        "Historical failure evidence must retain the actual cancellation receipt"
    )

    with pytest.raises(ValueError):
        Apply(selected)


def test_RelocatedHistoricalReplayCannotInspectLiveStagesReauthorizeApplyOrSave(pair, tmp_path,
                                                                              monkeypatch):
    """Historical verification survives removed stages without crossing live boundaries."""

    copied = tmp_path / "relocated"
    copytree(pair.root, copied, ignore=lambda directory, names: [
        name for name in names if name in {pair.proof.stage.root.name, pair.stage.root.name}
    ])

    def Forbidden(*arguments, **options):
        """Expose any accidental current-stage/authority/model operation in read-only replay."""

        raise AssertionError("Historical verification crossed a live or mutable boundary")

    monkeypatch.setattr(ArtifactStage, "Verify", Forbidden)
    monkeypatch.setattr(LocalScopeStore, "Open", Forbidden)
    monkeypatch.setattr(GovernedArtifactExecutor, "ValidatePairAcceptanceFresh", Forbidden)
    monkeypatch.setattr(GovernedArtifactExecutor, "Execute", Forbidden)
    monkeypatch.setattr(LocalModelStore, "Open", Forbidden)
    monkeypatch.setattr(LocalModelStore, "Save", Forbidden)
    monkeypatch.setattr(ModelState, "Apply", Forbidden)
    replay = VerifySyntheticTrivyImageReplay(pair.records, copied)
    original_records = tuple(sorted(pair.records, key=lambda record: record.reference.role))
    assert replay.records == original_records, (
        "Relocation replaced original acquisitions or original attribution"
    )


def NativeBaseline(pair):
    """Seed all independent collision families and a triaged native Finding as test data."""

    oracle = json.loads((Path(__file__).resolve().parents[1] / "fixtures/image_scan/oracle.json"
                         ).read_bytes())["native_namespace_baseline"]
    provenance = ModelProvenance(
        "fixture.seed", "run:collision-baseline", AT.isoformat(), pair.context.scope.Reference(),
        pair.stage.input.manifest.Target().Reference(),
        evidence_references=(pair.records[0].reference,),
    )
    assets = tuple(SecurityObject(
        ObjectIdentity(pair.state.workspace_id, ObjectKind.ASSET, item["natural_key"]),
        item["attributes"], (provenance,),
    ) for item in oracle["asset_seeds"])
    state, _ = pair.state.Apply(objects=assets)
    seed = oracle["triaged_finding"]
    subject = next(item.Reference() for item in assets if item.identity.key == (
        seed["subject_object_key"]
    ))
    finding = Finding(subject, seed["check_id"], seed["location_key"], "Owned baseline Finding",
        (provenance,), severity=FindingSeverity(seed["severity"]), confidence=seed["confidence"],
        remediation=Remediation(summary=seed["remediation_summary"]))
    state, _ = ApplyFindings(state, (finding,))
    state, _ = TransitionFinding(state, Findings(state)[0].ToObject(state.workspace_id).Reference(),
        FindingStatus.DISMISSED, provenance, "Owned independent native collision oracle")

    return state


def test_ActualSyntheticImportAndReplayPreserveEntireNativeCollisionObjectsAndTriage(pair):
    """All six colliding native assets and native triage/provenance remain byte-exact."""

    native = NativeBaseline(pair)
    before = {item.Reference(): CanonicalModelJson(item) for item in native.objects}
    state, _ = Apply(pair, state=native)
    VerifySyntheticTrivyImageReplay(pair.records, pair.root)
    after = {item.Reference(): CanonicalModelJson(item) for item in state.objects}
    assert len(before) == 7 and all(after[reference] == content
                                   for reference, content in before.items()), (
        "Synthetic image detection altered native asset attributes, provenance or operator triage"
    )
    native_refs = set(before)
    assert all(item.subject_reference not in native_refs for item in state.observations if (
        item.provenance.source_id == "synthetic.trivy"
    )), "Synthetic observation linked into the seeded native graph"
    assert all(not ({item.source_reference, item.target_reference} & native_refs)
               for item in state.relations), "Synthetic relation promoted a colliding native object"
    original = next(finding for finding in Findings(state) if finding.check_id == (
        "supply-chain.vulnerability"
    ))
    assert original.status == FindingStatus.DISMISSED, "Synthetic detection reopened native triage"


@pytest.mark.parametrize("role", [
    "provider-version", "provider-version-stderr", "stdout", "stderr",
    "artifact-version-receipt", "artifact-scan-receipt",
])
@pytest.mark.parametrize("mutation", ["source", "scope", "version", "execution", "invocation"])
def test_AllSixOriginalRolesRequireExactOperationProvenance(pair, role, mutation):
    """No newly saved acquisition can replace the original operation's actual attribution."""

    original = next(record for record in pair.records if record.reference.role == role)
    changes = {
        "source": {"source_id": "owned.other"}, "scope": {"scope_reference": "scope:other"},
        "version": {"source_version": "2"}, "invocation": {"invocation_sha256": "a" * 64},
        "execution": {"execution": replace(original.provenance.execution,
            state=ExecutionState.FAILED, exit_code=7)},
    }[mutation]
    records = ReplaceRecord(pair, role, provenance=replace(original.provenance, **changes))

    with pytest.raises(ValueError):
        VerifySyntheticTrivyImageReplay(records, pair.root)

    with pytest.raises(ValueError):
        Apply(pair, records=records)


@pytest.mark.parametrize("mutation", ["list", "missing", "duplicate", "reference", "wrong-media"])
def test_CaptureManifestAdmissionRequiresExactTypedRoleSet(pair, mutation):
    """Content-only, missing, repeated and wrong-media acquisitions never enter model admission."""

    records = pair.records

    if mutation == "list":
        records = list(records)

    elif mutation == "missing":
        records = records[:-1]

    elif mutation == "duplicate":
        records = records[:-1] + (records[0],)

    elif mutation == "reference":
        records = (records[0].reference,) + records[1:]

    else:
        records = ReplaceRecord(pair, "stdout", media_type="text/plain")

    with pytest.raises(ValueError):
        VerifySyntheticTrivyImageReplay(records, pair.root)


@pytest.mark.parametrize("mutation", [
    "extra", "missing", "schema-bool", "legacy-sdk", "request-hash", "stage-hash",
    "operation", "family", "window", "window-alias", "duplicate-json", "nonfinite", "utf8",
    "depth", "nodes", "private-enum", "bom", "empty-window",
])
def test_OriginalCaptureEnvelopesRefuseMalformedPrivateOrReplacedFactsAtomically(pair, mutation):
    """Exact original schema and bounds reject hostile facts without raw text in tracebacks."""

    store = LocalEvidenceStore(pair.root / "evidence")
    receipt = next(record for record in pair.records if record.reference.role == (
        "artifact-scan-receipt"
    ))
    envelope = json.loads(store.Read(receipt.reference))

    if mutation == "extra":
        envelope["private"] = "OWNED_PRIVATE_CAPTURE_MARKER"

    elif mutation == "missing":
        del envelope["stage_payload"]

    elif mutation == "schema-bool":
        envelope["schema_version"] = True

    elif mutation == "legacy-sdk":
        envelope["artifact_metadata"]["schema_version"] = 1

    elif mutation == "request-hash":
        envelope["prepared_payload"]["environment"]["PRIVATE"] = "OWNED_PRIVATE_CAPTURE_MARKER"

    elif mutation == "stage-hash":
        envelope["stage_payload"]["root"] = "OWNED_PRIVATE_CAPTURE_MARKER"

    elif mutation == "operation":
        envelope["artifact_metadata"]["grant"]["plan"]["operation"] = "version"

    elif mutation == "family":
        envelope["artifact_metadata"]["grant"]["plan"]["producer_family"] = "owned.other"

    elif mutation == "window":
        envelope["collection_started_at"] = NormalizeEvidenceTime(
            (AT + timedelta(seconds=30)).isoformat()
        )

    elif mutation == "window-alias":
        envelope["collection_started_at"] = "2026-10-13T00:00:00.010000Z"

    elif mutation == "private-enum":
        envelope["artifact_metadata"]["manifests"][0]["profile"] = "OWNED_PRIVATE_CAPTURE_MARKER"

    elif mutation == "empty-window":
        envelope["collection_finished_at"] = envelope["collection_started_at"]

    raw = SerializeContract(envelope).encode()

    if mutation == "duplicate-json":
        raw = b'{"private":"OWNED_PRIVATE_CAPTURE_MARKER","private":0}'

    elif mutation == "nonfinite":
        raw = b'{"private":NaN}'

    elif mutation == "utf8":
        raw = b"\xffOWNED_PRIVATE_CAPTURE_MARKER"

    elif mutation == "depth":
        raw = b'{"private":' + b"[" * 40 + b"0" + b"]" * 40 + b"}"

    elif mutation == "nodes":
        raw = b'{"private":[' + b"0," * 65536 + b"0]}"

    elif mutation == "bom":
        raw = b"\xef\xbb\xbf" + raw

    records = ReplaceRecord(pair, "artifact-scan-receipt", payload=raw)

    with pytest.raises(ValueError) as refused:
        VerifySyntheticTrivyImageReplay(records, pair.root)

    assert "OWNED_PRIVATE_CAPTURE_MARKER" not in "".join(format_exception(refused.value)), (
        "Historical capture refusal leaked private raw facts through chained diagnostics"
    )

    with pytest.raises(ValueError):
        Apply(pair, records=records)

    assert LocalModelStore(pair.root).Open() == pair.state, "Malformed capture changed saved state"


def ResignedScanRecords(pair, envelope):
    """Model self-consistent hostile saved attribution without claiming authentication."""

    metadata = envelope["artifact_metadata"]
    grant = metadata["grant"]
    plan = grant["plan"]
    plan["request_sha256"] = Digest(envelope["prepared_payload"])
    plan["stage_sha256"] = Digest(envelope["stage_payload"])
    plan["invocation_sha256"] = Digest(envelope["prepared_payload"]["invocation"])
    plan["intent_sha256"] = Digest({key: value for key, value in plan.items()
                                    if key != "intent_sha256"})
    authorization = grant["authorization"]
    authorization["invocation_sha256"] = plan["invocation_sha256"]
    authorization["authorization_id"] = "artifact-authorization:" + Digest((
        plan, grant["issued_at"], grant["valid_until"],
    ))
    metadata["acceptance"]["grant_id"] = authorization["authorization_id"]
    store = LocalEvidenceStore(pair.root / "evidence")
    records = []

    for record in pair.records:
        if record.reference.role not in {"stdout", "stderr", "artifact-scan-receipt"}:
            records.append(record)
            continue

        raw = SerializeContract(envelope).encode() if record.reference.role == (
            "artifact-scan-receipt"
        ) else store.Read(record.reference)
        source = replace(record.provenance, invocation_sha256=plan["invocation_sha256"])
        records.append(store.Put(raw, record.reference.role, record.reference.media_type, source))

    return tuple(records)


@pytest.mark.parametrize("alias", [
    "partition", "selected-copy", "rotated-directory", "cross-role-file", "root-to-directory",
])
def test_RecordedPairRefusesSelfConsistentReusedPhysicalCopies(pair, alias):
    """Rehashed old facts cannot claim distinct physical runs while reusing copied inputs."""

    store = LocalEvidenceStore(pair.root / "evidence")
    envelopes = {record.reference.role: json.loads(store.Read(record.reference))
                 for record in pair.records if record.reference.role.endswith("receipt")}
    version_stage = envelopes["artifact-version-receipt"]["stage_payload"]
    scan = deepcopy(envelopes["artifact-scan-receipt"])

    if alias == "partition":
        scan["stage_payload"]["partitions"][0]["directory_identity"] = (
            version_stage["partitions"][0]["directory_identity"]
        )

    elif alias == "selected-copy":
        scan["stage_payload"]["partitions"][0]["identities"] = (
            version_stage["partitions"][0]["identities"]
        )

    elif alias == "rotated-directory":
        for index, partition in enumerate(scan["stage_payload"]["partitions"]):
            partition["directory_identity"] = version_stage["partitions"][(index + 1) % 3][
                "directory_identity"
            ]

    elif alias == "cross-role-file":
        scan["stage_payload"]["partitions"][0]["identities"][0][1][:2] = (
            version_stage["partitions"][1]["identities"][0][1][:2]
        )

    else:
        scan["stage_payload"]["partitions"][0]["directory_identity"] = (
            version_stage["root_identity"]
        )

    records = ResignedScanRecords(pair, scan)

    with pytest.raises(ValueError):
        VerifySyntheticTrivyImageReplay(records, pair.root)


@pytest.mark.parametrize("mutation", ["argv", "cwd", "environment", "resources", "deadline"])
def test_ReadOnlyConsumerUsesOwningExactFactoryGrammarForRehashedCaptures(pair, mutation):
    """Self-consistent saved hashes cannot admit an unsupported detached factory request."""

    store = LocalEvidenceStore(pair.root / "evidence")
    record = next(record for record in pair.records if record.reference.role == (
        "artifact-scan-receipt"
    ))
    envelope = json.loads(store.Read(record.reference))
    prepared = envelope["prepared_payload"]

    if mutation == "argv":
        prepared["invocation"]["argv"] = ["unsupported-synthetic-command"]

    elif mutation == "cwd":
        prepared["workspace"] = "unsupported-scratch"

    elif mutation == "environment":
        prepared["environment"]["PYTHONPATH"] = "OWNED_PRIVATE_FACTORY_MARKER"

    elif mutation == "resources":
        prepared["resources"]["max_stdout_bytes"] = 4 * 1024 * 1024 + 1

    else:
        prepared["invocation"]["timeout_seconds"] = 61

    records = ResignedScanRecords(pair, envelope)

    with pytest.raises(ValueError) as refused:
        VerifySyntheticTrivyImageReplay(records, pair.root)

    assert "OWNED_PRIVATE_FACTORY_MARKER" not in "".join(format_exception(refused.value)), (
        "Canonical factory refusal leaked private detached request values"
    )


@pytest.mark.parametrize("role", ["provider-version", "stdout", "artifact-scan-receipt"])
def test_ActualOwningManifestReadIsRoleBoundedBeforeAllocatingItsRawBytes(pair, monkeypatch, role):
    """A small copied wrapper cannot conceal an oversized actual owning acquisition from Get."""

    store = LocalEvidenceStore(pair.root / "evidence")
    original = next(record for record in pair.records if record.reference.role == role)
    limit = {"provider-version": 16 * 1024, "stdout": 4 * 1024 * 1024,
             "artifact-scan-receipt": 1024 * 1024}[role]
    actual = store.Put(b"x" * (limit + 1), role, original.reference.media_type, original.provenance)
    copied = replace(original)
    object.__setattr__(copied, "evidence_id", actual.evidence_id)
    records = tuple(copied if record.reference.role == role else record for record in pair.records)
    base_read = LocalEvidenceStore.Read

    def Read(selected, reference):
        """Expose any attempted raw allocation of the oversized actual owning source record."""

        assert reference != actual.reference, "Consumer reached oversized owning raw allocation"

        return base_read(selected, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", Read)

    with pytest.raises(ValueError):
        VerifySyntheticTrivyImageReplay(records, pair.root)


@pytest.mark.parametrize("mutation", ["owner", "policy", "scope", "expiry"])
def test_CurrentAuthorityChangedDuringCandidatesCannotApply(tmp_path, monkeypatch, mutation):
    """The consumer uses current factual canonical acceptance after its last expensive pure work."""

    selected = CollectImagePair(tmp_path)
    current = selected.context
    original_candidates = synthetic_images.SyntheticTrivyCandidates
    apply_calls = []
    original_apply = ModelState.Apply

    def Candidates(*arguments):
        """Change only owned current authority once candidate interpretation has completed."""

        nonlocal current
        candidates = original_candidates(*arguments)

        if mutation == "owner":
            current = replace(current, owner_ref="owner:changed")

        elif mutation == "policy":
            current = replace(current, policy=replace(current.policy, permissions=()))

        elif mutation == "scope":
            scope = replace(current.scope, authorization=replace(current.scope.authorization,
                state=AuthorizationState.REVOKED))
            LocalScopeStore(selected.root).Save(scope)
            current = replace(current, scope=scope)

        else:
            DecisionDateTime.current_time = AT + timedelta(seconds=301)

        return candidates

    def ModelApply(state, **arguments):
        """Record any premature attempted in-memory model application after failed freshness."""

        apply_calls.append(state)

        return original_apply(state, **arguments)

    monkeypatch.setattr(synthetic_images, "SyntheticTrivyCandidates", Candidates)
    monkeypatch.setattr(ModelState, "Apply", ModelApply)

    with pytest.raises(ArtifactDeniedError):
        Apply(selected, context_provider=lambda: current)

    assert not apply_calls, "Stale authority reached pure model application"
    assert LocalModelStore(selected.root).Open() == selected.state, "Denial changed saved state"


def test_FinalCanonicalBarrierAllowsOnlyPureApplicationAfterwards(pair, monkeypatch):
    """No evidence read, workspace lookup, callback or model save occurs after fresh acceptance."""

    passed = False
    original_validate = GovernedArtifactExecutor.ValidatePairAcceptanceFresh

    def Validate(executor, version, scan, provider):
        """Use the actual canonical validator before activating post-barrier I/O tripwires."""

        nonlocal passed
        original_validate(executor, version, scan, provider)
        passed = True

    def Context():
        """Return factual current authority only while the canonical decision is still pending."""

        assert not passed, "Consumer called current context after its final freshness barrier"

        return pair.context

    original_read = LocalEvidenceStore.Read

    def Read(store, reference):
        """Reject evidence I/O after all exact candidate/evidence validation has completed."""

        assert not passed, "Consumer performed evidence I/O after its final freshness barrier"

        return original_read(store, reference)

    monkeypatch.setattr(GovernedArtifactExecutor, "ValidatePairAcceptanceFresh", Validate)
    monkeypatch.setattr(LocalEvidenceStore, "Read", Read)
    state, _ = Apply(pair, context_provider=Context)
    assert passed and len(Findings(state)) == 1, "Fresh canonical decision must precede application"


@pytest.mark.parametrize("changed", ["model", "proof", "outcome", "request", "stage", "context"])
def test_LiveBoundaryNeverAcceptsUntypedRunsOrCallerApprovalVerdicts(pair, changed):
    """A saved receipt or caller-selected boolean cannot replace an original typed live boundary."""

    values = [pair.state, pair.proof, pair.outcome, pair.prepared, pair.stage]
    index = {"model": 0, "proof": 1, "outcome": 2, "request": 3, "stage": 4}.get(changed)

    if index is not None:
        values[index] = pair.outcome.acceptance

    provider = (lambda: True) if changed == "context" else (lambda: pair.context)

    with pytest.raises(ValueError):
        ApplyVerifiedSyntheticTrivyImages(
            *values, pair.records, pair.root, context_provider=provider,
        )


def test_RepeatedActualCollectionsPreserveSyntheticOperatorDisposition(tmp_path):
    """New accepted actual runs retain fixture triage while accumulating original evidence."""

    first = CollectImagePair(tmp_path)
    state, _ = Apply(first)
    store = LocalModelStore(first.root)
    store.Save(state, expected_revision=first.state.revision)
    previous = Findings(state)[0]
    operator = ModelProvenance("operator", "decision:owned", AT.isoformat(),
        first.context.scope.Reference(), first.stage.input.manifest.Target().Reference())
    before_triage = state.revision
    state, _ = TransitionFinding(state, previous.ToObject(state.workspace_id).Reference(),
        FindingStatus.RESOLVED, operator, "Owned synthetic disposition")
    store.Save(state, expected_revision=before_triage)
    second = CollectImagePair(tmp_path, workspace=first.root, prefix="second")
    updated, _ = Apply(second, state=state)
    finding = Findings(updated)[0]
    assert finding.status == FindingStatus.RESOLVED, "Accepted re-detection reopened fixture triage"
    assert finding.status_reason == "Owned synthetic disposition", "Operator reason was replaced"
    assert len(finding.provenance) == 3, "Separate runs discarded original detection attribution"
    store.Save(updated, expected_revision=state.revision)
    assert store.Open() == updated, "Explicit model save lost triage or evidence"


def test_ActualOwnerManifestFailureNeverReflectsPrivateSourceTimeInTraceback(pair):
    """The owner's chained decoder errors remain sanitized at the synthetic consumer boundary."""

    original = pair.records[0]
    manifest = original.ToDict()
    manifest["provenance"]["started_at"] = "OWNED_PRIVATE_MANIFEST_MARKER"
    raw = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(raw).hexdigest()
    (pair.root / "evidence/records" / (digest + ".json")).write_bytes(raw)
    copied = replace(original)
    object.__setattr__(copied, "evidence_id", "sha256:" + digest)
    records = (copied,) + pair.records[1:]

    with pytest.raises(EvidenceIntegrityError) as refused:
        VerifySyntheticTrivyImageReplay(records, pair.root)

    assert "OWNED_PRIVATE_MANIFEST_MARKER" not in "".join(format_exception(refused.value)), (
        "Source manifest diagnostics exposed private untrusted fields from the owner decoder chain"
    )


def test_ActualWorkspaceSchemaFailureNeverReflectsPrivateLensInTraceback(pair, tmp_path):
    """Raw private workspace enum values stay outside the public original-capture error chain."""

    copied = tmp_path / "invalid-workspace"
    copytree(pair.root, copied, ignore=lambda directory, names: [
        name for name in names if name in {pair.proof.stage.root.name, pair.stage.root.name}
    ])
    path = copied / "workspace.json"
    state = json.loads(path.read_bytes())
    state["configuration"]["selected_lens"] = "OWNED_PRIVATE_WORKSPACE_MARKER"
    path.write_bytes(json.dumps(state).encode())

    with pytest.raises(ValueError) as refused:
        VerifySyntheticTrivyImageReplay(pair.records, copied)

    assert "OWNED_PRIVATE_WORKSPACE_MARKER" not in "".join(format_exception(refused.value)), (
        "Historical verification exposed private untrusted workspace metadata in its cause chain"
    )


def test_ActualCurrentScopeSchemaFailureNeverReflectsPrivateAuthorityText(tmp_path):
    """Canonical final acceptance remains the owner while diagnostics suppress private enums."""

    selected = CollectImagePair(tmp_path)
    path = selected.root / "state/scopes/artifact-scope.json"
    document = json.loads(path.read_bytes())
    document["authorization"]["state"] = "OWNED_PRIVATE_AUTHORITY_MARKER"
    path.write_bytes(json.dumps(document).encode())

    with pytest.raises(ValueError) as refused:
        Apply(selected)

    assert "OWNED_PRIVATE_AUTHORITY_MARKER" not in "".join(format_exception(refused.value)), (
        "Fresh canonical authority validation exposed private source schema values"
    )
    assert LocalModelStore(selected.root).Open() == selected.state, (
        "Invalid current scope changed the saved model"
    )


def test_CurrentMaterialLossRetainsDenialWithoutPrivatePhysicalPath(tmp_path, monkeypatch):
    """A missing original file refuses live application without leaking its physical location."""

    selected = CollectImagePair(tmp_path / "OWNED_PRIVATE_STAGE_MARKER")
    original_candidates = synthetic_images.SyntheticTrivyCandidates

    def Candidates(*arguments):
        """Remove only owned VERSION fixture material after original candidate construction."""

        candidates = original_candidates(*arguments)
        policy_path = selected.proof.stage.root / "material/policy.json"
        policy_path.chmod(0o600)
        policy_path.unlink()

        return candidates

    monkeypatch.setattr(synthetic_images, "SyntheticTrivyCandidates", Candidates)

    with pytest.raises(ArtifactDeniedError) as refused:
        Apply(selected)

    assert refused.value.reason == ArtifactDenialReason.MATERIAL_CHANGED, (
        "Consumer changed the canonical original-material denial reason"
    )
    assert "OWNED_PRIVATE_STAGE_MARKER" not in "".join(format_exception(refused.value)), (
        "Material failure exposed a private original staging path in its chained diagnostics"
    )


def test_FactualCurrentLookupPermissionFailureKeepsCategoryAndSanitizesCause(pair):
    """A deterministic denied authority lookup preserves storage failure without private context."""

    def Context():
        """Model an owned factual lookup denied by its storage service."""

        raise PermissionError("OWNED_PRIVATE_LOOKUP_MARKER")

    with pytest.raises(PermissionError) as refused:
        Apply(pair, context_provider=Context)

    assert "OWNED_PRIVATE_LOOKUP_MARKER" not in "".join(format_exception(refused.value)), (
        "Current-authority storage failure exposed private lookup diagnostics"
    )
