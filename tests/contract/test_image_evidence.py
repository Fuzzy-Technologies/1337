# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Original workflow captures and canonical consumer replay/alias/capture-budget contracts."""

from __future__ import annotations

import asyncio
import json
from copy import copy, deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337 import synthetic_images
from fuzzy1337.artifact_inputs import ArtifactStage
from fuzzy1337.artifact_policy import (
    ArtifactPolicyEngine,
    GovernedArtifactExecutor,
    VerifyArtifactReplay,
    VerifySyntheticImagePayloadReplay,
)
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import ExecutionResources
from fuzzy1337.image_evidence import ImageOperationCapture
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelState
from fuzzy1337.policy import Digest
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.synthetic_images import (
    ApplyVerifiedSyntheticTrivyImages,
    VerifySyntheticTrivyImageReplay,
)
from tests.image_helpers import CollectOwnedImagePair, CreateOwnedImage

PRIVATE = "SYNTHETIC_PRIVATE_IMAGE_MARKER"


@pytest.fixture(scope="module")
def actual_pair(tmp_path_factory):
    """Acquire both actual original SDK operations without manufacturing accepted outcomes."""

    owned = CreateOwnedImage(tmp_path_factory.mktemp("workflow-image-evidence"))
    proof, scan, records = asyncio.run(CollectOwnedImagePair(owned))

    return owned, proof, scan, records


def RebindCapture(envelope):
    """Coherently rehash changed claims to distinguish factory grammar from hash consistency."""

    metadata = envelope["artifact_metadata"]
    prepared = envelope["prepared_payload"]
    grant = metadata["grant"]
    plan = grant["plan"]
    plan["request_sha256"] = Digest(prepared)
    plan["stage_sha256"] = Digest(envelope["stage_payload"])
    plan["invocation_sha256"] = Digest(prepared["invocation"])
    plan["intent_sha256"] = Digest({key: value for key, value in plan.items()
        if key != "intent_sha256"})
    authorization = grant["authorization"]
    authorization["invocation_sha256"] = plan["invocation_sha256"]
    authorization["authorization_id"] = "artifact-authorization:" + Digest(
        (plan, grant["issued_at"], grant["valid_until"]))
    metadata["acceptance"]["grant_id"] = authorization["authorization_id"]


def ReadCaptures(pair):
    """Read only the two original owning-workspace capture records before controlled mutation."""

    owned, _, _, records = pair
    store = LocalEvidenceStore(owned.root / "evidence")
    by_role = {record.reference.role: record for record in records}

    return {
        operation: json.loads(store.Read(by_role["artifact-" + operation + "-receipt"].reference))
        for operation in ("version", "scan")
    }


def StoreCaptures(pair, envelopes):
    """Publish changed claims through the evidence owner while retaining actual original streams."""

    owned, _, _, records = pair
    store = LocalEvidenceStore(owned.root / "evidence")
    replacements = []

    for record in records:
        version = record.reference.role.startswith("provider-version") or (
            record.reference.role == "artifact-version-receipt")
        envelope = envelopes["version" if version else "scan"]
        data = CanonicalModelJson(envelope) if record.reference.role.endswith("-receipt") else (
            store.Read(record.reference))
        source = replace(record.provenance, invocation_sha256=(
            envelope["artifact_metadata"]["grant"]["plan"]["invocation_sha256"]))
        replacements.append(store.Put(data, record.reference.role,
            record.reference.media_type, source))

    return tuple(replacements)


def CheckOriginalRaw(pair, envelopes):
    """Prove coherent mutation cannot be rejected merely by the canonical raw receipt codec."""

    _, proof, scan, _ = pair

    for operation, outcome in (("version", proof.outcome), ("scan", scan.outcome)):
        VerifyArtifactReplay(envelopes[operation]["artifact_metadata"],
            outcome.raw_result.stdout, outcome.raw_result.stderr)


def test_ActualCapturesUseCanonicalGrammarWithoutCurrentStageAuthorityOrModelIo(
    actual_pair, monkeypatch
):
    """Historical verification reads retained evidence without consulting any live boundary."""

    owned, proof, scan, records = actual_pair
    before = ReadCaptures(actual_pair)
    stages = (proof.stage.root, scan.stage.root)
    actual_open, actual_stat, actual_resolve = Path.open, Path.stat, Path.resolve
    calls = []

    def Canonical(metadata, prepared, stage):
        """Call the real SDK grammar verifier and observe both original operation calls."""

        VerifySyntheticImagePayloadReplay(metadata, prepared, stage)
        calls.append(metadata["grant"]["plan"]["operation"])

    def NoStageOpen(path, *arguments, **options):
        """Permit owning evidence reads while refusing any original stage file access."""

        assert not any(path.is_relative_to(stage) for stage in stages), (
            "Historical replay attempted a current original-stage file read"
        )

        return actual_open(path, *arguments, **options)

    def NoStageStat(path, *arguments, **options):
        """Permit evidence integrity checks while refusing current original-stage observations."""

        assert not any(path.is_relative_to(stage) for stage in stages), (
            "Historical replay attempted a current original-stage physical observation"
        )

        return actual_stat(path, *arguments, **options)

    def NoStageResolve(path, *arguments, **options):
        """Permit owning-workspace resolution while refusing current original-stage resolution."""

        assert not any(path.is_relative_to(stage) for stage in stages), (
            "Historical replay attempted current original-stage path resolution"
        )

        return actual_resolve(path, *arguments, **options)

    def Forbidden(*arguments, **options):
        """Refuse any current principal, grant, process or model application/persistence."""

        raise AssertionError("Historical image replay crossed a live authority or write boundary")

    monkeypatch.setattr(synthetic_images, "VerifySyntheticImagePayloadReplay", Canonical)
    monkeypatch.setattr(Path, "open", NoStageOpen)
    monkeypatch.setattr(Path, "stat", NoStageStat)
    monkeypatch.setattr(Path, "resolve", NoStageResolve)
    monkeypatch.setattr(ArtifactStage, "Verify", Forbidden)
    monkeypatch.setattr(LocalScopeStore, "Open", Forbidden)
    monkeypatch.setattr(ArtifactPolicyEngine, "Authorize", Forbidden)
    monkeypatch.setattr(GovernedArtifactExecutor, "Execute", Forbidden)
    monkeypatch.setattr(GovernedArtifactExecutor, "CurrentContext", Forbidden)
    monkeypatch.setattr(GovernedArtifactExecutor, "ValidatePairAcceptanceFresh", Forbidden)
    monkeypatch.setattr(ModelState, "Apply", Forbidden)
    monkeypatch.setattr(LocalModelStore, "Open", Forbidden)
    monkeypatch.setattr(LocalModelStore, "Save", Forbidden)
    replay = VerifySyntheticTrivyImageReplay(records, owned.root)
    assert calls == ["version", "scan"] and replay.provenance.source_id == "synthetic.trivy", (
        "Canonical replay must delegate both exact original operation payloads to the owning SDK"
    )
    assert ReadCaptures(actual_pair) == before and set(replay.records) == set(records), (
        "Read-only verification must preserve every original record and detached capture fact"
    )


@pytest.mark.parametrize("operation", ["version", "scan"])
@pytest.mark.parametrize("mutation", [
    "directory-alias", "file-alias", "runtime-alias", "path-alias", "request-parameter",
])
def test_CoherentlyRehashedActualFactoryClaimsCannotPassCanonicalConsumer(
    actual_pair, operation, mutation
):
    """Rebound pair hashes and source attribution cannot replace closed SDK grammar."""

    owned = actual_pair[0]
    envelopes = ReadCaptures(actual_pair)
    envelope = envelopes[operation]
    stage = envelope["stage_payload"]
    partitions = stage["partitions"]

    if mutation == "directory-alias":
        partitions[2]["directory_identity"] = deepcopy(partitions[0]["directory_identity"])

    elif mutation == "file-alias":
        partitions[2]["identities"][0][1][:2] = partitions[0]["identities"][0][1][:2]

    elif mutation == "runtime-alias":
        stage["executable_identity"][:2] = partitions[1]["identities"][0][1][:2]

    elif mutation == "path-alias":
        stage["root"] += "\\." if "\\" in stage["root"] else "/."

    else:
        envelope["prepared_payload"]["invocation"]["request"]["parameters"][PRIVATE] = PRIVATE

    RebindCapture(envelope)

    if operation == "version":
        version = envelopes["version"]
        prerequisite = Digest({key: version[key] for key in (
            "artifact_metadata", "prepared_payload", "stage_payload")})

        for value in (envelopes["scan"]["prepared_payload"],
                      envelopes["scan"]["artifact_metadata"]["grant"]["plan"]):
            value["version_grant_id"] = version["artifact_metadata"]["acceptance"]["grant_id"]
            value["version_prerequisite_sha256"] = prerequisite

        RebindCapture(envelopes["scan"])

    CheckOriginalRaw(actual_pair, envelopes)
    changed = StoreCaptures(actual_pair, envelopes)

    with pytest.raises(ValueError):
        VerifySyntheticTrivyImageReplay(changed, owned.root)


@pytest.mark.parametrize("alias", ["directory", "copied-file", "root-to-copy"])
def test_CanonicalHistoricalPairRejectsCoherentCrossStageCopyAliases(actual_pair, alias):
    """Individually valid captures must retain disjoint original physical copied material."""

    owned = actual_pair[0]
    envelopes = ReadCaptures(actual_pair)
    original = envelopes["version"]["stage_payload"]
    stage = envelopes["scan"]["stage_payload"]

    if alias == "directory":
        stage["partitions"][2]["directory_identity"] = deepcopy(
            original["partitions"][0]["directory_identity"])

    elif alias == "copied-file":
        stage["partitions"][0]["identities"][0][1][:2] = (
            original["partitions"][0]["identities"][0][1][:2])

    else:
        stage["root_identity"] = original["partitions"][0]["identities"][0][1][:2]

    RebindCapture(envelopes["scan"])
    CheckOriginalRaw(actual_pair, envelopes)
    VerifySyntheticImagePayloadReplay(envelopes["scan"]["artifact_metadata"],
        envelopes["scan"]["prepared_payload"], stage)
    changed = StoreCaptures(actual_pair, envelopes)
    initial = LocalModelStore(owned.root).Open()

    with pytest.raises(ValueError, match="original capture facts"):
        VerifySyntheticTrivyImageReplay(changed, owned.root)

    assert LocalModelStore(owned.root).Open() == initial, (
        "Historical pair refusal cannot grant model authority or alter retained state"
    )


def test_CanonicalHistoricalPairRejectsSameMarkerDeviceInodeWithDifferentLaterFacts(actual_pair):
    """Original marker device/inode reuse cannot hide behind different size or timestamp fields."""

    owned = actual_pair[0]
    envelopes = ReadCaptures(actual_pair)
    version_marker = envelopes["version"]["artifact_metadata"]["acceptance"]["marker_identity"]
    scan_marker = envelopes["scan"]["artifact_metadata"]["acceptance"]["marker_identity"]
    assert version_marker[2:] != scan_marker[2:], (
        "Actual separately launched operations must supply different later marker observations"
    )
    scan_marker[:2] = version_marker[:2]
    CheckOriginalRaw(actual_pair, envelopes)
    changed = StoreCaptures(actual_pair, envelopes)

    with pytest.raises(ValueError, match="original capture facts"):
        VerifySyntheticTrivyImageReplay(changed, owned.root)


@pytest.mark.parametrize("role,media,bound", [
    ("provider-version", "application/json", 16 * 1024),
    ("provider-version-stderr", "text/plain", 16 * 1024),
    ("artifact-version-receipt", "application/json", 1024 * 1024),
    ("artifact-scan-receipt", "application/json", 1024 * 1024),
])
def test_ActualOwningManifestBudgetPrecedesEagerBlobRead(actual_pair, monkeypatch, role, media,
                                                       bound):
    """A forged small wrapper cannot conceal a different actual oversized owning manifest."""

    owned, _, _, records = actual_pair
    store = LocalEvidenceStore(owned.root / "evidence")
    original_record = next(record for record in records if record.reference.role == role)
    oversized = store.Put(b"x" * (bound + 1), role, media, original_record.provenance)
    forged = copy(original_record)
    object.__setattr__(forged, "evidence_id", oversized.evidence_id)
    changed = tuple(forged if record.reference.role == role else record for record in records)
    actual_read = LocalEvidenceStore.Read

    def NoOversizedRead(self, reference):
        """Refuse allocation if an oversized actual role reference bypasses the consumer facade."""

        assert reference.role != role or reference.size_bytes <= bound, (
            "Actual oversized owning-manifest reference reached eager blob allocation"
        )

        return actual_read(self, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", NoOversizedRead)

    with pytest.raises(ValueError, match="role budget"):
        VerifySyntheticTrivyImageReplay(changed, owned.root)


@pytest.mark.parametrize("changes", [
    {"role": "artifact-input-manifest"}, {"media_type": "text/plain"},
])
def test_CanonicalWrongRoleOrMediaRefusesBeforeAnyRawRead(actual_pair, monkeypatch, changes):
    """Selected-material roles and relabelled media cannot cross the exact six-role boundary."""

    owned, _, _, records = actual_pair
    original = next(record for record in records if record.reference.role == "stdout")
    forged = copy(original)
    object.__setattr__(forged, "reference", replace(original.reference, **changes))
    changed = (forged, *(record for record in records if record.reference.role != "stdout"))

    def Forbidden(*arguments, **options):
        """Trip any raw byte read before exact role/media admission."""

        raise AssertionError("Wrong image role or media reached a raw evidence read")

    monkeypatch.setattr(LocalEvidenceStore, "Read", Forbidden)

    with pytest.raises(ValueError):
        VerifySyntheticTrivyImageReplay(changed, owned.root)


@pytest.mark.parametrize("window", ["equal", "decreasing", "malformed"])
def test_CaptureProducerRetainsActualIncreasingCollectionWindow(actual_pair, window):
    """Typed real original SDK objects cannot replace missing or contradictory clock readings."""

    _, _, scan, _ = actual_pair
    start, finish = scan.started_at, scan.finished_at

    if window == "equal":
        finish = start

    elif window == "decreasing":
        start, finish = finish, start

    else:
        start = "unsupported collection reading"

    with pytest.raises(ValueError):
        ImageOperationCapture(scan.outcome, scan.prepared, scan.stage, start, finish)


def test_CaptureProducerDetachesOriginalSdkPayloadsWithoutChangingSource(actual_pair):
    """A caller-mutated envelope cannot alter any original operation facts or later captures."""

    _, _, scan, _ = actual_pair
    original = scan.Envelope()
    changed = scan.Envelope()
    changed["prepared_payload"]["environment"]["PATH"] = PRIVATE
    assert scan.Envelope() == original and scan.Provenance().invocation_sha256 == (
        scan.outcome.grant.plan.invocation_sha256
    ), "Capture production must retain original facts without caller aliases or authority claims"


def test_ActualTighterSdkCaptureCeilingsRemainAcceptedWithoutNativePromotion(tmp_path):
    """Real smaller SDK limits remain valid within unchanged original evidence-role ceilings."""

    owned = CreateOwnedImage(tmp_path)
    proof, scan, records = asyncio.run(CollectOwnedImagePair(owned,
        resources=ExecutionResources(max_stdout_bytes=8 * 1024, max_stderr_bytes=8 * 1024)))
    proposal, delta = ApplyVerifiedSyntheticTrivyImages(LocalModelStore(owned.root).Open(), proof,
        scan.outcome, scan.prepared, scan.stage, records, owned.root,
        context_provider=lambda: owned.context)
    assert delta.revision == proposal.revision == 1 and all(
        item.provenance[0].source_id == "synthetic.trivy" for item in proposal.objects
    ), "SDK capture ceilings cannot relabel fixture proposals as native detection"
    assert VerifySyntheticTrivyImageReplay(records, owned.root).provenance.source_id == (
        "synthetic.trivy"
    ), "Canonical replay must accept these actual original SDK captures with tighter limits"
    assert LocalModelStore(owned.root).Open().revision == 0, (
        "In-memory live proposal and historical replay perform no caller-owned persistence"
    )
