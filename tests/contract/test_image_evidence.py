# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exact synthetic image evidence/proof bindings and sanitized atomic refusal contracts."""

from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta
from traceback import format_exception

import pytest

from fuzzy1337 import images
from fuzzy1337.artifact_policy import ArtifactDeniedError, GovernedArtifactExecutor
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.image_evidence import VerifySavedStageShape
from fuzzy1337.images import ApplyVerifiedSyntheticTrivyImages, VerifySyntheticTrivyImageReplay
from fuzzy1337.model import CanonicalModelJson, LocalModelStore
from fuzzy1337.scope import AuthorizationState, LocalScopeStore
from tests.image_helpers import CollectOwnedImagePair, CreateOwnedImage

PRIVATE = "SYNTHETIC_PRIVATE_IMAGE_MARKER"


@pytest.fixture(scope="module")
def actual_pair(tmp_path_factory):
    """Acquire real reviewed VERSION/SCAN original facts once without fabricating acceptance."""

    owned = CreateOwnedImage(tmp_path_factory.mktemp("image-evidence"))
    proof, scan, records = asyncio.run(CollectOwnedImagePair(owned))

    return owned, proof, scan, records


def Apply(pair, records=Ellipsis, proof=Ellipsis):
    """Call the actual consumer with canonical original objects and explicit candidate records."""

    owned, original_proof, scan, original_records = pair

    return ApplyVerifiedSyntheticTrivyImages(LocalModelStore(owned.root).Open(),
        original_proof if proof is Ellipsis else proof, scan.outcome, scan.prepared, scan.stage,
        original_records if records is Ellipsis else records, owned.root,
        context_provider=lambda: owned.context)


def ReplaceRecord(pair, role, *, data=None, source_changes=None, media=None):
    """Store changed acquisition claims through the real immutable evidence owner."""

    owned, _, _, records = pair
    store = LocalEvidenceStore(owned.root / "evidence")
    original = next(item for item in records if item.reference.role == role)
    replacement = store.Put(store.Read(original.reference) if data is None else data,
        role, original.reference.media_type if media is None else media,
        replace(original.provenance, **(source_changes or {})))

    return tuple(replacement if item.reference.role == role else item for item in records)


@pytest.mark.parametrize("role", ["provider-version", "provider-version-stderr", "stdout",
    "stderr", "artifact-version-receipt", "artifact-scan-receipt"])
@pytest.mark.parametrize("changes", [
    {"workspace_id": "wrong-workspace"}, {"scope_reference": "scope:wrong"},
    {"source_id": "native.trivy"}, {"source_version": "2"},
    {"tool_version": "0.75.1-synthetic"}, {"invocation_sha256": "0" * 64},
])
def test_EveryRoleRequiresExactOriginalAcquisitionAttribution(actual_pair, role, changes):
    """Content identity cannot substitute for original workspace/source/scope/operation facts."""

    changed = ReplaceRecord(actual_pair, role, source_changes=changes)
    original = LocalModelStore(actual_pair[0].root).Open()

    with pytest.raises(ValueError, match="interpretation refused"):
        Apply(actual_pair, changed)

    assert LocalModelStore(actual_pair[0].root).Open() == original, (
        "Refusal must not save any proposal"
    )


@pytest.mark.parametrize("role", ["provider-version", "provider-version-stderr", "stdout",
    "stderr", "artifact-version-receipt", "artifact-scan-receipt"])
def test_EveryOriginalStreamAndReceiptCannotBeReplacedByOtherBytes(actual_pair, role):
    """All six stored role bytes must match the exact original operation, including empty stderr."""

    changed = ReplaceRecord(actual_pair, role, data=PRIVATE.encode())

    with pytest.raises(ValueError) as caught:
        Apply(actual_pair, changed)

    assert PRIVATE not in "".join(format_exception(caught.value)), (
        "Rejected private wire bytes must not appear in the exception or chained decoder traceback"
    )


@pytest.mark.parametrize("role", ["artifact-version-receipt", "artifact-scan-receipt"])
@pytest.mark.parametrize("mutation", ["unknown", "schema", "metadata-schema", "request",
    "stage", "operation", "family", "start", "finish", "duplicate", "nonfinite", "bom"])
def test_CaptureEnvelopeShapeAndOriginalBindingAreStrict(actual_pair, role, mutation):
    """Detached payloads, strict JSON and actual collection windows are inseparable."""

    owned, _, _, records = actual_pair
    record = next(item for item in records if item.reference.role == role)
    original = LocalEvidenceStore(owned.root / "evidence").Read(record.reference)
    envelope = json.loads(original)

    if mutation == "unknown":
        envelope[PRIVATE] = True

    elif mutation == "schema":
        envelope["schema_version"] = True

    elif mutation == "metadata-schema":
        envelope["artifact_metadata"]["schema_version"] = 1

    elif mutation == "request":
        envelope["prepared_payload"]["environment"]["PRIVATE"] = PRIVATE

    elif mutation == "stage":
        envelope["stage_payload"]["root"] = "/" + PRIVATE

    elif mutation == "operation":
        envelope["prepared_payload"]["operation"] = "scan" if role == (
            "artifact-version-receipt"
        ) else "version"

    elif mutation == "family":
        envelope["prepared_payload"]["producer_family"] = PRIVATE

    elif mutation == "start":
        envelope["collection_started_at"] = "2020-01-01T00:00:00Z"

    elif mutation == "finish":
        envelope["collection_finished_at"] = "2020-01-01T00:00:00Z"

    payload = CanonicalModelJson(envelope)

    if mutation == "duplicate":
        payload = b'{"schema_version":1,"schema_version":1,"private":"' + PRIVATE.encode() + b'"}'

    elif mutation == "nonfinite":
        payload = b'{"private":NaN}'

    elif mutation == "bom":
        payload = b"\xef\xbb\xbf" + original

    changed = ReplaceRecord(actual_pair, role, data=payload)

    with pytest.raises(ValueError) as caught:
        Apply(actual_pair, changed)

    assert PRIVATE not in "".join(format_exception(caught.value)), (
        "Capture diagnostics must be sanitized"
    )


@pytest.mark.parametrize("records", [(), None, "content-reference-only"])
def test_MissingOrUntypedEvidenceCannotEnterLiveOrHistoricalBoundary(actual_pair, records):
    """Historical and live verification require exact immutable acquisition manifests."""

    owned = actual_pair[0]

    with pytest.raises(ValueError):
        Apply(actual_pair, records)

    with pytest.raises(ValueError):
        VerifySyntheticTrivyImageReplay(records, owned.root)


@pytest.mark.parametrize("proof", [None, {}, True, "asserted-version"])
def test_LiveInterpretationRequiresOriginalTypedVersionPrerequisite(actual_pair, proof):
    """A version label, approval flag or absent proof cannot replace original executed facts."""

    with pytest.raises(ValueError, match="interpretation refused"):
        Apply(actual_pair, proof=proof)


@pytest.mark.parametrize("mutation", ["root-bool", "executable-short", "partition-count",
    "consent-field", "consent-type", "directory-type", "identity-count", "identity-name",
    "identity-type", "identity-size"])
def test_SavedPhysicalAndReadConsentShapeRemainsStrictWithoutFilesystemInspection(
    actual_pair, mutation
):
    """An original capture supplies the pure shape oracle; unsupported saved mutations refuse."""

    _, _, scan, _ = actual_pair
    stage = deepcopy(scan.Envelope()["stage_payload"])

    if mutation == "root-bool":
        stage["root_identity"][0] = True

    elif mutation == "executable-short":
        stage["executable_identity"] = [1, 2]

    elif mutation == "partition-count":
        stage["partitions"] = []

    elif mutation == "consent-field":
        stage["partitions"][0]["consent"]["extra"] = PRIVATE

    elif mutation == "consent-type":
        stage["partitions"][0]["consent"]["actor_ref"] = False

    elif mutation == "directory-type":
        stage["partitions"][0]["directory_identity"][0] = "1"

    elif mutation == "identity-count":
        stage["partitions"][0]["identities"] = []

    elif mutation == "identity-name":
        stage["partitions"][0]["identities"][0][0] = "other.tar"

    elif mutation == "identity-type":
        stage["partitions"][0]["identities"][0] = "asserted-identity"

    else:
        stage["partitions"][0]["identities"][0][1][2] += 1

    with pytest.raises(ValueError):
        VerifySavedStageShape(stage, scan.outcome.manifests)


def test_LiveImporterHasNoEvidenceReadsAfterCanonicalFinalPairBarrier(actual_pair, monkeypatch):
    """The original SDK barrier precedes pure application with no subsequent evidence I/O."""

    original = GovernedArtifactExecutor.ValidatePairAcceptanceFresh

    def Barrier(self, version, scan, context_provider):
        """Run real canonical acceptance, then forbid any later evidence reads."""

        original(self, version, scan, context_provider)

        def Forbidden(*arguments, **options):
            """Detect evidence I/O after the final acceptance barrier."""

            raise AssertionError("Evidence I/O occurred after final pair acceptance")

        monkeypatch.setattr(LocalEvidenceStore, "Read", Forbidden)

    monkeypatch.setattr(GovernedArtifactExecutor, "ValidatePairAcceptanceFresh", Barrier)
    proposal, delta = Apply(actual_pair)
    assert delta.revision == proposal.revision == 1, "Only pure accepted candidates may be applied"


def test_ExpiryAtFinalPairBarrierDeniesOriginalVersionEvenWhenScanStillValid(
    actual_pair, monkeypatch
):
    """Advance only the canonical SDK decision clock after real immutable candidate verification."""

    _, proof, scan, _ = actual_pair
    version_expiry = datetime.fromisoformat(proof.outcome.grant.valid_until)
    scan_expiry = datetime.fromisoformat(scan.outcome.grant.valid_until)
    assert version_expiry < scan_expiry, (
        "Actual independent grants must retain original issue times"
    )
    original = GovernedArtifactExecutor.ValidatePairAcceptanceFresh

    def AtExpiry(self, version, scan_tuple, context_provider):
        """Exercise the real SDK time refusal without manufacturing an acceptance flag."""

        self._clock = lambda: version_expiry + min(
            timedelta(microseconds=1), (scan_expiry - version_expiry) / 2
        )

        return original(self, version, scan_tuple, context_provider)

    monkeypatch.setattr(GovernedArtifactExecutor, "ValidatePairAcceptanceFresh", AtExpiry)

    with pytest.raises(ArtifactDeniedError):
        Apply(actual_pair)


def test_ActualRevocationDuringCandidateConstructionFailsFinalLiveAcceptance(tmp_path, monkeypatch):
    """Revoke persisted scope after expensive interpretation but before final SDK checks."""

    owned = CreateOwnedImage(tmp_path)
    proof, scan, records = asyncio.run(CollectOwnedImagePair(owned))
    original = images.SyntheticTrivyCandidates

    def Revoke(*arguments, **options):
        """Construct genuine candidates first, then revoke the actual persisted authority."""

        candidates = original(*arguments, **options)
        store = LocalScopeStore(owned.root)
        current = store.Open("image-scope")
        store.Save(replace(current, authorization=replace(current.authorization,
            state=AuthorizationState.REVOKED)))

        return candidates

    monkeypatch.setattr(images, "SyntheticTrivyCandidates", Revoke)

    with pytest.raises(ArtifactDeniedError):
        ApplyVerifiedSyntheticTrivyImages(LocalModelStore(owned.root).Open(), proof,
            scan.outcome, scan.prepared, scan.stage, records, owned.root,
            context_provider=lambda: owned.context)

    assert LocalModelStore(owned.root).Open().revision == 0, (
        "Late revocation must discard all candidates"
    )
