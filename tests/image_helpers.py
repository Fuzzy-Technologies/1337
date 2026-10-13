# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual owned image-operation fixtures over the independently reviewed archive/worker/oracle."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.artifact_inputs import (
    ArtifactFile,
    ArtifactManifest,
    ArtifactOperation,
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactRole,
)
from fuzzy1337.artifact_policy import (
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
    ArtifactVersionProof,
    GovernedArtifactExecutor,
    PrepareArtifact,
)
from fuzzy1337.evidence import EvidenceRecord, LocalEvidenceStore
from fuzzy1337.image_evidence import ImageOperationCapture
from fuzzy1337.image_workflow import ImageScanSelection
from fuzzy1337.model import CanonicalModelJson, LocalModelStore
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scope import AuthorizationState, LocalScopeStore, ScopeAuthorization, ScopeSnapshot
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "image_scan"
ORACLE = json.loads((FIXTURE_ROOT / "oracle.json").read_bytes())


@dataclass(frozen=True, slots=True)
class OwnedImage:
    """One explicitly owned source selection and current same-store canonical authority."""

    root: Path
    selection: ImageScanSelection
    context: ArtifactPolicyContext


def CreateOwnedImage(tmp_path: Path, scenario: str = "success") -> OwnedImage:
    """Create exact reviewed synthetic fixtures without changing their source or oracle.

    Args:
        tmp_path: Explicit test-owned scratch directory.
        scenario: Enumerated inert scenario accepted by the reviewed archive builder.

    Returns:
        Existing initialized workspace, selected fixture files and approved ARTIFACT scope.
    """

    module_spec = importlib.util.spec_from_file_location(
        "owned_image_archive_fixture", FIXTURE_ROOT / "fixture_image.py"
    )
    assert module_spec is not None and module_spec.loader is not None, "Owned fixture is importable"
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    selected = tmp_path.resolve() / "selected image fixture"
    archive, material = module.CreateFixture(selected, scenario)
    root = tmp_path.resolve() / "owned image workspace"
    workspace = LocalWorkspaceStore(root).Create(
        WorkspaceConfiguration("Owned synthetic image workflow"), "owned-images"
    )
    LocalModelStore(root).Create()
    selection = ImageScanSelection(archive, Path(sys.executable).resolve(),
        (FIXTURE_ROOT / "producer.py").resolve(), material,
        ArtifactReadConsent("owner:image-test", "consent:explicit-selected-files"))
    target = ArtifactManifest(ArtifactProfile.SYNTHETIC_IMAGE, ArtifactRole.INPUT,
        (ArtifactFile("image.tar", archive.stat().st_size,
            hashlib.sha256(archive.read_bytes()).hexdigest()),)).Target()
    now = datetime.now(UTC)
    scope = LocalScopeStore(root).Create(ScopeSnapshot("image-scope", workspace.workspace_id,
        targets=(target,), allow=(target,), authorization=ScopeAuthorization(
            AuthorizationState.GRANTED, "owner:image-test", "consent:image-scan",
            (now - timedelta(seconds=1)).isoformat(), (now + timedelta(hours=1)).isoformat())))
    policy = ImpactPolicy("synthetic-image-safe-v1", permissions=(CapabilityPermission(
        "image.archive-vulnerabilities", "synthetic.trivy", ImpactLevel.SAFE),))

    return OwnedImage(root, selection, ArtifactPolicyContext(scope, policy, "owner:image-test"))


async def CollectOwnedImagePair(owned: OwnedImage) -> tuple[
    ArtifactVersionProof, ImageOperationCapture, tuple[EvidenceRecord, ...],
]:
    """Run actual separate canonical VERSION/SCAN phases and retain their six exact records.

    Args:
        owned: Explicit reviewed fixture and persisted approved authority.

    Returns:
        Original VERSION proof, original SCAN capture and exact immutable six-role evidence tuple.
    """

    facade = GovernedArtifactExecutor(owned.root)
    engine = ArtifactPolicyEngine()
    proof = None
    captures = []
    records = []
    evidence = LocalEvidenceStore(owned.root / "evidence")

    for operation in (ArtifactOperation.VERSION, ArtifactOperation.SCAN):
        stage = owned.selection.Stage(owned.root / ("stage-" + operation.value + "-" + uuid4().hex))
        prepared = PrepareArtifact(stage, owned.root, operation=operation,
            timeout_seconds=3 if operation is ArtifactOperation.VERSION else 1, version_proof=proof)
        grant = engine.Authorize(prepared, stage, owned.context, at=datetime.now(UTC))
        started_at = datetime.now(UTC).isoformat()
        outcome = await facade.Execute(prepared, stage, grant, lambda: owned.context)
        capture = ImageOperationCapture(outcome, prepared, stage, started_at,
            datetime.now(UTC).isoformat())
        captures.append(capture)
        roles = ("provider-version", "provider-version-stderr", "artifact-version-receipt") if (
            operation is ArtifactOperation.VERSION
        ) else ("stdout", "stderr", "artifact-scan-receipt")
        streams = (outcome.raw_result.stdout, outcome.raw_result.stderr,
            CanonicalModelJson(capture.Envelope()))

        for role, data in zip(roles, streams, strict=True):
            records.append(evidence.Put(data, role,
                "text/plain" if role.endswith("stderr") or role == "stderr" else "application/json",
                capture.Provenance()))

        if operation is ArtifactOperation.VERSION:
            facade.ValidateAcceptanceFresh(outcome, prepared, stage, lambda: owned.context)
            proof = ArtifactVersionProof(outcome, prepared, stage)

    assert proof is not None, "Actual VERSION must precede SCAN"

    return proof, captures[-1], tuple(records)
