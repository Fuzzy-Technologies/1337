# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned portable artifact fixtures using only fixed reviewed producer/runtime bytes."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fuzzy1337 import artifact_fixture_worker
from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.artifact_inputs import (
    ArtifactOperation,
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactSelection,
    ArtifactStage,
)
from fuzzy1337.artifact_policy import (
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
    ArtifactVersionProof,
    PrepareArtifact,
    ProfileCapability,
)
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scope import AuthorizationState, LocalScopeStore, ScopeAuthorization, ScopeSnapshot
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

AT = datetime(2026, 10, 13, tzinfo=timezone.utc)


def OwnedArtifact(
    tmp_path: Path,
    *,
    mode: str = "success",
    profile: ArtifactProfile = ArtifactProfile.SYNTHETIC_IMAGE,
    policy_payload: bytes | None = None,
):
    """Create explicitly selected owned inputs and same-store approved scope fixtures."""

    root = tmp_path.resolve()
    workspace = root / "workspace"
    LocalWorkspaceStore(workspace).Create(
        WorkspaceConfiguration("Owned artifact fixture"), "owned-artifact"
    )
    source = root / "selected-source"
    source.write_bytes(
        b"FROM scratch\n" if profile == ArtifactProfile.SYNTHETIC_DOCKERFILE else b"owned-input"
    )
    policy_file = root / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "fixture_id": "owned-artifact-lifecycle-v1",
                "mode": mode,
            }
        )
    )
    if policy_payload is not None:
        policy_file.write_bytes(policy_payload)

    name = (
        "image.tar"
        if profile == ArtifactProfile.SYNTHETIC_IMAGE
        else (
            "Dockerfile" if profile == ArtifactProfile.SYNTHETIC_DOCKERFILE else "documents/a.yaml"
        )
    )
    stage = ArtifactStage.Create(
        workspace / "artifacts-stage",
        profile,
        ArtifactReadConsent("owner:test", "read:selected-files"),
        (ArtifactSelection(name, source),),
        ArtifactSelection("executable", Path(sys.executable).resolve()),
        "0.75.0-synthetic",
        material=(ArtifactSelection("policy.json", policy_file),),
        producer=ArtifactSelection("producer.py", Path(artifact_fixture_worker.__file__).resolve()),
    )
    target = stage.input.manifest.Target()
    scope = LocalScopeStore(workspace).Create(
        ScopeSnapshot(
            "artifact-scope",
            "owned-artifact",
            targets=(target,),
            allow=(target,),
            authorization=ScopeAuthorization(
                AuthorizationState.GRANTED,
                "attester:test",
                "consent:scan",
                AT.isoformat(),
                (AT + timedelta(hours=1)).isoformat(),
            ),
        )
    )
    capability = ProfileCapability(profile)
    policy = ImpactPolicy(
        "artifact-policy",
        permissions=(
            CapabilityPermission(capability.identifier, capability.adapter_id, ImpactLevel.SAFE),
        ),
    )
    context = ArtifactPolicyContext(scope, policy, "owner:test")
    prepared = PrepareArtifact(stage, workspace)
    grant = ArtifactPolicyEngine().Authorize(prepared, stage, context, at=AT)

    return workspace, stage, prepared, context, grant


def OwnedImageArtifact(
    tmp_path: Path,
    *,
    operation: ArtifactOperation = ArtifactOperation.VERSION,
    scenario: str = "success",
    stage_name: str = "image-stage",
    workspace: Path | None = None,
    policy_payload: bytes | None = None,
    version_proof: ArtifactVersionProof | None = None,
):
    """Stage the unchanged independently reviewed image worker and exact selected fixture bytes."""

    fixtures = Path(__file__).resolve().parent / "fixtures/image_scan"
    specification = importlib.util.spec_from_file_location(
        "owned_artifact_image_fixture", fixtures / "fixture_image.py"
    )
    assert specification is not None and specification.loader is not None, (
        "Owned image fixture must have a concrete import loader"
    )
    fixture = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(fixture)
    image, material = fixture.CreateFixture(
        tmp_path.resolve() / (stage_name + "-selection"), scenario
    )

    if policy_payload is not None:
        material.write_bytes(policy_payload)

    fresh_workspace = workspace is None

    if workspace is None:
        workspace = tmp_path.resolve() / "workspace"
        LocalWorkspaceStore(workspace).Create(
            WorkspaceConfiguration("Owned image artifact fixture"), "owned-artifact"
        )

    profile = ArtifactProfile.SYNTHETIC_IMAGE
    stage = ArtifactStage.Create(
        workspace / stage_name, profile,
        ArtifactReadConsent("owner:test", "read:selected-image-files"),
        (ArtifactSelection("image.tar", image),),
        ArtifactSelection("executable", Path(sys.executable).resolve()), "0.75.0-synthetic",
        material=(ArtifactSelection("policy.json", material),),
        producer=ArtifactSelection("producer.py", fixtures / "producer.py"),
    )
    scope_store = LocalScopeStore(workspace)

    if fresh_workspace:
        target = stage.input.manifest.Target()
        scope = scope_store.Create(
            ScopeSnapshot(
                "artifact-scope", "owned-artifact", targets=(target,), allow=(target,),
                authorization=ScopeAuthorization(
                    AuthorizationState.GRANTED, "attester:test", "consent:scan", AT.isoformat(),
                    (AT + timedelta(hours=1)).isoformat(),
                ),
            )
        )

    else:
        scope = scope_store.Open("artifact-scope")

    capability = ProfileCapability(profile)
    policy = ImpactPolicy(
        "artifact-policy", permissions=(
            CapabilityPermission(capability.identifier, capability.adapter_id, ImpactLevel.SAFE),
        ),
    )
    context = ArtifactPolicyContext(scope, policy, "owner:test")
    prepared = PrepareArtifact(stage, workspace, operation=operation, version_proof=version_proof)
    grant = ArtifactPolicyEngine().Authorize(prepared, stage, context, at=AT)

    return workspace, stage, prepared, context, grant
