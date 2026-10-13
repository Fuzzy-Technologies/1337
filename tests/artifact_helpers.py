# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned portable artifact fixtures using only fixed reviewed producer/runtime bytes."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fuzzy1337 import artifact_fixture_worker
from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.artifact_inputs import (
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactSelection,
    ArtifactStage,
)
from fuzzy1337.artifact_policy import (
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
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
