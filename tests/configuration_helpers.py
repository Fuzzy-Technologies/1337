# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned configuration stages with independent source fixtures and explicit artifact authority."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from artifact_helpers import AT

from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.artifact_inputs import (
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactSelection,
    ArtifactStage,
)
from fuzzy1337.artifact_policy import ArtifactPolicyContext, ProfileCapability
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scope import AuthorizationState, LocalScopeStore, ScopeAuthorization, ScopeSnapshot
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPOSITORY_ROOT / "tests/contract/fixtures/configuration_profiles"
PRODUCER = REPOSITORY_ROOT / "tests/fixtures/configuration_scan/producer.py"
ORACLE = json.loads((CORPUS / "oracle.v1.json").read_bytes())
CASES = {case["case_id"]: case for case in ORACLE["cases"]}
FAMILY = "owned-synthetic-configuration-wire-v1"


def OwnedConfiguration(
    tmp_path: Path,
    case_id: str = "dockerfile.root-user",
    *,
    policy_payload: bytes | None = None,
    source_payload: bytes | None = None,
    producer: Path = PRODUCER,
    profile: ArtifactProfile | None = None,
    input_name: str | None = None,
):
    """Capture explicit source/worker/policy selections without auto-granting the SDK operation."""

    root = tmp_path.resolve()
    workspace = root / "workspace"
    LocalWorkspaceStore(workspace).Create(
        WorkspaceConfiguration("Owned configuration acceptance"), "owned-config"
    )
    case = CASES[case_id]
    selected = case["inputs"][0]
    source = root / "selected-configuration"
    source.write_bytes((CORPUS / selected["fixture"]).read_bytes()
                       if source_payload is None else source_payload)
    policy_file = root / "selected-policy.json"
    policy_file.write_bytes(json.dumps({
        "schema_version": 1, "fixture_id": FAMILY, "provider_version": "0.75.0-synthetic",
        "profile_id": case["profile_id"], "case_id": case_id,
    }, sort_keys=True, separators=(",", ":")).encode()
        if policy_payload is None else policy_payload)
    profile = ArtifactProfile(case["profile_id"]) if profile is None else profile
    stage = ArtifactStage.Create(
        workspace / "configuration-stage", profile,
        ArtifactReadConsent("owner:test", "read:owned-configuration"),
        (ArtifactSelection(input_name or selected["logical_path"], source),),
        ArtifactSelection("executable", Path(sys.executable).resolve()), "0.75.0-synthetic",
        material=(ArtifactSelection("policy.json", policy_file),),
        producer=ArtifactSelection("producer.py", producer),
    )
    target = stage.input.manifest.Target()
    scope = LocalScopeStore(workspace).Create(ScopeSnapshot(
        "config-scope", "owned-config", targets=(target,), allow=(target,),
        authorization=ScopeAuthorization(
            AuthorizationState.GRANTED, "attester:test", "consent:scan-config", AT.isoformat(),
            (AT + timedelta(hours=1)).isoformat(),
        ),
    ))
    capability = ProfileCapability(profile)
    policy = ImpactPolicy("config-policy", permissions=(
        CapabilityPermission(capability.identifier, capability.adapter_id, ImpactLevel.SAFE),
    ))
    context = ArtifactPolicyContext(scope, policy, "owner:test")

    return workspace, stage, context


def LiveConfiguration(tmp_path: Path, case_id: str = "dockerfile.root-user"):
    """Initialize actual workflow model and current owner consent for one independent fixture."""

    from datetime import UTC, datetime

    from fuzzy1337.configuration_workflow import ConfigurationScanSelection
    from fuzzy1337.model import LocalModelStore

    workspace, stage, context = OwnedConfiguration(tmp_path, case_id)
    now = datetime.now(UTC)
    store = LocalScopeStore(workspace)
    scope = store.Save(replace(context.scope, authorization=replace(
        context.scope.authorization, authority_reference="owner:test",
        valid_from=(now - timedelta(minutes=1)).isoformat(),
        valid_until=(now + timedelta(hours=1)).isoformat())))
    LocalModelStore(workspace).Create()
    source = tmp_path.resolve() / "selected-configuration"
    material = tmp_path.resolve() / "selected-policy.json"
    selection = ConfigurationScanSelection(stage.input.manifest.profile,
        stage.input.manifest.files[0].name, source, Path(sys.executable).resolve(), PRODUCER,
        material, stage.input.consent)

    return workspace, selection, replace(context, scope=scope)
