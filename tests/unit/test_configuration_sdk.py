# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Configuration SDK family, selected-material, request and approval fail-closed boundaries."""

from __future__ import annotations

import json
import traceback
from dataclasses import replace

import pytest
from artifact_helpers import AT
from configuration_helpers import CASES, FAMILY, OwnedConfiguration

from fuzzy1337 import artifact_fixture_worker
from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.artifact_inputs import ArtifactOperation, ArtifactProfile
from fuzzy1337.artifact_policy import (
    ArtifactDenialReason,
    ArtifactDeniedError,
    ArtifactPolicyEngine,
    PrepareArtifact,
)
from fuzzy1337.executors import ExecutionResources


@pytest.mark.parametrize("case_id", list(CASES), ids=list(CASES))
def test_RegisteredConfigurationUsesExactFamilyProfileAndSafeRequest(tmp_path, case_id):
    """Each independent source has distinct canonical input identity and exact closed argv."""

    workspace, stage, context = OwnedConfiguration(tmp_path, case_id)
    prepared = PrepareArtifact(stage, workspace)
    grant = ArtifactPolicyEngine().Authorize(prepared, stage, context, at=AT)
    assert prepared.producer_family == FAMILY and grant.plan.producer_family == FAMILY, (
        "Configuration authority must retain its reviewed source family, never image/lifecycle"
    )
    assert prepared.operation is ArtifactOperation.SCAN and prepared.version_proof is None, (
        "Configuration registration exposes only SCAN without borrowing image VERSION proof"
    )
    assert prepared.capability.adapter_id == "synthetic.trivy" and (
        prepared.capability.maximum_impact is ImpactLevel.SAFE
    ), "Configuration registration must remain explicitly synthetic and bounded to SAFE"
    scanner = "dockerfile" if case_id.startswith("dockerfile.") else "kubernetes"
    expected = (str(stage.executable), "-I", "-S", str(stage.root / "scanner/producer.py"),
        "--fixture-policy", str(stage.root / "material/policy.json"), "--cache-dir",
        str(stage.root / "scratch/cache"), "--config=", "config", "--misconfig-scanners", scanner,
        "--cache-backend", "memory", "--format", "json", "--disable-telemetry",
        "--skip-check-update", "--skip-version-check", "--ignorefile=", "--exit-code", "0",
        "--timeout", "30s", str(stage.root / "input"))
    assert prepared.invocation.argv == expected, "Config factory changed its fixed owned argv"
    assert prepared.resources.max_stdout_bytes == prepared.resources.max_stderr_bytes == 16384, (
        "Configuration must not inherit the larger image/lifecycle stream ceilings"
    )
    assert grant.plan.target_reference == stage.input.manifest.Target().Reference() and (
        grant.plan.input_manifest_sha256 != stage.input.manifest.files[0].sha256
    ), "Scope targets must use canonical whole manifest identity, never source-file SHA"


@pytest.mark.parametrize("change", [
    "bool", "float", "constant", "duplicate", "integer", "surrogate", "deep", "utf8",
    "extra", "missing", "list", "family", "version", "profile", "case", "case-type", "large",
])
def test_MalformedConfigurationMaterialDeniesBeforeApproval(tmp_path, change):
    """Strict material keeps parser families distinct and never discloses private data."""

    private = "PRIVATE_CONFIGURATION_POLICY_VALUE"
    policy = {"schema_version": 1, "fixture_id": FAMILY, "provider_version": "0.75.0-synthetic",
              "profile_id": "synthetic.dockerfile-offline.v1", "case_id": "dockerfile.root-user"}
    changes = {"bool": ("schema_version", True), "float": ("schema_version", 1.0),
        "extra": (private, private), "family": ("fixture_id", "owned-artifact-lifecycle-v1"),
        "version": ("provider_version", "0.75.0"), "profile": ("profile_id", "trivy.dockerfile"),
        "case": ("case_id", private), "case-type": ("case_id", []),
        "surrogate": ("case_id", "\ud800")}

    if change in changes:
        field, value = changes[change]
        policy[field] = value
        payload = json.dumps(policy).encode()

    elif change == "missing":
        del policy["case_id"]
        payload = json.dumps(policy).encode()

    else:
        payload = {"constant": b'{"schema_version":NaN}',
            "duplicate": b'{"schema_version":1,"schema_version":1}',
            "integer": b'{"schema_version":' + b"9" * 100 + b"}",
            "deep": b"[" * 200 + b"0" + b"]" * 200, "utf8": b"\xff", "list": b"[]",
            "large": b" " * 1025}[change]

    workspace, stage, _ = OwnedConfiguration(tmp_path, policy_payload=payload)

    with pytest.raises(ArtifactDeniedError) as error:
        PrepareArtifact(stage, workspace)

    assert error.value.reason is ArtifactDenialReason.MATERIAL_CHANGED, (
        "Unsupported configuration policy must deny material rather than produce authority"
    )
    assert private not in "".join(traceback.format_exception(error.value)), (
        "Sanitized SDK material denial must not retain caller policy values in its traceback"
    )


@pytest.mark.parametrize("change", ["changed-source", "wrong-case", "large-source", "nested-name"])
def test_SelectedSourceCannotCrossClosedCaseOrSelectionBoundary(tmp_path, change):
    """Exact admitted source bytes, size and one flat logical name are mandatory before approval."""

    options = {}

    if change == "changed-source":
        options["source_payload"] = b"FROM owned.invalid/unknown\nUSER root\n"

    elif change == "wrong-case":
        options["policy_payload"] = json.dumps({"schema_version": 1, "fixture_id": FAMILY,
            "provider_version": "0.75.0-synthetic", "profile_id": "synthetic.dockerfile-offline.v1",
            "case_id": "dockerfile.non-root-user"}).encode()

    elif change == "large-source":
        options["source_payload"] = b"a" * 4097

    else:
        options["input_name"] = "nested/Dockerfile"

    workspace, stage, _ = OwnedConfiguration(tmp_path, **options)

    with pytest.raises(ArtifactDeniedError) as error:
        PrepareArtifact(stage, workspace)

    assert error.value.reason is ArtifactDenialReason.MATERIAL_CHANGED, (
        "Unknown source or expanded selection cannot acquire a configuration SCAN grant"
    )


@pytest.mark.parametrize("profile", [ArtifactProfile.DOCKERFILE, ArtifactProfile.KUBERNETES,
                                    ArtifactProfile.SYNTHETIC_IMAGE])
def test_ConfigurationProducerCannotGrantNativeOrImageProfiles(tmp_path, profile):
    """A frozen owned worker hash does not authorize native compatibility or another wire family."""

    workspace, stage, _ = OwnedConfiguration(tmp_path, profile=profile)

    with pytest.raises(ArtifactDeniedError) as error:
        PrepareArtifact(stage, workspace)

    expected = ArtifactDenialReason.UNTRUSTED_PRODUCER if profile is (
        ArtifactProfile.SYNTHETIC_IMAGE
    ) else ArtifactDenialReason.NATIVE_UNAVAILABLE
    assert error.value.reason is expected, "Cross-family producer/profile authorization escaped"


def test_LifecyclePolicyCannotBecomeConfigurationWireRegistration(tmp_path):
    """Reviewed legacy lifecycle remains distinct and cannot consume configuration material."""

    from pathlib import Path

    workspace, stage, _ = OwnedConfiguration(
        tmp_path, producer=Path(artifact_fixture_worker.__file__).resolve()
    )

    with pytest.raises(ArtifactDeniedError) as error:
        PrepareArtifact(stage, workspace)

    assert error.value.reason is ArtifactDenialReason.MATERIAL_CHANGED, (
        "Lifecycle producer must retain its original policy parser and independent family"
    )


@pytest.mark.parametrize("operation", [ArtifactOperation.VERSION, "scan"])
def test_ConfigurationRejectsVersionAndUntypedOperation(tmp_path, operation):
    """Configuration refuses unsupported VERSION and unchecked operation text."""

    workspace, stage, _ = OwnedConfiguration(tmp_path)

    with pytest.raises((ArtifactDeniedError, ValueError)):
        PrepareArtifact(stage, workspace, operation=operation)


@pytest.mark.parametrize("timeout", [True, 0, 61, 1.0])
def test_ConfigurationDeadlineCannotInheritLifecycleBounds(tmp_path, timeout):
    """Config timeout spelling remains integer1..60 before any launch or approval."""

    workspace, stage, _ = OwnedConfiguration(tmp_path)

    with pytest.raises(ValueError):
        PrepareArtifact(stage, workspace, timeout_seconds=timeout)


@pytest.mark.parametrize("resources", [ExecutionResources(max_stdout_bytes=16385),
    ExecutionResources(max_stderr_bytes=16385), ExecutionResources(terminate_grace_seconds=6)])
def test_ConfigurationCaptureAndCleanupCannotInheritLifecycleBounds(tmp_path, resources):
    """Caller resource selections may tighten but cannot expand the configuration envelope."""

    workspace, stage, _ = OwnedConfiguration(tmp_path)

    with pytest.raises(ValueError):
        PrepareArtifact(stage, workspace, resources=resources)


def test_ConfigurationDoesNotAcceptTypedImageVersionPrerequisite(tmp_path):
    """An extraneous prerequisite cannot supply configuration authorization."""

    workspace, stage, _ = OwnedConfiguration(tmp_path)

    with pytest.raises(ValueError):
        PrepareArtifact(stage, workspace, version_proof=object())


@pytest.mark.parametrize("change", ["profile", "family", "operation", "argv", "environment"])
def test_ConfigurationRequestAndGrantCannotBeSubstituted(tmp_path, change):
    """Immutable config approvals bind exact family, profile, operation, argv and environment."""

    workspace, stage, context = OwnedConfiguration(tmp_path)
    prepared = PrepareArtifact(stage, workspace)
    engine = ArtifactPolicyEngine()
    grant = engine.Authorize(prepared, stage, context, at=AT)

    if change in {"profile", "family", "operation"}:
        changes = {"profile": {"profile": ArtifactProfile.SYNTHETIC_IMAGE},
                   "family": {"producer_family": "owned-synthetic-image-wire-v1"},
                   "operation": {"operation": ArtifactOperation.VERSION}}

        with pytest.raises(ValueError):
            replace(grant.plan, **changes[change])

        return

    if change == "argv":
        prepared = replace(prepared, invocation=replace(
            prepared.invocation, argv=prepared.invocation.argv + ("--quiet",)
        ))

    else:
        prepared = replace(prepared, environment=dict(prepared.environment, PRIVATE="changed"))

    with pytest.raises(ArtifactDeniedError):
        engine.Validate(grant, prepared, stage, context, at=AT)
