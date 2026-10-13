# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Closed synthetic artifact grants with fresh authority and immutable raw-result receipts."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import math
import os
import re
import sys
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Any, cast

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterInvocation,
    AdapterRequest,
    ExecutionState,
    ImpactLevel,
    SerializeContract,
)
from fuzzy1337.artifact_fixture_worker import (
    FixtureFields,
    ParseFixturePolicy,
    RejectFixtureConstant,
)
from fuzzy1337.artifact_inputs import (
    ArtifactManifest,
    ArtifactOperation,
    ArtifactPathInfo,
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactRole,
    ArtifactStage,
    FreezePhysicalIdentity,
    PhysicalIdentity,
    ReadArtifactFile,
)
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    ExecutionResources,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutionResult,
    LocalExecutor,
)
from fuzzy1337.executors.contracts import (
    FreezeEnvironment,
    RequireIdentifier,
    RequireReference,
    UniqueIdentifiers,
)
from fuzzy1337.executors.local import EventCallback
from fuzzy1337.policy import Digest, ImpactPolicy, RequireDigest, RequireTime
from fuzzy1337.scope import LocalScopeStore, NormalizeTime, ScopeSnapshot
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceFields

# Source updates and matching LF byte identities require independent source review.
_REVIEWED_PRODUCERS = frozenset(
    {
        "2a07b2d817b1294305bedae203b8ae7f968c2eb27838d873becd0d29071ac91d",
    }
)
_LIFECYCLE_FAMILY = "owned-artifact-lifecycle-v1"
_IMAGE_FAMILY = "owned-synthetic-image-wire-v1"
_IMAGE_PRODUCER_SHA256 = "afb5b935f151fb9780feee28eda0fbf13ddc6d721e6f7cc55e753aa32e4cfa53"
_CONFIGURATION_FAMILY = "owned-synthetic-configuration-wire-v1"
_CONFIGURATION_PRODUCER_SHA256 = (
    "af34b374fa49ce3048d3a7821df5ad8370849240a786dabc7311e14322476eb6"
)
_CONFIGURATION_PROFILES = frozenset(
    {ArtifactProfile.SYNTHETIC_DOCKERFILE, ArtifactProfile.SYNTHETIC_KUBERNETES}
)
_CONFIGURATION_CASES = {
    "dockerfile.root-user": (ArtifactProfile.SYNTHETIC_DOCKERFILE, "Dockerfile", 264,
        "3f0114052cfa7d826abf315fededac339851d4c1991b5c2447bfdf01882323b7"),
    "dockerfile.non-root-user": (ArtifactProfile.SYNTHETIC_DOCKERFILE, "Dockerfile", 271,
        "1712d2480103b5881b6df078d5471d12a2c9e0d1d7f6cb96270aa7751943231c"),
    "kubernetes.privileged-container": (ArtifactProfile.SYNTHETIC_KUBERNETES, "unsafe.yaml", 410,
        "63b77e1703ab126b9f5283daa5091f750af8ddab3e3b8e24eed63ea36888dd1d"),
    "kubernetes.non-privileged-container": (ArtifactProfile.SYNTHETIC_KUBERNETES, "safe.yaml", 409,
        "52e45b63f8aec99934dcfddd90d1f3b417111ccabe4514c262e3e8cf443f729f"),
    "kubernetes.second-document": (ArtifactProfile.SYNTHETIC_KUBERNETES, "multi.yaml", 823,
        "8cd7163a754dc1a0c29ce1e54fc29cb68a5a0a2b71c79d03a3c54d9caf363b1f"),
}
_LEGACY_PRODUCERS = _REVIEWED_PRODUCERS | {
    "6cec015e044f290f2f5f48d04156fe1430ba679ee629505100e192459d10ec7a",
    "48626d65b8e4d092859ed948507b8162a5e276b70599469e65fe8abc179a6bb1",
}
_LEGACY_PLAN_FIELDS = frozenset(
    {
        "owner_ref", "profile", "provider_version", "input_manifest_sha256",
        "scanner_manifest_sha256", "material_manifest_sha256", "workspace_id",
        "scope_reference", "scope_revision", "scope_sha256", "policy_reference",
        "policy_revision", "policy_sha256", "target_reference", "stage_sha256",
        "stage_lease", "request_sha256", "invocation_sha256", "granted_privileges",
        "intent_sha256",
    }
)
_IMAGE_DATABASE_METADATA = {
    "Version": 2,
    "UpdatedAt": "2026-10-01T00:00:00Z",
    "NextUpdate": "2026-10-02T00:00:00Z",
    "DownloadedAt": "2026-10-01T01:00:00Z",
}
_SYNTHETIC_PROFILES = frozenset(
    {
        ArtifactProfile.SYNTHETIC_IMAGE,
        ArtifactProfile.SYNTHETIC_DOCKERFILE,
        ArtifactProfile.SYNTHETIC_KUBERNETES,
    }
)
_IMPACT_ORDER = {impact: index for index, impact in enumerate(ImpactLevel)}
_CAPABILITIES = {
    ArtifactProfile.IMAGE: "image.archive-vulnerabilities",
    ArtifactProfile.SYNTHETIC_IMAGE: "image.archive-vulnerabilities",
    ArtifactProfile.DOCKERFILE: "config.dockerfile-misconfigurations",
    ArtifactProfile.SYNTHETIC_DOCKERFILE: "config.dockerfile-misconfigurations",
    ArtifactProfile.KUBERNETES: "config.kubernetes-misconfigurations",
    ArtifactProfile.SYNTHETIC_KUBERNETES: "config.kubernetes-misconfigurations",
}

__all__ = [
    "ArtifactDenialReason",
    "ArtifactOperation",
    "ArtifactDeniedError",
    "ArtifactPolicyContext",
    "PreparedArtifact",
    "ArtifactPlan",
    "ArtifactGrant",
    "ArtifactAcceptance",
    "ArtifactExecutionOutcome",
    "ArtifactVersionProof",
    "ArtifactPolicyEngine",
    "GovernedArtifactExecutor",
    "PrepareArtifact",
    "ArtifactStagePayload",
    "ProfileCapability",
    "VerifyArtifactReplay",
    "VerifySyntheticImagePayloadReplay",
]


class ArtifactDenialReason(StrEnum):
    """Sanitized refusal reason without reflecting selected paths, flags or stream contents."""

    NATIVE_UNAVAILABLE = "native_unavailable"
    UNTRUSTED_PRODUCER = "untrusted_producer"
    UNTRUSTED_RUNTIME = "untrusted_runtime"
    MATERIAL_CHANGED = "material_changed"
    AUTHORITY_DENIED = "authority_denied"
    IMPACT_DENIED = "impact_denied"
    PLAN_CHANGED = "plan_changed"
    GRANT_EXPIRED = "grant_expired"
    EXECUTION_FAILED = "execution_failed"
    STORAGE = "storage"
    CONTEXT_INVALID = "context_invalid"


class ArtifactDeniedError(PermissionError):
    """Deny an artifact launch or normalization without changing actual process facts."""

    def __init__(self, reason: ArtifactDenialReason) -> None:
        """Retain only one typed sanitized refusal reason.

        Args:
            reason: Exact artifact boundary refusal classification.
        """

        self.reason = reason
        super().__init__("Artifact operation denied: " + reason.value)


@dataclass(frozen=True, slots=True)
class ArtifactPolicyContext:
    """Current same-store scope, operator impact policy and explicit executing owner metadata."""

    scope: ScopeSnapshot
    policy: ImpactPolicy
    owner_ref: str

    def __post_init__(self) -> None:
        """Require typed current authority without treating references as authentication."""

        if not isinstance(self.scope, ScopeSnapshot) or not isinstance(self.policy, ImpactPolicy):
            raise ValueError("artifact context requires existing scope and policy records")

        RequireReference(self.owner_ref, "artifact owner")

        if len(self.owner_ref) > 4096:
            raise ValueError("artifact owner reference is oversized")


def ProfileCapability(profile: ArtifactProfile) -> CapabilityDescriptor:
    """Return closed profile metadata without granting or proving native execution.

    Args:
        profile: One explicit Experimental profile identity.

    Returns:
        SAFE capability metadata; native profiles remain non-authorizable.

    Raises:
        ValueError: The profile is outside the closed catalog.
    """

    if not isinstance(profile, ArtifactProfile):
        raise ValueError("artifact capability requires a closed profile")

    provider = "synthetic.trivy" if profile in _SYNTHETIC_PROFILES else "native.trivy"

    return CapabilityDescriptor(_CAPABILITIES[profile], provider, ImpactLevel.SAFE)


def ValidateArtifactProfile(stage: ArtifactStage) -> str:
    """Derive one reviewed family without generic caller command or hash registration.

    Args:
        stage: Explicit selected-byte stage, independently verified by the request factory.

    Returns:
        Source-owned family; its profile, policy and operation dispatcher remain closed.
    """

    profile = stage.input.manifest.profile

    if profile not in _SYNTHETIC_PROFILES:
        raise ArtifactDeniedError(ArtifactDenialReason.NATIVE_UNAVAILABLE)

    if sys.implementation.name != "cpython" or stage.executable != Path(sys.executable).resolve():
        raise ArtifactDeniedError(ArtifactDenialReason.UNTRUSTED_RUNTIME)

    scanner = {item.name: item for item in stage.scanner.manifest.files}

    if set(scanner) != {"executable", "producer.py"}:
        raise ArtifactDeniedError(ArtifactDenialReason.UNTRUSTED_PRODUCER)

    producer_sha256 = scanner["producer.py"].sha256

    if producer_sha256 in _REVIEWED_PRODUCERS:
        family = _LIFECYCLE_FAMILY

    elif producer_sha256 == _IMAGE_PRODUCER_SHA256 and profile == ArtifactProfile.SYNTHETIC_IMAGE:
        family = _IMAGE_FAMILY

    elif producer_sha256 == _CONFIGURATION_PRODUCER_SHA256 and profile in _CONFIGURATION_PROFILES:
        family = _CONFIGURATION_FAMILY

    else:
        raise ArtifactDeniedError(ArtifactDenialReason.UNTRUSTED_PRODUCER)

    if stage.version != "0.75.0-synthetic":
        raise ArtifactDeniedError(ArtifactDenialReason.UNTRUSTED_PRODUCER)

    names = tuple(item.name for item in stage.input.manifest.files)

    if profile == ArtifactProfile.SYNTHETIC_IMAGE and names != ("image.tar",):
        raise ArtifactDeniedError(ArtifactDenialReason.MATERIAL_CHANGED)

    if family == _IMAGE_FAMILY and stage.input.manifest.files[0].size_bytes > 128 * 1024:
        raise ArtifactDeniedError(ArtifactDenialReason.MATERIAL_CHANGED)

    if family == _CONFIGURATION_FAMILY and (
        len(names) != 1 or stage.input.manifest.files[0].size_bytes > 4096
        or "/" in names[0]
    ):
        raise ArtifactDeniedError(ArtifactDenialReason.MATERIAL_CHANGED)

    if profile == ArtifactProfile.SYNTHETIC_DOCKERFILE and names != ("Dockerfile",):
        raise ArtifactDeniedError(ArtifactDenialReason.MATERIAL_CHANGED)

    if profile == ArtifactProfile.SYNTHETIC_KUBERNETES and any(
        not name.endswith((".yaml", ".yml"))
        or Path(name).name.casefold()
        in {
            "trivy.yaml",
            "trivy.yml",
            "trivyignore.yaml",
            "trivyignore.yml",
            "chart.yaml",
            "chart.yml",
            "values.yaml",
            "values.yml",
            "kustomization.yaml",
            "kustomization.yml",
        }
        for name in names
    ):
        raise ArtifactDeniedError(ArtifactDenialReason.MATERIAL_CHANGED)

    if tuple(item.name for item in stage.material.manifest.files) != ("policy.json",):
        raise ArtifactDeniedError(ArtifactDenialReason.MATERIAL_CHANGED)

    policy_limit = 512 if family == _IMAGE_FAMILY else (
        1024 if family == _CONFIGURATION_FAMILY else 4096
    )

    if stage.material.manifest.files[0].size_bytes > policy_limit:
        raise ArtifactDeniedError(ArtifactDenialReason.MATERIAL_CHANGED)

    return family


def ConfigurationPolicyInteger(text: str) -> int:
    """Bound configuration policy integer decoding before schema interpretation.

    Args:
        text: JSON decoder integer spelling, never reflected in diagnostics.

    Returns:
        Finite integer; spellings longer than ten characters raise ValueError.
    """

    if len(text) > 10:
        raise ValueError("configuration policy integer exceeds its bound")

    return int(text)


def ParseConfigurationFixturePolicy(payload: bytes, manifest: ArtifactManifest) -> None:
    """Bind exact source-owned policy to one immutable selected configuration file.

    Args:
        payload: At most 1 KiB of explicit configuration material, never worker code.
        manifest: Canonical input manifest; whole-manifest and file hashes stay distinct.

    Raises:
        ValueError: Closed family, profile, case, fields or actual selected bytes differ.
    """

    if not isinstance(payload, bytes) or not 0 < len(payload) <= 1024:
        raise ValueError("configuration policy exceeds its closed byte bound")

    try:
        policy = json.loads(
            payload.decode("utf-8"), object_pairs_hook=FixtureFields,
            parse_int=ConfigurationPolicyInteger, parse_float=RejectFixtureConstant,
            parse_constant=RejectFixtureConstant,
        )

    except (UnicodeError, ValueError, RecursionError, OverflowError):
        raise ValueError("configuration policy requires strict bounded UTF-8 JSON") from None

    if not isinstance(policy, dict) or set(policy) != {
        "schema_version", "fixture_id", "provider_version", "profile_id", "case_id",
    } or type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
        raise ValueError("configuration policy requires the exact owned schema")

    if any(type(policy[key]) is not str for key in (
        "fixture_id", "provider_version", "profile_id", "case_id",
    )) or policy["fixture_id"] != _CONFIGURATION_FAMILY or (
        policy["provider_version"] != "0.75.0-synthetic"
        or policy["case_id"] not in _CONFIGURATION_CASES
    ):
        raise ValueError("configuration policy requires the exact owned family and case")

    profile, name, size_bytes, sha256 = _CONFIGURATION_CASES[policy["case_id"]]

    if (
        manifest.role is not ArtifactRole.INPUT or manifest.profile is not profile
        or policy["profile_id"] != profile.value or len(manifest.files) != 1
        or manifest.files[0].name != name or manifest.files[0].size_bytes != size_bytes
        or manifest.files[0].sha256 != sha256
    ):
        raise ValueError("configuration policy differs from its exact selected source")


def ParseImageFixturePolicy(payload: bytes) -> None:
    """Verify exact reviewed image material without importing or executing the staged worker.

    Args:
        payload: Explicit selected policy bytes bounded to 512 bytes.

    Raises:
        ValueError: Strict fields/types/UTF-8/database fixture facts do not match.
    """

    if not isinstance(payload, bytes) or len(payload) > 512:
        raise ValueError("image fixture policy exceeds its closed byte bound")

    try:
        policy = json.loads(
            payload.decode("utf-8"), object_pairs_hook=FixtureFields,
            parse_constant=RejectFixtureConstant,
        )

    except (UnicodeError, ValueError, RecursionError):
        raise ValueError("image fixture policy requires strict finite UTF-8 JSON") from None

    expected = {
        "schema_version": 1,
        "fixture_id": _IMAGE_FAMILY,
        "provider_version": "0.75.0-synthetic",
        "database_metadata": _IMAGE_DATABASE_METADATA,
    }

    if (
        not isinstance(policy, dict)
        or policy != expected
        or type(policy["schema_version"]) is not int
        or type(policy["database_metadata"]["Version"]) is not int
    ):
        raise ValueError("image fixture policy does not match the closed reviewed family")


def ControlledArtifactEnvironment(stage: ArtifactStage) -> Mapping[str, str]:
    """Replace inherited overlays with bound owned paths and minimal trusted platform values.

    Args:
        stage: Single-run owned stage whose scratch is separate from immutable inputs.

    Returns:
        Frozen exact environment overrides, including bound trusted Windows runtime values.
    """

    return ArtifactEnvironment(stage.root, os.environ.get("SYSTEMROOT", ""),
                               os.environ.get("WINDIR", ""))


def ArtifactEnvironment(
    root: PurePath, system_root: str, windows_directory: str,
) -> Mapping[str, str]:
    """Build fixed scratch overlays from explicit original platform values without host lookup.

    Args:
        root: Original operation's absolute path in its original path flavor.
        system_root: Original factory-observed SYSTEMROOT value, without refreshed trust.
        windows_directory: Original factory-observed WINDIR value, without refreshed trust.

    Returns:
        Frozen canonical environment; recorded platform values remain operator attribution.
    """

    scratch = root / "scratch"
    environment = {
        "PATH": "",
        "PATHEXT": "",
        "LANG": "C",
        "LC_ALL": "C",
        "COMSPEC": "",
        "HOME": str(scratch / "home"),
        "USERPROFILE": str(scratch / "home"),
        "TMP": str(scratch / "temp"),
        "TEMP": str(scratch / "temp"),
        "TMPDIR": str(scratch / "temp"),
        "XDG_CONFIG_HOME": str(scratch / "config"),
        "XDG_CACHE_HOME": str(scratch / "cache"),
        "SYSTEMROOT": system_root,
        "WINDIR": windows_directory,
    }

    return FreezeEnvironment(environment)


def ParseObservedImageVersion(payload: bytes) -> None:
    """Require actual strict successful VERSION wire before richer SCAN authority.

    Args:
        payload: Original actual VERSION stdout bytes, at most 16 KiB.

    Raises:
        ArtifactDeniedError: Unsupported/ambiguous/malformed observed fixture version.
    """

    if not isinstance(payload, bytes) or len(payload) > 16 * 1024:
        raise ArtifactDeniedError(ArtifactDenialReason.MATERIAL_CHANGED)

    try:
        version = json.loads(
            payload.decode("utf-8"), object_pairs_hook=FixtureFields,
            parse_constant=RejectFixtureConstant,
        )

    except (UnicodeError, ValueError, RecursionError):
        raise ArtifactDeniedError(ArtifactDenialReason.MATERIAL_CHANGED) from None

    expected = {
        "Version": "0.75.0-synthetic", "VulnerabilityDB": _IMAGE_DATABASE_METADATA,
        "Fixture": "synthetic; no Trivy binary or vulnerability database",
    }

    if (
        not isinstance(version, dict) or version != expected
        or type(version["VulnerabilityDB"]["Version"]) is not int
    ):
        raise ArtifactDeniedError(ArtifactDenialReason.MATERIAL_CHANGED)


def ValidatePrerequisiteType(
    operation: ArtifactOperation, family: str, proof: ArtifactVersionProof | None
) -> None:
    """Require an original typed proof only for richer SCAN before any material read.

    Args:
        operation: Explicit previously validated SCAN or VERSION operation.
        family: Source-owned derived producer family.
        proof: Original typed VERSION prerequisite or absent lifecycle/VERSION value.

    Raises:
        ValueError: Missing, wrong-type or extraneous prerequisite.
    """

    needs_version = family == _IMAGE_FAMILY and operation == ArtifactOperation.SCAN

    if needs_version != (type(proof) is ArtifactVersionProof):
        raise ValueError("richer image SCAN requires its original typed VERSION prerequisite")

    if not needs_version and proof is not None:
        raise ValueError("VERSION and lifecycle SCAN do not accept a VERSION prerequisite")


@dataclass(frozen=True, slots=True)
class PreparedArtifact:
    """Exact fixed factory request including fields omitted by legacy InvocationDigest."""

    workspace_root: Path
    stage_lease: str
    invocation: AdapterInvocation
    capability: CapabilityDescriptor
    workspace: str
    environment: Mapping[str, str]
    resources: ExecutionResources
    operation: ArtifactOperation = ArtifactOperation.SCAN
    producer_family: str = _LIFECYCLE_FAMILY
    version_proof: ArtifactVersionProof | None = None

    def __post_init__(self) -> None:
        """Freeze controlled environment values and require typed request observations."""

        if (
            not isinstance(self.workspace_root, Path)
            or not self.workspace_root.is_absolute()
            or not isinstance(self.invocation, AdapterInvocation)
            or not isinstance(self.capability, CapabilityDescriptor)
            or not isinstance(self.resources, ExecutionResources)
            or not isinstance(self.environment, Mapping)
            or not isinstance(self.operation, ArtifactOperation)
            or not isinstance(self.producer_family, str)
            or self.producer_family not in {
                _LIFECYCLE_FAMILY, _IMAGE_FAMILY, _CONFIGURATION_FAMILY,
            }
            or (
                self.operation == ArtifactOperation.VERSION
                and self.producer_family != _IMAGE_FAMILY
            )
        ):
            raise ValueError("prepared artifact requires typed immutable request fields")

        ValidatePrerequisiteType(self.operation, self.producer_family, self.version_proof)

        RequireReference(self.stage_lease, "prepared artifact lease")
        object.__setattr__(self, "environment", FreezeEnvironment(self.environment))

    def Payload(self) -> dict[str, object]:
        """Render all immutable process-affecting request fields.

        Returns:
            Full request binding without an authorization envelope.
        """

        return {
            "workspace_root": str(self.workspace_root),
            "stage_lease": self.stage_lease,
            "invocation": self.invocation,
            "capability": self.capability,
            "workspace": self.workspace,
            "environment": dict(self.environment),
            "resources": self.resources,
            "operation": self.operation,
            "producer_family": self.producer_family,
            **self.VersionBindings(),
        }

    def VersionBindings(self) -> dict[str, object]:
        """Bind the original richer VERSION prerequisite without copying raw streams.

        Returns:
            Three exact nullable fields; only richer SCAN contains original VERSION identities.
        """

        proof = self.version_proof

        return {
            "version_run_id": None if proof is None else proof.outcome.run_id,
            "version_grant_id": None if proof is None else (
                proof.outcome.grant.authorization.authorization_id
            ),
            "version_prerequisite_sha256": None if proof is None else proof.Digest(),
        }

    def Request(self, grant: ArtifactGrant) -> LocalExecutionRequest:
        """Bridge only a matching artifact grant into the existing executor envelope.

        Args:
            grant: Same-plan artifact grant; launch freshness is checked by the facade.

        Returns:
            Exact SDK request; raw LocalExecutor alone is not the artifact policy facade.

        Raises:
            ArtifactDeniedError: Grant request identity is different.
            ValueError: A network or other grant type is supplied.
        """

        if not isinstance(grant, ArtifactGrant):
            raise ValueError("artifact execution requires an ArtifactGrant")

        if grant.plan.request_sha256 != Digest(self.Payload()):
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        return LocalExecutionRequest(
            self.invocation,
            self.capability,
            grant.authorization,
            self.workspace,
            self.environment,
            self.resources,
        )


def ValidateArtifactResources(
    family: str, operation: ArtifactOperation, timeout_seconds: int, resources: ExecutionResources,
) -> None:
    """Check the shared closed live/detached deadline, stream and cleanup bounds.

    Args:
        family: Previously selected source-owned lifecycle or richer image family.
        operation: Previously checked VERSION or SCAN operation.
        timeout_seconds: Exact VERSION or finite family-specific SCAN process bound.
        resources: Finite output and cleanup budgets, independently limited by this factory.

    Raises:
        ValueError: Numeric declarations exceed the original closed factory bounds.
    """

    timeout_max = 60 if family in {_IMAGE_FAMILY, _CONFIGURATION_FAMILY} else 300
    stdout_max = 4 * 1024 * 1024 if family == _IMAGE_FAMILY else 16 * 1024 * 1024
    stderr_max = 1024 * 1024 if family == _IMAGE_FAMILY else 16 * 1024 * 1024

    if family == _CONFIGURATION_FAMILY:
        stdout_max = stderr_max = 16 * 1024

    if operation == ArtifactOperation.VERSION:
        stdout_max = stderr_max = 16 * 1024

    if (
        type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= timeout_max
        or (operation == ArtifactOperation.VERSION and timeout_seconds != 3)
        or not isinstance(resources, ExecutionResources)
        or resources.max_stdout_bytes > stdout_max
        or resources.max_stderr_bytes > stderr_max
        or resources.terminate_grace_seconds > 5
    ):
        raise ValueError("artifact timeout/output/cleanup resources exceed fixed profile bounds")


def ArtifactArgv(
    root: PurePath, executable: PurePath, profile: ArtifactProfile, family: str,
    operation: ArtifactOperation, timeout_seconds: int,
) -> tuple[str, ...]:
    """Build the source-owned command from validated original facts without I/O.

    Args:
        root: Original absolute operation root, preserving its original path flavor.
        executable: Original selected executable path, without current-host discovery.
        profile: Validated closed synthetic artifact profile.
        family: Validated source-owned lifecycle or richer image family.
        operation: Validated VERSION or SCAN operation.
        timeout_seconds: Already validated exact executor deadline.

    Returns:
        Exact original fixed argv; constructing it supplies no execution authority.
    """

    cache = str(root / "scratch/cache")
    prefix = (
        str(executable),
        "-I",
        "-S",
        str(root / "scanner/producer.py"),
        "--fixture-policy",
        str(root / "material/policy.json"),
        "--cache-dir",
        cache,
        "--config=",
    )
    common = (
        "--cache-backend",
        "memory",
        "--format",
        "json",
        "--disable-telemetry",
        "--skip-check-update",
        "--skip-version-check",
        "--ignorefile=",
        "--exit-code",
        "0",
        "--timeout",
        f"{timeout_seconds}s",
    )

    argv: tuple[str, ...]

    if operation == ArtifactOperation.VERSION:
        argv = prefix + ("--version", "--format", "json")

    elif family == _IMAGE_FAMILY:
        argv = prefix + (
            "image", "--cache-backend", "memory", "--input", str(root / "input/image.tar"),
            "--format", "json", "--scanners", "vuln", "--disable-telemetry", "--offline-scan",
            "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
            "--skip-version-check", "--skip-vex-repo-update", "--ignorefile=", "--list-all-pkgs",
            "--exit-code", "0", "--no-progress", "--timeout", f"{timeout_seconds}s",
        )

    elif profile == ArtifactProfile.SYNTHETIC_IMAGE:
        argv = (
            prefix
            + (
                "image",
                "--input",
                str(root / "input/image.tar"),
                "--scanners",
                "vuln",
                "--offline-scan",
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-vex-repo-update",
                "--list-all-pkgs",
                "--no-progress",
            )
            + common
        )

    else:
        scanner = "dockerfile" if profile == ArtifactProfile.SYNTHETIC_DOCKERFILE else "kubernetes"
        argv = (
            prefix
            + ("config", "--misconfig-scanners", scanner)
            + common
            + (str(root / "input"),)
        )

    return argv


def BuildPreparedArtifact(
    stage: ArtifactStage,
    workspace_root: Path,
    timeout_seconds: int,
    resources: ExecutionResources,
    *,
    after_run: bool,
    operation: ArtifactOperation = ArtifactOperation.SCAN,
    version_proof: ArtifactVersionProof | None = None,
) -> PreparedArtifact:
    """Rebuild the only accepted command/environment/resource contract without launching.

    Args:
        stage: Closed reviewed synthetic stage; native profiles remain unavailable.
        workspace_root: Existing physical owned workspace enclosing the stage.
        timeout_seconds: Exact VERSION or finite family-specific SCAN process bound.
        resources: Finite output and cleanup budgets, independently limited by this factory.
        after_run: Verify bounded observed scratch outputs instead of requiring empty scratch.
        operation: Explicit SCAN default or independently staged reviewed image VERSION.
        version_proof: Actual original VERSION prerequisite for richer image SCAN only.

    Returns:
        Exact rebuilt fixed request; unavailable or changed material raises ArtifactDeniedError.
    """

    if not isinstance(stage, ArtifactStage) or not isinstance(workspace_root, Path):
        raise ValueError("artifact preparation requires a stage and owned workspace Path")

    family = ValidateArtifactProfile(stage)

    if not isinstance(operation, ArtifactOperation):
        raise ValueError("artifact preparation requires an explicit typed operation")

    if operation == ArtifactOperation.VERSION and family != _IMAGE_FAMILY:
        raise ArtifactDeniedError(ArtifactDenialReason.UNTRUSTED_PRODUCER)

    ValidatePrerequisiteType(operation, family, version_proof)
    ValidateArtifactResources(family, operation, timeout_seconds, resources)

    try:
        stage.Verify(after_run=after_run)

        with (stage.material.directory / "policy.json").open("rb") as policy_stream:
            policy = policy_stream.read(4097)

        if family == _IMAGE_FAMILY:
            ParseImageFixturePolicy(policy)

        elif family == _CONFIGURATION_FAMILY:
            ParseConfigurationFixturePolicy(policy, stage.input.manifest)

        else:
            ParseFixturePolicy(policy)

        stage.root.relative_to(workspace_root)
        LocalWorkspaceStore(workspace_root).Open()

    except ValueError:
        raise ArtifactDeniedError(ArtifactDenialReason.MATERIAL_CHANGED) from None

    profile = stage.input.manifest.profile
    capability = ProfileCapability(profile)
    argv = ArtifactArgv(stage.root, stage.executable, profile, family, operation, timeout_seconds)
    invocation = AdapterInvocation(
        capability.adapter_id,
        AdapterRequest(
            capability.identifier,
            stage.input.manifest.Target().Reference(),
            ImpactLevel.SAFE,
            {
                "profile": profile.value,
                "input_manifest_sha256": stage.input.manifest.Digest(),
                "operation": operation.value,
                "producer_family": family,
            },
        ),
        argv,
        timeout_seconds,
        stage.version,
    )

    return PreparedArtifact(
        workspace_root,
        stage.lease_id,
        invocation,
        capability,
        (stage.root / "scratch").relative_to(workspace_root).as_posix(),
        ControlledArtifactEnvironment(stage),
        resources,
        operation,
        family,
        version_proof,
    )


def PrepareArtifact(
    stage: ArtifactStage,
    workspace_root: Path,
    *,
    timeout_seconds: int | None = None,
    resources: ExecutionResources | None = None,
    operation: ArtifactOperation = ArtifactOperation.SCAN,
    version_proof: ArtifactVersionProof | None = None,
) -> PreparedArtifact:
    """Prepare one closed reviewed synthetic offline request with no process side effect.

    Args:
        stage: Fresh explicit-read-authorized stage with trusted runtime and producer bytes.
        workspace_root: Existing physical workspace enclosing the owned stage.
        timeout_seconds: Lifecycle SCAN defaults to 120; image/config SCAN to 30; VERSION to 3.
        resources: Family/operation capture ceilings; cleanup grace at most five seconds.
        operation: SCAN default, or reviewed richer image VERSION in a separate fresh stage.
        version_proof: Immutable accepted original VERSION, mandatory for richer image SCAN.

    Returns:
        Exact immutable request metadata; scope/policy approval remains necessary.

    Raises:
        ArtifactDeniedError: Native profile, untrusted runtime/producer or changed material.
        ValueError: Resource or structural inputs are unsupported.
        OSError: Selected material/workspace cannot be inspected.
    """

    if not isinstance(stage, ArtifactStage):
        raise ValueError("artifact preparation requires a typed stage")

    family = ValidateArtifactProfile(stage)

    if timeout_seconds is None:
        timeout_seconds = 3 if operation == ArtifactOperation.VERSION else (
            30 if family in {_IMAGE_FAMILY, _CONFIGURATION_FAMILY} else 120
        )

    if resources is None:
        if operation == ArtifactOperation.VERSION:
            resources = ExecutionResources(max_stdout_bytes=16 * 1024, max_stderr_bytes=16 * 1024)

        elif family == _IMAGE_FAMILY:
            resources = ExecutionResources(max_stderr_bytes=1024 * 1024)

        elif family == _CONFIGURATION_FAMILY:
            resources = ExecutionResources(max_stdout_bytes=16 * 1024, max_stderr_bytes=16 * 1024)

        else:
            resources = ExecutionResources()

    return BuildPreparedArtifact(
        stage,
        workspace_root,
        timeout_seconds,
        resources,
        after_run=False,
        operation=operation,
        version_proof=version_proof,
    )


def ArtifactStagePayload(stage: ArtifactStage) -> dict[str, object]:
    """Bind all immutable material, read receipts and physical single-run lease metadata.

    Args:
        stage: Original physical stage with role-separated selected-byte manifests.

    Returns:
        Non-secret exact physical/material/read-receipt binding for grant identity.
    """

    return {
        "root": str(stage.root),
        "lease": stage.lease_id,
        "root_identity": stage.root_identity,
        "executable": str(stage.executable),
        "executable_identity": stage.executable_identity,
        "version": stage.version,
        "partitions": [
            {
                "manifest": snapshot.manifest.ToDict(),
                "consent": snapshot.consent,
                "identities": snapshot.identities,
                "directory_identity": snapshot.directory_identity,
            }
            for snapshot in (stage.input, stage.scanner, stage.material)
        ],
    }


@dataclass(frozen=True, slots=True)
class ArtifactPlan:
    """Complete operator authority and request bindings; this plan grants nothing."""

    owner_ref: str
    profile: ArtifactProfile
    provider_version: str
    input_manifest_sha256: str
    scanner_manifest_sha256: str
    material_manifest_sha256: str
    workspace_id: str
    scope_reference: str
    scope_revision: int
    scope_sha256: str
    policy_reference: str
    policy_revision: int
    policy_sha256: str
    target_reference: str
    stage_sha256: str
    stage_lease: str
    request_sha256: str
    invocation_sha256: str
    granted_privileges: tuple[str, ...]
    operation: ArtifactOperation
    producer_family: str
    version_run_id: str | None
    version_grant_id: str | None
    version_prerequisite_sha256: str | None
    intent_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        """Digest every exact binding without inferring signatures or principal identity."""

        if (
            not isinstance(self.profile, ArtifactProfile)
            or self.profile not in _SYNTHETIC_PROFILES
            or self.provider_version != "0.75.0-synthetic"
            or not isinstance(self.operation, ArtifactOperation)
            or not isinstance(self.producer_family, str)
            or self.producer_family not in {
                _LIFECYCLE_FAMILY, _IMAGE_FAMILY, _CONFIGURATION_FAMILY,
            }
            or (
                self.producer_family == _IMAGE_FAMILY
                and self.profile != ArtifactProfile.SYNTHETIC_IMAGE
            )
            or (
                self.producer_family == _CONFIGURATION_FAMILY
                and self.profile not in _CONFIGURATION_PROFILES
            )
            or (
                self.operation == ArtifactOperation.VERSION
                and self.producer_family != _IMAGE_FAMILY
            )
        ):
            raise ValueError("artifact execution plan requires a reviewed synthetic profile")

        needs_version = (
            self.producer_family == _IMAGE_FAMILY and self.operation == ArtifactOperation.SCAN
        )
        prerequisite = (
            self.version_run_id, self.version_grant_id, self.version_prerequisite_sha256,
        )

        if needs_version:
            RequireReference(cast(str, self.version_run_id), "artifact VERSION prerequisite run")
            RequireReference(
                cast(str, self.version_grant_id), "artifact VERSION prerequisite grant"
            )
            RequireDigest(cast(str, self.version_prerequisite_sha256))

        elif any(value is not None for value in prerequisite):
            raise ValueError("VERSION and lifecycle SCAN prerequisite bindings must be null")

        RequireIdentifier(self.workspace_id, "artifact workspace")

        for value in (
            self.owner_ref,
            self.scope_reference,
            self.policy_reference,
            self.target_reference,
            self.stage_lease,
        ):
            RequireReference(value, "artifact plan reference")

        for name in (
            "input_manifest_sha256",
            "scanner_manifest_sha256",
            "material_manifest_sha256",
            "scope_sha256",
            "policy_sha256",
            "stage_sha256",
            "request_sha256",
            "invocation_sha256",
        ):
            RequireDigest(getattr(self, name))

        for revision in (self.scope_revision, self.policy_revision):
            if type(revision) is not int or revision < 0:
                raise ValueError("artifact authority revisions must be non-negative integers")

        object.__setattr__(
            self,
            "granted_privileges",
            UniqueIdentifiers(self.granted_privileges, "artifact privileges"),
        )

        object.__setattr__(
            self,
            "intent_sha256",
            Digest(
                {
                    item.name: getattr(self, item.name)
                    for item in fields(self)
                    if item.name != "intent_sha256"
                }
            ),
        )


@dataclass(frozen=True, slots=True)
class ArtifactGrant:
    """Artifact-only bounded metadata authority, independently refreshed at both boundaries."""

    plan: ArtifactPlan
    authorization: ExecutionAuthorization
    issued_at: str
    valid_until: str

    def __post_init__(self) -> None:
        """Require typed artifact authority with an increasing aware validity interval."""

        if not isinstance(self.plan, ArtifactPlan) or not isinstance(
            self.authorization, ExecutionAuthorization
        ):
            raise ValueError("artifact grant requires artifact plan and executor envelope")

        object.__setattr__(self, "issued_at", NormalizeTime(self.issued_at))
        object.__setattr__(self, "valid_until", NormalizeTime(self.valid_until))

        if datetime.fromisoformat(self.issued_at) >= datetime.fromisoformat(self.valid_until):
            raise ValueError("artifact grant validity must be increasing")


class ArtifactPolicyEngine:
    """Fresh same-store artifact authority with no fake destination or native launch bypass."""

    def Plan(
        self,
        prepared: PreparedArtifact,
        stage: ArtifactStage,
        context: ArtifactPolicyContext,
        *,
        at: datetime,
        after_run: bool = False,
    ) -> ArtifactPlan:
        """Rebuild exact fixed request and current owned scope/policy before planning.

        Args:
            prepared: Exact fixed factory request; free flags/environment are rejected.
            stage: Bound physical immutable input/scanner/material snapshots.
            context: Current operator owner, same-store scope and impact policy.
            at: Explicit aware decision time.
            after_run: Permit observed bounded scratch writes for result acceptance only.

        Returns:
            Complete artifact authority/request plan; no process is started.

        Raises:
            ArtifactDeniedError: Request/material/scope/policy is unavailable or changed.
            ValueError: Typed authority or clock contract is invalid.
            OSError: Current authoritative metadata/material is unreadable.
        """

        RequireTime(at)

        if not isinstance(prepared, PreparedArtifact) or not isinstance(
            context, ArtifactPolicyContext
        ):
            raise ValueError("artifact planning requires a fixed prepared request and context")

        rebuilt = BuildPreparedArtifact(
            stage,
            prepared.workspace_root,
            prepared.invocation.timeout_seconds,
            prepared.resources,
            after_run=after_run,
            operation=prepared.operation,
            version_proof=prepared.version_proof,
        )

        if Digest(prepared.Payload()) != Digest(rebuilt.Payload()):
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        workspace = LocalWorkspaceStore(prepared.workspace_root).Open()
        current_scope = LocalScopeStore(prepared.workspace_root).Open(context.scope.scope_id)

        if workspace.workspace_id != context.scope.workspace_id or current_scope != context.scope:
            raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

        target = stage.input.manifest.Target()

        if not context.scope.Check(target, at=at).Allowed():
            raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

        permission = next(
            (
                item
                for item in context.policy.permissions
                if (
                    item.capability_id == prepared.capability.identifier
                    and item.adapter_id == prepared.capability.adapter_id
                )
            ),
            None,
        )

        if permission is None or not set(prepared.capability.required_privileges).issubset(
            permission.granted_privileges
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

        if any(
            _IMPACT_ORDER[prepared.invocation.request.impact] > _IMPACT_ORDER[ceiling]
            for ceiling in (
                context.policy.maximum_impact,
                permission.maximum_impact,
                prepared.capability.maximum_impact,
            )
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.IMPACT_DENIED)

        self.ValidateVersionPrerequisite(prepared, stage, context, at=at)
        version_bindings = prepared.VersionBindings()

        return ArtifactPlan(
            context.owner_ref,
            stage.input.manifest.profile,
            stage.version,
            stage.input.manifest.Digest(),
            stage.scanner.manifest.Digest(),
            stage.material.manifest.Digest(),
            workspace.workspace_id,
            context.scope.Reference(),
            context.scope.revision,
            Digest(context.scope.ToDict()),
            context.policy.Reference(),
            context.policy.revision,
            Digest(context.policy),
            target.Reference(),
            Digest(ArtifactStagePayload(stage)),
            stage.lease_id,
            Digest(prepared.Payload()),
            InvocationDigest(prepared.invocation),
            permission.granted_privileges,
            prepared.operation,
            prepared.producer_family,
            cast(str | None, version_bindings["version_run_id"]),
            cast(str | None, version_bindings["version_grant_id"]),
            cast(str | None, version_bindings["version_prerequisite_sha256"]),
        )

    def ValidateVersionPrerequisite(
        self,
        prepared: PreparedArtifact,
        stage: ArtifactStage,
        context: ArtifactPolicyContext,
        *,
        at: datetime,
    ) -> None:
        """Require a fresh matching original VERSION before richer SCAN gets live authority.

        Args:
            prepared: Exact richer SCAN request holding its immutable original prerequisite.
            stage: Separate physical SCAN stage with identical selected content/executable.
            context: Current canonical scope/policy/owner for both operations.
            at: Actual aware SCAN issuance/validation time, including VERSION expiry.

        Raises:
            ArtifactDeniedError: Missing/failed/changed/stale VERSION or cross-stage mismatch.
        """

        proof = prepared.version_proof

        if proof is None:
            return

        if (
            stage.root == proof.stage.root or stage.root_identity == proof.stage.root_identity
            or stage.lease_id == proof.stage.lease_id
            or stage.executable != proof.stage.executable
            or stage.executable_identity != proof.stage.executable_identity
            or stage.version != proof.stage.version
            or proof.prepared.workspace_root != prepared.workspace_root
            or proof.outcome.manifests != (
                stage.input.manifest, stage.scanner.manifest, stage.material.manifest,
            )
            or proof.outcome.grant.plan.owner_ref != context.owner_ref
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        GovernedArtifactExecutor(prepared.workspace_root).ValidateAcceptance(
            proof.outcome, proof.prepared, proof.stage, context, at=at
        )
        ParseObservedImageVersion(proof.outcome.raw_result.stdout)

    def Authorize(
        self,
        prepared: PreparedArtifact,
        stage: ArtifactStage,
        context: ArtifactPolicyContext,
        *,
        at: datetime,
    ) -> ArtifactGrant:
        """Issue artifact-only metadata after fresh fixed-profile/same-store authority checks.

        Args:
            prepared: Fixed trusted synthetic request.
            stage: Fresh read-authorized owned stage.
            context: Current persisted scope, operator policy and explicit owner.
            at: Aware issuance time; lifetime is bounded by policy and consent.

        Returns:
            Immutable grant requiring fresh launch and acceptance validation.

        Raises:
            ArtifactDeniedError: Authority/material fails or a bounded expiry cannot be represented.
        """

        plan = self.Plan(prepared, stage, context, at=at)
        issued_at = at.astimezone(timezone.utc).isoformat()

        try:
            expiry = at + timedelta(seconds=context.policy.max_authorization_seconds)

        except OverflowError as error:
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED) from error

        if context.scope.authorization.valid_until is not None:
            expiry = min(expiry, datetime.fromisoformat(context.scope.authorization.valid_until))

        valid_until = expiry.astimezone(timezone.utc).isoformat()
        authorization = self.Envelope(plan, issued_at, valid_until)

        return ArtifactGrant(plan, authorization, issued_at, valid_until)

    def Envelope(
        self, plan: ArtifactPlan, issued_at: str, valid_until: str
    ) -> ExecutionAuthorization:
        """Rebuild domain-separated artifact metadata, never a network grant.

        Args:
            plan: Exact fresh artifact policy and complete request/material inputs.
            issued_at: Canonical aware issuance time.
            valid_until: Canonical exclusive expiry, also applied at acceptance.

        Returns:
            Existing executor envelope whose identity explicitly denotes artifact authority.
        """

        return ExecutionAuthorization(
            "artifact-authorization:" + Digest((plan, issued_at, valid_until)),
            plan.scope_reference,
            plan.policy_reference,
            plan.invocation_sha256,
            plan.granted_privileges,
        )

    def Validate(
        self,
        grant: ArtifactGrant,
        prepared: PreparedArtifact,
        stage: ArtifactStage,
        context: ArtifactPolicyContext,
        *,
        at: datetime,
        after_run: bool = False,
    ) -> None:
        """Reject expired, altered, revoked or replaced artifact-only authority.

        Args:
            grant: Previously issued artifact grant; possession alone proves no authority.
            prepared: Exact fixed request proposed for launch/acceptance.
            stage: Same observed physical immutable material and single-run lease.
            context: Fresh current persisted scope/operator policy/owner.
            at: Aware launch or result-acceptance time; expiry applies to both.
            after_run: Permit bounded observed scratch contents after execution.

        Raises:
            ArtifactDeniedError: Current authority, exact bindings or time fail closed.
            ValueError: A network grant or malformed clock/type is supplied.
        """

        if not isinstance(grant, ArtifactGrant):
            raise ValueError("artifact policy requires an ArtifactGrant")

        self.ValidateTime(grant, stage, context, at=at)
        plan = self.Plan(prepared, stage, context, at=at, after_run=after_run)

        if plan != grant.plan or grant.authorization != self.Envelope(
            plan, grant.issued_at, grant.valid_until
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    def ValidateTime(
        self,
        grant: ArtifactGrant,
        stage: ArtifactStage,
        context: ArtifactPolicyContext,
        *,
        at: datetime,
        version_proof: ArtifactVersionProof | None = None,
    ) -> None:
        """Check operation and original prerequisite lifetimes at one fresh decision time.

        Args:
            grant: Original typed artifact grant with issuance/exclusive expiry.
            stage: Bound input manifest; this check does not rehash physical files.
            context: Same current context already fully validated against persistent scope.
            at: Fresh aware clock read immediately before launch-hook return.
            version_proof: Bound original VERSION for SCAN; checked at the same refreshed time.

        Raises:
            ArtifactDeniedError: Canonical policy/consent lifetime differs or authority expired.
            ValueError: The typed context/grant/time contract is malformed.
        """

        RequireTime(at)

        if not isinstance(grant, ArtifactGrant) or not isinstance(context, ArtifactPolicyContext):
            raise ValueError("artifact time validation requires typed grant and context")

        if version_proof is not None and type(version_proof) is not ArtifactVersionProof:
            raise ValueError("artifact time validation requires its original typed VERSION proof")

        if (
            not datetime.fromisoformat(grant.issued_at)
            <= at
            < datetime.fromisoformat(grant.valid_until)
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.GRANT_EXPIRED)

        issued_at = datetime.fromisoformat(grant.issued_at)

        try:
            expiry = issued_at + timedelta(seconds=context.policy.max_authorization_seconds)

        except OverflowError as error:
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED) from error

        if context.scope.authorization.valid_until is not None:
            expiry = min(expiry, datetime.fromisoformat(context.scope.authorization.valid_until))

        if datetime.fromisoformat(grant.valid_until) != expiry:
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        if not context.scope.Check(stage.input.manifest.Target(), at=issued_at).Allowed():
            raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

        if not context.scope.Check(stage.input.manifest.Target(), at=at).Allowed():
            raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

        if version_proof is not None:
            self.ValidateTime(version_proof.outcome.grant, version_proof.stage, context, at=at)

    def ValidateCurrent(
        self,
        grant: ArtifactGrant,
        prepared: PreparedArtifact,
        stage: ArtifactStage,
        context: ArtifactPolicyContext,
        *,
        at: datetime,
    ) -> None:
        """Refresh complete authority/request metadata after hashing without rehashing files.

        Args:
            grant: Original artifact grant already fully validated against physical material.
            prepared: Original exact factory request including capability/environment/resources.
            stage: Original immutable role manifests and physical lease metadata.
            context: Newly read current owner/scope/policy after expensive work or scratch setup.
            at: Fresh aware time for current consent and grant validity.

        Raises:
            ArtifactDeniedError: Current content/revision/owner/permission/impact differs or denies.
            OSError: Fresh authoritative workspace/scope metadata cannot be read.
        """

        self.ValidateTime(grant, stage, context, at=at)
        scope = LocalScopeStore(prepared.workspace_root).Open(context.scope.scope_id)
        workspace = LocalWorkspaceStore(prepared.workspace_root).Open()

        if scope != context.scope or workspace.workspace_id != grant.plan.workspace_id:
            raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

        permission = next(
            (
                item
                for item in context.policy.permissions
                if (
                    item.capability_id == prepared.capability.identifier
                    and item.adapter_id == prepared.capability.adapter_id
                )
            ),
            None,
        )

        if permission is None or not set(prepared.capability.required_privileges).issubset(
            permission.granted_privileges
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

        if any(
            _IMPACT_ORDER[prepared.invocation.request.impact] > _IMPACT_ORDER[ceiling]
            for ceiling in (
                context.policy.maximum_impact,
                permission.maximum_impact,
                prepared.capability.maximum_impact,
            )
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.IMPACT_DENIED)

        if (
            context.owner_ref != grant.plan.owner_ref
            or context.scope.Reference() != grant.plan.scope_reference
            or context.scope.revision != grant.plan.scope_revision
            or Digest(context.scope.ToDict()) != grant.plan.scope_sha256
            or context.policy.Reference() != grant.plan.policy_reference
            or context.policy.revision != grant.plan.policy_revision
            or Digest(context.policy) != grant.plan.policy_sha256
            or permission.granted_privileges != grant.plan.granted_privileges
            or Digest(prepared.Payload()) != grant.plan.request_sha256
            or Digest(ArtifactStagePayload(stage)) != grant.plan.stage_sha256
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        proof = prepared.version_proof

        if proof is not None:
            VerifyExecutionMarker(
                proof.stage, proof.outcome.run_id, proof.outcome.acceptance.grant_id,
                proof.outcome.acceptance.marker_identity,
            )
            self.ValidateCurrent(proof.outcome.grant, proof.prepared, proof.stage, context, at=at)


def RawResultFacts(result: LocalExecutionResult) -> dict[str, object]:
    """Render bounded metadata binding actual process facts and retained stream/event bytes.

    Args:
        result: Actual unchanged result returned by the accepted local executor.

    Returns:
        Execution/termination/stream hashes and event digest/count, without copying raw content.
    """

    return {
        "execution": result.execution,
        "termination": result.termination,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stdout_bytes": len(result.stdout),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "stderr_bytes": len(result.stderr),
        "events_sha256": Digest(
            [
                (
                    event.sequence,
                    event.kind,
                    hashlib.sha256(event.data).hexdigest(),
                    len(event.data),
                    event.termination,
                )
                for event in result.events
            ]
        ),
        "events_count": len(result.events),
    }


def RawResultDigest(result: LocalExecutionResult) -> str:
    """Bind exact original process facts without reflecting stream bytes.

    Args:
        result: Actual raw executor result whose stream/event facts are retained.

    Returns:
        SHA-256 of exact fact metadata, never authority to execute or normalize.
    """

    return Digest(RawResultFacts(result))


@dataclass(frozen=True, slots=True)
class ArtifactAcceptance:
    """Per-run exact-raw-result receipt; acceptance is freshly checked before model use."""

    run_id: str
    grant_id: str
    stage_lease: str
    raw_sha256: str
    checked_at: str
    refusal: ArtifactDenialReason | None
    marker_identity: tuple[int, int, int, int, int] | None

    def __post_init__(self) -> None:
        """Reject malformed receipt identities without interpreting raw content."""

        for value in (self.run_id, self.grant_id, self.stage_lease):
            RequireReference(value, "artifact receipt")

        RequireDigest(self.raw_sha256)
        object.__setattr__(self, "checked_at", NormalizeTime(self.checked_at))

        if self.refusal is not None and not isinstance(self.refusal, ArtifactDenialReason):
            raise ValueError("artifact refusal must be a typed sanitized reason")

        if self.marker_identity is not None:
            object.__setattr__(
                self, "marker_identity", FreezePhysicalIdentity(self.marker_identity, 5)
            )

        if self.refusal is None and self.marker_identity is None:
            raise ValueError("accepted artifact receipt requires an actual launch marker")


@dataclass(frozen=True, slots=True)
class ArtifactExecutionOutcome:
    """Immutable raw process facts and separate original-run acceptance provenance."""

    raw_result: LocalExecutionResult
    grant: ArtifactGrant
    acceptance: ArtifactAcceptance
    run_id: str
    manifests: tuple[ArtifactManifest, ...]

    def __post_init__(self) -> None:
        """Reject replaced raw bytes or a receipt belonging to another grant/run."""

        if (
            not isinstance(self.raw_result, LocalExecutionResult)
            or not isinstance(self.grant, ArtifactGrant)
            or not isinstance(self.acceptance, ArtifactAcceptance)
        ):
            raise ValueError("artifact outcome requires raw result, artifact grant and receipt")

        if (
            self.acceptance.raw_sha256 != RawResultDigest(self.raw_result)
            or self.acceptance.grant_id != self.grant.authorization.authorization_id
        ):
            raise ValueError("artifact receipt does not bind the actual raw result and grant")

        if self.acceptance.run_id != self.run_id:
            raise ValueError("artifact receipt does not belong to this run")

        if self.acceptance.stage_lease != self.grant.plan.stage_lease:
            raise ValueError("artifact receipt does not belong to the granted stage")

        if self.acceptance.refusal is None and not (
            datetime.fromisoformat(self.grant.issued_at)
            <= datetime.fromisoformat(self.acceptance.checked_at)
            < datetime.fromisoformat(self.grant.valid_until)
        ):
            raise ValueError("accepted artifact receipt time contradicts its original grant")

        if (
            not isinstance(self.manifests, (list, tuple))
            or len(self.manifests) != 3
            or any(not isinstance(item, ArtifactManifest) for item in self.manifests)
        ):
            raise ValueError("artifact outcome requires three finite typed manifests")

        object.__setattr__(self, "manifests", tuple(self.manifests))
        expected = (
            self.grant.plan.input_manifest_sha256,
            self.grant.plan.scanner_manifest_sha256,
            self.grant.plan.material_manifest_sha256,
        )

        if len(self.manifests) != 3 or tuple(item.Digest() for item in self.manifests) != expected:
            raise ValueError("artifact outcome manifests do not match the original grant")

    def Metadata(self) -> dict[str, object]:
        """Render original provenance for existing evidence storage and read-only replay.

        Returns:
            Exact grant/receipt/manifest bindings without raw stream contents or new authority.
        """

        return cast(
            dict[str, object],
            json.loads(
                SerializeContract(
                    {
                        "schema_version": 2,
                        "grant": self.grant,
                        "acceptance": self.acceptance,
                        "manifests": [item.ToDict() for item in self.manifests],
                        "raw_facts": RawResultFacts(self.raw_result),
                    }
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class ArtifactVersionProof:
    """Immutable original VERSION prerequisite; possession alone grants no current authority."""

    outcome: ArtifactExecutionOutcome
    prepared: PreparedArtifact
    stage: ArtifactStage

    def __post_init__(self) -> None:
        """Keep original successful raw/receipt/request/stage bindings without filesystem reads."""

        if (
            not isinstance(self.outcome, ArtifactExecutionOutcome)
            or not isinstance(self.prepared, PreparedArtifact)
            or not isinstance(self.stage, ArtifactStage)
        ):
            raise ValueError("VERSION proof requires original typed outcome, request and stage")

        plan = self.outcome.grant.plan

        if (
            plan.operation != ArtifactOperation.VERSION
            or self.prepared.operation != ArtifactOperation.VERSION
            or plan.producer_family != _IMAGE_FAMILY
            or self.prepared.producer_family != _IMAGE_FAMILY
            or plan.profile != ArtifactProfile.SYNTHETIC_IMAGE
            or plan.request_sha256 != Digest(self.prepared.Payload())
            or plan.stage_sha256 != Digest(ArtifactStagePayload(self.stage))
            or self.outcome.manifests != (
                self.stage.input.manifest, self.stage.scanner.manifest,
                self.stage.material.manifest,
            )
            or self.outcome.acceptance.refusal is not None
            or self.outcome.raw_result.execution.state != ExecutionState.SUCCEEDED
            or self.outcome.raw_result.execution.exit_code != 0
            or self.outcome.raw_result.termination != ExecutionTermination.PROCESS_EXIT
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        ParseObservedImageVersion(self.outcome.raw_result.stdout)

    def Payload(self) -> dict[str, object]:
        """Capture only exact original detached VERSION metadata and complete payload bindings.

        Returns:
            Canonical original VERSION facts, without raw stream contents or refreshed authority.
        """

        return cast(dict[str, object], json.loads(SerializeContract({
            "artifact_metadata": self.outcome.Metadata(),
            "prepared_payload": self.prepared.Payload(),
            "stage_payload": ArtifactStagePayload(self.stage),
        })))

    def Digest(self) -> str:
        """Hash the original prerequisite facts bound by a richer SCAN request and grant.

        Returns:
            Canonical SHA-256; neither this digest nor saved bytes can reauthorize a VERSION.
        """

        return Digest(self.Payload())


def DetachedReplayBounds(value: object) -> None:
    """Bound detached JSON work before any hashing or nested reconstruction.

    Args:
        value: One original metadata/request/stage JSON object, never a caller-defined wrapper.

    Raises:
        ValueError: Shape, depth, node, text, integer or finite-number bounds are unsupported.
    """

    pending = [(value, 0)]
    nodes = 0
    text_bytes = 0

    while pending:
        item, depth = pending.pop()
        nodes += 1

        if nodes > 1024 or depth > 16:
            raise ValueError("detached artifact payload exceeds its structural bounds")

        if type(item) in (dict, list):
            container = cast(dict[str, object] | list[object], item)

            if len(container) > 1024 - nodes - len(pending):
                raise ValueError("detached artifact payload exceeds its node bound")

            if type(item) is dict:
                for key in item:
                    if type(key) is not str or len(key) > 64:
                        raise ValueError("detached artifact field names are unsupported")

                pending.extend((child, depth + 1) for child in item.values())

            else:
                pending.extend((child, depth + 1) for child in cast(list[object], item))

        elif type(item) is str:
            if len(item) > 4096 or "\x00" in item:
                raise ValueError("detached artifact text exceeds its field bound")

            text_bytes += len(item.encode("utf-8"))

            if text_bytes > 1024 * 1024:
                raise ValueError("detached artifact text exceeds its aggregate bound")

        elif type(item) is int:
            if item.bit_length() > 128:
                raise ValueError("detached artifact integers exceed their recorded bound")

        elif type(item) is float:
            if not math.isfinite(item):
                raise ValueError("detached artifact numbers must be finite")

        elif item is not None and type(item) is not bool:
            raise ValueError("detached artifact payload must contain only original JSON values")


def DetachedReplayPath(value: object) -> PurePath:
    """Preserve an original canonical absolute POSIX or Windows path without filesystem access.

    Args:
        value: Bounded original serialized path; current host syntax does not select its flavor.

    Returns:
        Lexical absolute path with its original flavor; no resolution or existence claim.
    """

    if type(value) is not str or not value or len(value) > 4096 or any(
        character in value for character in ("\x00", "\r", "\n")
    ):
        raise ValueError("detached artifact path text is unsupported")

    path: PurePath = PurePosixPath(value) if value.startswith("/") else PureWindowsPath(value)

    if not path.is_absolute() or str(path) != value or ".." in path.parts:
        raise ValueError("detached artifact requires an original canonical absolute path")

    return path


def DetachedReplayIdentity(value: object, length: int) -> tuple[int, ...]:
    """Check bounded recorded physical observations without consulting any current inode.

    Args:
        value: Original JSON list with two directory or five selected-file components.
        length: Exact required observation width.

    Returns:
        Frozen device/inode and optional size/time facts; these are attribution, not attestation.
    """

    if type(value) is not list:
        raise ValueError("detached artifact identity must use its original JSON list shape")

    identity = FreezePhysicalIdentity(value, length)

    if any(item.bit_length() > 128 for item in identity) or identity[0] < 0 or identity[1] <= 0:
        raise ValueError("detached artifact physical identity is unsupported")

    if length == 5 and identity[2] < 0:
        raise ValueError("detached artifact observed file size is unsupported")

    return identity


def VerifySyntheticImagePayloadReplay(
    metadata: object, prepared_payload: object, stage_payload: object,
) -> None:
    """Verify detached richer-image schema-2 factory grammar without current authority or I/O.

    Call VerifyArtifactReplay separately with the original retained raw streams. The consumer
    owns original evidence records, cross-operation pairing, prerequisites and capture chronology.
    Recorded platform values and physical identities are attribution, not publisher authentication.

    Args:
        metadata: Original operation-aware outcome metadata, independently obtained from evidence.
        prepared_payload: Original JSON-serialized PreparedArtifact.Payload, without relocation.
        stage_payload: Original JSON-serialized ArtifactStagePayload with original observations.

    Raises:
        ValueError: Bounded payloads, exact factory grammar or original bindings are inconsistent.
    """

    for value in (metadata, prepared_payload, stage_payload):
        DetachedReplayBounds(value)

    record = WorkspaceFields(metadata,
        {"schema_version", "grant", "acceptance", "manifests", "raw_facts"}, "detached artifact")

    if type(record["schema_version"]) is not int or record["schema_version"] != 2:
        raise ValueError("detached image factory replay requires original schema two")

    grant = WorkspaceFields(record["grant"],
        {"plan", "authorization", "issued_at", "valid_until"}, "detached grant")
    plan = VerifyReplayPlan(grant["plan"], 2)

    if plan["profile"] != ArtifactProfile.SYNTHETIC_IMAGE.value or (
        plan["producer_family"] != _IMAGE_FAMILY
    ):
        raise ValueError("detached replay requires the closed reviewed synthetic image family")

    prepared = WorkspaceFields(prepared_payload, {
        "workspace_root", "stage_lease", "invocation", "capability", "workspace", "environment",
        "resources", "operation", "producer_family", "version_run_id", "version_grant_id",
        "version_prerequisite_sha256",
    }, "detached request")
    stage = WorkspaceFields(stage_payload, {
        "root", "lease", "root_identity", "executable", "executable_identity", "version",
        "partitions",
    }, "detached stage")

    if Digest(prepared) != plan["request_sha256"] or Digest(stage) != plan["stage_sha256"]:
        raise ValueError("detached payloads differ from the original grant")

    if type(stage["lease"]) is not str or not re.fullmatch(r"[0-9a-f]{32}", stage["lease"]) or (
        stage["lease"] != prepared["stage_lease"] or stage["lease"] != plan["stage_lease"]
        or stage["version"] != plan["provider_version"]
    ):
        raise ValueError("detached stage lease or version differs from its original plan")

    for name in ("operation", "producer_family", "version_run_id", "version_grant_id",
                 "version_prerequisite_sha256"):
        if prepared[name] != plan[name]:
            raise ValueError("detached operation or prerequisite differs from the original plan")

    root = DetachedReplayPath(stage["root"])
    workspace_root = DetachedReplayPath(prepared["workspace_root"])
    executable = DetachedReplayPath(stage["executable"])

    if type(root) is not type(workspace_root) or type(root) is not type(executable) or (
        root == workspace_root or not root.is_relative_to(workspace_root)
        or executable.is_relative_to(root)
        or prepared["workspace"] != (root / "scratch").relative_to(workspace_root).as_posix()
    ):
        raise ValueError("detached stage, selected runtime or scratch paths are inconsistent")

    partitions = stage["partitions"]

    if type(partitions) is not list or len(partitions) != 3:
        raise ValueError("detached image requires three original stage partitions")

    physical_ids = {DetachedReplayIdentity(stage["root_identity"], 2)}
    executable_identity = DetachedReplayIdentity(stage["executable_identity"], 5)

    if executable_identity[:2] in physical_ids:
        raise ValueError("detached runtime and stage have aliased physical identities")

    physical_ids.add(executable_identity[:2])
    manifests = []

    for index, role in enumerate((ArtifactRole.INPUT, ArtifactRole.SCANNER, ArtifactRole.MATERIAL)):
        partition = WorkspaceFields(partitions[index],
            {"manifest", "consent", "identities", "directory_identity"}, "detached partition")
        manifest = ArtifactManifest.FromDict(partition["manifest"])
        manifests.append(manifest)
        consent = WorkspaceFields(partition["consent"], {"actor_ref", "record_ref"},
                                  "detached read consent")
        ArtifactReadConsent(**cast(dict[str, Any], consent))
        directory_identity = DetachedReplayIdentity(partition["directory_identity"], 2)

        if directory_identity in physical_ids or manifest.role is not role or (
            manifest.profile is not ArtifactProfile.SYNTHETIC_IMAGE
        ):
            raise ValueError("detached partition roles or physical identities are inconsistent")

        physical_ids.add(directory_identity)
        identities = partition["identities"]

        if type(identities) is not list or len(identities) != len(manifest.files):
            raise ValueError("detached partition file observations differ from its manifest")

        for file_record, observation in zip(manifest.files, identities, strict=True):
            if type(observation) is not list or len(observation) != 2 or (
                observation[0] != file_record.name
            ):
                raise ValueError("detached file observation ordering is inconsistent")

            identity = DetachedReplayIdentity(observation[1], 5)

            if identity[:2] in physical_ids or identity[2] != file_record.size_bytes:
                raise ValueError("detached selected copies have aliased identities or wrong sizes")

            physical_ids.add(identity[:2])

    if [item.ToDict() for item in manifests] != record["manifests"] or (
        tuple(item.Digest() for item in manifests) != (
            plan["input_manifest_sha256"], plan["scanner_manifest_sha256"],
            plan["material_manifest_sha256"],
        ) or manifests[0].Target().Reference() != plan["target_reference"]
        or tuple(item.name for item in manifests[0].files) != ("image.tar",)
        or tuple(item.name for item in manifests[1].files) != ("executable", "producer.py")
        or tuple(item.name for item in manifests[2].files) != ("policy.json",)
        or manifests[0].files[0].size_bytes > 128 * 1024
        or manifests[2].files[0].size_bytes > 512
        or manifests[1].files[1].sha256 != _IMAGE_PRODUCER_SHA256
        or executable_identity[2] != manifests[1].files[0].size_bytes
    ):
        raise ValueError("detached image material is outside the original closed factory")

    invocation_record = WorkspaceFields(prepared["invocation"],
        {"adapter_id", "request", "argv", "timeout_seconds", "provider_version"},
        "detached invocation")
    resource_record = WorkspaceFields(prepared["resources"],
        {item.name for item in fields(ExecutionResources)}, "detached resources")
    resources = ExecutionResources(**cast(dict[str, Any], resource_record))
    timeout = cast(int, invocation_record["timeout_seconds"])
    operation = ArtifactOperation(cast(str, plan["operation"]))
    ValidateArtifactResources(_IMAGE_FAMILY, operation, timeout, resources)
    capability = ProfileCapability(ArtifactProfile.SYNTHETIC_IMAGE)
    invocation = AdapterInvocation(capability.adapter_id, AdapterRequest(
        capability.identifier, manifests[0].Target().Reference(), ImpactLevel.SAFE, {
            "profile": ArtifactProfile.SYNTHETIC_IMAGE.value,
            "input_manifest_sha256": manifests[0].Digest(), "operation": operation.value,
            "producer_family": _IMAGE_FAMILY,
        }), ArtifactArgv(root, executable, ArtifactProfile.SYNTHETIC_IMAGE, _IMAGE_FAMILY,
                         operation, timeout), timeout, "0.75.0-synthetic")
    environment = WorkspaceFields(prepared["environment"],
        set(ArtifactEnvironment(root, "", "")), "detached environment")

    if invocation_record != json.loads(SerializeContract(invocation)) or (
        prepared["capability"] != json.loads(SerializeContract(capability))
        or environment != dict(ArtifactEnvironment(root, cast(str, environment["SYSTEMROOT"]),
                                                   cast(str, environment["WINDIR"])))
        or InvocationDigest(invocation) != plan["invocation_sha256"]
    ):
        raise ValueError("detached request differs from the original closed factory grammar")


def VerifyArtifactReplay(metadata: object, stdout: bytes, stderr: bytes) -> ArtifactAcceptance:
    """Verify saved original provenance against retained raw bytes without current authorization.

    Args:
        metadata: Original outcome metadata obtained from verified existing evidence storage.
        stdout: Retained original stdout bytes, independently verified by the evidence store.
        stderr: Retained original stderr bytes, independently verified by the evidence store.

    Returns:
        Original per-run acceptance/refusal metadata; this issues no launch or model authority.

    Raises:
        ValueError: Version, exact fields, hashes, execution facts or provenance are inconsistent.
    """

    record = WorkspaceFields(
        metadata,
        {"schema_version", "grant", "acceptance", "manifests", "raw_facts"},
        "artifact replay",
    )

    schema_version = record["schema_version"]

    if type(schema_version) is not int or schema_version not in {1, 2}:
        raise ValueError("artifact replay version is unsupported")

    if (
        not isinstance(stdout, bytes)
        or not isinstance(stderr, bytes)
        or max(len(stdout), len(stderr)) > 16 * 1024 * 1024
    ):
        raise ValueError("artifact replay requires bounded retained stream bytes")

    grant_record = WorkspaceFields(
        record["grant"], {"plan", "authorization", "issued_at", "valid_until"}, "artifact grant"
    )
    plan_record = VerifyReplayPlan(grant_record["plan"], schema_version)

    try:
        authorization_record = cast(
            dict[str, Any],
            WorkspaceFields(
                grant_record["authorization"],
                {item.name for item in fields(ExecutionAuthorization)},
                "artifact envelope",
            ),
        )
        authorization = ExecutionAuthorization(**authorization_record)
        issued_at = NormalizeTime(cast(str, grant_record["issued_at"]))
        valid_until = NormalizeTime(cast(str, grant_record["valid_until"]))

        if (
            issued_at != grant_record["issued_at"]
            or valid_until != grant_record["valid_until"]
            or datetime.fromisoformat(issued_at) >= datetime.fromisoformat(valid_until)
        ):
            raise ValueError("artifact replay grant times are inconsistent")

        receipt_record = WorkspaceFields(
            record["acceptance"],
            {item.name for item in fields(ArtifactAcceptance)},
            "artifact receipt",
        )
        receipt_values: dict[str, Any] = dict(receipt_record)
        receipt_values["refusal"] = (
            None
            if receipt_values["refusal"] is None
            else ArtifactDenialReason(receipt_values["refusal"])
        )
        receipt = ArtifactAcceptance(**receipt_values)

    except (TypeError, ValueError):
        raise ValueError("artifact replay metadata is malformed") from None

    expected_envelope = ExecutionAuthorization(
        "artifact-authorization:" + Digest((plan_record, issued_at, valid_until)),
        cast(str, plan_record["scope_reference"]),
        cast(str, plan_record["policy_reference"]),
        cast(str, plan_record["invocation_sha256"]),
        cast(tuple[str, ...], plan_record["granted_privileges"]),
    )

    if authorization != expected_envelope:
        raise ValueError("artifact replay plan or original envelope is inconsistent")

    manifest_records = record["manifests"]

    if not isinstance(manifest_records, list) or len(manifest_records) != 3:
        raise ValueError("artifact replay requires three role-separated manifests")

    try:
        manifests = tuple(ArtifactManifest.FromDict(item) for item in manifest_records)

    except (TypeError, ValueError):
        raise ValueError("artifact replay manifest metadata is malformed") from None

    if (
        tuple(item.role for item in manifests)
        != (ArtifactRole.INPUT, ArtifactRole.SCANNER, ArtifactRole.MATERIAL)
        or any(item.profile.value != plan_record["profile"] for item in manifests)
        or tuple(item.Digest() for item in manifests)
        != (
            plan_record["input_manifest_sha256"], plan_record["scanner_manifest_sha256"],
            plan_record["material_manifest_sha256"],
        )
        or manifests[0].Target().Reference() != plan_record["target_reference"]
    ):
        raise ValueError("artifact replay manifests do not match original input authority")

    scanner_files = {item.name: item for item in manifests[1].files}
    family = _LIFECYCLE_FAMILY if schema_version == 1 else plan_record["producer_family"]

    if set(scanner_files) != {"executable", "producer.py"} or (
        scanner_files["producer.py"].sha256 not in (
            _LEGACY_PRODUCERS if family == _LIFECYCLE_FAMILY else (
                {_CONFIGURATION_PRODUCER_SHA256} if family == _CONFIGURATION_FAMILY
                else {_IMAGE_PRODUCER_SHA256}
            )
        )
    ):
        raise ValueError("artifact replay producer does not match its original schema family")

    if family == _CONFIGURATION_FAMILY and (
        len(stdout) > 16 * 1024 or len(stderr) > 16 * 1024
        or len(manifests[0].files) != 1
        or (manifests[0].profile, manifests[0].files[0].name,
            manifests[0].files[0].size_bytes, manifests[0].files[0].sha256)
        not in _CONFIGURATION_CASES.values()
        or tuple(item.name for item in manifests[2].files) != ("policy.json",)
        or manifests[2].files[0].size_bytes > 1024
    ):
        raise ValueError("artifact replay configuration exceeds its original closed material")

    facts = cast(
        dict[str, Any],
        WorkspaceFields(
            record["raw_facts"],
            {
                "execution",
                "termination",
                "stdout_sha256",
                "stdout_bytes",
                "stderr_sha256",
                "stderr_bytes",
                "events_sha256",
                "events_count",
            },
            "artifact raw facts",
        ),
    )
    execution_record = cast(
        dict[str, Any],
        WorkspaceFields(
            facts["execution"],
            {item.name for item in fields(AdapterExecution)},
            "artifact execution",
        ),
    )

    if isinstance(execution_record["duration_seconds"], bool):
        raise ValueError("artifact replay execution duration is malformed")

    try:
        AdapterExecution(
            ExecutionState(execution_record["state"]),
            execution_record["exit_code"],
            execution_record["duration_seconds"],
        )
        ExecutionTermination(facts["termination"])
        RequireDigest(facts["events_sha256"])

    except (TypeError, ValueError, OverflowError):
        raise ValueError("artifact replay execution facts are malformed") from None

    if type(facts["events_count"]) is not int or facts["events_count"] < 0:
        raise ValueError("artifact replay event count is malformed")

    if facts["events_count"] > len(stdout) + len(stderr) + 2:
        raise ValueError("artifact replay event count exceeds retained-output bounds")

    if receipt.refusal is None and not (
        execution_record["state"] == ExecutionState.SUCCEEDED.value
        and execution_record["exit_code"] == 0
        and facts["termination"] == ExecutionTermination.PROCESS_EXIT.value
        and datetime.fromisoformat(issued_at)
        <= datetime.fromisoformat(receipt.checked_at)
        < datetime.fromisoformat(valid_until)
    ):
        raise ValueError("artifact replay falsely claims successful original acceptance")

    if (
        receipt.grant_id != authorization.authorization_id
        or receipt.raw_sha256 != Digest(facts)
        or receipt.stage_lease != plan_record["stage_lease"]
        or type(facts["stdout_bytes"]) is not int
        or type(facts["stderr_bytes"]) is not int
        or facts["stdout_bytes"] != len(stdout)
        or facts["stderr_bytes"] != len(stderr)
        or facts["stdout_sha256"] != hashlib.sha256(stdout).hexdigest()
        or facts["stderr_sha256"] != hashlib.sha256(stderr).hexdigest()
    ):
        raise ValueError("artifact replay raw bytes do not match their original receipt")

    return receipt


def VerifyReplayPlan(value: object, schema_version: int) -> dict[str, object]:
    """Hash the saved schema's original field shape without creating legacy live authority.

    Args:
        value: Exact saved plan; schema one contains only original lifecycle SCAN fields.
        schema_version: Previously validated integer execution metadata version one or two.

    Returns:
        Verified original canonical plan dictionary, never a live plan/grant upgrade.
    """

    required = _LEGACY_PLAN_FIELDS if schema_version == 1 else {
        item.name for item in fields(ArtifactPlan)
    }
    record = WorkspaceFields(value, set(required), "artifact replay plan")

    try:
        profile = ArtifactProfile(cast(str, record["profile"]))

        if profile not in _SYNTHETIC_PROFILES or record["provider_version"] != "0.75.0-synthetic":
            raise ValueError("artifact replay plan profile is unsupported")

        RequireIdentifier(cast(str, record["workspace_id"]), "artifact replay workspace")

        for name in (
            "owner_ref", "scope_reference", "policy_reference", "target_reference", "stage_lease",
        ):
            RequireReference(cast(str, record[name]), "artifact replay plan")

        for name in (
            "input_manifest_sha256", "scanner_manifest_sha256", "material_manifest_sha256",
            "scope_sha256", "policy_sha256", "stage_sha256", "request_sha256",
            "invocation_sha256", "intent_sha256",
        ):
            RequireDigest(cast(str, record[name]))

        for name in ("scope_revision", "policy_revision"):
            revision = record[name]

            if type(revision) is not int or revision < 0:
                raise ValueError("artifact replay revisions must be non-negative integers")

        privileges = UniqueIdentifiers(
            cast(tuple[str, ...], record["granted_privileges"]), "artifact replay privileges"
        )

        if list(privileges) != record["granted_privileges"]:
            raise ValueError("artifact replay privileges are not canonical")

        if schema_version == 2:
            values = {key: item for key, item in record.items() if key != "intent_sha256"}
            values["profile"] = profile
            values["operation"] = ArtifactOperation(cast(str, values["operation"]))
            ArtifactPlan(**cast(dict[str, Any], values))

        expected = Digest({key: item for key, item in record.items() if key != "intent_sha256"})

        if expected != record["intent_sha256"]:
            raise ValueError("artifact replay intent does not match original fields")

    except (TypeError, ValueError):
        raise ValueError("artifact replay plan is malformed") from None

    return record


def ExecutionMarkerBytes(run_id: str, grant_id: str) -> bytes:
    """Encode the fixed bounded original-run/original-authorization witness without I/O.

    Args:
        run_id: Original run reference chosen before the final launch hook.
        grant_id: Original artifact authorization identity validated for this exact launch.

    Returns:
        Canonical private schema-1 JSON bytes with exactly three fields, at most 512 bytes.

    Raises:
        ValueError: References are malformed or exceed the fixed marker byte limit.
    """

    RequireReference(run_id, "artifact marker run")
    RequireReference(grant_id, "artifact marker grant")
    payload = json.dumps(
        {"schema_version": 1, "run_id": run_id, "grant_id": grant_id},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    if len(payload) > 512:
        raise ValueError("artifact execution marker exceeds its fixed byte limit")

    return payload


def VerifyExecutionMarker(
    stage: ArtifactStage,
    run_id: str,
    grant_id: str,
    identity: tuple[int, int, int, int, int] | None,
) -> None:
    """Bind fresh acceptance to the physical marker created by this actual single launch.

    Args:
        stage: Original owned stage; historical replay never calls this physical check.
        run_id: Original run identity written at the final validated launch boundary.
        grant_id: Original authorization identity written alongside that actual run.
        identity: Original observed marker device/inode/length/modification/change identity.

    Raises:
        ArtifactDeniedError: Missing, replaced, relinked, changed or unrelated marker.
        OSError: The owned marker cannot be inspected.
    """

    if identity is None:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    path = stage.root / "scratch/run-lease.json"

    try:
        if PhysicalIdentity(ArtifactPathInfo(path)) != identity:
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        record = ReadArtifactFile(path, "run-lease.json", max_bytes=512)

    except ValueError as error:
        raise ArtifactDeniedError(ArtifactDenialReason.MATERIAL_CHANGED) from error

    expected = ExecutionMarkerBytes(run_id, grant_id)

    if record.size_bytes != len(expected) or record.sha256 != hashlib.sha256(expected).hexdigest():
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)


class GovernedArtifactExecutor:
    """Run only closed reviewed synthetic profiles and preserve raw post-run refusal evidence."""

    def __init__(
        self, workspace_root: Path, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        """Bind the accepted local executor and explicit decision clock.

        Args:
            workspace_root: Existing physical workspace root enclosing the selected stage.
            clock: Optional aware clock for deterministic grant/acceptance tests.
        """

        self._root = workspace_root
        self._executor = LocalExecutor(workspace_root)
        self._engine = ArtifactPolicyEngine()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def CurrentContext(
        self, provider: Callable[[], ArtifactPolicyContext]
    ) -> ArtifactPolicyContext:
        """Require a synchronous fresh typed authority provider, closing a bare coroutine.

        Args:
            provider: Trusted callable returning current authority synchronously.

        Returns:
            Current typed context; unsupported callbacks raise ValueError before launch.
        """

        if not callable(provider):
            raise ValueError("artifact context provider must be callable")

        response = provider()

        if not isinstance(response, ArtifactPolicyContext):
            if inspect.iscoroutine(response):
                response.close()

            raise ValueError("artifact context provider must synchronously return current context")

        return response

    async def Execute(
        self,
        prepared: PreparedArtifact,
        stage: ArtifactStage,
        grant: ArtifactGrant,
        context_provider: Callable[[], ArtifactPolicyContext],
        *,
        on_event: EventCallback | None = None,
        cancellation: asyncio.Event | None = None,
    ) -> ArtifactExecutionOutcome:
        """Launch through fresh authority and return raw facts even if later acceptance fails.

        Args:
            prepared: Exact fixed request for this executor workspace.
            stage: Fresh single-run owned stage.
            grant: Artifact-only bounded approval.
            context_provider: Trusted synchronous fresh persisted scope/policy/owner lookup.
            on_event: Existing executor observer; never a raw-output metadata logger.
            cancellation: Cooperative cancellation preserving a returned raw terminal result.

        Returns:
            Per-run immutable raw result and exact receipt, including post-run refusal.

        Raises:
            ArtifactDeniedError: Pre-launch approval/material fails; no process is started.
            ValueError: Structural request/context contract is malformed.
            asyncio.CancelledError: Caller coroutine cancellation after owned executor cleanup.
        """

        if prepared.workspace_root != self._root:
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        self._engine.Validate(
            grant, prepared, stage, self.CurrentContext(context_provider), at=self._clock()
        )
        request = prepared.Request(grant)
        run_id = "artifact-run:" + uuid.uuid4().hex
        marker_identity: tuple[int, int, int, int, int] | None = None

        def BeforeLaunch(actual: LocalExecutionRequest) -> None:
            """Recheck exact authority immediately before owned scratch initialization/launch."""

            nonlocal marker_identity

            if actual != prepared.Request(grant):
                raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

            launch_context = self.CurrentContext(context_provider)
            self._engine.Validate(grant, prepared, stage, launch_context, at=self._clock())
            launch_context = self.CurrentContext(context_provider)
            self._engine.ValidateCurrent(grant, prepared, stage, launch_context, at=self._clock())
            self._engine.ValidateTime(
                grant, stage, launch_context, at=self._clock(),
                version_proof=prepared.version_proof,
            )
            scratch = stage.root / "scratch"

            with (scratch / "run-lease.json").open("xb") as marker:
                marker.write(ExecutionMarkerBytes(run_id, grant.authorization.authorization_id))

            marker_identity = PhysicalIdentity(ArtifactPathInfo(scratch / "run-lease.json"))

            for name in ("home", "temp", "config", "cache"):
                (scratch / name).mkdir(mode=0o700)

            launch_context = self.CurrentContext(context_provider)
            self._engine.ValidateCurrent(grant, prepared, stage, launch_context, at=self._clock())
            self._engine.ValidateTime(
                grant, stage, launch_context, at=self._clock(),
                version_proof=prepared.version_proof,
            )

        raw = await self._executor.Execute(
            request, on_event=on_event, cancellation=cancellation, pre_launch=BeforeLaunch
        )
        checked_at = datetime.now(timezone.utc)
        refusal = None

        try:
            checked_at = self._clock()
            RequireTime(checked_at)
            self._engine.Validate(
                grant,
                prepared,
                stage,
                self.CurrentContext(context_provider),
                at=checked_at,
                after_run=True,
            )

            if marker_identity is not None:
                VerifyExecutionMarker(
                    stage, run_id, grant.authorization.authorization_id, marker_identity
                )

            acceptance_context = self.CurrentContext(context_provider)
            checked_at = self._clock()
            self._engine.ValidateCurrent(
                grant, prepared, stage, acceptance_context, at=checked_at
            )
            checked_at = self._clock()
            self._engine.ValidateTime(
                grant, stage, acceptance_context, at=checked_at,
                version_proof=prepared.version_proof,
            )

        except ArtifactDeniedError as error:
            refusal = error.reason

        except PermissionError:
            refusal = ArtifactDenialReason.AUTHORITY_DENIED

        except OSError:
            refusal = ArtifactDenialReason.STORAGE

        except Exception:
            refusal = ArtifactDenialReason.CONTEXT_INVALID
            checked_at = datetime.now(timezone.utc)

        if refusal is None and not (
            raw.execution.state == ExecutionState.SUCCEEDED
            and raw.execution.exit_code == 0
            and raw.termination == ExecutionTermination.PROCESS_EXIT
        ):
            refusal = ArtifactDenialReason.EXECUTION_FAILED

        if refusal is None and marker_identity is None:
            refusal = ArtifactDenialReason.PLAN_CHANGED

        receipt = ArtifactAcceptance(
            run_id,
            grant.authorization.authorization_id,
            stage.lease_id,
            RawResultDigest(raw),
            checked_at.isoformat(),
            refusal,
            marker_identity,
        )

        return ArtifactExecutionOutcome(
            raw,
            grant,
            receipt,
            run_id,
            (stage.input.manifest, stage.scanner.manifest, stage.material.manifest),
        )

    def ValidateAcceptance(
        self,
        outcome: ArtifactExecutionOutcome,
        prepared: PreparedArtifact,
        stage: ArtifactStage,
        context: ArtifactPolicyContext,
        *,
        at: datetime,
    ) -> None:
        """Refresh original-run authority after raw capture and immediately before model acceptance.

        Args:
            outcome: Original immutable raw result and bound receipt.
            prepared: Original exact fixed request.
            stage: Original physical stage; relocation/replay never authorizes another launch.
            context: Fresh persisted scope/operator policy/owner.
            at: Aware result-acceptance time, including grant expiry during execution.

        Raises:
            ArtifactDeniedError: Refusal, non-success, stale authority or altered material/result.
            ValueError: Result/receipt types are malformed.
        """

        if not isinstance(outcome, ArtifactExecutionOutcome):
            raise ValueError("artifact acceptance requires an immutable per-run outcome")

        if prepared.workspace_root != self._root:
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        RequireTime(at)
        receipt = outcome.acceptance

        if (
            receipt.raw_sha256 != RawResultDigest(outcome.raw_result)
            or receipt.grant_id != outcome.grant.authorization.authorization_id
            or receipt.stage_lease != stage.lease_id
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        if receipt.refusal is not None:
            raise ArtifactDeniedError(receipt.refusal)

        if not (
            datetime.fromisoformat(outcome.grant.issued_at)
            <= datetime.fromisoformat(receipt.checked_at)
            < datetime.fromisoformat(outcome.grant.valid_until)
            and datetime.fromisoformat(receipt.checked_at) <= at
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        VerifyExecutionMarker(stage, outcome.run_id, receipt.grant_id, receipt.marker_identity)

        if not (
            outcome.raw_result.execution.state == ExecutionState.SUCCEEDED
            and outcome.raw_result.execution.exit_code == 0
            and outcome.raw_result.termination == ExecutionTermination.PROCESS_EXIT
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.EXECUTION_FAILED)

        self._engine.Validate(outcome.grant, prepared, stage, context, at=at, after_run=True)

    def ValidateAcceptanceFresh(
        self,
        outcome: ArtifactExecutionOutcome,
        prepared: PreparedArtifact,
        stage: ArtifactStage,
        context_provider: Callable[[], ArtifactPolicyContext],
    ) -> None:
        """Revalidate an original run and refresh authority/time after all expensive checks.

        Args:
            outcome: Original immutable raw result and acceptance receipt.
            prepared: Original exact operation-aware request.
            stage: Original single-run physical stage, never a relocated snapshot.
            context_provider: Synchronous canonical fresh current authority lookup.

        Raises:
            ArtifactDeniedError: Original result, material, authority or fresh expiry rejects.
        """

        self.ValidateAcceptancesFresh(((outcome, prepared, stage),), context_provider)

    def ValidatePairAcceptanceFresh(
        self,
        version: tuple[ArtifactExecutionOutcome, PreparedArtifact, ArtifactStage],
        scan: tuple[ArtifactExecutionOutcome, PreparedArtifact, ArtifactStage],
        context_provider: Callable[[], ArtifactPolicyContext],
    ) -> None:
        """Validate separate matching image VERSION/SCAN originals at one final fresh barrier.

        Args:
            version: Original VERSION outcome, exact request and physical stage.
            scan: Original SCAN outcome, exact request and distinct physical stage.
            context_provider: Fresh current same-store owner/scope/policy lookup.

        Raises:
            ArtifactDeniedError: Pairing, any original acceptance or final authority fails.
            ValueError: Pair members are structurally invalid.
        """

        for member in (version, scan):
            if (
                not isinstance(member, tuple) or len(member) != 3
                or not isinstance(member[0], ArtifactExecutionOutcome)
                or not isinstance(member[1], PreparedArtifact)
                or not isinstance(member[2], ArtifactStage)
            ):
                raise ValueError("artifact pair requires original typed run/request/stage tuples")

        version_outcome, version_prepared, version_stage = version
        scan_outcome, scan_prepared, scan_stage = scan
        version_plan = version_outcome.grant.plan
        scan_plan = scan_outcome.grant.plan
        prerequisite = scan_prepared.version_proof

        if (
            version_prepared.operation != ArtifactOperation.VERSION
            or scan_prepared.operation != ArtifactOperation.SCAN
            or version_plan.operation != ArtifactOperation.VERSION
            or scan_plan.operation != ArtifactOperation.SCAN
            or any(
                plan.producer_family != _IMAGE_FAMILY
                or plan.profile != ArtifactProfile.SYNTHETIC_IMAGE
                for plan in (version_plan, scan_plan)
            )
            or version_stage.root == scan_stage.root
            or version_stage.root_identity == scan_stage.root_identity
            or version_stage.lease_id == scan_stage.lease_id
            or version_outcome.run_id == scan_outcome.run_id
            or version_outcome.grant.authorization.authorization_id
            == scan_outcome.grant.authorization.authorization_id
            or version_outcome.manifests != scan_outcome.manifests
            or version_stage.executable != scan_stage.executable
            or version_stage.executable_identity != scan_stage.executable_identity
            or version_prepared.workspace_root != scan_prepared.workspace_root
            or version_plan.workspace_id != scan_plan.workspace_id
            or version_plan.owner_ref != scan_plan.owner_ref
            or version_plan.provider_version != scan_plan.provider_version
            or prerequisite is None
            or prerequisite.outcome != version_outcome
            or prerequisite.prepared != version_prepared
            or prerequisite.stage != version_stage
            or scan_plan.version_run_id != version_outcome.run_id
            or scan_plan.version_grant_id != version_outcome.grant.authorization.authorization_id
            or scan_plan.version_prerequisite_sha256 != prerequisite.Digest()
            or datetime.fromisoformat(version_outcome.acceptance.checked_at)
            > datetime.fromisoformat(scan_outcome.grant.issued_at)
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        self.ValidateAcceptancesFresh((version, scan), context_provider)

    def ValidateAcceptancesFresh(
        self,
        originals: tuple[tuple[ArtifactExecutionOutcome, PreparedArtifact, ArtifactStage], ...],
        context_provider: Callable[[], ArtifactPolicyContext],
    ) -> None:
        """Keep all original runs fresh after physical hashing before any consumer model write.

        Args:
            originals: Internally supplied one-run or accepted two-operation image tuples.
            context_provider: Canonical synchronous current authority provider, never a verdict.

        Raises:
            ArtifactDeniedError: Any original physical/material/authority binding changed.
        """

        for outcome, prepared, stage in originals:
            self.ValidateAcceptance(
                outcome, prepared, stage, self.CurrentContext(context_provider), at=self._clock()
            )

        for outcome, _, stage in originals:
            VerifyExecutionMarker(
                stage, outcome.run_id, outcome.acceptance.grant_id,
                outcome.acceptance.marker_identity,
            )

        for _ in range(2):
            current = self.CurrentContext(context_provider)

            for outcome, prepared, stage in originals:
                self._engine.ValidateCurrent(
                    outcome.grant, prepared, stage, current, at=self._clock()
                )
                self._engine.ValidateTime(
                    outcome.grant, stage, current, at=self._clock(),
                    version_proof=prepared.version_proof,
                )
