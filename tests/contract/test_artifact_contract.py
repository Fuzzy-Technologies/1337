# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent canonical artifact identity, exact fields and existing scope-store contracts."""

from __future__ import annotations

import hashlib
import json
import traceback
from pathlib import Path

import jsonschema
import pytest

from fuzzy1337.artifact_inputs import ArtifactFile, ArtifactManifest, ArtifactProfile, ArtifactRole
from fuzzy1337.artifact_policy import VerifyArtifactReplay
from fuzzy1337.scope import Matches, ScopeSnapshot, Target, TargetKind


def Manifest():
    """Build one finite independent input manifest with a known byte digest."""

    return ArtifactManifest(
        ArtifactProfile.SYNTHETIC_IMAGE,
        ArtifactRole.INPUT,
        (ArtifactFile("image.tar", 5, hashlib.sha256(b"owned").hexdigest()),),
    )


def test_ExactCanonicalManifestDigestAndArchiveNamespaceAreDistinct():
    """The independent consumer hashes version/profile/role/files, never just archive bytes."""

    manifest = Manifest()
    expected = {
        "schema_version": 1,
        "profile": "synthetic.image-archive-offline.v1",
        "role": "input",
        "files": [
            {"name": "image.tar", "size_bytes": 5, "sha256": hashlib.sha256(b"owned").hexdigest()}
        ],
    }
    encoded = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()

    assert manifest.ToDict() == expected, "Manifest exact fields drifted"
    assert manifest.Digest() == hashlib.sha256(encoded).hexdigest(), (
        "Manifest digest encoding drifted"
    )
    assert manifest.Target().value == "manifest-sha256:" + hashlib.sha256(encoded).hexdigest(), (
        "Artifact scope target confused digest roles"
    )
    assert manifest.Digest() != expected["files"][0]["sha256"], "Archive/manifest digest collapsed"
    assert ArtifactManifest.FromDict(expected) == manifest, "Canonical manifest roundtrip changed"


def test_SchemaAndSameScopeSnapshotSupportOnlyExactArtifactTarget():
    """Artifact targets reuse scope schema1 without matching CIDRs, URLs or OCI strings."""

    manifest = Manifest()
    schema_path = Path(__file__).resolve().parents[2] / "contracts/artifact-manifest.schema.json"
    jsonschema.Draft202012Validator(json.loads(schema_path.read_text())).validate(manifest.ToDict())
    target = manifest.Target()
    scope = ScopeSnapshot("artifact", "owned", targets=(target,), allow=(target,))

    assert ScopeSnapshot.FromDict(scope.ToDict()) == scope, (
        "Existing scope persistence rejected artifact"
    )
    assert Matches(target, target), "Exact artifact membership did not match"
    assert not Matches(Target(TargetKind.NETWORK, "192.0.2.0/24"), target), (
        "Network allowed artifact"
    )
    assert not Matches(target, Target(TargetKind.URL, "https://example.test/"), denying=True), (
        "Artifact target entered URL authority expansion"
    )


@pytest.mark.parametrize(
    "value",
    [
        "sha256:" + "0" * 64,
        "manifest-sha256:" + "A" * 64,
        "manifest-sha256:" + "0" * 63,
        "/owned/archive.tar",
        "0" * 64,
    ],
    ids=["oci-prefix", "uppercase", "short-digest", "physical-path", "missing-prefix"],
)
def test_ArtifactTargetRejectsOciPathAndNoncanonicalDigests(value):
    """No path, OCI spelling or heuristic kind inference can grant an artifact scope."""

    with pytest.raises(ValueError):
        Target(TargetKind.ARTIFACT, value)


@pytest.mark.parametrize(
    "mutation",
    [
        "version",
        "boolean-version",
        "extra",
        "file-extra",
        "missing",
        "bad-profile",
        "bad-role",
        "not-list",
    ],
)
def test_ManifestReaderRejectsUnsupportedOrAmbiguousFields(mutation):
    """Exact reader contract fails before any filesystem read."""

    document = Manifest().ToDict()

    if mutation == "version":
        document["schema_version"] = 2

    elif mutation == "boolean-version":
        document["schema_version"] = True

    elif mutation == "extra":
        document["extra"] = "owned"

    elif mutation == "file-extra":
        document["files"][0]["source"] = "owned-source"

    elif mutation == "missing":
        del document["files"][0]["sha256"]

    elif mutation == "bad-profile":
        document["profile"] = "arbitrary.command"

    elif mutation == "bad-role":
        document["role"] = "arbitrary"

    else:
        document["files"] = {}

    with pytest.raises(ValueError):
        ArtifactManifest.FromDict(document)


def test_NetworkIssuanceExplicitlyRejectsArtifactEvenWithLiteralIp():
    """The network producer independently rejects the new same-store target namespace."""

    from datetime import datetime, timezone

    from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ImpactLevel
    from fuzzy1337.executors import CapabilityDescriptor
    from fuzzy1337.policy import (
        ImpactPolicy,
        PolicyContext,
        PolicyDenialReason,
        PolicyDeniedError,
        PolicyEngine,
    )

    target = Manifest().Target()
    ip = Target(TargetKind.IP, "192.0.2.1")
    scope = ScopeSnapshot("network", "owned", targets=(target, ip), allow=(target, ip))
    policy = ImpactPolicy("network")

    with pytest.raises(ValueError):
        PolicyContext(scope, policy, target, (ip,))

    context = PolicyContext(scope, policy, ip, (ip,))
    object.__setattr__(context, "target", target)
    invocation = AdapterInvocation(
        "test.provider", AdapterRequest("test.capability", target.Reference(), ImpactLevel.SAFE),
        ("never-launch",), 1,
    )

    with pytest.raises(PolicyDeniedError) as rejected:
        PolicyEngine().Plan(
            invocation, CapabilityDescriptor("test.capability", "test.provider", ImpactLevel.SAFE),
            context, at=datetime(2026, 10, 13, tzinfo=timezone.utc),
        )

    assert rejected.value.reason == PolicyDenialReason.TARGET_MISMATCH, (
        "Artifact target reached network scope/capability issuance"
    )


def FrozenLegacyCapture():
    """Read immutable actual base-SDK bytes without a current grant or acquisition stage."""

    fixture = Path(__file__).resolve().parent / "fixtures/artifact_replay"
    metadata = (fixture / "schema1-metadata.json").read_bytes()
    stdout = (fixture / "schema1-stdout.bin").read_bytes()
    stderr = (fixture / "schema1-stderr.bin").read_bytes()
    assert hashlib.sha256(metadata).hexdigest() == (
        "4e5d538f3630757eadd2cbcd8be077a7f5471c46585d8594bae9f7da64334563"
    ), "Original schema1 metadata fixture changed"
    assert hashlib.sha256(stdout).hexdigest() == (
        "76613b243099e09fda13117811c3651bc1918cc3772da07fd0601e8c5106c333"
    ), "Original captured schema1 raw stdout bytes changed"
    assert stderr == b"", "Original empty stderr must remain an actual preserved stream"

    return json.loads(metadata), stdout, stderr


def test_FrozenActualSchemaOneReplayRetainsOriginalIntentEnvelopeAndReceipt(monkeypatch):
    """New defaults never enter hashing of a real old acquisition after its stage was removed."""

    from fuzzy1337.artifact_inputs import ArtifactStage
    from fuzzy1337.scope import LocalScopeStore

    def ForbiddenPhysicalLookup(*args, **kwargs):
        """Historical verification must use original facts instead of current stage/authority."""

        raise AssertionError("Schema1 replay attempted current physical or authority lookup")

    monkeypatch.setattr(ArtifactStage, "Verify", ForbiddenPhysicalLookup)
    monkeypatch.setattr(LocalScopeStore, "Open", ForbiddenPhysicalLookup)
    metadata, stdout, stderr = FrozenLegacyCapture()
    assert metadata["grant"]["plan"]["intent_sha256"] == (
        "b925f262e2e4a2c572d54da63a3f7b6daeeaa1c0c737c538f8287409d3ad2295"
    ), "Original plan intent was recomputed using a new field shape"
    receipt = VerifyArtifactReplay(metadata, stdout, stderr)
    assert receipt.grant_id == (
        "artifact-authorization:0bba640c5ae94c199965befa14321f03b5fb5851bb29a855e54af479385a7044"
    ), "Historical grant envelope was upgraded or replaced"
    assert receipt.run_id == metadata["acceptance"]["run_id"] and receipt.refusal is None, (
        "Historical replay must retain the original accepted run identity"
    )
    assert set(metadata["grant"]["plan"]) == {
        "owner_ref", "profile", "provider_version", "input_manifest_sha256",
        "scanner_manifest_sha256", "material_manifest_sha256", "workspace_id",
        "scope_reference", "scope_revision", "scope_sha256", "policy_reference",
        "policy_revision", "policy_sha256", "target_reference", "stage_sha256",
        "stage_lease", "request_sha256", "invocation_sha256", "granted_privileges",
        "intent_sha256",
    }, "Legacy verification injected operation/family/prerequisite defaults"


@pytest.mark.parametrize("field", [
    "operation", "producer_family", "version_run_id", "version_grant_id",
    "version_prerequisite_sha256",
])
def test_FrozenSchemaOneNeverAcceptsInjectedOperationOrVersionPrerequisite(field):
    """Legacy original facts cannot become richer schema2 authority through field injection."""

    metadata, stdout, stderr = FrozenLegacyCapture()
    metadata["grant"]["plan"][field] = None

    with pytest.raises(ValueError):
        VerifyArtifactReplay(metadata, stdout, stderr)


@pytest.mark.parametrize("field", ["profile", "role"])
def test_ReplayManifestFailuresNeverEchoPrivateUntrustedEnumText(field):
    """Saved hostile fields reject without exposing original raw values in chained diagnostics."""

    metadata, stdout, stderr = FrozenLegacyCapture()
    metadata["manifests"][0][field] = "OWNED_PRIVATE_REPLAY_MARKER"

    with pytest.raises(ValueError) as refused:
        VerifyArtifactReplay(metadata, stdout, stderr)

    assert "OWNED_PRIVATE_REPLAY_MARKER" not in "".join(
        traceback.format_exception(refused.value)
    ), "Replay refusal must not expose private raw manifest values in its traceback"
