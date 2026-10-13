# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent canonical artifact identity, exact fields and existing scope-store contracts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from fuzzy1337.artifact_inputs import ArtifactFile, ArtifactManifest, ArtifactProfile, ArtifactRole
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
