# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic owned archive/cache fixtures; no build, image runtime or external database."""

from __future__ import annotations

import hashlib
import json
import tarfile
from io import BytesIO
from pathlib import Path

PROVIDER_VERSION = "0.75.0-synthetic"
DATABASE_METADATA = {
    "Version": 2,
    "UpdatedAt": "2026-10-01T00:00:00Z",
    "NextUpdate": "2026-10-02T00:00:00Z",
    "DownloadedAt": "2026-10-01T01:00:00Z",
}
FIXTURE_ID = "owned-synthetic-image-wire-v1"
SCENARIOS = (
    "success", "no_findings", "provider_error", "malformed", "version_mismatch",
    "package_mismatch", "output_limit", "hold",
)


def JsonBytes(value: object) -> bytes:
    """Encode standards-compliant deterministic fixture metadata without a clock."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def Digest(data: bytes) -> str:
    """Keep content hashes algorithm-labelled and distinct from provider identities."""

    return "sha256:" + hashlib.sha256(data).hexdigest()


def TarBytes(members: tuple[tuple[str, bytes], ...]) -> bytes:
    """Construct finite regular members with stable USTAR headers and no extraction."""

    output = BytesIO()

    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.uid = info.gid = info.mtime = 0
            archive.addfile(info, BytesIO(data))

    return output.getvalue()


def ArchiveBytes(scenario: str = "success") -> bytes:
    """Build one tiny Docker-save-shaped archive with independently hashable config/layer bytes.

    The additional scenario and OCI manifest members belong to this fixture only.
    Genuine Docker/Trivy decoding compatibility has not been executed.
    """

    if scenario not in SCENARIOS:
        raise ValueError("unsupported owned image fixture scenario")

    layer = TarBytes((
        ("1337-fixture.txt", b"Owned inert image fixture; no package installation\n"),
    ))
    layer_digest = Digest(layer)
    config = JsonBytes({
        "architecture": "amd64", "os": "linux", "config": {},
        "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
    })
    config_name = hashlib.sha256(config).hexdigest() + ".json"
    layer_name = layer_digest[7:] + "/layer.tar"
    manifest = JsonBytes({
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": Digest(config), "size": len(config)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": layer_digest, "size": len(layer)}],
    })

    return TarBytes((
        ("manifest.json", JsonBytes([{"Config": config_name, "RepoTags": [],
                                      "Layers": [layer_name]}])),
        (config_name, config), (layer_name, layer), ("oci-manifest.json", manifest),
        ("1337-fixture.json", JsonBytes({"scenario": scenario})),
    ))


def CreateFixture(root: Path, scenario: str = "success") -> tuple[Path, Path]:
    """Write only a selected test directory, image input and immutable synthetic policy data."""

    root.mkdir(parents=True, exist_ok=True)
    (root / "input").mkdir()
    (root / "material").mkdir()
    (root / "scratch").mkdir()
    image = root / "input" / "image.tar"
    image.write_bytes(ArchiveBytes(scenario))
    policy = root / "material" / "policy.json"
    policy.write_bytes(JsonBytes({
        "schema_version": 1, "fixture_id": FIXTURE_ID, "provider_version": PROVIDER_VERSION,
        "database_metadata": DATABASE_METADATA,
    }))

    return image, policy
