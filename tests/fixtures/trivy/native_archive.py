# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic owned Docker-save archives containing inert Python package metadata only."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile

VERSIONS = ("2.30.0", "2.31.0")


def TarBytes(members: tuple[tuple[str, bytes], ...]) -> bytes:
    """Write bounded regular USTAR members without paths being extracted or executed."""

    output = io.BytesIO()

    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in members:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(content))

    return output.getvalue()


def JsonBytes(value: object) -> bytes:
    """Keep image config and manifest byte identities independent and reproducible."""

    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def ArchiveBytes(package_version: str) -> bytes:
    """Construct a single-layer owned image with declared requests metadata and no program code.

    Args:
        package_version: One of the independently selected advisory boundary versions.

    Returns:
        Docker-save bytes with one inert package metadata layer and exact config DiffID.

    Raises:
        ValueError: A caller attempts an unreviewed fixture version.
    """

    if package_version not in VERSIONS:
        raise ValueError("unsupported native acceptance fixture version")

    base = f"usr/local/lib/python3.11/site-packages/requests-{package_version}.dist-info/"
    metadata = (f"Metadata-Version: 2.1\nName: requests\nVersion: {package_version}\n"
                "Summary: Owned inert scanner metadata fixture\nLicense: Apache-2.0\n\n").encode()
    layer = TarBytes(((base + "METADATA", metadata), (base + "RECORD", b"")))
    diff_id = "sha256:" + hashlib.sha256(layer).hexdigest()
    config = JsonBytes({"architecture": "amd64", "os": "linux", "config": {},
        "rootfs": {"type": "layers", "diff_ids": [diff_id]}})
    config_name = hashlib.sha256(config).hexdigest() + ".json"
    manifest = JsonBytes([{"Config": config_name, "RepoTags": [], "Layers": ["layer.tar"]}])

    return TarBytes((("manifest.json", manifest), (config_name, config), ("layer.tar", layer)))
