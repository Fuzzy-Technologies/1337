# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent owned native-image bytes, advisory boundary and inert archive contract."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from tests.fixtures.trivy.native_archive import ArchiveBytes

ORACLE = json.loads((Path(__file__).parents[1] / "fixtures/trivy/native_oracle.json").read_bytes())


@pytest.mark.parametrize("case", ORACLE["cases"])
def test_IndependentOwnedArchiveOracleRetainsExactInertMetadata(case):
    """Archive identity and package metadata match the separately authored advisory oracle."""

    raw = ArchiveBytes(case["version"])
    assert len(raw) == case["archive_size_bytes"], (
        "Native fixture size must remain independently pinned"
    )
    assert hashlib.sha256(raw).hexdigest() == case["archive_sha256"], (
        "Native fixture bytes must not drift without explicit oracle review"
    )

    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        members = archive.getmembers()
        assert len(members) == 3 and all(member.isfile() for member in members), (
            "The owned Docker-save archive contains only three inert regular members"
        )
        manifest = json.load(archive.extractfile("manifest.json"))
        config = json.load(archive.extractfile(manifest[0]["Config"]))
        layer = archive.extractfile("layer.tar").read()
        assert config["rootfs"]["diff_ids"] == ["sha256:" + hashlib.sha256(layer).hexdigest()], (
            "Config DiffID identifies the exact inert layer, separately from archive identity"
        )

    with tarfile.open(fileobj=io.BytesIO(layer)) as archive:
        members = archive.getmembers()
        assert len(members) == 2 and all(member.isfile() for member in members), (
            "The metadata layer contains no package implementation, executable or link"
        )
        metadata = archive.extractfile(members[0]).read().decode()
        assert "Name: requests\n" in metadata and f"Version: {case['version']}\n" in metadata, (
            "The native analyzer sees the exact independent package/version specimen"
        )
        assert archive.extractfile(members[1]).read() == b"", "The owned RECORD is inert"


def test_NativeFixtureRejectsUnreviewedPackageVersions():
    """No caller-selected dependency or arbitrary source data enters this known-answer fixture."""

    with pytest.raises(ValueError, match="unsupported native acceptance"):
        ArchiveBytes("unreviewed-version")


def test_AdvisoryOracleKeepsSpecificBoundaryWithoutCleanScanClaim():
    """Only the independently selected advisory changes across the fixture boundary."""

    assert ORACLE["advisory_id"] == "CVE-2023-32681", "Oracle identity follows the PSF advisory"
    assert [case["expected_advisory_match"] for case in ORACLE["cases"]] == [True, False], (
        "The advisory's vulnerable/fixed version boundary is independently declared"
    )
    assert ORACLE["scan_completeness"] == "not-assessed", "One advisory is not scanner completeness"
