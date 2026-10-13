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


@pytest.mark.parametrize("raw,expected", [
    ("", True), ("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n", True),
    ("Iface\tDestination\tGateway\neth0\t00000000\t0100007F\n", False),
    ("eth0\t00000000\t0100007F\n", False), ("Unrecognized kernel route output\n", False),
    ("Iface Destination Gateway garbage\n", False),
    ("Iface Destination Gateway eth0 00000000 0100007F\n", False),
])
def test_IsolatedIpv4RouteTableAcceptsBothEmptyKernelForms(raw, expected):
    """Actual CI's headerless empty table remains no-routes while every route stays refused."""

    from tests.integration.test_trivy_native import NoIpv4Routes

    assert NoIpv4Routes(raw) is expected, (
        "Route validation must accept genuine empty/header-only tables and reject route content"
    )


def test_OwnedNativeEvidenceRootExistsBeforeAnyProviderWork(tmp_path, monkeypatch):
    """Initialize canonical storage before any owned provider output can be captured."""

    from fuzzy1337.adapters.trivy import TrivyAdapter
    from tests.integration.test_trivy_native import RunNative

    (tmp_path / "trivy-cache").mkdir()

    def StopBeforeProviderWork(adapter):
        """Inspect only owned initialization and stop before any native process can run."""

        assert (tmp_path / "evidence").is_dir(), (
            "Actual evidence root must exist before version probing or scan execution"
        )

        raise RuntimeError("owned provider checkpoint")

    monkeypatch.setattr(TrivyAdapter, "ProbeHealth", StopBeforeProviderWork)

    with pytest.raises(RuntimeError, match="owned provider checkpoint"):
        RunNative(tmp_path, tmp_path / "unused-executable", "2.30.0")
