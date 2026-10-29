# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent inert Docker-save bytes test exact config binding without filesystem extraction."""

import hashlib
import io
import json
import tarfile

import pytest

from fuzzy1337 import local_image_archive as archive_module
from fuzzy1337.local_image_archive import InspectConfigId, LocalImageArchivePin, VerifyDockerSave

CONFIG = b'{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}'
CONFIG_ID = "sha256:" + hashlib.sha256(CONFIG).hexdigest()


def TarBytes(members):
    """Build explicitly inert regular or linked tar members with no Docker or external process."""

    output = io.BytesIO()

    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, raw, kind in members:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw) if kind == tarfile.REGTYPE else None)

    return output.getvalue()


def OriginalArchive(config=CONFIG, manifest=None, extra=()):
    """Keep the independent image config, manifest source and archive byte identities separate."""

    document = [{"Config": "config.json", "RepoTags": [], "Layers": []}]
    manifest = json.dumps(document).encode() if manifest is None else manifest

    return TarBytes((*(extra), ("manifest.json", manifest, tarfile.REGTYPE),
                     ("config.json", config, tarfile.REGTYPE)))


def test_OriginalExportBindsConfigBytesWithoutExtractingOrConflatingArchiveIdentity(monkeypatch):
    """Real tar parsing reads only in-memory members and keeps config/manifest scope distinct."""

    def Forbidden(*arguments, **options):
        """Refuse any filesystem extraction from original export bytes."""

        raise AssertionError("Local image identity verification must never extract tar paths")

    monkeypatch.setattr(tarfile.TarFile, "extract", Forbidden)
    monkeypatch.setattr(tarfile.TarFile, "extractall", Forbidden)
    raw = OriginalArchive()
    pin = VerifyDockerSave(raw, CONFIG_ID)
    assert pin.image_config_id == CONFIG_ID and (
        pin.archive_sha256 == hashlib.sha256(raw).hexdigest()
    ), (
        "The accepted image config and complete original export must retain independent hashes."
    )
    assert pin.size_bytes == len(raw) and pin.Manifest().files[0].sha256 == pin.archive_sha256, (
        "Only the complete accepted tar bytes may identify the separately approved native input."
    )
    assert pin.Manifest().Target().value != (
        "manifest-sha256:" + CONFIG_ID.removeprefix("sha256:")
    ), (
        "An image config hash must never masquerade as its native archive scope target."
    )


@pytest.mark.parametrize("raw", [
    b'{"Id":"sha256:' + b"a" * 64 + b'","Id":"sha256:' + b"b" * 64 + b'","Os":"linux"}',
    b'{"Id":"short","Os":"linux"}', b'[{"Id":"short"}]', b'{}',
    b'{"Id":"sha256:' + b"a" * 64 + b'","Os":"windows"}',
    b'{"Id":"sha256:' + b"a" * 64 + b'","Os":"linux","x":NaN}',
    b'{"Id":"sha256:' + b"a" * 64 + b'","Os":"linux","x":1e999}', b"\xff",
])
def test_InvalidInspectFactsCannotResolveAnExport(raw):
    """Duplicate identities, unsupported OS, malformed bytes and nonfinite data refuse."""

    with pytest.raises(ValueError):
        InspectConfigId(raw)


def test_InspectRetainsTheExactConfigIdentity():
    """Only an explicitly reported full Linux config ID supplies the resolution fact."""

    raw = json.dumps({"Id": CONFIG_ID, "Os": "linux", "RepoTags": ["owned:local"]}).encode()
    assert InspectConfigId(raw) == CONFIG_ID, "Original inspect identity must remain exact."


@pytest.mark.parametrize("fault", [
    "wrong-config", "missing-config", "two-images", "duplicate-key", "traversal",
    "duplicate-member", "symlink", "missing-manifest", "not-tar", "config-oversize",
    "trailing-data", "missing-eof",
])
def test_MalformedOrUnboundExportsCannotBecomeAcceptedNativeArchives(fault):
    """Manifest/config/member faults fail before a later native input can be described."""

    raw = OriginalArchive()

    if fault == "wrong-config":
        raw = OriginalArchive(config=b"different original config")

    elif fault == "missing-config":
        raw = OriginalArchive(manifest=b'[{"Config":"missing.json"}]')

    elif fault == "two-images":
        raw = OriginalArchive(manifest=b'[{"Config":"config.json"},{"Config":"config.json"}]')

    elif fault == "duplicate-key":
        raw = OriginalArchive(manifest=b'[{"Config":"config.json","Config":"other.json"}]')

    elif fault == "traversal":
        raw = OriginalArchive(extra=(("../escape", b"inert", tarfile.REGTYPE),))

    elif fault == "duplicate-member":
        raw = OriginalArchive(extra=(("config.json", CONFIG, tarfile.REGTYPE),))

    elif fault == "symlink":
        raw = OriginalArchive(extra=(("linked", b"", tarfile.SYMTYPE),))

    elif fault == "missing-manifest":
        raw = TarBytes((("config.json", CONFIG, tarfile.REGTYPE),))

    elif fault == "not-tar":
        raw = b"not an archive"

    elif fault == "trailing-data":
        raw += b"unparsed bytes cannot become an accepted archive"

    elif fault == "missing-eof":
        raw = raw.rstrip(b"\0")

    else:
        raw = OriginalArchive(config=b"x" * (1024 * 1024 + 1))

    with pytest.raises(ValueError):
        VerifyDockerSave(raw, CONFIG_ID)


def test_OriginalArchiveByteLimitRefusesBeforeTarParsing(monkeypatch):
    """A complete original over the declared export budget cannot be accepted as a prefix."""

    raw = OriginalArchive()
    monkeypatch.setattr(archive_module, "LOCAL_IMAGE_ARCHIVE_BYTES", len(raw) - 1)

    with pytest.raises(ValueError, match="original bound"):
        VerifyDockerSave(raw, CONFIG_ID)


@pytest.mark.parametrize("config_id, digest, size", [
    ("owned:local", "a" * 64, 512), (CONFIG_ID, "invalid", 512),
    (CONFIG_ID, "a" * 64, -1), (CONFIG_ID, "a" * 64, True),
])
def test_DescriptiveArchivePinCannotCarryInvalidIdentityFacts(config_id, digest, size):
    """A plain descriptive constructor is no proof and still refuses malformed metadata."""

    with pytest.raises(ValueError):
        LocalImageArchivePin(config_id, digest, size)
