# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise the release consumer against the actual shared immutable archive verifier."""

import hashlib
import io
import json
import tarfile

import pytest

from tools import release_delivery as delivery


@pytest.mark.integration
@pytest.mark.parametrize("fault", [None, "source-tree", "archive-bytes"])
def test_ReleaseConsumesActualSharedVersionTransferWithoutRendering(tmp_path, fault):
    """Verify a finite marked archive through both real modules and refuse changed source/bytes."""

    source = {"version": "0.3.0", "commit": "a" * 40, "tree": "b" * 40,
              "source_date_epoch": 1790000000}
    files = {f"{locale}/index.html": b"<!doctype html><html><body>marked fixture</body></html>"
             for locale in ("en", "ru", "zh-cn")}
    inventory = {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}
    provenance = {"schema_version": 1, "version": source["version"], "revision": source["commit"],
        "tree": source["tree"], "base_path": "/1337", "locales": ["en", "ru", "zh-cn"],
        "source_date_epoch": source["source_date_epoch"], "files": inventory,
        "artifact_sha256": hashlib.sha256(json.dumps(inventory, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()}
    original = json.dumps(provenance, sort_keys=True).encode()
    files["api-version-provenance.json"] = original
    archive = tmp_path / "1337-0.3.0-api-docs.tar.gz"

    with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as stream:
        for name, raw in sorted(files.items()):
            member = tarfile.TarInfo("0.3.0/" + name)
            member.size = len(raw)
            member.mtime = source["source_date_epoch"]
            stream.addfile(member, io.BytesIO(raw))

    transfer = {key: value for key, value in provenance.items()
                if key not in {"files", "artifact_sha256"}}
    transfer.update(filename=archive.name, sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        size_bytes=archive.stat().st_size, provenance_sha256=hashlib.sha256(original).hexdigest())
    delivery.WriteJson(tmp_path / "1337-0.3.0-api-docs.manifest.json", transfer)

    if fault == "source-tree":
        source["tree"] = "c" * 40

    elif fault == "archive-bytes":
        archive.write_bytes(archive.read_bytes() + b"changed original archive")

    if fault is None:
        before = archive.read_bytes()
        assert delivery.VerifyDocumentationTransfer(tmp_path, source) == transfer, (
            "The actual shared verifier must preserve the exact source-bound transfer manifest")
        assert archive.read_bytes() == before and len(tuple(tmp_path.iterdir())) == 2, (
            "Verification must keep original archive bytes and remove its private extraction state")

    else:
        with pytest.raises(ValueError):
            delivery.VerifyDocumentationTransfer(tmp_path, source)
