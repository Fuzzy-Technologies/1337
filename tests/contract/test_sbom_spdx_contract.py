# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent source consumers verify emitted SPDX aliases and canonical package identities."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.images import ImageIdentity, PackageIdentity
from fuzzy1337.model import LocalModelStore, ModelProvenance
from fuzzy1337.sbom_spdx import ApplyVerifiedSpdx
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("name,hash_letter,kind", [
    ("spdx.image.v2.3.json", "a", "config"),
    ("spdx.image.manifest.v2.3.json", "b", "manifest"),
    ("spdx.namespaces.v2.3.json", "a", "config"),
    ("spdx.license-status.v2.3.json", "a", "config"),
])
def test_HandWrittenSourceAliasesResolveIndependently(tmp_path, name, hash_letter, kind):
    """Source alias records locate actual independent package declarations, not fabricated rows."""

    raw = (ROOT / "tests/contract/fixtures" / name).read_bytes()
    source = json.loads(raw)
    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(
        WorkspaceConfiguration("SPDX contract fixture"), "spdx-contract",
    )
    store = LocalEvidenceStore(root / "evidence")
    record = store.Put(raw, "sbom", "application/json", EvidenceProvenance(
        "spdx-contract", "scope:owned", "inventory.spdx", "1", None,
        "2026-10-13T00:00:00Z", "2026-10-13T00:00:01Z",
    ))
    provenance = ModelProvenance("inventory.spdx", "run:contract", record.provenance.finished_at,
        "scope:owned", "target:owned", evidence_references=(record.reference,))
    image = ImageIdentity("sha256:" + hash_letter * 64, kind)
    state, _ = ApplyVerifiedSpdx(LocalModelStore(root).Create(), record, provenance, image, root)
    rows = {package["SPDXID"]: package for package in source["packages"]}
    aliases = [item for item in state.observations if item.kind == "spdx-source-alias"]
    assert len(aliases) == len(rows), "A source package alias was omitted or invented"

    for alias in aliases:
        package = rows[alias.attributes["spdx_id"]]
        assert alias.attributes["document_sha256"] == record.reference.sha256, (
            "Source alias was detached from its verified document digest"
        )
        if package.get("primaryPackagePurpose") == "CONTAINER":
            expected = image.Object(state.workspace_id)
        else:
            references = [item["referenceLocator"] for item in package["externalRefs"]
                          if item["referenceType"] == "purl"]
            assert len(references) == 1, "Independent fixture contains an ambiguous package PURL"
            expected = PackageIdentity.FromPurl(references[0]).Object(state.workspace_id)
        assert alias.subject_reference == expected.Reference(), "Alias resolved to another package"
    assert store.Read(record.reference) == raw, "Interpretation changed independent source evidence"
