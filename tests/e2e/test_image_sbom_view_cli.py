# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed image/SBOM query joins actual owned imports without inferring runtime exposure."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess

from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from tests.docker_helpers import Payload
from tests.runtime_helpers import Arguments as RuntimeArguments
from tests.sbom_helpers import FIXTURES, IMAGE_DIGEST, Arguments, Context, ViewArguments


def Console(parent, namespace, arguments):
    """Invoke the installed product entry point from outside the source tree."""

    executable = shutil.which("1337")
    assert executable is not None, "The package installation must expose its actual console"
    result = subprocess.run([executable, namespace, *arguments, "--json"], cwd=parent,
                            capture_output=True, check=False, text=True, timeout=30)
    assert not result.stderr, "The installed product must preserve safe terminal diagnostics"

    return result.returncode, json.loads(result.stdout)


def test_InstalledImageViewJoinsOriginalGraphAndDockerImportsWithExplicitKinds(tmp_path):
    """Operators can inspect nested source packages and their explicit configured containers."""

    owned = Context(tmp_path)

    for kind in ("config", "manifest"):
        status, outcome = Console(tmp_path, "sbom", Arguments(owned, digest_kind=kind))
        assert status == 0 and outcome["status"] == "succeeded", (
            "Both explicit digest kinds must acquire their own original image-bound source custody"
        )

    store = LocalModelStore(owned.root)
    basis = store.Open()
    provenance = ModelProvenance("synthetic.host", "run:host", "2026-10-14T09:00:00Z",
                                "scope:owned", "host:owned")
    host = SecurityObject(ObjectIdentity(basis.workspace_id, ObjectKind.HOST, "192.0.2.1"),
                          {"fixture_kind": "owned-explicit-host"}, (provenance,))
    proposed, _ = basis.Apply(objects=(host,))
    store.Save(proposed, expected_revision=basis.revision)
    payload = Payload()

    for container in payload:
        container["Image"] = IMAGE_DIGEST

    source = tmp_path / "owned inspect.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    runtime = (owned.root, proposed, host, LocalEvidenceStore(owned.root / "evidence"), source)
    status, imported = Console(tmp_path, "runtime", RuntimeArguments(runtime))
    assert status == 0, "Actual runtime console must save its exact owned inspect image use"
    record = runtime[3].Get(imported["evidence_id"])
    saved = store.Open()
    oracle = json.loads((FIXTURES / "spdx.graph.oracle.json").read_bytes())
    expected_packages = {key for key in oracle["package_keys"].values()
                         if key.startswith("package-version:")}
    objects = {item.Reference(): item for item in saved.objects}
    relations = {item.Reference(): item for item in saved.relations}
    before = {path.relative_to(owned.root): path.read_bytes()
              for path in owned.root.rglob("*") if path.is_file()}
    results = {}

    for kind in ("config", "manifest"):
        status, view = Console(tmp_path, "sbom", ViewArguments(owned, kind=kind))
        assert status == 0 and view["model_revision"] == saved.revision, (
            "The installed image view must pin the actual verified saved model revision"
        )
        digest = hashlib.sha256(json.dumps(saved.ToDict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        assert view["snapshot_sha256"] == digest and view["inventory_status"] == "observed", (
            "The query must identify its complete canonical source snapshot without a clean verdict"
        )
        assert {objects[item].identity.key for item in view["package_references"]} == (
            expected_packages
        ), "Nested package inventory must match the independent handwritten source identity oracle"
        assert len(view["containment_relation_references"]) == oracle["canonical_contains_count"], (
            "Inventory traversal must retain original containment and exclude dependency claims"
        )
        results[kind] = view

    assert results["config"]["image_reference"] != results["manifest"]["image_reference"] and (
        not results["manifest"]["docker_uses"] and len(results["config"]["docker_uses"]) == 2
    ), "Equal checksum bytes with manifest semantics cannot borrow Docker's config image use"

    for use in results["config"]["docker_uses"]:
        relation = relations[use["relation_reference"]]
        container = objects[use["container_reference"]]
        assert relation.source_reference == results["config"]["image_reference"] and (
            relation.target_reference == container.Reference()
            and relation.provenance[0].evidence_references == (record.reference,)
            and container.attributes["image_reference"] == relation.source_reference
        ), "Every returned Docker link must resolve its exact original attributed association"
        assert use["runtime_reachability"] == "unknown" and use["runtime_reason"] == (
            "not-evaluated"
        ), "Configured image use must not become confirmed vulnerability exposure or reachability"

    after = {path.relative_to(owned.root): path.read_bytes()
             for path in owned.root.rglob("*") if path.is_file()}
    assert before == after, "Installed queries must preserve all evidence and saved owner bytes"
    assert runtime[3].Read(record.reference) == source.read_bytes(), (
        "Installed cross-source query must retain complete original inspect bytes"
    )
    blob = runtime[3].StoragePath(("blobs", "sha256", record.reference.sha256))
    blob.write_bytes(b"corrupt owned original")
    status, refusal = Console(tmp_path, "sbom", ViewArguments(owned))
    assert status == 4 and refusal["status"] == "failed" and (
        "package_references" not in refusal
    ), "A changed retained original must refuse the whole view without partial inventory output"
