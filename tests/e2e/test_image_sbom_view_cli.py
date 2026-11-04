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
    expectedPackages = {key for key in oracle["package_keys"].values()
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
            expectedPackages
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


def test_InstalledImageLicensePolicyKeepsExactSourcesRolesAndDigestKindsAfterRelocation(tmp_path):
    """Match explicit caller policy to original assertions without a package/global verdict."""

    owned = Context(tmp_path)
    status, config = Console(tmp_path, "sbom", Arguments(owned))
    assert status == 0, "The actual product must first acquire the unchanged config source"
    payload = json.loads(owned.source.read_bytes())
    library = next(package for package in payload["packages"]
                   if package["SPDXID"] == "SPDXRef-Lib")
    library["licenseDeclared"] = "GPL-2.0-only"
    library["licenseConcluded"] = "MIT"
    owned.source.write_text(json.dumps(payload), encoding="utf-8")
    status, manifest = Console(tmp_path, "sbom", Arguments(owned, digest_kind="manifest"))
    assert status == 0 and manifest["evidence_id"] != config["evidence_id"], (
        "The independent manifest image source must retain its different original declaration"
    )
    owned.source.unlink()
    relocated = tmp_path / "relocated workspace"
    shutil.copytree(owned.root, relocated)
    saved = LocalModelStore(relocated).Open()
    observations = {item.Reference(): item for item in saved.observations}
    before = {path.relative_to(relocated): path.read_bytes()
              for path in relocated.rglob("*") if path.is_file()}
    selected = {}

    for kind, source in (("config", config), ("manifest", manifest)):
        arguments = ViewArguments(owned, kind=kind)
        arguments[1] = str(relocated)
        status, default = Console(tmp_path, "sbom", arguments)
        assert status == 0 and "license_policy" not in default, (
            "The existing default output remains unchanged without explicit caller policy"
        )
        arguments.extend(["--license-policy", "owned-review-v1", "--allow-license", "MIT",
                          "--deny-license", "Apache-2.0"])
        status, result = Console(tmp_path, "sbom", arguments)
        assert status == 0 and result["snapshot_sha256"] == default["snapshot_sha256"], (
            "The new read-only policy route must retain the exact same verified source snapshot"
        )
        policy = result["license_policy"]
        assert policy["source_profile"] == "owned-spdx-graph-v1" and policy["policy"] == {
            "profile": "spdx-expression-policy-v1", "policy_id": "owned-review-v1",
            "allowed": ["mit"], "denied": ["apache-2.0"],
            "sha256": hashlib.sha256(json.dumps({"profile": "spdx-expression-policy-v1",
                "policy_id": "owned-review-v1", "allowed": ["mit"], "denied": ["apache-2.0"]},
                sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        }, "The installed result must identify every explicit caller decision and its profile"
        assertions = [item for package in policy["packages"] for item in package["assertions"]]
        assert len(assertions) == 4 and {item["evidence_id"] for item in assertions} == {
            source["evidence_id"]
        }, "Shared packages must not borrow license facts from the equal-byte other digest kind"

        for assertion in assertions:
            observation = observations[assertion["observation_reference"]]
            assert observation.attributes["image_reference"] == result["image_reference"] and (
                observation.attributes["document_sha256"] == assertion["source_sha256"]
                and observation.attributes["spdx_id"] == assertion["source_spdx_id"]
                and observation.provenance.source_id == assertion["source_id"]
                and observation.attributes["evidence_id"] == assertion["evidence_id"]
            ), "Every policy result must resolve the exact original source/image/alias assertion"

        selected[kind] = {item["source_spdx_id"]: item for item in assertions}

    original = selected["config"]["SPDXRef-Lib"]
    changed = selected["manifest"]["SPDXRef-Lib"]
    assert original["declared"]["evaluation"]["status"] == "allow" and (
        original["concluded"]["evaluation"]["status"] == "deny"
    ), "Publisher-declared and publisher-concluded assertions must retain their conflicting roles"
    assert changed["declared"]["source"]["expression"] == "GPL-2.0-only" and (
        changed["declared"]["evaluation"]["status"] == "unknown"
        and changed["concluded"]["evaluation"]["status"] == "allow"
    ), "A changed unconfigured declaration remains unknown despite another allowed conclusion"
    assert selected["config"]["SPDXRef-App"]["declared"]["evaluation"] == {
        "status": "unknown", "reason": "source-none", "atoms": []
    } and selected["config"]["SPDXRef-Lib-Alias"]["declared"]["evaluation"] == {
        "status": "unknown", "reason": "source-absent", "atoms": []
    }, "NONE and omitted license information must not become implicit policy permissions"
    assert all(item["concluded"]["evaluation"]["status"] == "unknown" for item in (
        selected["config"]["SPDXRef-App"], selected["config"]["SPDXRef-Lib-Alias"]
    )), "NOASSERTION remains an explicit unknown source state"
    after = {path.relative_to(relocated): path.read_bytes()
             for path in relocated.rglob("*") if path.is_file()}
    assert before == after and LocalModelStore(relocated).Open() == saved, (
        "The relocated installed policy query cannot write evidence, model, triage or workspace"
    )
    evidence = LocalEvidenceStore(relocated / "evidence")
    record = evidence.Get(config["evidence_id"])
    evidence.StoragePath(("blobs", "sha256", record.reference.sha256)).write_bytes(b"changed")
    status, refused = Console(tmp_path, "sbom", arguments)
    assert status == 4 and refused["status"] == "failed" and "license_policy" not in refused, (
        "Changed original bytes must withhold every policy decision and fail the whole view"
    )
