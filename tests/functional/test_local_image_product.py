# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed two-phase product proof over an explicitly owned daemon and unchanged inert images."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import fuzzy1337
from fuzzy1337.adapters import ImpactLevel, SerializeContract
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import CanonicalModelJson, LocalModelStore
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scan_commands import CreateWorkspace
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.fixtures.trivy.native_archive import ArchiveBytes
from tests.functional.test_native_image_product import (
    ORACLE,
    Canonical,
    CheckModel,
    ConfigDigest,
)
from tests.functional.test_native_image_product import product_runtime as product_runtime
from tests.integration.test_trivy_native import native_runtime as native_runtime

REQUIRED = "FUZZY1337_RUN_LOCAL_IMAGE_PRODUCT_ACCEPTANCE"
OWNER = "actor:local-image-product"
OUTPUT = Path("functional-evidence/local-image-product")


@pytest.fixture(scope="module")
def local_runtime(request):
    """Refuse partial enabled setup and require original private daemon lifecycle provenance."""

    names = ("FUZZY1337_LOCAL_DOCKER_BINARY", "FUZZY1337_LOCAL_DOCKER_SOCKET",
             "FUZZY1337_LOCAL_DOCKER_CONFIG", "FUZZY1337_LOCAL_DOCKER_PROVENANCE")
    values = [os.environ.get(name) for name in names]
    required = os.environ.get(REQUIRED) == "1"
    if not required and all(value is None for value in values):
        pytest.skip("Owned local image product material is absent; this is not acceptance")
    assert required and all(values), "Enabled local product acceptance cannot skip missing material"
    docker, endpoint, config, receipt = (Path(value) for value in values)
    provenance = json.loads(receipt.read_bytes())
    assert provenance["owned_daemon"] is True and provenance["ambient_containerd"] is False, (
        "The product lane must use only its dedicated daemon and private containerd socket."
    )
    assert provenance["network_namespace"] == os.readlink("/proc/self/ns/net") and (
        provenance["network_namespace"] != os.environ["FUZZY1337_TRIVY_HOST_NETNS"]
    ), "Docker fixture setup and native scans must share the owned no-egress network namespace."
    assert provenance["docker_client_sha256"] == hashlib.sha256(docker.read_bytes()).hexdigest(), (
        "The declared selected client must match the original owned-daemon provenance."
    )
    assert list(endpoint.lstat()[:2]) == provenance["socket_mode_inode"], (
        "The exact selected socket metadata must match the original daemon startup receipt."
    )
    repository = Path(__file__).parents[2]
    assert not Path(fuzzy1337.__file__).is_relative_to(repository / "src"), (
        "This acceptance lane must exercise the installed wheel rather than editable source."
    )
    return docker, endpoint, config, request.getfixturevalue("product_runtime")


def Client(runtime, *arguments: str, data: bytes | None = None) -> bytes:
    """Use fixed explicit fixture-only Docker requests against the dedicated private socket.

    Args:
        runtime: Original selected private client, endpoint, config and provider material.
        arguments: Fixed load/tag/inspect fixture setup operations, never product dispatch.
        data: Optional unchanged repository-owned inert Docker-save archive bytes.

    Returns:
        Bounded successful fixture response; failures retain no invented provider success.
    """

    docker, endpoint, config, _ = runtime
    result = subprocess.run([str(docker), "--host", "unix://" + str(endpoint), "--config",
        str(config), *arguments], input=data, capture_output=True, timeout=30, check=False,
        env={"PATH": "/usr/bin:/bin", "HOME": str(config)}, shell=False)
    assert len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 64 * 1024, (
        "Owned fixture setup responses must remain within their explicit finite bounds."
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")[:4096]
    return result.stdout


def Console(arguments: list[str], output: Path, label: str, *, expected: int = 0) -> dict:
    """Run the installed isolated CLI and retain the actual separate stdout/stderr facts.

    Args:
        arguments: Exact explicit installed product arguments without a shell.
        output: Owned case evidence directory.
        label: Fixed receipt basename.
        expected: Exact expected process exit category, never a fabricated PASS marker.

    Returns:
        Actual complete single-document JSON from the installed product.
    """

    result = subprocess.run([sys.executable, "-I", "-m", "fuzzy1337", *arguments, "--json"],
        capture_output=True, timeout=110, check=False, shell=False)
    (output / (label + ".stdout")).write_bytes(result.stdout)
    (output / (label + ".stderr")).write_bytes(result.stderr)
    assert len(result.stdout) <= 4 * 1024 * 1024 and len(result.stderr) <= 64 * 1024, (
        "The installed product summary must remain bounded and exclude raw provider streams."
    )
    assert result.returncode == expected, result.stderr.decode(errors="replace")[:4096]
    return json.loads(result.stdout)


def ExportConfigDigest(raw: bytes) -> str:
    """Independently read one Docker-save config without assuming a daemon-version filename.

    Args:
        raw: Actual bounded exported bytes, never extracted to the filesystem.

    Returns:
        SHA-256 identity of the manifest-selected ordinary bounded config bytes.
    """

    assert 1 <= len(raw) <= 64 * 1024 * 1024, "Exported archive must remain bounded."
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        manifest_file = archive.extractfile("manifest.json")
        assert manifest_file is not None, "Docker-save must contain its exact manifest."
        manifest = json.loads(manifest_file.read(64 * 1024 + 1))
        assert len(manifest) == 1, "Owned exported archive must identify one image only."
        name = manifest[0]["Config"]
        assert not name.startswith("/") and ".." not in name.split("/"), (
            "The selected config must remain a safe archive member name."
        )
        member = archive.getmember(name)
        assert member.isfile() and 1 <= member.size <= 1024 * 1024, (
            "The selected config must remain ordinary and bounded."
        )
        config_file = archive.extractfile(member)
        assert config_file is not None, "The selected config bytes must exist."
        config = config_file.read(1024 * 1024 + 1)
        assert len(config) == member.size, "Selected config bytes must be complete."
    return "sha256:" + hashlib.sha256(config).hexdigest()


def Register(root: Path, scope_id: str, target: Target) -> None:
    """Explicitly attest one source or archive target as two independent operator decisions.

    Args:
        root: Existing owning product workspace.
        scope_id: Separate source or archive scope identity.
        target: Independently verified exact target, never a runtime auto-enrollment request.
    """

    now = datetime.now(UTC)
    workspace_id = LocalWorkspaceStore(root).Open().workspace_id
    LocalScopeStore(root).Create(ScopeSnapshot(scope_id, workspace_id,
        ScopeAuthorization(AuthorizationState.GRANTED, "attester:separate-local-image",
            "consent:" + scope_id, (now - timedelta(minutes=1)).isoformat(),
            (now + timedelta(minutes=15)).isoformat()), targets=(target,), allow=(target,)))


def RetainSavedWorkspace(root: Path, destination: Path) -> dict:
    """Copy bounded original stores, excluding selected tools, standalone archives and caches.

    Args:
        root: Quiescent owned workspace after its acknowledged scan and reopen.
        destination: Fresh artifact directory for portable offline inspection.
    Returns:
        Original selected file sizes and hashes, verified again after copying.
    """

    paths = [root / "workspace.json"]
    for name in ("state", "evidence"):
        paths.extend(sorted((root / name).rglob("*")))
    assert len(paths) <= 10000, "Selected original store inventory must remain finite."
    destination.mkdir(mode=0o700)
    inventory = {}
    total = 0
    for source in paths:
        info = source.lstat()
        assert not stat.S_ISLNK(info.st_mode), "Original stores cannot contain symbolic aliases."
        relative = source.relative_to(root)
        target = destination / relative
        if stat.S_ISDIR(info.st_mode):
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            continue
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and (
            info.st_size <= 64 * 1024 * 1024
        ), "Only bounded original regular store files may enter the retained artifact."
        total += info.st_size
        assert total <= 128 * 1024 * 1024, "Retained saved workspace exceeds its finite byte cap."
        raw = source.read_bytes()
        assert len(raw) == info.st_size, "The original saved file changed during retention."
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(raw)
        target.chmod(0o600)
        digest = hashlib.sha256(raw).hexdigest()
        assert hashlib.sha256(target.read_bytes()).hexdigest() == digest, (
            "The retained original file must preserve its complete selected byte hash."
        )
        inventory[relative.as_posix()] = {"size_bytes": len(raw), "sha256": digest}
    return inventory


@pytest.mark.parametrize("case", ORACLE["cases"], ids=[case["case_id"] for case in ORACLE["cases"]])
def test_InstalledLocalExportThenExplicitNativeScanPreservesConfigAndFinding(
    tmp_path, local_runtime, case, request,
):
    """Docker output crosses separate scope approval, genuine Trivy and saved model reopen."""

    root = tmp_path / "workspace"
    CreateWorkspace(root, "local-image-" + case["package_version"].replace(".", ""),
                    "Owned two-phase local image product")
    before_model = LocalModelStore(root).Open()
    output = OUTPUT / case["case_id"]
    output.mkdir(parents=True, exist_ok=True)

    def RetainPartialStores() -> None:
        """Retain available original stores on an assertion failure without granting acceptance."""

        destination = output / "saved-workspace"
        if not destination.exists():
            inventory = RetainSavedWorkspace(root, destination)
            (output / "partial-store-inventory.json").write_bytes(Canonical(inventory))

    request.addfinalizer(RetainPartialStores)
    original = ArchiveBytes(case["package_version"])
    expected_id = ConfigDigest(original)
    assert hashlib.sha256(original).hexdigest() == case["archive_sha256"], (
        "The daemon may receive only the unchanged independently pinned inert image fixture."
    )
    Client(local_runtime, "image", "load", data=original)
    reference = "owned-local-m2:requests-" + case["package_version"]
    Client(local_runtime, "image", "tag", expected_id, reference)
    observed = json.loads(Client(local_runtime, "image", "inspect", "--format", "{{json .}}",
                                 reference))
    assert observed["Id"] == expected_id, (
        "Owned fixture setup must resolve the independent config ID."
    )
    docker, endpoint, _, runtime = local_runtime
    source_arguments = ["image", "export-local", str(root), "--reference", reference, "--owner",
        OWNER, "--executable", str(docker), "--socket", str(endpoint), "--read-consent-reference",
        "read:owned-local-source"]
    plan = Console([*source_arguments, "--plan"], output, "source-plan")
    assert plan["execution_authorized"] is False and LocalModelStore(root).Open() == before_model, (
        "Source planning must not contact a daemon or change the model."
    )
    source_target = Target(TargetKind.ARTIFACT, plan["target"]["value"])
    Register(root, "local-source", source_target)
    source_policy = ImpactPolicy("local-source", permissions=(CapabilityPermission(
        "image.local-reference-export", "native.docker-local", ImpactLevel.SAFE,
        ("local-docker-read",)),))
    policy_path = root / "source-policy.json"
    policy_path.write_text(SerializeContract(source_policy))
    exported = Console([*source_arguments, "--scope", "local-source", "--policy", str(policy_path),
        "--approve-local-image"], output, "export")
    assert exported["state"] == "completed" and exported["workspace_acknowledged"] is True and (
        exported["image_config_id"] == expected_id
    ), "A genuine export must confirm authority, config and actual workspace persistence."
    if case["expected_selected_advisory_match"]:
        missing_arguments = list(source_arguments)
        missing_arguments[missing_arguments.index(reference)] = "owned-local-m2:missing-image"
        missing_plan = Console([*missing_arguments, "--plan"], output, "missing-plan")
        Register(root, "missing-source", Target(TargetKind.ARTIFACT,
                                                missing_plan["target"]["value"]))
        missing = Console([*missing_arguments, "--scope", "missing-source", "--policy",
            str(policy_path), "--approve-local-image"], output, "missing-image", expected=4)
        assert missing["state"] == "failed" and missing["archive_sha256"] is None, (
            "An absent local reference must refuse without pulling or accepting an archive."
        )
    archive = root / exported["archive_relative_path"]
    actual = archive.read_bytes()
    assert hashlib.sha256(actual).hexdigest() == exported["archive_sha256"] and (
        ExportConfigDigest(actual) == expected_id and LocalModelStore(root).Open() == before_model
    ), "Exported bytes and config must verify independently before any scan/model transition."
    assert LocalScopeStore(root).Open("local-source").targets == (source_target,), (
        "Export permission must never silently register the resulting archive target."
    )
    manifest = {"schema_version": 1, "profile": "trivy.image-archive-offline.v1", "role": "input",
        "files": [{"name": "image.tar", "size_bytes": len(actual),
                   "sha256": hashlib.sha256(actual).hexdigest()}]}
    assert exported["archive_manifest"] == manifest, (
        "The archive scope must bind actual bytes independently of config identity."
    )
    target = Target(TargetKind.ARTIFACT, "manifest-sha256:" + hashlib.sha256(
        Canonical(manifest)).hexdigest())
    assert exported["archive_target"]["value"] == target.value, (
        "The separately reviewed archive target must match independent canonical manifest bytes."
    )
    executable, cache, _, _ = runtime
    selected_trivy = root / "selected-trivy"
    shutil.copyfile(executable, selected_trivy)
    selected_trivy.chmod(0o700)
    shutil.copytree(cache, root / "trivy-cache")
    scan_policy = root / "scan-policy.json"
    scan_policy.write_text(SerializeContract(ImpactPolicy("local-archive", permissions=(
        CapabilityPermission("image.archive-vulnerabilities", "native.trivy", ImpactLevel.SAFE),))))
    scan_arguments = ["scan", "image", str(root), "--profile", "native", "--owner", OWNER,
        "--archive", exported["archive_relative_path"], "--cache-directory", "trivy-cache",
        "--executable", str(selected_trivy), "--read-consent-reference", "read:owned-export-scan",
        "--expected-config-id", expected_id, "--policy", str(scan_policy)]
    denied = Console([*scan_arguments, "--scope", "local-source", "--approve-safe-image"],
                     output, "scan-unregistered", expected=3)
    assert denied["state"] == "failed" and LocalModelStore(root).Open() == before_model, (
        "An export receipt alone must never authorize scanning an unregistered archive target."
    )
    Register(root, "local-archive", target)
    scanned = Console([*scan_arguments, "--scope", "local-archive", "--approve-safe-image"],
                      output, "scan")
    assert scanned["state"] == "completed", (
        "The genuine separately approved native scan must complete."
    )
    store = LocalEvidenceStore(root / "evidence")
    records = tuple(store.Get(identity) for identity in scanned["retained_evidence_ids"])
    model, findings = CheckModel(root, case, records)
    assert model.revision == before_model.revision + 1 and bool(findings) is (
        case["expected_selected_advisory_match"]
    ), "The original selected advisory boundary must survive local export without a ranking claim."
    Console(["workspace", "open", str(root)], output, "reopen")
    assert CanonicalModelJson(LocalModelStore(root).Open()) == CanonicalModelJson(model), (
        "Installed product reopen must preserve the exact saved canonical model."
    )
    saved = output / "saved-workspace"
    inventory = RetainSavedWorkspace(root, saved)
    Console(["workspace", "open", str(saved)], output, "relocated-reopen")
    assert CanonicalModelJson(LocalModelStore(saved).Open()) == CanonicalModelJson(model), (
        "The actual artifact must reopen the same saved model without selected tools or caches."
    )
    (output / "result.json").write_bytes(Canonical({"case_id": case["case_id"],
        "outcome": "selected-two-phase-assertions-passed", "config_id": expected_id,
        "archive_sha256": exported["archive_sha256"], "model_revision": model.revision,
        "selected_advisory_match": bool(findings), "scan_completeness": "not-assessed",
        "saved_workspace_files": inventory}))
