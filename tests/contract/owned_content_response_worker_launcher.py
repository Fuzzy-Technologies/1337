# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit opt-in installed-worker launcher; importing this module performs no acceptance.

Build and Run require separate caller opt-in and one explicitly selected frozen worker case.
There is no case loop, SDK, header-v2, input/transport matrix or genuine pytest enrollment.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path
from zipfile import ZipFile

from tests.contract.owned_content_response_product_runner import (
    CASES,
    SOURCE_MODULES,
    AssertContentInstallation,
    AssertContentLauncherEvidence,
    AssertContentSourceFacts,
)
from tests.contract.owned_content_response_target import OwnedContentResponseTarget
from tests.native_crawl_acceptance_helpers import (
    CanonicalNative,
    NativeCaseEvidence,
    NativeEnvironment,
    NativeInstallation,
    NativeProcess,
)

REPOSITORY = Path(__file__).resolve().parents[2]
SUPPORTED_CASES = frozenset(CASES)
MAX_INSTALL_STREAM = 1024 * 1024
MAX_MODULE_BYTES = 1024 * 1024
WORKER_TIMEOUT = 10
IMPORT_PROBE = '''import hashlib, importlib, importlib.metadata, json
from pathlib import Path
names = %r
result = {"distribution_version": importlib.metadata.version("1337"), "installed_sources": {}}
for name in names:
    module = importlib.import_module("fuzzy1337." + name[:-3].replace("/", "."))
    path = Path(module.__file__).resolve()
    assert path.stat().st_size <= 1048576
    result["installed_sources"][name] = {"path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True), end="")
''' % (SOURCE_MODULES,)


@dataclass(frozen=True)
class InstalledContentWorker:
    """Retain the exact actual interpreter, original manifest envelope and import observation."""

    python: Path
    installation: dict
    imported: dict
    commit: str
    tree: str


def ChildEvidence(owner: NativeCaseEvidence, label: str) -> NativeCaseEvidence:
    """Allocate only fixed independent artifact namespaces, without creating runtime state.

    Args:
        owner: Original caller-owned case evidence destinations.
        label: Fixed source-owned artifact child identity.

    Returns:
        Separate original evidence owner, so equal final filenames cannot overwrite siblings.
    """

    assert label in ("main", "sentinel", "worker"), "Evidence child identity must remain fixed"

    return NativeCaseEvidence(owner.local / label, owner.retained / label)


def Build(repository: Path, directory: Path, evidence: NativeCaseEvidence, *, commit: str,
    tree: str, enabled: bool = False) -> InstalledContentWorker:
    """Build/install one clean exact offline wheel and observe its actual isolated import hashes.

    Args:
        repository: This exact source checkout, never an inferred external repository.
        directory: New absolute owned installation root; existing roots are refused.
        evidence: Original build/install/process evidence owner.
        commit: Independently selected immutable complete Git commit.
        tree: Independently selected complete Git tree.
        enabled: Separate explicit runtime authorization; false refuses before any work.

    Returns:
        Installed identity only after actual clean-source, wheel and import reconciliation.
    """

    if enabled is not True:
        raise PermissionError("Installed content worker build requires explicit runtime opt-in")

    assert repository.resolve() == REPOSITORY and directory.is_absolute(), (
        "Build must own this exact source checkout and a new absolute installation directory")
    directory.mkdir(parents=True, exist_ok=False)
    environment = NativeEnvironment(directory / "owned-state")
    environment["PIP_NO_INDEX"] = "1"
    environment["PIP_CONFIG_FILE"] = os.devnull

    def Process(label, argv, *, cwd, timeout=40):
        """Retain every original process before checking its terminal result."""

        result = NativeProcess(evidence, label, tuple(argv), cwd=cwd, environment=environment,
            timeout=timeout, maximum=MAX_INSTALL_STREAM)
        assert result.returncode == 0, "Offline installation step failed; original logs retained"

        return result

    status = Process("source-status", ("git", "status", "--porcelain"), cwd=repository, timeout=5)
    checkpoint = Process("source-checkpoint", ("git", "rev-parse", "HEAD", "HEAD^{tree}"),
        cwd=repository, timeout=5)
    assert status.stdout == b"" and checkpoint.stdout.decode("ascii").split() == [commit, tree], (
        "Build requires the selected exact immutable clean checkpoint before acquisition")
    sources = {}

    for name in SOURCE_MODULES:
        path = repository / "src/fuzzy1337" / name
        assert path.resolve().is_relative_to(repository) and path.stat().st_size <= (
            MAX_MODULE_BYTES), (
            "Build module source must remain within its fixed owned checkpoint and bound")
        sources[name] = hashlib.sha256(path.read_bytes()).hexdigest()

    identity = {"schema_version": 1, "source_commit": commit, "source_tree": tree,
        "source_modules_sha256": sources}
    evidence.Json("source-checkpoint.json", identity)
    wheels = directory / "wheel"
    wheels.mkdir()
    Process("build", (sys.executable, "-m", "build", "--wheel", "--no-isolation",
        "--outdir", str(wheels)), cwd=repository)
    candidates = tuple(wheels.glob("*.whl"))
    assert len(candidates) == 1, "Offline build must produce one original wheel"
    wheel = candidates[0]
    assert 0 < wheel.stat().st_size <= 32 * 1024 * 1024, "Original wheel exceeds its finite bound"

    with ZipFile(wheel) as archive:
        assert len(archive.namelist()) == len(set(archive.namelist())), "Duplicate wheel member"
        members = {}

        for name in SOURCE_MODULES:
            member = "fuzzy1337/" + name
            assert archive.getinfo(member).file_size <= MAX_MODULE_BYTES, "Oversized wheel module"
            members[name] = hashlib.sha256(archive.read(member)).hexdigest()

        metadata_names = [name for name in archive.namelist()
            if name.endswith(".dist-info/METADATA")]
        assert len(metadata_names) == 1, "Original wheel must identify one distribution"
        assert archive.getinfo(metadata_names[0]).file_size <= MAX_MODULE_BYTES, (
            "Original distribution metadata must remain bounded")
        metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
        assert metadata["Name"] == "1337" and metadata["Version"], "Wheel distribution is foreign"

    assert members == sources, "Original wheel module bytes must match the exact clean checkpoint"
    identity.update(wheel_name=wheel.name, wheel_size_bytes=wheel.stat().st_size,
        wheel_sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(), wheel_modules_sha256=members,
        distribution_version=metadata["Version"])
    evidence.Json("wheel-identity.json", identity)
    environment_root = directory / "environment"
    Process("create-interpreter", (sys.executable, "-m", "venv", str(environment_root)),
        cwd=directory)
    python = environment_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    Process("install", (str(python), "-I", "-B", "-m", "pip", "--isolated", "install",
        "--no-index", "--no-deps", "--no-compile", "--disable-pip-version-check", str(wheel)),
        cwd=directory)
    probe = Process("import-probe", (str(python), "-I", "-B", "-c", IMPORT_PROBE), cwd=directory,
        timeout=10)
    assert probe.stderr == b"", "Installed import probe diagnostics are not clean acceptance"
    imported = json.loads(probe.stdout)
    assert CanonicalNative(imported) == probe.stdout, "Original import probe must remain canonical"
    AssertContentInstallation(identity, imported, commit=commit, tree=tree)

    for item in imported["installed_sources"].values():
        assert Path(item["path"]).resolve().is_relative_to(environment_root.resolve()), (
            "Actual imports must belong to this selected clean environment, never another install")

    final_status = Process("source-status-final", ("git", "status", "--porcelain"),
        cwd=repository, timeout=5)
    final_checkpoint = Process("source-checkpoint-final",
        ("git", "rev-parse", "HEAD", "HEAD^{tree}"), cwd=repository, timeout=5)
    assert final_status.stdout == b"" and final_checkpoint.stdout.decode("ascii").split() == (
        [commit, tree]), "The source checkpoint must remain exact and clean after build/install"
    assert all(hashlib.sha256((repository / "src/fuzzy1337" / name).read_bytes()).hexdigest() == (
        sources[name]) for name in SOURCE_MODULES), "Source bytes changed during installation"
    identity["installed_sources"] = imported["installed_sources"]
    (directory / "installation.json").write_bytes(CanonicalNative(identity))
    installation = NativeInstallation(python)
    evidence.Json("installation-envelope.json", installation)

    return InstalledContentWorker(python, installation, imported, commit, tree)


def RetainSourceFinal(evidence: NativeCaseEvidence,
    children: dict[str, NativeCaseEvidence]) -> dict:
    """Mirror original final records before predicates, preserving explicit absent-owner facts.

    Args:
        evidence: Original caller-owned combined case destination.
        children: Separate original main/sentinel evidence owners.

    Returns:
        Observed original final records, with explicit absence rather than invented zero counts.
    """

    finals = {}

    for label, owner in children.items():
        path = owner.local / "content-source-final.json"

        if path.is_file():
            raw = path.read_bytes()
            evidence.Write(label + "-source-final.json", raw)
            finals[label] = json.loads(raw)

        else:
            finals[label] = {"record_observed": False, "owner_state": "unobserved"}
            evidence.Json(label + "-source-final.json", finals[label])

    return finals


def Run(installed: InstalledContentWorker, name: str, address: str,
    evidence: NativeCaseEvidence, *, enabled: bool = False) -> dict:
    """Run only a fixed owned worker case and retain both source owners before case predicates.

    Args:
        installed: Original reconciled Build result, with no interpreter fallback.
        name: One explicitly supported frozen case, not an arbitrary URL or command.
        address: Explicit IPv4 or IPv6 loopback; unsupported families never fall back.
        evidence: New original case evidence owner.
        enabled: Separate explicit runtime opt-in, false by default.

    Returns:
        Original installation/process/source facts, not SDK or header-v2 acceptance.
    """

    if enabled is not True:
        raise PermissionError("Installed content worker run requires explicit runtime opt-in")

    assert name in SUPPORTED_CASES and address in ("127.0.0.1", "::1"), (
        "Only the explicit small owned worker matrix is enrolled")
    assert NativeInstallation(installed.python) == installed.installation, (
        "Original installed manifest changed; do not repair or substitute it")
    main, sentinel, worker = (ChildEvidence(evidence, label) for label in (
        "main", "sentinel", "worker"))
    assert all(not path.exists() for owner in (main, sentinel, worker)
        for path in (owner.local, owner.retained)), "Original child evidence namespaces must be new"
    directory = evidence.local / "launch"
    directory.mkdir(parents=True, exist_ok=False)
    environment = NativeEnvironment(directory / "owned-state")
    evidence.Json("launcher-environment.json", {"keys": sorted(environment), "sha256":
        hashlib.sha256(CanonicalNative(environment)).hexdigest()})

    try:
        with OwnedContentResponseTarget(main, address=address, case=name) as source:
            with OwnedContentResponseTarget(sentinel, address=address, case="missing") as other:
                url = source.graph.Url(CASES[name].path)
                sentinel_origin = other.graph.origin
                result = NativeProcess(worker, "worker", (str(installed.python), "-I", "-B", "-m",
                    "fuzzy1337.owned_content_response_worker", url), cwd=directory,
                    environment=environment, timeout=WORKER_TIMEOUT, maximum=131072,
                    installation=installed.installation)

    finally:
        finals = RetainSourceFinal(evidence, {"main": main, "sentinel": sentinel})

    prefix = worker.local / f"process-{worker.sequence:03d}-worker"
    invocation = json.loads((prefix / "invocation.json").read_bytes())
    process = json.loads((prefix / "process.json").read_bytes())
    AssertContentLauncherEvidence(name, url, installed.installation, installed.imported,
        invocation, process, result.stdout, result.stderr, commit=installed.commit,
        tree=installed.tree, python=str(installed.python), cwd=str(directory),
        timeout_seconds=WORKER_TIMEOUT)
    delivery = AssertContentSourceFacts(name, url, finals["main"], finals["sentinel"],
        sentinel_origin=sentinel_origin)

    return {"installation": installed.installation, "process": process, "sources": finals,
        "source_delivery": delivery, "worker_case": name, "address": address,
        "evidence_paths": {"local": str(evidence.local), "retained": str(evidence.retained),
            "main_final": str(main.local / "content-source-final.json"),
            "sentinel_final": str(sentinel.local / "content-source-final.json"),
            "worker_process": str(prefix / "process.json")}}
