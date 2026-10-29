# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded installed CLI evidence owners; reuse reviewed raw-process retention primitives."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from uuid import uuid4
from zipfile import ZipFile

import pytest

from tests.contract.native_header_cli_consumer import SOURCE_MODULES
from tests.contract.native_response_header_evidence import (
    MAX_BUILD_STREAM,
    AdmitHeaderPlatform,
    Canonical,
    HeaderEnvironment,
    HeaderEvidence,
    HeaderProcess,
    Installation,
)
from tests.native_crawl_acceptance_helpers import NativeCaseEvidence, NativeProcess

REPOSITORY = Path(__file__).resolve().parents[2]
CONSUMER = Path(__file__).with_name("native_header_cli_consumer.py")
TEST_SOURCES = ("tests/contract/native_header_cli_consumer.py",
    "tests/contract/native_header_cli_evidence.py", "tests/contract/native_header_cli_target.py",
    "tests/functional/test_native_header_cli_pipeline.py",
    "tests/unit/test_native_header_pipeline_source.py",
    "tests/native_crawl_graph_helpers.py", "tests/native_crawl_acceptance_helpers.py",
    "tests/contract/native_response_header_evidence.py",
    "tests/contract/native_response_header_oracle.py",
    "tests/contract/fixtures/zap-passive.oracle.v1.json")


@pytest.fixture(scope="session")
def header_cli_platform() -> None:
    """Fail required unsupported custody; other unsupported lanes remain unassessed."""

    required = os.environ.get("FUZZY1337_RUN_NATIVE_HEADER_CLI_ACCEPTANCE",
        os.environ.get("FUZZY1337_RUN_OWNED_RESPONSE_PRODUCT_ACCEPTANCE"))
    AdmitHeaderPlatform(sys.platform, required)


@pytest.fixture(scope="session")
def header_cli_run(header_cli_platform) -> Path:
    """Allocate a unique CI-retained root before any module build or per-case setup."""

    root = REPOSITORY / "functional-evidence/native-header-cli" / ("run-" + uuid4().hex)
    root.mkdir(parents=True)

    return root


@pytest.fixture
def header_cli_evidence(request, tmp_path, header_cli_run) -> NativeCaseEvidence:
    """Give every case explicit retained ownership without a module/function scope mismatch."""

    key = hashlib.sha256(request.node.nodeid.encode()).hexdigest()[:20]
    owner = NativeCaseEvidence(tmp_path / "original-evidence", header_cli_run /
        ("case-" + key + "-" + uuid4().hex[:8]))
    owner.Json("case.json", {"schema_version": 1, "pytest_case": request.node.nodeid,
        "runtime_acceptance": "unassessed-until-terminal-assertions"})

    return owner


def CliSourceHashes() -> dict[str, str]:
    """Bind all command/crawl/header wheel owners and independent tests to the actual tree."""

    result = {}

    for name in (*("src/fuzzy1337/" + path for path in SOURCE_MODULES), *TEST_SOURCES):
        path = REPOSITORY / name
        assert path.stat().st_size <= 1024 * 1024, "Fixed source exceeds its finite ceiling"
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()

    return result


@pytest.fixture(scope="module")
def installed_header_cli(tmp_path_factory, header_cli_run, header_cli_platform) -> Path:
    """Retain clean source, build/venv/install streams, wheel members and actual import identity."""

    root = tmp_path_factory.mktemp("installed-native-response-headers")
    owner = HeaderEvidence(root / "build-evidence", header_cli_run /
        ("installation-" + uuid4().hex))
    environment = HeaderEnvironment(root / "owned-state")
    status = HeaderProcess(owner, "source-status", ("git", "status", "--porcelain"),
        cwd=REPOSITORY, environment=environment, timeout=5, maximum=MAX_BUILD_STREAM)
    checkpoint = HeaderProcess(owner, "source-checkpoint",
        ("git", "rev-parse", "HEAD", "HEAD^{tree}"), cwd=REPOSITORY,
        environment=environment, timeout=5, maximum=MAX_BUILD_STREAM)
    assert status.returncode == checkpoint.returncode == 0 and status.stdout == b"", (
        "Genuine build requires a clean immutable source composition; original facts are retained"
    )
    commit, tree = checkpoint.stdout.decode("ascii").split()
    identity = {"schema_version": 1, "source_commit": commit, "source_tree": tree,
        "source_sha256": None}
    owner.Json("source-checkpoint.json", identity)
    identity["source_sha256"] = CliSourceHashes()
    owner.Json("source-checkpoint.json", identity)
    wheel_root = root / "wheel"
    wheel_root.mkdir()
    built = HeaderProcess(owner, "build", (sys.executable, "-m", "build", "--wheel",
        "--no-isolation", "--outdir", str(wheel_root)), cwd=REPOSITORY, environment=environment,
        timeout=40, maximum=MAX_BUILD_STREAM)
    assert built.returncode == 0, "Actual wheel build failed; raw original build evidence retained"
    wheels = tuple(wheel_root.glob("*.whl"))
    assert len(wheels) == 1, "Exactly one freshly built actual wheel is required"
    wheel, = wheels
    size = wheel.stat().st_size
    assert size <= 32 * 1024 * 1024, "Actual wheel exceeded its fixed finite size ceiling"
    identity.update(wheel_name=wheel.name, wheel_size_bytes=size,
        wheel_sha256=hashlib.sha256(wheel.read_bytes()).hexdigest())
    members = {}
    identity["wheel_modules_sha256"] = members
    owner.Json("wheel-identity.json", identity)

    try:
        with ZipFile(wheel) as archive:
            for name in SOURCE_MODULES:
                info = archive.getinfo("fuzzy1337/" + name)
                assert info.file_size <= 1024 * 1024, "Actual wheel module exceeded source ceiling"
                members[name] = hashlib.sha256(archive.read(info)).hexdigest()

    finally:
        owner.Json("wheel-identity.json", identity)

    assert members == {name: identity["source_sha256"]["src/fuzzy1337/" + name]
        for name in SOURCE_MODULES}, "Wheel member bytes must equal the original source checkpoint"
    status_after = HeaderProcess(owner, "source-status-after-build",
        ("git", "status", "--porcelain"), cwd=REPOSITORY,
        environment=environment, timeout=5, maximum=MAX_BUILD_STREAM)
    after = HeaderProcess(owner, "source-checkpoint-after-build",
        ("git", "rev-parse", "HEAD", "HEAD^{tree}"), cwd=REPOSITORY,
        environment=environment, timeout=5, maximum=MAX_BUILD_STREAM)
    assert status_after.returncode == after.returncode == 0 and status_after.stdout == b"" and (
        after.stdout == checkpoint.stdout and CliSourceHashes() == identity["source_sha256"]
    ), "Actual build may not inherit mixed, changed or dirty source identity"
    created = HeaderProcess(owner, "create-interpreter", (sys.executable, "-m", "venv",
        str(root / "environment")), cwd=root, environment=environment, timeout=40,
        maximum=MAX_BUILD_STREAM)
    assert created.returncode == 0, "Actual interpreter creation failed; raw evidence retained"
    python = root / "environment" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    installed = HeaderProcess(owner, "install", (str(python), "-I", "-B", "-m", "pip", "--isolated",
        "install", "--no-index", "--no-deps", "--no-compile", "--disable-pip-version-check",
        str(wheel)), cwd=root, environment=environment, timeout=40, maximum=MAX_BUILD_STREAM)
    assert installed.returncode == 0, "Actual wheel install failed; raw original evidence retained"
    probe = HeaderProcess(owner, "import-identity", (str(python), "-I", "-B", str(CONSUMER),
        "identity"), cwd=root, environment=environment, timeout=10, maximum=MAX_BUILD_STREAM,
        installation=identity)
    assert probe.returncode == 0 and probe.stderr == b"", (
        "Actual installed import probe failed; raw original evidence retained before decoding"
    )
    imported = json.loads(probe.stdout)
    owner.Json("import-identity.json", imported)
    assert {name: item["sha256"] for name, item in imported["installed_sources"].items()} == (
        members
    ), (
        "Actual isolated installed module hashes must equal the recorded wheel members"
    )
    assert all(Path(item["path"]).is_relative_to(python.parents[1])
        for item in imported["installed_sources"].values()), (
        "Imports must come from the clean wheel"
    )
    identity.update(installed_sources=imported["installed_sources"],
        distribution_version=imported["distribution_version"])
    (root / "installation.json").write_bytes(Canonical(identity))
    owner.Json("installation.json", identity)

    return python


def CliProcess(python: Path, directory: Path, owner: NativeCaseEvidence,
    label: str, arguments: tuple[str, ...], *, offline: bool = False):
    """Preserve exact entry argv/streams/status/timeout before decoding or product assertions."""

    assert owner.sequence < 32, "One fixed CLI case exceeded its32process ceiling"
    installation = Installation(python)
    metrics = directory / (label + "-offline-metrics.json")
    argv = (str(python), "-I", "-B", str(CONSUMER), "offline", str(metrics), "--",
        *arguments) if offline else (str(python), "-I", "-B", "-m", "fuzzy1337", *arguments)

    try:
        result = NativeProcess(owner, label, argv, cwd=directory,
            environment=HeaderEnvironment(directory / "consumer-state"), timeout=35,
            installation=installation)

    finally:
        if offline and metrics.exists():
            owner.Write(label + "-offline-metrics.json", metrics.read_bytes())

    return result


def CliJson(python: Path, directory: Path, owner: NativeCaseEvidence, label: str,
    arguments: tuple[str, ...], *, offline: bool = False, status: int = 0) -> dict:
    """Assert only after original retention, preserving real nonzero terminal work unchanged."""

    result = CliProcess(python, directory, owner, label, (*arguments, "--json"), offline=offline)
    assert result.returncode == status and result.stderr == b"", (
        "Actual installed CLI status differs; original raw argv/streams/return are retained")
    output = json.loads(result.stdout)
    owner.Json(label + "-result.json", output)

    if offline:
        metrics = json.loads((directory / (label + "-offline-metrics.json")).read_bytes())
        assert metrics["entry_exit_code"] == result.returncode and (
            metrics["forbidden_calls"] == 0), (
            "Offline entry point must return its actual exit without any acquisition/grant/Put")
        assert {name: item["sha256"] for name, item in
            metrics["installed_identity"]["installed_sources"].items()} == (
            Installation(python)["identity"]["wheel_modules_sha256"]), (
                "Every actual offline import must equal the immutable installed wheel")

    return output


def CliControl(python: Path, directory: Path, owner: NativeCaseEvidence,
    action: str, config: dict) -> dict:
    """Run only fixed real setup/triage owners, never a replacement executor or analysis."""

    assert action in ("setup", "triage") and owner.sequence < 32, "Fixed control action required"
    path = directory / (action + "-input.json")
    path.write_bytes(Canonical(config))
    owner.Write(path.name, path.read_bytes())
    result = NativeProcess(owner, action, (str(python), "-I", "-B", str(CONSUMER), action,
        str(path)), cwd=directory, environment=HeaderEnvironment(directory / "consumer-state"),
        timeout=10, installation=Installation(python))
    assert result.returncode == 0 and result.stderr == b"", "Fixed owner failed; raw retained"
    output = json.loads(result.stdout)
    owner.Json(action + "-result.json", output)
    assert {name: item["sha256"] for name, item in
        output["installed_identity"]["installed_sources"].items()} == (
        Installation(python)["identity"]["wheel_modules_sha256"]), "Installed identity differs"

    return output
