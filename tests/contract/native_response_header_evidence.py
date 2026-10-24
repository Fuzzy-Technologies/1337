# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded test-owned raw build/capture evidence and original listener-final custody."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4
from zipfile import ZipFile

import pytest

from tests.integration.test_owned_response_worker_execution import OwnedResponseListener

REPOSITORY = Path(__file__).resolve().parents[2]
CONSUMER = Path(__file__).with_name("native_response_header_capture_consumer.py")
MAX_STREAM = 8 * 1024 * 1024
MAX_BUILD_STREAM = 1024 * 1024
MAX_PROCESSES = 16
REQUIRED_ACCEPTANCE = "FUZZY1337_RUN_OWNED_RESPONSE_PRODUCT_ACCEPTANCE"
SOURCE_MODULES = ("adapters/owned_response_capture.py", "owned_response_capture.py",
    "owned_response_capture_worker.py", "owned_response_custody.py", "owned_response_workflow.py",
    "native_response_headers.py", "native_response_header_workflow.py")
TEST_SOURCES = ("tests/contract/native_response_header_oracle.py",
    "tests/contract/native_response_header_evidence.py",
    "tests/contract/native_response_header_capture_consumer.py",
    "tests/functional/test_native_response_header_check.py",
    "tests/contract/owned_response_product_runner.py",
    "tests/integration/test_owned_response_product.py",
    "tests/integration/test_owned_response_worker_execution.py")


def Canonical(value: object) -> bytes:
    """Encode only explicit bounded test-owned inputs or observed facts as standard JSON."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")


@dataclass(slots=True)
class HeaderEvidence:
    """Mirror one finite case's fixed original artifacts into the existing CI upload root."""

    local: Path
    retained: Path
    sequence: int = 0
    analysis_sequence: int = 0

    def Write(self, name: str, raw: bytes) -> None:
        """Copy only a fixed bounded artifact, never a workspace, runtime tree or environment."""

        parts = name.split("/")

        if not 1 <= len(parts) <= 3 or any(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", part)
            is None or part in (".", "..") for part in parts) or len(raw) > 2 * MAX_STREAM:
            raise ValueError("Header evidence requires a bounded fixed relative artifact")

        for root in (self.local, self.retained):
            path = root.joinpath(*parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def Json(self, name: str, value: object) -> None:
        """Preserve original structured facts without manufacturing producer success."""

        self.Write(name, Canonical(value))


def HeaderProcess(owner: HeaderEvidence, label: str, argv: tuple[str, ...], *, cwd: Path,
    environment: dict[str, str], timeout: int, maximum: int = MAX_STREAM,
    installation: dict | None = None) -> subprocess.CompletedProcess[bytes]:
    """Retain actual argv/status/streams before caller assertions, parsing or timeout escape."""

    if re.fullmatch(r"[a-z][a-z0-9-]{0,47}", label) is None or owner.sequence >= MAX_PROCESSES or (
        not 1 <= maximum <= MAX_STREAM or not 1 <= timeout <= 45
    ):
        raise ValueError("Header process evidence requires one finite fixed source-owned label")

    owner.sequence += 1
    prefix = f"process-{owner.sequence:02d}-{label}"
    metadata = {"schema_version": 1, "argv": list(argv), "cwd": str(cwd),
        "timeout_seconds": timeout, "stdin": "closed-devnull", "state": "not-launched",
        "returncode": None, "terminal_return_observed": False, "installation": installation}
    owner.Json(prefix + "/invocation.json", metadata)
    stdout = stderr = None

    try:
        metadata["state"] = "call-entered"
        result = subprocess.run(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=timeout, check=False)
        stdout, stderr = result.stdout, result.stderr
        metadata.update(state="returned", returncode=result.returncode,
            terminal_return_observed=True)

    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout, error.stderr
        metadata.update(state="timeout", exception_type="TimeoutExpired")

        raise

    except OSError as error:
        metadata.update(state="launch-failed", exception_type=type(error).__name__)

        raise

    except BaseException:
        metadata.update(state="interrupted", exception_type="other")

        raise

    finally:
        for role, raw in (("stdout", stdout), ("stderr", stderr)):
            metadata[role] = {"observed": raw is not None,
                "observed_size_bytes": None if raw is None else len(raw),
                "observed_sha256": None if raw is None else hashlib.sha256(raw).hexdigest(),
                "retained_size_bytes": 0 if raw is None else min(len(raw), maximum),
                "complete_original": raw is not None and len(raw) <= maximum
                    and metadata["state"] == "returned",
                "timeout_prefix": metadata["state"] == "timeout" and raw is not None,
                "retention_overflow": raw is not None and len(raw) > maximum}

            if raw is not None:
                owner.Write(prefix + "/" + role + ".bin", raw[:maximum])

        owner.Json(prefix + "/process.json", metadata)

    assert len(result.stdout) <= maximum and len(result.stderr) <= maximum, (
        "Original process exceeded bounded retention; saved prefix remains explicitly incomplete"
    )

    return result


def HeaderEnvironment(root: Path) -> dict[str, str]:
    """Use finite owned runtime directories and copy no unrelated host environment values."""

    environment = {name: os.environ[name] for name in ("SYSTEMROOT", "WINDIR", "PATH")
        if name in os.environ}

    for name, suffix in (("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
        ("XDG_CACHE_HOME", "cache"), ("XDG_DATA_HOME", "data"),
        ("TMPDIR", "tmp"), ("TMP", "tmp"), ("TEMP", "tmp")):
        directory = root / suffix
        directory.mkdir(parents=True, exist_ok=True)
        environment[name] = str(directory)

    return environment


def AdmitHeaderPlatform(platform: str, required_flag: str | None) -> None:
    """Require real Linux custody, distinguishing optional unsupported lanes from acceptance."""

    if platform == "linux":
        return

    if required_flag == "1":
        pytest.fail("Required native-header acceptance needs the supported Linux "
            "acquisition parent")

    pytest.skip("Unsupported native-header acquisition parent; "
        "this skip is not positive acceptance")


@pytest.fixture(scope="session")
def header_platform() -> None:
    """Admit only genuine fixture dependencies; never skip portable pure/mock/source tests."""

    AdmitHeaderPlatform(sys.platform, os.environ.get(REQUIRED_ACCEPTANCE))


@pytest.fixture(scope="session")
def header_evidence_run(header_platform) -> Path:
    """Allocate one unique worker-owned root already included by shared CI artifact collection."""

    root = REPOSITORY / "functional-evidence/native-response-headers" / ("run-" + uuid4().hex)
    root.mkdir(parents=True)

    return root


@pytest.fixture
def header_case_evidence(request, tmp_path, header_evidence_run) -> HeaderEvidence:
    """Retain each case independently before its build, capture, assertions or failures."""

    key = hashlib.sha256(request.node.nodeid.encode()).hexdigest()[:20]
    owner = HeaderEvidence(tmp_path / "original-evidence", header_evidence_run /
        ("case-" + key + "-" + uuid4().hex[:8]))
    owner.Json("case.json", {"schema_version": 1, "pytest_case": request.node.nodeid})

    return owner


def SourceHashes() -> dict[str, str]:
    """Hash only the fixed production/test owners needed to identify this exact composition."""

    paths = tuple("src/fuzzy1337/" + name for name in SOURCE_MODULES) + TEST_SOURCES
    hashes = {}

    for name in paths:
        path = REPOSITORY / name
        assert path.stat().st_size <= 1024 * 1024, "Fixed source owner exceeds its finite ceiling"
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()

    return hashes


def Installation(python: Path) -> dict:
    """Read the fixture's actual retained wheel/import manifest without guessing package state."""

    raw = (python.parents[2] / "installation.json").read_bytes()

    return {"manifest_sha256": hashlib.sha256(raw).hexdigest(), "identity": json.loads(raw)}


@pytest.fixture(scope="module")
def installed_header_worker(tmp_path_factory, header_evidence_run, header_platform) -> Path:
    """Retain clean source, build/venv/install streams, wheel members and actual import identity."""

    root = tmp_path_factory.mktemp("installed-native-response-headers")
    owner = HeaderEvidence(root / "build-evidence", header_evidence_run /
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
    identity["source_sha256"] = SourceHashes()
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
        after.stdout == checkpoint.stdout and SourceHashes() == identity["source_sha256"]
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


def HeaderConsumer(python: Path, directory: Path, config: dict, owner: HeaderEvidence) -> dict:
    """Retain actual capture input/process/import facts before result assertions or JSON parse."""

    path = directory / "capture-input.json"
    raw = Canonical(config)
    path.write_bytes(raw)
    owner.Write("capture-input.json", raw)
    installation = Installation(python)
    owner.Json("installation.json", installation)
    result = HeaderProcess(owner, "capture", (str(python), "-I", "-B", str(CONSUMER),
        "capture", str(path)), cwd=directory,
        environment=HeaderEnvironment(directory / "owned-state"),
        timeout=35, installation=installation)
    assert result.returncode == 0 and result.stderr == b"", (
        "Actual capture consumer failed; original argv/streams/status retained before assertions"
    )
    output = json.loads(result.stdout)
    owner.Json("original-capture-result.json", output)
    imported = output["installed_identity"]
    assert {name: item["sha256"] for name, item in imported["installed_sources"].items()} == (
        installation["identity"]["wheel_modules_sha256"]
    ), "Actual capture imports must match the original recorded wheel identity"

    return output


def ListenerFinal(listener, close_returned: bool, failure: str | None) -> dict:
    """Record bounded actual post-Close/join facts without probing any target or opening sockets."""

    if listener is None:
        return {"schema_version": 1, "listener_returned": False,
            "cleanup": "unobserved", "close_returned": False, "close_failure": failure}

    requests = listener.requests
    alive = listener.thread.is_alive()
    closed = listener.listener.fileno() == -1
    complete = len(requests) <= 8 and len(requests) == listener.accepted and all(
        len(raw) <= 1025 for raw in requests)

    return {"schema_version": 1, "listener_returned": True, "origin": listener.origin,
        "accepted": listener.accepted, "requests_hex": [raw[:1025].hex() for raw in requests[:8]],
        "complete_contacts": complete, "contact_overflow": max(0, len(requests) - 8),
        "thread_alive": alive, "listener_closed": closed, "close_returned": close_returned,
        "close_failure": failure,
        "cleanup": "settled" if close_returned and not alive and closed else "unsettled"}


@contextmanager
def HeaderListener(owner: HeaderEvidence, wire: bytes):
    """Always retain original listener-final facts after Close/join, including exceptional paths."""

    listener = None
    close_returned = False
    failure = None

    try:
        listener = OwnedResponseListener(wire)

        yield listener

    finally:
        try:
            if listener is not None:
                try:
                    listener.Close()
                    close_returned = True

                except BaseException as error:
                    failure = type(error).__name__ if type(error) in (
                        OSError, RuntimeError, AssertionError) else "other"

                    raise

        finally:
            owner.Json("listener-final.json", ListenerFinal(listener, close_returned, failure))
