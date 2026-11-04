# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Prepare and verify four installed read-helper cases without executing the provider."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from urllib.request import urlopen
from xml.etree import ElementTree

CASE_IDS = (
    "installed-create-verify-close",
    "installed-invalid-utf8-child-refusal",
    "installed-original-scratch-replacement-refusal",
    "installed-caller-cancellation-settlement",
)
TEST_PATH = "tests/integration/test_native_configuration_material_execution.py"
CONTEXT_BYTES = 1024 * 1024
RECEIPT_BYTES = 512 * 1024


def Digest(path: Path) -> str:
    """Hash an explicit regular file with constant-memory streaming."""

    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024**2:
        raise ValueError("Acceptance input must be an explicit physical regular file")

    digest = hashlib.sha256()
    received = 0

    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            received += len(chunk)

            if received > 256 * 1024**2:
                raise ValueError("Acceptance hash input exceeds its finite streaming budget")

            digest.update(chunk)

    return digest.hexdigest()


def WriteJson(path: Path, value: object, maximum: int = CONTEXT_BYTES) -> None:
    """Write bounded metadata exclusively, excluding executable and archive bodies."""

    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()

    if len(raw) > maximum:
        raise ValueError("Acceptance metadata exceeds its finite envelope")

    with path.open("xb") as output:
        output.write(raw)


def ReadJson(path: Path, maximum: int = CONTEXT_BYTES) -> dict:
    """Admit only a bounded physical metadata file."""

    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("Acceptance metadata is missing or exceeds its finite envelope")

    with path.open("rb") as source:
        raw = source.read(maximum + 1)

    if len(raw) > maximum:
        raise ValueError("Acceptance metadata grew beyond its finite envelope")

    return json.loads(raw)


def Command(argv: list[str], cwd: Path, environment: dict[str, str]) -> bytes:
    """Run only explicit preparation tools with a finite deadline and bounded retained output."""

    completed = subprocess.run(argv, cwd=cwd, env=environment, check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)

    if len(completed.stdout) + len(completed.stderr) > CONTEXT_BYTES:
        raise ValueError("Preparation tool output exceeds its metadata budget")

    return completed.stdout


def SourceState(repository: Path, environment: dict[str, str]) -> dict[str, str]:
    """Require one clean committed source revision before and after the wheel build."""

    if Command(["git", "status", "--porcelain=v1", "--untracked-files=no"],
               repository, environment):
        raise ValueError("Installed acceptance requires a clean committed source revision")

    return {name: Command(["git", "rev-parse", reference], repository, environment).decode().strip()
            for name, reference in (("commit", "HEAD"), ("tree", "HEAD^{tree}"))}


def Provision(repository: Path, root: Path) -> dict:
    """Verify the fixed archive before bounded inspection and stream one nonexecutable member."""

    oracle = ReadJson(repository / "tests/fixtures/trivy/native_oracle.json")
    tree = ast.parse((repository / "src/fuzzy1337/native_configuration.py").read_text())
    pin = next(ast.literal_eval(node.value) for node in tree.body
               if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                   and target.id == "NATIVE_CONFIGURATION_EXECUTABLE_SHA256"
                   for target in node.targets))
    archivePath = root / "release.tar.gz"
    digest = hashlib.sha256()
    received = 0

    with urlopen(oracle["release_asset"], timeout=30) as source, archivePath.open("xb") as output:
        while chunk := source.read(1024 * 1024):
            received += len(chunk)

            if received > 128 * 1024**2:
                raise ValueError("Pinned release exceeds its finite archive budget")

            digest.update(chunk)
            output.write(chunk)

    if digest.hexdigest() != oracle["release_asset_sha256"]:
        raise ValueError("Release differs from the existing independently pinned archive")

    members = []

    with tarfile.open(archivePath) as archive:
        for member in archive:
            if len(members) >= 64:
                raise ValueError("Pinned release exceeds its bounded member inventory")

            members.append(member)

        selected = [member for member in members if member.name == "trivy"]

        if len(selected) != 1 or not selected[0].isfile() or not (
            1 <= selected[0].size <= 256 * 1024**2
        ):
            raise ValueError("Release must contain exactly one bounded regular trivy member")

        member = selected[0]
        executable = root / "selected-trivy"
        source = archive.extractfile(member)

        if source is None:
            raise ValueError("Pinned release member is unavailable")

        written = 0

        with source, executable.open("xb") as output:
            while chunk := source.read(1024 * 1024):
                written += len(chunk)

                if written > member.size:
                    raise ValueError("Release member exceeds its verified size")

                output.write(chunk)

        if written != member.size or Digest(executable) != pin:
            raise ValueError("Selected member differs from the source-owned executable pin")

    executable.chmod(0o400)

    return {"release_asset": oracle["release_asset"], "release_asset_sha256": digest.hexdigest(),
        "release_size_bytes": received, "executable": str(executable),
        "executable_size_bytes": written, "executable_sha256": pin, "mode": "0400",
        "provider_executed": False, "database_provisioned": False}


def Prepare(repository: Path, root: Path) -> None:
    """Build once, install a wheel outside the checkout, and retain exact source provenance."""

    repository = repository.resolve(strict=True)
    root = root.absolute()

    if root.is_relative_to(repository) or root.exists():
        raise ValueError("Acceptance needs a fresh outside-checkout destination")

    root.mkdir(mode=0o700)
    home = root / "preparation-home"
    home.mkdir(mode=0o700)
    environment = {"PATH": os.environ["PATH"], "HOME": str(home),
                   "UV_CACHE_DIR": str(root / "uv-cache"), "LANG": "C.UTF-8"}
    state = SourceState(repository, environment)

    if os.environ.get("MATERIAL_SOURCE_SHA", state["commit"]) != state["commit"]:
        raise ValueError("Acceptance checkout differs from the current workflow revision")

    wheelDirectory = root / "wheel"
    Command([sys.executable, "-I", "-m", "build", "--wheel", "--no-isolation",
             "--outdir", str(wheelDirectory)], repository, environment)
    wheels = tuple(wheelDirectory.glob("*.whl"))

    if len(wheels) != 1:
        raise ValueError("Acceptance requires exactly one original wheel build")

    wheel = wheels[0]
    inventory = []
    sourceHashes = {}

    with zipfile.ZipFile(wheel) as archive:
        for member in archive.infolist():
            if member.file_size > 4 * 1024**2 or len(inventory) >= 4096:
                raise ValueError("Wheel member inventory exceeds its finite provenance budget")

            raw = archive.read(member)
            digest = hashlib.sha256(raw).hexdigest()
            inventory.append({"name": member.filename, "size_bytes": len(raw), "sha256": digest})

            if member.filename.startswith("fuzzy1337/"):
                source = repository / "src" / member.filename

                if not source.is_relative_to(repository / "src/fuzzy1337") or (
                    Digest(source) != digest
                ):
                    raise ValueError("Wheel member differs from the exact clean source revision")

                sourceHashes[member.filename] = digest

    uv = shutil.which("uv", path=environment["PATH"])

    if uv is None:
        raise ValueError("Pinned uv is required for locked noneditable preparation")

    requirements = Command([uv, "export", "--locked", "--extra", "dev", "--no-emit-project",
                            "--format", "requirements-txt"], repository, environment)
    requirementsPath = root / "locked-requirements.txt"
    requirementsPath.write_bytes(requirements)
    installed = root / "environment"
    Command([sys.executable, "-I", "-m", "venv", str(installed)], root, environment)
    interpreter = installed / "bin/python"
    Command([uv, "pip", "install", "--python", str(interpreter), "--require-hashes",
             "-r", str(requirementsPath)], root, environment)
    Command([uv, "pip", "install", "--python", str(interpreter), "--no-deps", str(wheel)],
            root, environment)
    runDirectory = root / "run"
    runDirectory.mkdir(mode=0o700)
    shutil.copyfile(repository / TEST_PATH, runDirectory / Path(TEST_PATH).name)
    helperSource = repository / "tests/fixtures/trivy/native_configuration_material_acceptance.py"
    shutil.copyfile(helperSource, runDirectory / "material_acceptance.py")
    provisioning = Provision(repository, root)

    if SourceState(repository, environment) != state:
        raise ValueError("Source revision changed while preparing installed acceptance")

    evidence = root / "evidence"
    evidence.mkdir(mode=0o700)
    context = {"schema_version": 1, **state, "repository": str(repository), "root": str(root),
        "interpreter": str(interpreter), "environment": str(installed),
        "run_directory": str(runDirectory), "evidence": str(evidence),
        "wheel": {"name": wheel.name, "sha256": Digest(wheel), "members": inventory},
        "source_hashes": sourceHashes, "test_sha256": Digest(repository / TEST_PATH),
        "helper_sha256": Digest(helperSource),
        "requirements_sha256": Digest(requirementsPath), "provisioning": provisioning,
        "quota": "UNKNOWN", "native_product_acceptance": False}
    WriteJson(root / "context.json", context)
    WriteJson(evidence / "installation.json", context)


class InstalledWorkers:
    """Keep bounded xdist workers on the same genuine isolated installed interpreter."""

    def __init__(self, interpreter: str) -> None:
        """Bind only the exact prepared interpreter; do not spawn or patch an executor."""

        self.interpreter = interpreter

    def ConfigureInstalledWorkers(self, config, specs) -> None:
        """Add interpreter isolation to the two existing local worker specifications."""

        del config

        if len(specs) != 2 or any(not spec.popen or spec.python for spec in specs):
            raise ValueError("Installed acceptance requires exactly two fresh local workers")

        for spec in specs:
            spec.python = shlex.join([self.interpreter, "-I"])

    # Pytest discovers its external callback name; the implementation keeps owned naming.
    pytest_xdist_setupnodes = ConfigureInstalledWorkers


def Run(root: Path) -> int:
    """Run only four declared cases with isolated installed controller and xdist interpreters."""

    import pytest

    context = ReadJson(root / "context.json")

    if not sys.flags.isolated or Path(sys.executable).absolute() != Path(context["interpreter"]):
        raise ValueError("Acceptance controller requires the isolated installed interpreter")

    if Path.cwd() != Path(context["run_directory"]) or Digest(Path(__file__)) != (
        context["helper_sha256"]
    ):
        raise ValueError("Installed test controller differs from the exact source helper")

    return int(pytest.main(["test_native_configuration_material_execution.py", "-o", "addopts=",
        "--no-cov", "-n", "2", "--dist=loadscope", "--timeout=120", "-q", "-x",
        "--max-worker-restart=0", "--junitxml=" + str(root / "evidence/pytest.xml")],
        plugins=[InstalledWorkers(context["interpreter"])]))


def Verify(root: Path) -> None:
    """Require all four current-revision JUnit cases and matching original bounded receipts."""

    context = ReadJson(root / "context.json")
    evidence = root / "evidence"
    junitPath = evidence / "pytest.xml"

    if os.environ.get("MATERIAL_SOURCE_SHA", context["commit"]) != context["commit"]:
        raise ValueError("Required helper evidence differs from the current workflow revision")

    if junitPath.is_symlink() or junitPath.stat().st_size > CONTEXT_BYTES:
        raise ValueError("Current-head JUnit is missing or unbounded")

    junit = ElementTree.parse(junitPath).getroot()
    cases = list(junit.iter("testcase"))
    prefix = "test_InstalledMaterialLifecycle["
    expected = {prefix + caseId + "]" for caseId in CASE_IDS}

    if len(cases) != 4 or {item.attrib["name"] for item in cases} != expected or any(
        child.tag in {"skipped", "failure", "error"} for item in junit.iter() for child in item
    ):
        raise ValueError("Required four helper cases did not execute without skips/errors")

    for caseId in CASE_IDS:
        directory = evidence / caseId
        facts = ReadJson(directory / "case.json", RECEIPT_BYTES)
        expectedCount = 2 if caseId == CASE_IDS[0] else 1

        if facts["case_id"] != caseId or facts["commit"] != context["commit"] or (
            facts["tree"] != context["tree"] or facts["wheel_sha256"] != context["wheel"]["sha256"]
            or facts["outcome"] != "installed-helper-assertions-passed"
            or facts["native_product_acceptance"] is not False
            or facts["provider_executed"] is not False
            or facts["pending_tasks"] != [] or facts["helper_count"] != expectedCount
            or facts["terminal"] is not True or facts["private_controls_retained"] != []
            or len(facts["receipt_sha256"]) != expectedCount
        ):
            raise ValueError("Original installed helper case association is incomplete")

        for index in range(expectedCount):
            receiptPath = directory / f"observation-{index + 1}.json"
            receipt = ReadJson(receiptPath, RECEIPT_BYTES)
            argv = receipt["request"]["invocation"]["argv"]

            if receipt["original_result_returned"] is not True or (
                receipt["own_descendants"] is not True or receipt["commit"] != context["commit"]
                or receipt["terminal_ownership"] != (
                    "original-owned-executor-returned-after-verified-cleanup")
                or receipt["module_hashes"] != facts["module_hashes"]
                or Digest(receiptPath) != facts["receipt_sha256"][index]
                or len(argv) != 7 or argv[:4] != [context["interpreter"], "-I", "-m",
                    "fuzzy1337.native_configuration_material_worker"]
            ):
                raise ValueError("Original owned terminal helper result is missing")

            events = receipt["events"]

            if not 2 <= len(events) <= 1024 or (
                [event["sequence"] for event in events] != list(range(len(events)))
                or events[0]["kind"] != "started" or events[-1]["kind"] != "completed"
                or events[-1]["termination"] != receipt["termination"]
            ):
                raise ValueError("Original helper event sequence or terminal association differs")

            for stream, maximum in (("stdout", 64 * 1024), ("stderr", 4096)):
                path = directory / f"observation-{index + 1}-{stream}.bin"

                if path.stat().st_size > maximum or Digest(path) != receipt[stream + "_sha256"]:
                    raise ValueError("Retained original bounded helper stream differs")


def Main() -> None:
    """Expose fixed preparation, isolated helper cases and report verification."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "run", "verify"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--repository", type=Path)
    arguments = parser.parse_args()

    if arguments.action == "prepare":
        if arguments.repository is None:
            parser.error("prepare requires --repository")

        Prepare(arguments.repository, arguments.root)

    elif arguments.action == "run":
        raise SystemExit(Run(arguments.root))

    else:
        Verify(arguments.root)


if __name__ == "__main__":
    Main()
