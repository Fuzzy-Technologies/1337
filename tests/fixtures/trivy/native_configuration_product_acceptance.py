# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Build a noneditable installed configuration product lane and verify genuine case evidence."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import shutil
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree

SHARED_PATH = Path(__file__).with_name("native_configuration_material_acceptance.py")
SHARED_SPEC = importlib.util.spec_from_file_location("configuration_product_preparation",
                                                   SHARED_PATH)

if SHARED_SPEC is None or SHARED_SPEC.loader is None:
    raise ValueError("Fixed configuration product preparation module is unavailable")

shared = importlib.util.module_from_spec(SHARED_SPEC)
SHARED_SPEC.loader.exec_module(shared)

TEST_PATH = "tests/functional/test_native_configuration_product.py"
CASE_IDS = (
    "dockerfile.root-user", "dockerfile.non-root-user", "kubernetes.privileged-container",
    "kubernetes.non-privileged-container", "kubernetes.second-document",
    "approval-refused", "scope-refused", "invalid-utf8-refused", "oversized-source-refused",
    "unsupported-executable-refused",
    "owned-executor-checkpoints",
)


def Prepare(repository: Path, root: Path) -> None:
    """Build one clean source wheel, install it without editability, and copy fixed owned inputs.

    Args:
        repository: Explicit clean committed source checkout.
        root: Fresh explicitly selected outside-checkout lane directory.
    """

    repository = repository.resolve(strict=True)
    root = root.absolute()

    if root.is_relative_to(repository) or root.exists():
        raise ValueError("Installed product acceptance requires a fresh outside-checkout root")

    root.mkdir(mode=0o700)
    home = root / "preparation-home"
    home.mkdir(mode=0o700)
    environment = {"PATH": os.environ["PATH"], "HOME": str(home),
                   "UV_CACHE_DIR": str(root / "uv-cache"), "LANG": "C.UTF-8"}
    state = shared.SourceState(repository, environment)

    if os.environ.get("CONFIGURATION_SOURCE_SHA", state["commit"]) != state["commit"]:
        raise ValueError("Installed product source differs from the selected workflow revision")

    wheels = root / "wheel"
    shared.Command([sys.executable, "-I", "-m", "build", "--wheel", "--no-isolation",
                    "--outdir", str(wheels)], repository, environment)
    selected = tuple(wheels.glob("*.whl"))

    if len(selected) != 1:
        raise ValueError("Installed product acceptance requires exactly one built wheel")

    wheel = selected[0]
    hashes = {}

    with zipfile.ZipFile(wheel) as archive:
        members = archive.infolist()

        if len(members) > 4096:
            raise ValueError("Installed product wheel member inventory exceeds its bound")

        for member in members:
            if member.file_size > 4 * 1024**2:
                raise ValueError("Installed product wheel member exceeds its finite byte bound")

            if not member.filename.startswith("fuzzy1337/"):
                continue

            digest = hashlib.sha256(archive.read(member)).hexdigest()
            source = repository / "src" / member.filename

            if not source.is_relative_to(repository / "src/fuzzy1337") or (
                shared.Digest(source) != digest
            ):
                raise ValueError("Installed product wheel member differs from its clean source")

            hashes[member.filename] = digest

    uv = shutil.which("uv", path=environment["PATH"])

    if uv is None:
        raise ValueError("Installed product preparation requires the pinned uv environment")

    requirements = root / "locked-requirements.txt"
    requirements.write_bytes(shared.Command([uv, "export", "--locked", "--extra", "dev",
        "--no-emit-project", "--format", "requirements-txt"], repository, environment))
    installed = root / "environment"
    shared.Command([sys.executable, "-I", "-m", "venv", str(installed)], root, environment)
    interpreter = installed / "bin/python"
    shared.Command([uv, "pip", "install", "--python", str(interpreter), "--require-hashes",
                    "-r", str(requirements)], root, environment)
    shared.Command([uv, "pip", "install", "--python", str(interpreter), "--no-deps", str(wheel)],
                   root, environment)
    run_directory = root / "run"
    run_directory.mkdir(mode=0o700)
    files = {"test_native_configuration_product.py": repository / TEST_PATH,
        "product_acceptance.py": Path(__file__).absolute(),
        "native_configuration_material_acceptance.py": Path(shared.__file__).absolute(),
        "configuration_oracle.json": repository /
            "tests/fixtures/trivy/configuration_compatibility.v1.json"}
    copied = {}

    for name, source in files.items():
        shutil.copyfile(source, run_directory / name)
        copied[name] = shared.Digest(source)

    corpus = repository / "tests/contract/fixtures/configuration_profiles"

    for relative in ("dockerfile/unsafe/Dockerfile", "dockerfile/safe/Dockerfile",
                     "kubernetes/unsafe.yaml", "kubernetes/safe.yaml", "kubernetes/multi.yaml"):
        destination = run_directory / "specimens" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(corpus / relative, destination)

    provisioning = shared.Provision(repository, root)

    if shared.SourceState(repository, environment) != state:
        raise ValueError("Installed product source changed during preparation")

    evidence = root / "evidence"
    evidence.mkdir(mode=0o700)
    context = {"schema_version": 1, **state, "repository": str(repository), "root": str(root),
        "interpreter": str(interpreter), "environment": str(installed),
        "run_directory": str(run_directory), "evidence": str(evidence),
        "wheel": {"name": wheel.name, "sha256": shared.Digest(wheel)},
        "source_hashes": hashes, "copied_hashes": copied,
        "requirements_sha256": shared.Digest(requirements), "provisioning": provisioning,
        "native_product_acceptance": "unexecuted"}
    shared.WriteJson(root / "context.json", context)
    shared.WriteJson(evidence / "installation.json", context)


def Run(root: Path) -> int:
    """Run ten product cases and one owned-executor case with isolated installed interpreters.

    Args:
        root: Prepared outside-checkout lane root.

    Returns:
        Actual pytest exit code; skips never establish acceptance.
    """

    import pytest

    context = shared.ReadJson(root / "context.json")

    if not sys.flags.isolated or Path(sys.executable).absolute() != Path(context["interpreter"]):
        raise ValueError("Installed product controller requires its isolated installed interpreter")

    if Path.cwd() != Path(context["run_directory"]) or shared.Digest(Path(__file__)) != (
        context["copied_hashes"]["product_acceptance.py"]
    ):
        raise ValueError("Installed product controller source or working directory differs")

    return int(pytest.main(["test_native_configuration_product.py", "-o", "addopts=", "--no-cov",
        "-n", "2", "--dist=loadscope", "--timeout=180", "-q", "-x", "--max-worker-restart=0",
        "--junitxml=" + str(root / "evidence/pytest.xml")],
        plugins=[shared.InstalledWorkers(context["interpreter"])]))


def Verify(root: Path) -> None:
    """Require every genuine current-revision case, original pair and installed module association.

    Args:
        root: Explicit prepared lane root containing actual pytest evidence.
    """

    context = shared.ReadJson(root / "context.json")

    if os.environ.get("CONFIGURATION_SOURCE_SHA", context["commit"]) != context["commit"]:
        raise ValueError("Installed product evidence differs from the current workflow revision")

    junit = root / "evidence/pytest.xml"

    if junit.is_symlink() or junit.stat().st_size > 1024 * 1024:
        raise ValueError("Installed product JUnit is missing or exceeds its finite bound")

    document = ElementTree.parse(junit).getroot()
    cases = list(document.iter("testcase"))
    wanted = {"test_InstalledNativeConfigurationProduct[" + identity + "]"
              for identity in CASE_IDS[:10]}
    wanted.add("test_InstalledOwnedHarmlessExecutor")

    if len(cases) != len(wanted) or {item.attrib["name"] for item in cases} != wanted or any(
        child.tag in {"skipped", "failure", "error"} for item in document.iter() for child in item
    ):
        raise ValueError("Required installed product cases did not actually pass without skips")

    for identity in CASE_IDS:
        facts = shared.ReadJson(root / "evidence" / identity / "case.json", 512 * 1024)

        if facts["case_id"] != identity or facts["commit"] != context["commit"] or (
            facts["tree"] != context["tree"] or facts["wheel_sha256"] != context["wheel"]["sha256"]
            or facts["outcome"] != "installed-product-assertions-passed"
            or facts["installed_module_hashes"].get("fuzzy1337.native_configuration_workflow") != (
                context["source_hashes"]["fuzzy1337/native_configuration_workflow.py"])
        ):
            raise ValueError("Installed product original source/case attribution is incomplete")

        if identity in CASE_IDS[:5] and (facts["original_operations"] != ["version", "scan"] or
            len(facts["sdk_evidence_ids"]) != 7 or len(facts["cli_evidence_ids"]) != 7
            or facts["native_product_acceptance"] is not True
            or facts["observed_provider_operations"] != ["version", "scan"]
            or facts["provider_authority_checkpoints"] != ["version", "version", "scan", "scan"]):
            raise ValueError("Genuine product case lacks its original SDK/CLI seven-role pairs")

        if identity in CASE_IDS[5:] and (facts["observed_provider_operations"] or
            facts["provider_authority_checkpoints"]):
            raise ValueError("Refused native product case reached an actual provider launch")

        if identity == CASE_IDS[-1]:
            directory = root / "evidence" / identity

            if len(facts["actual_checkpoints"]) != 2 or facts["actual_checkpoints"][0] != (
                facts["actual_checkpoints"][1]
            ) or facts["termination"] != "process_exit" or facts["execution"]["exit_code"] != 0:
                raise ValueError("Installed owned producer lacks its original two launch checks")

            for stream in ("stdout", "stderr"):
                if shared.Digest(directory / ("original-" + stream + ".bin")) != (
                    facts[stream + "_sha256"]
                ):
                    raise ValueError("Installed owned producer original stream identity differs")


def Main() -> None:
    """Expose fixed product preparation, installed pytest execution and actual-evidence checking."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "run", "verify"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--repository", type=Path)
    arguments = parser.parse_args()

    if arguments.action == "prepare":
        if arguments.repository is None:
            raise ValueError("Installed product preparation requires the explicit repository")

        Prepare(arguments.repository, arguments.root)

    elif arguments.action == "run":
        raise SystemExit(Run(arguments.root))

    else:
        Verify(arguments.root)


if __name__ == "__main__":
    Main()
