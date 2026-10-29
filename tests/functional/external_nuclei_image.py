# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Prepare an installed lab image and own target-free explicit-HOME prerequisites.

No image build or engine success is implied by this source. The host must inspect
the later network-none container before launch. Explicit-HOME Go validation does
not establish compatibility with the governed provider's unchanged environment.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from pathlib import Path

from .external_native_runner import MAX_FILE_BYTES, ExportBundle, StrictJson, WriteJson
from .external_nuclei_provisioning import (
    MAX_EXECUTABLE_BYTES,
    IdentityBytes,
    InstalledSourceInventory,
    PrepareMaterial,
)
from .external_nuclei_runner import (
    ARCHIVE_NAME,
    EMPTY_CONFIG,
    PROVIDER_TIMEOUT_SECONDS,
    STDERR_BYTES,
    STDOUT_BYTES,
    VERSION,
    OwnStandaloneProcess,
    ProfileDocument,
    RegularIdentity,
    VerifyBinary,
)

MATERIAL = Path("/opt/benchmark-material")
INPUT = Path("/opt/benchmark-input")
SUPPORT = Path("/opt/benchmark-support/tests/functional")
WHEELS = Path("/opt/benchmark-wheel")
SOURCE = Path("/workspace/src/fuzzy1337")
MANIFEST = Path("/opt/benchmark-provisioning.json")
ROOT = Path("/tmp/nuclei-prerequisites")
ARCHIVE = Path("/opt/benchmark-download") / ARCHIVE_NAME
ASSET_URL = ("https://github.com/projectdiscovery/nuclei/releases/download/v"
             + VERSION + "/" + ARCHIVE_NAME)
SUPPORT_FILES = ("external_native_runner.py", "external_nuclei_runner.py",
                 "external_nuclei_provisioning.py", "external_nuclei_image.py")
TMPFS_BYTES = 64 * 1024 * 1024
VERSION_CAPTURE_BYTES = 16 * 1024


def PrerequisiteArguments(name: str, image_id: str) -> tuple[str, ...]:
    """Declare the later finite offline container without starting Docker.

    Args:
        name: Unique owned prerequisite-container name with twelve lowercase hex digits.
        image_id: Actual immutable image ID, never a mutable image tag.

    Returns:
        Mount-free, nonroot, read-only, bounded network-none Docker create arguments.

    Raises:
        ValueError: The container name or immutable image identity is invalid.
    """

    if re.fullmatch("fuzzy-1337-nuclei-preflight-[a-f0-9]{12}", name) is None or (
        re.fullmatch("sha256:[a-f0-9]{64}", image_id) is None
    ):
        raise ValueError("Nuclei prerequisites require exact owned container/image identities")

    return ("docker", "create", "--name", name, "--user", "1337:1337", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1337,gid=1337,mode=0700",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--cpus", "1",
            "--memory", "256m", "--pids-limit", "64", "--init", "--stop-timeout", "5",
            "--network", "none", image_id, "--prerequisites")


def CurrentWheel() -> Path:
    """Select the single image-local current wheel, refusing missing or ambiguous artifacts.

    Returns:
        Original wheel inside the fixed image directory; no installation is performed.

    Raises:
        ValueError: Zero or multiple wheel candidates are present.
    """

    wheels = list(WHEELS.glob("*.whl"))

    if len(wheels) != 1:
        raise ValueError("Nuclei image requires exactly one original current-source wheel")

    return wheels[0]


def PrepareImage(source_revision: str) -> dict:
    """Freeze verified materials and installed-source inventory without running Nuclei.

    Args:
        source_revision: Host-verified clean committed revision passed by the image build.

    Returns:
        Material/inventory manifest explicitly leaving engine prerequisites not-run.

    Raises:
        ValueError: Linux/root/isolated execution or reused material/origin checks refuse.
        OSError: New image-local files or ownership-preserving modes cannot be created.
    """

    if sys.platform != "linux" or not sys.flags.isolated:
        raise ValueError("Nuclei image preparation requires isolated Linux Python")

    if os.geteuid() != 0:
        raise ValueError("Nuclei image preparation requires image-build root ownership")

    if re.fullmatch("[a-f0-9]{40}", source_revision) is None:
        raise ValueError("Nuclei image preparation requires an exact current source revision")

    configuration = INPUT / "operator-config.yaml"

    with configuration.open("xb") as stream:
        stream.write(EMPTY_CONFIG)

    material = PrepareMaterial(ARCHIVE, INPUT / "prometheus-exposition.yaml",
                               configuration, MATERIAL)
    installed = InstalledSourceInventory(source_revision, CurrentWheel(), SOURCE)
    manifest = {"schema_version": 1, "status": "material-prepared-prerequisites-not-run",
        "source_revision": source_revision, "asset_url": ASSET_URL, "material": material,
        "installed": installed, "support_sha256": {name: RegularIdentity(
            SUPPORT / name, maximum=MAX_FILE_BYTES)["sha256"] for name in SUPPORT_FILES},
        "recipe_sha256": RegularIdentity(INPUT / "nuclei-runner.Dockerfile",
                                          maximum=MAX_FILE_BYTES)["sha256"]}
    WriteJson(MANIFEST, manifest)

    for name in ("nuclei", "prometheus-exposition.yaml", "operator-config.yaml"):
        (MATERIAL / name).chmod(0o555 if name == "nuclei" else 0o444)

    MATERIAL.chmod(0o555)
    MANIFEST.chmod(0o444)

    return manifest


def RequireImageRuntime() -> None:
    """Refuse unisolated, root, writable-root or unbounded/networked prerequisite launches.

    Host Docker inspection remains required; these local checks do not prove the
    image ID, absence of host mounts, resource limits or actual Docker enforcement.

    Raises:
        ValueError: The explicit Linux/nonroot/read-only/private-tmp/network boundary differs.
        OSError: Required kernel filesystem or network-interface state is unavailable.
    """

    if sys.platform != "linux" or not sys.flags.isolated:
        raise ValueError("Nuclei prerequisites require isolated Linux Python")

    if os.geteuid() != 1337 or os.getegid() != 1337:
        raise ValueError("Nuclei prerequisites require UID/GID 1337")

    temporary = os.statvfs("/tmp")
    metadata = Path("/tmp").lstat()

    if not os.statvfs("/").f_flag & os.ST_RDONLY or temporary.f_flag & os.ST_RDONLY or (
        not 0 < temporary.f_blocks * temporary.f_frsize <= TMPFS_BYTES
        or metadata.st_uid != 1337 or metadata.st_gid != 1337
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or {path.name for path in Path("/sys/class/net").iterdir()} != {"lo"}
    ):
        raise ValueError("Nuclei prerequisites require read-only root, bounded private tmp "
                         "and no egress")


def CaptureBytes(stage: Path, role: str, maximum: int) -> bytes:
    """Read bounded original process bytes without truncation or replacement.

    Args:
        stage: Owned prerequisite stage directory containing the process owner's raw files.
        role: Fixed stdout or stderr role selected by this module.
        maximum: Byte ceiling applied before interpreting any original capture.

    Returns:
        Exact captured bytes, including empty streams.

    Raises:
        ValueError: The retained original exceeds its interpretation/transport ceiling.
        OSError: The original stream cannot be read.
    """

    with (stage / (role + ".raw")).open("rb") as stream:
        raw = stream.read(maximum + 1)

    if len(raw) > maximum:
        raise ValueError("Nuclei prerequisite original capture exceeds its byte ceiling")

    return raw


def RunStage(root: Path, name: str, argv: tuple[str, ...], environment: dict[str, str],
             maximum: int) -> bytes:
    """Reuse reviewed Linux process ownership and reject every incomplete prerequisite.

    Args:
        root: New owned prerequisite workspace.
        name: Fixed stage name, either version or validate.
        argv: Exact local prerequisite arguments, without target or discovery inputs.
        environment: Only newly owned explicit HOME/config/cache/temp paths.
        maximum: Original stdout interpretation ceiling; stderr interpretation is
            limited to 16 KiB, separately from the reused owner's raw capture ceiling.

    Returns:
        Original combined stdout/stderr for bounded version/validation interpretation.

    Raises:
        ValueError: Process completion, capture, cleanup or output size is unacceptable.
        OSError: Required original files cannot be retained or read.
        BaseException: Cancellation propagates after the reused owner cleans its process group.
    """

    stage = root / name
    stage.mkdir(mode=0o700)
    WriteJson(stage / "invocation.json", {"argv": list(argv), "environment": environment,
        "provider_timeout_seconds": PROVIDER_TIMEOUT_SECONDS,
        "stdout_capture_bytes": STDOUT_BYTES, "stderr_capture_bytes": STDERR_BYTES,
        "stdout_interpretation_bytes": maximum,
        "stderr_interpretation_bytes": VERSION_CAPTURE_BYTES,
        "original_file_ceiling_bytes": MAX_FILE_BYTES,
        "basis": "target-free-explicit-home-prerequisite"})
    result = OwnStandaloneProcess(stage, argv, environment)

    if result["exit_code"] != 0 or result["streams_complete"] is not True or any(
        result[field] for field in ("timed_out", "capture_exhausted", "launch_error",
            "capture_error", "interrupted", "cleanup_error")
    ):
        raise ValueError("Nuclei prerequisite process did not complete within its owned bounds")

    return CaptureBytes(stage, "stdout", maximum) + CaptureBytes(
        stage, "stderr", VERSION_CAPTURE_BYTES)


def RunPrerequisites() -> dict:
    """Own target-free version and strict exact-template validation, preserving failure bytes.

    Returns:
        Internal prerequisite outcome; never a case observation or scanner-accuracy result.

    Raises:
        ValueError: The runtime boundary refuses before a new workspace is created.
        OSError: A new owned workspace or truthful result files cannot be retained.
        BaseException: Cancellation propagates after actual process-owner cleanup.
    """

    RequireImageRuntime()
    ROOT.mkdir(mode=0o700)
    home = ROOT / "home"

    for directory in (home, home / "config", home / "cache", home / "tmp"):
        directory.mkdir(mode=0o700)

    environment = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / "config"),
                   "XDG_CACHE_HOME": str(home / "cache"), "TMPDIR": str(home / "tmp")}
    outcome = {"status": "failed", "version_probe": "not-run", "go_template_validation": "not-run",
               "governed_no_home_compatibility": "not-established", "configured_target_inputs": [],
               "independent_server_contact_count": None}

    try:
        identity = RegularIdentity(MANIFEST, maximum=MAX_FILE_BYTES)
        manifest = StrictJson(IdentityBytes(MANIFEST, identity, maximum=MAX_FILE_BYTES))

        if not isinstance(manifest, dict) or type(manifest.get("schema_version")) is not int or (
            manifest["schema_version"] != 1
            or manifest.get("status") != "material-prepared-prerequisites-not-run"
            or manifest.get("asset_url") != ASSET_URL
        ):
            raise ValueError("Nuclei immutable image manifest is incompatible")

        installed = InstalledSourceInventory(manifest["source_revision"], CurrentWheel(), SOURCE)

        if installed != manifest["installed"]:
            raise ValueError("Nuclei runtime wheel/source/import inventory changed")

        executable = MATERIAL / "nuclei"
        template = MATERIAL / "prometheus-exposition.yaml"
        configuration = MATERIAL / "operator-config.yaml"
        ProfileDocument(template, configuration)
        expected = manifest["material"]["executable"]["sha256"]
        binary = RegularIdentity(executable, maximum=MAX_EXECUTABLE_BYTES, executable=True)

        if binary["sha256"] != expected:
            raise ValueError("Nuclei image executable differs from acquired material identity")

        WriteJson(ROOT / "image-provisioning.json", manifest)
        outcome["version_probe"] = "failed"
        raw = RunStage(ROOT, "version", (str(executable), "-version", "-duc"), environment,
                       VERSION_CAPTURE_BYTES)
        versions = re.findall(rb"Nuclei Engine Version:\s*v?([0-9A-Za-z.+-]+)", raw)

        if versions != [VERSION.encode("ascii")]:
            raise ValueError("Nuclei prerequisite requires exact observed version 3.4.10")

        VerifyBinary(executable, expected, VERSION)
        outcome["version_probe"] = "completed"
        outcome["go_template_validation"] = "failed"
        raw = RunStage(ROOT, "validate", (str(executable), "-validate", "-t", str(template),
            "-config", str(configuration), "-duc", "-ni", "-no-stdin", "-pt", "http", "-nc"),
            environment, MAX_FILE_BYTES)

        if b"All templates validated successfully" not in raw:
            raise ValueError("Nuclei strict validation success receipt is absent")

        outcome.update(status="completed-prerequisites", go_template_validation="completed")

    except Exception as error:
        WriteJson(ROOT / "failure.json", {"exception_type": type(error).__name__,
                                         "basis": "failed-prerequisite-not-a-case-result"})

    WriteJson(ROOT / "prerequisites.json", outcome)

    return outcome


def Main(arguments: list[str] | None = None) -> int:
    """Prepare material at build time or export offline prerequisites after host admission.

    Args:
        arguments: Explicit CLI selection for inert tests; defaults to actual process arguments.

    Returns:
        Zero only for successful material preparation or completed local prerequisites;
        four for failed prerequisites. This entry has no target/case execution mode.

    Raises:
        SystemExit: CLI selection is missing, ambiguous or outside the finite interface.
        OSError: Required original evidence cannot be retained or exported.
        ValueError: Image/runtime/transport checks refuse; no success bundle is fabricated.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare", action="store_true")
    mode.add_argument("--prerequisites", action="store_true")
    parser.add_argument("--source-revision")
    options = parser.parse_args(arguments)

    if options.prepare:
        if options.source_revision is None:
            parser.error("--prepare requires --source-revision")

        PrepareImage(options.source_revision)

        return 0

    if options.source_revision is not None:
        parser.error("--source-revision is restricted to image preparation")

    outcome = RunPrerequisites()

    try:
        bundle = ExportBundle(ROOT, outcome)

    except ValueError:
        outcome["status"] = "failed"
        WriteJson(ROOT / "prerequisites.json", outcome)

        raise

    print(bundle)

    return 0 if outcome["status"] == "completed-prerequisites" else 4
