# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Inert image/prerequisite contracts; no Docker, installation, acquisition or engine execution."""

from __future__ import annotations

import asyncio
import json
import os
import stat
import subprocess
import sys
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.functional import external_nuclei_image as image
from tests.functional.external_native_runner import MAX_FILE_BYTES, ImportBundle, WriteJson
from tests.functional.external_nuclei_runner import (
    ARCHIVE_NAME,
    ARCHIVE_SHA256,
    EMPTY_CONFIG,
    RegularIdentity,
)

REPOSITORY = Path(__file__).resolve().parents[2]
LINUX_IMAGE = pytest.mark.skipif(sys.platform != "linux", reason="Image entry is Linux-only")


@pytest.fixture(autouse=True)
def ForbidActualProcessesAndAcquisition(monkeypatch):
    """Reject any accidental subprocess or download in this explicitly inert source selection."""

    def Forbidden(*arguments, **options):
        """Make external behavior fail before any actual provider, Docker or network work."""

        raise AssertionError("Image contracts must never launch or acquire a genuine prerequisite")

    for module, attribute in ((subprocess, "Popen"), (subprocess, "run"),
                              (asyncio, "create_subprocess_exec"), (urllib.request, "urlopen")):
        monkeypatch.setattr(module, attribute, Forbidden)


def InertImage(tmp_path, monkeypatch, mode="success"):
    """Visibly replace runtime/origin/process checks while retaining ordinary fixture bytes."""

    for name in ("MATERIAL", "INPUT", "SUPPORT", "WHEELS", "SOURCE"):
        path = tmp_path / name.lower()
        path.mkdir()
        monkeypatch.setattr(image, name, path)

    monkeypatch.setattr(image, "MANIFEST", tmp_path / "image.json")
    monkeypatch.setattr(image, "ROOT", tmp_path / "prerequisites")
    (image.MATERIAL / "prometheus-exposition.yaml").write_bytes((REPOSITORY /
        "labs/external/benchmark/templates/prometheus-exposition.yaml").read_bytes())
    (image.MATERIAL / "operator-config.yaml").write_bytes(EMPTY_CONFIG)
    executable = image.MATERIAL / "nuclei"
    executable.write_bytes(b"INERT bytes, never a Nuclei executable or process\n")
    executable.chmod(0o700)
    (image.WHEELS / "inert-not-installed.whl").write_bytes(b"INERT wheel, never installed\n")
    installed = {"basis": "inert substituted installed-origin preflight; no installation"}
    manifest = {"schema_version": 1, "status": "material-prepared-prerequisites-not-run",
        "asset_url": image.ASSET_URL, "source_revision": "a" * 40, "installed": installed,
        "material": {"executable": RegularIdentity(executable, maximum=1024)}}
    calls = []

    def Process(root, argv, environment):
        """Write labeled synthetic captures instead of starting any genuine child process."""

        calls.append((argv, dict(environment)))
        version = root.name == "version"
        stdout = b"INERT contract output\n" + (b"Nuclei Engine Version: v3.4.10\n" if version
            else b"All templates validated successfully\n")

        if mode == "version" and version:
            stdout = b"INERT Nuclei Engine Version: v3.4.100\n"

        elif mode == "validation" and not version:
            stdout = b"INERT no validation receipt\n"

        elif mode == "overflow" and version:
            stdout = b"x" * (image.VERSION_CAPTURE_BYTES + 1)

        (root / "stdout.raw").write_bytes(stdout)
        (root / "stderr.raw").write_bytes(b"INERT diagnostic bytes\n")
        (Path(environment["XDG_CONFIG_HOME"]) / "inert-init.json").write_bytes(
            b'{"basis":"inert generated fixture, not genuine initialization"}\n')
        result = {"exit_code": 0, "timed_out": False, "capture_exhausted": None,
            "launch_error": None, "capture_error": None, "interrupted": None,
            "cleanup_error": None, "streams_complete": True, "duration_seconds": 0.01,
            "basis": "inert substituted local process owner; no binary executed"}

        if mode in {"timeout", "capture", "cleanup", "nonzero", "incomplete"} and version:
            field, value = {"timeout": ("timed_out", True), "capture": ("capture_error", "OSError"),
                "cleanup": ("cleanup_error", "OSError"), "nonzero": ("exit_code", 1),
                "incomplete": ("streams_complete", False)}[mode]
            result[field] = value

        WriteJson(root / "process.json", result)

        return result

    monkeypatch.setattr(image, "RequireImageRuntime", Mock(return_value=None))
    monkeypatch.setattr(image, "InstalledSourceInventory", Mock(return_value=installed))
    monkeypatch.setattr(image, "OwnStandaloneProcess", Process)

    if mode == "inventory":
        manifest["installed"] = {"basis": "different inert inventory"}

    elif mode == "binary":
        executable.write_bytes(b"changed inert executable")

    elif mode == "manifest":
        manifest["schema_version"] = True

    WriteJson(image.MANIFEST, manifest)

    return calls, manifest


@LINUX_IMAGE
@pytest.mark.parametrize("refusal", [False, True], ids=["completed", "failed-validation"])
def test_InertGovernedPrerequisiteNeverAddsHomeOrClaimsCaseExecution(
    tmp_path, monkeypatch, refusal
):
    """Inert no-HOME probe retains exact environment, strict validation and unknown contacts."""

    _, _ = InertImage(tmp_path, monkeypatch)
    monkeypatch.setattr(image, "GOVERNED_ROOT", tmp_path / "governed")
    calls = []

    def Process(root, argv, environment):
        """Record explicit source contracts instead of launching the inert provider bytes."""

        calls.append((argv, dict(environment)))
        stdout = b"Nuclei Engine Version: v3.4.10\n" if root.name == "version" else (
            b"validation refused\n" if refusal else b"All templates validated successfully\n")
        (root / "stdout.raw").write_bytes(stdout)
        (root / "stderr.raw").write_bytes(b"")
        result = {"exit_code": 0, "timed_out": False, "capture_exhausted": None,
            "launch_error": None, "capture_error": None, "interrupted": None,
            "cleanup_error": None, "streams_complete": True, "duration_seconds": 0.01}
        WriteJson(root / "process.json", result)

        return result

    monkeypatch.setattr(image, "OwnStandaloneProcess", Process)
    outcome = image.RunPrerequisites(governed_no_home=True)
    assert len(calls) == 2 and all(environment == {
        "PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"
    } for _, environment in calls), (
        "The governed initialization probe must never add HOME, XDG, config routing or host values"
    )
    assert outcome["governed_no_home_compatibility"] == (
        "not-established" if refusal else "established"
    ) and outcome["configured_target_inputs"] == [] and (
        outcome["independent_server_contact_count"] is None
    ), "A failed no-HOME probe cannot borrow explicit-HOME evidence or become a target observation"
    assert all("-u" not in argv for argv, _ in calls), (
        "No target contact or additional endpoint probe belongs to the no-HOME prerequisite"
    )
    invocation = json.loads((image.GOVERNED_ROOT / "validate/invocation.json").read_bytes())
    assert invocation["basis"] == "target-free-governed-no-home-prerequisite", (
        "Original invocation evidence must distinguish the new gate from earlier HOME evidence"
    )


@pytest.mark.parametrize("missing", [None, "--path", "--target-instance", "--owner-token"])
def test_FiniteImageEntryDispatchesOnlyCompleteExplicitApplicationSelection(monkeypatch, missing):
    """The actual image entry forwards only the finite selected tuple; no provider runs here."""

    from tests.functional import external_nuclei_application as application

    calls = []

    def Export(*arguments):
        """Record explicit dispatch instead of starting any actual image-side application work."""

        calls.append(arguments)

        return 7

    monkeypatch.setattr(application, "ExportApplication", Export)
    arguments = ["--track", "whole1337", "--path", "/metrics", "--target-instance", "d" * 64,
                 "--owner-token", "a" * 32]

    if missing is not None:
        position = arguments.index(missing)
        del arguments[position:position + 2]

        with pytest.raises(SystemExit):
            image.Main(arguments)

        assert not calls, "Incomplete image selection cannot dispatch or choose a default"

    else:
        assert image.Main(arguments) == 7 and calls == [(
            "whole1337", "/metrics", "d" * 64, "a" * 32)
        ], "The actual entry must preserve explicit selection and the real result status"


def test_ImageRecipeFreezesAssetAndInstalledWheelBeforeRuntime():
    """The new recipe pins acquisition and performs no engine probe during image construction."""

    recipe = (REPOSITORY / "labs/external/benchmark/nuclei-runner.Dockerfile").read_text()
    assert "ADD --checksum=sha256:" + ARCHIVE_SHA256 in recipe, (
        "Docker acquisition must use the already accepted official archive checksum."
    )
    assert image.ASSET_URL in recipe and recipe.count(ARCHIVE_NAME) == 2, (
        "Only the exact official release URL and retained archive path may be acquired."
    )
    assert "--no-isolation --wheel" in recipe and "--no-index --no-deps" in recipe, (
        "The runtime must import the new wheel without editable or dependency fallback."
    )
    assert recipe.count("RUN --network=none") == 2 and "--prepare --source-revision" in recipe, (
        "Build phases must prepare material offline after the separate pinned ADD acquisition."
    )
    assert "-version" not in recipe and "-validate" not in recipe, (
        "Docker build must not silently execute unreviewed engine prerequisites."
    )
    assert 'USER 1337:1337' in recipe and '["/usr/bin/env", "-i"' in recipe, (
        "The later entry must launch isolated Python as nonroot with a clean environment."
    )


def test_PrerequisiteContainerArgumentsStayOfflineAndBounded():
    """Declare one isolated prerequisite container without target network or host access."""

    argv = image.PrerequisiteArguments("fuzzy-1337-nuclei-preflight-" + "a" * 12,
                                       "sha256:" + "b" * 64)
    assert argv[argv.index("--network") + 1] == "none" and "--read-only" in argv, (
        "Prerequisites must use neither target namespace nor external network access."
    )
    assert argv[argv.index("--tmpfs") + 1] == (
        "/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1337,gid=1337,mode=0700"
    ), "HOME/cache evidence needs a private finite tmpfs owned by the nonroot user."
    assert not {"--env", "--env-file", "--mount", "--volume", "--publish"}.intersection(argv), (
        "No host environment, mounts, ports or Docker socket may enter prerequisite execution."
    )


@pytest.mark.parametrize("name,image_id", [("arbitrary", "sha256:" + "b" * 64),
    ("fuzzy-1337-nuclei-preflight-" + "a" * 12, "mutable:tag")], ids=["name", "tag"])
def test_PrerequisiteArgumentsRefuseAmbiguousOwnership(name, image_id):
    """A mutable image reference or unrelated container name never reaches Docker arguments."""

    with pytest.raises(ValueError, match="exact owned"):
        image.PrerequisiteArguments(name, image_id)


@LINUX_IMAGE
def test_InertPrerequisitesPreserveExactFlagsPrivateHomeAndOriginalBundle(
    tmp_path, monkeypatch, capsys,
):
    """Labeled synthetic stages prove custody only, never genuine version or Go compatibility."""

    calls, manifest = InertImage(tmp_path, monkeypatch)
    monkeypatch.setenv("INERT_HOST_TOKEN", "fixture-must-not-forward")
    assert image.Main(["--prerequisites"]) == 0, (
        "Both replaced local stages must complete the fixture."
    )
    bundle = ImportBundle(capsys.readouterr().out.encode(), tmp_path / "imported")
    outcome = bundle["outcome"]
    executable = str(image.MATERIAL / "nuclei")
    assert calls[0][0] == (executable, "-version", "-duc"), (
        "The version prerequisite must use only the genuine fixed local version arguments."
    )
    assert calls[1][0] == (executable, "-validate", "-t",
        str(image.MATERIAL / "prometheus-exposition.yaml"), "-config",
        str(image.MATERIAL / "operator-config.yaml"), "-duc", "-ni", "-no-stdin", "-pt", "http",
        "-nc"), "Go validation must bind one exact reviewed rule/config and contain no target."
    home = image.ROOT / "home"
    assert calls[0][1] == calls[1][1] == {"HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache"),
        "TMPDIR": str(home / "tmp")}, "Neither stage may inherit host/process environment."
    assert outcome["governed_no_home_compatibility"] == "not-established" and (
        outcome["configured_target_inputs"] == []
        and outcome["independent_server_contact_count"] is None
    ), "Prerequisite success cannot invent governed compatibility or measured target contacts."
    assert manifest["installed"]["basis"].startswith("inert substituted"), (
        "Successful fixture origin checks must remain explicitly labeled as replaced evidence."
    )
    retained = tmp_path / "imported/home/config/inert-init.json"
    assert retained.read_bytes().startswith(b'{"basis"'), (
        "Generated configuration originals and their bundle inventory must survive unchanged."
    )
    invocation = json.loads((tmp_path / "imported/version/invocation.json").read_text())
    assert (invocation["stdout_capture_bytes"], invocation["stderr_capture_bytes"]) == (
        image.STDOUT_BYTES, image.STDERR_BYTES
    ), "Raw owner capture ceilings must remain separate from smaller interpretation/transport caps."
    assert invocation["stdout_interpretation_bytes"] == image.VERSION_CAPTURE_BYTES, (
        "The local version parser must retain its stricter separately recorded byte ceiling."
    )


@LINUX_IMAGE
@pytest.mark.parametrize("mode", ["version", "validation", "overflow", "timeout", "capture",
    "cleanup", "nonzero", "incomplete", "inventory", "binary", "manifest"],
    ids=["version", "go-receipt", "bytes", "deadline", "capture", "cleanup", "exit", "eof",
         "inventory", "binary", "manifest"])
def test_InertPrerequisiteRefusalNeverProducesCompletedObservation(tmp_path, monkeypatch, mode):
    """Provider/origin/custody failures keep original bytes and remain failed prerequisites."""

    calls, _ = InertImage(tmp_path, monkeypatch, mode)
    outcome = image.RunPrerequisites()
    assert outcome["status"] == "failed", "No refused prerequisite may be relabeled completed."
    assert outcome["governed_no_home_compatibility"] == "not-established", (
        "An incompatible prerequisite cannot establish the unchanged SDK environment behavior."
    )
    assert (image.ROOT / "failure.json").is_file(), (
        "The owned workspace must retain refusal evidence."
    )

    if mode in {"inventory", "binary", "manifest"}:
        assert calls == [], "Invalid image custody must refuse before any local tool stage."

    elif mode == "overflow":
        retained = image.ROOT / "version/stdout.raw"
        assert retained.stat().st_size == image.VERSION_CAPTURE_BYTES + 1, (
            "Output exceeding the interpretation cap must remain untruncated original evidence."
        )


@LINUX_IMAGE
def test_PrerequisiteExportRefusalKeepsOriginalsAndFailedState(tmp_path, monkeypatch):
    """An oversized original cannot be silently omitted from a successful prerequisite bundle."""

    InertImage(tmp_path, monkeypatch)
    original = image.RunPrerequisites

    def Oversize():
        """Add explicitly inert oversized evidence after both replaced local stages finish."""

        outcome = original()
        (image.ROOT / "oversize.raw").write_bytes(b"x" * (MAX_FILE_BYTES + 1))

        return outcome

    monkeypatch.setattr(image, "RunPrerequisites", Oversize)

    with pytest.raises(ValueError, match="finite original-byte"):
        image.Main(["--prerequisites"])

    assert json.loads((image.ROOT / "prerequisites.json").read_text())["status"] == "failed", (
        "Failed transport must revoke aggregate prerequisite success without discarding raw files."
    )
    assert (image.ROOT / "oversize.raw").stat().st_size == MAX_FILE_BYTES + 1, (
        "Refused originals must never be truncated or replaced by normalized output."
    )


@pytest.mark.parametrize("platform", ["win32", "darwin"], ids=["windows", "macos"])
def test_ImageEntryRejectsUnsupportedPlatformBeforeReadingOrWriting(
    tmp_path, monkeypatch, platform,
):
    """Unsupported identifiers are logical refusal tests, never emulated Linux execution proof."""

    monkeypatch.setattr(image.sys, "platform", platform)
    monkeypatch.setattr(image, "ROOT", tmp_path / "absent")

    with pytest.raises(ValueError, match="isolated Linux"):
        image.PrepareImage("a" * 40)

    with pytest.raises(ValueError, match="isolated Linux"):
        image.RunPrerequisites()

    assert list(tmp_path.iterdir()) == [], (
        "Unsupported entry must not create preparation/runtime files."
    )


@LINUX_IMAGE
@pytest.mark.parametrize("failure", ["none", "user", "root", "tmp-size", "tmp-owner", "network"],
                         ids=["allowed", "user", "root", "tmp-size", "tmp-owner", "network"])
def test_RuntimeKernelGuardsUseInertReadbackOnly(monkeypatch, failure):
    """Exercise replaced kernel metadata without claiming real Docker enforcement."""

    temporary = SimpleNamespace(f_flag=0, f_blocks=64, f_frsize=1024 * 1024)
    root = SimpleNamespace(f_flag=0 if failure == "root" else os.ST_RDONLY)
    metadata = SimpleNamespace(st_uid=0 if failure == "tmp-owner" else 1337, st_gid=1337,
                               st_mode=stat.S_IFDIR | 0o700)

    if failure == "tmp-size":
        temporary.f_blocks = 65

    monkeypatch.setattr(image.sys, "flags", SimpleNamespace(isolated=True))
    monkeypatch.setattr(image.os, "geteuid", Mock(return_value=0 if failure == "user" else 1337))
    monkeypatch.setattr(image.os, "getegid", Mock(return_value=1337))
    monkeypatch.setattr(image.os, "statvfs", lambda path: root if path == "/" else temporary)
    monkeypatch.setattr(Path, "lstat", Mock(return_value=metadata))
    monkeypatch.setattr(Path, "iterdir", Mock(return_value=[Path("eth0" if failure == "network"
                                                              else "lo")]))

    if failure == "none":
        image.RequireImageRuntime()

    else:
        with pytest.raises(ValueError):
            image.RequireImageRuntime()


@pytest.mark.parametrize("arguments", [[], ["--path", "/metrics"], ["--prepare"],
    ["--prepare", "--prerequisites"], ["--prerequisites", "--source-revision", "a" * 40]],
    ids=["missing", "case", "revision", "ambiguous", "runtime-revision"])
def test_ImageEntryHasNoCaseOrArbitraryToolMode(arguments):
    """The prerequisite entry cannot become a hidden case runner or arbitrary command launcher."""

    with pytest.raises(SystemExit) as captured:
        image.Main(arguments)

    assert captured.value.code == 2, (
        "Invalid finite CLI selection must fail before image/process work."
    )


@pytest.mark.parametrize("count", [0, 2], ids=["missing", "ambiguous"])
def test_CurrentWheelRequiresSingleOriginalArtifact(tmp_path, monkeypatch, count):
    """Missing or ambiguous original wheels cannot silently select a convenient artifact."""

    monkeypatch.setattr(image, "WHEELS", tmp_path)

    for index in range(count):
        (tmp_path / (str(index) + ".whl")).write_bytes(b"INERT never installed")

    with pytest.raises(ValueError, match="exactly one"):
        image.CurrentWheel()


@LINUX_IMAGE
def test_InertImagePreparationReusesReviewedGatesWithoutEngineExecution(tmp_path, monkeypatch):
    """Replaced material/origin gates leave a not-run manifest and readable frozen fixture files."""

    for name in ("MATERIAL", "INPUT", "SUPPORT", "WHEELS", "SOURCE"):
        path = tmp_path / name.lower()
        monkeypatch.setattr(image, name, path)

        if name != "MATERIAL":
            path.mkdir()

    monkeypatch.setattr(image, "MANIFEST", tmp_path / "prepared.json")
    (image.WHEELS / "inert.whl").write_bytes(b"INERT never installed")
    (image.INPUT / "nuclei-runner.Dockerfile").write_bytes(b"INERT recipe fixture")

    for name in image.SUPPORT_FILES:
        (image.SUPPORT / name).write_bytes(b"INERT support identity, never imported")

    def Material(archive, template, configuration, destination):
        """Create labeled fixture files without claiming verification of official material."""

        assert archive == image.ARCHIVE and configuration.read_bytes() == EMPTY_CONFIG, (
            "Preparation must select the fixed archive and exact empty operator config."
        )
        assert template == image.INPUT / "prometheus-exposition.yaml", (
            "Preparation must pass the fixed exact candidate path to its reviewed verifier."
        )
        destination.mkdir()

        for name in ("nuclei", "prometheus-exposition.yaml", "operator-config.yaml"):
            (destination / name).write_bytes(b"INERT replaced material verifier")

        return {"basis": "inert substituted material gate; no official asset acquired"}

    monkeypatch.setattr(image, "PrepareMaterial", Material)
    monkeypatch.setattr(image, "InstalledSourceInventory", Mock(return_value={
        "basis": "inert substituted installed-origin gate; no wheel installed"}))
    monkeypatch.setattr(image.sys, "flags", SimpleNamespace(isolated=True))
    monkeypatch.setattr(image.os, "geteuid", Mock(return_value=0))
    result = image.PrepareImage("a" * 40)
    assert result["status"] == "material-prepared-prerequisites-not-run", (
        "Material preparation must not invent a version or genuine Go validation result."
    )
    assert result["material"]["basis"].startswith("inert substituted"), (
        "Successful replaced prerequisite gates must remain visible as inert fixture evidence."
    )
    assert stat.S_IMODE((image.MATERIAL / "nuclei").stat().st_mode) == 0o555, (
        "Root-prepared executable material must be readable/executable by the later nonroot entry."
    )
    assert stat.S_IMODE(image.MANIFEST.stat().st_mode) == 0o444, (
        "The new image manifest must be frozen after its bounded source facts are written."
    )
