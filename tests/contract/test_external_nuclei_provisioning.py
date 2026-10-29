# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Inert offline material contracts; no official acquisition, installation or execution."""

from __future__ import annotations

import asyncio
import hashlib
import io
import stat
import subprocess
import sys
import urllib.request
from pathlib import Path
from zipfile import ZIP_STORED, BadZipFile, ZipFile, ZipInfo

import pytest

from tests.functional import external_nuclei_provisioning as provisioning
from tests.functional.external_nuclei_runner import (
    EMPTY_CONFIG,
    MODULES,
    ProfileDocument,
    RegularIdentity,
)

REPOSITORY = Path(__file__).resolve().parents[2]
INERT_EXECUTABLE = b"INERT fixture bytes, never an installed or executed Nuclei binary\n"
LINUX_MATERIALIZATION = pytest.mark.skipif(
    sys.platform != "linux", reason="Executable materialization requires Linux file-mode semantics",
)


@pytest.fixture(autouse=True)
def ForbidExternalProcessesAndNetwork(monkeypatch):
    """Make accidental subprocesses, downloads or asynchronous providers fail immediately."""

    def Forbidden(*arguments, **options):
        """Refuse external behavior in this explicitly inert contract selection."""

        raise AssertionError("Provisioning contracts must not launch or acquire anything")

    for module, attribute in ((subprocess, "Popen"), (subprocess, "run"),
                              (asyncio, "create_subprocess_exec"), (urllib.request, "urlopen")):
        monkeypatch.setattr(module, attribute, Forbidden)


def ZipBytes(entries):
    """Serialize small synthetic stored members without claiming official archive provenance."""

    output = io.BytesIO()

    with ZipFile(output, "w", compression=ZIP_STORED) as archive:
        for name, raw in entries:
            if "\\" in name:
                # Bypass constructor normalization so the hostile raw name reaches admission.
                member = ZipInfo("inert")
                member.filename = member.orig_filename = name
                archive.writestr(member, raw)

            else:
                archive.writestr(name, raw)

    return output.getvalue()


def Material(tmp_path, monkeypatch, *, raw=None):
    """Explicitly replace only the official archive check with labeled inert fixture identity."""

    archive = tmp_path / "inert-not-official.zip"
    archive.write_bytes(raw if raw is not None else ZipBytes([
        ("README.md", b"inert release documentation\n"), ("nuclei", INERT_EXECUTABLE),
    ]))
    template = tmp_path / "candidate.yaml"
    template.write_bytes((REPOSITORY / "labs/external/benchmark/templates/"
                         "prometheus-exposition.yaml").read_bytes())
    configuration = tmp_path / "operator-config.yaml"
    configuration.write_bytes(EMPTY_CONFIG)
    identity = {**RegularIdentity(archive, maximum=provisioning.ARCHIVE_BYTES),
                "basis": "inert substituted archive check; not official acquisition"}

    def InertArchive(selected):
        """Return the fixture's observed identity without fabricating a pinned release hash."""

        assert selected == archive, "Only the explicitly supplied inert archive may be selected."

        return identity

    monkeypatch.setattr(provisioning, "VerifyArchive", InertArchive)

    return archive, template, configuration, tmp_path / "new-material", identity


@LINUX_MATERIALIZATION
def test_MaterialRetainsSeparateArchiveAndExtractedIdentities(tmp_path, monkeypatch):
    """Extract only nuclei, copy exact profile bytes, and leave genuine prerequisites unrun."""

    archive, template, configuration, destination, identity = Material(tmp_path, monkeypatch)
    result = provisioning.PrepareMaterial(archive, template, configuration, destination)
    assert result["archive"] == identity, "Inert provenance must remain explicitly labeled."
    assert result["executable"]["sha256"] == hashlib.sha256(INERT_EXECUTABLE).hexdigest(), (
        "The executable hash must come from actual extracted bytes, not the archive pin."
    )
    assert result["archive"]["sha256"] != result["executable"]["sha256"], (
        "Archive and executable identities must remain separate observed facts."
    )
    assert {path.name for path in destination.iterdir()} == {
        "nuclei", "prometheus-exposition.yaml", "operator-config.yaml",
    }, "Release documentation and other ZIP members must never be extracted."
    assert (destination / "nuclei").read_bytes() == INERT_EXECUTABLE, (
        "The inert executable member must survive extraction byte for byte."
    )
    assert stat.S_IMODE((destination / "nuclei").stat().st_mode) == 0o500, (
        "Successfully copied executable material must be private and read-only."
    )
    assert stat.S_IMODE((destination / "operator-config.yaml").stat().st_mode) == 0o400, (
        "Operator configuration must be private and read-only."
    )
    assert result["profile"] == ProfileDocument(destination / "prometheus-exposition.yaml",
                                                destination / "operator-config.yaml"), (
        "The copied profile must pass the original exact-byte preflight."
    )
    assert [item["crc_verified"] for item in result["release_inventory"]] == [False, True], (
        "Only the fully read executable member may claim CRC verification."
    )
    assert result["version_probe"] == result["go_template_validation"] == "not-run", (
        "Source fixture extraction must never masquerade as genuine engine validation."
    )
    assert "immutability unproven" in result["material_basis"], (
        "Local mode bits cannot prove a later read-only image or root ownership."
    )


@pytest.mark.parametrize("name", ["../nuclei", "/nuclei", "a/../nuclei", "a//nuclei",
    "./nuclei", "a\\nuclei", "C:nuclei", "a\nnuclei", "a\x7fnuclei", "nuclei/"],
    ids=["parent", "absolute", "nested-parent", "empty-part", "dot", "backslash", "drive",
         "control", "delete", "directory"])
def test_ZipInventoryRejectsUntrustedPathSpellings(name):
    """Reject unsafe paths even though only the exact root executable would be extracted."""

    with ZipFile(io.BytesIO(ZipBytes([(name, b"inert")]))) as archive:
        assert archive.infolist()[0].orig_filename == name, (
            "The invalid-path fixture must retain its original unnormalized archive spelling")

        with pytest.raises(ValueError, match="regular file members"):
            provisioning.RegularMembers(archive, maximum_members=32, maximum_bytes=1024)


@pytest.mark.parametrize("name, allowed", [("a\\nuclei", False), ("a/nuclei", True)],
    ids=["raw-backslash", "canonical-slash"])
def test_ZipPathFixturesPreserveRawNamesBeforeStrictInventory(name, allowed):
    """Retain raw hostile separators across ZIP writers while a canonical file remains readable."""

    payload = b"inert stored bytes"
    raw = ZipBytes([(name, payload)])
    assert raw.count(name.encode("ascii")) == 2, (
        "Both local header and central directory must retain the exact selected raw filename")

    with ZipFile(io.BytesIO(raw)) as archive:
        member = archive.infolist()[0]
        assert member.orig_filename == name, (
            "The ZIP reader must expose the exact original name before platform normalization")

        if allowed:
            members = provisioning.RegularMembers(archive, maximum_members=1, maximum_bytes=32)
            assert set(members) == {name} and member.filename == name, (
                "A canonical slash path must remain one exact admitted regular file")
            assert archive.read(members[name]) == payload, (
                "The safe control must retain a valid readable ZIP member and its complete bytes")

        else:
            with pytest.raises(ValueError, match="regular file members"):
                provisioning.RegularMembers(archive, maximum_members=1, maximum_bytes=32)


@pytest.mark.parametrize("field,value", [
    ("external_attr", (stat.S_IFLNK | 0o777) << 16),
    ("external_attr", (stat.S_IFCHR | 0o600) << 16),
    ("external_attr", 0x10),
    ("flag_bits", 1), ("compress_type", 99), ("file_size", 1025),
    ("compress_size", 1025), ("file_size", 1000), ("orig_filename", "nuclei\x00alias"),
], ids=["symlink", "device", "dos-directory", "encrypted", "compression", "size",
        "compressed-size", "ratio", "nul-alias"])
def test_ZipInventoryRejectsInvalidMetadata(field, value):
    """Exercise ZIP metadata refusal without creating or executing hostile external material."""

    with ZipFile(io.BytesIO(ZipBytes([("nuclei", b"x")]))) as archive:
        setattr(archive.infolist()[0], field, value)

        with pytest.raises(ValueError, match="regular file members"):
            provisioning.RegularMembers(archive, maximum_members=32, maximum_bytes=1024)


def test_ZipInventoryRejectsDuplicatesCountAndAggregateBounds():
    """Do not silently choose among duplicate members or ignore finite expanded budgets."""

    with pytest.warns(UserWarning, match="Duplicate name"):
        duplicate = ZipBytes([("nuclei", b"a"), ("nuclei", b"b")])

    for raw, count, budget in ((duplicate, 32, 1024),
                               (ZipBytes([]), 32, 1024),
                               (ZipBytes([("nuclei", b"a"), ("doc", b"b")]), 1, 1024),
                               (ZipBytes([("nuclei", b"aa"), ("doc", b"bb")]), 32, 3)):
        with ZipFile(io.BytesIO(raw)) as archive:
            with pytest.raises(ValueError):
                provisioning.RegularMembers(archive, maximum_members=count, maximum_bytes=budget)


@LINUX_MATERIALIZATION
@pytest.mark.parametrize("entries", [[("nested/nuclei", b"inert")], [("nuclei", b"")]],
                         ids=["missing", "empty"])
def test_MaterialRejectsMissingExecutableBeforeCreatingDestination(tmp_path, monkeypatch, entries):
    """An ordinary ZIP without a nonempty exact root nuclei member is not provisioned material."""

    arguments = Material(tmp_path, monkeypatch, raw=ZipBytes(entries))

    with pytest.raises(ValueError, match="root executable"):
        provisioning.PrepareMaterial(*arguments[:4])

    assert not arguments[3].exists(), "Missing executable must refuse before output creation."


@LINUX_MATERIALIZATION
def test_MaterialBindsExtractionToVerifiedSnapshot(tmp_path, monkeypatch):
    """Replacing the archive path after snapshot cannot change the bytes being extracted."""

    arguments = Material(tmp_path, monkeypatch)
    original = provisioning.IdentityBytes

    def Snapshot(path, identity, *, maximum):
        """Replace the mutable path only after capturing the correctly identified fixture bytes."""

        raw = original(path, identity, maximum=maximum)
        path.write_bytes(b"replaced path is not a ZIP")

        return raw

    monkeypatch.setattr(provisioning, "IdentityBytes", Snapshot)
    result = provisioning.PrepareMaterial(*arguments[:4])
    assert result["executable"]["sha256"] == hashlib.sha256(INERT_EXECUTABLE).hexdigest(), (
        "ZIP parsing must consume the verified snapshot instead of reopening its pathname."
    )


@LINUX_MATERIALIZATION
def test_MaterialRejectsChangedArchiveBeforeParsing(tmp_path, monkeypatch):
    """A stale identity cannot authorize an unchecked replacement archive at the same path."""

    arguments = Material(tmp_path, monkeypatch)
    arguments[0].write_bytes(ZipBytes([("nuclei", b"different inert bytes")]))

    with pytest.raises(ValueError, match="changed after its identity"):
        provisioning.PrepareMaterial(*arguments[:4])

    assert not arguments[3].exists(), "Changed archive bytes must refuse before extraction."


@LINUX_MATERIALIZATION
def test_MaterialRejectsCrcFailureAndRemovesPartialExecutable(tmp_path, monkeypatch):
    """A corrupt selected member must not leave a usable executable or success manifest."""

    raw = ZipBytes([("nuclei", INERT_EXECUTABLE)])
    corrupt = raw.replace(INERT_EXECUTABLE, b"x" * len(INERT_EXECUTABLE), 1)
    arguments = Material(tmp_path, monkeypatch, raw=corrupt)

    with pytest.raises(BadZipFile, match="CRC"):
        provisioning.PrepareMaterial(*arguments[:4])

    assert not (arguments[3] / "nuclei").exists(), (
        "An extraction that fails CRC must remove its own partial executable."
    )


@LINUX_MATERIALIZATION
def test_MaterialRejectsChangedCopiedProfile(tmp_path, monkeypatch):
    """Copying cannot convert a changed source template into accepted reviewed bytes."""

    arguments = Material(tmp_path, monkeypatch)

    def Profile(template, configuration):
        """Change the source only after the first real profile preflight has completed."""

        result = ProfileDocument(template, configuration)

        if template == arguments[1]:
            template.write_bytes(b"changed")

        return result

    monkeypatch.setattr(provisioning, "ProfileDocument", Profile)

    with pytest.raises(ValueError, match="exact reviewed"):
        provisioning.PrepareMaterial(*arguments[:4])

    assert not (arguments[3] / "nuclei").exists(), (
        "A failed copied-profile check must not leave accepted executable material."
    )


def WheelMaterial(tmp_path, monkeypatch):
    """Build labeled inert source/wheel/directory bytes while replacing installed-import proof."""

    source = tmp_path / "source" / "fuzzy1337"
    installed = tmp_path / "installed" / "site-packages" / "fuzzy1337"
    files = {"__init__.py": b"inert package\n", "data/example.json": b"{}\n"}

    for name in MODULES:
        relative = name.replace(".", "/") + ("/__init__.py" if name == "executors" else ".py")
        files[relative] = ("inert " + name + "\n").encode()

    for root in (source, installed):
        for name, raw in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    wheel = tmp_path / "inert-not-installed.whl"
    wheel.write_bytes(ZipBytes([("fuzzy1337/" + name, raw) for name, raw in files.items()]))
    inventory = {"basis": "inert substituted installed preflight; no package imported",
        "source_revision": "a" * 40, "package_path": str(installed),
        "wheel": RegularIdentity(wheel, maximum=provisioning.MAX_FILE_BYTES),
        "module_sha256": {name: hashlib.sha256(files[name.replace(".", "/") + (
            "/__init__.py" if name == "executors" else ".py")]).hexdigest() for name in MODULES}}

    def InertInstalled(revision, selected_wheel):
        """Keep replaced runtime origin checks visibly distinct from genuine installation."""

        assert revision == "a" * 40 and selected_wheel == wheel, (
            "Only the explicit inert fixture revision and wheel may enter this contract."
        )

        return inventory

    monkeypatch.setattr(provisioning, "InstalledInventory", InertInstalled)

    return ("a" * 40, wheel, source), installed, files, inventory


def test_WheelInventoryBindsAllPackageBytesWithExplicitCoverage(tmp_path, monkeypatch):
    """Compare source, wheel and installed-directory bytes without claiming actual imports."""

    arguments, installed, files, _ = WheelMaterial(tmp_path, monkeypatch)
    generated = installed / "__pycache__" / "generated.pyc"
    generated.parent.mkdir()
    generated.write_bytes(b"ignored generated bytecode")
    result = provisioning.InstalledSourceInventory(*arguments)
    assert set(result["package_files"]) == set(files), (
        "The inventory must cover all first-party package files, including package data."
    )
    assert result["installed"]["basis"].startswith("inert substituted"), (
        "A replaced installed-import preflight must remain labeled as inert fixture evidence."
    )
    assert result["coverage"] == {
        "package_content": "all ordinary fuzzy1337 files", "actual_import_modules": list(MODULES),
        "excluded_generated": ["__pycache__/**", "*.pyc"],
        "excluded_content": ["distribution metadata", "dependencies"],
    }, "Content coverage and selected import coverage must remain separately explicit."
    assert "host clean-commit check required" in result["source_revision_basis"], (
        "Byte comparison cannot independently attest to the caller's clean Git revision."
    )


@pytest.mark.parametrize("failure", ["source-bytes", "installed-bytes", "wheel-bytes",
    "source-extra", "installed-extra", "wheel-extra", "wheel-missing", "import-hash",
    "wheel-replaced", "symlink"], ids=["source", "installed", "wheel", "source-extra",
    "installed-extra", "wheel-extra", "wheel-missing", "import", "snapshot", "link"])
def test_WheelInventoryRejectsContentAndOriginMismatch(tmp_path, monkeypatch, failure):
    """Matching path spellings cannot hide changed bytes, missing files or a fake import hash."""

    arguments, installed, files, inventory = WheelMaterial(tmp_path, monkeypatch)
    _, wheel, source = arguments

    if failure in {"source-bytes", "installed-bytes"}:
        ((source if failure == "source-bytes" else installed) / "__init__.py").write_bytes(b"bad")

    elif failure in {"source-extra", "installed-extra"}:
        ((source if failure == "source-extra" else installed) / "extra.py").write_bytes(b"extra")

    elif failure in {"wheel-bytes", "wheel-extra", "wheel-missing", "wheel-replaced"}:
        changed = dict(files)

        if failure in {"wheel-bytes", "wheel-replaced"}:
            changed["__init__.py"] = b"changed wheel package"

        elif failure == "wheel-extra":
            changed["extra.py"] = b"extra"

        else:
            del changed["__init__.py"]

        wheel.write_bytes(ZipBytes([("fuzzy1337/" + name, raw) for name, raw in changed.items()]))

        if failure != "wheel-replaced":
            inventory["wheel"] = RegularIdentity(wheel, maximum=provisioning.MAX_FILE_BYTES)

    elif failure == "import-hash":
        inventory["module_sha256"][MODULES[0]] = "0" * 64

    else:
        (source / "alias.py").symlink_to(source / "__init__.py")

    with pytest.raises(ValueError):
        provisioning.InstalledSourceInventory(*arguments)


def test_RealInstalledPreflightRefusesSourceCheckout(tmp_path):
    """Successful inert byte comparisons cannot replace the genuine isolated origin gate."""

    with pytest.raises(ValueError, match="isolated current-wheel"):
        provisioning.InstalledSourceInventory("a" * 40, tmp_path / "absent.whl",
                                              REPOSITORY / "src/fuzzy1337")


@pytest.mark.parametrize("limit", ["MAX_WHEEL_MEMBERS", "MAX_PACKAGE_BYTES", "MAX_PACKAGE_ENTRIES"],
                         ids=["files", "bytes", "entries"])
def test_PackageInventoryEnforcesFiniteTraversalAndContentBounds(tmp_path, monkeypatch, limit):
    """Stop oversized source inventories during traversal rather than eagerly sorting all paths."""

    package = tmp_path / "fuzzy1337"
    package.mkdir()
    (package / "__init__.py").write_bytes(b"inert initializer\n")
    (package / "other.py").write_bytes(b"inert module\n")
    monkeypatch.setattr(provisioning, limit, 1)

    with pytest.raises(ValueError, match="finite"):
        provisioning.PackageFiles(package)


@pytest.mark.parametrize("platform", ["win32", "darwin"], ids=["windows", "macos"])
def test_MaterializationRefusesUnsupportedPlatformBeforeInputOrOutput(
    tmp_path, monkeypatch, platform,
):
    """Unsupported platform identifiers refuse before any material input read or directory write."""

    def Forbidden(*arguments, **options):
        """Make reaching the first material read an explicit preflight contract failure."""

        raise AssertionError("Unsupported materialization must refuse before input reads")

    monkeypatch.setattr(provisioning.sys, "platform", platform)
    monkeypatch.setattr(provisioning, "VerifyArchive", Forbidden)

    with pytest.raises(ValueError, match="requires Linux file-mode semantics"):
        provisioning.PrepareMaterial(tmp_path / "absent.zip", tmp_path / "absent.yaml",
                                     tmp_path / "absent-config.yaml", tmp_path / "absent-output")

    assert list(tmp_path.iterdir()) == [], (
        "Unsupported platform refusal must not create a material workspace or output files."
    )


@LINUX_MATERIALIZATION
def test_MaterialCleanupFailurePreservesOriginalRefusal(tmp_path, monkeypatch):
    """An owned unlink failure annotates the primary profile refusal instead of replacing it."""

    arguments = Material(tmp_path, monkeypatch)
    original_unlink = Path.unlink

    def Profile(template, configuration):
        """Refuse only the copied profile after executable extraction and chmod completed."""

        if template.parent == arguments[3]:
            raise ValueError("inert primary copied-profile refusal")

        return ProfileDocument(template, configuration)

    def Unlink(path, *arguments_for_unlink, **options):
        """Simulate a cleanup denial only for this fixture's owned partial executable."""

        if path == arguments[3] / "nuclei":
            raise PermissionError("inert owned-file cleanup denial")

        return original_unlink(path, *arguments_for_unlink, **options)

    monkeypatch.setattr(provisioning, "ProfileDocument", Profile)
    monkeypatch.setattr(Path, "unlink", Unlink)

    with pytest.raises(ValueError, match="primary copied-profile refusal") as captured:
        provisioning.PrepareMaterial(*arguments[:4])

    assert captured.value.__notes__ == [
        "Nuclei partial executable cleanup failed: PermissionError; destination remains unaccepted",
    ], "Cleanup refusal must remain visible on the original error without inventing success."
    assert (arguments[3] / "nuclei").exists(), (
        "This inert denied cleanup deliberately leaves unaccepted material for diagnosis."
    )


@pytest.mark.parametrize("system,attribute", [(0, 0), (0, 0o600 << 16), (3, 0o600 << 16),
    (3, (stat.S_IFREG | 0o644) << 16)],
    ids=["dos-empty", "dos-default", "unix-default", "unix-file"])
def test_ZipInventoryAcceptsOrdinaryDefaultFileModes(system, attribute):
    """DOS and Unix default ZipInfo permissions do not falsely require Unix type bits."""

    with ZipFile(io.BytesIO(ZipBytes([("nuclei", b"inert")]))) as archive:
        member = archive.infolist()[0]
        member.create_system = system
        member.external_attr = attribute
        members = provisioning.RegularMembers(archive, maximum_members=1, maximum_bytes=16)

    assert set(members) == {"nuclei"}, (
        "Ordinary default ZIP modes must remain portable byte metadata."
    )


@pytest.mark.parametrize("system,attribute", [(0, 0x10), (3, 0),
    (3, (stat.S_IFDIR | 0o755) << 16 | 0x10)], ids=["dos-directory", "default", "unix-directory"])
def test_WheelZipInventoryAcceptsSafeEmptyDirectoryRecords(system, attribute):
    """Validate and count optional wheel directory records while returning file content only."""

    raw = ZipBytes([("fuzzy1337/", b""), ("fuzzy1337/__init__.py", b"x")])

    with ZipFile(io.BytesIO(raw)) as archive:
        directory = archive.infolist()[0]
        directory.create_system = system
        directory.external_attr = attribute
        members = provisioning.RegularMembers(archive, maximum_members=2, maximum_bytes=1,
                                              allow_directories=True)

        with pytest.raises(ValueError, match="finite member budget"):
            provisioning.RegularMembers(archive, maximum_members=1, maximum_bytes=1,
                                        allow_directories=True)

    assert set(members) == {"fuzzy1337/__init__.py"}, (
        "Safe empty directories must be validated without becoming package content files."
    )


@pytest.mark.parametrize("name,payload,mode", [("../", b"", 0), ("pkg/", b"x", 0),
    ("pkg/", b"", stat.S_IFLNK << 16), ("pkg/", b"", stat.S_IFREG << 16)],
    ids=["parent", "nonempty", "link", "conflicting-file"])
def test_WheelZipInventoryRejectsUnsafeDirectoryRecords(name, payload, mode):
    """Wheel-only directory allowance never admits path escapes, content or conflicting types."""

    with ZipFile(io.BytesIO(ZipBytes([(name, payload)]))) as archive:
        archive.infolist()[0].external_attr = mode

        with pytest.raises(ValueError, match="regular file members"):
            provisioning.RegularMembers(archive, maximum_members=2, maximum_bytes=16,
                                        allow_directories=True)


def test_WheelZipInventoryRejectsCanonicalFileDirectoryCollision():
    """A trailing directory separator cannot hide a file/directory identity collision."""

    with ZipFile(io.BytesIO(ZipBytes([("pkg/", b""), ("pkg", b"file")]))) as archive:
        with pytest.raises(ValueError, match="unique bounded"):
            provisioning.RegularMembers(archive, maximum_members=2, maximum_bytes=16,
                                        allow_directories=True)


def test_WheelByteInventoryAcceptsValidatedDirectoryRecords(tmp_path, monkeypatch):
    """Legitimate wheel directory entries do not change the complete package-file byte inventory."""

    arguments, _, files, inventory = WheelMaterial(tmp_path, monkeypatch)
    wheel = arguments[1]
    entries = [("fuzzy1337/", b""), ("fuzzy1337/data/", b"")]
    entries.extend(("fuzzy1337/" + name, raw) for name, raw in files.items())
    wheel.write_bytes(ZipBytes(entries))
    inventory["wheel"] = RegularIdentity(wheel, maximum=provisioning.MAX_FILE_BYTES)
    result = provisioning.InstalledSourceInventory(*arguments)
    assert set(result["package_files"]) == set(files), (
        "Directory records must not be mistaken for extra package content or imported proof."
    )
