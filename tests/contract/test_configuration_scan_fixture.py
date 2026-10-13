# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent portable configuration wire checks, without SDK registration or ingestion claims."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import traceback
from pathlib import Path
from types import SimpleNamespace

import pytest

REPOSITORY_ROOT = Path(__file__).parents[2]
CORPUS = REPOSITORY_ROOT / "tests/contract/fixtures/configuration_profiles"
PRODUCER = REPOSITORY_ROOT / "tests/fixtures/configuration_scan/producer.py"
ORACLE = json.loads((CORPUS / "oracle.v1.json").read_bytes())
CASES = {case["case_id"]: case for case in ORACLE["cases"]}
PRIVATE = "SYNTHETIC_PRIVATE_CONFIG_FAILURE_VALUE"


def Module():
    """Load only the owned producer for direct adversarial metadata/decoder probes."""

    spec = importlib.util.spec_from_file_location("owned_configuration_fixture", PRODUCER)
    assert spec is not None and spec.loader is not None, "Owned producer must be importable."
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def Stage(root: Path, case_id: str = "dockerfile.root-user") -> tuple[Path, Path]:
    """Copy the exact independent fixture and worker into one selected synthetic test stage."""

    case = CASES[case_id]
    selected = case["inputs"][0]

    for name in ("input", "scanner", "material", "scratch"):
        (root / name).mkdir(parents=True)

    source = root / "input" / selected["logical_path"]
    source.write_bytes((CORPUS / selected["fixture"]).read_bytes())
    (root / "scanner/producer.py").write_bytes(PRODUCER.read_bytes())
    policy = root / "material/policy.json"
    policy.write_bytes(json.dumps({
        "schema_version": 1, "fixture_id": "owned-synthetic-configuration-wire-v1",
        "provider_version": "0.75.0-synthetic", "profile_id": case["profile_id"],
        "case_id": case_id,
    }, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())

    return source, policy


def Arguments(source: Path, policy: Path) -> tuple[str, ...]:
    """Declare exact config argv independently of the producer implementation."""

    root = source.parent.parent
    scanner = "dockerfile" if source.name == "Dockerfile" else "kubernetes"

    return ("--fixture-policy", str(policy), "--cache-dir", str(root / "scratch/cache"),
            "--config=", "config", "--misconfig-scanners", scanner, "--cache-backend", "memory",
            "--format", "json", "--disable-telemetry", "--skip-check-update",
            "--skip-version-check", "--ignorefile=", "--exit-code", "0", "--timeout", "1s",
            str(root / "input"))


def Run(root: Path, arguments: tuple[str, ...], *, cwd: Path | None = None):
    """Run only the staged owned worker using isolated stdlib CPython with bounded process IO."""

    environment = {"SYSTEMROOT": os.environ["SYSTEMROOT"]} if "SYSTEMROOT" in os.environ else {}

    return subprocess.run(
        (sys.executable, "-I", "-S", str(root / "scanner/producer.py"), *arguments),
        cwd=cwd or root / "scratch", env=environment, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=5, check=False,
    )


def Refused(result):
    """Require atomic sanitized refusal rather than a partial or empty successful specimen."""

    assert result.returncode == 64 and result.stdout == b"", (
        "Unsupported policy/profile/source must refuse atomically with no JSON proposal."
    )
    assert result.stderr == (
        b"Owned synthetic configuration fixture rejected its profile or inputs.\n"
    ), "Refusal must contain only one fixed sanitized message, without private values or paths."


def Metadata(value, **changes):
    """Copy observed stat facts while changing only named adversarial identity fields."""

    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns",
              "st_ctime_ns", "st_birthtime_ns", "st_file_attributes", "st_reparse_tag")
    copied = {field: getattr(value, field, None if field == "st_birthtime_ns" else 0)
              for field in fields}
    copied.update(changes)

    return SimpleNamespace(**copied)


@pytest.mark.parametrize("case_id", list(CASES), ids=list(CASES))
def test_RealIsolatedWireMatchesIndependentFiveCaseOracle(tmp_path, case_id):
    """Compare actual selected-byte interpretation to every unchanged oracle coordinate."""

    root = tmp_path / "owned config workspace"
    source, policy = Stage(root, case_id)
    result = Run(root, Arguments(source, policy))
    assert result.returncode == 0 and result.stderr == b"", "Known fixture must yield its wire."
    assert len(result.stdout) <= 16 * 1024, "Output must retain its declared finite byte limit."
    wire = json.loads(result.stdout)
    assert set(wire) == {"schema_version", "provider_id", "provider_version", "fixture_id",
                         "profile_id", "case_id", "scan_completeness", "file_outcomes",
                         "findings"}, (
        "The result must expose only the exact reviewed wire fields."
    )
    assert type(wire["schema_version"]) is int and wire["schema_version"] == 1, (
        "The owned result wire uses exact integer schema version one."
    )
    assert wire["provider_id"] == "synthetic.trivy" and (
        wire["provider_version"] == "0.75.0-synthetic"
        and wire["fixture_id"] == "owned-synthetic-configuration-wire-v1"
        and wire["case_id"] == case_id and wire["profile_id"] == CASES[case_id]["profile_id"]
    ), "Fixture source/profile/version/case must remain explicit, never native."
    assert wire["scan_completeness"] == "not-assessed", "No fixture becomes a clean-scan claim."
    expected = [dict(item, outcome="failed") for item in CASES[case_id]["expected_findings"]]
    assert wire["findings"] == expected, "Finding coordinates must match the independent oracle."
    document_count = None if source.name == "Dockerfile" else (
        2 if case_id == "kubernetes.second-document" else 1
    )
    assert wire["file_outcomes"] == [{
        "logical_path": source.name, "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "size_bytes": source.stat().st_size,
        "configuration_type": "dockerfile" if source.name == "Dockerfile" else "kubernetes",
        "document_count": document_count, "outcome": "processed",
    }], "Each selected file must have its actual byte identity and explicit processed outcome."
    assert ORACLE["raw_only_marker"].encode() not in result.stdout and (
        str(root).encode() not in result.stdout and b"owned.invalid" not in result.stdout
    ), "Raw source comments, image hints and physical locations must not escape into the wire."
    assert result.stdout == json.dumps(wire, sort_keys=True, separators=(",", ":"),
                                       allow_nan=False).encode() + b"\n", (
        "Successful wire bytes must be canonical finite JSON."
    )


@pytest.mark.parametrize("change", ["added-flag", "wrong-command", "wrong-scanner",
    "disk-cache", "wrong-cache-path", "wrong-input-path", "wrong-policy-path", "zero-timeout",
    "large-timeout", "float-timeout", "leading-zero-timeout", "version-operation"])
def test_ExactProfileRejectsFlagPathAndDeadlineChanges(tmp_path, change):
    """Refuse caller-selected deviations without arbitrary flags or finding proposals."""

    root = tmp_path / change
    source, policy = Stage(root)
    arguments = list(Arguments(source, policy))

    if change == "added-flag":
        arguments.append("--quiet")

    elif change == "wrong-command":
        arguments[5] = "image"

    elif change == "wrong-scanner":
        arguments[7] = "terraform"

    elif change == "disk-cache":
        arguments[9] = "fs"

    elif change == "wrong-cache-path":
        arguments[3] = str(root / PRIVATE)

    elif change == "wrong-input-path":
        arguments[-1] = str(root / PRIVATE)

    elif change == "wrong-policy-path":
        arguments[1] = str(root / "material" / PRIVATE)

    elif change == "version-operation":
        arguments = ["--fixture-policy", str(policy), "--version", "--format", "json"]

    else:
        arguments[19] = {"zero-timeout": "0s", "large-timeout": "61s",
                         "float-timeout": "1.0s", "leading-zero-timeout": "01s"}[change]

    Refused(Run(root, tuple(arguments)))


def test_ProfilePolicyAndCwdMustAgreeWithActualSelection(tmp_path):
    """A different valid profile or selected-set mismatch cannot produce success."""

    root = tmp_path / "profile mismatch"
    source, policy = Stage(root)
    arguments = list(Arguments(source, policy))
    arguments[7] = "kubernetes"
    Refused(Run(root, tuple(arguments)))
    Refused(Run(root, Arguments(source, policy), cwd=root))
    source.rename(source.with_name("dockerfile"))
    Refused(Run(root, Arguments(source, policy)))


@pytest.mark.parametrize("change", ["boolean-schema", "floating-schema", "wrong-version",
    "wrong-family", "wrong-profile", "unknown-case", "case-type", "profile-type", "extra-field",
    "missing-field", "duplicate-field", "nan", "infinity", "large-integer", "deep", "utf8",
    "surrogate-value", "surrogate-key", "large-policy", "top-array", "syntax"])
def test_PolicyAmbiguityAndUnsupportedDataHaveSanitizedAtomicRefusal(tmp_path, change):
    """Bound hostile JSON parsing across Python versions and keep private values out of stderr."""

    root = tmp_path / change
    source, policy = Stage(root)
    value = json.loads(policy.read_bytes())
    changed_fields = {
        "boolean-schema": ("schema_version", True), "floating-schema": ("schema_version", 1.0),
        "wrong-version": ("provider_version", PRIVATE), "wrong-family": ("fixture_id", PRIVATE),
        "wrong-profile": ("profile_id", PRIVATE), "unknown-case": ("case_id", PRIVATE),
        "case-type": ("case_id", False), "profile-type": ("profile_id", []),
        "extra-field": (PRIVATE, PRIVATE), "surrogate-value": ("case_id", "\ud800"),
        "surrogate-key": ("\ud800", PRIVATE),
    }

    if change in changed_fields:
        key, replacement = changed_fields[change]
        value[key] = replacement
        raw = json.dumps(value).encode()

    elif change == "missing-field":
        del value["case_id"]
        raw = json.dumps(value).encode()

    else:
        raw = {
            "duplicate-field": ('{"' + PRIVATE + '":1,"' + PRIVATE + '":2}').encode(),
            "nan": b'{"schema_version":NaN}', "infinity": b'{"schema_version":1e999}',
            "large-integer": b'{"schema_version":' + b"9" * 100 + b"}",
            "deep": b"[" * 18 + b"0" + b"]" * 18, "utf8": b"\xff", "top-array": b"[]",
            "large-policy": b" " * 1025, "syntax": b'{"' + PRIVATE.encode() + b'":',
        }[change]

    policy.write_bytes(raw)
    Refused(Run(root, Arguments(source, policy)))


@pytest.mark.parametrize("change", ["comment", "large-source", "wrong-case-bytes", "extra-file",
    "extra-directory", "control-file", "extra-material", "missing-source", "directory-source",
    "hardlink"])
def test_SelectedSetAndCorpusBytesCannotSilentlyExpand(tmp_path, change):
    """Unsupported data and ambient files never produce processed or clean-looking output."""

    root = tmp_path / change
    source, policy = Stage(root)

    if change == "comment":
        source.write_bytes(source.read_bytes() + PRIVATE.encode())

    elif change == "large-source":
        source.write_bytes(b"X" * 4097)

    elif change == "wrong-case-bytes":
        source.write_bytes((CORPUS / "dockerfile/safe/Dockerfile").read_bytes())

    elif change == "extra-file":
        (root / "input" / PRIVATE).write_text(PRIVATE)

    elif change == "extra-directory":
        (root / "input" / PRIVATE).mkdir()

    elif change == "control-file":
        (root / "input/.trivyignore").write_text(PRIVATE)

    elif change == "extra-material":
        (root / "material" / PRIVATE).write_text(PRIVATE)

    elif change == "missing-source":
        source.unlink()

    elif change == "directory-source":
        source.unlink()
        source.mkdir()

    else:
        os.link(source, root / PRIVATE)

    Refused(Run(root, Arguments(source, policy)))


@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_size", "st_mtime_ns", "st_mode"])
def test_PathHandleCommonIdentityMismatchAlwaysRejects(tmp_path, field):
    """The Windows ctime exception must not remove object/type/size/mtime binding."""

    path = tmp_path / "owned metadata"
    path.write_bytes(b"owned")
    module = Module()
    metadata = path.stat()
    replacement = stat.S_IFDIR if field == "st_mode" else getattr(metadata, field) + 1

    with pytest.raises(ValueError):
        module.BindHandle(metadata, Metadata(metadata, **{field: replacement}))


@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_size", "st_mtime_ns"])
def test_MissingCommonIdentityRefusesRatherThanWeakeningTrust(tmp_path, field):
    """Zero/unavailable disk identity fields cannot be silently accepted."""

    path = tmp_path / "owned metadata"
    path.write_bytes(b"owned")
    module = Module()

    with pytest.raises(ValueError):
        module.Regular(Metadata(path.stat(), **{field: 0}))


def test_WindowsCrossMethodCtimeExceptionRetainsFullSameMethodFacts(tmp_path, monkeypatch):
    """Model the documented API difference without relaxing stable before/after change identity."""

    path = tmp_path / "owned metadata"
    path.write_bytes(b"owned")
    module = Module()
    metadata = path.stat()
    different_ctime = Metadata(metadata, st_ctime_ns=metadata.st_ctime_ns + 100)
    monkeypatch.setattr(module, "IS_WINDOWS", True)
    module.BindHandle(metadata, different_ctime)
    assert module.Identity(metadata) != module.Identity(different_ctime), (
        "Same-method before/after ctime changes must remain part of the full identity."
    )
    monkeypatch.setattr(module, "IS_WINDOWS", False)

    with pytest.raises(ValueError):
        module.BindHandle(metadata, different_ctime)


def test_ReparseAndHardlinkMetadataStayFailClosed(tmp_path):
    """An observed NTFS reparse flag cannot evade POSIX-independent regular-file guards."""

    path = tmp_path / "owned metadata"
    path.write_bytes(b"owned")
    module = Module()

    for changed in (Metadata(path.stat(), st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT),
                    Metadata(path.stat(), st_reparse_tag=1), Metadata(path.stat(), st_nlink=2)):
        with pytest.raises(ValueError):
            module.Regular(changed)


@pytest.mark.parametrize("phase", ["handle", "path"])
def test_SameMethodReadMutationFailsDespiteCrossMethodCtimeException(tmp_path, monkeypatch, phase):
    """Retain the complete path-before/after and handle-before/after checks on Windows."""

    path = tmp_path / "owned bytes"
    path.write_bytes(b"owned")
    module = Module()
    monkeypatch.setattr(module, "IS_WINDOWS", True)

    if phase == "handle":
        original = os.fstat
        count = 0

        def ChangedHandle(descriptor):
            """Return changed ctime only on the second same-handle metadata observation."""

            nonlocal count
            count += 1
            result = original(descriptor)

            return Metadata(result, st_ctime_ns=result.st_ctime_ns + 100) if count == 2 else result

        monkeypatch.setattr(module.os, "fstat", ChangedHandle)

    else:
        original = Path.lstat
        count = 0

        def ChangedPath(selected):
            """Return changed ctime only on the second selected-file path observation."""

            nonlocal count
            result = original(selected)

            if selected == path:
                count += 1

                if count == 2:
                    return Metadata(result, st_ctime_ns=result.st_ctime_ns + 100)

            return result

        monkeypatch.setattr(Path, "lstat", ChangedPath)

    with pytest.raises(ValueError, match="changed while reading"):
        module.ReadFile(path, 20)


def test_JsonExceptionTracebacksDoNotReflectRejectedPrivateValues():
    """Suppress decoder causes that contain the private source document."""

    module = Module()
    raw = ('{"' + PRIVATE + '":1,"' + PRIVATE + '":2}').encode()

    try:
        module.Policy(raw)

    except ValueError as error:
        assert PRIVATE not in "".join(traceback.format_exception(error)), (
            "Full decoder traceback must contain no private source values."
        )

    else:
        pytest.fail("Duplicate private fields must be refused by the bounded decoder.")


def test_EveryAdmittedSourceAndProducerRetainsPinnedHashesAndLfWithoutGit():
    """Require six independently pinned byte/LF contracts on every runtime runner."""

    pinned = {
        "dockerfile/unsafe/Dockerfile":
            "3f0114052cfa7d826abf315fededac339851d4c1991b5c2447bfdf01882323b7",
        "dockerfile/safe/Dockerfile":
            "1712d2480103b5881b6df078d5471d12a2c9e0d1d7f6cb96270aa7751943231c",
        "kubernetes/unsafe.yaml":
            "63b77e1703ab126b9f5283daa5091f750af8ddab3e3b8e24eed63ea36888dd1d",
        "kubernetes/safe.yaml":
            "52e45b63f8aec99934dcfddd90d1f3b417111ccabe4514c262e3e8cf443f729f",
        "kubernetes/multi.yaml":
            "8cd7163a754dc1a0c29ce1e54fc29cb68a5a0a2b71c79d03a3c54d9caf363b1f",
    }
    selected = [(CORPUS / path, digest) for path, digest in pinned.items()]
    selected.append((PRODUCER,
        "af34b374fa49ce3048d3a7821df5ad8370849240a786dabc7311e14322476eb6"))
    assert set(pinned) == {case["inputs"][0]["fixture"] for case in CASES.values()}, (
        "Independent byte pins must cover exactly every admitted input fixture."
    )

    for path, digest in selected:
        raw = path.read_bytes()

        assert hashlib.sha256(raw).hexdigest() == digest and b"\r" not in raw, (
            "Each admitted corpus/worker source must retain its exact reviewed LF byte hash."
        )


def test_WindowsCheckoutPreservesEveryAdmittedSourceAndProducerByte(tmp_path):
    """Simulate CRLF checkout configuration using only the six explicit owned index paths."""

    paths = [str((CORPUS / case["inputs"][0]["fixture"]).relative_to(REPOSITORY_ROOT))
             for case in CASES.values()]
    paths.append(str(PRODUCER.relative_to(REPOSITORY_ROOT)))
    destination = tmp_path / "simulated windows checkout"
    destination.mkdir()
    git = shutil.which("git")

    if git is None:
        pytest.skip("Git checkout simulation requires Git; byte/hash/LF checks run separately.")

    attributes = (REPOSITORY_ROOT / ".gitattributes").read_text().splitlines()

    for path in paths:
        assert path.replace("\\", "/") + " text eol=lf" in attributes, (
            "Every source-hashed corpus/worker file must keep its exact narrow LF attribute."
        )

    subprocess.run([git, "-c", "core.autocrlf=true", "-c", "core.eol=crlf", "checkout-index",
                    "--prefix=" + destination.as_posix() + "/", "--", *paths],
                   cwd=REPOSITORY_ROOT, capture_output=True, check=True)

    for path in paths:
        assert (destination / path).read_bytes() == (REPOSITORY_ROOT / path).read_bytes(), (
            "Each exact source-hashed corpus/worker file must keep LF bytes under Windows settings."
        )
