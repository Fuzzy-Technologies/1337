# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded standalone configuration fixture wire; never scans arbitrary Dockerfile/YAML."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

FIXTURE_ID = "owned-synthetic-configuration-wire-v1"
PROVIDER_VERSION = "0.75.0-synthetic"
MAX_POLICY_BYTES = 1024
MAX_SOURCE_BYTES = 4096
MAX_OUTPUT_BYTES = 16 * 1024
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 1024
IS_WINDOWS = sys.platform == "win32"
REFUSAL = b"Owned synthetic configuration fixture rejected its profile or inputs.\n"
CASES = {
    "dockerfile.root-user": (
        "dockerfile", "Dockerfile", 264,
        "3f0114052cfa7d826abf315fededac339851d4c1991b5c2447bfdf01882323b7",
    ),
    "dockerfile.non-root-user": (
        "dockerfile", "Dockerfile", 271,
        "1712d2480103b5881b6df078d5471d12a2c9e0d1d7f6cb96270aa7751943231c",
    ),
    "kubernetes.privileged-container": (
        "kubernetes", "unsafe.yaml", 410,
        "63b77e1703ab126b9f5283daa5091f750af8ddab3e3b8e24eed63ea36888dd1d",
    ),
    "kubernetes.non-privileged-container": (
        "kubernetes", "safe.yaml", 409,
        "52e45b63f8aec99934dcfddd90d1f3b417111ccabe4514c262e3e8cf443f729f",
    ),
    "kubernetes.second-document": (
        "kubernetes", "multi.yaml", 823,
        "8cd7163a754dc1a0c29ce1e54fc29cb68a5a0a2b71c79d03a3c54d9caf363b1f",
    ),
}


def Policy(raw: bytes) -> tuple[str, str, str, int, str]:
    """Decode one finite non-executable policy without leaking rejected source text."""

    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_POLICY_BYTES:
        raise ValueError("configuration policy exceeds its byte/type bounds")

    def Object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Require unique JSON fields before schema interpretation."""

        result: dict[str, object] = {}

        for key, value in pairs:
            if key in result:
                raise ValueError("configuration policy has duplicate fields")

            result[key] = value

        return result

    def Integer(text: str) -> int:
        """Bound integer conversion identically on every supported Python version."""

        if len(text) > 10:
            raise ValueError("configuration policy integer exceeds its bound")

        return int(text)

    def NonInteger(text: str) -> object:
        """Refuse floats and nonstandard constants without reflecting their text."""

        raise ValueError("configuration policy requires finite bounded integers")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=Object, parse_int=Integer,
                           parse_float=NonInteger, parse_constant=NonInteger)
        stack = [(value, 0)]
        nodes = 0

        while stack:
            item, depth = stack.pop()
            nodes += 1

            if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
                raise ValueError("configuration policy exceeds structural bounds")

            if isinstance(item, str):
                item.encode("utf-8")

            elif isinstance(item, dict):
                stack.extend((key, depth + 1) for key in item)
                stack.extend((child, depth + 1) for child in item.values())

            elif isinstance(item, list):
                stack.extend((child, depth + 1) for child in item)

    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ValueError("configuration policy JSON is invalid or exceeds its bounds") from None

    if not isinstance(value, dict) or set(value) != {
        "schema_version", "fixture_id", "provider_version", "profile_id", "case_id",
    } or type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("configuration policy requires the exact owned schema")

    if any(type(value[key]) is not str for key in (
        "fixture_id", "provider_version", "profile_id", "case_id",
    )) or value["fixture_id"] != FIXTURE_ID or value["provider_version"] != PROVIDER_VERSION:
        raise ValueError("configuration policy requires the exact owned family/version")

    case_id = value["case_id"]

    if case_id not in CASES:
        raise ValueError("configuration policy case is unsupported")

    scanner, name, size, sha256 = CASES[case_id]

    if value["profile_id"] != f"synthetic.{scanner}-offline.v1":
        raise ValueError("configuration policy profile differs from the selected case")

    return case_id, scanner, name, size, sha256


def Reparse(metadata: os.stat_result) -> bool:
    """Detect observed Windows reparse metadata without interpreting a linked target."""

    return bool(getattr(metadata, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
                or getattr(metadata, "st_reparse_tag", 0))


def Identity(metadata: os.stat_result) -> tuple[object, ...]:
    """Keep complete same-method physical change facts except read-driven access time."""

    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
            metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns,
            getattr(metadata, "st_birthtime_ns", None), getattr(metadata, "st_file_attributes", 0),
            getattr(metadata, "st_reparse_tag", 0))


def Regular(metadata: os.stat_result) -> None:
    """Require a non-linked finite disk file with observable common identity fields."""

    if not stat.S_ISREG(metadata.st_mode) or Reparse(metadata) or metadata.st_nlink != 1 or (
        metadata.st_size <= 0 or any(value == 0 for value in (
            metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns,
        ))
    ):
        raise ValueError("configuration input requires an observed regular unlinked file")


def BindHandle(path_metadata: os.stat_result, handle_metadata: os.stat_result) -> None:
    """Bind path to open handle, excluding only Windows' cross-method ctime semantics."""

    Regular(path_metadata)
    Regular(handle_metadata)
    path_common = (path_metadata.st_dev, path_metadata.st_ino,
                   stat.S_IFMT(path_metadata.st_mode), path_metadata.st_size,
                   path_metadata.st_mtime_ns)
    handle_common = (handle_metadata.st_dev, handle_metadata.st_ino,
                     stat.S_IFMT(handle_metadata.st_mode), handle_metadata.st_size,
                     handle_metadata.st_mtime_ns)

    if path_common != handle_common or (
        not IS_WINDOWS and path_metadata.st_ctime_ns != handle_metadata.st_ctime_ns
    ):
        raise ValueError("configuration file handle differs from the selected path")


def Directory(path: Path) -> None:
    """Reject observed links/reparse points throughout the selected directory ancestry."""

    for selected in (*reversed(path.parents), path):
        metadata = selected.lstat()

        if not stat.S_ISDIR(metadata.st_mode) or Reparse(metadata):
            raise ValueError("configuration stage directories cannot be linked")


def SingleEntry(directory: Path, expected: str) -> None:
    """Bound enumeration to two entries and require one exact declared flat file."""

    Directory(directory)
    count = 0

    with os.scandir(directory) as entries:
        for entry in entries:
            count += 1

            if count > 1 or entry.name != expected:
                raise ValueError("configuration selection contains undeclared entries")

    if count != 1:
        raise ValueError("configuration selection requires one explicit file")


def ReadFile(path: Path, limit: int) -> bytes:
    """Read bounded bytes while preserving path/handle and before/after identity guards."""

    Directory(path.parent)
    before_path = path.lstat()
    Regular(before_path)

    if before_path.st_size > limit:
        raise ValueError("configuration input exceeds its byte bound")

    with path.open("rb") as source:
        before_handle = os.fstat(source.fileno())
        BindHandle(before_path, before_handle)
        raw = source.read(limit + 1)
        after_handle = os.fstat(source.fileno())
        Regular(after_handle)

        if Identity(before_handle) != Identity(after_handle):
            raise ValueError("configuration file changed while reading its handle")

    after_path = path.lstat()
    BindHandle(after_path, after_handle)

    if Identity(before_path) != Identity(after_path) or len(raw) != before_path.st_size or (
        len(raw) > limit
    ):
        raise ValueError("configuration file changed while reading its selected path")

    return raw


def Findings(raw: bytes, scanner: str, name: str) -> tuple[int | None, list[dict[str, object]]]:
    """Interpret only finite admitted USER/privileged fixture lines and document separators."""

    lines = raw.decode("utf-8").splitlines()

    if len(lines) > 64 or any(len(line) > 256 for line in lines):
        raise ValueError("configuration source text exceeds its structural bounds")

    findings = []
    document_index = 0

    for line_number, line in enumerate(lines, start=1):
        if line == "---":
            document_index += 1

        failed = line == "USER root" if scanner == "dockerfile" else (
            line.strip() == "privileged: true"
        )

        if failed:
            findings.append({
                "logical_path": name,
                "check_id": "synthetic.configuration.dockerfile-root-user"
                if scanner == "dockerfile" else "synthetic.configuration.privileged-container",
                "severity": "HIGH", "outcome": "failed",
                "start_line": line_number, "end_line": line_number,
                "document_index": None if scanner == "dockerfile" else document_index,
                "resource_selector": "instruction:USER" if scanner == "dockerfile" else
                "/spec/containers/0/securityContext/privileged",
            })

    if document_index > 1 or len(findings) > 1:
        raise ValueError("configuration source exceeds its supported fixture shape")

    return None if scanner == "dockerfile" else document_index + 1, findings


def Result(arguments: list[str]) -> bytes:
    """Validate the complete fixed wire and input before proposing one atomic JSON specimen."""

    if len(arguments) != 21 or arguments[0] != "--fixture-policy":
        raise ValueError("configuration invocation requires its exact fixed argv")

    policy = Path(arguments[1])

    if not policy.is_absolute() or ".." in policy.parts or policy.name != "policy.json" or (
        policy.parent.name != "material"
    ):
        raise ValueError("configuration policy requires the exact declared material path")

    root = policy.parent.parent
    scanner, deadline = arguments[7], arguments[19]

    if scanner not in {"dockerfile", "kubernetes"} or not re.fullmatch(
        r"(?:[1-9]|[1-5][0-9]|60)s", deadline,
    ):
        raise ValueError("configuration scanner/deadline is outside its closed profile")

    expected = ["--fixture-policy", str(policy), "--cache-dir", str(root / "scratch/cache"),
        "--config=", "config", "--misconfig-scanners", scanner, "--cache-backend", "memory",
        "--format", "json", "--disable-telemetry", "--skip-check-update", "--skip-version-check",
        "--ignorefile=", "--exit-code", "0", "--timeout", deadline, str(root / "input")]

    if arguments != expected or not Path.cwd().is_relative_to(root / "scratch"):
        raise ValueError("configuration invocation differs from its fixed stage/profile")

    Directory(root / "scratch")
    SingleEntry(root / "material", "policy.json")
    case_id, declared_scanner, name, size, expected_sha256 = Policy(
        ReadFile(policy, MAX_POLICY_BYTES),
    )

    if scanner != declared_scanner:
        raise ValueError("configuration scanner differs from its selected policy")

    SingleEntry(root / "input", name)
    raw = ReadFile(root / "input" / name, MAX_SOURCE_BYTES)
    sha256 = hashlib.sha256(raw).hexdigest()

    if len(raw) != size or sha256 != expected_sha256:
        raise ValueError("configuration source is outside the reviewed fixture corpus")

    document_count, findings = Findings(raw, scanner, name)
    result = {
        "schema_version": 1, "provider_id": "synthetic.trivy", "provider_version": PROVIDER_VERSION,
        "fixture_id": FIXTURE_ID, "profile_id": f"synthetic.{scanner}-offline.v1",
        "case_id": case_id, "scan_completeness": "not-assessed",
        "file_outcomes": [{"logical_path": name, "sha256": sha256, "size_bytes": len(raw),
                           "configuration_type": scanner, "document_count": document_count,
                           "outcome": "processed"}],
        "findings": findings,
    }
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

    if len(encoded) + 1 > MAX_OUTPUT_BYTES:
        raise ValueError("configuration result exceeds its byte bound")

    return encoded + b"\n"


def Main(arguments: list[str] | None = None) -> int:
    """Emit the complete owned specimen or one sanitized refusal, never partial success."""

    try:
        encoded = Result(sys.argv[1:] if arguments is None else arguments)

    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        sys.stderr.buffer.write(REFUSAL)

        return 64

    sys.stdout.buffer.write(encoded)

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
