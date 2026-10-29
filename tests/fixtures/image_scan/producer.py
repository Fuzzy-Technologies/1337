# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Portable fixed-profile synthetic Trivy wire producer; never executes or scans an image."""

from __future__ import annotations

import hashlib
import json
import re
import stat
import sys
import tarfile
import time
from io import BytesIO
from pathlib import Path

MAX_ARCHIVE_BYTES = 128 * 1024
MAX_MEMBER_BYTES = 16 * 1024
PROVIDER_VERSION = "0.75.0-synthetic"
DATABASE_METADATA = {
    "Version": 2,
    "UpdatedAt": "2026-10-01T00:00:00Z",
    "NextUpdate": "2026-10-02T00:00:00Z",
    "DownloadedAt": "2026-10-01T01:00:00Z",
}
FIXTURE_ID = "owned-synthetic-image-wire-v1"
SCENARIOS = (
    "success", "no_findings", "provider_error", "malformed", "version_mismatch",
    "package_mismatch", "output_limit", "hold",
)
IMAGE_FLAGS = (
    "--format", "json", "--scanners", "vuln", "--disable-telemetry", "--offline-scan",
    "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--skip-version-check",
    "--skip-vex-repo-update", "--ignorefile=", "--list-all-pkgs", "--exit-code", "0",
    "--no-progress", "--timeout",
)


def JsonBytes(value: object) -> bytes:
    """Emit deterministic complete JSON so raw bytes can be independently preserved."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def ParseJson(raw: bytes) -> object:
    """Reject ambiguous duplicate keys and nonstandard numbers in finite fixture JSON."""

    def Object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Require one interpretation per object field before fixture semantics are checked."""

        result: dict[str, object] = {}

        for key, value in pairs:
            if key in result:
                raise ValueError("fixture JSON must have unique fields")

            result[key] = value

        return result

    def Constant(value: str) -> object:
        """Keep JSON finite instead of admitting parser-specific NaN or infinity spellings."""

        raise ValueError("fixture JSON must contain finite standard values")

    return json.loads(raw, object_pairs_hook=Object, parse_constant=Constant)


def ReadOwnedFile(path: Path, limit: int, root: Path) -> bytes:
    """Read one finite regular non-linked fixture file below the explicitly selected stage root."""

    selected = path if path.is_absolute() else root / path

    if ".." in selected.parts or not selected.is_relative_to(root):
        raise ValueError("fixture input is outside the selected working directory")

    current = root

    for part in selected.relative_to(root).parts:
        current /= part

        if current.is_symlink():
            raise ValueError("fixture inputs cannot use links")

    metadata = selected.stat()

    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("fixture inputs must be owned regular files")

    with selected.open("rb") as source:
        raw = source.read(limit + 1)

    if len(raw) > limit:
        raise ValueError("fixture input exceeds its byte limit")

    return raw


def Version(policy_path: Path, root: Path) -> dict[str, object]:
    """Interpret the exact immutable synthetic policy, without claiming a real database exists."""

    policy = ParseJson(ReadOwnedFile(policy_path, 512, root))
    expected = {"schema_version": 1, "fixture_id": FIXTURE_ID,
                "provider_version": PROVIDER_VERSION, "database_metadata": DATABASE_METADATA}

    if not isinstance(policy, dict) or policy != expected or (
        type(policy["schema_version"]) is not int
        or type(policy["database_metadata"]["Version"]) is not int
    ):
        raise ValueError("fixture material does not match the closed synthetic profile")

    return {"Version": PROVIDER_VERSION, "VulnerabilityDB": policy["database_metadata"],
            "Fixture": "synthetic; no Trivy binary or vulnerability database"}


def Image(archive_path: Path, root: Path) -> tuple[dict[str, object], str]:
    """Inspect finite fixture members in memory without extracting or executing scenario data."""

    raw = ReadOwnedFile(archive_path, MAX_ARCHIVE_BYTES, root)
    members: dict[str, bytes] = {}

    with tarfile.open(fileobj=BytesIO(raw), mode="r:") as archive:
        for member in archive:
            allowed_name = member.name in {
                "manifest.json", "oci-manifest.json", "1337-fixture.json",
            } or re.fullmatch(r"[a-f0-9]{64}(?:\.json|/layer\.tar)", member.name)

            if not allowed_name or len(members) >= 5 or member.name in members or (
                not member.isfile()
            ) or (
                member.size < 0 or member.size > MAX_MEMBER_BYTES
            ):
                raise ValueError("fixture archive has unsupported members")

            stream = archive.extractfile(member)

            if stream is None:
                raise ValueError("fixture member has no bytes")

            with stream:
                members[member.name] = stream.read(MAX_MEMBER_BYTES + 1)

    docker_manifest = ParseJson(members["manifest.json"])

    if not isinstance(docker_manifest, list) or len(docker_manifest) != 1:
        raise ValueError("fixture has exactly one image")

    image = docker_manifest[0]
    config_name = image["Config"]
    layers = image["Layers"]

    if not re.fullmatch(r"[a-f0-9]{64}\.json", config_name) or len(layers) != 1 or (
        not re.fullmatch(r"[a-f0-9]{64}/layer\.tar", layers[0])
    ) or set(members) != {
        "manifest.json", config_name, layers[0], "oci-manifest.json", "1337-fixture.json",
    }:
        raise ValueError("fixture members differ from the closed image profile")

    scenario = ParseJson(members["1337-fixture.json"])

    if not isinstance(scenario, dict) or set(scenario) != {"scenario"} or (
        scenario["scenario"] not in SCENARIOS
    ):
        raise ValueError("fixture scenario must be an enumerated inert value")

    config_digest = "sha256:" + hashlib.sha256(members[config_name]).hexdigest()
    layer_digest = "sha256:" + hashlib.sha256(members[layers[0]]).hexdigest()
    manifest_digest = "sha256:" + hashlib.sha256(members["oci-manifest.json"]).hexdigest()
    metadata = {"ImageID": config_digest, "OS": {"Family": "alpine", "Name": "3.20"},
                "RepoDigests": ["owned.invalid/synthetic@" + manifest_digest],
                "DiffIDs": [layer_digest]}

    return metadata, scenario["scenario"]


def Main(arguments: list[str] | None = None) -> int:
    """Accept only the pinned profile wire; unknown flags cannot change fixture behavior."""

    arguments = sys.argv[1:] if arguments is None else arguments

    try:
        if len(arguments) < 4 or arguments[0] != "--fixture-policy":
            raise ValueError("unsupported fixture profile")

        policy = Path(arguments[1])
        arguments = arguments[2:]

        if not policy.is_absolute() or policy.name != "policy.json" or (
            policy.parent.name != "material" or ".." in policy.parts
        ):
            raise ValueError("fixture requires the fixed material policy path")

        root = policy.parent.parent

        if not Path.cwd().is_relative_to(root / "scratch"):
            raise ValueError("fixture cwd must remain under the declared scratch partition")

        if arguments[0] != "--cache-dir":
            raise ValueError("unsupported fixture profile")

        cache = Path(arguments[1])

        if cache != root / "scratch" / "cache":
            raise ValueError("fixture requires the fixed disposable memory-cache path")

        if arguments == ["--cache-dir", str(cache), "--config=", "--version", "--format", "json"]:
            sys.stdout.buffer.write(JsonBytes(Version(policy, root)) + b"\n")

            return 0

        if len(arguments) != 9 + len(IMAGE_FLAGS) or arguments[2:7] != [
            "--config=", "image", "--cache-backend", "memory", "--input",
        ] or tuple(arguments[8:-1]) != IMAGE_FLAGS or (
            not re.fullmatch(r"[1-9][0-9]?s", arguments[-1])
            or int(arguments[-1][:-1]) > 60
        ):
            raise ValueError("unsupported fixture profile")

        Version(policy, root)
        image_path = Path(arguments[7])

        if image_path != root / "input" / "image.tar":
            raise ValueError("fixture requires the exact declared image input name")

        metadata, scenario = Image(image_path, root)
        package = {"ID": "owned-1", "Name": "Owned_Lib", "Version": "1.0",
                   "Identifier": {"PURL": "pkg:pypi/owned-lib@1.0"}, "Licenses": ["MIT"]}
        vulnerability = {"VulnerabilityID": "CVE-2099-0001", "PkgID": "owned-1",
                         "PkgName": "Owned_Lib", "InstalledVersion": "1.0",
                         "FixedVersion": "2.0", "Severity": "HIGH"}

        if scenario == "package_mismatch":
            vulnerability["PkgID"] = "not-an-installed-package"

        payload = {"SchemaVersion": 2, "ArtifactType": "container_image",
                   "ArtifactName": "owned synthetic image fixture", "Metadata": metadata,
                   "Trivy": {"Version": "0.75.1-synthetic" if scenario == "version_mismatch"
                             else PROVIDER_VERSION},
                   "Results": [{"Target": "owned synthetic package inventory", "Type": "python-pkg",
                                "Packages": [package], "Vulnerabilities": []
                                if scenario == "no_findings" else [vulnerability]}],
                   "Fixture": "synthetic package/advisory proposals; not Trivy detection"}
        sys.stderr.buffer.write(b"owned synthetic wire producer; no image scan or network\n")
        sys.stderr.buffer.flush()

        if scenario == "hold":
            sys.stdout.buffer.write(b"{")
            sys.stdout.buffer.flush()
            time.sleep(30)

            return 8

        if scenario == "output_limit":
            sys.stdout.buffer.write(b"X" * (4 * 1024 * 1024 + 1))

        elif scenario == "malformed":
            sys.stdout.buffer.write(b'{"SchemaVersion":2')

        else:
            sys.stdout.buffer.write(JsonBytes(payload) + b"\n")

        return 7 if scenario == "provider_error" else 0

    except (OSError, ValueError, KeyError, TypeError, RecursionError, tarfile.TarError):
        sys.stderr.write("Owned synthetic image fixture rejected its inputs/profile.\n")

        return 64


if __name__ == "__main__":
    raise SystemExit(Main())
