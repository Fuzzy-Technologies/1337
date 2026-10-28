# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Preflight and independent projection contracts; no scanner or container execution."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import re
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit

from .external_native_runner import MAX_FILE_BYTES, StrictJson

VERSION = "3.4.10"
UPSTREAM_REVISION = "5bff7a2a90965a0ed8b03f2ff557f3220624dd57"
ARCHIVE_NAME = "nuclei_3.4.10_linux_amd64.zip"
ARCHIVE_BYTES = 33657343
ARCHIVE_SHA256 = "234c12cc5288af071abdcd6f854245b6067345556e1235cf96b76725c1004357"
TEMPLATE_ID = "fuzzy1337-prometheus-process-exposition"
TEMPLATE_BYTES = 1215
TEMPLATE_SHA256 = "dff3e6ea0821ba769cf63575ad685b8c1def939ed24f790f42d2fde924d55c74"
TEMPLATE_SOURCE_REVISION = "ca73fb44606a40301db3a3d466235094aafad4c7"
TEMPLATE_REVIEW = ("ADR0106:accepted-proposal-sha256:"
                   "cdc0a17fa4b8710fd1d4db9bae606582448d863c6d03a28451fb299ae60859e2")
EMPTY_CONFIG = b"{}\n"
CONFIG_SHA256 = "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"
PATHS = ("/metrics", "/rest/admin/application-version", "/")
TRACKS = ("whole1337", "external-nuclei")
MODULES = ("adapters.nuclei", "nucleiscan", "executors", "evidence", "findings", "model")
STDOUT_BYTES = 4 * 1024 * 1024
STDERR_BYTES = 64 * 1024
PROVIDER_TIMEOUT_SECONDS = 3
WRAPPER_TIMEOUT_SECONDS = 8
MAX_LINE_BYTES = 128 * 1024
MAX_RECORDS = 4096
ATTEMPT_BASIS = "approved-single-configured-nuclei-invocation"


def ExactUrl(path: str) -> str:
    """Select one unchanged pinned application's loopback input without URL inference."""

    if path not in PATHS:
        raise ValueError("Nuclei comparison accepts only the three exact case paths")

    return "http://127.0.0.1:3000" + path


def RegularIdentity(path: Path, *, maximum: int, executable: bool = False) -> dict:
    """Hash a singly linked ordinary file without following observed path aliases."""

    if not path.is_absolute() or any(part == ".." for part in path.parts):
        raise ValueError("Nuclei material requires an absolute ordinary path")

    for component in (*reversed(path.parents), path):
        metadata = component.lstat()

        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("Nuclei material cannot traverse symbolic links")

    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or (
        not 0 < metadata.st_size <= maximum
        or executable and not metadata.st_mode & 0o111
    ):
        raise ValueError("Nuclei material must be a singly linked bounded regular file")

    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)

    if len(raw) != metadata.st_size or len(raw) > maximum:
        raise ValueError("Nuclei material changed or exceeded its byte budget")

    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}


def VerifyArchive(path: Path) -> dict:
    """Verify acquired official archive bytes independently of its extracted executable."""

    identity = RegularIdentity(path, maximum=ARCHIVE_BYTES)

    if path.name != ARCHIVE_NAME or identity["size_bytes"] != ARCHIVE_BYTES or (
        identity["sha256"] != ARCHIVE_SHA256
    ):
        raise ValueError("Nuclei archive differs from the pinned official amd64 asset")

    return identity


def VerifyBinary(path: Path, expected_sha256: str, observed_version: str) -> dict:
    """Require a separately acquired executable hash and exact bounded-probe version."""

    if re.fullmatch("[a-f0-9]{64}", expected_sha256) is None or observed_version != VERSION:
        raise ValueError("Nuclei comparison requires an acquired binary digest and exact 3.4.10")

    identity = RegularIdentity(path, maximum=128 * 1024 * 1024, executable=True)

    if identity["sha256"] != expected_sha256:
        raise ValueError("Nuclei extracted executable differs from its acquired identity")

    return {**identity, "version": observed_version}


def ProfileDocument(template: Path, configuration: Path) -> dict:
    """Build the actual reviewed one-template profile only after verifying local bytes."""

    rule = RegularIdentity(template, maximum=TEMPLATE_BYTES)
    config = RegularIdentity(configuration, maximum=len(EMPTY_CONFIG))

    if rule["sha256"] != TEMPLATE_SHA256 or rule["size_bytes"] != TEMPLATE_BYTES or (
        config["sha256"] != CONFIG_SHA256 or config["size_bytes"] != len(EMPTY_CONFIG)
        or template == configuration
    ):
        raise ValueError("Nuclei comparison requires exact reviewed rule and empty config bytes")

    return {"profile_id": "external-juice-shop-prometheus-v1", "templates": [{
        "template_id": TEMPLATE_ID, "path": str(template), "sha256": TEMPLATE_SHA256,
        "size_bytes": TEMPLATE_BYTES,
        "source_reference": "https://github.com/Fuzzy-Technologies/1337/blob/"
                            + TEMPLATE_SOURCE_REVISION
                            + "/labs/external/benchmark/templates/prometheus-exposition.yaml",
        "source_revision": TEMPLATE_SOURCE_REVISION, "review_reference": TEMPLATE_REVIEW,
        "reviewed_profile": "single-get-exact-url",
    }], "configuration_path": str(configuration)}


def StandaloneArguments(executable: Path, path: str, template: Path,
                        configuration: Path) -> tuple[str, ...]:
    """Construct standalone detection flags directly, without a planner or product adapter."""

    for artifact in (executable, template, configuration):
        if not artifact.is_absolute() or any(part == ".." for part in artifact.parts) or (
            any(character.isspace() or character in ",\\" for character in str(artifact))
        ):
            raise ValueError("Nuclei argv requires unambiguous absolute artifact paths")

    if len({executable, template, configuration}) != 3:
        raise ValueError("Nuclei executable, template and config cannot alias")

    return (str(executable), "-u", ExactUrl(path), "-config", str(configuration),
            "-pt", "http", "-jsonl", "-silent", "-nc", "-omit-raw", "-omit-template",
            "-duc", "-ni", "-dr", "-no-stdin", "-nh", "-dc", "-rl", "1", "-bs", "1",
            "-c", "1", "-retries", "0", "-mhe", "1", "-timeout", "3", "-rsr",
            "1048576", "-rss", "1048576", "-t", str(template))


def ProjectStandaloneMatches(raw: bytes) -> list[dict]:
    """Project explicit raw HTTP identities independently, preserving unknown/off-case matches."""

    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("Nuclei original stdout exceeds the 2 MiB per-file ceiling")

    lines = raw.splitlines()

    if len(lines) > MAX_RECORDS:
        raise ValueError("Nuclei raw output exceeds the finite record budget")

    findings = []

    for line in lines:
        if len(line) > MAX_LINE_BYTES:
            raise ValueError("Nuclei raw output exceeds the finite line budget")

        record = StrictJson(line)

        if not isinstance(record, dict) or record.get("type") != "http" or (
            type(record.get("template-id")) is not str or not record["template-id"]
            or type(record.get("matched-at")) is not str or not record["matched-at"]
            or "matcher-status" in record and record["matcher-status"] is not True
        ):
            raise ValueError("Nuclei raw output requires explicit HTTP match identities")

        matched = record["matched-at"]

        try:
            parsed = urlsplit(matched)
            port = parsed.port

        except ValueError as error:
            raise ValueError("Nuclei raw match has an invalid explicit HTTP URL") from error

        if parsed.scheme != "http" or not parsed.hostname or (
            parsed.username is not None or parsed.password is not None
            or port is not None and not 1 <= port <= 65535
            or any(character.isspace() or ord(character) < 32 or ord(character) == 127
                   for character in matched)
        ):
            raise ValueError("Nuclei raw match requires an explicit HTTP input identity")

        findings.append({"rule_id": record["template-id"], "path": parsed.path,
                         "target_url": matched})

    return findings


def AttemptProvenance(path: str) -> dict:
    """Describe one configured invocation while explicitly leaving actual contacts unknown."""

    return {"basis": ATTEMPT_BASIS, "approved_attempt_count": 1,
            "independent_server_contact_count": None,
            "configured_requests": [{"method": "GET", "url": ExactUrl(path)}]}


def InstalledInventory(source_revision: str, wheel: Path) -> dict:
    """Require isolated imports from the installed current wheel, without invoking a provider."""

    import fuzzy1337

    package = Path(fuzzy1337.__file__).parent

    if not sys.flags.isolated or not package.is_relative_to("/opt/benchmark-runtime") or (
        "site-packages" not in package.parts
        or re.fullmatch("[a-f0-9]{40}", source_revision) is None
    ):
        raise ValueError("Nuclei whole1337 requires isolated current-wheel installed imports")

    modules = {}

    for name in MODULES:
        module = importlib.import_module("fuzzy1337." + name)
        path = Path(module.__file__)

        if not path.is_relative_to(package):
            raise ValueError("Nuclei module escaped the installed package")

        modules[name] = RegularIdentity(path, maximum=MAX_FILE_BYTES)["sha256"]

    return {"source_revision": source_revision, "package_path": str(package),
            "distribution_version": importlib.metadata.version("1337"),
            "module_sha256": modules, "wheel": RegularIdentity(wheel, maximum=MAX_FILE_BYTES),
            "runner_sha256": RegularIdentity(Path(__file__), maximum=MAX_FILE_BYTES)["sha256"]}
