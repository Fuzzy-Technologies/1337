# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded native configuration report interpretation without execution or model authority."""

from __future__ import annotations

import re
from dataclasses import dataclass

from fuzzy1337.adapters.trivy import ParseJson
from fuzzy1337.artifact_inputs import ArtifactManifest, ArtifactProfile
from fuzzy1337.native_configuration import ConfigurationManifest, NativeConfigurationSelection

MAX_CONFIGURATION_STDOUT_BYTES = 1024 * 1024
MAX_CONFIGURATION_STDERR_BYTES = 64 * 1024
MAX_CONFIGURATION_RECEIPT_BYTES = 256 * 1024
NATIVE_CONFIGURATION_FAMILY = "native-configuration-v1"
NATIVE_CONFIGURATION_ROLES = {
    "native-configuration-version-stdout": (16 * 1024, "application/json"),
    "native-configuration-version-stderr": (16 * 1024, "text/plain"),
    "native-configuration-version-receipt": (MAX_CONFIGURATION_RECEIPT_BYTES, "application/json"),
    "native-configuration-scan-stdout": (MAX_CONFIGURATION_STDOUT_BYTES, "application/json"),
    "native-configuration-scan-stderr": (MAX_CONFIGURATION_STDERR_BYTES, "text/plain"),
    "native-configuration-scan-receipt": (MAX_CONFIGURATION_RECEIPT_BYTES, "application/json"),
    "native-configuration-source": (4096, "text/plain"),
}


@dataclass(frozen=True, slots=True)
class NativeConfigurationCheck:
    """One provider-attributed check, preserving optional native coordinates without inference."""

    check_id: str
    status: str
    severity: str
    title: str
    description: str
    resolution: str
    start_line: int | None
    end_line: int | None
    resource: str | None


def BoundedText(value: object, maximum: int, field: str, *, empty: bool = False) -> str:
    """Require finite provider text without coercion or silently dropping malformed values.

    Args:
        value: Exact decoded provider value.
        maximum: Maximum Unicode character count.
        field: Diagnostic field name.
        empty: Whether the empty string is admitted.

    Returns:
        The unchanged validated text.
    """

    if type(value) is not str or not (0 if empty else 1) <= len(value) <= maximum or (
        "\x00" in value
    ):
        raise ValueError("Native configuration has invalid " + field)

    return value


def VerifyEmbeddedConfigurationChecks(stderr: bytes) -> tuple[int, int]:
    """Require original positive embedded loader evidence and refuse external check loaders.

    Args:
        stderr: Original bounded SCAN stderr, retained separately from the provider report.

    Returns:
        Positive original embedded library/check counts; not a completeness claim.
    """

    if type(stderr) is not bytes or len(stderr) > MAX_CONFIGURATION_STDERR_BYTES:
        raise ValueError("Native configuration loader evidence exceeds its bound")

    text = stderr.decode("utf-8")

    if any(message in text for message in (
        "Checks from disk are loaded", "Checks from readers are loaded",
        "Overriding filesystem for checks",
    )):
        raise ValueError("Native configuration used an unselected check source")

    counts = []

    for kind in ("libraries", "checks"):
        matches = re.findall(r"Embedded " + kind + r" are loaded[^\n]*\bcount=([1-9][0-9]*)\b",
                             text)

        if not matches or len(matches[-1]) > 9:
            raise ValueError("Native configuration lacks positive embedded " + kind)

        counts.append(int(matches[-1]))

    return counts[0], counts[1]


def ParseNativeConfigurationReport(
    stdout: bytes, stderr: bytes, selection: NativeConfigurationSelection,
    manifest: ArtifactManifest, source: bytes,
) -> tuple[NativeConfigurationCheck, ...]:
    """Validate selected-file processing and native check rows without a synthetic oracle.

    Args:
        stdout: Original schema-two provider report.
        stderr: Original debug loader evidence.
        selection: Declared Dockerfile or already-rendered Kubernetes input selection.
        manifest: Exact captured one-file input manifest.
        source: Exact bounded captured source, used only to validate supplied coordinates.

    Returns:
        All provider check rows, including nonfailures. Only FAIL rows become Findings.
    """

    ConfigurationManifest(selection, manifest)
    VerifyEmbeddedConfigurationChecks(stderr)
    payload = ParseJson(stdout, max_bytes=MAX_CONFIGURATION_STDOUT_BYTES)
    results = payload.get("Results")

    if type(payload.get("SchemaVersion")) is not int or payload["SchemaVersion"] != 2 or (
        type(results) is not list or len(results) != 1 or type(results[0]) is not dict
    ):
        raise ValueError("Native configuration requires exactly one schema-two file result")

    result = results[0]
    expected_type = "dockerfile" if manifest.profile is ArtifactProfile.DOCKERFILE else "kubernetes"
    rows = result.get("Misconfigurations")

    if result.get("Target") != selection.logical_path or result.get("Class") != "config" or (
        result.get("Type") != expected_type or type(rows) is not list or not 1 <= len(rows) <= 2048
    ):
        raise ValueError("Native configuration did not positively process its selected file")

    lines = source.decode("utf-8").splitlines()
    checks = []

    for row in rows:
        if type(row) is not dict:
            raise ValueError("Native configuration check must be an object")

        check_id = BoundedText(row.get("ID"), 128, "check ID")

        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*(?:[._-][A-Za-z0-9]+)*", check_id):
            raise ValueError("Native configuration check ID is not a canonical provider identifier")

        status = row.get("Status")
        severity = row.get("Severity")

        if status not in {"FAIL", "PASS", "EXCEPTION"} or severity not in {
            "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"
        }:
            raise ValueError("Native configuration has unsupported check status or severity")

        title = BoundedText(row.get("Title"), 4096, "check title")
        description = BoundedText(row.get("Description", ""), 16384, "description", empty=True)
        resolution = BoundedText(row.get("Resolution", ""), 4096, "resolution", empty=True)
        cause = row.get("CauseMetadata", {})

        if type(cause) is not dict:
            raise ValueError("Native configuration cause metadata must be an object")

        start = cause.get("StartLine")
        end = cause.get("EndLine")

        if start == 0 and end == 0:
            start, end = None, None

        if (start is None) != (end is None) or start is not None and (
            type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(lines)
        ):
            raise ValueError("Native configuration source coordinates exceed selected source")

        resource = cause.get("Resource")

        if resource is not None:
            resource = BoundedText(resource, 4096, "resource", empty=True)

        checks.append(NativeConfigurationCheck(check_id, status, severity, title, description,
                                                resolution, start, end, resource))

    return tuple(checks)
