# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Optional offline Trivy archive scans through governed SDK and evidence contracts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from fuzzy1337.adapters import (
    AdapterDescriptor,
    AdapterHealth,
    AdapterHealthState,
    AdapterInvocation,
    AdapterReport,
    AdapterRequest,
    AdapterResult,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
    NormalizedFinding,
    NormalizedObservation,
)
from fuzzy1337.adapters.contracts import RequireText

TRIVY_ADAPTER_VERSION = "1"
TRIVY_HEALTH_TIMEOUT_SECONDS = 3
TRIVY_HEALTH_MAX_BYTES = 16 * 1024
TRIVY_JSON_MAX_BYTES = 4 * 1024 * 1024
TRIVY_JSON_MAX_NODES = 65536
TRIVY_JSON_MAX_DEPTH = 32
TRIVY_MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
TRIVY_MAX_TIMEOUT_SECONDS = 3600

__all__ = [
    "TRIVY_ADAPTER_VERSION", "TRIVY_HEALTH_TIMEOUT_SECONDS", "TRIVY_HEALTH_MAX_BYTES",
    "TRIVY_JSON_MAX_BYTES", "TRIVY_JSON_MAX_NODES", "TRIVY_JSON_MAX_DEPTH",
    "TRIVY_MAX_ARCHIVE_BYTES", "TRIVY_MAX_TIMEOUT_SECONDS", "TrivyAdapter",
    "TrivyReportError", "TrivyHealthProbe",
]

_DESCRIPTOR = AdapterDescriptor("native.trivy", "Trivy", TRIVY_ADAPTER_VERSION,
                                ("image.archive-vulnerabilities",), ImpactLevel.SAFE)
_VERSION_PATTERN = re.compile(r"0\.75\.[0-9]+(?:[.+_-][0-9A-Za-z._-]+)?")
_SEVERITIES = frozenset({"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"})


class TrivyReportError(ValueError):
    """Trivy evidence cannot safely produce normalized SDK output."""


@dataclass(frozen=True, slots=True)
class TrivyHealthProbe:
    """Bounded version observation with exact bytes for caller-owned evidence storage.

    Raw bytes may be persisted as provider-version evidence with actual collection
    provenance. Available executable health alone does not establish database health.
    """

    health: AdapterHealth
    stdout: bytes = b""


def ParseJson(raw: bytes, max_bytes: int = TRIVY_JSON_MAX_BYTES) -> dict[str, object]:
    """Parse finite strict JSON without duplicate keys or non-finite scalars.

    Args:
        raw: Verified UTF-8 raw evidence.
        max_bytes: Inclusive byte budget; structural budgets also apply.

    Returns:
        Provider JSON object, without assigning trusted domain semantics.

    Raises:
        TrivyReportError: Encoding, JSON shape, duplicate key or budget fails.
    """

    if len(raw) > max_bytes:
        raise TrivyReportError("Trivy JSON exceeds the byte budget")

    def Object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Reject ambiguous object fields during the JSON parser boundary."""

        value: dict[str, object] = {}

        for key, item in pairs:
            if key in value:
                raise TrivyReportError("Trivy JSON contains duplicate keys")

            value[key] = item

        return value

    def Constant(value: str) -> object:
        """Reject the JSON decoder's nonstandard NaN and infinity spellings."""

        raise TrivyReportError(f"Trivy JSON contains non-finite constant {value}")

    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=Object,
                           parse_constant=Constant)

    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise TrivyReportError("Trivy JSON is malformed, incomplete or not UTF-8") from error

    if not isinstance(value, dict):
        raise TrivyReportError("Trivy JSON must be an object")

    pending = [(value, 1)]
    nodes = 0

    while pending:
        item, depth = pending.pop()
        nodes += 1

        if nodes > TRIVY_JSON_MAX_NODES or depth > TRIVY_JSON_MAX_DEPTH:
            raise TrivyReportError("Trivy JSON exceeds the structural budget")

        if isinstance(item, dict):
            pending.extend((nested, depth + 1) for nested in item.values())

        elif isinstance(item, list):
            pending.extend((nested, depth + 1) for nested in item)

        elif isinstance(item, float) and not (-float("inf") < item < float("inf")):
            raise TrivyReportError("Trivy JSON contains a non-finite number")

    return cast(dict[str, object], value)


def RelativePath(value: object) -> PurePosixPath:
    """Validate portable workspace path syntax without reading mutable filesystem state.

    Args:
        value: Non-secret portable relative path, without traversal or option syntax.

    Returns:
        Validated portable path for deterministic historical invocation reconstruction.

    Raises:
        ValueError: The value is not a permitted finite workspace path.
    """

    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("Trivy paths must be nonempty portable relative paths")

    path = PurePosixPath(value)

    if path.is_absolute() or any(part in {"..", "."} for part in value.split("/")) or (
        ":" in value or value.startswith("-") or "//" in value
    ):
        raise ValueError("Trivy paths must not use traversal, drive names or option syntax")

    return path


def WorkspacePath(root: Path, value: object, directory: bool = False) -> Path:
    """Select existing non-symlink files or directories beneath the trusted workspace.

    Filesystem isolation against concurrent replacement remains the caller's
    responsibility. Historical evidence replay does not read these mutable files.

    Args:
        root: Trusted physical workspace root.
        value: Portable relative path beneath root, without symlinks.
        directory: Require an existing directory instead of a regular input file.

    Returns:
        Existing physical path selected within the workspace.

    Raises:
        ValueError: A path escapes root, uses symlinks or has the wrong file type.
        OSError: A selected path cannot be resolved.
    """

    path = RelativePath(value)
    selected = root

    for part in path.parts:
        selected /= part

        if selected.is_symlink():
            raise ValueError("Trivy paths must not use symbolic links")

    if not selected.resolve(strict=True).is_relative_to(root):
        raise ValueError("Trivy paths must remain below the workspace")

    if (directory and not selected.is_dir()) or (not directory and not selected.is_file()):
        raise ValueError("Trivy paths must identify the required file or directory")

    return selected


def ReadEvidence(report: AdapterReport, role: str, reader: Callable[[EvidenceReference], bytes],
                 max_bytes: int) -> bytes:
    """Read exactly one independently bounded immutable raw evidence role.

    Args:
        report: Original executor report and immutable references.
        role: Required unique non-secret evidence role.
        reader: Caller-owned verified evidence reader.
        max_bytes: Inclusive independent capture-size budget.

    Returns:
        Exact bytes matching the reference's SHA-256 and length.

    Raises:
        TrivyReportError: Role cardinality, byte limit or integrity differs.
        OSError: The caller's evidence reader cannot access the stored bytes.
    """

    references = [item for item in report.evidence if item.role == role]

    if len(references) != 1:
        raise TrivyReportError(f"Trivy report requires exactly one {role} evidence reference")

    reference = references[0]

    if reference.size_bytes > max_bytes:
        raise TrivyReportError("Trivy evidence exceeds the byte budget")

    raw = reader(reference)

    if len(raw) != reference.size_bytes or hashlib.sha256(raw).hexdigest() != reference.sha256:
        raise TrivyReportError("Trivy raw bytes differ from their evidence reference")

    return raw


class TrivyAdapter:
    """Experimental offline archive-only adapter; no installation or scan authority.

    The executable and workspace are trusted operator selections. The executor
    bounds time/output; this adapter does not sandbox the binary, archive decoder,
    mutable files, CPU, memory or network. Registry and daemon targets are absent.
    """

    def __init__(self, evidence_reader: Callable[[EvidenceReference], bytes], workspace_root: Path,
                 executable: str = "trivy", provider_version: str | None = None,
                 cache_directory: str = "trivy-cache") -> None:
        """Bind trusted local tool, isolated workspace and pre-provisioned database cache.

        Args:
            evidence_reader: Verified store reader, with no discovery or secret lookup.
            workspace_root: Existing physical directory for archives and cache.
            executable: Operator-owned executable name or absolute path.
            provider_version: Previously observed version, if known.
            cache_directory: Existing workspace-relative offline database/cache directory.

        Raises:
            ValueError: A selection is invalid or uses a symlink.
            OSError: A selected workspace/cache does not exist.
        """

        RequireText(executable, "Trivy executable")

        if provider_version is not None:
            RequireText(provider_version, "Trivy provider version")

            if not _VERSION_PATTERN.fullmatch(provider_version):
                raise ValueError("Trivy supports only the documented 0.75.x CLI envelope")

        if workspace_root.is_symlink() or not workspace_root.is_dir():
            raise ValueError("Trivy workspace must be a physical directory")

        self._root = workspace_root.resolve(strict=True)
        self._cache_relative = cache_directory
        self._cache = WorkspacePath(self._root, cache_directory, directory=True)
        self._read_evidence = evidence_reader
        self._executable = executable
        self._provider_version = provider_version

    @property
    def Descriptor(self) -> AdapterDescriptor:
        """Return immutable SAFE archive metadata without invoking the optional tool.

        Returns:
            Declared capabilities, with no installation or execution authority.
        """

        return _DESCRIPTOR

    def ProbeHealth(self) -> TrivyHealthProbe:
        """Observe version/DB metadata with finite time/capture budgets and exact bytes.

        Returns:
            Available, degraded or unavailable health plus raw version stdout.
            Database metadata is provider-reported, not a database-file attestation.
        """

        executable = shutil.which(self._executable)

        if executable is None:
            return TrivyHealthProbe(AdapterHealth(_DESCRIPTOR.adapter_id,
                AdapterHealthState.UNAVAILABLE, detail="Trivy executable is not available"))

        try:
            process = subprocess.Popen(
                (executable, "--cache-dir", str(self._cache), "--config=",
                 "--version", "--format", "json"), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False, bufsize=0,
                env={},
            )

        except OSError:
            return TrivyHealthProbe(AdapterHealth(_DESCRIPTOR.adapter_id,
                AdapterHealthState.UNAVAILABLE, detail="Trivy version probe could not start"))

        assert process.stdout is not None, "subprocess.PIPE must provide a capture handle"
        pipe = process.stdout
        captured: list[bytes] = []
        capture_failed = threading.Event()

        def Capture() -> None:
            """Drain a finite capture plus one detection byte without unbounded allocation."""

            remaining = TRIVY_HEALTH_MAX_BYTES + 1

            try:
                while remaining:
                    chunk = os.read(pipe.fileno(), min(4096, remaining))

                    if not chunk:
                        break

                    captured.append(chunk)
                    remaining -= len(chunk)

                if not remaining:
                    process.kill()

            except (OSError, ValueError):
                capture_failed.set()

        worker = threading.Thread(target=Capture, daemon=True)
        worker.start()
        timed_out = False

        try:
            process.wait(timeout=TRIVY_HEALTH_TIMEOUT_SECONDS)

        except subprocess.TimeoutExpired:
            timed_out = True

            try:
                process.kill()

            except ProcessLookupError:
                pass

            process.wait()

        worker.join(timeout=0.1)
        pipe.close()
        raw = b"".join(captured)
        detail = "Trivy version probe exceeded a resource budget"

        if not (timed_out or worker.is_alive() or capture_failed.is_set() or
                len(raw) > TRIVY_HEALTH_MAX_BYTES):
            try:
                metadata = ParseJson(raw, TRIVY_HEALTH_MAX_BYTES)
                version = metadata.get("Version")

                if process.returncode == 0 and isinstance(version, str) and (
                    _VERSION_PATTERN.fullmatch(version)
                ):
                    RequireText(version, "Trivy version")

                    return TrivyHealthProbe(AdapterHealth(_DESCRIPTOR.adapter_id,
                        AdapterHealthState.AVAILABLE, version), raw)

            except ValueError:
                pass

            detail = "Trivy version probe failed or returned unrecognized JSON"

        return TrivyHealthProbe(AdapterHealth(_DESCRIPTOR.adapter_id,
            AdapterHealthState.DEGRADED, detail=detail), raw[:TRIVY_HEALTH_MAX_BYTES])

    def CheckHealth(self) -> AdapterHealth:
        """Return bounded executable health without granting scan or update authority.

        Returns:
            Version availability under the bounded local health exception.
        """

        return self.ProbeHealth().health

    def PrepareInvocation(self, request: AdapterRequest) -> AdapterInvocation:
        """Prepare a deterministic offline scan of one approved existing image archive.

        Args:
            request: SAFE image.archive-vulnerabilities request with archive and timeout_seconds.

        Returns:
            Shell-free argv bound separately by exact executor authorization.

        Raises:
            ValueError: Profile, credentials, path, archive size or timeout is unsupported.
            OSError: An operator-selected input/cache is unavailable.
        """

        invocation = self.BuildInvocation(request)
        archive = WorkspacePath(self._root, request.parameters["archive"])

        if archive.stat().st_size > TRIVY_MAX_ARCHIVE_BYTES:
            raise ValueError("Trivy archive exceeds the input byte budget")

        WorkspacePath(self._root, self._cache_relative, directory=True)

        return invocation

    def BuildInvocation(self, request: AdapterRequest) -> AdapterInvocation:
        """Reconstruct internal finite metadata without requiring historical input files.

        Args:
            request: Recorded or approved request with the exact supported profile.

        Returns:
            Deterministic invocation metadata for preparation or archived evidence replay.

        Raises:
            ValueError: Version, capability, impact, parameters or timeout is unsupported.
        """

        if self._provider_version is None:
            raise ValueError("Trivy scanning requires a previously observed 0.75.x version")

        if not _DESCRIPTOR.Supports(request.capability) or request.impact is not ImpactLevel.SAFE:
            raise ValueError("Trivy requires the archive capability with SAFE impact")

        if request.credential_references or set(request.parameters) != {
            "archive", "timeout_seconds"
        }:
            raise ValueError("Trivy accepts only archive and timeout_seconds, without credentials")

        archive = self._root / RelativePath(request.parameters["archive"])
        timeout = request.parameters["timeout_seconds"]

        if isinstance(timeout, bool) or not isinstance(timeout, int) or not (
            1 <= timeout <= TRIVY_MAX_TIMEOUT_SECONDS
        ):
            raise ValueError("Trivy timeout_seconds must be an integer from 1 through 3600")

        argv = (self._executable, "--cache-dir", str(self._cache), "--config=",
            "image", "--input", str(archive), "--format", "json", "--scanners", "vuln",
            "--disable-telemetry", "--offline-scan", "--skip-db-update",
            "--skip-java-db-update", "--skip-check-update",
            "--skip-version-check", "--skip-vex-repo-update", "--ignorefile=",
            "--list-all-pkgs", "--exit-code", "0", "--no-progress", "--timeout", f"{timeout}s")

        return AdapterInvocation(_DESCRIPTOR.adapter_id, request, argv, timeout,
                                 self._provider_version)

    def NormalizeReport(self, report: AdapterReport) -> AdapterResult:
        """Verify exact invocation and raw JSON; preserve failed execution as a diagnostic.

        Success requires one stdout and one provider-version evidence reference,
        schema 2 container_image output and provider-observed vulnerability DB
        metadata. Unknown optional provider fields remain raw evidence. Findings
        are SDK proposals; they do not persist model state or evaluate risk policy.

        Args:
            report: Immutable executed invocation, terminal facts and attributed raw references.

        Returns:
            The unchanged report plus generic SDK observations/findings; failures stay diagnostic.

        Raises:
            TrivyReportError: Evidence, schema, version or result structure is inconsistent.
            ValueError: The original request metadata fails the finite archive profile.
        """

        expected = self.BuildInvocation(report.invocation.request)

        if report.invocation != expected:
            raise TrivyReportError("Trivy report invocation differs from the prepared profile")

        raw = ReadEvidence(report, "stdout", self._read_evidence, TRIVY_JSON_MAX_BYTES)
        subject = report.invocation.request.target_reference

        if report.execution.state is not ExecutionState.SUCCEEDED:
            return AdapterResult(report, observations=(NormalizedObservation("trivy.run", subject,
                {"complete": False, "execution_state": report.execution.state.value}),))

        version = ParseJson(ReadEvidence(report, "provider-version", self._read_evidence,
                                        TRIVY_HEALTH_MAX_BYTES), TRIVY_HEALTH_MAX_BYTES)

        if not isinstance(version.get("Version"), str) or (
            report.invocation.provider_version is not None and
            version["Version"] != report.invocation.provider_version
        ):
            raise TrivyReportError("Trivy version evidence differs from invocation provenance")

        database = version.get("VulnerabilityDB")

        if not isinstance(database, dict) or type(database.get("Version")) is not int or (
            database["Version"] < 1 or not isinstance(database.get("UpdatedAt"), str)
        ):
            raise TrivyReportError("successful Trivy output requires observed DB metadata")

        payload = ParseJson(raw)

        if type(payload.get("SchemaVersion")) is not int or payload["SchemaVersion"] != 2 or (
            payload.get("ArtifactType") != "container_image"
        ):
            raise TrivyReportError("Trivy output requires schema 2 container_image JSON")

        native_version = payload.get("Trivy")

        if native_version is not None and (
            not isinstance(native_version, dict) or
            native_version.get("Version") != version["Version"]
        ):
            raise TrivyReportError("Trivy native version differs from observed provenance")

        results = payload.get("Results", [])

        if not isinstance(results, list):
            raise TrivyReportError("Trivy Results must be an array")

        observations = [NormalizedObservation("trivy.run", subject, {
            "complete": True, "schema_version": 2, "provider_version": version["Version"],
            "database_metadata": database, "java_database_metadata": version.get("JavaDB"),
            "database_provenance": "provider-version-evidence", "artifact_name":
            payload.get("ArtifactName"), "archive": report.invocation.request.parameters["archive"],
        })]
        findings: list[NormalizedFinding] = []

        for result in results:
            if not isinstance(result, dict) or not isinstance(result.get("Target"), str):
                raise TrivyReportError("Trivy result requires an object and Target text")

            packages = result.get("Packages", [])
            vulnerabilities = result.get("Vulnerabilities", [])

            if packages is None:
                packages = []

            if vulnerabilities is None:
                vulnerabilities = []

            if not isinstance(packages, list) or not isinstance(vulnerabilities, list):
                raise TrivyReportError("Trivy package and vulnerability collections must be arrays")

            for package in packages:
                if not isinstance(package, dict) or not isinstance(package.get("Name"), str):
                    raise TrivyReportError("Trivy package requires an object and Name text")

                observations.append(NormalizedObservation("image.package", subject, {
                    "result_target": result["Target"], "result_type": result.get("Type"),
                    "provider_fields": package,
                }))

            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict) or any(
                    not isinstance(vulnerability.get(key), str) or not vulnerability[key]
                    for key in ("VulnerabilityID", "PkgName", "InstalledVersion", "Severity")
                ) or vulnerability["Severity"] not in _SEVERITIES:
                    raise TrivyReportError("Trivy vulnerability/package/severity is invalid")

                summary = f"{vulnerability['VulnerabilityID']} in {vulnerability['PkgName']}"

                try:
                    finding = NormalizedFinding("image.package-vulnerability", subject, summary, {
                        "result_target": result["Target"], "result_type": result.get("Type"),
                        "provider_fields": vulnerability,
                    })

                except ValueError as error:
                    raise TrivyReportError("Trivy vulnerability summary is invalid") from error

                findings.append(finding)

        return AdapterResult(report, tuple(observations), tuple(findings))
