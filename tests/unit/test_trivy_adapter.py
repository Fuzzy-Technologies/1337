# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite Trivy offline invocations and immutable JSON interpretation failures."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterHealthState,
    AdapterReport,
    AdapterRequest,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
    ToolAdapter,
    trivy,
)
from fuzzy1337.adapters.trivy import ParseJson, TrivyAdapter, TrivyReportError, WorkspacePath

VERSION = {"Version": "0.75.0-synthetic", "VulnerabilityDB": {"Version": 2,
           "UpdatedAt": "2026-10-01T00:00:00Z"}}
PAYLOAD = {"SchemaVersion": 2, "ArtifactType": "container_image", "ArtifactName": "owned.tar",
    "Results": [{"Target": "owned (alpine)", "Type": "alpine", "Packages": [
        {"Name": "synthetic-lib", "Version": "1.0", "ID": "synthetic-lib@1.0"}],
        "Vulnerabilities": [{"VulnerabilityID": "CVE-2099-0001", "PkgName": "synthetic-lib",
            "InstalledVersion": "1.0", "FixedVersion": "2.0", "Severity": "HIGH"}]}]}


@pytest.fixture
def adapter(tmp_path):
    """Create an owned finite file/cache boundary without executing any real scanner."""

    (tmp_path / "owned.tar").write_bytes(b"synthetic archive marker")
    (tmp_path / "trivy-cache").mkdir()

    return TrivyAdapter(lambda item: b"", tmp_path, provider_version="0.75.0-synthetic")


def Request(**parameters):
    """Build an approved-profile fixture, which still grants no authority."""

    values = {"archive": "owned.tar", "timeout_seconds": 5}
    values.update(parameters)

    return AdapterRequest("image.archive-vulnerabilities", "target:owned", ImpactLevel.SAFE, values)


def Report(adapter, payload=PAYLOAD, version=VERSION, state=ExecutionState.SUCCEEDED):
    """Attribute exact synthetic bytes through immutable existing SDK envelopes."""

    stdout = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    version_bytes = json.dumps(version).encode()
    data = {"stdout": stdout, "provider-version": version_bytes}
    references = tuple(EvidenceReference(role, f"fixture/{role}.json",
        hashlib.sha256(raw).hexdigest(), "application/json", len(raw))
        for role, raw in data.items())
    adapter._read_evidence = lambda item: data[item.role]
    execution = AdapterExecution(state, 0 if state is ExecutionState.SUCCEEDED else 7, 0.01)

    return AdapterReport(adapter.PrepareInvocation(Request()), execution, references)


def test_OfflineArgvIsFiniteAndOptional(adapter, tmp_path):
    """Preparation declares exactly archive scanning and disables implicit online sources."""

    assert isinstance(adapter, ToolAdapter), "Trivy must implement the accepted SDK."
    invocation = adapter.PrepareInvocation(Request())
    args = invocation.argv

    assert (
        adapter.Descriptor.maximum_impact is ImpactLevel.SAFE
    ), (
        "Preparation declares exactly archive scanning and disables implicit online sources."
    )
    assert (
        Path(args[args.index("--input") + 1]) == tmp_path.resolve() / "owned.tar"
    ), (
        "Preparation declares exactly archive scanning and disables implicit online sources."
    )
    assert (
        "--disable-telemetry" in args
    ), (
        "Preparation declares exactly archive scanning and disables implicit online sources."
    )
    assert (
        "--offline-scan" in args and "--skip-db-update" in args
    ), (
        "Preparation declares exactly archive scanning and disables implicit online sources."
    )
    assert (
        "--skip-java-db-update" in args and "--skip-check-update" in args
    ), (
        "Preparation declares exactly archive scanning and disables implicit online sources."
    )
    assert (
        "--skip-version-check" in args and "--skip-vex-repo-update" in args
    ), (
        "Preparation declares exactly archive scanning and disables implicit online sources."
    )
    assert (
        "--ignorefile=" in args
    ), (
        "Preparation declares exactly archive scanning and disables implicit online sources."
    )
    assert (
        "--config=" in args
    ), (
        "Preparation declares exactly archive scanning and disables implicit online sources."
    )
    assert (
        args[args.index("--scanners") + 1] == "vuln"
    ), (
        "Preparation declares exactly archive scanning and disables implicit online sources."
    )
    assert (
        invocation.timeout_seconds == 5
    ), (
        "Preparation declares exactly archive scanning and disables implicit online sources."
    )


@pytest.mark.parametrize("parameters", [
    {"archive": "../outside.tar"}, {"archive": "/absolute.tar"}, {"archive": "C:/owned.tar"},
    {"archive": "./owned.tar"}, {"archive": "-x"}, {"archive": "a//b"},
    {"archive": "a\\b"}, {"archive": ""}, {"archive": None},
    {"timeout_seconds": True}, {"timeout_seconds": 0}, {"timeout_seconds": 3601},
    {"timeout_seconds": 1.0}, {"flags": "--server https://example.invalid"},
])
def test_InvalidParametersFailClosed(adapter, parameters):
    """Reject path expansion, raw flags and unbounded timeout requests."""

    with pytest.raises(ValueError):
        adapter.PrepareInvocation(Request(**parameters))


@pytest.mark.parametrize("tool_request", [
    AdapterRequest("image.registry", "target:owned", ImpactLevel.SAFE, {}),
    AdapterRequest("image.archive-vulnerabilities", "target:owned", ImpactLevel.STANDARD, {}),
    AdapterRequest("image.archive-vulnerabilities", "target:owned", ImpactLevel.SAFE,
                   {"archive": "owned.tar", "timeout_seconds": 5}, ("credential:opaque",)),
])
def test_UnsupportedCapabilityImpactAndCredentials(adapter, tool_request):
    """Declared offline capability grants no daemon, registry or credential access."""

    with pytest.raises(ValueError):
        adapter.PrepareInvocation(tool_request)


def test_FileCacheAndSymlinkBoundaries(adapter, tmp_path, monkeypatch):
    """Existing physical bounded files and directories are required before execution."""

    with pytest.raises(FileNotFoundError):
        adapter.PrepareInvocation(Request(archive="missing.tar"))

    with pytest.raises(ValueError):
        adapter.PrepareInvocation(Request(archive="trivy-cache"))

    (tmp_path / "linked.tar").symlink_to(tmp_path / "owned.tar")

    with pytest.raises(ValueError):
        adapter.PrepareInvocation(Request(archive="linked.tar"))

    monkeypatch.setattr(trivy, "TRIVY_MAX_ARCHIVE_BYTES", 1)

    with pytest.raises(ValueError):
        adapter.PrepareInvocation(Request())

    monkeypatch.setattr(trivy, "TRIVY_MAX_ARCHIVE_BYTES", 512 * 1024 * 1024)
    (tmp_path / "trivy-cache").rmdir()
    (tmp_path / "trivy-cache").write_text("file")

    with pytest.raises(ValueError):
        adapter.PrepareInvocation(Request())


def test_ConstructorValidatesOperatorSelection(tmp_path):
    """Invalid executable/version/root/cache selections never start any tool."""

    with pytest.raises(ValueError):
        TrivyAdapter(lambda item: b"", tmp_path, executable="")

    with pytest.raises(ValueError):
        TrivyAdapter(lambda item: b"", tmp_path, provider_version="\n")

    with pytest.raises(ValueError):
        TrivyAdapter(lambda item: b"", tmp_path / "missing")

    with pytest.raises(ValueError):
        WorkspacePath(tmp_path, ".", directory=True)


@pytest.mark.parametrize("raw", [b"", b"[]", b"{", b"\xff", b'{"a":1,"a":2}',
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b'{"x":-Infinity}',
    b'{"x":' + b'9' * 5000 + b'}',
    b'{"x":' + b'[' * 1200 + b'0' + b']' * 1200 + b'}'])
def test_JsonParserRejectsAmbiguityAndMalformedEvidence(raw):
    """Provider JSON fails explicitly on encoding, duplicate keys, nonfinite and deep trees."""

    with pytest.raises(TrivyReportError):
        ParseJson(raw)


def test_JsonParserBudgets(monkeypatch):
    """Independent byte, node and depth bounds fail closed before normalization."""

    with pytest.raises(TrivyReportError):
        ParseJson(b'{"a": 1}', max_bytes=1)

    monkeypatch.setattr(trivy, "TRIVY_JSON_MAX_DEPTH", 2)

    with pytest.raises(TrivyReportError):
        ParseJson(b'{"a": [{"b": 1}]}')

    monkeypatch.setattr(trivy, "TRIVY_JSON_MAX_NODES", 2)

    with pytest.raises(TrivyReportError):
        ParseJson(b'{"a": [1,2]}')


def test_NormalizationPreservesProviderEvidence(adapter):
    """Package/vulnerability SDK proposals keep raw bytes and observed version/DB provenance."""

    report = Report(adapter)
    result = adapter.NormalizeReport(report)

    assert (
        result.report is report
    ), (
        "Package/vulnerability SDK proposals keep raw bytes and observed version/DB provenance."
    )
    assert (
        result.observations[0].attributes["database_metadata"]["Version"] == 2
    ), (
        "Package/vulnerability SDK proposals keep raw bytes and observed version/DB provenance."
    )
    assert (
        result.observations[1].kind == "image.package"
    ), (
        "Package/vulnerability SDK proposals keep raw bytes and observed version/DB provenance."
    )
    assert (
        result.findings[0].kind == "image.package-vulnerability"
    ), (
        "Package/vulnerability SDK proposals keep raw bytes and observed version/DB provenance."
    )
    assert (
        result.findings[0].attributes["provider_fields"]["Severity"] == "HIGH"
    ), (
        "Package/vulnerability SDK proposals keep raw bytes and observed version/DB provenance."
    )

    with pytest.raises(TypeError):
        result.findings[0].attributes["provider_fields"]["Severity"] = "LOW"


@pytest.mark.parametrize("state", [ExecutionState.FAILED, ExecutionState.TIMED_OUT,
                                   ExecutionState.CANCELLED])
def test_FailedExecutionCannotBecomeSuccessfulOutput(adapter, state):
    """Terminal failure yields only an incomplete diagnostic, even when stdout looks complete."""

    report = Report(adapter, state=state)
    result = adapter.NormalizeReport(report)

    assert (
        result.report is report and not result.findings
    ), (
        "Terminal failure yields only an incomplete diagnostic, even when stdout looks complete."
    )
    assert (
        result.observations[0].attributes["complete"] is False
    ), (
        "Terminal failure yields only an incomplete diagnostic, even when stdout looks complete."
    )
    assert (
        result.observations[0].attributes["execution_state"] == state.value
    ), (
        "Terminal failure yields only an incomplete diagnostic, even when stdout looks complete."
    )


@pytest.mark.parametrize("mutation", [
    {"SchemaVersion": 1}, {"SchemaVersion": True}, {"ArtifactType": "repository"},
    {"Results": {}}, {"Results": [None]}, {"Results": [{"Target": 3}]},
    {"Results": [{"Target": "x", "Packages": {}}]},
    {"Results": [{"Target": "x", "Vulnerabilities": {}}]},
    {"Results": [{"Target": "x", "Packages": [None]}]},
    {"Results": [{"Target": "x", "Vulnerabilities": [None]}]},
    {"Results": [{"Target": "x", "Vulnerabilities": [{"VulnerabilityID": "x"}]}]},
])
def test_SuccessfulMalformedReportsFail(adapter, mutation):
    """Success at the executor does not hide invalid native output structure."""

    with pytest.raises(TrivyReportError):
        adapter.NormalizeReport(Report(adapter, {**PAYLOAD, **mutation}))


@pytest.mark.parametrize("version", [{}, {"Version": "different"},
    {**VERSION, "VulnerabilityDB": {}}, {**VERSION, "VulnerabilityDB": None},
    {**VERSION, "VulnerabilityDB": {"Version": True, "UpdatedAt": "x"}},
    {**VERSION, "VulnerabilityDB": {"Version": 2, "UpdatedAt": ""}},
    {**VERSION, "VulnerabilityDB": {"Version": 2, "UpdatedAt": "not-a-timestamp"}},
    {**VERSION, "VulnerabilityDB": {"Version": 2, "UpdatedAt": "2026-10-01T00:00:00"}},
    {**VERSION, "VulnerabilityDB": {"Version": 2, "UpdatedAt": "2026-13-01T00:00:00Z"}},
    {**VERSION, "VulnerabilityDB": {"Version": 2, "UpdatedAt": 1}},
])
def test_VersionAndDatabaseProvenanceFailures(adapter, version):
    """Success requires verified provider version and database metadata evidence."""

    with pytest.raises(TrivyReportError):
        adapter.NormalizeReport(Report(adapter, version=version))


def test_OptionalNativeCollectionsAndFields(adapter):
    """Missing/null optional arrays and unknown provider fields do not create false findings."""

    report = Report(adapter, {**PAYLOAD, "Results": [{"Target": "x", "Packages": None,
        "Vulnerabilities": None, "NewOptionalField": "ignored"}]})
    result = adapter.NormalizeReport(report)

    assert (
        not result.findings and len(result.observations) == 1
    ), (
        "Missing/null optional arrays and unknown provider fields do not create false findings."
    )


def test_InvocationAndEvidenceIntegrity(adapter, monkeypatch):
    """Wrong argv, missing/duplicate stdout and hash/length drift fail before parsing."""

    report = Report(adapter)

    with pytest.raises(TrivyReportError):
        adapter.NormalizeReport(replace(report,
            invocation=replace(report.invocation, argv=("trivy", "--server", "invalid"))))

    with pytest.raises(TrivyReportError):
        adapter.NormalizeReport(replace(report, evidence=()))

    extra = replace(report.evidence[0], locator="fixture/duplicate.json")

    with pytest.raises(TrivyReportError):
        adapter.NormalizeReport(replace(report, evidence=(*report.evidence, extra)))

    monkeypatch.setattr(adapter, "_read_evidence", lambda item: b"different")

    with pytest.raises(TrivyReportError):
        adapter.NormalizeReport(report)

    monkeypatch.setattr(trivy, "TRIVY_JSON_MAX_BYTES", 1)

    with pytest.raises(TrivyReportError):
        adapter.NormalizeReport(report)


def test_HealthUnavailableAndLaunchFailure(adapter, monkeypatch):
    """Absent or unlaunchable optional Trivy is an explicit unavailable observation."""

    monkeypatch.setattr(trivy.shutil, "which", lambda value: None)

    assert (
        adapter.CheckHealth().state is AdapterHealthState.UNAVAILABLE
    ), (
        "Absent or unlaunchable optional Trivy is an explicit unavailable observation."
    )

    monkeypatch.setattr(trivy.shutil, "which", lambda value: "trivy")

    def Fail(*args, **kwargs):
        """Model a local executable that cannot start."""

        raise OSError("owned fixture failure")

    monkeypatch.setattr(trivy.subprocess, "Popen", Fail)

    assert (
        adapter.ProbeHealth().health.state is AdapterHealthState.UNAVAILABLE
    ), (
        "Absent or unlaunchable optional Trivy is an explicit unavailable observation."
    )


def test_HistoricalReplayIgnoresRemovedInputs(adapter, tmp_path):
    """Immutable native/version evidence remains interpretable after mutable files are removed."""

    report = Report(adapter)
    (tmp_path / "owned.tar").unlink()
    (tmp_path / "trivy-cache").rmdir()

    assert (
        len(adapter.NormalizeReport(report).findings) == 1
    ), (
        "Immutable native/version evidence remains interpretable after mutable files are removed."
    )


def test_UnsupportedOrUnobservedVersionCannotPrepare(tmp_path):
    """Version capability knowledge is explicit, with no implicit old-version fallback."""

    (tmp_path / "trivy-cache").mkdir()
    adapter = TrivyAdapter(lambda item: b"", tmp_path)

    with pytest.raises(ValueError):
        adapter.PrepareInvocation(Request())

    with pytest.raises(ValueError):
        TrivyAdapter(lambda item: b"", tmp_path, provider_version="0.74.0")


@pytest.mark.parametrize("metadata", [{"Version": "0.74.0"}, {}, "0.75.0"])
def test_NativeReportVersionMustMatchEvidence(adapter, metadata):
    """Native report provenance cannot contradict independently captured version evidence."""

    with pytest.raises(TrivyReportError):
        adapter.NormalizeReport(Report(adapter, {**PAYLOAD, "Trivy": metadata}))


def test_OriginalVersionInvocationHasNoBorrowedProviderVersion(adapter, tmp_path):
    """Independent VERSION uses fixed bounded JSON argv without borrowing scan provenance."""

    invocation = adapter.PrepareVersionInvocation(Request(timeout_seconds=3))
    assert invocation.argv == ("trivy", "--cache-dir", str(tmp_path.resolve() / "trivy-cache"),
        "--config=", "--version", "--format", "json"), "VERSION uses exact selected argv"
    assert invocation.provider_version is None, "Unknown VERSION provenance remains original"
    assert invocation.timeout_seconds == 3, "VERSION has a fixed independent deadline"

    with pytest.raises(TrivyReportError):
        adapter.NormalizeReport(replace(Report(adapter), invocation=invocation))


@pytest.mark.parametrize("version_request", [
    Request(timeout_seconds=True), Request(timeout_seconds=4), Request(flags="--arbitrary"),
    AdapterRequest("image.registry", "target:owned", ImpactLevel.SAFE,
                   {"archive": "owned.tar", "timeout_seconds": 3}),
    AdapterRequest("image.archive-vulnerabilities", "target:owned", ImpactLevel.STANDARD,
                   {"archive": "owned.tar", "timeout_seconds": 3}),
    AdapterRequest("image.archive-vulnerabilities", "target:owned", ImpactLevel.SAFE,
                   {"archive": "owned.tar", "timeout_seconds": 3}, ("credential:opaque",)),
])
def test_OriginalVersionPreparationRejectsProfileExpansion(adapter, version_request):
    """VERSION refuses expanded deadlines, flags, registry, credentials and stronger impact."""

    with pytest.raises(ValueError):
        adapter.PrepareVersionInvocation(version_request)
