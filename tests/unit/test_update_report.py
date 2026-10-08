# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic component-observation and required-health boundary tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from io import StringIO

import pytest

from fuzzy1337 import component_health
from fuzzy1337.component_health import (
    CheckInstalledCore,
    CheckPythonComponent,
    CollectComponentHealth,
    ComponentHealth,
    ComponentKind,
    HealthStatus,
    RunUpdate,
    UpdateReport,
)


@pytest.mark.parametrize("status", list(HealthStatus))
@pytest.mark.parametrize("required", [True, False])
def test_RequiredChecksFailClosedForEveryNonHealthyStatus(status, required):
    """Keep unavailable and unknown required observations from becoming success."""

    component = ComponentHealth("test", ComponentKind.CORE, status, None, required, "Observed.")
    report = UpdateReport((component,))

    assert report.ExitCode == int(required and status is not HealthStatus.HEALTHY), (
        "A required non-healthy component must fail; optional inventory state must remain explicit."
    )
    expected = "failed" if report.ExitCode else "passed"
    assert f"required core checks {expected}" in report.Render(), (
        "Human output must preserve the required-check result."
    )
    assert report.ToDict()["exitCode"] == report.ExitCode, (
        "Machine and terminal consumers must agree on the required-check exit code."
    )


def test_HealthSnapshotsAreImmutable():
    """Prevent either consumer from altering an already collected observation."""

    component = CheckPythonComponent()
    report = UpdateReport((component,))

    with pytest.raises(FrozenInstanceError):
        component.status = HealthStatus.FAILED

    with pytest.raises(FrozenInstanceError):
        report.components = ()


@pytest.mark.parametrize("detected, healthy", [((3, 10, 9), False), ((3, 11, 0), True)])
def test_PythonObservationRetainsDetectedVersionAndCompatibility(monkeypatch, detected, healthy):
    """Observe interpreter compatibility using the existing minimum-runtime contract."""

    monkeypatch.setattr(component_health.sys, "version_info", detected)
    component = CheckPythonComponent()

    assert component.installed_version == ".".join(str(value) for value in detected), (
        "The report must retain the actual interpreter version."
    )
    expected = HealthStatus.HEALTHY if healthy else HealthStatus.FAILED
    assert component.status is expected and component.required, (
        "An unsupported interpreter must be an explicit required failure."
    )


@pytest.mark.parametrize(
    "error", [component_health.PackageNotFoundError(), OSError(), ValueError()]
)
def test_CoreMetadataFailuresRemainRequiredFailures(monkeypatch, error):
    """Keep missing and unreadable metadata from masquerading as an installed core."""

    def MissingMetadata(distribution):
        """Raise a deterministic metadata failure for the requested distribution."""

        assert distribution == "1337", "Inspection must query only the known core distribution."

        raise error

    monkeypatch.setattr(component_health, "version", MissingMetadata)
    component = CheckInstalledCore()

    assert component.status is HealthStatus.FAILED and component.required, (
        "Missing or unreadable core metadata must fail the required local observation."
    )
    assert component.installed_version is None, (
        "Failed metadata cannot invent an installed version."
    )


@pytest.mark.parametrize("detected", [None, "", "  "])
def test_EmptyDistributionVersionsFailClosed(monkeypatch, detected):
    """Reject an empty local version without inventing update availability."""

    monkeypatch.setattr(component_health, "version", lambda _: detected)
    component = CheckInstalledCore()

    assert component.status is HealthStatus.FAILED and component.installed_version is None, (
        "Empty distribution metadata must remain a required failure."
    )


def test_CollectorReportsAllFamiliesWithoutClaimingOptionalInventoryHealth(monkeypatch):
    """Keep SDK existence and installed core metadata separate from inventory health."""

    monkeypatch.setattr(component_health, "version", lambda _: " 0.1.8 ")
    report = CollectComponentHealth()

    assert len(report.components) == 5 and {value.kind for value in report.components} == set(
        ComponentKind
    ), "The initial report must retain core, adapters, tools, and intelligence datasets."
    assert report.components[1].installed_version == "0.1.8", (
        "Core inspection must preserve the locally installed version."
    )
    assert all(
        value.status is HealthStatus.UNAVAILABLE and value.installed_version is None
        for value in report.components[2:]
    ), "Unavailable inventories cannot be marked healthy or assigned invented versions."
    assert report.ExitCode == 0, "Unavailable optional inventory must not fail healthy core checks."
    assert "version=0.1.8" in report.Render(), "Human output must retain the observed core version."


def test_OutputFailuresPropagateWithoutChangingTheHealthResult(monkeypatch):
    """Leave stream failures visible rather than silently reporting success."""

    monkeypatch.setattr(component_health, "version", lambda _: "0.1.8")

    output = StringIO()

    def FailingWrite(text):
        """Reject stream output with the original I/O failure."""

        raise OSError("Output unavailable")

    monkeypatch.setattr(output, "write", FailingWrite)

    with pytest.raises(OSError, match="Output unavailable"):
        RunUpdate(output)
