# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Read-only component health and update inspection for the CLI and Workbench."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, version
from typing import IO

from fuzzy1337.doctor import MINIMUM_PYTHON_VERSION

UPDATE_REPORT_SCHEMA_VERSION = 1


class ComponentKind(StrEnum):
    """Identify the lifecycle families independently from their implementation."""

    CORE = "core"
    ADAPTERS = "adapters"
    TOOLS = "tools"
    INTELLIGENCE_DATASETS = "intelligence_datasets"


class HealthStatus(StrEnum):
    """Distinguish observations from unavailable inventories and failed checks."""

    HEALTHY = "healthy"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ComponentHealth:
    """Describe one local observation without inferring remote update freshness."""

    identifier: str
    kind: ComponentKind
    status: HealthStatus
    installed_version: str | None
    required: bool
    summary: str

    def ToDict(self) -> dict[str, object]:
        """Serialize the observation for the experimental versioned report.

        Returns:
            Explicit component fields containing only local observations.
        """

        return {
            "id": self.identifier,
            "kind": self.kind.value,
            "health": self.status.value,
            "installedVersion": self.installed_version,
            "required": self.required,
            "summary": self.summary,
        }


@dataclass(frozen=True, slots=True)
class UpdateReport:
    """Collect an inspection result; no record authorizes or performs mutation."""

    components: tuple[ComponentHealth, ...]

    @property
    def ExitCode(self) -> int:
        """Fail closed when a required local component cannot be proven healthy.

        Returns:
            One for any required non-healthy observation, otherwise zero.
        """

        return int(
            any(
                component.required and component.status is not HealthStatus.HEALTHY
                for component in self.components
            )
        )

    def ToDict(self) -> dict[str, object]:
        """Expose local health separately from unchecked update availability.

        Returns:
            Schema-versioned inspection data with an explicit non-mutation boundary.
        """

        return {
            "schemaVersion": UPDATE_REPORT_SCHEMA_VERSION,
            "mode": "inspect",
            "updateAvailability": "not_checked",
            "mutationsPerformed": False,
            "components": [component.ToDict() for component in self.components],
            "exitCode": self.ExitCode,
        }

    def Render(self) -> str:
        """Render local facts and manual next steps without promising freshness.

        Returns:
            Human-readable inspection output with unavailable families kept explicit.
        """

        lines = ["1337 update: read-only inspection"]

        for component in self.components:
            detected = (
                f" version={component.installed_version}" if component.installed_version else ""
            )
            lines.append(
                f"{component.status.value.upper():<11} {component.identifier}{detected}: "
                f"{component.summary}"
            )

        lines.extend(
            (
                "Update availability: not checked; no remote requests were made.",
                "No updates were performed.",
                "Next step: review updates through the installation owner's approved "
                "environment/package workflow.",
                "Result: required core checks failed."
                if self.ExitCode
                else "Result: required core checks passed; "
                "unavailable inventories remain unchecked.",
            )
        )

        return "\n".join(lines)


def CollectComponentHealth() -> UpdateReport:
    """Observe core metadata and expose unavailable optional inventory boundaries.

    Reads installed distribution metadata only. Does not scan the filesystem, discover
    executables, import adapters, run subprocesses, contact a network, or modify state.

    Returns:
        Ordered core checks and explicit adapter, tool, and dataset inventory observations.
    """

    return UpdateReport(
        components=(
            CheckPythonComponent(),
            CheckInstalledCore(),
            ComponentHealth(
                "adapters.inventory",
                ComponentKind.ADAPTERS,
                HealthStatus.UNAVAILABLE,
                None,
                False,
                "Adapter inventory is unavailable; the SDK does not establish installations.",
            ),
            ComponentHealth(
                "tools.inventory",
                ComponentKind.TOOLS,
                HealthStatus.UNAVAILABLE,
                None,
                False,
                "A managed tool inventory is not configured.",
            ),
            ComponentHealth(
                "intelligence_datasets.inventory",
                ComponentKind.INTELLIGENCE_DATASETS,
                HealthStatus.UNAVAILABLE,
                None,
                False,
                "An intelligence dataset inventory is not configured.",
            ),
        )
    )


def CheckPythonComponent() -> ComponentHealth:
    """Compare the executing interpreter with the existing minimum-runtime contract.

    Returns:
        Required Python observation with the detected interpreter version.
    """

    detected = sys.version_info[:3]
    actual = ".".join(str(value) for value in detected)
    required = ".".join(str(value) for value in MINIMUM_PYTHON_VERSION)
    supported = detected >= MINIMUM_PYTHON_VERSION

    return ComponentHealth(
        "core.python",
        ComponentKind.CORE,
        HealthStatus.HEALTHY if supported else HealthStatus.FAILED,
        actual,
        True,
        f"Python meets the minimum {required}."
        if supported
        else f"Python is below the required {required}.",
    )


def CheckInstalledCore() -> ComponentHealth:
    """Read the installed distribution version without querying a release source.

    Returns:
        Required installed-core observation, failing for missing or unreadable metadata.
    """

    try:
        detected_version = version("1337")

    except (PackageNotFoundError, OSError, ValueError):
        return ComponentHealth(
            "core.1337",
            ComponentKind.CORE,
            HealthStatus.FAILED,
            None,
            True,
            "Installed 1337 distribution metadata is missing or unreadable.",
        )

    if not isinstance(detected_version, str) or not detected_version.strip():
        return ComponentHealth(
            "core.1337",
            ComponentKind.CORE,
            HealthStatus.FAILED,
            None,
            True,
            "Installed 1337 distribution version is absent or empty.",
        )

    return ComponentHealth(
        "core.1337",
        ComponentKind.CORE,
        HealthStatus.HEALTHY,
        detected_version.strip(),
        True,
        "Installed distribution metadata is available; latest release is not checked.",
    )


def RunUpdate(output: IO[str], *, json_output: bool = False) -> int:
    """Write an inspection report through either consumer's configured stream.

    Args:
        output: Stream receiving the human or JSON report.
        json_output: Whether to write the experimental schema-versioned JSON document.

    Returns:
        Zero for healthy required core observations, otherwise one.

    Raises:
        OSError: Writing the output stream fails.
    """

    report = CollectComponentHealth()
    rendered = (
        json.dumps(report.ToDict(), sort_keys=True, allow_nan=False)
        if json_output
        else report.Render()
    )
    output.write(f"{rendered}\n")

    return report.ExitCode
