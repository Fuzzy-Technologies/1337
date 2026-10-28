# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal native configuration selections and fixed recipes, without execution authority."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ImpactLevel
from fuzzy1337.artifact_inputs import (
    ArtifactManifest,
    ArtifactName,
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactRole,
)

NATIVE_CONFIGURATION_VERSION = "0.75.0"
NATIVE_CONFIGURATION_EXECUTABLE_SHA256 = (
    "93f9da8e4ba5e0c1c76d8234ed2494cf9afb0a96fd21953e424bb795f3299b8e"
)
NATIVE_CONFIGURATION_PLATFORM = ("linux", "x86_64")
MAX_NATIVE_CONFIGURATION_SOURCE_BYTES = 4096
MAX_NATIVE_CONFIGURATION_EXECUTABLE_BYTES = 256 * 1024**2
NATIVE_CONFIGURATION_VERSION_SECONDS = 10
DEFAULT_NATIVE_CONFIGURATION_SCAN_SECONDS = 30
MAX_NATIVE_CONFIGURATION_SCAN_SECONDS = 60
_PROFILES = frozenset({ArtifactProfile.DOCKERFILE, ArtifactProfile.KUBERNETES})
_CONTROL_NAMES = frozenset({
    "trivy.yaml", "trivy.yml", "trivyignore.yaml", "trivyignore.yml",
    "chart.yaml", "chart.yml", "values.yaml", "values.yml",
    "kustomization.yaml", "kustomization.yml",
})


def ConfigurationPath(path: Path) -> None:
    """Require explicit bounded absolute path syntax without resolving or reading it."""

    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts or (
        len(str(path)) > 4096 or any(character in str(path) for character in ("\x00", "\n", "\r"))
    ):
        raise ValueError("native configuration requires explicit absolute path syntax")


@dataclass(frozen=True, slots=True)
class NativeConfigurationSelection:
    """One general selected source and trusted executable; construction performs no reads."""

    profile: ArtifactProfile
    logical_path: str
    source: Path
    executable: Path
    read_consent: ArtifactReadConsent

    def __post_init__(self) -> None:
        """Validate native profile, flat source name and explicit selected-read metadata."""

        if type(self.profile) is not ArtifactProfile or self.profile not in _PROFILES or (
            type(self.read_consent) is not ArtifactReadConsent
        ):
            raise ValueError("native configuration requires its native profile and read consent")

        ArtifactName(self.logical_path)

        if "/" in self.logical_path or (
            self.profile is ArtifactProfile.DOCKERFILE and self.logical_path != "Dockerfile"
        ) or (
            self.profile is ArtifactProfile.KUBERNETES and (
                not self.logical_path.endswith((".yaml", ".yml"))
                or self.logical_path.casefold() in _CONTROL_NAMES
            )
        ):
            raise ValueError("native configuration requires one supported flat source name")

        ConfigurationPath(self.source)
        ConfigurationPath(self.executable)

    def Scanner(self) -> str:
        """Return the fixed native scanner selector, without registering a capability."""

        return "dockerfile" if self.profile is ArtifactProfile.DOCKERFILE else "kubernetes"

    def Capability(self) -> str:
        """Describe this profile's capability without issuing execution permission."""

        return "config." + self.Scanner() + "-misconfigurations"


def ConfigurationManifest(selection: NativeConfigurationSelection,
                          manifest: ArtifactManifest) -> None:
    """Check descriptive selected input metadata without accepting its observed bytes."""

    if type(selection) is not NativeConfigurationSelection or type(manifest) is not (
        ArtifactManifest
    ) or manifest.profile is not selection.profile or manifest.role is not ArtifactRole.INPUT or (
        len(manifest.files) != 1
    ):
        raise ValueError("native configuration requires its exact one-file input manifest")

    source = manifest.files[0]

    if source.name != selection.logical_path or not (
        1 <= source.size_bytes <= MAX_NATIVE_CONFIGURATION_SOURCE_BYTES
    ):
        raise ValueError("native configuration input metadata exceeds its selected-file contract")


def PrepareNativeConfigurationVersion(
    selection: NativeConfigurationSelection, input_manifest: ArtifactManifest,
    cache_directory: Path,
) -> AdapterInvocation:
    """Describe original fixed VERSION with unknown observed version and no process permission.

    The later material and authority owners must independently verify the selected bytes,
    fresh cache and original execution. This pure factory cannot supply those facts.
    """

    ConfigurationManifest(selection, input_manifest)
    ConfigurationPath(cache_directory)
    request = AdapterRequest(selection.Capability(), input_manifest.Target().Reference(),
        ImpactLevel.SAFE, {"profile": selection.profile.value, "operation": "version"})
    arguments = (str(selection.executable), "--cache-dir", str(cache_directory), "--config=",
                 "--version", "--format", "json")

    return AdapterInvocation("native.trivy", request, arguments,
                             NATIVE_CONFIGURATION_VERSION_SECONDS, None)


@dataclass(frozen=True, slots=True)
class NativeConfigurationScanRecipe:
    """Descriptive config argv, never an observed VERSION prerequisite or executable request."""

    selection: NativeConfigurationSelection
    input_manifest: ArtifactManifest
    input_directory: Path
    cache_directory: Path
    timeout_seconds: int = DEFAULT_NATIVE_CONFIGURATION_SCAN_SECONDS

    def __post_init__(self) -> None:
        """Keep selected metadata, separate path syntax and integer deadline bounded."""

        ConfigurationManifest(self.selection, self.input_manifest)
        ConfigurationPath(self.input_directory)
        ConfigurationPath(self.cache_directory)

        if self.input_directory.is_relative_to(self.cache_directory) or (
            self.cache_directory.is_relative_to(self.input_directory)
        ):
            raise ValueError("native configuration input and cache paths must be separate")

        if type(self.timeout_seconds) is not int or not (
            1 <= self.timeout_seconds <= MAX_NATIVE_CONFIGURATION_SCAN_SECONDS
        ):
            raise ValueError("native configuration scan deadline requires an integer1..60")

    def Arguments(self) -> tuple[str, ...]:
        """Return fixed embedded-check argv; current material and authority remain unproved."""

        return (str(self.selection.executable), "--cache-dir", str(self.cache_directory),
            "--config=", "--debug", "config", "--cache-backend", "memory",
            "--misconfig-scanners", self.selection.Scanner(), "--include-non-failures",
            "--format", "json", "--exit-code", "0", "--ignorefile=", "--skip-check-update",
            "--skip-version-check", "--disable-telemetry", "--timeout",
            str(self.timeout_seconds) + "s", str(self.input_directory))
