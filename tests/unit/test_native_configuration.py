# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure native configuration grammar and selected metadata without provider authority."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.artifact_inputs import (
    ArtifactFile,
    ArtifactManifest,
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactRole,
)
from fuzzy1337.native_configuration import (
    MAX_NATIVE_CONFIGURATION_EXECUTABLE_BYTES,
    MAX_NATIVE_CONFIGURATION_SOURCE_BYTES,
    NATIVE_CONFIGURATION_EXECUTABLE_SHA256,
    NATIVE_CONFIGURATION_PLATFORM,
    NATIVE_CONFIGURATION_VERSION,
    NativeConfigurationScanRecipe,
    NativeConfigurationSelection,
    PrepareNativeConfigurationVersion,
)


def Selection(root: Path, profile: ArtifactProfile = ArtifactProfile.DOCKERFILE,
              logical_path: str | None = None) -> NativeConfigurationSelection:
    """Describe nonexistent selected paths to expose accidental filesystem dependence."""

    name = logical_path if logical_path is not None else (
        "Dockerfile" if profile is ArtifactProfile.DOCKERFILE else "ordinary-manifest.yaml")

    return NativeConfigurationSelection(profile, name, root / "selected-source",
        root / "supplied-trivy", ArtifactReadConsent("owner:test", "read:explicit-test"))


def Manifest(selection: NativeConfigurationSelection, size: int = 47) -> ArtifactManifest:
    """Supply arbitrary noncatalog descriptive bytes, never a native compatibility proof."""

    return ArtifactManifest(selection.profile, ArtifactRole.INPUT,
        (ArtifactFile(selection.logical_path, size, "a" * 64),))


@pytest.mark.parametrize("profile,scanner", [
    (ArtifactProfile.DOCKERFILE, "dockerfile"), (ArtifactProfile.KUBERNETES, "kubernetes"),
])
def test_FixedNativeRecipesRetainOriginalVersionAndSeparateScanDescription(tmp_path, profile,
                                                                         scanner):
    """Both general profiles use the accepted config grammar without an image or fixture path."""

    selection = Selection(tmp_path, profile)
    manifest = Manifest(selection)
    cache = tmp_path / "version-cache"
    version = PrepareNativeConfigurationVersion(selection, manifest, cache)
    assert version.argv == (str(selection.executable), "--cache-dir", str(cache), "--config=",
        "--version", "--format", "json"), "VERSION changed its fixed original JSON recipe"
    assert version.provider_version is None and version.timeout_seconds == 10, (
        "Original VERSION must remain unobserved with its independent finite deadline"
    )
    assert version.request.target_reference == manifest.Target().Reference() and (
        version.request.capability == "config." + scanner + "-misconfigurations"
    ), "Native configuration must use its whole INPUT manifest and declared config capability"
    assert dict(version.request.parameters) == {"profile": profile.value, "operation": "version"}, (
        "VERSION request metadata must not supply a caller extension channel"
    )
    recipe = NativeConfigurationScanRecipe(selection, manifest, tmp_path / "input",
                                            tmp_path / "scan-cache")
    assert recipe.Arguments() == (str(selection.executable), "--cache-dir",
        str(tmp_path / "scan-cache"), "--config=", "--debug", "config", "--cache-backend",
        "memory", "--misconfig-scanners", scanner, "--include-non-failures", "--format", "json",
        "--exit-code", "0", "--ignorefile=", "--skip-check-update", "--skip-version-check",
        "--disable-telemetry", "--timeout", "30s", str(tmp_path / "input")), (
        "SCAN must retain the fixed embedded-check config-only grammar"
    )


def test_FactoryAndSelectionPerformNoFilesystemAccess(tmp_path, monkeypatch):
    """Selection and pure recipes cannot hash, resolve, create or read selected material."""

    def Forbidden(*args, **kwargs):
        """Fail immediately if pure syntax or grammar reaches a selected file operation."""

        pytest.fail("Pure native configuration factories must not access the filesystem")

    for method in ("stat", "lstat", "open", "read_bytes", "resolve", "mkdir"):
        monkeypatch.setattr(Path, method, Forbidden)

    selection = Selection(tmp_path)
    manifest = Manifest(selection)
    version = PrepareNativeConfigurationVersion(selection, manifest, tmp_path / "version-cache")
    recipe = NativeConfigurationScanRecipe(selection, manifest, tmp_path / "input",
                                            tmp_path / "scan-cache")
    assert version.provider_version is None and recipe.Arguments()[-1] == str(tmp_path / "input"), (
        "Pure recipe creation should need only explicit syntax and descriptive metadata"
    )


@pytest.mark.parametrize("profile,name", [
    (ArtifactProfile.KUBERNETES, "ordinary.yaml"),
    (ArtifactProfile.KUBERNETES, "different-source.yml"),
    (ArtifactProfile.DOCKERFILE, "Dockerfile"),
])
@pytest.mark.parametrize("size", [1, 4096])
def test_GeneralInputMetadataIsNotRestrictedToCompatibilityCatalog(tmp_path, profile, name, size):
    """Arbitrary valid manifest hashes and boundary lengths remain descriptive selected input."""

    selection = Selection(tmp_path, profile, name)
    manifest = Manifest(selection, size)
    version = PrepareNativeConfigurationVersion(selection, manifest, tmp_path / "cache")
    assert version.request.target_reference == manifest.Target().Reference(), (
        "General selected-file identity must not be replaced with a fixture byte allowlist"
    )


@pytest.mark.parametrize("profile", [
    ArtifactProfile.IMAGE, ArtifactProfile.SYNTHETIC_IMAGE, ArtifactProfile.SYNTHETIC_DOCKERFILE,
    ArtifactProfile.SYNTHETIC_KUBERNETES, "trivy.dockerfile-offline.v1", None,
])
def test_NonnativeConfigurationProfilesAreRejectedWithoutReads(tmp_path, profile):
    """Image, synthetic and untyped values cannot enter the native configuration selection."""

    with pytest.raises(ValueError):
        Selection(tmp_path, profile, "Dockerfile")


@pytest.mark.parametrize("name", [
    "nested/file.yaml", "../file.yaml", "/file.yaml", "file\\name.yaml", "file:stream.yaml",
    "CON.yaml", "file.yaml.", "file.yaml ", "file.YAML", "file.json", "", "é.yaml",
    "trivy.yaml", "TRIVY.yaml", "trivyignore.yml", "Chart.yaml", "values.yml",
    "KUSTOMIZATION.yaml",
])
def test_UnsafeOrControlKubernetesNamesCannotBecomeSelectedInputs(tmp_path, name):
    """One flat portable data file cannot become implicit scanner configuration or rendering."""

    with pytest.raises(ValueError):
        Selection(tmp_path, ArtifactProfile.KUBERNETES, name)


@pytest.mark.parametrize("name", ["dockerfile", "Dockerfile.extra", "nested/Dockerfile", "x.yaml"])
def test_DockerfileLogicalNameRemainsExact(tmp_path, name):
    """The Dockerfile recognizer receives only its canonical selected logical name."""

    with pytest.raises(ValueError):
        Selection(tmp_path, ArtifactProfile.DOCKERFILE, name)


@pytest.mark.parametrize("field", ["source", "executable"])
@pytest.mark.parametrize("value", [
    Path("relative"), Path("/selected/../other"), Path("/private\npath"),
    Path("/private\rpath"), Path("/private\x00path"), Path("/" + "a" * 4096), "/untyped/path",
])
def test_SelectedPhysicalPathsRequireBoundedAbsoluteSyntax(tmp_path, field, value):
    """Unsafe selected path spellings reject before filesystem resolution or source access."""

    with pytest.raises(ValueError):
        replace(Selection(tmp_path), **{field: value})


def test_ReadConsentMustRemainTheExistingTypedArtifactRecord(tmp_path):
    """A string or substitute read-consent object cannot authorize selected material reads."""

    with pytest.raises(ValueError):
        replace(Selection(tmp_path), read_consent="read:untyped")


@pytest.mark.parametrize("change", [
    "selection-type", "manifest-type", "profile", "role", "count", "name", "empty", "large",
])
def test_RecipeRejectsMismatchedInputMetadata(tmp_path, change):
    """Only one matching bounded INPUT manifest may describe a future configuration scan."""

    selection = Selection(tmp_path)
    manifest = Manifest(selection)

    if change == "selection-type":
        selection = None

    elif change == "manifest-type":
        manifest = None

    elif change == "profile":
        manifest = replace(manifest, profile=ArtifactProfile.SYNTHETIC_DOCKERFILE)

    elif change == "role":
        manifest = replace(manifest, role=ArtifactRole.SCANNER)

    elif change == "count":
        manifest = replace(manifest, files=(*manifest.files, ArtifactFile("other", 1, "b" * 64)))

    elif change == "name":
        manifest = replace(manifest, files=(ArtifactFile("other", 1, "b" * 64),))

    else:
        manifest = Manifest(selection, 0 if change == "empty" else 4097)

    with pytest.raises(ValueError):
        NativeConfigurationScanRecipe(selection, manifest, tmp_path / "input", tmp_path / "cache")

    with pytest.raises(ValueError):
        PrepareNativeConfigurationVersion(selection, manifest, tmp_path / "cache")


@pytest.mark.parametrize("deadline", [True, False, 0, 61, 1.0, None, "30"])
def test_ScanDeadlineRejectsCoercionOrExpansion(tmp_path, deadline):
    """Configuration scan windows retain the exact integer1..60 contract."""

    selection = Selection(tmp_path)

    with pytest.raises(ValueError):
        NativeConfigurationScanRecipe(selection, Manifest(selection), tmp_path / "input",
                                        tmp_path / "cache", deadline)


@pytest.mark.parametrize("deadline", [1, 60])
def test_ScanDeadlineBoundariesArePreservedInFixedArgv(tmp_path, deadline):
    """Accepted finite scan deadlines remain exact and do not change VERSION's window."""

    selection = Selection(tmp_path)
    recipe = NativeConfigurationScanRecipe(selection, Manifest(selection), tmp_path / "input",
                                            tmp_path / "cache", deadline)
    assert recipe.Arguments()[-3:] == ("--timeout", str(deadline) + "s", str(tmp_path / "input")), (
        "The selected integer deadline must be carried exactly into the descriptive config argv"
    )


@pytest.mark.parametrize("input_name,cache_name", [
    ("same", "same"), ("input", "input/cache"), ("cache/input", "cache"),
])
def test_InputAndCacheCannotOverlap(tmp_path, input_name, cache_name):
    """The future provider cache cannot reside within or contain selected configuration input."""

    selection = Selection(tmp_path)

    with pytest.raises(ValueError):
        NativeConfigurationScanRecipe(selection, Manifest(selection), tmp_path / input_name,
                                        tmp_path / cache_name)


def test_CompatibilityConstantsDescribeOnlyTheTestedCandidate():
    """The initial candidate pin and admission bounds cannot imply broader runtime acceptance."""

    assert NATIVE_CONFIGURATION_VERSION == "0.75.0" and (
        NATIVE_CONFIGURATION_PLATFORM == ("linux", "x86_64")
    ), "The first native configuration candidate must retain its tested provider and platform"
    assert NATIVE_CONFIGURATION_EXECUTABLE_SHA256 == (
        "93f9da8e4ba5e0c1c76d8234ed2494cf9afb0a96fd21953e424bb795f3299b8e"
    ), "The admitted executable pin must remain independently bound to compatibility evidence"
    assert MAX_NATIVE_CONFIGURATION_SOURCE_BYTES == 4096 and (
        MAX_NATIVE_CONFIGURATION_EXECUTABLE_BYTES == 256 * 1024**2
    ), "Source/scanner admitted-byte bounds must not silently inherit global snapshot ceilings"
