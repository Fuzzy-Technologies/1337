# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit closed-image CLI profile, selection and authority argument contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fuzzy1337.cli import Main
from fuzzy1337.command_registry import COMMAND_REGISTRY
from fuzzy1337.scope import AuthorizationState, LocalScopeStore, TargetKind


def ImageArguments(root: Path) -> list[str]:
    """Describe explicit inert selections without reading files or granting scan authority."""

    return ["scan", "image", str(root), "--profile", "synthetic", "--scope", "image-scope",
        "--owner", "owner:image-test", "--archive", str(root / "image.tar"),
        "--executable", str(root / "python"), "--producer", str(root / "producer.py"),
        "--material", str(root / "policy.json"), "--read-consent-reference", "read:explicit"]


@pytest.mark.parametrize("option", [
    "--profile", "--scope", "--owner", "--archive", "--executable", "--producer", "--material",
    "--read-consent-reference",
])
def test_ImageInputsAreRequiredBeforeAnyWorkspaceMutation(tmp_path, option):
    """Missing profile, consent or selected source never falls back to implicit discovery."""

    root = tmp_path / "absent"
    arguments = ImageArguments(root)
    index = arguments.index(option)
    del arguments[index:index + 2]

    with pytest.raises(SystemExit) as caught:
        Main(arguments)

    assert caught.value.code == 2 and not root.exists(), (
        "Every image source and authority reference is required before runtime setup"
    )


@pytest.mark.parametrize("options", [
    ["--profile", "native"], ["--report-format", "sarif"],
    ["--report-output", "new-report.json"], ["--json", "--events-json"],
    ["--registry", "synthetic-secret-shaped-value"],
])
def test_ImageUnsupportedOrAmbiguousArgumentsDoNotEchoValues(tmp_path, capsys, options):
    """Reject native/provider extension and ambiguous presentation before selected-file access."""

    with pytest.raises(SystemExit) as caught:
        Main([*ImageArguments(tmp_path / "absent"), *options])

    output = capsys.readouterr()
    assert caught.value.code == 2 and "synthetic-secret-shaped-value" not in output.err, (
        "Untrusted unsupported arguments must stay out of diagnostics"
    )
    assert not (tmp_path / "absent").exists(), "Parse refusal must precede local state mutation"


@pytest.mark.parametrize("option,value", [
    ("--archive", "relative.tar"), ("--executable", "relative-python"),
    ("--producer", "relative-worker.py"), ("--material", "relative-policy.json"),
    ("--timeout", "0"), ("--timeout", "61"), ("--read-consent-reference", ""),
])
def test_ImageInvalidSelectionFailsBeforeWorkspaceRead(tmp_path, capsys, option, value):
    """Selection paths, consent and SDK integer limits fail without inventing runtime state."""

    assert Main([*ImageArguments(tmp_path / "absent"), option, value, "--json"]) == 2, (
        "Invalid selections and deadlines must remain configuration refusal"
    )
    document = json.loads(capsys.readouterr().out)
    assert document["failure"]["code"] == "invalid_configuration", (
        "Configuration refusal must not be relabelled as an empty successful scan"
    )
    assert not (tmp_path / "absent").exists(), "Invalid selection must not create local state"


def test_ScopeManifestRulesRemainArtifactTargetsWithoutAutomaticConsent(tmp_path, capsys):
    """Literal manifest identities are registered through the existing canonical scope owner."""

    root = tmp_path / "workspace"
    assert Main(["workspace", "create", str(root), "--id", "images", "--name", "Images"]) == 0
    capsys.readouterr()
    allowed = "manifest-sha256:" + "a" * 64
    excluded = "manifest-sha256:" + "b" * 64
    assert Main(["scope", "create", str(root), "--id", "image-scope",
        "--allow-artifact", allowed, "--exclude-artifact", excluded, "--json"]) == 0
    capsys.readouterr()
    scope = LocalScopeStore(root).Open("image-scope")
    assert scope.targets[0].kind is TargetKind.ARTIFACT and scope.allow[0].value == allowed, (
        "Artifact manifest identity must never become an IP or HTTP target"
    )
    assert scope.exclusions[0].value == excluded, "Exclusions retain canonical manifest identity"
    assert scope.authorization.state is AuthorizationState.UNKNOWN, (
        "Artifact selection is not an approval or execution grant"
    )


@pytest.mark.parametrize("target", ["image.tar", "https://example.invalid/image.tar",
    "manifest-sha256:" + "A" * 64, "manifest-sha256:" + "a" * 63])
def test_ScopeRejectsPathsAndMalformedArtifactIdentities(tmp_path, capsys, target):
    """Artifact rules accept only the exact current canonical manifest-digest syntax."""

    root = tmp_path / "workspace"
    assert Main(["workspace", "create", str(root), "--id", "images", "--name", "Images"]) == 0
    capsys.readouterr()
    assert Main(["scope", "create", str(root), "--id", "image-scope",
        "--allow-artifact", target, "--json"]) == 2
    assert "invalid_configuration" in capsys.readouterr().out, "Malformed artifact is refused"

    with pytest.raises(OSError):
        LocalScopeStore(root).Open("image-scope")


def test_RegistryAdvertisesAvailableBoundedImageCapability():
    """Existing scan namespace advertises only the bounded capability it now dispatches."""

    command = COMMAND_REGISTRY.Resolve("scan")
    assert command is not None and "image" in command.usage, "Image CLI is discoverable"
    assert "image.archive-vulnerabilities" in command.capabilities, "SAFE image capability is named"
