# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Closed configuration CLI selections, output modes and refusal-before-I/O contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fuzzy1337.cli import Main
from fuzzy1337.command_registry import COMMAND_REGISTRY


def ConfigurationArguments(root: Path) -> list[str]:
    """Build inert explicit selections without reading sources or granting authority."""

    return ["scan", "config", str(root), "--profile", "synthetic", "--type", "dockerfile",
        "--logical-path", "Dockerfile", "--source", str(root / "Dockerfile"),
        "--scope", "config-scope", "--owner", "owner:test", "--executable", str(root / "python"),
        "--producer", str(root / "producer.py"), "--material", str(root / "policy.json"),
        "--read-consent-reference", "read:explicit"]


@pytest.mark.parametrize("option", [
    "--profile", "--type", "--logical-path", "--source", "--scope", "--owner", "--executable",
    "--producer", "--material", "--read-consent-reference",
])
def test_ConfigurationRequiresEveryExplicitSelectionBeforeMutation(tmp_path, option):
    """An omitted source/runtime/authority selection never becomes discovery or consent."""

    root = tmp_path / "absent"
    arguments = ConfigurationArguments(root)
    index = arguments.index(option)
    del arguments[index:index + 2]

    with pytest.raises(SystemExit) as caught:
        Main(arguments)

    assert caught.value.code == 2 and not root.exists(), (
        "Missing config inputs must be rejected before opening or creating local state"
    )


@pytest.mark.parametrize("options", [
    ["--profile", "native"], ["--type", "terraform"], ["--report-format", "sarif"],
    ["--report-output", "new.json"], ["--json", "--events-json"],
    ["--registry", "synthetic-secret-shaped-value"],
], ids=["native", "foreign-type", "format-only", "output-only", "two-modes", "unknown"])
def test_ConfigurationRejectsForeignOrAmbiguousArgumentsWithoutEcho(tmp_path, capsys, options):
    """Finite argument admission precedes sources and excludes untrusted values from errors."""

    with pytest.raises(SystemExit) as caught:
        Main([*ConfigurationArguments(tmp_path / "absent"), *options])

    output = capsys.readouterr()
    assert caught.value.code == 2 and "synthetic-secret-shaped-value" not in output.err, (
        "Rejected arbitrary option values must not enter CLI diagnostics"
    )
    assert not (tmp_path / "absent").exists(), "Parse refusal must not mutate workspace state"


@pytest.mark.parametrize("option,value", [
    ("--source", "relative-source"), ("--executable", "relative-python"),
    ("--producer", "relative-worker"), ("--material", "relative-policy"),
    ("--logical-path", "../Dockerfile"), ("--logical-path", ""),
    ("--read-consent-reference", ""), ("--timeout", "0"), ("--timeout", "61"),
], ids=["source", "runtime", "worker", "material", "parent", "empty", "consent", "low", "high"])
def test_ConfigurationInvalidSelectionsFailBeforeWorkspaceRead(tmp_path, capsys, option, value):
    """Relative sources, invalid logical names and out-of-bound deadlines cannot launch."""

    root = tmp_path / "absent"
    assert Main([*ConfigurationArguments(root), option, value, "--json"]) == 2, (
        "Invalid selected paths, read consent or deadlines must remain input refusal"
    )
    assert json.loads(capsys.readouterr().out)["failure"]["code"] == "invalid_configuration", (
        "Input refusal cannot be an empty successful configuration scan"
    )
    assert not root.exists(), "Rejected selection cannot create local state"


def test_ConfigurationHelpAndRegistryExposeOnlyImplementedClosedProfiles(capsys):
    """Discoverable help describes explicit selection and the two admitted SAFE capabilities."""

    with pytest.raises(SystemExit) as caught:
        Main(["scan", "config", "--help"])

    assert caught.value.code == 0, "Config help must be usable without an existing workspace"
    output = capsys.readouterr().out
    assert "--profile {synthetic,native}" in output and (
        "--type {dockerfile,kubernetes}" in output
    ), (
        "Help must expose both implemented native and synthetic source profiles"
    )
    assert "--approve-safe-configuration" in output, "SAFE execution approval stays explicit"
    command = COMMAND_REGISTRY.Resolve("scan")
    assert command is not None and "config" in command.usage, "Config dispatch is discoverable"
    assert {"config.dockerfile-misconfigurations", "config.kubernetes-misconfigurations"} <= (
        set(command.capabilities)
    ), "Registry must name both implemented configuration capabilities"
