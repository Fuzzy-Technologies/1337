# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Native configuration CLI/shell contracts with explicit original process and proof doubles."""

from __future__ import annotations

import io
import json
import shlex
from pathlib import Path

import pytest

from fuzzy1337 import native_configuration_workflow as product
from fuzzy1337 import scan_commands
from fuzzy1337.adapters import SerializeContract
from fuzzy1337.artifact_policy import ArtifactDenialReason, ArtifactDeniedError
from fuzzy1337.cli import Main
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_configuration_material import NativeConfigurationMaterialError
from fuzzy1337.policy import ImpactPolicy
from fuzzy1337.shell import InteractiveShell
from tests.unit.test_native_configuration_workflow import (
    configuration_runner as configuration_runner,
)
from tests.unit.test_native_configuration_workflow import controlled_runtime as controlled_runtime


def NativeArguments(root: Path, selection=None) -> list[str]:
    """Build only explicitly selected native source/provider/read-consent declarations."""

    return ["scan", "config", str(root), "--profile", "native", "--type", "dockerfile",
        "--logical-path", "Dockerfile", "--source", str(root / "Dockerfile" if selection is None
        else selection.source), "--owner", "owner:unit", "--executable",
        str(root / "trivy" if selection is None else selection.executable),
        "--read-consent-reference", "read:unit"]


@pytest.mark.parametrize("option", ["--profile", "--type", "--logical-path", "--source", "--owner",
                                   "--executable", "--read-consent-reference"])
def test_NativeRequiredSelectionsRefuseBeforeWorkspaceAccess(tmp_path, option):
    """Missing selected source/provider/owner inputs cannot trigger discovery or reads."""

    root = tmp_path / "absent"
    arguments = NativeArguments(root)
    index = arguments.index(option)
    del arguments[index:index + 2]

    with pytest.raises(SystemExit) as error:
        Main([*arguments, "--plan"])

    assert error.value.code == 2 and not root.exists(), "Missing selections must refuse before IO"


@pytest.mark.parametrize("options", [[], ["--scope", "owned", "--plan"],
    ["--policy", "policy.json", "--plan"], ["--producer", "worker.py", "--plan"],
    ["--material", "policy.json", "--plan"], ["--plan", "--approve-safe-configuration"],
    ["--plan", "--events-json"],
    ["--plan", "--report-format", "json", "--report-output", "r.json"]])
def test_NativeMixedOrIncompleteAuthorityRefusesBeforeReads(tmp_path, options):
    """Native preview and execution keep synthetic inputs and independent authority unambiguous."""

    root = tmp_path / "absent"

    with pytest.raises(SystemExit) as error:
        Main([*NativeArguments(root), *options])

    assert error.value.code == 2 and not root.exists(), "Mixed declarations must refuse before IO"


@pytest.mark.parametrize("option,value", [("--source", "relative-source"),
    ("--executable", "relative-executable"), ("--logical-path", "../Dockerfile"),
    ("--logical-path", ""), ("--read-consent-reference", ""), ("--timeout", "0"),
    ("--timeout", "61")])
def test_NativeLexicalErrorsRemainSanitizedInputRefusals(tmp_path, capsys, option, value):
    """Pure native selection admission precedes owning workspace reads and process launch."""

    root = tmp_path / "absent"
    assert Main([*NativeArguments(root), option, value, "--plan", "--json"]) == 2, (
        "Invalid original native syntax must remain an input refusal"
    )
    assert json.loads(capsys.readouterr().out)["failure"]["code"] == "invalid_configuration", (
        "Selected syntax refusal cannot be relabelled as missing workspace storage"
    )
    assert not root.exists(), "Invalid selected paths must not initialize workspace state"


@pytest.fixture
def native_cli(controlled_runtime, configuration_runner, monkeypatch):
    """Use the actual native SDK owners with explicit unit process/material originals."""

    root, selection, context, settings = controlled_runtime
    policy = root / "explicit-policy.json"
    policy.write_text(SerializeContract(context.policy))
    monkeypatch.setattr(scan_commands.asyncio, "run", configuration_runner.run)

    return root, selection, policy, settings


@pytest.mark.parametrize("presentation", ["json", "events", "shell"])
def test_NativeProductDispatchUsesSameGovernedOwners(native_cli, capsys, presentation):
    """CLI, JSON events and shell share original VERSION/SCAN and canonical persistence."""

    root, selection, policy, settings = native_cli
    arguments = [*NativeArguments(root, selection), "--scope", "native-scope", "--policy",
                 str(policy), "--approve-safe-configuration"]

    if presentation == "shell":
        output = io.StringIO()
        shell = InteractiveShell(stdout=output)
        shell.RunLocalCommand("scan", shlex.join(arguments[1:]))
        assert "Native Configuration Scan completed; model revision 1; evidence records 7" in (
            output.getvalue()
        ), "Shell must dispatch the exact implemented native configuration route"

    else:
        assert Main([*arguments, "--events-json" if presentation == "events" else "--json"]) == 0, (
            "Native CLI must complete through canonical SDK authority/evidence/model owners"
        )
        rows = [json.loads(row) for row in capsys.readouterr().out.splitlines()]
        document = rows[-1]["summary"] if presentation == "events" else rows[-1]
        assert document["workflow"] == "native-configuration" and (
            document["state"] == "completed"
        ), (
            "Native dispatch must retain native source and terminal facts"
        )

    assert settings["calls"] == ["version", "scan"] and (
        LocalModelStore(root).Open().revision == 1
    ), (
        "Every route must preserve one actual original component pair and one acknowledged save"
    )


def test_NativePreviewAliasAndFreshPolicyRemainSeparate(native_cli, capsys):
    """The type alias, descriptive preview, explicit opt-in and fresh policy remain independent."""

    root, selection, policy, settings = native_cli
    arguments = NativeArguments(root, selection)
    arguments[arguments.index("--type")] = "--kind"
    assert Main([*arguments, "--plan", "--json"]) == 0, "Explicit kind alias must support preview"
    preview = json.loads(capsys.readouterr().out)
    assert preview["execution_authorized"] is False and settings["calls"] == [], (
        "Read-authorized preview must never execute Trivy or register authority"
    )
    arguments += ["--scope", "native-scope", "--policy", str(policy)]
    assert Main([*arguments, "--json"]) == 3, "Policy cannot manufacture workflow approval"
    capsys.readouterr()
    policy.write_text(SerializeContract(ImpactPolicy("revoked-native-config")))
    assert Main([*arguments, "--approve-safe-configuration", "--json"]) == 3, (
        "Explicit workflow opt-in cannot replace a freshly reread native permission"
    )
    assert settings["calls"] == [], "Refused policy/approval must reach no native provider"


@pytest.mark.parametrize("failure,code", [("material", "provider"), ("storage", "storage")])
def test_NativePlanFailurePreservesSanitizedCategory(tmp_path, capsys, monkeypatch, failure, code):
    """Typed material/storage failures expose truthful categories without private selected paths."""

    async def Plan(*args, **options):
        """Raise an explicit typed unit failure without claiming positive provider execution."""

        if failure == "material":
            raise NativeConfigurationMaterialError("private-selected-source")

        raise ArtifactDeniedError(ArtifactDenialReason.STORAGE)

    monkeypatch.setattr(product, "PlanNativeConfigurationScan", Plan)
    assert Main([*NativeArguments(tmp_path), "--plan", "--json"]) == 4, (
        "Unknown selected material or storage must not become successful preview"
    )
    output = capsys.readouterr().out
    assert json.loads(output)["failure"]["code"] == code and (
        "private-selected-source" not in output
    ), (
        "Native plan diagnostics must preserve categories without disclosing selected content"
    )
