# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit native image CLI grammar and shared product dispatch over controlled original wire."""

from __future__ import annotations

import io
import json
import shlex
from pathlib import Path

import pytest

from fuzzy1337 import native_image_workflow as product
from fuzzy1337 import scan_commands
from fuzzy1337.adapters import SerializeContract
from fuzzy1337.artifact_policy import ArtifactDenialReason, ArtifactDeniedError
from fuzzy1337.cli import Main
from fuzzy1337.command_registry import COMMAND_REGISTRY
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_image_observation import NativeImageObservationError
from fuzzy1337.shell import InteractiveShell
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.unit.test_native_image_policy import AT
from tests.unit.test_native_image_policy import authority as authority
from tests.unit.test_native_image_policy import collector as collector
from tests.unit.test_native_image_policy import material_control as material_control
from tests.unit.test_native_image_policy import observation_runner as observation_runner
from tests.unit.test_native_image_policy import simulated_observer as simulated_observer


def NativeArguments(root: Path) -> list[str]:
    """Select native inputs without deriving read consent or execution permission."""

    return ["scan", "image", str(root), "--profile", "native", "--owner", "actor:unit",
        "--archive", "image.tar", "--cache-directory", "cache", "--executable",
        str(root / "trivy"), "--read-consent-reference", "read:explicit"]


@pytest.mark.parametrize("option", ["--profile", "--owner", "--archive", "--executable",
    "--cache-directory", "--read-consent-reference"])
def test_NativeRequiredInputsRefuseBeforeWorkspaceRead(tmp_path, option):
    """An explicit native profile still requires every independent selected input."""

    root = tmp_path / "absent"
    arguments = NativeArguments(root)
    index = arguments.index(option)
    del arguments[index:index + 2]
    with pytest.raises(SystemExit) as caught:
        Main([*arguments, "--plan"])
    assert caught.value.code == 2 and not root.exists(), (
        "Missing native inputs must refuse before constructing any workspace state."
    )


@pytest.mark.parametrize("options", [[], ["--scope", "native-unit", "--plan"],
    ["--policy", "policy.json", "--plan"], ["--producer", "producer.py", "--plan"],
    ["--material", "material.json", "--plan"], ["--plan", "--approve-safe-image"],
    ["--plan", "--events-json"],
    ["--plan", "--report-format", "json", "--report-output", "report.json"]])
def test_NativeAmbiguousAuthorityAndSyntheticInputsRefuseBeforeReads(tmp_path, options):
    """Preview requires both authority arguments absent and excludes execution options."""

    root = tmp_path / "absent"
    with pytest.raises(SystemExit) as caught:
        Main([*NativeArguments(root), *options])
    assert caught.value.code == 2 and not root.exists(), (
        "Neither a partial authority declaration nor mixed profile may become preview."
    )


@pytest.mark.parametrize("option,value", [("--archive", "a//b.tar"),
    ("--archive", "./image.tar"), ("--archive", "../image.tar"),
    ("--archive", "/absolute/image.tar"), ("--cache-directory", "cache//db"),
    ("--cache-directory", "cache/../db"), ("--timeout", "0"), ("--timeout", "3601"),
    ("--executable", "relative-trivy"), ("--read-consent-reference", "")])
def test_NativeRawSelectionSpellingIsValidatedBeforeWorkspaceRead(tmp_path, capsys, option, value):
    """Path normalization cannot hide an invalid original native archive or cache spelling."""

    root = tmp_path / "absent"
    assert Main([*NativeArguments(root), option, value, "--plan", "--json"]) == 2, (
        "Native lexical and finite-limit errors must remain configuration refusal."
    )
    assert json.loads(capsys.readouterr().out)["failure"]["code"] == "invalid_configuration", (
        "Rejected original syntax must not be relabelled as a missing workspace."
    )
    assert not root.exists(), "Invalid original selections must not initialize a workspace."


@pytest.fixture
def native_cli(authority, monkeypatch):
    """Use real product owners with the existing explicitly controlled process wire."""

    root = authority.root
    LocalModelStore(root).Create()
    policy = root / "explicit-policy.json"
    policy.write_text(SerializeContract(authority.context.policy), encoding="utf-8")
    monkeypatch.setattr(scan_commands.asyncio, "run", authority.collector.run)
    original_plan = product.PlanNativeImageScan
    original_scan = product.ScanNativeImage

    async def Plan(*args, **kwargs):
        """Keep the canonical planner while selecting the fixture's deterministic clock."""

        return await original_plan(*args, **kwargs, clock=lambda: AT)

    async def Scan(*args, **kwargs):
        """Keep the canonical paired workflow while selecting the same deterministic clock."""

        return await original_scan(*args, **kwargs, clock=lambda: AT)

    monkeypatch.setattr(product, "PlanNativeImageScan", Plan)
    monkeypatch.setattr(product, "ScanNativeImage", Scan)
    return authority, policy


def test_NativePreviewAndScopedPlanNeverRunTrivyOrEnrollAuthority(native_cli, capsys):
    """Both CLI planning phases return descriptive exact targets without claims or engine calls."""

    authority, policy = native_cli
    root = authority.root
    before = LocalWorkspaceStore(root).Open()
    arguments = NativeArguments(root)
    assert Main([*arguments, "--plan", "--json"]) == 0, "Explicit preview must be available."
    preview = json.loads(capsys.readouterr().out)
    assert preview["phase"] == "material-preview" and not preview["execution_authorized"], (
        "Unscoped material facts must never masquerade as execution authorization."
    )
    assert Main([*arguments, "--scope", "native-unit", "--policy", str(policy),
                 "--plan", "--json"]) == 0, "Both authority arguments select the scoped plan."
    plan = json.loads(capsys.readouterr().out)
    assert plan["phase"] == "scoped-version-plan" and plan["target"] == preview["target"], (
        "Scoped planning must retain the exact already registered INPUT manifest identity."
    )
    assert plan["version_invocation"]["provider_version"] is None, (
        "An unexecuted VERSION invocation cannot acquire a made-up tool version."
    )
    assert not authority.collector.state.calls and not (root / "native-image-claims").exists(), (
        "Neither native plan phase may execute the selected engine or reserve a grant."
    )
    assert LocalWorkspaceStore(root).Open() == before, "Planning must not enroll scope or evidence."


@pytest.mark.parametrize("presentation", ["json", "events", "shell"])
def test_NativeSharedCliRunsRealOwnersWithDistinctConsentAndPreservesSummary(
    native_cli, capsys, presentation,
):
    """Shared CLI and shell preserve canonical original pairs, model state and ordered events."""

    authority, policy = native_cli
    arguments = [*NativeArguments(authority.root), "--scope", "native-unit", "--policy",
                 str(policy), "--approve-safe-image"]
    if presentation == "shell":
        output = io.StringIO()
        shell = InteractiveShell(stdout=output)
        shell.RunLocalCommand("scan", shlex.join(arguments[1:]))
        assert "Native Image Scan completed; model revision 1; evidence records 6" in (
            output.getvalue()), "The shell must dispatch the same explicit native profile."
        document = None
    else:
        assert Main([*arguments, "--events-json" if presentation == "events" else "--json"]) == 0, (
            "The explicit native route must complete through the existing canonical owners."
        )
        rows = [json.loads(row) for row in capsys.readouterr().out.splitlines()]
        document = rows[-1]["summary"] if presentation == "events" else rows[-1]
        if presentation == "events":
            assert all(row["type"] == "event" for row in rows[:-1]), (
                "Event streaming must contain only structured actual events before the summary."
            )
    if document is not None:
        assert document["workflow"] == "native-image" and document["state"] == "completed", (
            "Native dispatch cannot use a synthetic product summary or completion claim."
        )
        assert len(document["retained_evidence_ids"]) == 6, (
            "Each original role must stay available."
        )
    assert len(authority.collector.state.calls) == 2, (
        "Original VERSION must precede exactly one SCAN."
    )
    assert LocalModelStore(authority.root).Open().revision == 1, "The paired model save is durable."
    assert len(LocalWorkspaceStore(authority.root).Open().evidence_record_references) == 6, (
        "The explicit read record and independent actor must survive the entire original pair."
    )


def test_NativeApprovalAndFreshPolicyRemainIndependent(native_cli, capsys):
    """Existing permission cannot manufacture product approval or survive revocation."""

    authority, policy = native_cli
    arguments = [*NativeArguments(authority.root), "--scope", "native-unit",
                 "--policy", str(policy)]
    assert Main([*arguments, "--json"]) == 3, "Read consent and policy do not approve execution."
    assert json.loads(capsys.readouterr().out)["failure"]["code"] == "authorization", (
        "Typed native refusal must not be caught as a generic storage error."
    )
    policy.write_text(SerializeContract(product.ImpactPolicy("denied")), encoding="utf-8")
    assert Main([*arguments, "--plan", "--json"]) == 3, (
        "Denied scoped planning cannot become preview."
    )
    capsys.readouterr()
    assert Main([*arguments, "--approve-safe-image", "--json"]) == 3, (
        "Explicit approval cannot replace a freshly reread native capability permission."
    )
    assert not authority.collector.state.calls, "Denied native authority must execute no engine."


@pytest.mark.parametrize("failure,code", [("observer", "provider"), ("storage", "storage")])
def test_NativePlanUnavailableAndStorageErrorsHaveSanitizedTruth(tmp_path, capsys, monkeypatch,
                                                               failure, code):
    """Unavailable material and storage denial remain structured sanitized failures."""

    async def Plan(*args, **kwargs):
        """Inject only typed closed errors without establishing positive engine acceptance."""

        if failure == "observer":
            raise NativeImageObservationError("private-selected-path")
        raise ArtifactDeniedError(ArtifactDenialReason.STORAGE)

    monkeypatch.setattr(product, "PlanNativeImageScan", Plan)
    assert Main([*NativeArguments(tmp_path), "--plan", "--json"]) == 4, (
        "Unknown material custody or storage must never produce an empty successful plan."
    )
    output = capsys.readouterr().out
    assert json.loads(output)["failure"]["code"] == code and (
        "private-selected-path" not in output
    ), (
        "The CLI must retain sanitized failure categories without selected content or paths."
    )


def test_ImageHelpDescribesBothExplicitProfilesWithoutImplicitProvider(capsys):
    """Profile requirements are discoverable without executing selected providers."""

    with pytest.raises(SystemExit) as caught:
        Main(["scan", "image", "--help"])
    help_text = capsys.readouterr().out
    assert caught.value.code == 0 and "{synthetic,native}" in help_text, (
        "Help must list both explicit image profiles without changing the required selection."
    )
    assert "--cache-directory" in help_text and "--policy" in help_text and "--plan" in help_text, (
        "Native material, authority and read-only planning options must remain discoverable."
    )
    assert "synthetic/native images" in COMMAND_REGISTRY.Resolve("scan").summary, (
        "The shared command descriptor must describe both actual image routes."
    )
