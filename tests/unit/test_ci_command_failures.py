# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""CI parser preflight, safe diagnostics and isolated terminal consumer refusal."""

from __future__ import annotations

import io
import json
from dataclasses import replace

import pytest
from configuration_helpers import LiveConfiguration

import fuzzy1337.ci_commands as commands
from fuzzy1337.artifact_policy import ArtifactDenialReason, ArtifactDeniedError
from fuzzy1337.ci_commands import RequireSummary, RunCiCommands
from fuzzy1337.configuration_workflow import ConfigurationReportOutcome, ConfigurationScanSummary
from fuzzy1337.jobs import JobSnapshot, JobSpec, JobState
from fuzzy1337.report_commands import ReportFailure
from tests.ci_helpers import CiArguments, ImageCiArguments, InvokeCi
from tests.image_helpers import CreateOwnedImage


@pytest.mark.parametrize("mode", ["ack", "severity", "status", "negative", "large", "timeout",
                                  "existing", "same", "inside", "relative-source", "unknown"])
def test_InvalidExplicitSelectionRefusesBeforeAnyWorkflowLaunch(tmp_path, monkeypatch, mode):
    """Acknowledgement, typed predicates and all destinations preflight before execution."""

    root, selection, _ = LiveConfiguration(tmp_path)
    arguments = CiArguments(root, selection, tmp_path)

    if mode == "ack":
        arguments.remove("--acknowledge-unassessed-completeness")

    elif mode in {"severity", "status"}:
        arguments.extend(["--" + mode, "high" if mode == "severity" else "open"])

    elif mode in {"negative", "large"}:
        arguments[arguments.index("--max-matches") + 1] = "-1" if mode == "negative" else "1025"

    elif mode == "timeout":
        arguments.extend(["--timeout", "0"])

    elif mode == "existing":
        (tmp_path / "ci.xml").write_bytes(b"preserved owned output")

    elif mode == "same":
        arguments[arguments.index("--report-junit") + 1] = str(tmp_path / "ci.json")

    elif mode == "inside":
        arguments[arguments.index("--report-sarif") + 1] = str(root / "inside.sarif")

    elif mode == "relative-source":
        arguments[arguments.index("--source") + 1] = "relative-source"

    else:
        arguments.extend(["--credential-shaped-invalid", "sensitive-rejected-value"])

    async def Forbidden(*_args, **_kwargs):
        """Trip any execution request for inputs rejected by parser or preflight."""

        raise AssertionError("Invalid CI configuration reached workflow execution")

    monkeypatch.setattr(commands, "RunSyntheticConfigurationScan", Forbidden)
    status, outcome = InvokeCi(arguments)
    assert status == 2 and outcome["scan"] is None and outcome["status"] == "failed", (
        "Invalid explicit inputs must fail before launching an owned process or claiming criteria"
    )
    assert "sensitive-rejected-value" not in json.dumps(outcome), (
        "Rejected argument values cannot enter command diagnostics or retained machine output"
    )
    assert not (tmp_path / "ci.json").exists(), "Configuration refusal publishes no JSON artifact"


@pytest.mark.parametrize("error,status,failure", [
    (OSError("private storage detail"), 4, "scan"),
    (ValueError("private input detail"), 4, "scan"),
    (KeyboardInterrupt(), 130, "interrupted"),
    (RuntimeError("private unexpected detail"), 4, "internal"),
    (ReportFailure("owned-failure"), 4, "owned-failure"),
    (ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED), 3, "authorization"),
    (ArtifactDeniedError(ArtifactDenialReason.STORAGE), 4, "storage"),
])
def test_IsolatedWorkflowBoundaryFailureUsesStableSafeTaxonomy(
    tmp_path, monkeypatch, error, status, failure
):
    """Consumer exceptions use fixed classifications without opening sockets or running workers."""

    root, selection, _ = LiveConfiguration(tmp_path)

    async def Unexecuted(*_args, **_kwargs):
        """Declare a coroutine boundary without executing an actual scanner in unit tests."""

        return None

    def Drive(coroutine):
        """Close the unexecuted coroutine and inject only the declared boundary exception."""

        coroutine.close()

        raise error

    monkeypatch.setattr(commands, "RunSyntheticConfigurationScan", Unexecuted)
    monkeypatch.setattr(commands.asyncio, "run", Drive)
    observed, outcome = InvokeCi(CiArguments(root, selection, tmp_path))
    assert observed == status and outcome["failure"] == failure, (
        "Each isolated failure must preserve its documented terminal category"
    )
    assert "private" not in json.dumps(outcome) and outcome["criterion"]["status"] == (
        "indeterminate"
    ), "Private exception detail and failed work cannot become successful criterion evidence"


def TerminalSummary():
    """Create only isolated first-party terminal records for consumer shape tests."""

    snapshot = JobSnapshot(JobSpec("job:test", "ci-test", "scope:test", "owner:test",
        "synthetic.trivy"), JobState.COMPLETED, 1, None, None, (), False)

    return ConfigurationScanSummary(snapshot, "2026-10-14T10:00:00Z",
        "2026-10-14T10:00:01Z", 1.0, None, 1, (), (), ())


@pytest.mark.parametrize("mode", ["foreign", "state", "nonterminal", "cancel-request",
                                  "revision", "duration", "report", "report-count"])
def test_ForeignOrUncertainTerminalSummaryCannotReachGate(mode):
    """Exact terminal records and finite facts cannot be replaced by equal labels or bool values."""

    summary = TerminalSummary()

    if mode == "foreign":
        value = None

    elif mode in {"state", "nonterminal", "cancel-request"}:
        change = {"state": {"state": "completed"}, "nonterminal": {"state": JobState.RUNNING},
                  "cancel-request": {"cancellation_requested": True}}[mode]
        value = replace(summary, snapshot=replace(summary.snapshot, **change))

    elif mode == "revision":
        value = replace(summary, model_revision=True)

    elif mode == "duration":
        value = replace(summary, duration_seconds=float("nan"))

    elif mode == "report":
        value = replace(summary, report={})

    else:
        value = replace(summary, report=ConfigurationReportOutcome("completed", "json",
                        model_revision=True))

    with pytest.raises(ValueError):
        RequireSummary(value)


def test_HelpAndHumanOutputUseTheSameExplicitContract():
    """Help advertises explicit limits and acknowledgement; invalid human output remains safe."""

    output = io.StringIO()
    assert RunCiCommands(["--help"], output) == 0, "Read-only help must succeed without scanning"
    assert "--max-matches" in output.getvalue() and (
        "--acknowledge-unassessed-completeness" in output.getvalue()
    ), "Help must expose caller-selected criterion and acknowledged completeness limitations"
    output = io.StringIO()
    assert RunCiCommands(["invalid-sensitive-value"], output) == 2, (
        "Malformed product command must preserve status two"
    )
    assert "invalid-sensitive-value" not in output.getvalue() and "not assessed" in (
        output.getvalue()
    ), "Human output must preserve safe diagnostics and honest global completeness"


@pytest.mark.parametrize("profile,mode", [
    ("image", "source"), ("image", "logical"), ("image", "approval"), ("image", "missing-archive"),
    ("config", "archive"), ("config", "approval"), ("config", "missing-source"),
    ("config", "missing-logical"),
])
def test_CrossProfileInputsRefuseBeforeExecutionOrArtifactWrites(
    tmp_path, monkeypatch, profile, mode
):
    """Source/profile grammar and independent SAFE opt-ins cannot be silently ignored."""

    if profile == "image":
        arguments = ImageCiArguments(CreateOwnedImage(tmp_path), tmp_path)

        if mode == "missing-archive":
            position = arguments.index("--archive")
            del arguments[position:position + 2]

        else:
            additions = {"source": ["--source", str(tmp_path / "source")],
                "logical": ["--logical-path", "Dockerfile"],
                "approval": ["--approve-safe-configuration"]}
            arguments.extend(additions[mode])

    else:
        root, selection, _ = LiveConfiguration(tmp_path)
        arguments = CiArguments(root, selection, tmp_path)

        if mode in {"missing-source", "missing-logical"}:
            position = arguments.index("--source" if mode == "missing-source" else "--logical-path")
            del arguments[position:position + 2]

        else:
            arguments.extend(["--archive", str(tmp_path / "archive.tar")] if mode == "archive"
                             else ["--approve-safe-image"])

    async def Forbidden(*_args, **_kwargs):
        """Trip any workflow launch for incompatible explicit profile configuration."""

        raise AssertionError("Cross-profile inputs reached actual execution")

    monkeypatch.setattr(commands, "RunSyntheticConfigurationScan", Forbidden)
    monkeypatch.setattr(commands, "RunSyntheticImageScan", Forbidden)
    status, outcome = InvokeCi(arguments)
    assert status == 2 and outcome["scan"] is None and not (tmp_path / "ci.json").exists(), (
        "Cross-profile arguments must fail before any producer or artifact write"
    )
