# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure approval, action routing and closed-profile assessment demo contracts."""

from __future__ import annotations

import json
from io import StringIO

import pytest

from fuzzy1337 import demo_assessment, demo_commands
from fuzzy1337.demo import DemoFailure, OwnedDemoTarget


@pytest.mark.parametrize("json_output", [False, True])
def test_UnapprovedAssessmentDoesNotInspectPathsOrStartResources(
    tmp_path, monkeypatch, json_output,
) -> None:
    """The complete useful plan/refusal precedes every filesystem, listener and product action."""

    def Unexpected(*args, **kwargs) -> None:
        """Refuse any resource acquisition before separate explicit STANDARD approval."""

        pytest.fail("Unapproved assessment must not inspect or acquire resources")

    monkeypatch.setattr(demo_assessment, "RequireNewDemoRoot", Unexpected)
    monkeypatch.setattr(demo_assessment.OwnedDemoTarget, "Start", Unexpected)
    monkeypatch.setattr(demo_assessment, "RunCommands", Unexpected)
    output = StringIO()
    status = demo_assessment.RunAssessmentDemo(
        tmp_path / "missing" / "root", output, json_output=json_output,
    )
    assert status == 3 and not list(tmp_path.iterdir()), (
        "Missing STANDARD approval must deny before paths, artifacts or network work"
    )

    if json_output:
        outcome = json.loads(output.getvalue())
        assert outcome["command"] == "demo.assessment" and outcome["state"] == "denied", (
            "The refused assessment must retain its own command and denial state"
        )
        assert outcome["commands"] == [] and outcome["artifacts"] == [], (
            "Unapproved planning must not claim acquired material or executed commands"
        )
        assert outcome["plan"] == demo_assessment.AssessmentDemoPlan(), (
            "The refusal must expose the exact finite STANDARD plan"
        )

    else:
        assert "--approve-standard-http" in output.getvalue(), (
            "Human plan presentation must identify the independent required approval"
        )


@pytest.mark.parametrize("approval", [1, 0, "yes", None, (), object()])
def test_OnlyExactBooleanStandardApprovalIsAccepted(tmp_path, approval) -> None:
    """Truthy values and integer booleans cannot be interpreted as operator authority."""

    output = StringIO()
    assert demo_assessment.RunAssessmentDemo(
        tmp_path / "demo", output, approve_standard_http=approval, json_output=True,
    ) == 2, "Non-boolean STANDARD approval must reject as configuration"
    assert not list(tmp_path.iterdir()), "Invalid approval must not create any demo output"
    assert json.loads(output.getvalue())["phase"] == "configuration", (
        "Invalid SDK approval must preserve its fixed configuration category"
    )


@pytest.mark.parametrize("suffix", ["../escape", "missing/root", "line\nbreak", "."])
def test_InvalidApprovedDestinationRejectsBeforeTargetStartup(
    tmp_path, monkeypatch, suffix,
) -> None:
    """STANDARD approval does not grant path traversal, absent-parent or overwrite authority."""

    def Unexpected(self) -> None:
        """Refuse startup when the selected physical root was not safely acquired."""

        pytest.fail("Invalid root must reject before target startup")

    monkeypatch.setattr(demo_assessment.OwnedDemoTarget, "Start", Unexpected)
    output = StringIO()
    assert demo_assessment.RunAssessmentDemo(
        tmp_path / suffix, output, approve_standard_http=True, json_output=True,
    ) == 2, "Invalid output selection must retain configuration status two"
    assert not list(tmp_path.iterdir()), "Invalid root must leave its selected parent unchanged"


@pytest.mark.parametrize("arguments", [
    ["assessment", "new", "--approve-safe-http"],
    ["assessment", "new", "--approve-safe-http", "--approve-standard-http"],
    ["local", "new", "--approve-standard-http"],
    ["assessment", "new", "--target", "https://unselected.invalid/private"],
])
def test_ActionSpecificApprovalAndClosedArgumentsCannotBeCrossGranted(
    monkeypatch, arguments,
) -> None:
    """Wrong approval modes and arbitrary target selection reject without dispatch or echoes."""

    def Unexpected(*args, **kwargs) -> int:
        """Refuse dispatch for an action whose independently required approval is invalid."""

        pytest.fail("Rejected approval or target arguments must prevent demo dispatch")

    monkeypatch.setattr(demo_commands, "RunLocalDemo", Unexpected)
    monkeypatch.setattr(demo_commands, "RunAssessmentDemo", Unexpected)
    output = StringIO()
    assert demo_commands.RunDemoCommands(arguments, output, json_output=True) == 2, (
        "Wrong action approval or arbitrary target arguments must reject"
    )
    document = json.loads(output.getvalue())
    assert document["state"] == "failed" and document["phase"] == "configuration", (
        "Invalid action flags must retain bounded truthful configuration failure"
    )
    assert "unselected.invalid" not in output.getvalue(), (
        "Rejected raw target text must never be reflected in demo diagnostics"
    )


@pytest.mark.parametrize("approved", [False, True])
def test_AssessmentDispatchPreservesItsIndependentExplicitApproval(tmp_path, monkeypatch, approved):
    """The existing root dispatcher reaches the separate assessment SDK without SAFE approval."""

    calls = []

    def Execute(path, output, *, approve_standard_http, json_output) -> int:
        """Record the exact selected SDK approval and output mode without resource work."""

        calls.append((path, approve_standard_http, json_output))

        return 0 if approve_standard_http else 3

    monkeypatch.setattr(demo_commands, "RunAssessmentDemo", Execute)
    arguments = ["assessment", str(tmp_path / "new")]

    if approved:
        arguments.append("--approve-standard-http")

    assert demo_commands.RunDemoCommands(arguments, StringIO(), json_output=True) == (
        0 if approved else 3
    ), "Action dispatch must preserve the assessment SDK's actual exit status"
    assert calls == [(tmp_path / "new", approved, True)], (
        "Assessment dispatch must bind the exact output and independent approval flag"
    )


def test_AssessmentProfileIsClosedAndDefaultDiscoveryRoutesAreUnchanged() -> None:
    """The fixture exposes two closed constant profiles and accepts only an exact bool selector."""

    assert OwnedDemoTarget().routes == ("/", "/health", "/redirect"), (
        "The existing SAFE demo target routes must remain unchanged"
    )
    assert OwnedDemoTarget(assessment=True).routes == ("/.git/HEAD", "/fixed/.git/HEAD"), (
        "The assessment target must select only its two known-answer routes"
    )

    with pytest.raises(DemoFailure):
        OwnedDemoTarget(assessment=1)


@pytest.mark.parametrize("receipt", [{}, {"state": "completed"}, {
    "state": "completed", "check_id": "native.git-head-exposure", "job": {"state": "completed"},
}])
def test_IncompleteExecutionReceiptCannotEstablishAssessmentTruth(tmp_path, receipt) -> None:
    """Missing execution identity cannot cause owner reads or manufacture a successful check."""

    with pytest.raises(DemoFailure):
        demo_assessment.ReadAssessmentExecution(
            tmp_path / "missing", "http://127.0.0.1:1234/.git/HEAD", receipt, matched=True,
        )
