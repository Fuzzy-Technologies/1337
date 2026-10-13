# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure demo approval, path, parser and partial-publication failure contracts."""

from __future__ import annotations

import json
from io import StringIO

import pytest

from fuzzy1337 import demo
from fuzzy1337.demo_commands import RunDemoCommands
from fuzzy1337.report_commands import ReportFailure


def test_UnapprovedPlanDoesNotInspectPathOrStartResources(tmp_path, monkeypatch) -> None:
    """A useful denied plan must precede all filesystem and target work, even for invalid paths."""

    def Unexpected(*args, **kwargs) -> None:
        """Fail if a plan-only invocation attempts to inspect or acquire a resource."""

        pytest.fail("A denied plan must not inspect paths or start resources")

    monkeypatch.setattr(demo, "RequireNewDemoRoot", Unexpected)
    monkeypatch.setattr(demo.OwnedDemoTarget, "Start", Unexpected)
    output = StringIO()
    assert demo.RunLocalDemo(tmp_path / "missing" / "root", output, json_output=True) == 3, (
        "A plan without explicit approval must return denial status three."
    )
    outcome = json.loads(output.getvalue())
    assert outcome["state"] == "denied" and not outcome["commands"], (
        "A denied plan must retain no executed product command receipts."
    )
    assert outcome["plan"]["routes"] == ["/", "/health", "/redirect"], (
        "The plan must enumerate only the three fixed synthetic routes."
    )
    assert outcome["plan"]["capabilities"] == ["http.endpoint-discovery"], (
        "The plan may approve only native endpoint discovery."
    )
    assert not list(tmp_path.iterdir()), "Plan-only operation must not create local artifacts."
    human = StringIO()
    assert demo.RunLocalDemo(tmp_path / "demo", human) == 3, (
        "Human plan presentation must preserve the same denial status."
    )
    assert "Explicit --approve-safe-http is required" in human.getvalue(), (
        "Human output must identify the separate required approval switch."
    )


@pytest.mark.parametrize("suffix", ["../traversal", "control\nroot", "missing/root", "."])
def test_ApprovedUnsafePathsFailBeforeResourceStartup(tmp_path, monkeypatch, suffix) -> None:
    """An explicit approval does not authorize traversal, absent parents or existing paths."""

    def Unexpected(self) -> None:
        """Reject any target startup for an invalid destination."""

        pytest.fail("Invalid output path must reject before target startup")

    monkeypatch.setattr(demo.OwnedDemoTarget, "Start", Unexpected)
    output = StringIO()
    assert demo.RunLocalDemo(tmp_path / suffix, output, approve_safe_http=True,
                             json_output=True) == 2, (
        "Unsafe output selection must fail configuration before startup."
    )
    assert json.loads(output.getvalue())["phase"] == "configuration", (
        "Unsafe paths must retain an explicit configuration failure phase."
    )
    assert not list(tmp_path.iterdir()), (
        "Invalid output paths must leave the selected parent untouched."
    )


def test_ApprovalMustBeAnExplicitBoolean(tmp_path) -> None:
    """A truthy non-boolean SDK value is not an operator grant."""

    output = StringIO()
    assert demo.RunLocalDemo(tmp_path / "demo", output, approve_safe_http="yes",  # type: ignore
                             json_output=True) == 2, (
        "Truthy non-boolean SDK values cannot grant SAFE HTTP approval."
    )
    assert not (tmp_path / "demo").exists(), (
        "Invalid SDK approval must not create the demo output root."
    )


def test_NewPhysicalRootValidationDoesNotCreateIt(tmp_path) -> None:
    """Valid path selection is separate from the later exclusive ownership acquisition."""

    root = tmp_path / "fresh root"
    assert demo.RequireNewDemoRoot(root) == root.absolute(), (
        "Valid selection must return the exact absolute physical root."
    )
    assert not root.exists(), (
        "Pure path validation must not acquire the output directory."
    )


def test_SymlinkParentRejectsWithoutFollowingOrStarting(tmp_path) -> None:
    """The demo cannot reinterpret a selected path through a link to another directory."""

    physical = tmp_path / "physical"
    physical.mkdir()
    linked = tmp_path / "linked"

    try:
        linked.symlink_to(physical, target_is_directory=True)

    except OSError:
        pytest.skip("Creating directory symlinks is unavailable on this host")

    output = StringIO()
    assert demo.RunLocalDemo(linked / "demo", output, approve_safe_http=True,
                             json_output=True) == 2, (
        "A linked parent must fail configuration before target startup."
    )
    assert not list(physical.iterdir()), (
        "Rejected symlink traversal must not modify its physical target."
    )


@pytest.mark.parametrize("arguments", [[], ["remote", "root"], ["local"],
                                       ["local", "root", "--token=synthetic-secret"]])
@pytest.mark.parametrize("json_output", [False, True])
def test_ParserRejectsWithoutEchoingRejectedArguments(arguments, json_output) -> None:
    """Malformed command diagnostics cannot retain a secret-shaped rejected argument."""

    output = StringIO()
    assert RunDemoCommands(arguments, output, json_output=json_output) == 2, (
        "Malformed demo arguments must return configuration status two."
    )
    assert "synthetic-secret" not in output.getvalue(), (
        "Rejected secret-shaped arguments must not enter diagnostics."
    )

    if json_output:
        assert json.loads(output.getvalue())["failure"] == "configuration", (
            "JSON parse rejection must retain its configuration category."
        )


def test_LocalHelpDoesNotRequireOrCreateAnOutputRoot(tmp_path) -> None:
    """Parser help exposes the real explicit switch without running the demo."""

    output = StringIO()
    assert RunDemoCommands(["--help"], output) == 0, (
        "Local demo help must succeed without a selected output root."
    )
    assert "--approve-safe-http" in output.getvalue(), (
        "Parser help must expose the explicit SAFE HTTP approval option."
    )
    assert not list(tmp_path.iterdir()), (
        "Help presentation must leave local filesystem state untouched."
    )


@pytest.mark.parametrize("published", [False, True])
def test_ArtifactPublicationFailureRetainsOwnerAcknowledgement(tmp_path, monkeypatch,
                                                              published) -> None:
    """A lost post-link acknowledgement must not be converted into missing or successful output."""

    def Fail(destination, payload) -> None:
        """Raise the report owner's fixed publication failure with its actual acknowledgement."""

        raise ReportFailure("publication", published=published)

    monkeypatch.setattr(demo, "PublishReport", Fail)
    artifacts = []

    with pytest.raises(ReportFailure) as caught:
        demo.SaveDemoArtifact(tmp_path, "receipt.json", {"actual": True}, artifacts)

    assert caught.value.published is published, (
        "Publication failure must preserve the report owner acknowledgement."
    )
    assert artifacts == (["receipt.json"] if published else []), (
        "Only confirmed published material may enter the artifact index."
    )


@pytest.mark.parametrize("failure", [OSError, RuntimeError, KeyboardInterrupt])
def test_TargetStartupFailureRetainsPartialOutcomeAndAttemptsCleanup(tmp_path, monkeypatch,
                                                                    failure) -> None:
    """Startup problems and interruption still write truthful receipts after resource cleanup."""

    def Fail(self) -> None:
        """Inject startup failure before any synthetic service exists."""

        raise failure("synthetic-startup-failure")

    monkeypatch.setattr(demo.OwnedDemoTarget, "Start", Fail)
    root = tmp_path / "demo"
    output = StringIO()
    status = demo.RunLocalDemo(root, output, approve_safe_http=True, json_output=True)
    outcome = json.loads(output.getvalue())
    assert status == (130 if failure is KeyboardInterrupt else 4), (
        "Startup interruption and startup failure must retain distinct statuses."
    )
    assert outcome["target_teardown_completed"] is True, (
        "Startup failure must still confirm owned target cleanup."
    )
    assert outcome["phase"] == "target" and not outcome["commands"], (
        "A startup failure must not invent successful product command receipts."
    )
    assert json.loads((root / "target.json").read_bytes())["teardown_completed"] is True, (
        "The retained target receipt must confirm actual cleanup."
    )
    assert json.loads((root / "demo-summary.json").read_bytes()) == outcome, (
        "The saved startup outcome must match the terminal outcome."
    )
    assert "synthetic-startup-failure" not in output.getvalue(), (
        "Raw startup exception text must remain outside diagnostics."
    )


def test_UrlsRequireActiveOwnedTargetAndCloseWithoutStartIsSafe() -> None:
    """No guessed target can escape the lifecycle and cleanup is safe before binding."""

    target = demo.OwnedDemoTarget()

    with pytest.raises(demo.DemoFailure, match="target"):
        target.Urls()

    target.Close()
    assert target.stopped, (
        "Closing an unstarted target must complete its owned lifecycle."
    )

    with pytest.raises(OSError, match="restarted"):
        target.Start()


def test_EventRecorderPreservesExactLinesAndFlushesActualPresentation() -> None:
    """The journal retains product bytes while terminal updates reuse actual event data."""

    journal = StringIO()
    output = StringIO()
    events = demo.DemoEventOutput(journal, output, live=True)
    line = json.dumps({"type": "event", "event": {"sequence": 4, "kind": "model_delta",
                                                 "data": {"revision": 1}}}) + "\n"
    assert events.write(line[:5]) == 5, (
        "The recorder must report the exact accepted character count."
    )
    events.flush()
    assert not output.getvalue(), (
        "Partial event lines must not be presented before completion."
    )
    events.write(line[5:])
    events.flush()
    assert journal.getvalue() == events.getvalue() == line, (
        "The journal and recorder must preserve the exact original event line."
    )
    assert "4 model_delta" in output.getvalue(), (
        "Live presentation must reuse the actual event sequence and kind."
    )
    assert '"revision": 1' in output.getvalue(), (
        "Live presentation must retain the actual saved-model revision."
    )
