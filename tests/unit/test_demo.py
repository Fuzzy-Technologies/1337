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
    assert demo.RunLocalDemo(tmp_path / "missing" / "root", output, json_output=True) == 3
    outcome = json.loads(output.getvalue())
    assert outcome["state"] == "denied" and not outcome["commands"]
    assert outcome["plan"]["routes"] == ["/", "/health", "/redirect"]
    assert outcome["plan"]["capabilities"] == ["http.endpoint-discovery"]
    assert not list(tmp_path.iterdir()), "Plan-only operation must not create local artifacts."
    human = StringIO()
    assert demo.RunLocalDemo(tmp_path / "demo", human) == 3
    assert "Explicit --approve-safe-http is required" in human.getvalue()


@pytest.mark.parametrize("suffix", ["../traversal", "control\nroot", "missing/root", "."])
def test_ApprovedUnsafePathsFailBeforeResourceStartup(tmp_path, monkeypatch, suffix) -> None:
    """An explicit approval does not authorize traversal, absent parents or existing paths."""

    def Unexpected(self) -> None:
        """Reject any target startup for an invalid destination."""

        pytest.fail("Invalid output path must reject before target startup")

    monkeypatch.setattr(demo.OwnedDemoTarget, "Start", Unexpected)
    output = StringIO()
    assert demo.RunLocalDemo(tmp_path / suffix, output, approve_safe_http=True,
                             json_output=True) == 2
    assert json.loads(output.getvalue())["phase"] == "configuration"
    assert not list(tmp_path.iterdir())


def test_ApprovalMustBeAnExplicitBoolean(tmp_path) -> None:
    """A truthy non-boolean SDK value is not an operator grant."""

    output = StringIO()
    assert demo.RunLocalDemo(tmp_path / "demo", output, approve_safe_http="yes",  # type: ignore
                             json_output=True) == 2
    assert not (tmp_path / "demo").exists()


def test_NewPhysicalRootValidationDoesNotCreateIt(tmp_path) -> None:
    """Valid path selection is separate from the later exclusive ownership acquisition."""

    root = tmp_path / "fresh root"
    assert demo.RequireNewDemoRoot(root) == root.absolute()
    assert not root.exists()


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
                             json_output=True) == 2
    assert not list(physical.iterdir())


@pytest.mark.parametrize("arguments", [[], ["remote", "root"], ["local"],
                                       ["local", "root", "--token=synthetic-secret"]])
@pytest.mark.parametrize("json_output", [False, True])
def test_ParserRejectsWithoutEchoingRejectedArguments(arguments, json_output) -> None:
    """Malformed command diagnostics cannot retain a secret-shaped rejected argument."""

    output = StringIO()
    assert RunDemoCommands(arguments, output, json_output=json_output) == 2
    assert "synthetic-secret" not in output.getvalue()

    if json_output:
        assert json.loads(output.getvalue())["failure"] == "configuration"


def test_LocalHelpDoesNotRequireOrCreateAnOutputRoot(tmp_path) -> None:
    """Parser help exposes the real explicit switch without running the demo."""

    output = StringIO()
    assert RunDemoCommands(["--help"], output) == 0
    assert "--approve-safe-http" in output.getvalue()
    assert not list(tmp_path.iterdir())


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

    assert caught.value.published is published
    assert artifacts == (["receipt.json"] if published else [])


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
    assert status == (130 if failure is KeyboardInterrupt else 4)
    assert outcome["target_teardown_completed"] is True
    assert outcome["phase"] == "target" and not outcome["commands"]
    assert json.loads((root / "target.json").read_bytes())["teardown_completed"] is True
    assert json.loads((root / "demo-summary.json").read_bytes()) == outcome
    assert "synthetic-startup-failure" not in output.getvalue()


def test_UrlsRequireActiveOwnedTargetAndCloseWithoutStartIsSafe() -> None:
    """No guessed target can escape the lifecycle and cleanup is safe before binding."""

    target = demo.OwnedDemoTarget()

    with pytest.raises(demo.DemoFailure, match="target"):
        target.Urls()

    target.Close()
    assert target.stopped

    with pytest.raises(OSError, match="restarted"):
        target.Start()


def test_EventRecorderPreservesExactLinesAndFlushesActualPresentation() -> None:
    """The journal retains product bytes while terminal updates reuse actual event data."""

    journal = StringIO()
    output = StringIO()
    events = demo.DemoEventOutput(journal, output, live=True)
    line = json.dumps({"type": "event", "event": {"sequence": 4, "kind": "model_delta",
                                                 "data": {"revision": 1}}}) + "\n"
    assert events.write(line[:5]) == 5
    events.flush()
    assert not output.getvalue()
    events.write(line[5:])
    events.flush()
    assert journal.getvalue() == events.getvalue() == line
    assert "4 model_delta" in output.getvalue()
    assert '"revision": 1' in output.getvalue()
