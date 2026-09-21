"""Tests for shell behavior."""

from __future__ import annotations

from io import StringIO

import pytest

from fuzzy1337.shell import ContextualAction, FuzzyMatches, InteractiveShell, WorkbenchUpdate


def test_FuzzyMatchesPrioritizeCompactSubsequences():
    """Verify fuzzy matches prioritize compact subsequences."""

    assert FuzzyMatches("ct", ("context", "commands", "select")) == ("context", "select"), (
        "fuzzy matches prioritize compact subsequences invariant failed."
    )
    assert FuzzyMatches("", ("select", "commands")) == ("commands", "select"), (
        "fuzzy matches prioritize compact subsequences invariant failed."
    )
    assert FuzzyMatches("missing", ("context", "commands")) == (), (
        "fuzzy matches prioritize compact subsequences invariant failed."
    )


def test_ShellTracksLensSelectedObjectAndUpdates():
    """Verify shell tracks lens selected object and updates."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)

    shell.onecmd("lens devsecops")
    shell.onecmd("view updates")
    shell.onecmd("select asset:demo")
    shell.PublishUpdate(WorkbenchUpdate("progress", "discovery queued"))
    shell.onecmd("context")
    shell.onecmd("updates")

    assert shell.State.lens == "devsecops", (
        "shell tracks lens selected object and updates invariant failed."
    )
    assert shell.State.view == "updates", (
        "shell tracks lens selected object and updates invariant failed."
    )
    assert shell.State.selectedObject == "asset:demo", (
        "shell tracks lens selected object and updates invariant failed."
    )
    assert output.getvalue().splitlines() == [
        "Selected lens: devsecops",
        "Selected view: updates",
        "Selected object: asset:demo",
        "Lens: devsecops",
        "View: updates",
        "Selected object: asset:demo",
        "Pending updates: 1",
        "[progress] discovery queued",
    ], "shell tracks lens selected object and updates invariant failed."


def test_ShellCompletionAndUnknownCommandsAreDeterministic():
    """Verify shell completion and unknown commands are deterministic."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)

    assert shell.completenames("ct") == ["context", "select"], (
        "shell completion and unknown commands are deterministic invariant failed."
    )
    shell.onecmd("lens unknown")
    shell.onecmd("scan authorized.example")

    assert output.getvalue().splitlines() == [
        "Unknown lens: unknown. Available lenses: pentest, dfir, devsecops, purple",
        "Unknown command: scan authorized.example. Type 'help' for commands.",
    ], "shell completion and unknown commands are deterministic invariant failed."


def test_ShellHelpAndUsageErrorsRemainCompact():
    """Verify shell help and usage errors remain compact."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)

    shell.onecmd("commands extra")
    shell.onecmd("context extra")
    shell.onecmd("help lens")
    shell.onecmd("help unknown")
    shell.onecmd("lens")
    shell.onecmd("select")
    shell.onecmd("updates extra")
    shell.onecmd("view")
    shell.onecmd("view unknown")

    assert output.getvalue().splitlines() == [
        "usage: commands",
        "usage: context",
        "lens <name>: select pentest, dfir, devsecops, or purple.",
        "No shell help for: unknown",
        "Available lenses: pentest, dfir, devsecops, purple",
        "usage: select <object-id>",
        "usage: updates",
        "Available views: context, updates",
        "Unknown view: unknown. Available views: context, updates",
    ], "shell help and usage errors remain compact invariant failed."


def test_ShellPaletteSearchesLocalCommandsAndCachedContextActions():
    """Verify shell palette searches local commands and cached context actions."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.SetContextActions(
        "asset:demo",
        (
            ContextualAction("show-evidence", "Show evidence for this object."),
            ContextualAction("show-paths", "Show paths from this object."),
        ),
    )

    shell.onecmd("select asset:demo")
    shell.onecmd("palette ct")
    shell.onecmd("palette evidence")
    shell.onecmd("palette missing")

    assert output.getvalue().splitlines() == [
        "Selected object: asset:demo",
        "command: context",
        "command: select",
        "cli: shell",
        "action: show-evidence — Show evidence for this object.",
        "action: show-paths — Show paths from this object.",
        "action: show-evidence — Show evidence for this object.",
        "No palette matches.",
    ], "shell palette searches local commands and cached context actions invariant failed."


def test_ShellHistorySearchesInReverseOrderWithoutRecordingSearches():
    """Verify shell history searches in reverse order without recording searches."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)

    shell.onecmd("lens purple")
    shell.onecmd("select asset:demo")
    shell.onecmd("context")
    shell.onecmd("history select")
    shell.onecmd("history missing")

    assert output.getvalue().splitlines() == [
        "Selected lens: purple",
        "Selected object: asset:demo",
        "Lens: purple",
        "View: context",
        "Selected object: asset:demo",
        "Pending updates: 0",
        "select asset:demo",
        "No matching history entries.",
    ], "shell history searches in reverse order without recording searches invariant failed."


def test_ContextActionCacheRequiresAnObjectIdentifier():
    """Verify context action cache requires an object identifier."""

    shell = InteractiveShell(stdin=StringIO(), stdout=StringIO())

    with pytest.raises(ValueError, match="non-empty"):
        shell.SetContextActions(" ", ())


def test_ShellReportsCommandsDrainsUpdatesAndExitsCleanly():
    """Verify shell reports commands drains updates and exits cleanly."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)

    shell.onecmd("commands")
    shell.PublishUpdate(WorkbenchUpdate("model", "asset changed"))
    assert shell.precmd("context") == "context", (
        "shell reports commands drains updates and exits cleanly invariant failed."
    )
    shell.onecmd("updates")
    assert shell.onecmd("quit extra") is False, (
        "shell reports commands drains updates and exits cleanly invariant failed."
    )
    assert shell.onecmd("quit") is True, (
        "shell reports commands drains updates and exits cleanly invariant failed."
    )
    assert shell.onecmd("EOF") is True, (
        "shell reports commands drains updates and exits cleanly invariant failed."
    )

    assert output.getvalue().splitlines() == [
        (
            "Interactive commands: commands, context, help, history, lens, "
            "palette, quit, select, updates, view"
        ),
        "CLI commands: help, version, shell",
        "[model] asset changed",
        "usage: quit",
        "",
    ], "shell reports commands drains updates and exits cleanly invariant failed."
