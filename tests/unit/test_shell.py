# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Tests for shell behavior."""

from __future__ import annotations

import json
from io import StringIO

import pytest

from fuzzy1337.lenses import ResolveLens
from fuzzy1337.model import ModelProvenance, ModelState, ObjectIdentity, ObjectKind, SecurityObject
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
    assert shell.State.selected_object == "asset:demo", (
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
        "lens [<name>] [--json]: select pentest, dfir, devsecops, or purple; "
        "--json describes the selected lens.",
        "No shell help for: unknown",
        "Available lenses: pentest, dfir, devsecops, purple",
        "usage: select <object-id>",
        "usage: updates",
        "Available views: context, updates, model",
        "Unknown view: unknown. Available views: context, updates, model",
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
        "cli: doctor",
        "cli: shell",
        "cli: update",
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
            "Interactive commands: commands, context, help, history, lens, model, palette, "
            "quit, select, update, updates, view"
        ),
        "CLI commands: doctor, help, version, shell, update",
        "[model] asset changed",
        "usage: quit",
        "",
    ], "shell reports commands drains updates and exits cleanly invariant failed."


def test_ShellLensJsonUsesTheMachineReadableCatalog():
    """Human and automated shell clients inspect the same descriptor without execution."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.onecmd("lens --json")
    shell.onecmd("lens dfir --json")
    documents = [json.loads(line) for line in output.getvalue().splitlines()]

    assert documents == [ResolveLens("pentest").ToDict(), ResolveLens("dfir").ToDict()], (
        'Lens contract failed: shell lens json uses the machine readable catalog.'
    )
    assert shell.State.lens == "dfir", (
        'Lens contract failed: shell lens json uses the machine readable catalog.'
    )
    assert shell.State.view == "context", (
        'Lens contract failed: shell lens json uses the machine readable catalog.'
    )


def test_InvalidJsonArgumentsDoNotChangeLensOrViewState():
    """Malformed flags never select a preset or implicitly bind an ambient model."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    original = shell.State

    for command in ("lens dfir extra", "view model extra", "view --json", "view context --json"):
        shell.onecmd(command)

    assert shell.State == original, (
        'Lens contract failed: invalid json arguments do not change lens or view state.'
    )
    assert output.getvalue().splitlines() == [
        "usage: lens [<name>] [--json]", "usage: view <name> [--json]",
        "usage: view <name> [--json]", "usage: view <name> [--json]",
    ], (
        'Lens contract failed: invalid json arguments do not change lens or view state.'
    )


def test_ModelViewRequiresAnExplicitSnapshotAndBindingIsTyped():
    """No fake empty live view is shown when a user has not selected canonical model state."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.onecmd("model")
    shell.onecmd("view model")
    shell.RenderModel()

    with pytest.raises(ValueError, match="ModelState"):
        shell.BindModel({})

    assert shell.State.view == "context", (
        'Lens contract failed: model view requires an explicit snapshot and binding is typed.'
    )
    assert output.getvalue().splitlines() == [
        "usage: model <workspace-path>", "No model loaded. Use model <workspace-path>.",
        "No model loaded. Use model <workspace-path>.",
    ], (
        'Lens contract failed: model view requires an explicit snapshot and binding is typed.'
    )
    state = ModelState("synthetic")
    shell.BindModel(state)
    shell.onecmd("view model --json")
    actual = json.loads(output.getvalue().splitlines()[-1])
    assert actual == ResolveLens("pentest").Project(state), (
        'Lens contract failed: model view requires an explicit snapshot and binding is typed.'
    )


def test_FailedModelOpenKeepsTheExplicitBoundSnapshot(tmp_path):
    """A missing workspace does not replace a selected snapshot or create new local state."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    state = ModelState("synthetic")
    shell.BindModel(state)
    missing = tmp_path / "missing"
    shell.onecmd(f"model {missing}")
    shell.onecmd("view model --json")

    assert output.getvalue().splitlines()[0].startswith("Could not open model:"), (
        'Lens contract failed: failed model open keeps the explicit bound snapshot.'
    )
    actual = json.loads(output.getvalue().splitlines()[-1])
    assert actual == ResolveLens("pentest").Project(state), (
        'Lens contract failed: failed model open keeps the explicit bound snapshot.'
    )
    assert not missing.exists(), (
        'Lens contract failed: failed model open keeps the explicit bound snapshot.'
    )


def test_ModelViewEscapesUntrustedControlCharactersWithoutChangingCanonicalKeys():
    """Observed keys cannot inject terminal commands or override displayed presentation."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    key = "build:\x1b[2J\u202ehidden"
    item = SecurityObject(
        ObjectIdentity("synthetic", ObjectKind.ASSET, key), provenance=(ModelProvenance(
            "native", "run:local", "2026-10-11T10:00:00Z", "scope:local", "target:" + "a" * 64,
        ),),
    )
    state = ModelState("synthetic", objects=(item,))
    shell.BindModel(state)
    shell.onecmd("lens devsecops --json")
    shell.onecmd("view model")

    assert "\\u001b[2J\\u202ehidden" in output.getvalue(), (
        "Terminal model keys must escape control and directionality characters."
    )
    assert "\x1b" not in output.getvalue() and "\u202e" not in output.getvalue(), (
        "An observed control sequence reached the terminal unchanged."
    )
    assert state.objects[0].identity.key == key, (
        "Presentation escaping must not rewrite canonical object identity."
    )
