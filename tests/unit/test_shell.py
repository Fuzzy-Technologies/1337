# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Tests for shell behavior."""

from __future__ import annotations

import json
import shlex
import sys
from io import StringIO
from types import ModuleType

import pytest

from fuzzy1337.lenses import ResolveLens
from fuzzy1337.model import ModelProvenance, ModelState, ObjectIdentity, ObjectKind, SecurityObject
from fuzzy1337.shell import (
    ContextualAction,
    FuzzyMatches,
    InteractiveShell,
    NativeInputHistory,
    WorkbenchUpdate,
)


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
    shell.onecmd("exploit authorized.example")

    assert output.getvalue().splitlines() == [
        "Unknown lens: unknown. Available lenses: pentest, dfir, devsecops, purple",
        "Unknown command: exploit authorized.example. Type 'help' for commands.",
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
        "cli: scan",
        "cli: raw",
        "cli: intel",
        "cli: ci",
        "cli: paths",
        "cli: sbom",
        "cli: api",
        "cli: runtime",
        "cli: trace",
        "action: show-evidence — Show evidence for this object.",
        "action: show-paths — Show paths from this object.",
        "cli: workspace",
        "cli: runtime",
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
            "Interactive commands: api, ci, commands, context, demo, help, history, image, "
            "intel, lens, model, palette, paths, quit, raw, report, runtime, sbom, scan, scope, "
            "select, trace, update, updates, view, workspace"
        ),
        ("CLI commands: doctor, help, version, shell, update, workspace, scope, image, "
         "scan, raw, report, intel, demo, ci, paths, sbom, api, response, runtime, trace"),
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


def test_ShellProductCommandsUseExplicitSharedDispatcher(monkeypatch):
    """The selected object/lens never becomes implicit scan scope or operator approval."""

    from fuzzy1337 import scan_commands

    calls = []

    def Dispatch(command, arguments, output, *, json_output=False):
        """Record the exact operator command without executing a provider."""

        calls.append((command, arguments, json_output))
        return 3 if command == "scan" else 0

    monkeypatch.setattr(scan_commands, "RunCommands", Dispatch)
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.onecmd('workspace open "path with spaces" --json')
    shell.onecmd("scope create fixture --id local")
    shell.onecmd("scan quick fixture --scope local --owner operator:x --target http://127.0.0.1/")
    shell.onecmd('workspace open "unterminated')
    assert calls == [
        ("workspace", ["open", "path with spaces"], True),
        ("scope", ["create", "fixture", "--id", "local"], False),
        ("scan", ["quick", "fixture", "--scope", "local", "--owner", "operator:x",
                  "--target", "http://127.0.0.1/"], False),
    ], (
        'The selected object/lens never becomes implicit scan scope or operator approval '
        'invariant failed.'
    )
    assert "Command exit status: 3" in output.getvalue(), (
        'The selected object/lens never becomes implicit scan scope or operator approval '
        'invariant failed.'
    )
    assert "Invalid quoted command arguments." in output.getvalue(), (
        'The selected object/lens never becomes implicit scan scope or operator approval '
        'invariant failed.'
    )


def test_ShellDemoUsesItsExplicitLazyDispatcherAndPreservesContext(monkeypatch):
    """Selected context cannot provide demo inputs or its separate SAFE capability opt-in."""

    from fuzzy1337 import demo_commands

    calls = []

    def Dispatch(arguments, output, *, json_output=False):
        """Record the exact foreground inputs without acquiring any synthetic target resource."""

        calls.append((arguments, json_output))

        return 3

    monkeypatch.setattr(demo_commands, "RunDemoCommands", Dispatch)
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.onecmd("lens dfir")
    shell.onecmd("select object:explicit")
    before = shell.State
    assert not shell.onecmd('demo local "path with spaces" --json'), (
        "Foreground demo dispatch must keep the Workbench shell running."
    )
    assert calls == [(["local", "path with spaces"], True)], (
        "The shell must forward only the explicitly supplied demo arguments."
    )
    assert shell.State == before, "Demo dispatch must preserve the chosen presentation context."
    assert shell.lastcmd == "demo", "Replay must retain only the protected demo namespace."
    assert "Command exit status: 3" in output.getvalue(), (
        "The shell must preserve the actual demo command denial status."
    )
    assert shell.completenames("dem") == ["demo"], (
        "Shell completion must expose the implemented demo namespace."
    )
    shell.onecmd("help demo")
    assert "--approve-safe-http" in output.getvalue(), "Help must name the separate approval."


def test_ShellIncompleteProductCommandCannotTerminateWorkbench():
    """Parser help/errors remain bounded foreground results rather than exiting the shell."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    assert not shell.onecmd("scan"), (
        'Parser help/errors remain bounded foreground results rather than exiting the shell '
        'invariant failed.'
    )
    assert "usage: scan --help" in output.getvalue(), (
        'Parser help/errors remain bounded foreground results rather than exiting the shell '
        'invariant failed.'
    )
    assert not shell.onecmd("workspace --help"), (
        'Parser help/errors remain bounded foreground results rather than exiting the shell '
        'invariant failed.'
    )


def test_ShellNeverRetainsRejectedProductCredentialsOrMalformedArguments(capsys):
    """New product namespaces must keep rejected sensitive text out of all local history."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    target = "http://user:synthetic-password@127.0.0.1/?token=synthetic-query-token"
    commands = (
        f"scan quick absent --scope local --owner operator:fixture --target {target}",
        f"SCOPE create absent --id local --allow-url {target}",
        'scan quick "synthetic-password malformed',
        f"scan synthetic-password {target}",
        f"demo local absent --token=synthetic-password --target {target}",
        'demo local "synthetic-password malformed',
    )

    for command in commands:
        shell.onecmd(command)
        assert "synthetic-password" not in shell.lastcmd, (
            "The framework's empty-line replay state must not retain rejected passwords."
        )
        assert "synthetic-query-token" not in shell.lastcmd, (
            "The framework's empty-line replay state must not retain rejected tokens."
        )

    shell.onecmd("history")
    diagnostics = capsys.readouterr()
    retained = output.getvalue() + diagnostics.out + diagnostics.err
    assert "synthetic-password" not in retained, "Rejected product passwords must not be retained."
    assert "synthetic-query-token" not in retained, "Rejected product tokens must not be retained."
    assert output.getvalue().splitlines()[-6:] == [
        "demo", "demo", "scan", "scan", "scope", "scan",
    ], (
        "Product history must retain only bounded canonical namespaces, including malformed input."
    )


@pytest.mark.parametrize("namespace", [
    "workspace", "scope", "scan", "report", "demo", "ci", "runtime", "paths", "sbom", "api",
    "trace", "raw",
])
@pytest.mark.parametrize("separator", [";", "--format=", "/", ":"])
def test_ProductHistoryAndReplayUseActualDispatchGrammar(monkeypatch, namespace, separator):
    """Punctuation/missing-space forms dispatch a protected namespace without retaining its argv."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    marker = "synthetic-private-argument"
    arguments = []

    def ObserveDispatcher(self, command, argument):
        """Observe protected replay/history during dispatch without executing a local action."""

        assert self.lastcmd == namespace and marker not in str(self._history), (
            "Replay/history must already be sanitized while the foreground consumer runs."
        )
        assert command == namespace, "The parsed namespace must preserve the shared dispatcher."
        arguments.append(argument)

    monkeypatch.setattr(InteractiveShell, "RunLocalCommand", ObserveDispatcher)
    line = namespace + separator + " " + marker
    _, expected_argument, _ = shell.parseline(line)
    assert not shell.onecmd(line), "Product dispatch cannot terminate the workbench."
    assert arguments == [expected_argument], "Sanitization must preserve actual dispatch grammar."
    assert shell.lastcmd == namespace, "No malformed argument can enter the framework replay state."
    shell.onecmd("")
    assert arguments == [expected_argument, ""], "Empty-line repeat may replay only the namespace."
    shell.onecmd("history")
    assert output.getvalue().splitlines() == [namespace, namespace], (
        "History must retain the parsed protected namespace, regardless of raw prefix punctuation."
    )


def NativeEditor(entries):
    """Build an independent native index/relative-position oracle without global editor state."""

    editor = ModuleType("owned-native-history-oracle")
    editor.backend = "readline"
    settings = {"completer": None, "bindings": []}

    def Count():
        """Observe the live native vector's size rather than its possibly advanced absolute base."""

        return len(entries)

    def Item(index):
        """Read by absolute native index, as GNU history_get does after a buffer cap."""

        return next((value for key, value in entries if key == index), None)

    def Replace(position, value):
        """Replace by zero-based relative native position, preserving all other entries."""

        key, _ = entries[position]
        entries[position] = (key, value)

    def GetCompleter():
        """Return only the test-owned caller completer."""

        return settings["completer"]

    def SetCompleter(value):
        """Observe the framework's temporary completer without accessing user configuration."""

        settings["completer"] = value

    def Bind(value):
        """Record only the framework binding callback in this isolated synthetic backend."""

        settings["bindings"].append(value)

    editor.get_current_history_length = Count
    editor.get_history_item = Item
    editor.replace_history_item = Replace
    editor.get_completer = GetCompleter
    editor.set_completer = SetCompleter
    editor.parse_and_bind = Bind

    return editor, settings


@pytest.mark.parametrize("namespace", [
    "report", "demo", "ci", "runtime", "paths", "sbom", "api", "trace", "raw",
])
def test_NativeHistoryOwnershipHandlesAdvancedCappedIndicesAndOnlyNewInput(namespace):
    """A native cap advances absolute base; matching prior/command-time entries remain unowned."""

    original = namespace + "; synthetic-prior-private-value"
    entries = [(5, original)]
    editor, _ = NativeEditor(entries)
    cursor = NativeInputHistory.Open(editor)
    shell = InteractiveShell(stdout=StringIO())
    cursor.Reconcile(shell, original)
    assert entries == [(5, original)], "A disabled-auto-history prior entry must remain untouched."
    entries[:] = [(6, namespace + "; synthetic-current-private-value")]
    cursor.Reconcile(shell, entries[0][1])
    assert entries == [(6, namespace)], "Current input remains owned under a native cap."
    entries.append((7, "scope; synthetic-command-time-value"))
    cursor.Reconcile(shell, "")
    cursor.Reconcile(shell, None)
    assert entries[-1] == (7, "scope; synthetic-command-time-value"), (
        "Observing command-time additions must not claim them during exit cleanup."
    )
    entries.append((8, "scan; synthetic-interrupted-input-value"))
    cursor.Reconcile(shell, None)
    assert entries[-1] == (8, "scan"), "An interrupted input boundary must remain protected."
    assert entries[0] == (6, namespace), "Keep already sanitized native input intact."


def test_CappedRetirementGapKeepsHandlerAdditionsAndProtectsNextActualInput():
    """Tip 6/input 7/handler 8+9/input 10 retire the missing gap without losing ownership."""

    entries = [(6, "owned-prior-tip")]
    editor, _ = NativeEditor(entries)
    cursor = NativeInputHistory.Open(editor)
    shell = InteractiveShell(stdout=StringIO())
    entries[:] = [(7, "seed")]
    cursor.Reconcile(shell, "seed")
    entries[:] = [(9, "owned-command-time-two")]
    cursor.Reconcile(shell, "")
    assert cursor.last_index == 9 and entries == [(9, "owned-command-time-two")], (
        "Retired index8 cannot stall the cursor or rewrite the handler's unowned addition."
    )
    entries[:] = [(10, "report; synthetic-current-private-value")]
    cursor.Reconcile(shell, entries[0][1])
    assert entries == [(10, "report")], "Protect the next actual product input before dispatch."


@pytest.mark.parametrize("additions", [100, 101, 102])
def test_CappedRetirementGapUsesFiniteLookupAndRefusesUnidentifiedTip(additions):
    """Exactly 100 advances remain identifiable; excess or wholly missing tips fail closed."""

    entries = [(7, "seed")]
    editor, _ = NativeEditor(entries)
    cursor = NativeInputHistory.Open(editor)
    shell = InteractiveShell(stdout=StringIO())
    queried = []
    original_item = editor.get_history_item

    def Observe(index):
        """Count only the independent oracle's public lookup calls and absolute positions."""

        queried.append(index)

        return original_item(index)

    editor.get_history_item = Observe
    entries[:] = [(7 + additions, "scope; synthetic-unowned-command-addition")]

    if additions == 100:
        cursor.Reconcile(shell, "")
        assert cursor.last_index == 107, "The exact lookup budget includes its final live tip."

    else:
        with pytest.raises(RuntimeError, match="owned boundary|identified safely"):
            cursor.Reconcile(shell, "")

        assert cursor.last_index == 7, "An unidentified boundary cannot be silently acknowledged."

    assert entries == [(7 + additions, "scope; synthetic-unowned-command-addition")], (
        "Boundary refusal and observation preserve the unowned handler addition exactly."
    )
    assert max(queried) <= 108 and len(queried) <= 208, (
        "Forward/previous lookups remain bounded to 100 positions plus fixed end/identity checks."
    )


@pytest.mark.parametrize("retired", [99, 100, 101])
def test_ObservationOnlyBackwardCapReshapingUsesBoundedKnownPositions(retired):
    """GNU cap introduction can renumber a known tip without transferring entry ownership."""

    entries = [(index, "owned-prior-" + str(index)) for index in range(100, 201)]
    editor, _ = NativeEditor(entries)
    cursor = NativeInputHistory.Open(editor)
    shell = InteractiveShell(stdout=StringIO())
    entries[:] = [(201, "owned-ordinary-input")]
    cursor.Reconcile(shell, "owned-ordinary-input")
    entries[:] = [(201 - retired, "scope; synthetic-unowned-command-addition")]

    if retired <= 100:
        cursor.Reconcile(shell, "")
        assert cursor.last_index == 201 - retired, "Pin only the identified observation tip."

    else:
        with pytest.raises(RuntimeError, match="identified safely"):
            cursor.Reconcile(shell, "")

        assert cursor.last_index == 201, "Excess backward changes cannot transfer ownership."

    assert entries == [(201 - retired, "scope; synthetic-unowned-command-addition")], (
        "Observation-time re-identification must not sanitize or alter an unowned caller entry."
    )


def test_ActualInputCannotClaimAnEarlierUnownedNativeTip():
    """Actual input cannot acquire a prior caller entry through backward recovery."""

    entries = [(6, "owned-prior-tip")]
    editor, _ = NativeEditor(entries)
    cursor = NativeInputHistory.Open(editor)
    line = "report; synthetic-identical-prior-value"
    entries[:] = [(5, line)]

    with pytest.raises(RuntimeError, match="identified safely"):
        cursor.Reconcile(InteractiveShell(stdout=StringIO()), line)

    assert entries == [(5, line)], "An identical earlier entry never becomes newly owned input."


def test_DisappearedNativeHistoryCannotSilentlyContinueAfterOwnedInput():
    """A live cursor whose tip disappears has no authority to accept further native input."""

    entries = [(7, "owned-ordinary-input")]
    editor, _ = NativeEditor(entries)
    cursor = NativeInputHistory.Open(editor)
    entries.clear()

    with pytest.raises(RuntimeError, match="identified safely"):
        cursor.Reconcile(InteractiveShell(stdout=StringIO()), "")

    assert not entries and cursor.last_index == 7, "Refusal never clears or invents native history."


@pytest.mark.parametrize("first_index", [100, 101])
def test_StartingNativeIdentificationHonorsExactLookupBoundary(first_index):
    """Starting index 100 is supported; index 101 is refused before input without any rewrite."""

    entries = [(first_index, "owned-prior-tip")]
    editor, _ = NativeEditor(entries)

    if first_index == 100:
        assert NativeInputHistory.Open(editor).last_index == 100, (
            "The final documented starting position must identify a legitimate capped history."
        )

    else:
        with pytest.raises(RuntimeError, match="identified safely"):
            NativeInputHistory.Open(editor)

    assert entries == [(first_index, "owned-prior-tip")], "Starting lookup preserves caller data."


def test_NativeOwnershipRefusesUnidentifiableHistoryWithoutMutatingIt():
    """Bounded identification never clears or guesses unrelated preexisting native history."""

    entries = [(1000, "owned-unidentifiable-prior-entry")]
    editor, _ = NativeEditor(entries)

    with pytest.raises(RuntimeError, match="identified safely"):
        NativeInputHistory.Open(editor)

    assert entries == [(1000, "owned-unidentifiable-prior-entry")], (
        "Unsupported native indexing must fail before input without rewriting caller history."
    )


@pytest.mark.parametrize("line", [
    "report; synthetic-current-input", "demo; synthetic-current-input", "context",
])
def test_CommandExceptionCannotClaimCallerNativeAdditionsDuringLoopCleanup(monkeypatch, line):
    """Handler-created entries remain unowned even when it exits before framework postcmd."""

    entries = []
    editor, _ = NativeEditor(entries)
    shell = InteractiveShell(stdout=StringIO())
    shell._native_history = NativeInputHistory.Open(editor)
    entries.append((1, line))
    shell.precmd(line)

    def Interrupt(*arguments):
        """Add one unrelated test-owned entry, then interrupt before framework postcmd."""

        entries.append((2, "scope; synthetic-unowned-command-addition"))
        raise KeyboardInterrupt

    monkeypatch.setattr(shell, "RunLocalCommand", Interrupt)
    monkeypatch.setattr(shell, "do_context", Interrupt)

    with pytest.raises(KeyboardInterrupt):
        shell.onecmd(line)

    shell._native_history.Reconcile(shell, None)
    assert entries[1] == (2, "scope; synthetic-unowned-command-addition"), (
        "Exit cleanup cannot claim a command-time native entry after handler interruption."
    )


@pytest.mark.parametrize("namespace", [
    "report", "demo", "ci", "runtime", "paths", "sbom", "api", "trace", "raw",
])
def test_NonrawLoopAndDirectCommandsNeverClaimGlobalNativeHistory(monkeypatch, namespace):
    """Stream/queued inputs have no native auto-history ownership and preserve preexisting state."""

    original = namespace + "; synthetic-prior-private-value"
    entries = [(1, original)]
    editor, settings = NativeEditor(entries)
    monkeypatch.setitem(sys.modules, "readline", editor)
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(namespace + "; synthetic-current-private-value\n"),
                             stdout=output)
    shell.use_rawinput = False
    shell.cmdloop()
    shell.onecmd(namespace + "; synthetic-direct-private-value")
    assert entries == [(1, original)], (
        "Nonraw/direct calls must not sanitize an unrelated native entry."
    )
    assert shell._native_history is None and settings["bindings"] == [], (
        "The nonraw lifecycle must not take a native editor or completion setting."
    )
    assert "synthetic-current-private-value" not in output.getvalue(), (
        "Stream input receives the same actual grammar/privacy protections."
    )


@pytest.mark.parametrize("namespace", [
    "report", "demo", "ci", "runtime", "paths", "sbom", "api", "trace", "raw",
])
def test_QueuedLoopPreservesUnownedNativeEntryAndCallerCompleter(monkeypatch, namespace):
    """Even a matching queued string cannot claim an unchanged preexisting native history item."""

    line = namespace + "; synthetic-prior-private-value"
    entries = [(1, line)]
    editor, settings = NativeEditor(entries)
    marker = object()
    settings["completer"] = marker
    monkeypatch.setitem(sys.modules, "readline", editor)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    shell = InteractiveShell(stdout=StringIO())
    shell.cmdqueue = [line, "quit"]
    shell.cmdloop()
    assert entries == [(1, line)], "Queued commands cannot own prior native history, even if equal."
    assert settings["completer"] is marker and shell._native_history is None, (
        "The standard completion lifecycle and scoped cursor must restore exactly."
    )


@pytest.mark.parametrize("interrupted", [False, True])
def test_TraceShellProtectsWindowsSelectionsBeforeDispatchAndPreservesContext(monkeypatch,
                                                                           interrupted):
    """Source paths and receipt selections never enter replay even when IOC dispatch interrupts."""

    module = ModuleType("fuzzy1337.ioc_commands")
    output = StringIO()
    shell = InteractiveShell(stdout=output)
    shell.onecmd("select object:owned")
    basis = shell._state
    selected = ["ioc", "import", r"C:\Owned Workspace", "--file",
                r"C:\Owned Evidence\private-candidates.tsv"]
    calls = []

    def ObserveInvocation(arguments, stream, *, json_output=False):
        """Inspect the already protected command boundary without executing acquisition."""

        assert stream is output and shell.lastcmd == "trace", (
            "The shell forwards its output owner and protects replay before consumer entry."
        )
        assert "private-candidates" not in str(shell._history), (
            "History must already omit private source arguments while acquisition runs."
        )
        calls.append((arguments, json_output))

        if interrupted:
            raise KeyboardInterrupt

        return 4

    module.RunIocCommands = ObserveInvocation
    monkeypatch.setitem(sys.modules, module.__name__, module)
    line = "trace " + shlex.join([*selected, "--json"])

    if interrupted:
        with pytest.raises(KeyboardInterrupt):
            shell.onecmd(line)

    else:
        shell.onecmd(line)
        assert "Command exit status: 4" in output.getvalue(), (
            "The interactive route preserves actual consumer failure status."
        )

    assert calls == [(selected, True)] and shell._state == basis, (
        "Quoted Windows selections retain their exact spelling without using selected context."
    )
    assert shell._history[-1] == "trace" and shell.lastcmd == "trace", (
        "Normal and interrupted IOC input retain only the canonical protected namespace."
    )


def test_RuntimeShellUsesQuotedWindowsPathsWithoutImplicitContextOrRetainedArguments(monkeypatch):
    """Quoted backslashes/spaces round-trip through the real shell's lazy runtime dispatcher."""

    from fuzzy1337 import runtime_commands

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    supplied = ["import", "docker-inspect", r"C:\Owned Workspace", "--file",
        r"C:\Owned Input\inspect.json", "--owner", "owner:explicit",
        "--read-consent-reference", "consent:explicit", "--host", "object:explicit",
        "--scope", "scope-explicit", "--run", "run:explicit", "--expected-revision", "1",
        "--expected-workspace-revision", "0"]
    calls = []

    def RunRuntimeCommands(arguments, target, *, json_output):
        """Observe caller-owned values and private history before producing one safe result."""

        assert shell.lastcmd == "runtime" and list(shell._history)[-1] == "runtime", (
            "Runtime arguments entered history before the handler was dispatched"
        )
        calls.append((arguments, json_output, target))

        return 4

    monkeypatch.setattr(runtime_commands, "RunRuntimeCommands", RunRuntimeCommands)
    shell.onecmd("lens purple")
    shell.onecmd("select object:unrelated")
    prior = shell.State
    shell.onecmd("runtime " + shlex.join([*supplied, "--json"]))
    assert calls == [(supplied, True, output)] and shell.State == prior, (
        "Shell runtime route changed explicit Windows selections or inferred context"
    )
    assert "Command exit status: 4" in output.getvalue(), "Shell hid actual runtime failure"
    shell.onecmd("history")
    assert r"C:\Owned" not in output.getvalue() and shell.lastcmd == "history", (
        "Windows source arguments escaped the protected namespace history"
    )


def test_ApiShellUsesQuotedWindowsPathsWithoutImplicitContextOrRetainedArguments(monkeypatch):
    """Quoted backslashes/spaces round-trip through the real shell's lazy api dispatcher."""

    from fuzzy1337 import api_commands

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    supplied = ["import", "graphql-introspection", r"C:\Owned Workspace", "--file",
        r"C:\Owned Input\introspection.json", "--owner", "owner:explicit",
        "--read-consent-reference", "consent:explicit", "--endpoint", "https://127.0.0.1/graphql",
        "--scope", "scope-explicit", "--run", "run:explicit", "--expected-revision", "1",
        "--expected-workspace-revision", "0"]
    calls = []

    def RunApiCommands(arguments, target, *, json_output):
        """Observe caller-owned values and private history before producing one safe result."""

        assert shell.lastcmd == "api" and list(shell._history)[-1] == "api", (
            "Api arguments entered history before the handler was dispatched"
        )
        calls.append((arguments, json_output, target))

        return 4

    monkeypatch.setattr(api_commands, "RunApiCommands", RunApiCommands)
    shell.onecmd("lens purple")
    shell.onecmd("select object:unrelated")
    prior = shell.State
    shell.onecmd("api " + shlex.join([*supplied, "--json"]))
    assert calls == [(supplied, True, output)] and shell.State == prior, (
        "Shell api route changed explicit Windows selections or inferred context"
    )
    assert "Command exit status: 4" in output.getvalue(), "Shell hid actual api failure"
    shell.onecmd("history")
    assert r"C:\Owned" not in output.getvalue() and shell.lastcmd == "history", (
        "Windows source arguments escaped the protected namespace history"
    )


def test_SbomShellUsesQuotedWindowsPathsWithoutImplicitContextOrRetainedArguments(monkeypatch):
    """Quoted backslashes/spaces round-trip through the real shell's lazy sbom dispatcher."""

    from fuzzy1337 import sbom_commands

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    supplied = ["import", "spdx-graph", r"C:\Owned Workspace", "--file",
        r"C:\Owned Input\sbom.json", "--owner", "owner:explicit",
        "--read-consent-reference", "consent:explicit",
        "--image-digest", "sha256:" + "a" * 64, "--image-digest-kind", "config",
        "--scope", "scope-explicit", "--run", "run:explicit", "--expected-revision", "1",
        "--expected-workspace-revision", "0"]
    calls = []

    def RunSbomCommands(arguments, target, *, json_output):
        """Observe caller-owned values and private history before producing one safe result."""

        assert shell.lastcmd == "sbom" and list(shell._history)[-1] == "sbom", (
            "Sbom arguments entered history before the handler was dispatched"
        )
        calls.append((arguments, json_output, target))

        return 4

    monkeypatch.setattr(sbom_commands, "RunSbomCommands", RunSbomCommands)
    shell.onecmd("lens purple")
    shell.onecmd("select object:unrelated")
    prior = shell.State
    shell.onecmd("sbom " + shlex.join([*supplied, "--json"]))
    assert calls == [(supplied, True, output)] and shell.State == prior, (
        "Shell sbom route changed explicit Windows selections or inferred context"
    )
    assert "Command exit status: 4" in output.getvalue(), "Shell hid actual sbom failure"
    shell.onecmd("history")
    assert r"C:\Owned" not in output.getvalue() and shell.lastcmd == "history", (
        "Windows source arguments escaped the protected namespace history"
    )


def test_PathShellUsesQuotedWindowsPathsWithoutImplicitContextOrRetainedArguments(monkeypatch):
    """Quoted backslashes/spaces round-trip through the real shell's lazy paths dispatcher."""

    from fuzzy1337 import path_commands

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    supplied = ["analyze", r"C:\Owned Workspace", "--source", "object:explicit-source",
        "--target", "object:explicit-target", "--transition", "relation:explicit",
        "--expected-revision", "1", "--expected-snapshot-sha256", "a" * 64,
        "--no-assessments", "--context", "context:explicit", "--scope-reference", "scope:explicit",
        "--as-of", "2026-10-14T10:00:00Z", "--max-age-seconds", "60", "--max-depth", "2",
        "--max-paths", "4", "--max-work", "20", "--max-frontier", "8", "--max-cut-work", "100"]
    calls = []

    def RunPathCommands(arguments, target, *, json_output):
        """Observe caller-owned values and private history before producing one safe result."""

        assert shell.lastcmd == "paths" and list(shell._history)[-1] == "paths", (
            "Path arguments entered history before the handler was dispatched"
        )
        calls.append((arguments, json_output, target))

        return 4

    monkeypatch.setattr(path_commands, "RunPathCommands", RunPathCommands)
    shell.onecmd("lens purple")
    shell.onecmd("select object:unrelated")
    prior = shell.State
    shell.onecmd("paths " + shlex.join([*supplied, "--json"]))
    assert calls == [(supplied, True, output)] and shell.State == prior, (
        "Shell paths route changed explicit Windows selections or inferred context"
    )
    assert "Command exit status: 4" in output.getvalue(), "Shell hid actual paths failure"
    shell.onecmd("history")
    assert r"C:\Owned" not in output.getvalue() and shell.lastcmd == "history", (
        "Windows source arguments escaped the protected namespace history"
    )
