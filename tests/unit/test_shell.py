from __future__ import annotations

from io import StringIO

from fuzzy1337.shell import InteractiveShell, WorkbenchUpdate, fuzzy_matches


def test_fuzzy_matches_prioritize_compact_subsequences():
    assert fuzzy_matches("ct", ("context", "commands", "select")) == ("context", "select")
    assert fuzzy_matches("", ("select", "commands")) == ("commands", "select")
    assert fuzzy_matches("missing", ("context", "commands")) == ()


def test_shell_tracks_lens_selected_object_and_updates():
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)

    shell.onecmd("lens devsecops")
    shell.onecmd("select asset:demo")
    shell.publish_update(WorkbenchUpdate("progress", "discovery queued"))
    shell.onecmd("context")
    shell.onecmd("updates")

    assert shell.state.lens == "devsecops"
    assert shell.state.selected_object == "asset:demo"
    assert output.getvalue().splitlines() == [
        "Selected lens: devsecops",
        "Selected object: asset:demo",
        "Lens: devsecops",
        "Selected object: asset:demo",
        "Pending updates: 1",
        "[progress] discovery queued",
    ]


def test_shell_completion_and_unknown_commands_are_deterministic():
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)

    assert shell.completenames("ct") == ["context", "select"]
    shell.onecmd("lens unknown")
    shell.onecmd("scan authorized.example")

    assert output.getvalue().splitlines() == [
        "Unknown lens: unknown. Available lenses: pentest, dfir, devsecops, purple",
        "Unknown command: scan authorized.example. Type 'help' for commands.",
    ]


def test_shell_help_and_usage_errors_remain_compact():
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)

    shell.onecmd("commands extra")
    shell.onecmd("context extra")
    shell.onecmd("help lens")
    shell.onecmd("help unknown")
    shell.onecmd("lens")
    shell.onecmd("select")
    shell.onecmd("updates extra")

    assert output.getvalue().splitlines() == [
        "usage: commands",
        "usage: context",
        "lens <name>: select pentest, dfir, devsecops, or purple.",
        "No shell help for: unknown",
        "Available lenses: pentest, dfir, devsecops, purple",
        "usage: select <object-id>",
        "usage: updates",
    ]


def test_shell_reports_commands_drains_updates_and_exits_cleanly():
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)

    shell.onecmd("commands")
    shell.publish_update(WorkbenchUpdate("model", "asset changed"))
    assert shell.precmd("context") == "context"
    shell.onecmd("updates")
    assert shell.onecmd("quit extra") is False
    assert shell.onecmd("quit") is True
    assert shell.onecmd("EOF") is True

    assert output.getvalue().splitlines() == [
        "Interactive commands: commands, context, help, lens, quit, select, updates",
        "CLI commands: help, version, shell",
        "[model] asset changed",
        "usage: quit",
        "",
    ]
