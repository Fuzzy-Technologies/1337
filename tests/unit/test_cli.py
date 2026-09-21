"""Tests for cli behavior."""

import runpy
import sys
from importlib.metadata import version

import pytest

from fuzzy1337 import cli
from fuzzy1337.cli import GetCommandRegistry, GetCommands, Main


def test_DeveloperCommandsAreRegistered():
    """Verify developer commands are registered."""

    commands = GetCommands()

    assert set(commands) == {
        "setup",
        "unit",
        "test",
        "lint",
        "typecheck",
        "compile",
        "build",
        "check",
    }, "developer commands are registered invariant failed."
    assert "mypy" in commands["check"], "developer commands are registered invariant failed."
    assert commands["unit"].startswith("python -m pytest tests/unit"), (
        "developer commands are registered invariant failed."
    )
    assert "fuzzy1337.coverage_gate" in commands["test"], (
        "developer commands are registered invariant failed."
    )
    assert commands["setup"] == "uv sync --locked --extra dev", (
        "developer commands are registered invariant failed."
    )
    commands["test"] = "changed by a consumer"
    assert GetCommands()["test"] != commands["test"], (
        "developer commands are registered invariant failed."
    )


def test_NoArgumentsDescribeBootstrap(capsys):
    """Verify no arguments describe bootstrap."""

    assert Main([]) == 0, "no arguments describe bootstrap invariant failed."
    output = capsys.readouterr()
    assert "1337 Security Workbench" in output.out, (
        "no arguments describe bootstrap invariant failed."
    )
    assert "1337 help" in output.out, "no arguments describe bootstrap invariant failed."
    assert "1337 --version" in output.out, "no arguments describe bootstrap invariant failed."
    assert "1337 shell" in output.out, "no arguments describe bootstrap invariant failed."
    assert not output.err, "no arguments describe bootstrap invariant failed."


def test_HelpCommandUsesTheCommandRegistry(capsys):
    """Verify help command uses the command registry."""

    assert Main(["help"]) == 0, "help command uses the command registry invariant failed."

    output = capsys.readouterr()
    assert "Currently available commands:" in output.out, (
        "help command uses the command registry invariant failed."
    )
    assert GetCommandRegistry().Resolve("help") is not None, (
        "help command uses the command registry invariant failed."
    )


def test_ExplicitShellCommandStartsTheInteractiveWorkbench(monkeypatch):
    """Verify explicit shell command starts the interactive workbench."""

    monkeypatch.setattr(cli, "RunInteractiveShell", lambda: 0)

    assert Main(["shell"]) == 0, (
        "explicit shell command starts the interactive workbench invariant failed."
    )


@pytest.mark.parametrize(
    "arguments, code",
    [(["--version"], 0), (["--help"], 0), (["scan"], 2)],
)
def test_CliOptions(arguments, code, capsys):
    """Verify cli options."""

    with pytest.raises(SystemExit) as caught:
        Main(arguments)

    assert caught.value.code == code, "cli options invariant failed."
    output = capsys.readouterr()
    if arguments == ["--version"]:
        assert output.out.strip() == f"1337 {version('1337')}", "cli options invariant failed."


def test_PythonModuleEntrypoint(monkeypatch, capsys):
    """Verify python module entrypoint."""

    monkeypatch.setattr(sys, "argv", ["1337", "--version"])
    with pytest.raises(SystemExit) as caught:
        runpy.run_module("fuzzy1337", run_name="__main__")
    assert caught.value.code == 0, "python module entrypoint invariant failed."
    assert capsys.readouterr().out.strip() == f"1337 {version('1337')}", (
        "python module entrypoint invariant failed."
    )
