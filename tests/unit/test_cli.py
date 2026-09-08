import runpy
import sys
from importlib.metadata import version

import pytest

from fuzzy1337.cli import get_commands, main


def test_developer_commands_are_registered():
    commands = get_commands()

    assert set(commands) == {
        "setup",
        "unit",
        "test",
        "lint",
        "typecheck",
        "compile",
        "build",
        "check",
    }
    assert "mypy" in commands["check"]
    assert commands["unit"].startswith("python -m pytest tests/unit")
    assert "fuzzy1337.coverage_gate" in commands["test"]
    assert commands["setup"] == "uv sync --locked --extra dev"
    commands["test"] = "changed by a consumer"
    assert get_commands()["test"] != commands["test"]


def test_no_arguments_describe_bootstrap(capsys):
    assert main([]) == 0
    output = capsys.readouterr()
    assert "1337 Security Workbench" in output.out
    assert "not available yet" in output.out
    assert not output.err


@pytest.mark.parametrize(
    "arguments, code",
    [(["--version"], 0), (["--help"], 0), (["scan"], 2)],
)
def test_cli_options(arguments, code, capsys):
    with pytest.raises(SystemExit) as caught:
        main(arguments)

    assert caught.value.code == code
    output = capsys.readouterr()
    if arguments == ["--version"]:
        assert output.out.strip() == f"1337 {version('1337')}"


def test_python_module_entrypoint(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["1337", "--version"])
    with pytest.raises(SystemExit) as caught:
        runpy.run_module("fuzzy1337", run_name="__main__")
    assert caught.value.code == 0
    assert capsys.readouterr().out.strip() == f"1337 {version('1337')}"
