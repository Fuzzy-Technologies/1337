# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit dispatch doubles test CI status forwarding and protected shell argument history."""

import shlex
from io import StringIO

import pytest

from fuzzy1337 import ci_commands
from fuzzy1337.cli import Main
from fuzzy1337.shell import InteractiveShell


@pytest.mark.parametrize("status", [0, 1, 2, 3, 4, 130])
def test_CiRoutePreservesPredicateAndFailureStatuses(monkeypatch, capsys, status):
    """A dispatch-only double verifies owning status forwarding without claiming scan evidence."""

    observed = []

    def Dispatch(arguments, output, *, json_output=False):
        """Record the selected adapter arguments without launching a scanner."""

        observed.append((arguments, json_output))
        output.write("selected predicate outcome\n")

        return status

    monkeypatch.setattr(ci_commands, "RunCiCommands", Dispatch)
    assert Main(["ci", "scan", "owned workspace", "--json"]) == status, (
        "CLI must preserve satisfied, violated, denied, failed and cancelled outcomes."
    )
    assert observed == [(["scan", "owned workspace"], True)], (
        "Dispatch must preserve explicit input selection and global JSON presentation."
    )
    assert capsys.readouterr().out == "selected predicate outcome\n", (
        "The adapter owns terminal outcome presentation."
    )


def test_CiShellExcludesQuotedArgumentsBeforeDispatch(monkeypatch):
    """Selected paths remain explicit and private during failed dispatch and command replay."""

    output = StringIO()
    shell = InteractiveShell(stdout=output)
    observed = []

    def Dispatch(arguments, terminal, *, json_output=False):
        """Inspect actual shell history at the owning command boundary without scanning."""

        assert list(shell._history) == ["ci"] and shell.lastcmd == "ci", (
            "Private argument paths must be excluded before the consumer executes."
        )
        observed.append((arguments, json_output))

        return 1

    monkeypatch.setattr(ci_commands, "RunCiCommands", Dispatch)
    arguments = ["scan", r"C:\Owned workspace", "--source", "private source path", "--json"]
    assert not shell.onecmd(shlex.join(["ci", *arguments])), "A CI violation keeps the shell open."
    assert observed == [(arguments[:-1], True)], "Quoting must preserve each explicit argument."
    assert output.getvalue() == "Command exit status: 1\n", "The violation must remain visible."
