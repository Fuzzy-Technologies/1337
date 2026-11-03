# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Comparison grammar, finite original-output capture and fixed failure diagnostics."""

from __future__ import annotations

import json
from io import StringIO

import pytest

from fuzzy1337 import path_comparison_commands as commands
from fuzzy1337.runtime_commands import RuntimeFailure


def Arguments():
    """Select complete synthetic canonical references without opening an owning workspace."""

    return ["/absent", "--expected-revision", "0", "--expected-snapshot-sha256", "a" * 64,
        "--source", "object:" + "b" * 64, "--target", "object:" + "c" * 64,
        "--transition", "relation:" + "d" * 64, "--focus-transition", "relation:" + "d" * 64,
        "--before-no-assessments", "--after-no-assessments", "--context", "owned:comparison",
        "--scope-reference", "scope:owned", "--as-of", "2026-11-03T00:00:00Z",
        "--max-age-seconds", "3600", "--max-depth", "16", "--max-paths", "64",
        "--max-work", "4096", "--max-frontier", "1024", "--max-cut-work", "100000"]


def Run(arguments, *, human=False):
    """Capture one owned handler outcome without involving the common command dispatcher."""

    output = StringIO()
    status = commands.RunPathComparisonCommands(arguments, output, json_output=not human)

    return status, output.getvalue() if human else json.loads(output.getvalue())


def Refuse(*args, **kwargs):
    """Trip any workspace read before complete comparison configuration admission."""

    raise AssertionError("Invalid comparison configuration reached an owning workspace.")


@pytest.mark.parametrize("case", ["revision", "pin", "same-endpoints", "reference", "focus",
    "duplicate-transition", "many-transitions", "duplicate-assessment", "many-assessments",
    "context", "scope", "clock", "age", "depth", "paths", "work", "frontier", "cuts",
    "duplicate-scalar", "duplicate-boolean", "abbreviation", "missing-side", "mixed-side",
    "import", "url", "html-json", "path", "help-bypass"])
def test_CompleteAdmissionRefusesBeforeWorkspaceOrSourceReads(monkeypatch, case):
    """All finite selections, scalar uniqueness and mode rules precede owner activity."""

    arguments = Arguments()

    if case in ("duplicate-transition", "many-transitions"):
        values = ["relation:" + "d" * 64] if case == "duplicate-transition" else [
            "relation:" + f"{index:064x}" for index in range(128)
        ]

        for value in values:
            arguments.extend(("--transition", value))

    elif case in ("duplicate-assessment", "many-assessments"):
        arguments.remove("--before-no-assessments")
        values = ["sha256:" + "a" * 64] * 2 if case == "duplicate-assessment" else [
            "sha256:" + f"{index:064x}" for index in range(33)
        ]

        for value in values:
            arguments.extend(("--before-assessment", value))

    elif case == "duplicate-scalar":
        arguments.append("--max-paths=1")

    elif case == "duplicate-boolean":
        arguments.append("--before-no-assessments")

    elif case == "abbreviation":
        arguments[arguments.index("--max-paths")] = "--max-p"

    elif case == "missing-side":
        arguments.remove("--after-no-assessments")

    elif case == "mixed-side":
        arguments.extend(("--before-assessment", "sha256:" + "a" * 64))

    elif case in ("import", "url", "help-bypass"):
        arguments.extend({"import": ["--file", "untrusted-value"],
                          "url": ["--url", "untrusted-value"],
                          "help-bypass": ["--help", "untrusted-value"]}[case])

    elif case == "html-json":
        arguments.append("--html")

    elif case == "path":
        arguments[0] = "../untrusted-value"

    else:
        flag, value = {"revision": ("--expected-revision", "-1"),
            "pin": ("--expected-snapshot-sha256", "untrusted-value"),
            "same-endpoints": ("--target", "object:" + "b" * 64),
            "reference": ("--transition", "untrusted-value"),
            "focus": ("--focus-transition", "relation:" + "e" * 64),
            "context": ("--context", ""), "scope": ("--scope-reference", ""),
            "clock": ("--as-of", "untrusted-value"), "age": ("--max-age-seconds", "604801"),
            "depth": ("--max-depth", "33"), "paths": ("--max-paths", "257"),
            "work": ("--max-work", "20001"), "frontier": ("--max-frontier", "4097"),
            "cuts": ("--max-cut-work", "2000001")}[case]
        arguments[arguments.index(flag) + 1] = value

    monkeypatch.setattr(commands.LocalWorkspaceStore, "Open", Refuse)
    status, result = Run(arguments)
    assert status == 2 and result["status"] == "failed" and result["before"] is None and (
        result["after"] is None and "untrusted-value" not in json.dumps(result)
    ), "Invalid comparison grammar exposed values, partial state or reached an owner."


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_StaticHelpUsesCallerStreamWithoutAnyWorkspaceRead(monkeypatch, flag):
    """Only explicit bare help describes common selections and both original assessment sides."""

    monkeypatch.setattr(commands.LocalWorkspaceStore, "Open", Refuse)
    status, output = Run([flag], human=True)
    assert status == 0 and "--focus-transition" in output and "--after-assessment" in output, (
        "Comparison help omitted explicit paired selections."
    )


def test_BoundedCaptureCountsUtf8AndRejectsBeforeRetainingExcess():
    """The original owner cannot retain an oversized second chunk or undercharge UTF-8 bytes."""

    capture = commands.BoundedPathCapture()
    retained = "é" * (1024 * 1024 // 2)
    assert capture.write(retained) == len(retained), "Capture changed TextIO character count."

    with pytest.raises(RuntimeFailure, match="output-limit"):
        capture.write("x")

    assert capture.getvalue() == retained and capture.received_bytes == 1024 * 1024, (
        "Oversized output was retained or UTF-8 accounting omitted bytes."
    )
    capture.close()


@pytest.mark.parametrize("status,raw,expected", [(2, "", 2), (4, "", 4), (130, "", 130),
    (1, "", 4), (0, "[]", 4), (0, '{"status":"failed"}', 4)])
def test_ActualOwnerFailureCannotEscapeAsSuccessfulCapturedOutcome(
    monkeypatch, status, raw, expected,
):
    """Failed/invalid original output is a fixed side failure, never partial comparison success."""

    from fuzzy1337 import path_commands

    def Original(arguments, output, *, json_output):
        """Emit a bounded synthetic owning-handler result for capture failure tests only."""

        output.write(raw)

        return status

    monkeypatch.setattr(path_commands, "RunPathCommands", Original)

    with pytest.raises(RuntimeFailure) as error:
        commands.AnalyzeSide(["analyze"], "after")

    assert error.value.status == expected and error.value.category == "after-analysis", (
        "Captured original failure changed status or exposed a successful side."
    )


def test_GeneratedOwnerArgumentsHaveNoForwardedComparisonSyntax():
    """Explicit side selections become ordinary analyze requests with unchanged common values."""

    arguments = Arguments()
    arguments.remove("--before-no-assessments")
    arguments.extend(("--before-assessment", "sha256:" + "a" * 64))
    options = commands.PathComparisonParser().parse_args(arguments)
    before = commands.AnalyzeArguments(options, "before")
    after = commands.AnalyzeArguments(options, "after")
    assert before[0] == after[0] == "analyze" and "--assessment" in before and (
        "--no-assessments" in after and "--focus-transition" not in before
        and not any(value.startswith("--before") or value.startswith("--after") for value in before)
    ), "Comparison forwarded its grammar instead of generating finite ordinary owner requests."
