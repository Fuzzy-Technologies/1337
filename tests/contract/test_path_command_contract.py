# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit model/selection/clock/budget grammar and independently known selected-graph oracle."""

from __future__ import annotations

import pytest

from tests.path_command_helpers import Files, Run, SmallArguments, SmallGraph, Value


@pytest.mark.parametrize("name", ["--expected-revision", "--expected-snapshot-sha256", "--source",
    "--target", "--transition", "--context", "--scope-reference", "--as-of", "--max-age-seconds",
    "--max-depth", "--max-paths", "--max-work", "--max-frontier", "--max-cut-work"])
def test_EverySelectionAndBudgetIsExplicitBeforeAnyProofRead(tmp_path, name):
    """Missing configuration never discovers graph edges, original assessments or analysis time."""

    context = SmallGraph(tmp_path)
    arguments = SmallArguments(context)

    while name in arguments:
        index = arguments.index(name)
        del arguments[index:index + 2]

    before = Files(context[0])
    status, result = Run(arguments)
    assert status == 2 and result["analysis"] is None and Files(context[0]) == before, (
        "Omitted path configuration was inferred or changed owning storage"
    )


@pytest.mark.parametrize("name,value", [("--expected-snapshot-sha256", "sha256:" + "a" * 64),
    ("--expected-revision", "-1"), ("--max-age-seconds", "604801"), ("--max-depth", "33"),
    ("--max-paths", "257"), ("--max-work", "0"), ("--max-frontier", "4097"),
    ("--max-cut-work", "2000001"), ("--as-of", "2026-10-14T00:00:00"),
    ("--source", "secret-sentinel"), ("--context", "secret\nmarker")])
def test_InvalidClosedInputsFailWithGenericDiagnostics(tmp_path, name, value):
    """Exact SDK ranges, references and aware clocks remain bounded product contracts."""

    context = SmallGraph(tmp_path)
    before = Files(context[0])
    status, result = Run(Value(SmallArguments(context), name, value))
    assert status == 2 and result["failure"] == "configuration" and result["analysis"] is None, (
        "Invalid bounded path configuration reached an owning proof or analysis claim"
    )
    assert "secret" not in str(result) and Files(context[0]) == before, (
        "Path argument rejection leaked input or changed saved state"
    )


def test_HandwrittenTwoPathAndTwoCutOracleThroughRealHandler(tmp_path):
    """The product yields two original UNKNOWN paths and two exact independent structural cuts."""

    context = SmallGraph(tmp_path)
    root, _, objects, relations = context
    before = Files(root)
    status, result = Run(SmallArguments(context))
    assert status == 0, "Actual owned selected-graph analysis failed"
    analysis = result["analysis"]
    expected = {
        (relations["source-pivot"].Reference(), relations["pivot-left"].Reference(),
         relations["left-target"].Reference()),
        (relations["source-pivot"].Reference(), relations["pivot-right"].Reference(),
         relations["right-target"].Reference())}
    assert {tuple(path["hops"]) for path in analysis["search"]["paths"]} == expected, (
        "Product candidate paths differ from the independent literal graph oracle"
    )
    assert all(path["state"] == "UNKNOWN" and not path["confidence_estimates"]
        for path in analysis["search"]["paths"]), (
        "Unassessed graph gained confidence or confirmation"
    )
    assert {(item["kind"], item["reference"]) for item in analysis["cuts"]["verified"]} == {
        ("node", objects["pivot"].Reference()), ("relation", relations["source-pivot"].Reference())
    }, "Structural cut result differs from the independently known shared pivot/edge"
    assert analysis["coverage"]["unassessed_transitions"] == 5 and all(
        item["reasons"] == ["unassessed"] for item in analysis["transitions"]
    ), "Product DTO erased original unassessed transition reasons"
    assert analysis["search"]["complete"] and analysis["cuts"]["complete"] and (
        analysis["nonblocked_returned_candidates"] == 2
    ), "Small selected-graph coverage or structural denominator changed"
    expected_counts = {("node", objects["pivot"].Reference()): 2,
        ("node", objects["left"].Reference()): 1, ("node", objects["right"].Reference()): 1,
        **{("relation", item.Reference()): 2 if alias == "source-pivot" else 1
           for alias, item in relations.items()}}
    assert {(item["kind"], item["reference"]): len(item["removed_path_references"])
        for item in analysis["removal_leverage"]} == expected_counts and all(
        item["remaining_candidate_count"] == 2 - expected_counts[(item["kind"], item["reference"])]
        for item in analysis["removal_leverage"]
    ), "Product single-removal structural counts differ from the handwritten two-path graph"
    participation = {(item["kind"], item["reference"]): item
        for item in analysis["participation"]}
    assert all(participation[("node", objects[name].Reference())]["state_counts"] == {
        "CONFIRMED": 0, "LIKELY": 0, "POTENTIAL": 0, "BLOCKED": 0, "UNKNOWN": 2}
        for name in ("source", "pivot", "target")), (
        "Product participation erased original UNKNOWN state counts or endpoint explanation"
    )
    assert Files(root) == before, "Read-only path command saved authoritative owner bytes"


def test_ShallowEnumerationAndIndependentCutsRetainSeparateCompleteness(tmp_path):
    """Depth-limited zero returned candidates cannot become global no-path or false cut evidence."""

    context = SmallGraph(tmp_path)
    status, result = Run(Value(SmallArguments(context), "--max-depth", "1"))
    assert status == 0, "Honest bounded truncation was reported as execution failure"
    analysis = result["analysis"]
    assert not analysis["search"]["complete"] and not analysis["search"]["no_candidate_path"], (
        "Truncated enumeration silently claimed complete route absence"
    )
    assert analysis["search"]["reasons"] == ["depth-limit"] and analysis["cuts"]["complete"] and (
        analysis["cuts"]["candidate_route_exists"] is True
    ), "Independent full-selected-graph cut analysis inherited the shallow enumeration bound"


def test_ExhaustedCutWorkRemainsUnknownWhileReturnedPathEnumerationCompletes(tmp_path):
    """Independent cut work exhaustion cannot fabricate cuts or route absence."""

    context = SmallGraph(tmp_path)
    status, result = Run(Value(SmallArguments(context), "--max-cut-work", "1"))
    assert status == 0, "Honest independent cut truncation failed the read-only analysis command"
    analysis = result["analysis"]
    assert analysis["search"]["complete"] and not analysis["cuts"]["complete"] and (
        analysis["cuts"]["candidate_route_exists"] is None
        and not analysis["cuts"]["verified"] and analysis["cuts"]["reasons"] == ["cut-work-limit"]
    ), "Cut work exhaustion invented a verified cut, absence or combined completeness"
