# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Opt-in six actual Nuclei observations over fresh unchanged pinned application targets."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from .external_benchmark import LoadPack
from .external_nuclei_comparison import SELECTION, Enabled, NucleiComparisonHost, Shielded

pytestmark = pytest.mark.serial


@pytest.fixture(scope="module")
def external_nuclei_comparison():
    """Skip disabled execution before discovery; fail every enabled missing genuine prerequisite."""

    if not Enabled(os.environ.get(SELECTION)):
        pytest.skip("Nuclei application execution is UNRUN without juice-shop selection")

    pack, target = LoadPack()

    if any(item["implementation"] != "available" for item in pack["scanner_tracks"]):
        pytest.fail("Enabled comparison requires accepted source for both Nuclei tracks")

    runtime = NucleiComparisonHost(Path(__file__).absolute().parents[2], pack, target)

    try:
        asyncio.run(runtime.Provision())

        yield runtime

    finally:
        asyncio.run(Shielded(runtime.Close()))


@pytest.mark.parametrize("track", ["whole1337", "external-nuclei"])
@pytest.mark.parametrize("case_id", ["metrics.exposed", "metrics.json-control",
                                    "metrics.html-control"])
def test_GenuineNucleiApplicationComparison(external_nuclei_comparison, track, case_id):
    """Require the known positive match while keeping both empty negative outputs unproven."""

    runtime = external_nuclei_comparison
    case = next(item for item in runtime.pack["cases"] if item["id"] == case_id)
    observation = runtime.RunCase(track, case)
    expected = "completed" if case["expected"] else "unproven"
    assert observation["status"] == expected, (
        "Known positive must match; empty negative invocations stay unproven without TN/FN credit"
    )
    assert len(observation["execution"]["findings"]) == int(case["expected"]), (
        "Finite inputs must retain exact known mapped-match behavior without duplicates"
    )
