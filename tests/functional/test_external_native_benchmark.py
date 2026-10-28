# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Opt-in installed scanner acceptance against three fresh pinned Juice Shop instances."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from .external_benchmark import LoadPack
from .external_native_runtime import Enabled, NativeBenchmarkRuntime

pytestmark = pytest.mark.serial


@pytest.fixture(scope="module")
def external_native_runtime():
    """Fail enabled prerequisites and skip disabled execution before Docker discovery."""

    if not Enabled(os.environ.get("FUZZY1337_EXTERNAL_NATIVE_BENCHMARK")):
        pytest.skip("Installed external native benchmark is UNRUN without explicit selection")

    pack, target = LoadPack()
    native = next(item for item in pack["scanner_tracks"] if item["id"] == "native-engine")

    if native["implementation"] != "available":
        pytest.fail("Enabled benchmark requires accepted integrated native detector mapping")

    if shutil.which("docker") is None:
        pytest.fail("Enabled installed external native benchmark requires Docker")

    repository = Path(__file__).resolve().parents[2]
    runtime = NativeBenchmarkRuntime(repository,
        repository / "functional-evidence/external-native-benchmark", pack, target)

    try:
        runtime.Build()

        yield runtime

    finally:
        runtime.Close()


@pytest.mark.parametrize("case_id", [
    "metrics.exposed", "metrics.json-control", "metrics.html-control",
])
def test_InstalledNativeScannerMatchesRealApplicationCases(external_native_runtime, case_id):
    """Verify persisted real Findings against independent source truth, with no marker detector."""

    case = next(item for item in external_native_runtime.pack["cases"] if item["id"] == case_id)
    observation = external_native_runtime.RunCase(case)
    actual = observation["execution"]["findings"]
    assert bool(actual) is case["expected"], "Installed native findings disagree with case truth"
    assert len(actual) == int(case["expected"]), "The native case produced duplicate findings"
