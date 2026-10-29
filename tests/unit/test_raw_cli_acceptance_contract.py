# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Execute the genuine raw Nmap lane's exact required-case JUnit gate using inert XML controls."""

from __future__ import annotations

from xml.etree import ElementTree

import pytest

from tests.unit.test_ci_workflows import Workflow


@pytest.mark.parametrize("refusal", [None, "missing", "duplicate", "skipped", "failure", "error"])
def test_RequiredGenuineRawJUnitGateRejectsAbsentOrUnexecutedCases(tmp_path, monkeypatch, refusal):
    """Only all three actually executed passing SDK/raw cases satisfy the existing genuine lane."""

    steps = Workflow("nmap-acceptance.yml")["jobs"]["owned-loopback"]["steps"]
    selected = next(step for step in steps if step.get("name") == (
        "Execute genuine SDK and installed CLI against pytest-owned loopback only"))
    assert "tests/functional/test_nmap_product_loopback.py" in selected["run"] and (
        "tests/functional/test_raw_cli_nmap.py" in selected["run"]), (
        "The genuine lane must retain old SDK/installed CLI acceptance and both new raw profiles")
    gate = next(step for step in steps if step.get("name") == (
        "Require every genuine SDK and raw profile case to execute"))
    assert gate["if"] == "always()", "Required native case inventory must remain checked on failure"
    source = gate["run"].removeprefix("python - <<'PY'\n").removesuffix("PY\n")
    names = ["test_GenuineSdkAndInstalledConsolePreserveOwnedTwoPortOracleAndRelocatedReopen",
        "test_GenuineRawProfilesRetainExactArgvCustodyAndRelocatedOfflineReplay[tcp-connect]",
        "test_GenuineRawProfilesRetainExactArgvCustodyAndRelocatedOfflineReplay[light-services]"]
    suite = ElementTree.Element("testsuite")

    for name in names:
        ElementTree.SubElement(suite, "testcase", name=name)

    if refusal == "missing":
        suite.remove(suite[-1])

    elif refusal == "duplicate":
        suite[-1].set("name", names[0])

    elif refusal is not None:
        ElementTree.SubElement(suite[-1], refusal)

    destination = tmp_path / "functional-evidence/nmap-product/junit.xml"
    destination.parent.mkdir(parents=True)
    ElementTree.ElementTree(suite).write(destination)
    monkeypatch.chdir(tmp_path)

    if refusal is None:
        exec(compile(source, "required-native-raw-junit-gate", "exec"), {})

    else:
        with pytest.raises(ValueError):
            exec(compile(source, "required-native-raw-junit-gate", "exec"), {})
