# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual native 1337Scope CLI gates over owned endpoints and original saved report artifacts."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from xml.etree import ElementTree

import pytest

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.findings import Findings
from fuzzy1337.model import LocalModelStore
from tests.e2e.test_native_web_cli import Plan, Setup
from tests.functional.test_native_prometheus import MetricsPolicy
from tests.functional.test_native_prometheus import prometheus_target as prometheus_target  # noqa: F401
from tests.web_vulnerability_helpers import OwnedWebVulnerabilityTarget


def CiArguments(scan_arguments, parent):
    """Select the same exact scan inputs/limits and all explicit finite CI predicate outputs."""

    plan = Plan(scan_arguments)

    return ["scan", *scan_arguments[1:], "--profile", "native-web", "--timeout", "10",
        "--confirm-plan", plan["policy_plan"]["intent_sha256"], "--confirmation-reference",
        "approval:ci-native-owned", "--severity", "low", "--status", "open", "--max-matches", "0",
        "--acknowledge-unassessed-completeness", "--report-json", str(parent / "native.json"),
        "--report-sarif", str(parent / "native.sarif"),
        "--report-junit", str(parent / "native.xml")]


def Invoke(arguments, parent):
    """Invoke the actual assembled entry point from outside the source checkout."""

    process = subprocess.run([sys.executable, "-m", "fuzzy1337", "ci", *arguments, "--json"],
        cwd=parent, check=False, capture_output=True, text=True, timeout=30)
    assert not process.stderr, "The actual native CI command unexpectedly emitted diagnostics"

    return process.returncode, json.loads(process.stdout)


def CheckArtifacts(root, parent, outcome):
    """Verify each actual report uses the exact complete durable model and published byte digest."""

    state = LocalModelStore(root).Open()
    document = json.loads((parent / "native.json").read_bytes())
    sarif = json.loads((parent / "native.sarif").read_bytes())
    junit = ElementTree.parse(parent / "native.xml").getroot()
    properties = {item.attrib["name"]: item.attrib["value"]
                  for item in junit.findall("properties/property")}
    pin = document["snapshot_sha256"]
    assert document["model"] == state.ToDict(), "The JSON artifact changed the current saved model"
    assert pin == outcome["snapshot_sha256"] == properties["snapshot_sha256"] == (
        sarif["runs"][0]["properties"]["canonicalSnapshotSha256"]
    ), "JSON/SARIF/JUnit must describe one identical current complete model snapshot"

    for name, filename in (("json", "native.json"), ("sarif", "native.sarif"),
                            ("junit", "native.xml")):
        report = outcome["reports"][name]
        assert report["status"] == "completed" and report["output_published"] is True, (
            "Predicate satisfaction and violation must retain each actual completed artifact"
        )
        digest = hashlib.sha256((parent / filename).read_bytes()).hexdigest()
        assert report["report_sha256"] == digest, (
            "A publication outcome must identify the exact original exported bytes"
        )


@pytest.mark.parametrize("case_id,approved,expected", [
    ("git-exposed", True, 1), ("git-fixed", True, 0), ("git-exposed", False, 3),
])
def test_ActualNativeCiSubprocessRequiresExactConsentAndProducesOriginalArtifacts(
    tmp_path, case_id, approved, expected,
):
    """Genuine native HTTP work keeps both finite criterion outcomes and zero-contact refusal."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as target:
        root = tmp_path / "workspace"
        arguments = CiArguments(Setup(root, target.Url(case_id)), tmp_path)

        if not approved:
            for flag in ("--confirm-plan", "--confirmation-reference"):
                position = arguments.index(flag)
                del arguments[position:position + 2]

        before = target.Observe()
        status, outcome = Invoke(arguments, tmp_path)
        assert status == expected == outcome["exit_code"], (
            "Actual native CI terminal result drifted"
        )
        assert outcome["scan_completeness"] == "not-assessed", (
            "A finite response predicate cannot assert whole-target scan completeness"
        )

        if approved:
            CheckArtifacts(root, tmp_path, outcome)
            assert len(Findings(LocalModelStore(root).Open())) == int(expected == 1), (
                "The actual worker result differs from the independent target truth"
            )
            assert len(target.Observe()["requests"]) == len(before["requests"]) + 1, (
                "The selected CI scan must perform exactly one original native request"
            )

        else:
            assert target.Observe() == before and not (tmp_path / "native.json").exists(), (
                "Missing confirmation cannot contact the target or publish a successful report"
            )


@pytest.mark.parametrize("prometheus_target,expected", [
    ("chunked-positive", 1), ("plain-prose-decoy", 0), ("truncated-chunk", 4),
], indirect=["prometheus_target"])
def test_ActualMetricsCiPreservesNegativeAndUnassessedFailure(
    tmp_path, prometheus_target, expected,
):
    """Real complete positive, complete negative and malformed transport remain distinct."""

    _, url, requests = prometheus_target
    root = tmp_path / "workspace"
    scan = Setup(root, url, check="prometheus-exposition")
    policy = root / "native-policy.json"
    policy.write_text(SerializeContract(MetricsPolicy()), encoding="utf-8")
    arguments = CiArguments(scan, tmp_path)
    status, outcome = Invoke(arguments, tmp_path)
    assert status == expected == outcome["exit_code"], "Metrics CI changed actual native outcome"
    assert len(requests) == 1, "The native metrics CI scan repeated or followed a request"

    if expected in {0, 1}:
        CheckArtifacts(root, tmp_path, outcome)

    else:
        assert outcome["criterion"] == {"status": "indeterminate"} and not (
            tmp_path / "native.json"
        ).exists(), "Malformed wire cannot become a no-findings predicate success"
