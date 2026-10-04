# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Optional black-box regression smoke for the pinned Juice Shop target."""

from __future__ import annotations

import json
import time
from dataclasses import asdict

import pytest

from fuzzy1337.functional_metrics import (
    BuildReport,
    FunctionalRun,
    OracleCheck,
    RawEvidence,
    RenderHtml,
    RenderMarkdown,
    RunStatus,
    ScenarioOracle,
    SerializeReport,
)

from .external_targets import ExternalTargetLab

pytestmark = pytest.mark.serial


def ProbeExternalTarget(lab: ExternalTargetLab) -> dict[str, object]:
    """Generate qualitative metrics from actual pinned loopback HTTP responses."""

    target = lab.target.manifest
    oracle = ScenarioOracle(
        identifier="external.juice-shop.http-contract",
        target_pack="external.juice-shop",
        target_version=target["version"],
        provenance=f"upstream:{target['source_revision']};image:{lab.target.ImageReference}",
        complete=False,
        checks=(
            OracleCheck("application.version", "application.version", None),
            OracleCheck("catalog.search", "http.json", None),
            OracleCheck("web.root", "http.html", None),
        ),
    )
    started = time.monotonic()
    observation_start = len(lab.observations)
    detected = []
    failure = ""

    try:
        version = lab.Request("/rest/admin/application-version")
        root = lab.Request("/")
        catalog = lab.Request("/rest/products/search?q=1337-regression-marker")

        if (
            version.status == 200 and not version.error
            and json.loads(version.body).get("version") == target["version"]
        ):
            detected.append("application.version")

        if root.status == 200 and not root.error and "OWASP Juice Shop" in root.body:
            detected.append("web.root")

        if (
            catalog.status == 200 and not catalog.error
            and json.loads(catalog.body).get("data") == []
        ):
            detected.append("catalog.search")

    except (AttributeError, json.JSONDecodeError) as error:
        failure = f"{type(error).__name__}: {error}"

    duration = time.monotonic() - started
    failed_requests = [
        observation for observation in lab.observations[observation_start:] if observation.error
    ]
    status = (
        RunStatus.TIMED_OUT if any(observation.timed_out for observation in failed_requests)
        else RunStatus.CRASHED if failure or failed_requests else RunStatus.COMPLETED
    )
    run = FunctionalRun(
        scenario_id=oracle.identifier,
        scanner_id="first-party.external-contract-probe",
        release_id="target-contract-1",
        status=status,
        duration_seconds=duration,
        detected_checks=tuple(detected),
        discovered_objects=tuple("route." + check for check in detected),
        evidence=(
            RawEvidence("stdout", "application/json", json.dumps([
                command.stdout for command in lab.commands
            ])),
            RawEvidence("stderr", "application/json", json.dumps([
                command.stderr for command in lab.commands
            ])),
            RawEvidence("invocation", "application/json", json.dumps([
                command.argv for command in lab.commands
            ])),
            RawEvidence("http", "application/json", json.dumps([
                asdict(observation) for observation in lab.observations
            ])),
            RawEvidence("provenance", "application/json", json.dumps(lab.provenance)),
            RawEvidence("failure", "text/plain", failure),
        ),
    )
    report = BuildReport((oracle,), (run,))
    lab.evidence_directory.mkdir(parents=True, exist_ok=True)

    for name, content in (
        ("report.json", SerializeReport(report)),
        ("matrix.md", RenderMarkdown(report)),
        ("matrix.html", RenderHtml(report)),
    ):
        (lab.evidence_directory / name).write_text(content, encoding="utf-8")

    return report


def test_PinnedJuiceShopServesItsExactReleaseAndRegressionContract(
    external_target_lab: ExternalTargetLab,
) -> None:
    """Execute real opt-in application probes and retain a truthfully unscored report."""

    report = ProbeExternalTarget(external_target_lab)
    scored = report["runs"][0]
    run = scored["run"]

    assert set(run["detected_checks"]) == {
        "application.version", "catalog.search", "web.root",
    }, "Pinned Juice Shop must expose its exact version, root UI, and empty search JSON."
    assert run["status"] == "completed", "External probe parse failures must not count as success."
    assert scored["metrics"]["accuracy"] is None, (
        "A realistic target without a complete oracle must never claim absolute accuracy."
    )
    assert external_target_lab.provenance["platform_manifest_digest"], (
        "Executed external regression evidence must identify its exact running platform image."
    )
