# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Map actual first-party micro-target probe output to its finite functional oracle."""

from __future__ import annotations

import json

from fuzzy1337.functional_metrics import (
    FunctionalRun,
    OracleCheck,
    RawEvidence,
    RunStatus,
    ScenarioOracle,
)

from .scenarios import WEB_MICRO_TARGET_CONTRACT

WEB_MICRO_ORACLE = ScenarioOracle(
    identifier=WEB_MICRO_TARGET_CONTRACT.identifier,
    target_pack=WEB_MICRO_TARGET_CONTRACT.target.identifier,
    target_version=WEB_MICRO_TARGET_CONTRACT.target.version,
    provenance=WEB_MICRO_TARGET_CONTRACT.target.provenance,
    complete=True,
    checks=tuple(
        OracleCheck(identifier=finding, capability=finding, expected=True)
        for finding in WEB_MICRO_TARGET_CONTRACT.expected_findings
    ) + (OracleCheck("negative.unknown-route", "route.discovery", False),),
)


def NormalizeWebMicroRun(
    stdout: str,
    stderr: str,
    argv: tuple[str, ...],
    returncode: int,
    duration_seconds: float,
    timed_out: bool = False,
) -> FunctionalRun:
    """Preserve raw probe output and map actual markers to exact scenario check IDs."""

    status = (
        RunStatus.TIMED_OUT if timed_out else
        RunStatus.CRASHED if returncode else RunStatus.COMPLETED
    )
    observations = json.loads(stdout) if status is RunStatus.COMPLETED else {}
    detected = []

    for check in WEB_MICRO_ORACLE.checks:
        if not check.identifier.startswith("simulated."):
            continue

        marker = check.identifier.removeprefix("simulated.")
        key = "canary.upload" if marker == "upload-validation" else f"canary.{marker}"
        response = observations.get(key, {})

        if response.get("status") == 200 and response.get("body", {}).get("simulation") == marker:
            detected.append(check.identifier)

    if observations.get("unknown-route", {}).get("status") == 200:
        detected.append("negative.unknown-route")

    discovered = tuple(
        "route." + key.replace("-", ".") for key, response in sorted(observations.items())
        if isinstance(response, dict) and response.get("status") == 200
    )

    return FunctionalRun(
        scenario_id=WEB_MICRO_ORACLE.identifier,
        scanner_id="first-party.contract-probe",
        release_id="target-contract-1",
        status=status,
        duration_seconds=duration_seconds,
        detected_checks=tuple(detected),
        discovered_objects=discovered,
        evidence=(
            RawEvidence("stdout", "application/json", stdout),
            RawEvidence("stderr", "text/plain", stderr),
            RawEvidence("invocation", "application/json", json.dumps(argv)),
        ),
    )
