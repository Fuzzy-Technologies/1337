# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Build reviewed-check metrics metadata without requiring or impersonating native execution."""

from __future__ import annotations

from fuzzy1337.functional_metrics import FunctionalRun, OracleCheck, ScenarioOracle


def Scenario(metadata, case):
    """Translate only independent target expectations into the existing finite oracle schema."""

    return ScenarioOracle(
        identifier=case["id"], target_pack=metadata["target_pack"],
        target_version=metadata["target_version"], provenance=metadata["provenance"],
        complete=True,
        checks=(OracleCheck(case["id"], case["capability"], case["expected_match"]),),
    )


def WebCheckRun(scenario_id, provider_version, pack_version, status, duration_seconds,
                detected_checks, evidence):
    """Bind actual consumer metadata while preserving supplied outcomes, detections and bytes."""

    return FunctionalRun(
        scenario_id, "fuzzy1337.nuclei.web-checks",
        "nuclei-" + provider_version + "+checks-" + pack_version,
        status, duration_seconds, detected_checks=detected_checks, evidence=evidence,
    )
