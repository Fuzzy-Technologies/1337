# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Score first-party web checks using independently authored target expectations."""

from __future__ import annotations

from fuzzy1337.functional_metrics import FunctionalRun, OracleCheck, ScenarioOracle


def NativeScenario(metadata, case):
    """Select declared Git truth without consulting the detector or target implementation."""

    return ScenarioOracle(
        identifier=case["id"], target_pack=metadata["target_pack"],
        target_version=metadata["target_version"], provenance=metadata["provenance"],
        complete=True,
        checks=(OracleCheck(case["id"], case["capability"], case["expected_match"]),),
    )


def NativeCheckRun(scenario_id, provider_version, status, duration_seconds,
                   detected_checks, evidence):
    """Keep actual native outcomes and evidence separate from the independent expected matches."""

    return FunctionalRun(
        scenario_id, "native.web-check", "development-contract-" + provider_version,
        status, duration_seconds, detected_checks=detected_checks, evidence=evidence,
    )
