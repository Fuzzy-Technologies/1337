# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Black-box contracts for the executable attack-path-mini lab."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from .conftest import ComposeLab
from .scenarios import ATTACK_PATH_MINI_LAB

pytestmark = pytest.mark.serial
ATTACK_PATH_ROOT = Path(__file__).resolve().parents[2] / "labs" / "targets" / "attack-path-mini"


def LoadJson(name: str) -> dict[str, Any]:
    """Load one versioned attack-path contract document."""

    return json.loads((ATTACK_PATH_ROOT / name).read_text(encoding="utf-8"))


def RunOperation(lab: ComposeLab, operation: str) -> dict[str, Any]:
    """Run one controlled lab operation and decode its evidence payload."""

    result = lab.Execute(
        ATTACK_PATH_MINI_LAB.client_service,
        "python",
        "client.py",
        operation,
        timeout_seconds=ATTACK_PATH_MINI_LAB.health_budget_seconds,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_AttackPathLabScenarioMatchesVersionedOracle():
    """Bind the executable topology to the exact versioned path identifiers."""

    oracle = LoadJson("oracle.v1.json")
    scenario = ATTACK_PATH_MINI_LAB

    assert scenario.provenance == "first-party:labs/targets/attack-path-mini", (
        "executable lab provenance must remain repository-owned."
    )
    assert scenario.version == "1", "executable lab version must match the v1 oracle."
    assert scenario.canonical_path_id == oracle["canonical_path"]["path_id"], (
        "executable lab canonical path must match the versioned oracle."
    )
    assert scenario.blocked_path_id == oracle["blocked_negative_path"]["path_id"], (
        "executable lab blocked path must match the versioned oracle."
    )
    assert scenario.compose_services == (
        "lab-attack-portal",
        "lab-attack-identity",
        "lab-attack-events",
        "lab-attack-billing",
        "lab-attack-client",
    ), "executable lab must retain the complete five-container topology."


def test_AttackPathLabConfirmsCanonicalPathAndBlocksSigningKey(attack_path_lab: ComposeLab):
    """Exercise real service hops and the independent policy-blocked negative path."""

    oracle = LoadJson("oracle.v1.json")
    RunOperation(attack_path_lab, "reset")
    confirmed = RunOperation(attack_path_lab, "validate")
    negative = RunOperation(attack_path_lab, "negative")

    assert confirmed["path_id"] == oracle["canonical_path"]["path_id"], (
        "authorized validation must report the canonical path."
    )
    assert confirmed["node_ids"] == oracle["canonical_path"]["node_ids"], (
        "authorized validation nodes must match the oracle exactly."
    )
    assert confirmed["relation_ids"] == oracle["canonical_path"]["relation_ids"], (
        "authorized validation relations must match the oracle exactly."
    )
    assert confirmed["phase_id"] == "phase.authorized-validation", (
        "successful validation must identify its lifecycle phase."
    )
    assert confirmed["state"] == "CONFIRMED", (
        "the complete executable path must become confirmed."
    )
    assert {
        "evidence.authorized-validation",
        "evidence.validation-authorization",
    } <= set(confirmed["evidence_ids"]), (
        "confirmed path must preserve validation and authorization evidence."
    )
    assert negative == {
        "blocked_by": "control.billing-key-policy",
        "path_id": oracle["blocked_negative_path"]["path_id"],
        "relation_id": "relation.billing-api-signing-key",
        "state": "BLOCKED",
    }, "signing-key access must remain blocked by the declared policy."
    assert RunOperation(attack_path_lab, "events") == {
        "asset_id": "asset.business-event",
        "events": ["invoice-settlement-demo"],
    }, "authorized validation must create exactly one deterministic business event."


def test_AttackPathLabRemediationAndResetAreDeterministic(attack_path_lab: ComposeLab):
    """Prove remediation blocks the path and reset restores the initial lab behavior."""

    oracle = LoadJson("oracle.v1.json")
    remediated = RunOperation(attack_path_lab, "remediate")

    assert remediated == {
        "blocked_by": oracle["remediation_path_break"]["control_id"],
        "path_id": oracle["remediation_path_break"]["path_id"],
        "phase_id": oracle["remediation_path_break"]["phase_id"],
        "relation_id": oracle["remediation_path_break"]["relation_id"],
        "state": oracle["remediation_path_break"]["resulting_state"],
    }, "remediation must block the exact canonical relation declared by the oracle."

    reset = RunOperation(attack_path_lab, "reset")
    assert reset["reset"] is True, "reset operation must report successful restoration."
    assert RunOperation(attack_path_lab, "events") == {
        "asset_id": "asset.business-event",
        "events": [],
    }, "reset must remove every synthetic business event."
    assert RunOperation(attack_path_lab, "validate")["state"] == "CONFIRMED", (
        "reset must restore the authorized canonical path."
    )
