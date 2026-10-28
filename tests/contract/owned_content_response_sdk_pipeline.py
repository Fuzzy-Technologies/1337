# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite content capture/header-v2 sequence using existing consumers and independent oracles.

This coordinator launches nothing. Its explicit handoff must retain original installed-process
and target-owner evidence separately; mocked handoffs never establish runtime acceptance.
Fresh setup is a distinct operation, never the old fixed-identity SDK seed or renewed consent.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from tests.contract.owned_content_response_header_v2_oracle import (
    AssertContentHeaderV2,
    AssertHistoricalContentHeaderReplay,
)
from tests.contract.owned_content_response_sdk_oracle import AssertContentParts, Canonical
from tests.contract.owned_content_response_sdk_state_oracle import AssertSdkSaveTransition

EXPECTATIONS = {"missing": 1, "fixed": 0, "body-decoy": 1}
SCENARIOS = ("positive", "approval-denied", "policy-denied", "owner-drift")
FIELDS = {"fixture_id", "workspace", "relocated_workspace", "observations", "url", "case",
    "scenario", "consent_valid_from", "consent_valid_until"}


def Plan(selection: dict) -> dict:
    """Freeze one fresh finite attempt and its Finding/authority expectations before any handoff.

    Args:
        selection: Entire explicit fixture identity, paths, literal IPv4 URL, source case,
            authority scenario and aware consent times. No clock or filesystem is consulted.

    Returns:
        Closed independent inputs and derived fixture identities; no product IDs or ACKs.
        Window shape is not current freshness: reviewed setup and unchanged product authority
        still must check real time. Historical consent is never renewed by this plan.
    """

    if type(selection) is not dict or set(selection) != FIELDS or any(
        type(value) is not str or not value for value in selection.values()
    ):
        raise ValueError("Pipeline selection requires every explicit text input")

    if re.fullmatch(r"[a-z0-9][a-z0-9-]{7,63}", selection["fixture_id"]) is None or (
        selection["case"] not in EXPECTATIONS or selection["scenario"] not in SCENARIOS
    ):
        raise ValueError("Pipeline identity, case and authority scenario must be predeclared")

    roots = [Path(selection[key]) for key in (
        "workspace", "relocated_workspace", "observations")]

    if any(not root.is_absolute() or ".." in root.parts for root in roots) or any(
        left.is_relative_to(right) or right.is_relative_to(left)
        for index, left in enumerate(roots) for right in roots[index + 1:]
    ):
        raise ValueError("Pipeline owners must be explicit separate absolute roots")

    parsed = urlsplit(selection["url"])

    if parsed.hostname != "127.0.0.1" or parsed.port is None or not (
        1024 <= parsed.port <= 65535) or selection["url"] != (
            f"http://127.0.0.1:{parsed.port}/research/content"):
        raise ValueError("First integrated path selects only its literal IPv4 owned content URL")

    start, end = [datetime.fromisoformat(selection[key]) for key in (
        "consent_valid_from", "consent_valid_until")]

    if any(value.tzinfo is None or value.utcoffset() is None for value in (start, end)) or not (
        0 < (end - start).total_seconds() <= 900
    ):
        raise ValueError("Fresh fixture consent requires an aware positive window of at most 900s")

    identity = "owned-content-header-" + selection["fixture_id"]

    return {"schema_version": 1, "selection": dict(selection), "workspace_id": identity,
        "scope_id": identity, "owner_reference": "actor:" + identity,
        "attester_reference": "attester:" + identity, "consent_reference": "consent:" + identity,
        "analysis_reference": "analysis:" + identity,
        "expected_state": "completed" if selection["scenario"] == "positive" else "denied",
        "expected_findings": EXPECTATIONS[selection["case"]] if selection["scenario"] == (
            "positive") else 0}


def AssertOffline(record: dict, *, historical: bool) -> None:
    """Require observed tripwire delivery and zero forbidden effects, never infer missing zeros."""

    assert set(record) == {"calls", "audit_probe_seen", "saves"} and (
        record["audit_probe_seen"] is True), "Original offline guard telemetry is required"
    required = {"socket.audit", "socket.socket", "subprocess.Popen", "LocalExecutor.Execute",
        "GovernedLocalExecutor.Execute", "PolicyEngine.Authorize", "LocalEvidenceStore.Put",
        "LocalEvidenceStore.PublishStoredBytes", "OwnedResponseStage.__init__"}

    if historical:
        required.update(("LocalModelStore.Save", "LocalWorkspaceStore.Save",
            "LocalScopeStore.Open"))

    assert type(record["calls"]) is dict and required <= set(record["calls"]) and all(
        type(value) is int and value == 0 for value in record["calls"].values()), (
            "Any forbidden offline call, including a swallowed refusal, fails the sequence")
    assert type(record["saves"]) is list, "Original Save observations must remain explicit"

    if historical:
        assert record["saves"] == [], "Historical replay must not attempt any Save"


def Run(plan: dict, handoff, *, enabled: bool = False) -> dict:
    """Drive one fixed setup/capture/analysis/relocation/header-replay sequence without retries.

    Args:
        plan: Exact independent Plan result, frozen before fresh setup.
        handoff: Fixed installed consumer transport for named operations. Each call receives
            an explicit selection and distinct observation owner and returns actual detached
            observations. Fresh setup and physical relocation remain separately reviewed owners.
        enabled: Independent exact sequence opt-in; false performs no reads or handoffs.

    Returns:
        Checked historical identities or checked authority refusal. Original installation,
        process and target cleanup evidence remain required for genuine acceptance.
    """

    if enabled is not True:
        raise PermissionError("Integrated SDK sequence requires explicit execution opt-in")

    if type(plan) is not dict or Canonical(Plan(plan["selection"])) != Canonical(plan):
        raise ValueError("Pipeline plan changed after independent expectations were frozen")

    selected = plan["selection"]
    root, relocated = selected["workspace"], selected["relocated_workspace"]
    observations = Path(selected["observations"])
    paths = [Path(root), Path(relocated), observations]
    canonical = [path.resolve() for path in paths]

    if any(path.exists() or path.is_symlink() for path in paths[:2]) or any(
        left.is_relative_to(right) or right.is_relative_to(left)
        for index, left in enumerate(canonical) for right in canonical[index + 1:]
    ):
        raise ValueError("Fresh pipeline roots must be absent and canonically separate")

    step = 0

    def Call(operation: str, inputs: dict) -> dict:
        """Pass one explicit finite operation to a fresh, separately named observation owner."""

        nonlocal step
        step += 1

        return handoff(operation, inputs, observations / f"{step:02d}-{operation}")

    setup = Call("fresh-setup", {key: selected[key] for key in (
        "fixture_id", "workspace", "url", "consent_valid_from", "consent_valid_until")})
    before = setup["state"]
    scope = setup["scope"]
    assert before["workspace"]["workspace_id"] == before["model"]["workspace_id"] == (
        plan["workspace_id"]), "Fresh setup cannot reuse a historical workspace identity"
    assert scope["scope_id"] == plan["scope_id"] and scope["workspace_id"] == (
        plan["workspace_id"]), "Fresh scope must belong to this independently selected fixture"
    consent = scope["authorization"]
    assert consent == {"state": "granted", "authority_reference": plan["attester_reference"],
        "record_reference": plan["consent_reference"],
        "valid_from": selected["consent_valid_from"],
        "valid_until": selected["consent_valid_until"]}, "Original fresh consent must be exact"
    capture = Call("capture", {"workspace": root, "url": selected["url"],
        "scope_id": plan["scope_id"], "owner_reference": plan["owner_reference"],
        "policy": setup["policies"]["acquisition"]["path"],
        "approve_safe_content_response_capture": True, "retain_response": True})
    acquired = Call("inspect", {"workspace": root})["state"]
    summary = capture["summary"]
    AssertSdkSaveTransition(before, acquired, summary, capture["store_saves"],
        url=selected["url"], workspace_id=plan["workspace_id"],
        scope_reference="scope:" + plan["scope_id"])
    receipt = summary["original_receipt_id"]
    AssertContentParts(selected["case"], selected["url"], receipt, acquired["originals"],
        summary["source_facts"], job_id=summary["original_job_id"])
    analysis = Call("analyze-offline", {"workspace": root, "url": selected["url"],
        "scope_id": plan["scope_id"], "owner_reference": plan["owner_reference"],
        "policy": setup["policies"]["analysis"]["path"], "original_receipt_id": receipt,
        "analysis_reference": plan["analysis_reference"],
        "expected_model_revision": acquired["model"]["revision"],
        "expected_workspace_revision": acquired["workspace"]["revision"],
        "approve_passive_header_check": selected["scenario"] != "approval-denied",
        "authority_scenario": selected["scenario"]})
    AssertOffline(analysis["guard"], historical=False)
    interpreted = Call("inspect", {"workspace": root})["state"]
    actual = analysis["summary"]

    if plan["expected_state"] == "denied":
        assert actual["state"] == "denied" and actual["failure"] == "authorization"
        assert all(actual[key] is None for key in (
            "condition_observed", "assessment_reference", "finding_reference"))
        assert analysis["guard"]["saves"] == [] and Canonical(acquired) == Canonical(interpreted)

        return {"state": "checked-authority-refusal", "expected_findings": 0}

    identities = AssertContentHeaderV2(acquired, interpreted, actual,
        analysis["guard"]["saves"], case=selected["case"], url=selected["url"],
        receipt_id=receipt, analysis=plan["analysis_reference"], authority={"scope": scope,
            "policy": setup["policies"]["analysis"]["document"],
            "owner_reference": plan["owner_reference"], "owner_attribution": "trusted-reader"})
    assert int(identities["finding_reference"] is not None) == plan["expected_findings"], (
        "Persisted Finding truth must equal the expectation declared before capture")
    moved = Call("relocate", {"workspace": root, "relocated_workspace": relocated})
    assert moved == {"original_root_absent": True, "relocated_root_present": True}, (
        "Relocation must physically remove the original root before historical verification")
    assert not Path(root).exists() and not Path(root).is_symlink() and Path(relocated).is_dir(), (
        "Returned relocation claims cannot substitute for the physical selected roots")
    relocated_before = Call("inspect", {"workspace": relocated})["state"]
    assert Canonical(interpreted) == Canonical(relocated_before), "Relocation cannot repair state"
    replay = Call("replay-offline", {"workspace": relocated, "kind": "header",
        "reference": identities["assessment_reference"]})
    AssertOffline(replay["guard"], historical=True)
    relocated_after = Call("inspect", {"workspace": relocated})["state"]
    AssertHistoricalContentHeaderReplay(relocated_before, relocated_after, replay["summary"],
        identities)

    return {"state": "checked-header-replay", "expected_findings": plan["expected_findings"],
        "identities": identities}
