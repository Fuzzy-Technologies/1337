# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Assess finite local checkpoints without tools, processes, models, or polling."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]


def ParseTime(value: str) -> datetime:
    """Parse an explicit timezone-bearing checkpoint timestamp.

    Args:
        value: Caller-supplied ISO-8601 timestamp with a timezone.

    Returns:
        Parsed timezone-aware timestamp.

    Raises:
        ValueError: The timestamp is invalid or lacks a timezone.
    """

    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Checkpoint timestamps require a timezone")

    return result


def ExpandTaskRoles(tasks: list[JsonObject]) -> list[JsonObject]:
    """Flatten explicitly registered child owners into independent finite tasks.

    Args:
        tasks: Task checkpoints with optional explicit source-role field names.

    Returns:
        Parent tasks and child-role tasks with separate state and progress leases.
    """

    expanded: list[JsonObject] = []
    for task in tasks:
        expanded.append(task)
        for key in task.get("source_role_keys", []):
            actor = task[key]
            running = actor.get("observed_state") == "running"
            parent_complete = task.get("phase") in {"merged", "complete"}
            expanded.append({
                "task": f"{task['task']}:{key}",
                "phase": (
                    "complete" if parent_complete and not running
                    else actor.get("phase", "role_handoff")
                ),
                "source": actor,
                "next_owner": actor.get(
                    "next_owner", actor.get("agent") if running else task.get("next_owner"),
                ),
                "next_action": actor.get("next_action", task.get("next_action")),
                "next_action_requires_source": actor.get("next_action_requires_source", running),
                "explicit_stop": actor.get("explicit_stop", task.get("explicit_stop")),
            })

    return expanded


def ProgressProofFindings(
    lease: JsonObject, owner: str, prefix: str, now: datetime,
) -> list[JsonObject]:
    """Validate canonical proof fields without judging the claimed action.

    Args:
        lease: Present progress lease with an expiry timestamp.
        owner: Actor whose verified action the lease must describe.
        prefix: Controller or source finding prefix.
        now: Caller-supplied timezone-aware assessment instant.

    Returns:
        One structural proof finding, or an empty list for a canonical proof.
    """

    required = ("owner", "kind", "last_verified_action", "last_verified_action_at")
    missing = [key for key in required if not isinstance(lease.get(key), str)
               or not lease[key].strip()]
    reason = "canonical_fields_missing" if missing else None
    if reason is None and lease["owner"] != owner:
        reason = "owner_mismatch"

    if reason is None:
        try:
            verified = ParseTime(lease["last_verified_action_at"])
        except (TypeError, ValueError):
            reason = "proof_time_invalid"
        else:
            if verified > now:
                reason = "proof_time_future"

    if reason is None:
        return []

    return [{
        "code": f"{prefix}_progress_proof_invalid", "owner": owner,
        "reason": reason, "missing_fields": missing,
    }]


def Assess(
    controller: JsonObject,
    tasks: list[JsonObject],
    now: datetime,
    expected_active_owners: list[str] | None = None,
) -> JsonObject:
    """Assess owner and progress leases at one caller-supplied clock instant.

    Args:
        controller: Explicit integration-controller checkpoint loaded from JSON.
        tasks: Finite checkpoints with primary and explicitly registered child owners.
        now: Injected timezone-aware instant; this function never reads a clock.
        expected_active_owners: Complete roster of verified unfinished active assignments.

    Returns:
        Deterministic findings, task states, and dispatch recommendations.

    Raises:
        ValueError: A checkpoint expiry timestamp is invalid or lacks a timezone.
    """

    findings: list[JsonObject] = []
    valid_tasks: list[JsonObject] = []
    for task in tasks:
        source = task.get("source", {})
        if (
            not task.get("task") or not isinstance(source, dict)
            or not source.get("agent") or not source.get("observed_state")
        ):
            findings.append({"code": "task_source_schema_invalid", "task": task.get("task")})
            continue

        valid_keys: list[str] = []
        for key in task.get("source_role_keys", []):
            actor = task.get(key)
            if (
                not isinstance(actor, dict) or not actor.get("agent")
                or not actor.get("observed_state")
            ):
                findings.append({
                    "code": "child_source_schema_invalid", "task": task["task"], "role": key,
                })
            else:
                valid_keys.append(key)

        valid_tasks.append({**task, "source_role_keys": valid_keys})

    tasks = ExpandTaskRoles(valid_tasks)
    states: list[JsonObject] = []
    unfinished = [task for task in tasks if task.get("phase") not in {"merged", "complete"}]
    if controller.get("observed_state") in {"interrupted", "errored"}:
        findings.append({
            "code": "controller_interrupted", "owner": controller.get("agent"),
            "recommended_action": (
                "Resume controller turn or explicitly replace it; message-only delivery "
                "does not restart a completed turn"
            ),
        })

    lease = controller.get("progress_lease", {})
    expiry = lease.get("expires_at")
    if unfinished and expiry and controller.get("observed_state") == "running":
        findings.extend(ProgressProofFindings(lease, controller["agent"], "controller", now))

    if unfinished and expiry and now >= ParseTime(expiry):
        findings.append({
            "code": "unfinished_controller_expired", "owner": controller.get("agent"),
        })

    owners: dict[str, list[str]] = defaultdict(list)
    for task in tasks:
        name = task["task"]
        phase = task.get("phase")
        source = task.get("source", {})
        source_state = source.get("observed_state")
        state = "completed" if phase in {"merged", "complete"} else "handoff_pending"
        recommendation = "No source restart: next owner owns the completed handoff"
        if state != "completed" and task.get("next_action_requires_source"):
            if task.get("explicit_stop"):
                recommendation = "Hold explicit stop; do not retry or rephrase a blocked task"
            elif source_state == "running":
                recommendation = (
                    "collaboration.send_message: deliver steering to the running source agent"
                )
            elif source_state in {"completed", "interrupted", "errored"}:
                recommendation = (
                    "collaboration.followup_task or explicit replacement: authorized work remains; "
                    "send_message alone cannot restart it"
                )
                findings.append({
                    "code": "authorized_source_not_running", "task": name,
                    "owner": source.get("agent"), "recommended_action": recommendation,
                })

        if state != "completed" and source_state == "running":
            state = "source_active"
            owners[source["agent"]].append(name)
            expiry = source.get("progress_lease", {}).get("expires_at")
            if not expiry:
                findings.append({
                    "code": "source_progress_lease_missing", "task": name,
                    "owner": source["agent"],
                })
            elif now >= ParseTime(expiry):
                findings.append({
                    "code": "source_progress_expired", "task": name, "owner": source["agent"],
                })

            if expiry:
                findings.extend(ProgressProofFindings(
                    source["progress_lease"], source["agent"], "source", now,
                ))

        if phase == "waiting_ci":
            state = "waiting_ci"
            expiry = task.get("ci", {}).get("deadline_at")
            if expiry and now >= ParseTime(expiry):
                findings.append({
                    "code": "ci_deadline", "task": name, "owner": task.get("next_owner"),
                })

        states.append({
            "task": name, "state": state, "next_owner": task.get("next_owner"),
            "next_action": task.get("next_action"), "recommended_action": recommendation,
        })

    for owner, names in owners.items():
        if len(names) > 1:
            findings.append({"code": "duplicate_source_owner", "owner": owner, "tasks": names})

    covered = set(owners)
    if controller.get("observed_state") == "running":
        covered.add(controller["agent"])

    if expected_active_owners is not None:
        for owner in sorted(set(expected_active_owners) - covered):
            findings.append({"code": "active_owner_unregistered", "owner": owner})

        for owner in sorted(covered - set(expected_active_owners)):
            findings.append({
                "code": "registered_active_owner_not_in_roster", "owner": owner,
                "recommended_action": (
                    "Refresh actual control-plane roster and current canonical handoffs; "
                    "a registered active owner is absent from the explicit roster"
                ),
            })

    if findings:
        assessment = "attention"
    elif not unfinished:
        assessment = "complete"
    elif all(item["state"] in {"waiting_ci", "completed"} for item in states):
        assessment = "waiting_ci"
    else:
        assessment = "active_or_handoff"

    return {
        "checked_at": now.isoformat(), "assessment": assessment,
        "findings": findings, "tasks": states,
        "owner_coverage_checked": expected_active_owners is not None,
        "covered_active_owners": sorted(covered),
    }


def Main() -> int:
    """Read explicit JSON paths once and print one deterministic assessment.

    Returns:
        Zero when no attention is required, otherwise status two.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("controller", type=Path)
    parser.add_argument("tasks", nargs="*", type=Path)
    parser.add_argument("--now", required=True, help="Injected ISO-8601 clock with timezone")
    parser.add_argument(
        "--active-owner", action="append", default=None,
        help="Verified owner of a current unfinished assignment; repeat for each owner",
    )
    arguments = parser.parse_args()

    controller = json.loads(arguments.controller.read_text(encoding="utf-8"))
    paths = arguments.tasks or [Path(value) for value in controller.get("task_ledger_paths", [])]
    tasks = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    result = Assess(controller, tasks, ParseTime(arguments.now), arguments.active_owner)

    print(json.dumps(result, sort_keys=True))

    return 2 if result["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(Main())
