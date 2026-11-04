# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental ordered composition of pinned CVE HTTPS selections."""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from fuzzy1337.intel_references import RequireReferenceText
from fuzzy1337.intelligence_acquisition import SyncState
from fuzzy1337.intelligence_cve_remote import (
    ENVELOPE_ROLE,
    MAX_ENVELOPE_BYTES,
    MAX_RECEIPT_BYTES,
    MAX_SOURCE_BYTES,
    PARTIAL_ROLE,
    RAW_ROLE,
    RECEIPT_ROLE,
    CveHttpsAcknowledgement,
    CveHttpsOutcome,
    CveHttpsRequest,
    CveHttpsState,
    RequireRecord,
    _AcquireHttpsCveSelection,
    _CveHttpsOwnershipStop,
    _CveHttpsReceiveFacts,
)
from fuzzy1337.workspace import LocalWorkspaceStore

__all__ = ("CveHttpsBatchMemberState", "CveHttpsBatchMember", "CveHttpsBatchOutcome",
           "AcquireHttpsCveBatch")

_MAX_MEMBERS = 4
_MAX_BATCH_BYTES = 4 * MAX_SOURCE_BYTES
_MAX_RECEIVE_SECONDS = 60.0
_NO_PUBLICATION = CveHttpsAcknowledgement.NOT_ATTEMPTED
_BatchStop = Literal["workspace-unavailable", "workspace-changed", "outcome-mismatch"]


class CveHttpsBatchMemberState(StrEnum):
    """Distinguish verified success, attempted failure and members without a receive."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    NOT_ATTEMPTED = "not-attempted"


@dataclass(frozen=True, slots=True)
class CveHttpsBatchMember:
    """Keep the selected request, scoped custody and structural stop facts distinct.

    Attributes:
        request: Exact pinned single-record selection.
        state: Batch-level member classification.
        outcome: Existing per-record result after validating its attribution.
        stop_reason: Structural failure preventing further receives, when observed.
        stopped_receive: Observed transport facts when a stopped receive has no usable outcome.
        raw_ack: Confirmed, not attempted, or unknown original publication.
        snapshot_ack: Confirmed, not attempted, or unknown selected publication.
        receipt_ack: Confirmed, not attempted, or unknown receipt publication.
    """

    request: CveHttpsRequest
    state: CveHttpsBatchMemberState
    outcome: CveHttpsOutcome | None = None
    stop_reason: _BatchStop | None = None
    stopped_receive: _CveHttpsReceiveFacts | None = None
    raw_ack: CveHttpsAcknowledgement = _NO_PUBLICATION
    snapshot_ack: CveHttpsAcknowledgement = _NO_PUBLICATION
    receipt_ack: CveHttpsAcknowledgement = _NO_PUBLICATION


@dataclass(frozen=True, slots=True)
class CveHttpsBatchOutcome:
    """Summarize independent member custody without an atomic or persisted batch claim.

    Attributes:
        state: Succeeded, partial or failed summary of actual member outcomes.
        workspace_id: Owning workspace when its preflight Open succeeds.
        scope_reference: Declared source collection attribution.
        members: One result in original caller order for each request.
    """

    state: SyncState
    workspace_id: str | None
    scope_reference: str
    members: tuple[CveHttpsBatchMember, ...]


def _ValidateBatch(requests: tuple[CveHttpsRequest, ...], scope_reference: str) -> None:
    """Refuse undeclared or excessive selections before any receive or evidence write."""

    if type(requests) is not tuple or not 2 <= len(requests) <= _MAX_MEMBERS or any(
        type(request) is not CveHttpsRequest for request in requests
    ):
        raise ValueError("CVE HTTPS batch requires two to four exact typed requests")

    if len({request.source.commit for request in requests}) != 1:
        raise ValueError("CVE HTTPS batch requires one immutable source commit")

    if len({request.source.identifier for request in requests}) != len(requests):
        raise ValueError("CVE HTTPS batch requires unique CVE identifiers")

    if sum(request.max_bytes for request in requests) > _MAX_BATCH_BYTES or (
        math.fsum(request.timeout_seconds for request in requests) > _MAX_RECEIVE_SECONDS
    ):
        raise ValueError("CVE HTTPS batch exceeds its configured receive budget")

    RequireReferenceText(scope_reference, "scope_reference")


def _MatchesHandles(outcome: CveHttpsOutcome, workspace_id: str, scope_reference: str) -> bool:
    """Validate each handle in its exact original publication slot without opening stores."""

    raw_role = RAW_ROLE if outcome.body_complete else PARTIAL_ROLE
    slots = (
        (outcome.raw, outcome.raw_ack, raw_role, outcome.received_bytes),
        (outcome.snapshot_record, outcome.snapshot_ack, ENVELOPE_ROLE, MAX_ENVELOPE_BYTES),
        (outcome.receipt, outcome.receipt_ack, RECEIPT_ROLE, MAX_RECEIPT_BYTES),
    )
    for record, ack, role, limit in slots:
        if (record is not None) != (ack is CveHttpsAcknowledgement.CONFIRMED):
            return False

        if record is None:
            continue

        try:
            RequireRecord(record, role, "application/json")

        except ValueError:
            return False

        provenance = record.provenance

        if (
            provenance.workspace_id != workspace_id or provenance.scope_reference != scope_reference
            or provenance.started_at != outcome.started_at
            or provenance.finished_at != outcome.finished_at
            or record.reference.size_bytes > limit
        ):
            return False

    return outcome.raw is None or outcome.raw.reference.size_bytes == outcome.received_bytes


def _AcceptMember(
    request: CveHttpsRequest, outcome: CveHttpsOutcome, workspace_id: str, scope_reference: str,
) -> CveHttpsBatchMember:
    """Keep attributed outcomes and refuse mismatched request or custody handles."""

    handles = (outcome.raw, outcome.snapshot_record, outcome.receipt)
    acknowledgements = (outcome.raw_ack, outcome.snapshot_ack, outcome.receipt_ack)
    matching = (
        outcome.source == request.source and outcome.max_bytes == request.max_bytes
        and outcome.timeout_seconds == request.timeout_seconds
        and _MatchesHandles(outcome, workspace_id, scope_reference)
    )
    success = outcome.state is CveHttpsState.SUCCEEDED
    raw, envelope = outcome.raw, outcome.envelope
    complete = (
        raw is not None and raw.reference.sha256 == request.source.expected_sha256
        and envelope is not None and envelope.source == request.source
        and envelope.max_bytes == request.max_bytes
        and envelope.timeout_seconds == request.timeout_seconds and envelope.raw == raw
        and outcome.body_complete and outcome.received_bytes > 0
        and outcome.snapshot_record is not None and outcome.receipt is not None
    )

    if not matching or (success and not complete) or (not success and envelope is not None):
        # An invalid join cannot confirm attribution for any attempted publication.
        unbound = tuple(_NO_PUBLICATION if ack is _NO_PUBLICATION and record is None
                        else CveHttpsAcknowledgement.UNKNOWN
                        for record, ack in zip(handles, acknowledgements, strict=True))

        return CveHttpsBatchMember(request, CveHttpsBatchMemberState.FAILED,
            stop_reason="outcome-mismatch", stopped_receive=_CveHttpsReceiveFacts.FromOutcome(
                outcome,
            ), raw_ack=unbound[0], snapshot_ack=unbound[1], receipt_ack=unbound[2])

    state = CveHttpsBatchMemberState.SUCCEEDED if success else CveHttpsBatchMemberState.FAILED

    return CveHttpsBatchMember(request, state, outcome, raw_ack=outcome.raw_ack,
        snapshot_ack=outcome.snapshot_ack, receipt_ack=outcome.receipt_ack)


def AcquireHttpsCveBatch(
    workspace_root: Path, requests: tuple[CveHttpsRequest, ...], *, scope_reference: str,
) -> CveHttpsBatchOutcome:
    """Process explicit pinned selections in order through existing single-record custody.

    Args:
        workspace_root: One existing operator-owned physical workspace.
        requests: Two to four unique selected CVEs sharing one immutable commit.
        scope_reference: Explicit collection attribution.

    Returns:
        Ordered actual member results and an honest succeeded, partial or failed summary.

    Raises:
        ValueError: The batch inputs or workspace locator fail preflight admission.
    """

    _ValidateBatch(requests, scope_reference)
    workspace = LocalWorkspaceStore(workspace_root)
    members: list[CveHttpsBatchMember] = []

    try:
        workspace_id: str | None = workspace.Open().workspace_id

    except (OSError, ValueError):
        workspace_id = None

    stop_reason: _BatchStop | None = "workspace-unavailable" if workspace_id is None else None

    if workspace_id is not None:
        for request in requests:
            try:
                outcome = _AcquireHttpsCveSelection(workspace.root, request,
                    scope_reference=scope_reference, expected_workspace_id=workspace_id)

            except _CveHttpsOwnershipStop as stop:
                member_state = (CveHttpsBatchMemberState.NOT_ATTEMPTED if stop.receive is None
                                else CveHttpsBatchMemberState.FAILED)
                member = CveHttpsBatchMember(request, member_state, stop_reason=stop.reason,
                                             stopped_receive=stop.receive)

            else:
                member = _AcceptMember(request, outcome, workspace_id, scope_reference)

            members.append(member)
            stop_reason = member.stop_reason

            if stop_reason is not None:
                break

    members.extend(CveHttpsBatchMember(request, CveHttpsBatchMemberState.NOT_ATTEMPTED,
                                      stop_reason=stop_reason)
                   for request in requests[len(members):])
    successes = sum(member.state is CveHttpsBatchMemberState.SUCCEEDED for member in members)
    state = (
        SyncState.SUCCEEDED if successes == len(members)
        else SyncState.PARTIAL if successes else SyncState.FAILED
    )

    return CveHttpsBatchOutcome(state, workspace_id, scope_reference, tuple(members))
