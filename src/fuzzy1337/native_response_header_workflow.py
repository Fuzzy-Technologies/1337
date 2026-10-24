# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline, explicitly admitted interpretation of acknowledged original response headers."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar, cast

from fuzzy1337.adapters import ExecutionState, ImpactLevel
from fuzzy1337.adapters.owned_response_capture import Destination, ParseOwnedResponseCapture
from fuzzy1337.evidence import EvidenceRecord
from fuzzy1337.findings import ApplyVerifiedFindings, Finding, FindingSeverity
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Observation,
)
from fuzzy1337.native_response_headers import (
    MAX_ASSESSMENT_BYTES,
    MAX_HEADER_BYTES,
    NATIVE_RESPONSE_ASSESSMENT_KIND,
    NATIVE_RESPONSE_CAPABILITY,
    NATIVE_RESPONSE_CHECK_ID,
    NATIVE_RESPONSE_PROFILE,
    NATIVE_RESPONSE_PROVIDER_ID,
    NATIVE_RESPONSE_SUMMARY,
    NATIVE_RESPONSE_VERSION,
    HeaderFieldAbsent,
    NativeResponseHeaderError,
)
from fuzzy1337.owned_response_custody import (
    PROVIDER_ID,
    OwnedResponseEvidenceStore,
    ReplayOwnedResponseCapture,
)
from fuzzy1337.owned_response_workflow import (
    SOURCE_KIND,
    PersistenceStatus,
    ReplayOwnedResponse,
    SourceFact,
)
from fuzzy1337.policy import Digest, ImpactPolicy, UtcNow
from fuzzy1337.scope import LocalScopeStore, Target, TargetKind
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    RequireWorkspaceInteger,
    RequireWorkspaceText,
    WorkspaceConflictError,
    WorkspaceState,
)

_ROLES = frozenset(("stdout", "stderr", "owned-response-request", "owned-response-headers",
    "owned-response-body", "owned-response-wire", "owned-response-receipt"))
_BASIS_FIELDS = frozenset(("workspace_id", "model_revision", "workspace_revision",
    "scope_reference", "scope_revision", "scope_sha256", "policy_reference", "policy_revision",
    "policy_sha256", "owner_reference", "owner_attribution", "analysis_reference",
    "original_receipt_id", "source_target_reference", "literal_ip_reference", "capability",
    "impact", "workflow_approved", "issued_at", "expires_at", "checked_at"))
_ASSESSMENT_FIELDS = frozenset(("schema_version", "profile", "check_id", "analysis_reference",
    "original_receipt_id", "original_job_id", "source_observation_reference", "original_role_ids",
    "header_sha256", "condition_observed", "authority_basis"))
_RECEIPT_ID = re.compile(r"sha256:[0-9a-f]{64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RESULT = TypeVar("_RESULT")


class MissingHeaderRetentionError(NativeResponseHeaderError):
    """A verified historical positive remains a prior partial reference-retention outcome."""


class HeaderAdmissionDeniedError(PermissionError):
    """Fixed safe refusal of this attempt, without a new policy grant or retry window."""

    def __init__(self, code: str = "authorization") -> None:
        """Retain a closed failure code rather than provider diagnostics.

        Args:
            code: Fixed local admission failure classification.
        """

        super().__init__(code)
        self.code = code


def AwareTime(value: object) -> datetime:
    """Require actual aware time and normalize it to UTC.

    Args:
        value: Receiver clock result or decoded recorded time.

    Returns:
        Aware UTC datetime without consulting another clock.
    """

    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise HeaderAdmissionDeniedError()

    return value.astimezone(timezone.utc)


class HeaderAdmission:
    """Pin one local admission window and full selected intent; never issue a PolicyGrant."""

    def __init__(self, root: Path, scope_id: str, workspace: WorkspaceState, model: ModelState,
                 receipt_id: str, target: Target, owner: str, analysis: str,
                 policy_provider: Callable[[], ImpactPolicy], approved: bool,
                 current_owner_provider: Callable[[], str] | None,
                 clock: Callable[[], datetime]) -> None:
        """Freeze selected attribution separately from the independent scope attester.

        Args:
            root: Existing workspace root.
            scope_id: Existing selected scope identifier.
            workspace: Original workspace CAS basis.
            model: Original model CAS basis.
            receipt_id: Explicit original acknowledged receipt ID.
            target: Exact selected original URL Target.
            owner: Selected operator attribution, not authentication.
            analysis: Explicit analysis identity.
            policy_provider: Fresh synchronous typed policy reader.
            approved: Separate explicit workflow opt-in.
            current_owner_provider: Optional trusted exact actor reader, not the attester.
            clock: Aware synchronous receiver clock, never renewed on progress.
        """

        self.root, self.scope_id = root, scope_id
        self.workspace, self.model = workspace, model
        self.receipt_id, self.target = receipt_id, target
        self.owner, self.analysis = owner, analysis
        self.policy_provider, self.approved = policy_provider, approved
        self.current_owner_provider, self.clock = current_owner_provider, clock
        self.literal_ip = Target(TargetKind.IP, Destination(target.value)[0])
        self.fixed: dict[str, object] | None = None
        self.issued: datetime | None = None
        self.expires: datetime | None = None
        self.last: datetime | None = None

    def CheckTime(self) -> datetime:
        """Fence synchronous work against regression and the original exclusive expiry.

        Returns:
            Fresh aware decision time, or a fixed refusal.
        """

        try:
            now = AwareTime(self.clock())

        except Exception:
            raise HeaderAdmissionDeniedError() from None

        if self.last is not None and now < self.last:
            raise HeaderAdmissionDeniedError("clock-regression")

        if self.issued is not None and self.expires is not None and not (
            self.issued <= now < self.expires
        ):
            raise HeaderAdmissionDeniedError("admission-expired")

        self.last = now

        return now

    def Check(self) -> dict[str, object]:
        """Read fresh scope, exact policy and actor within the same immutable local window.

        Fence the first authority read against its consumed time, then refresh authority once
        after the clock callback. No later clock callback can leave that selection stale.
        Each owner is read at most twice per Check. These ordered trusted reads are not an atomic
        temporal snapshot: the final refresh has no further clock callback and cannot preempt
        blocking readers or mutually mutating authority/time callbacks.

        Returns:
            Closed basis with a fresh checked_at; all other fields remain fixed.
        """

        self.CheckTime()

        try:
            observed_scope = LocalScopeStore(self.root).Open(self.scope_id)
            observed_policy = self.policy_provider()
            observed_owner = self.owner if self.current_owner_provider is None else (
                self.current_owner_provider())
            now = self.CheckTime()
            scope = LocalScopeStore(self.root).Open(self.scope_id)
            policy = self.policy_provider()
            owner = self.owner if self.current_owner_provider is None else (
                self.current_owner_provider())

            if type(observed_policy) is not ImpactPolicy or type(observed_owner) is not str or (
                observed_owner != self.owner or type(policy) is not ImpactPolicy
                or type(owner) is not str or owner != self.owner
            ):
                raise HeaderAdmissionDeniedError()

            if (scope, policy, owner) != (observed_scope, observed_policy, observed_owner):
                raise HeaderAdmissionDeniedError()

            if self.approved is not True or scope.workspace_id != self.workspace.workspace_id or (
                scope.Reference() not in self.workspace.scope_references
                or not scope.Check(self.target, at=now).Allowed()
                or not scope.Check(self.literal_ip, at=now).Allowed()
            ):
                raise HeaderAdmissionDeniedError()

            permission = next((item for item in policy.permissions if
                item.adapter_id == NATIVE_RESPONSE_PROVIDER_ID
                and item.capability_id == NATIVE_RESPONSE_CAPABILITY), None)
            impacts = tuple(ImpactLevel)

            if permission is None or impacts.index(ImpactLevel.PASSIVE) > impacts.index(
                policy.maximum_impact
            ) or impacts.index(ImpactLevel.PASSIVE) > impacts.index(permission.maximum_impact):
                raise HeaderAdmissionDeniedError()

            if self.issued is None:
                self.issued = now
                self.expires = now + timedelta(seconds=policy.max_authorization_seconds)

                if scope.authorization.valid_until is not None:
                    self.expires = min(self.expires, AwareTime(datetime.fromisoformat(
                        scope.authorization.valid_until)))

            if self.expires is None or not self.issued <= now < self.expires:
                raise HeaderAdmissionDeniedError("admission-expired")

            basis: dict[str, object] = {
                "workspace_id": self.workspace.workspace_id, "model_revision": self.model.revision,
                "workspace_revision": self.workspace.revision, "scope_reference": scope.Reference(),
                "scope_revision": scope.revision, "scope_sha256": Digest(scope.ToDict()),
                "policy_reference": policy.Reference(), "policy_revision": policy.revision,
                "policy_sha256": Digest(policy), "owner_reference": self.owner,
                "owner_attribution": "selected" if self.current_owner_provider is None else
                    "trusted-reader", "analysis_reference": self.analysis,
                "original_receipt_id": self.receipt_id,
                "source_target_reference": self.target.Reference(),
                "literal_ip_reference": self.literal_ip.Reference(),
                "capability": NATIVE_RESPONSE_CAPABILITY, "impact": "PASSIVE",
                "workflow_approved": True, "issued_at": self.issued.isoformat(),
                "expires_at": self.expires.isoformat(), "checked_at": now.isoformat(),
            }
            fixed = {key: value for key, value in basis.items() if key != "checked_at"}

            if self.fixed is not None and fixed != self.fixed:
                raise HeaderAdmissionDeniedError()

            self.fixed = fixed

            return basis

        except HeaderAdmissionDeniedError:
            raise

        except Exception:
            raise HeaderAdmissionDeniedError() from None


def SourceCall(admission: HeaderAdmission | None, read: Callable[[], _RESULT]) -> _RESULT:
    """Admit a bounded synchronous source phase before and after its actual return.

    Args:
        admission: Current attempt authority; absent only for historical verification.
        read: Existing source owner operation, without retries.

    Returns:
        Result only after the same original admission window remains valid.
    """

    if admission is not None:
        admission.Check()

    value = read()

    if admission is not None:
        admission.Check()

    return value


@dataclass(frozen=True, slots=True)
class OwnedHeaderSource:
    """Verified original association; construction alone grants no admission."""

    target: Target
    fact: Observation
    records: tuple[EvidenceRecord, ...]
    headers: bytes
    receipt_id: str
    job_id: str

    def RoleIds(self) -> dict[str, str]:
        """Return existing original manifest IDs by role without adopting a raw locator.

        Returns:
            Closed seven-role original ID mapping.
        """

        return {item.reference.role: item.evidence_id for item in self.records}


def ReadHeaderSource(root: Path, workspace: WorkspaceState, model: ModelState, receipt_id: str,
                     target: Target, scope_reference: str | None = None,
                     admission: HeaderAdmission | None = None) -> OwnedHeaderSource:
    """Join both original replay owners and exact retained seven-role source association.

    Args:
        root: Explicit existing or relocated workspace.
        workspace: Actual selected workspace snapshot.
        model: Actual selected model snapshot.
        receipt_id: Actual retained acknowledged receipt ID.
        target: Exact original URL Target.
        scope_reference: Selected original scope for a new analysis, absent for replay.
        admission: Fixed-window authority for a new analysis, absent for replay.

    Returns:
        Original role bytes and source association after complete successful verification.
    """

    product = SourceCall(admission, lambda: ReplayOwnedResponse(root, receipt_id))
    store = OwnedResponseEvidenceStore(root / "evidence")
    custody = SourceCall(admission, lambda: ReplayOwnedResponseCapture(store, receipt_id))
    record = ParseOwnedResponseCapture(custody.record_json, target.value)
    records = product.records
    identities = tuple(item.evidence_id for item in records)
    roles = {item.reference.role for item in records}

    if product.original_receipt_id != receipt_id or custody.receipt_id != receipt_id or (
        product.model_revision != model.revision or product.workspace_revision != workspace.revision
        or record["outcome"] != "captured" or record["url"] != target.value
        or len(records) != 7 or roles != _ROLES or len(set(identities)) != 7
        or set(identities) != {*custody.original_ids, custody.receipt_id}
        or any(identity not in workspace.evidence_record_references for identity in identities)
        or any(item.reference not in workspace.evidence_references for item in records)
        or product.original_job_id not in workspace.job_references
    ):
        raise NativeResponseHeaderError("original response source is unadmitted")

    for item in records:
        if SourceCall(admission, lambda: store.Get(item.evidence_id)) != item:
            raise NativeResponseHeaderError("original response source is unadmitted")

    receipt = next(item for item in records if item.evidence_id == receipt_id)
    original = receipt.provenance

    if original.workspace_id != workspace.workspace_id or original.source_id != PROVIDER_ID or (
        original.source_version != "1" or original.tool_version != "1"
        or original.scope_reference not in workspace.scope_references
        or scope_reference is not None and original.scope_reference != scope_reference
        or original.execution is None or original.execution.state is not ExecutionState.SUCCEEDED
        or original.execution.exit_code != 0
        or any(item.provenance != original for item in records)
    ):
        raise NativeResponseHeaderError("original response source is unadmitted")

    expected = SourceFact(workspace.workspace_id, record, records, receipt_id,
        product.original_job_id)
    facts = tuple(item for item in model.observations if item.kind == SOURCE_KIND and
        item.attributes.get("original_receipt_id") == receipt_id)
    endpoint_id = ObjectIdentity(workspace.workspace_id, ObjectKind.ENDPOINT, target.value)
    endpoint = next((item for item in model.objects if item.identity == endpoint_id), None)

    if facts != (expected,) or endpoint is None or (
        expected.provenance not in endpoint.provenance or
        endpoint.Reference() not in workspace.object_references
        or CanonicalModelJson(product.source_facts) != CanonicalModelJson(expected.attributes)
    ):
        raise NativeResponseHeaderError("original response source is unadmitted")

    header = next(item for item in records if item.reference.role == "owned-response-headers")
    raw = SourceCall(admission, lambda: store.Read(header.reference))
    report = record["response_headers"]

    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_HEADER_BYTES or (
        header.reference.media_type != "application/octet-stream"
        or len(raw) != header.reference.size_bytes
        or hashlib.sha256(raw).hexdigest() != header.reference.sha256
        or type(report) is not dict or type(report.get("size_bytes")) is not int
        or report.get("size_bytes") != len(raw)
        or report.get("sha256") != header.reference.sha256
    ):
        raise NativeResponseHeaderError("original response source is unadmitted")

    return OwnedHeaderSource(target, expected, records, raw, receipt_id, product.original_job_id)


def HeaderFinding(source: OwnedHeaderSource, provenance: ModelProvenance) -> Finding:
    """Construct the one native positive without changing triage or interpreting body text.

    Args:
        source: Fully verified original source.
        provenance: Honest offline interpretation attribution, with execution absent.

    Returns:
        Untriaged LOW detection with unknown confidence and fixed location/summary.
    """

    return Finding(source.fact.subject_reference, NATIVE_RESPONSE_CHECK_ID,
        source.target.value + "#response-header:x-content-type-options", NATIVE_RESPONSE_SUMMARY,
        (provenance,), FindingSeverity.LOW)


def HeaderAssessment(source: OwnedHeaderSource, provenance: ModelProvenance,
                     condition: bool, basis: Mapping[str, object]) -> Observation:
    """Build bounded closed metadata without copying raw headers, body or authority secrets.

    Args:
        source: Original custody-verified association.
        provenance: Receiver interpretation attribution, never an acquisition job.
        condition: Exact field-name absence result.
        basis: Final fresh fixed-window decision.

    Returns:
        One new content-addressed native assessment observation.
    """

    attributes = {"schema_version": 1, "profile": NATIVE_RESPONSE_PROFILE,
        "check_id": NATIVE_RESPONSE_CHECK_ID, "analysis_reference": provenance.run_reference,
        "original_receipt_id": source.receipt_id, "original_job_id": source.job_id,
        "source_observation_reference": source.fact.Reference(),
        "original_role_ids": source.RoleIds(), "header_sha256": hashlib.sha256(
            source.headers).hexdigest(), "condition_observed": condition, "authority_basis": basis}

    if len(CanonicalModelJson(attributes)) > MAX_ASSESSMENT_BYTES:
        raise NativeResponseHeaderError("native response assessment is unadmitted")

    return Observation(NATIVE_RESPONSE_ASSESSMENT_KIND, source.fact.subject_reference,
        attributes, provenance)


def VerifyHeaderAssessment(workspace: WorkspaceState, model: ModelState,
                           assessment: Observation, source: OwnedHeaderSource) -> str | None:
    """Verify recorded interpretation and positive detection while allowing later valid triage.

    Args:
        workspace: Actual current relocated workspace snapshot.
        model: Actual current model snapshot.
        assessment: Actual selected retained observation.
        source: Independently reopened original source.

    Returns:
        Required retained positive Finding reference, or None for a negative observation.
    """

    attributes = json.loads(CanonicalModelJson(assessment.attributes))
    basis = attributes.get("authority_basis")
    provenance = assessment.provenance

    if assessment.kind != NATIVE_RESPONSE_ASSESSMENT_KIND or (
        set(attributes) != _ASSESSMENT_FIELDS or
        type(basis) is not dict or set(basis) != _BASIS_FIELDS
        or type(attributes.get("condition_observed")) is not bool
        or type(attributes.get("schema_version")) is not int or attributes["schema_version"] != 1
    ):
        raise NativeResponseHeaderError("native response assessment is unadmitted")

    for name in ("model_revision", "workspace_revision", "scope_revision", "policy_revision"):
        RequireWorkspaceInteger(basis[name], name)

    for name in ("workspace_id", "scope_reference", "policy_reference", "owner_reference",
                 "analysis_reference", "original_receipt_id", "source_target_reference",
                 "literal_ip_reference"):
        if type(basis[name]) is not str:
            raise NativeResponseHeaderError("native response assessment is unadmitted")

        RequireWorkspaceText(basis[name], name)

    if any(type(basis[name]) is not str or _SHA256.fullmatch(basis[name]) is None for name in (
        "scope_sha256", "policy_sha256"
    )) or basis["owner_attribution"] not in ("selected", "trusted-reader") or (
        basis["capability"] != NATIVE_RESPONSE_CAPABILITY or basis["impact"] != "PASSIVE"
        or basis["workflow_approved"] is not True
        or basis["workspace_id"] != workspace.workspace_id
        or basis["scope_reference"] != source.fact.provenance.scope_reference
        or basis["source_target_reference"] != source.target.Reference()
        or basis["literal_ip_reference"] != Target(TargetKind.IP,
            Destination(source.target.value)[0]).Reference()
        or basis["original_receipt_id"] != source.receipt_id
        or basis["analysis_reference"] != provenance.run_reference
        or not cast(str, basis["policy_reference"]).startswith("policy:")
        or cast(int, basis["model_revision"]) >= model.revision
        or cast(int, basis["workspace_revision"]) > workspace.revision
    ):
        raise NativeResponseHeaderError("native response assessment is unadmitted")

    times = []

    for name in ("issued_at", "checked_at", "expires_at"):
        text = basis[name]

        if type(text) is not str:
            raise NativeResponseHeaderError("native response assessment is unadmitted")

        at = AwareTime(datetime.fromisoformat(text))

        if at.isoformat() != text:
            raise NativeResponseHeaderError("native response assessment is unadmitted")

        times.append(at)

    issued, checked, expires = times
    observed = AwareTime(datetime.fromisoformat(provenance.observed_at))
    expected_provenance = ModelProvenance(NATIVE_RESPONSE_PROVIDER_ID, provenance.run_reference,
        provenance.observed_at, source.fact.provenance.scope_reference, source.target.Reference(),
        NATIVE_RESPONSE_VERSION, tuple(item.reference for item in source.records), None)

    if not issued <= observed <= checked < expires or (
        expires - issued > timedelta(seconds=3600) or provenance != expected_provenance or
        type(attributes["analysis_reference"]) is not str
        or attributes["analysis_reference"] != provenance.run_reference
        or provenance.run_reference == source.job_id
        or attributes["condition_observed"] is not HeaderFieldAbsent(source.headers)
        or assessment != HeaderAssessment(source, provenance,
            attributes["condition_observed"], basis)
    ):
        raise NativeResponseHeaderError("native response assessment is unadmitted")

    if not attributes["condition_observed"]:
        return None

    finding = HeaderFinding(source, provenance)
    reference = finding.ToObject(workspace.workspace_id).Reference()
    entity = next((item for item in model.objects if item.Reference() == reference), None)
    detection = Observation("finding-detection", reference, finding.ToAttributes(), provenance)

    if entity is None or (
        provenance not in entity.provenance or detection not in model.observations
    ):
        raise NativeResponseHeaderError("native response assessment is unadmitted")

    actual = Finding.FromObject(entity)

    if actual.Fingerprint() != finding.Fingerprint():
        raise NativeResponseHeaderError("native response assessment is unadmitted")

    if reference not in workspace.object_references:
        raise MissingHeaderRetentionError("native response finding retention is incomplete")

    return reference


@dataclass(frozen=True, slots=True)
class OwnedResponseHeaderCheckSummary:
    """Truthful separate persistence outcomes, without a fabricated executor result."""

    state: str
    original_receipt_id: str
    analysis_reference: str
    source_target_reference: str
    condition_observed: bool | None = None
    assessment_reference: str | None = None
    finding_reference: str | None = None
    model_commit: str = "not-attempted"
    workspace_commit: str = "not-attempted"
    model_revision: int | None = None
    workspace_revision: int | None = None
    failure: str | None = None

    def ToDict(self) -> dict[str, object]:
        """Render the closed version-one SDK result without rejected diagnostic material.

        Returns:
            Safe current attempt result with independent store ACK classifications.
        """

        return {"schema_version": 1, "workflow": "owned-response-header-check", "state": self.state,
            "source_id": NATIVE_RESPONSE_PROVIDER_ID, "profile": NATIVE_RESPONSE_PROFILE,
            "check_id": NATIVE_RESPONSE_CHECK_ID, "impact": "PASSIVE",
            "original_receipt_id": self.original_receipt_id,
            "analysis_reference": self.analysis_reference,
            "source_target_reference": self.source_target_reference,
            "condition_observed": self.condition_observed,
            "assessment_reference": self.assessment_reference,
            "finding_reference": self.finding_reference, "model_commit": self.model_commit,
            "workspace_commit": self.workspace_commit, "model_revision": self.model_revision,
            "workspace_revision": self.workspace_revision, "failure": self.failure}


@dataclass(frozen=True, slots=True)
class OwnedResponseHeaderReplaySummary:
    """Verified historical interpretation, never a renewed live authority or repaired ACK."""

    original_receipt_id: str
    analysis_reference: str
    assessment_reference: str
    condition_observed: bool
    finding_reference: str | None
    model_revision: int
    workspace_revision: int

    def ToDict(self) -> dict[str, object]:
        """Render the closed historical result without target access or new persistence.

        Returns:
            Safe original assessment identity and current verified retained revisions.
        """

        return {"schema_version": 1, "workflow": "owned-response-header-replay",
            "state": "verified",
            "source_id": NATIVE_RESPONSE_PROVIDER_ID, "profile": NATIVE_RESPONSE_PROFILE,
            "check_id": NATIVE_RESPONSE_CHECK_ID, "original_receipt_id": self.original_receipt_id,
            "analysis_reference": self.analysis_reference,
            "assessment_reference": self.assessment_reference,
            "condition_observed": self.condition_observed,
            "finding_reference": self.finding_reference,
            "model_revision": self.model_revision, "workspace_revision": self.workspace_revision}


def RequireHeaderConfiguration(root: Path, scope_id: str, receipt_id: str, target: Target,
                               owner: str, policy: Callable[[], ImpactPolicy], analysis: str,
                               model_revision: int, workspace_revision: int, approved: bool,
                               actor: Callable[[], str] | None,
                               clock: Callable[[], datetime]) -> None:
    """Reject malformed preconfiguration before source I/O, without interpreting it as consent.

    Args:
        root: Existing explicit workspace path.
        scope_id: Existing selected scope identity.
        receipt_id: Original acknowledged receipt manifest ID.
        target: Exact original URL Target.
        owner: Non-secret selected operator attribution.
        policy: Fresh typed policy reader.
        analysis: Explicit independent analysis identity.
        model_revision: Selected model CAS basis.
        workspace_revision: Selected workspace CAS basis.
        approved: Exact separate opt-in boolean.
        actor: Optional trusted synchronous actor reader.
        clock: Aware receiver clock reader.
    """

    try:
        if not isinstance(root, Path) or type(target) is not Target or (
            target.kind is not TargetKind.URL or type(approved) is not bool
            or not callable(policy) or not callable(clock)
            or actor is not None and not callable(actor)
            or type(receipt_id) is not str or _RECEIPT_ID.fullmatch(receipt_id) is None
        ):
            raise ValueError("configuration")

        Destination(target.value)

        for text in (scope_id, owner, analysis):
            RequireWorkspaceText(text, "selection")

        RequireWorkspaceInteger(model_revision, "model_revision")
        RequireWorkspaceInteger(workspace_revision, "workspace_revision")

        if len(CanonicalModelJson((scope_id, receipt_id, target.Reference(), owner, analysis))) > (
            MAX_ASSESSMENT_BYTES
        ):
            raise ValueError("configuration")

    except Exception:
        raise NativeResponseHeaderError("native response header configuration is invalid") from None


class HeaderAttempt:
    """Keep original-basis persistence and independent outcome observation in one attempt."""

    def __init__(self, root: Path, receipt_id: str, analysis: str, target: Target) -> None:
        """Initialize outcome tracking without reading sources or granting permission.

        Args:
            root: Selected existing workspace root.
            receipt_id: Selected original receipt.
            analysis: Explicit new analysis identity.
            target: Selected exact original URL.
        """

        self.root, self.receipt_id, self.analysis, self.target = root, receipt_id, analysis, target
        self.workspace: WorkspaceState | None = None
        self.model: ModelState | None = None
        self.model_proposed: ModelState | None = None
        self.workspace_proposed: WorkspaceState | None = None
        self.model_attempted = self.workspace_attempted = False
        self.model_acknowledged = self.workspace_acknowledged = False
        self.assessment: Observation | None = None
        self.finding_reference: str | None = None

    def Summary(self, failure: str | None = None,
                state: str | None = None) -> OwnedResponseHeaderCheckSummary:
        """Observe actual retained metadata after an attempt without retrying either Save.

        Args:
            failure: Closed safe failure code, if any.
            state: Explicit already-applied state after complete verification.

        Returns:
            Honest ACK and observed persistence state, preserving uncertainty.
        """

        actual_model = None
        actual_workspace = None

        try:
            actual_model = LocalModelStore(self.root).Open()

        except Exception:
            pass

        try:
            actual_workspace = LocalWorkspaceStore(self.root).Open()

        except Exception:
            pass

        model_status = PersistenceStatus(actual_model, self.model, self.model_proposed,
            self.model_attempted, self.model_acknowledged)
        workspace_status = PersistenceStatus(actual_workspace, self.workspace,
            self.workspace_proposed, self.workspace_attempted, self.workspace_acknowledged)
        retained = self.assessment is not None and actual_model is not None and (
            self.assessment in actual_model.observations)
        condition = cast(bool, self.assessment.attributes["condition_observed"]) if retained and (
            self.assessment is not None) else None
        committed = model_status in ("acknowledged", "observed-committed")

        if state is None:
            state = "completed" if failure is None else "partial" if committed else (
                "denied" if failure in ("authorization", "admission-expired", "clock-regression")
                else "failed")

        return OwnedResponseHeaderCheckSummary(state, self.receipt_id, self.analysis,
            self.target.Reference(), condition,
            self.assessment.Reference() if retained and self.assessment is not None else None,
            self.finding_reference if retained else None, model_status, workspace_status,
            actual_model.revision if actual_model is not None else None,
            actual_workspace.revision if actual_workspace is not None else None, failure)

    def Run(self, scope_id: str, owner: str, policy: Callable[[], ImpactPolicy], approved: bool,
            actor: Callable[[], str] | None, clock: Callable[[], datetime],
            model_revision: int, workspace_revision: int) -> OwnedResponseHeaderCheckSummary:
        """Apply one original-basis analysis without retry, synthetic custody or new jobs.

        Args:
            scope_id: Existing exact source scope.
            owner: Fixed selected actor attribution.
            policy: Fresh typed current policy reader.
            approved: Separate exact opt-in.
            actor: Optional trusted fresh actor reader.
            clock: Monotonic aware receiver decision clock.
            model_revision: Caller selected original model revision.
            workspace_revision: Caller selected original workspace revision.

        Returns:
            One truthful synchronous SDK outcome, including late or partial refusal.
        """

        phase = "storage"

        try:
            workspace_store = LocalWorkspaceStore(self.root)
            self.root = workspace_store.root
            workspace = self.workspace = workspace_store.Open()
            model_store = LocalModelStore(self.root)
            model = self.model = model_store.Open()

            if model.workspace_id != workspace.workspace_id or model.revision != model_revision or (
                workspace.revision != workspace_revision
            ):
                raise WorkspaceConflictError("original basis changed")

            admission = HeaderAdmission(self.root, scope_id, workspace, model, self.receipt_id,
                self.target, owner, self.analysis, policy, approved, actor, clock)
            basis = admission.Check()
            phase = "source"
            source = ReadHeaderSource(self.root, workspace, model, self.receipt_id, self.target,
                cast(str, basis["scope_reference"]), admission)

            if self.analysis == source.job_id:
                raise NativeResponseHeaderError("analysis identity differs from acquisition")

            previous = tuple(item for item in model.observations if
                item.kind == NATIVE_RESPONSE_ASSESSMENT_KIND and
                item.attributes.get("analysis_reference") == self.analysis)

            if previous:
                if len(previous) != 1:
                    raise NativeResponseHeaderError("analysis identity is already bound")

                assessment = previous[0]
                prior_basis = assessment.attributes.get("authority_basis")

                if not isinstance(prior_basis, Mapping) or (
                    prior_basis.get("owner_reference") != owner
                ):
                    raise NativeResponseHeaderError("analysis identity is already bound")

                try:
                    reference = SourceCall(admission, lambda: VerifyHeaderAssessment(
                        workspace, model, assessment, source))

                except MissingHeaderRetentionError:
                    admission.Check()
                    self.assessment = assessment
                    self.finding_reference = HeaderFinding(source, assessment.provenance).ToObject(
                        workspace.workspace_id).Reference()

                    return self.Summary("storage", "partial")
                SourceCall(admission, lambda: self.RequireBases(model, workspace))
                admission.Check()
                self.assessment, self.finding_reference = assessment, reference

                return self.Summary(state="already-applied")

            admission.Check()
            condition = HeaderFieldAbsent(source.headers)
            interpreted = admission.Check()
            provenance = ModelProvenance(NATIVE_RESPONSE_PROVIDER_ID, self.analysis,
                cast(str, interpreted["checked_at"]), source.fact.provenance.scope_reference,
                self.target.Reference(), NATIVE_RESPONSE_VERSION,
                tuple(item.reference for item in source.records), None)
            finding = HeaderFinding(source, provenance) if condition else None
            proposed, _ = SourceCall(admission, lambda: ApplyVerifiedFindings(model,
                (finding,) if finding is not None else (), self.root))
            SourceCall(admission, lambda: self.RequireBases(model, workspace))
            final_basis = admission.Check()
            self.assessment = HeaderAssessment(source, provenance, condition, final_basis)
            self.finding_reference = finding.ToObject(workspace.workspace_id).Reference() if (
                finding is not None) else None
            self.model_proposed, _ = model.Apply(objects=proposed.objects,
                relations=proposed.relations,
                observations=(*proposed.observations, self.assessment))
            phase = "storage"
            self.model_attempted = True
            acknowledged = model_store.Save(self.model_proposed, expected_revision=model.revision)

            if acknowledged != self.model_proposed:
                raise NativeResponseHeaderError("model acknowledgement differs")

            self.model_acknowledged = True
            admission.CheckTime()
            references = workspace.object_references

            if self.finding_reference is not None and self.finding_reference not in references:
                references = tuple(sorted((*references, self.finding_reference)))
                proposal = replace(workspace, object_references=references)
                self.workspace_proposed = replace(proposal, revision=workspace.revision + 1)
                committed_model = self.model_proposed
                SourceCall(admission, lambda: self.RequireBases(committed_model, workspace))
                admission.Check()
                self.workspace_attempted = True
                acknowledged_workspace = workspace_store.Save(proposal)

                if acknowledged_workspace != self.workspace_proposed:
                    raise NativeResponseHeaderError("workspace acknowledgement differs")

                self.workspace_acknowledged = True
                admission.CheckTime()

            return self.Summary()

        except HeaderAdmissionDeniedError as error:
            return self.Summary(error.code)

        except WorkspaceConflictError:
            return self.Summary("revision-conflict")

        except Exception:
            return self.Summary(phase)

    def RequireBases(self, model: ModelState, workspace: WorkspaceState) -> None:
        """Reopen exact selected content before final authority, without rebasing proposals.

        Args:
            model: Exact original or acknowledged model state required at this boundary.
            workspace: Exact original workspace CAS basis.
        """

        if LocalModelStore(self.root).Open() != model or LocalWorkspaceStore(self.root).Open() != (
            workspace
        ):
            raise WorkspaceConflictError("original basis changed")


def ApplyOwnedResponseHeaderCheck(
    workspace_root: Path, scope_id: str, original_receipt_id: str,
    source_target: Target, owner_reference: str, policy_provider: Callable[[], ImpactPolicy], *,
    analysis_reference: str, expected_model_revision: int, expected_workspace_revision: int,
    approve_passive_header_check: bool = False,
    current_owner_provider: Callable[[], str] | None = None,
    clock: Callable[[], datetime] = UtcNow,
) -> OwnedResponseHeaderCheckSummary:
    """Interpret one verified original response with separate explicit PASSIVE admission.

    Default attribution is the selected operator; external actor changes can be detected only
    through an actually supplied trusted synchronous current_owner_provider. No authentication,
    executor invocation, new evidence, capture, current grant or hidden retry is manufactured.

    Args:
        workspace_root: Existing explicit owning workspace path.
        scope_id: Existing original source scope identity.
        original_receipt_id: Actual original acknowledged receipt manifest ID.
        source_target: Exact selected original URL Target.
        owner_reference: Fixed selected operator attribution, independent of the consent attester.
        policy_provider: Fresh exact typed policy reader with an explicit native permission.
        analysis_reference: Explicit independent non-secret analysis identity.
        expected_model_revision: Caller selected original model CAS basis.
        expected_workspace_revision: Caller selected original workspace CAS basis.
        approve_passive_header_check: Separate opt-in, default denied.
        current_owner_provider: Optional trusted actor reader, never an attester alias.
        clock: Fresh aware receiver clock; original window never renews.

    Returns:
        Truthful completed, denied, failed, already-applied or partial outcome.
    """

    RequireHeaderConfiguration(workspace_root, scope_id, original_receipt_id, source_target,
        owner_reference, policy_provider, analysis_reference, expected_model_revision,
        expected_workspace_revision, approve_passive_header_check, current_owner_provider, clock)
    attempt = HeaderAttempt(workspace_root, original_receipt_id, analysis_reference, source_target)

    return attempt.Run(scope_id, owner_reference, policy_provider, approve_passive_header_check,
        current_owner_provider, clock, expected_model_revision, expected_workspace_revision)


def ReplayOwnedResponseHeaderCheck(
    workspace_root: Path, original_assessment_reference: str,
) -> OwnedResponseHeaderReplaySummary:
    """Verify an actual historical native assessment after relocation, without current grant.

    Args:
        workspace_root: Existing explicit relocated workspace root.
        original_assessment_reference: Actual retained native Observation reference.

    Returns:
        Verified original interpretation and optional retained positive Finding identity.

    Raises:
        NativeResponseHeaderError: Historical source, association or interpretation is invalid.
    """

    try:
        if not isinstance(workspace_root, Path) or (
            type(original_assessment_reference) is not str or
            not original_assessment_reference.startswith("observation:")
        ):
            raise ValueError("selection")

        workspace_store = LocalWorkspaceStore(workspace_root)
        workspace = workspace_store.Open()
        model = LocalModelStore(workspace_store.root).Open()
        matches = tuple(item for item in model.observations if
            item.Reference() == original_assessment_reference)

        if len(matches) != 1 or model.workspace_id != workspace.workspace_id:
            raise ValueError("selection")

        assessment = matches[0]
        endpoint = next((item for item in model.objects if
            item.Reference() == assessment.subject_reference), None)

        if endpoint is None or endpoint.identity.kind is not ObjectKind.ENDPOINT:
            raise ValueError("subject")

        target = Target(TargetKind.URL, endpoint.identity.key)
        Destination(target.value)
        receipt_id = assessment.attributes.get("original_receipt_id")

        if type(receipt_id) is not str or _RECEIPT_ID.fullmatch(receipt_id) is None:
            raise ValueError("receipt")

        source = ReadHeaderSource(workspace_store.root, workspace, model, receipt_id, target)
        reference = VerifyHeaderAssessment(workspace, model, assessment, source)

        return OwnedResponseHeaderReplaySummary(receipt_id,
            cast(str, assessment.attributes["analysis_reference"]), assessment.Reference(),
            cast(bool, assessment.attributes["condition_observed"]), reference,
            model.revision, workspace.revision)

    except Exception:
        raise NativeResponseHeaderError("native response header replay is unverified") from None
