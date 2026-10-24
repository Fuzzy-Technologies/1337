# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Governed content-driven traversal over a fixed admitted owned-loopback URL selection."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fuzzy1337.adapters import (
    AdapterRequest,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
    NormalizedObservation,
    SerializeContract,
)
from fuzzy1337.adapters.native_crawl import (
    MAX_RECORD_BYTES,
    NATIVE_CRAWL_CAPABILITY,
    NATIVE_CRAWL_PROFILE,
    NATIVE_CRAWL_PROVIDER_ID,
    NATIVE_CRAWL_VERSION,
    BuildCrawlInput,
    CrawlEndpoint,
    CrawlTemplate,
    EncodeCrawlInput,
    NativeCrawlAdapter,
    ParseCrawlInput,
    ParseCrawlRecord,
)
from fuzzy1337.adapters.page_capture import Seconds
from fuzzy1337.captured_web import WebInteger
from fuzzy1337.evidence import EvidenceError, EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptors,
    ExecutionResources,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutionResult,
)
from fuzzy1337.executors.contracts import ExecutionEvent, ExecutionEventKind, ExecutionTermination
from fuzzy1337.executors.local import LocalExecutionError
from fuzzy1337.jobs import JobContext, JobError, JobFailure, JobFailureCode
from fuzzy1337.model import (
    MAX_MODEL_BYTES,
    CanonicalModelJson,
    LocalModelStore,
    ModelProvenance,
    ModelState,
    ObjectKind,
    Observation,
)
from fuzzy1337.page_capture import ValidateResult
from fuzzy1337.policy import (
    Digest,
    GovernedLocalExecutor,
    ImpactPolicy,
    PolicyContext,
    PolicyEngine,
    PolicyGrant,
    UtcNow,
)
from fuzzy1337.requests import ProjectRequests, RequestsFromObject
from fuzzy1337.scope import LocalScopeStore, Target, TargetKind
from fuzzy1337.workspace import LocalWorkspaceStore, RequireWorkspaceText, WorkspaceConflictError


class NativeCrawlAuthorityDeniedError(PermissionError):
    """Current independent attribution, explicit workflow approval or selected authority differs."""


@dataclass(frozen=True, slots=True)
class NativeCrawlAuthority:
    """Keep independent actor attribution separate from the scope's consent attester."""

    context: PolicyContext
    owner_reference: str
    workflow_approved: bool

    def __post_init__(self) -> None:
        """Require exact local authority fields without manufacturing execution permission."""

        if type(self.context) is not PolicyContext or type(self.owner_reference) is not str or (
            type(self.workflow_approved) is not bool
        ):
            raise ValueError("native crawl requires exact authority fields")

        RequireWorkspaceText(self.owner_reference, "owner_reference")


@dataclass(frozen=True, slots=True)
class NativeCrawlLimits:
    """Bound whole-wave reservations and one original operation without refund or renewal."""

    max_pages: int = 16
    max_depth: int = 4
    concurrency: int = 2
    max_total_body_bytes: int = 262144
    start_interval_seconds: float = 0.05
    timeout_seconds: float = 30.0
    max_body_bytes: int = 16384
    request_timeout_ms: int = 3000

    def __post_init__(self) -> None:
        """Reject coercions and limits outside the accepted finite contract."""

        WebInteger(self.max_pages, 1, 16)
        WebInteger(self.max_depth, 0, 4)
        WebInteger(self.concurrency, 1, 4)
        WebInteger(self.max_total_body_bytes, 1, 1048576)
        Seconds(self.start_interval_seconds, 1)
        Seconds(self.timeout_seconds, 60)
        WebInteger(self.max_body_bytes, 1, 65536)
        WebInteger(self.request_timeout_ms, 50, 5000)


def CurrentCrawlAuthority(
    workspace_root: Path, scope_id: str, source: Target,
    selected_urls: tuple[Target, ...], owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy], workflow_approved: bool, *,
    current_owner_provider: Callable[[], str] | None = None,
) -> NativeCrawlAuthority:
    """Read fresh original source authority while preserving the independent consent attester.

    Complete selection permission is checked at the same explicit decision time by the
    consuming boundary; this reader does not substitute wall time for its injected clock.

    Args:
        workspace_root: Existing physical owning workspace.
        scope_id: Existing caller-selected scope identifier.
        source: Exact current selected URL Target.
        selected_urls: Entire immutable sorted selected URL Target tuple.
        owner_reference: Original fixed selected actor attribution.
        policy_provider: Synchronous current typed policy reader.
        workflow_approved: Exact independent workflow approval.
        current_owner_provider: Optional trusted attribution reader, without authentication.

    Returns:
        Fresh immutable actor/context wrapper; canonical policy still checks source and IP.

    Raises:
        NativeCrawlAuthorityDeniedError: Attribution or complete workspace selection differs.
    """

    RequireWorkspaceText(owner_reference, "owner_reference")

    try:
        actor = owner_reference if current_owner_provider is None else current_owner_provider()

    except Exception:
        raise NativeCrawlAuthorityDeniedError("native crawl current attribution unavailable") \
            from None

    if type(actor) is not str or actor != owner_reference:
        raise NativeCrawlAuthorityDeniedError("native crawl current attribution changed")

    if type(source) is not Target or source.kind is not TargetKind.URL or (
        type(selected_urls) is not tuple or not 1 <= len(selected_urls) <= 16
        or any(type(item) is not Target or item.kind is not TargetKind.URL
               for item in selected_urls)
        or source not in selected_urls
        or tuple(item.value for item in selected_urls) != tuple(sorted({
            item.value for item in selected_urls}))
    ):
        raise ValueError("native crawl requires the original complete sorted selection")

    try:
        policy = policy_provider()

    except Exception:
        raise NativeCrawlAuthorityDeniedError("native crawl current policy unavailable") from None

    if type(policy) is not ImpactPolicy:
        raise ValueError("native crawl requires a typed current policy")

    scope = LocalScopeStore(workspace_root).Open(scope_id)

    if scope.workspace_id != LocalWorkspaceStore(workspace_root).Open().workspace_id:
        raise NativeCrawlAuthorityDeniedError("native crawl scope workspace differs")

    parsed = urlsplit(source.value)
    _, address, _, _, _ = CrawlEndpoint(source.value)

    if address not in ("127.0.0.1", "::1") or any(
        urlsplit(item.value).netloc != parsed.netloc for item in selected_urls
    ):
        raise ValueError("native crawl selection requires one literal loopback origin")

    return NativeCrawlAuthority(PolicyContext(scope, policy, source,
        (source, Target(TargetKind.IP, address))), actor, workflow_approved)


class NativeCrawlEvidenceStore(LocalEvidenceStore):
    """Apply closed role ceilings before the existing owner's eager Get/Read allocation."""

    def Read(self, reference: EvidenceReference) -> bytes:
        """Read only bounded original reports, empty stderr and separate parent control facts.

        Args:
            reference: Actual manifest reference including the unchanged Get readback path.

        Returns:
            Independently verified bytes within the selected closed role ceiling.
        """

        if type(reference) is not EvidenceReference:
            raise ValueError("native crawl requires exact evidence references")

        if reference.role == "stdout" and reference.media_type == "application/json":
            maximum = MAX_RECORD_BYTES

        elif reference.role == "stderr" and reference.media_type == "application/octet-stream":
            maximum = 0

        elif reference.role == "native-crawl-control" and (
            reference.media_type == "application/json"
        ):
            maximum = 65536

        else:
            raise ValueError("native crawl evidence role is unsupported")

        WebInteger(reference.size_bytes, 0, maximum)

        return super().Read(reference)


@dataclass(frozen=True, slots=True)
class NativeCrawlPage:
    """Bind a report to its exact original invocation, grant and acknowledged stream records."""

    input_json: bytes
    request: LocalExecutionRequest
    grant: PolicyGrant
    result: LocalExecutionResult
    report_json: bytes
    records: tuple[EvidenceRecord, ...]


async def SettleCrawlTask(task: asyncio.Future[Any]) -> Any:
    """Settle one original owned task through repeated caller cancellation without spinning.

    Args:
        task: One already-created original cleanup or provider task.

    Returns:
        Original actual result after settlement.

    Raises:
        RuntimeError: The original cleanup task itself terminated without confirmation.
        BaseException: Original owned task failure, after its cleanup finished.
    """

    while not task.done():
        try:
            await asyncio.shield(task)

        except asyncio.CancelledError:
            continue

    if task.cancelled():
        raise RuntimeError("Native crawl owned cleanup terminated without confirmation")

    return task.result()


class NativeCrawlProvider:
    """Own finite concurrent acquisition, sorted incremental source projection and cleanup."""

    def __init__(
        self, workspace_root: Path, scope_id: str, seed_url: str,
        selected_urls: tuple[str, ...], owner_reference: str,
        policy_provider: Callable[[], ImpactPolicy], *, approve_safe_crawl: bool,
        limits: NativeCrawlLimits = NativeCrawlLimits(),
        clock: Callable[[], datetime] = UtcNow,
        current_owner_provider: Callable[[], str] | None = None,
    ) -> None:
        """Freeze the explicit selection without target contact or automatic enrollment.

        Args:
            workspace_root: Existing physical workspace/model/scope partition.
            scope_id: Existing consented source scope.
            seed_url: Original canonical seed URL, sole initial frontier entry.
            selected_urls: Complete sorted distinct same-origin admitted URL selection.
            owner_reference: Original executing attribution, independent of attestation.
            policy_provider: Fresh synchronous typed acquisition policy reader.
            approve_safe_crawl: Exact independent SAFE workflow approval.
            limits: Accepted finite allocation, scheduling and inclusive operation bounds.
            clock: Fresh aware policy and evidence decision clock.
            current_owner_provider: Optional trusted fresh attribution, not authentication.
        """

        if type(limits) is not NativeCrawlLimits or type(approve_safe_crawl) is not bool:
            raise ValueError("native crawl requires exact limits and explicit boolean approval")

        self.root = LocalWorkspaceStore(workspace_root).root
        self.workspace_id = LocalWorkspaceStore(self.root).Open().workspace_id
        self.input = BuildCrawlInput(self.workspace_id, seed_url, seed_url, selected_urls,
            max_body_bytes=limits.max_body_bytes, request_timeout_ms=limits.request_timeout_ms)
        self.seed_url, self.selected_urls = seed_url, selected_urls
        self.targets = tuple(Target(TargetKind.URL, url) for url in selected_urls)
        self.scope_id, self.owner_reference = scope_id, owner_reference
        self.policy_provider, self.approved = policy_provider, approve_safe_crawl
        self.limits, self.clock = limits, clock
        self.current_owner_provider = current_owner_provider
        self.store = NativeCrawlEvidenceStore(self.root / "evidence")
        self.adapter = NativeCrawlAdapter(self.store.Read)
        self.capability = next(item for item in CapabilityDescriptors(self.adapter.Descriptor)
                               if item.identifier == NATIVE_CRAWL_CAPABILITY)
        self.completed_urls: tuple[str, ...] = ()
        self.pages: tuple[NativeCrawlPage, ...] = ()
        self.model_saves: list[dict[str, object]] = []
        self.persistence_model: ModelState | None = LocalModelStore(self.root).Open()
        self._publications: dict[str, tuple[EvidenceRecord, bytes, bool]] = {}
        self._context: JobContext | None = None
        self._task: asyncio.Task[Any] | None = None
        self._origin: float | None = None
        self._scope_digest: str | None = None
        self._policy_digest: str | None = None

    def Current(self, source_url: str, context: JobContext | None = None) -> NativeCrawlAuthority:
        """Reread actor, complete selected scope membership and source/IP policy context.

        Args:
            source_url: Exact original selected source.
            context: Actual current job when execution or persistence is underway.

        Returns:
            Fresh original-bound authority wrapper, never a cached context.
        """

        authority = CurrentCrawlAuthority(self.root, self.scope_id,
            Target(TargetKind.URL, source_url), self.targets, self.owner_reference,
            self.policy_provider, self.approved, current_owner_provider=self.current_owner_provider)

        if authority.context.scope.workspace_id != self.workspace_id or context is not None and (
            context is not self._context
            or context.Spec.owner_reference != authority.owner_reference
            or context.Spec.workspace_id != self.workspace_id
            or context.Spec.provider_id != NATIVE_CRAWL_PROVIDER_ID
            or context.Spec.scope_reference != authority.context.scope.Reference()
            or not authority.workflow_approved
        ):
            raise NativeCrawlAuthorityDeniedError("native crawl owning authority differs")

        at = self.clock()

        for target in (*self.targets, *authority.context.destinations):
            if not authority.context.scope.Check(target, at=at).Allowed():
                raise NativeCrawlAuthorityDeniedError("native crawl complete selection is denied")

        if self._scope_digest is not None and (
            Digest(authority.context.scope.ToDict()) != self._scope_digest
            or Digest(authority.context.policy) != self._policy_digest
        ):
            raise NativeCrawlAuthorityDeniedError("native crawl original authority changed")

        return authority

    def CheckBudget(self) -> None:
        """Check the one original operation clock without renewing it on progress.

        Raises:
            JobError: The original inclusive operation budget expired.
        """

        if self._origin is None or asyncio.get_running_loop().time() - self._origin >= (
            self.limits.timeout_seconds
        ):
            raise JobError(JobFailure(JobFailureCode.TIMEOUT, "Native crawl operation expired"))

    def ValidatePage(self, context: JobContext, page: NativeCrawlPage) -> None:
        """Require original request, fresh actor/authority, admitted report and actual stream IDs.

        Args:
            context: Same original still-running owning job context.
            page: Original provider-owned page, not an adopted copied result.
        """

        if not any(item is page for item in self.pages):
            raise ValueError("native crawl page is not the original owned capture")

        self.CheckBudget()
        document = ParseCrawlInput(page.input_json)
        expected = self.adapter.PrepareInvocation(AdapterRequest(NATIVE_CRAWL_CAPABILITY,
            Target(TargetKind.URL, document["source_url"]).Reference(), ImpactLevel.SAFE, document))
        request = LocalExecutionRequest(expected, self.capability, page.grant.authorization,
            resources=ExecutionResources(MAX_RECORD_BYTES, 1, 0.1))

        if page.request != request or page.report_json != page.result.stdout:
            raise ValueError("native crawl original complete request differs")

        ParseCrawlRecord(page.report_json, document)

        for record in page.records:
            self.VerifyRecord(record)

        # Every custody read precedes the fresh final synchronous authority decision.
        authority = self.Current(document["source_url"], context)
        PolicyEngine().Validate(page.grant, expected, self.capability, authority.context,
                                at=self.clock())
        self.CheckBudget()

    def VerifyRecord(self, record: EvidenceRecord) -> None:
        """Reverify a bounded original publication without adopting an unknown stored manifest.

        Args:
            record: Original expected manifest retained in the finite publication ledger.
        """

        original = self._publications.get(record.evidence_id)

        if original is None or original[0] != record or self.store.Get(record.evidence_id) != (
            record
        ) or self.store.Read(record.reference) != original[1]:
            raise ValueError("native crawl original evidence differs")

    def Publish(self, context: JobContext, data: bytes, role: str, media_type: str,
                provenance: EvidenceProvenance) -> EvidenceRecord:
        """Publish exact admitted bytes once and retain independently confirmed lost ACK facts.

        Args:
            context: Original active job evidence owner.
            data: Complete admitted original stream or separately labeled control metadata.
            role: Closed owning evidence role.
            media_type: Exact role-specific media type.
            provenance: Original invocation and actual terminal execution attribution.

        Returns:
            Exact acknowledged original record; a failed ACK is never converted into success.
        """

        reference = EvidenceReference(role, "blobs/sha256/" + hashlib.sha256(data).hexdigest(),
            hashlib.sha256(data).hexdigest(), media_type, len(data))
        expected = EvidenceRecord(reference, provenance)
        acknowledged = False

        try:
            artifact = context.CaptureEvidence(data, role, media_type, provenance)

            if artifact.job_id != context.Spec.job_id or (
                artifact.workspace_id != self.workspace_id or artifact.evidence != expected
            ):
                raise ValueError("native crawl original evidence acknowledgement differs")

            acknowledged = True

            return expected

        finally:
            try:
                if self.store.Get(expected.evidence_id) == expected and (
                    self.store.Read(expected.reference) == data
                ):
                    self._publications[expected.evidence_id] = (expected, data, acknowledged)

                else:
                    raise ValueError("native crawl evidence readback differs")

            except (EvidenceError, OSError, ValueError):
                if acknowledged:
                    raise

    def Records(self) -> tuple[EvidenceRecord, ...]:
        """Return only reverified original bounded ledger records, including truthful lost ACKs.

        Returns:
            Actual retained manifests; no unknown candidate manifest is adopted.
        """

        records = tuple(value[0] for _, value in sorted(self._publications.items()))

        for record in records:
            self.VerifyRecord(record)

        return records

    async def Acquire(self, context: JobContext, url: str) -> NativeCrawlPage:
        """Acquire exactly one governed page and retain admitted originals before model work.

        Args:
            context: Original active outer job, shared by every bounded owned page task.
            url: One discovered member of the original complete selection.

        Returns:
            Original acknowledged page with strict report and separate actual control receipt.

        Raises:
            JobError: Current authority, transport, closed output or original custody failed.
            asyncio.CancelledError: Owned executor cancellation finished its cleanup.
        """

        self.CheckBudget()
        context.CheckCancellation()
        document = BuildCrawlInput(self.workspace_id, self.seed_url, url, self.selected_urls,
            max_body_bytes=self.limits.max_body_bytes,
            request_timeout_ms=self.limits.request_timeout_ms)
        invocation = self.adapter.PrepareInvocation(AdapterRequest(NATIVE_CRAWL_CAPABILITY,
            Target(TargetKind.URL, url).Reference(), ImpactLevel.SAFE, document))
        authority = self.Current(url, context)
        grant = PolicyEngine().Authorize(invocation, self.capability, authority.context,
                                         at=self.clock())
        request = LocalExecutionRequest(invocation, self.capability, grant.authorization,
            resources=ExecutionResources(MAX_RECORD_BYTES, 1, 0.1))
        cancellation = asyncio.Event()

        def Current() -> PolicyContext:
            """Bind the full fixed request and reread actor/selection at final governed launch.

            Returns:
                Fresh source/IP policy context after complete selected-set validation.
            """

            self.CheckBudget()
            context.CheckCancellation()

            if cancellation.is_set():
                raise PermissionError("native crawl original page launch was cancelled")

            if request != LocalExecutionRequest(invocation, self.capability, grant.authorization,
                resources=ExecutionResources(MAX_RECORD_BYTES, 1, 0.1)):
                raise ValueError("native crawl whole request changed")

            current = self.Current(url, context).context
            self.CheckBudget()

            return current

        def OnEvent(event: ExecutionEvent) -> None:
            """Publish lifecycle liveness only; all raw stream fragments remain transient.

            Args:
                event: Original executor notification, never rewritten or reconstructed.
            """

            if event.kind in (ExecutionEventKind.STARTED, ExecutionEventKind.COMPLETED):
                context.Heartbeat()

        started_at = self.clock().isoformat()
        interrupted = False

        try:
            executor = GovernedLocalExecutor(self.root, clock=self.clock)
            original = asyncio.create_task(executor.Execute(
                request, grant=grant, context_provider=Current, on_event=OnEvent,
                cancellation=cancellation))

            try:
                result = await asyncio.shield(original)

            except asyncio.CancelledError:
                interrupted = True
                cancellation.set()

                try:
                    result = await SettleCrawlTask(original)

                except RuntimeError:
                    if original.cancelled():
                        raise LocalExecutionError(
                            "native crawl original executor ended without an outcome") from None

                    raise

        except PermissionError:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                "Native crawl launch authority denied")) from None

        except LocalExecutionError:
            raise JobError(JobFailure(JobFailureCode.PROVIDER,
                "Native crawl execution or cleanup is unconfirmed")) from None

        try:
            result = ValidateResult(result)

        except (ValueError, TypeError, AttributeError):
            raise JobError(JobFailure(JobFailureCode.NORMALIZATION,
                "Native crawl executor result violated its original control contract")) from None
        provenance = EvidenceProvenance(self.workspace_id, context.Spec.scope_reference,
            NATIVE_CRAWL_PROVIDER_ID, NATIVE_CRAWL_VERSION, NATIVE_CRAWL_VERSION,
            started_at, self.clock().isoformat(), InvocationDigest(invocation),
            result.execution)
        originals: list[EvidenceRecord] = []
        parsed = None
        invalid = False

        try:
            if result.stderr or len(result.stdout) > MAX_RECORD_BYTES:
                raise ValueError("native crawl streams exceed the closed record profile")

            parsed = ParseCrawlRecord(result.stdout, document)

            if result.termination is ExecutionTermination.PROCESS_EXIT and (
                result.execution.exit_code != (2 if parsed["outcome"] == "refused" else 0)
                or result.execution.state is not (ExecutionState.FAILED
                    if parsed["outcome"] == "refused" else ExecutionState.SUCCEEDED)
            ):
                raise ValueError("native crawl report and original exit disagree")

        except (ValueError, TypeError):
            invalid = True

        publication_error: BaseException | None = None

        try:
            if not invalid:
                originals.append(self.Publish(context, result.stdout, "stdout", "application/json",
                                               provenance))
                originals.append(self.Publish(context, result.stderr, "stderr",
                    "application/octet-stream", provenance))

        except BaseException as error:
            publication_error = error

        try:
            # This receipt is parent control metadata, never fabricated worker stdout/stderr.
            control = SerializeContract({"schema_version": 1, "profile": NATIVE_CRAWL_PROFILE,
                "original_job_id": context.Spec.job_id,
                "request": json.loads(SerializeContract(request)),
                "termination": result.termination.value,
                "execution": json.loads(SerializeContract(result.execution)),
                "stdout_size_bytes": len(result.stdout), "stderr_size_bytes": len(result.stderr),
                "original_stdout_id": next((item.evidence_id for item in originals
                    if item.reference.role == "stdout"), None),
                "original_stderr_id": next((item.evidence_id for item in originals
                    if item.reference.role == "stderr"), None)}).encode("ascii")

            if len(control) > 65536:
                raise JobError(JobFailure(JobFailureCode.OUTPUT_LIMIT,
                    "Native crawl control receipt exceeded its fixed bound"))

            originals.append(self.Publish(context, control, "native-crawl-control",
                                           "application/json", provenance))

        except BaseException:
            if publication_error is None:
                raise

        if result.termination is ExecutionTermination.CANCELLATION:
            raise asyncio.CancelledError

        if result.termination in (ExecutionTermination.TIMEOUT, ExecutionTermination.OUTPUT_LIMIT):
            code = (JobFailureCode.TIMEOUT if result.termination is ExecutionTermination.TIMEOUT
                    else JobFailureCode.OUTPUT_LIMIT)
            raise JobError(JobFailure(code, "Native crawl original execution did not complete"))

        if interrupted:
            raise asyncio.CancelledError

        if publication_error is not None:
            raise publication_error

        if invalid or parsed is None:
            raise JobError(JobFailure(JobFailureCode.NORMALIZATION,
                "Native crawl report was refused before raw retention"))

        page = NativeCrawlPage(EncodeCrawlInput(document), request, grant, result, result.stdout,
                               tuple(originals))
        self.pages += (page,)

        if parsed["outcome"] == "refused":
            codes = {"timeout": JobFailureCode.TIMEOUT, "output-limit": JobFailureCode.OUTPUT_LIMIT}
            raise JobError(JobFailure(codes.get(parsed["error"], JobFailureCode.PROVIDER),
                "Native crawl worker refused this page"))

        return page

    def Commit(self, context: JobContext, page: NativeCrawlPage) -> tuple[str, ...]:
        """Compose and save one page synchronously after its sorted acquisition gate.

        Args:
            context: Original live job owner and model/event boundary.
            page: Exact admitted original page in deterministic breadth/URL commit order.

        Returns:
            Actual admitted candidate URLs; discovery alone never schedules an unselected URL.
        """

        context.CheckCancellation()
        self.ValidatePage(context, page)
        document = ParseCrawlInput(page.input_json)
        record = ParseCrawlRecord(page.report_json, document)

        if record["outcome"] == "refused":
            raise ValueError("native crawl refused page cannot become a model observation")

        store = LocalModelStore(self.root)
        state = store.Open()
        self.persistence_model = state
        report = next(item for item in page.records if item.reference.role == "stdout")
        control = next(item for item in page.records
                       if item.reference.role == "native-crawl-control")
        target = Target(TargetKind.URL, document["source_url"])
        provenance = ModelProvenance(NATIVE_CRAWL_PROVIDER_ID, context.Spec.job_id,
            report.provenance.finished_at, context.Spec.scope_reference, target.Reference(),
            NATIVE_CRAWL_VERSION, tuple(item.reference for item in page.records),
            page.result.execution)
        source = CrawlTemplate(self.workspace_id, document["source_url"])
        by_identity = {item.Reference(): item for item in state.Objects(ObjectKind.ENDPOINT)}
        templates = (source, *(CrawlTemplate(self.workspace_id, entry["url"])
                               for entry in record["frontier"]["entries"]))
        patches = []

        for template in templates:
            identity = template.endpoint.Identity().Reference()
            previous = RequestsFromObject(by_identity[identity]) if identity in by_identity else ()
            complete = {item.Reference(): item for item in (*previous, template)}
            patches.append(ProjectRequests(tuple(complete[key] for key in sorted(complete)),
                                           provenance=(provenance,)))

        base = {"profile": NATIVE_CRAWL_PROFILE, "original_job_id": context.Spec.job_id,
            "original_stdout_id": report.evidence_id, "original_control_id": control.evidence_id,
            "input_sha256": record["input_sha256"],
            "selected_urls_sha256": record["selected_urls_sha256"],
            "source_target_reference": target.Reference(),
            "source_request_reference": source.Reference(),
            "source_endpoint_reference": source.endpoint.Identity().Reference()}
        observations = [Observation("web.owned-crawl-response",
            source.endpoint.Identity().Reference(),
            {**base, "outcome": record["outcome"], "source": record["source"],
             "response": record["response"], "frontier": record["frontier"]}, provenance)]

        for entry in record["frontier"]["entries"]:
            observations.append(Observation("web.owned-crawl-link", entry["endpoint_reference"],
                {**base, "candidate_url": entry["url"],
                 "candidate_request_reference": entry["request_reference"],
                 "candidate_endpoint_reference": entry["endpoint_reference"],
                 "ordinals": entry["ordinals"]}, provenance))

        proposed, delta = state.Apply(objects=tuple(patches), observations=tuple(observations))

        if len(CanonicalModelJson(proposed.ToDict())) > MAX_MODEL_BYTES:
            raise JobError(JobFailure(JobFailureCode.OUTPUT_LIMIT,
                "Native crawl proposed model exceeded its owner limit"))

        status: dict[str, object] = {"source_url": document["source_url"],
            "prior_revision": state.revision, "proposed_revision": proposed.revision,
            "persistence": "not-attempted"}
        self.model_saves.append(status)
        context.CheckCancellation()
        self.ValidatePage(context, page)
        context.CheckCancellation()
        status["persistence"] = "unconfirmed"

        try:
            saved = store.Save(proposed, expected_revision=state.revision)

            if saved != proposed:
                raise ValueError("native crawl model acknowledgement differs")

            status["persistence"] = "acknowledged"
            self.persistence_model = saved

        except (OSError, ValueError, RuntimeError):
            try:
                actual = store.Open()
                status["persistence"] = ("observed-committed" if actual == proposed else
                    "observed-unchanged" if actual == state else "unconfirmed")
                self.persistence_model = actual if actual in (state, proposed) else None

            except (OSError, ValueError):
                self.persistence_model = None

            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Native crawl model acknowledgement failed; actual state retained")) from None

        self.ValidatePage(context, page)
        context.CheckCancellation()
        context.ModelChanged(delta)

        for observation in observations:
            context.Observe(NormalizedObservation(observation.kind, observation.subject_reference,
                                                  observation.attributes))

        context.Progress(len(self.completed_urls) + 1)
        self.completed_urls += (document["source_url"],)

        return tuple(entry["url"] for entry in record["frontier"]["entries"])

    async def Traverse(self, context: JobContext) -> None:
        """Reserve whole sorted waves and commit incrementally without orphaned sibling tasks.

        Args:
            context: Original job context carrying current cancellation and evidence ownership.
        """

        pending = {self.seed_url: 0}
        visited: set[str] = set()
        reserved = 0
        next_start = asyncio.get_running_loop().time()
        context.Progress(0)

        while pending:
            self.CheckBudget()
            context.CheckCancellation()
            depth = min(pending.values())
            wave = tuple(sorted(url for url in pending if pending[url] == depth)[
                :self.limits.concurrency])
            wave_bytes = len(wave) * self.limits.max_body_bytes

            if depth > self.limits.max_depth or (
                len(visited) + len(wave) > self.limits.max_pages
            ) or (
                reserved + wave_bytes > self.limits.max_total_body_bytes
            ):
                raise JobError(JobFailure(JobFailureCode.OUTPUT_LIMIT,
                    "Native crawl budget omitted reachable selected work"))

            reserved += wave_bytes
            visited.update(wave)
            tasks: list[asyncio.Task[NativeCrawlPage]] = []

            try:
                for url in wave:
                    delay = next_start - asyncio.get_running_loop().time()

                    if delay > 0:
                        await asyncio.sleep(delay)

                    self.CheckBudget()
                    context.CheckCancellation()
                    del pending[url]
                    tasks.append(asyncio.create_task(self.Acquire(context, url)))
                    next_start = asyncio.get_running_loop().time() + (
                        self.limits.start_interval_seconds)

                for task in tasks:
                    page = await asyncio.shield(task)
                    candidates = self.Commit(context, page)

                    for url in candidates:
                        if url not in visited:
                            pending[url] = min(pending.get(url, depth + 1), depth + 1)

            finally:
                for task in tasks:
                    if not task.done() and not task.cancelling():
                        task.cancel()

                if tasks:
                    cleanup = asyncio.ensure_future(asyncio.gather(*tasks, return_exceptions=True))

                    await SettleCrawlTask(cleanup)

        self.CheckBudget()
        context.CheckCancellation()
        context.Progress(len(self.completed_urls), len(self.completed_urls))

    def ValidatePersistence(self, context: JobContext) -> None:
        """Guard workspace retention using the same actual owner, clock and original pages.

        Args:
            context: Same active outer provider task and job used for this original operation.
        """

        if context is not self._context or asyncio.current_task() is not self._task:
            raise NativeCrawlAuthorityDeniedError("native crawl persistence owner differs")

        self.CheckBudget()

        if not self.pages:
            raise NativeCrawlAuthorityDeniedError("native crawl has no original admitted page")

        for page in self.pages:
            self.ValidatePage(context, page)

        # Recheck every original grant after all pages' custody I/O from one fresh wrapper.
        documents = tuple(ParseCrawlInput(page.input_json) for page in self.pages)
        current = self.Current(self.seed_url, context)
        address = Target(TargetKind.IP, CrawlEndpoint(self.seed_url)[1])
        at = self.clock()

        for page, document in zip(self.pages, documents, strict=True):
            source = Target(TargetKind.URL, document["source_url"])
            authority = PolicyContext(current.context.scope, current.context.policy, source,
                                       (source, address))
            PolicyEngine().Validate(page.grant, page.request.invocation, self.capability,
                                    authority, at=at)

        self.CheckBudget()
        context.CheckCancellation()

    async def Run(self, context: JobContext) -> None:
        """Own one deadline and drain original tasks before every terminal transition.

        Args:
            context: Exact matching original job context, never a delegated runtime authority.

        Raises:
            JobError: Scope/actor/policy, transport, output, persistence or inclusive budget failed.
            asyncio.CancelledError: Requested cancellation after original cleanup was awaited.
        """

        if self._context is not None or type(context) is not JobContext or not self.approved:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                "Native crawl requires a single approved original job"))

        self._context, self._task = context, asyncio.current_task()
        self._origin = asyncio.get_running_loop().time()
        task: asyncio.Task[None] | None = None
        cancelled = asyncio.create_task(context.Cancellation.wait())

        try:
            authority = self.Current(self.seed_url, context)
            self._scope_digest = Digest(authority.context.scope.ToDict())
            self._policy_digest = Digest(authority.context.policy)
            task = asyncio.create_task(self.Traverse(context))
            done, _ = await asyncio.wait((task, cancelled), timeout=self.limits.timeout_seconds,
                                         return_when=asyncio.FIRST_COMPLETED)

            if task not in done:
                self.CheckBudget()
                raise asyncio.CancelledError

            task.result()
            self.CheckBudget()
            context.CheckCancellation()

        except PermissionError:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                "Native crawl current authority denied")) from None

        except (EvidenceError, OSError, ValueError, WorkspaceConflictError):
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Native crawl original state or evidence could not be verified")) from None

        finally:
            cancelled.cancel()

            if task is not None and not task.done() and not task.cancelling():
                task.cancel()

            cleanup = asyncio.ensure_future(asyncio.gather(
                *(item for item in (task, cancelled) if item is not None), return_exceptions=True))

            await SettleCrawlTask(cleanup)
