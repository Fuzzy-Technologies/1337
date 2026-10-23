# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Governed closed loopback page acquisition into existing evidence/frontier/model owners."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path

from fuzzy1337.adapters import (
    AdapterDescriptor,
    AdapterInvocation,
    AdapterReport,
    AdapterRequest,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
)
from fuzzy1337.adapters.browser_page import BROWSER_ERROR_EXITS, ParseBrowserRecord
from fuzzy1337.adapters.contracts import RequireIdentifier
from fuzzy1337.adapters.page_capture import (
    ERROR_EXITS,
    MAX_BODY_BYTES,
    MAX_RECORD_BYTES,
    MAX_STDERR_BYTES,
    PAGE_BROWSER_CAPABILITY,
    PAGE_CAPTURE_CAPABILITY,
    PAGE_CAPTURE_PROVIDER_ID,
    PAGE_CAPTURE_VERSION,
    BrowserPageCaptureLimits,
    DecodeBody,
    Destination,
    Execution,
    Integer,
    KnownBody,
    KnownSyntheticHtmlBody,
    NativeLoopbackPageAdapter,
    PageCaptureLimits,
    PageCaptureRecordError,
    PageRenderer,
    ParseRecord,
)
from fuzzy1337.captured_web import (
    CapturedWebFrontier,
    CapturedWebLimits,
    FrontierDigest,
    ProjectCapturedWebFrontier,
    ReadCapturedWebFrontier,
    WebSource,
    WebText,
)
from fuzzy1337.evidence import (
    EvidenceError,
    EvidenceProvenance,
    EvidenceRecord,
    LocalEvidenceStore,
)
from fuzzy1337.executors import (
    CapabilityDescriptor,
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
from fuzzy1337.policy import (
    Digest,
    GovernedLocalExecutor,
    ImpactPolicy,
    PolicyContext,
    PolicyEngine,
    PolicyGrant,
    RequireTime,
    UtcNow,
)
from fuzzy1337.requests import ProjectRequests, RequestsFromObject, RequestTemplate
from fuzzy1337.scope import LocalScopeStore, ScopeSnapshot, Target, TargetKind
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceBusyError, WorkspaceConflictError

__all__ = [
    "PAGE_CAPTURE_VERSION", "PAGE_CAPTURE_PROVIDER_ID", "PAGE_CAPTURE_CAPABILITY",
    "PAGE_BROWSER_CAPABILITY", "PageRenderer", "BrowserPageCaptureLimits",
    "KnownSyntheticHtmlBody", "PageCaptureLimits", "LocalPageCaptureProvider",
]


class BoundedPageEvidenceStore(LocalEvidenceStore):
    """Intercept owner Get's actual parsed reference before its eager Read allocation."""

    def Read(self, reference: object) -> bytes:
        """Admit exact stdout/body roles and quotas before unchanged owner integrity checks.

        Args:
            reference: Actual parsed owner reference, including Get's internal eager read.

        Returns:
            Verified bytes after role-specific 98304-byte stdout or 65536-byte body admission.
        """

        if type(reference) is not EvidenceReference:
            raise ValueError("page capture requires exact owning evidence references")

        if reference.role == "stdout" and reference.media_type == "application/json":
            limit = MAX_RECORD_BYTES

        elif reference.role == "response-body" and reference.media_type == "text/html":
            limit = MAX_BODY_BYTES

        else:
            raise ValueError("page capture actual evidence role is unsupported")

        Integer(reference.size_bytes, 1, limit)

        return super().Read(reference)


def ValidateResult(result: object) -> LocalExecutionResult:
    """Refuse copied nested executor wrappers and verify exact ordered terminal stream facts.

    Args:
        result: Owning terminal process result with bounded streams and ordered lifecycle events.

    Returns:
        Original fully revalidated result; nonnormal termination never admits page evidence.
    """

    if type(result) is not LocalExecutionResult or type(result.stdout) is not bytes or (
        type(result.stderr) is not bytes or type(result.events) is not tuple
        or type(result.termination) is not ExecutionTermination
        or len(result.stdout) > MAX_RECORD_BYTES or len(result.stderr) > MAX_STDERR_BYTES
        or not 1 <= len(result.events) <= MAX_RECORD_BYTES + MAX_STDERR_BYTES + 2
    ):
        raise PageCaptureRecordError("page capture requires a bounded exact executor result")

    Execution(result.execution)
    stdout: list[bytes] = []
    stderr: list[bytes] = []
    stream_bytes = 0

    for sequence, event in enumerate(result.events):
        if type(event) is not ExecutionEvent or type(event.sequence) is not int or (
            event.sequence != sequence or type(event.kind) is not ExecutionEventKind
            or type(event.data) is not bytes
            or event.termination is not None and type(event.termination) is not ExecutionTermination
        ):
            raise PageCaptureRecordError("page capture executor event shape is invalid")

        stream_bytes += len(event.data)

        if stream_bytes > MAX_RECORD_BYTES + MAX_STDERR_BYTES or (
            ExecutionEvent(event.sequence, event.kind, event.data, event.termination) != event
        ):
            raise PageCaptureRecordError("page capture executor event bounds differ")

        if event.kind is ExecutionEventKind.STDOUT:
            stdout.append(event.data)

        elif event.kind is ExecutionEventKind.STDERR:
            stderr.append(event.data)

        elif event.kind is ExecutionEventKind.STARTED and sequence != 0 or (
            event.kind is ExecutionEventKind.COMPLETED and sequence != len(result.events) - 1
        ):
            raise PageCaptureRecordError("page capture executor lifecycle order differs")

    if result.events[-1].kind is not ExecutionEventKind.COMPLETED or (
        result.events[-1].termination is not result.termination
        or b"".join(stdout) != result.stdout or b"".join(stderr) != result.stderr
        or result.termination is ExecutionTermination.PROCESS_EXIT
        and result.events[0].kind is not ExecutionEventKind.STARTED
    ):
        raise PageCaptureRecordError("page capture executor terminal stream facts differ")

    expected_states = {
        ExecutionTermination.PROCESS_EXIT: (ExecutionState.SUCCEEDED, ExecutionState.FAILED),
        ExecutionTermination.CANCELLATION: (ExecutionState.CANCELLED,),
        ExecutionTermination.TIMEOUT: (ExecutionState.TIMED_OUT,),
        ExecutionTermination.OUTPUT_LIMIT: (ExecutionState.CANCELLED,),
    }

    if result.execution.state not in expected_states[result.termination]:
        raise PageCaptureRecordError("page capture execution and termination disagree")

    return result


class LocalPageCaptureProvider:
    """Acquire one reviewed owned page and commit structural/lexical facts in one model Save."""

    def __init__(
        self, workspace_root: Path, source: RequestTemplate,
        expected_body: KnownSyntheticHtmlBody, scope_id: str, policy: ImpactPolicy,
        *, limits: PageCaptureLimits | BrowserPageCaptureLimits = PageCaptureLimits(),
        frontier_limits: CapturedWebLimits = CapturedWebLimits(),
        clock: Callable[[], datetime] = UtcNow,
        renderer: PageRenderer = PageRenderer.NATIVE,
    ) -> None:
        """Validate only finite typed inputs; preparation performs no network or owner writes.

        Args:
            workspace_root: Existing physical consumer-owned workspace/model/scope/evidence.
            source: Exact anonymous concrete structural GET, with non-secret caller metadata.
            expected_body: Explicit reviewed non-secret closed catalog selection.
            scope_id: Existing scope ID; exact URL and literal IP must have current consent.
            policy: Explicit distinct capability permission, independently checked at launch.
            limits: Selected body/request/provider budgets following ADR 0052.
            frontier_limits: Existing lexical-work/candidate bounds, without traversal.
            clock: Aware decision clock, reread again immediately before model Save.
            renderer: Finite native or offline-browser profile, with matching explicit limit type.

        Raises:
            ValueError: Source, catalog, nested types or finite budgets are unsupported.
        """

        if type(renderer) is not PageRenderer:
            raise ValueError("page capture requires an explicit finite renderer selection")

        limit_type = PageCaptureLimits if renderer is PageRenderer.NATIVE else (
            BrowserPageCaptureLimits)

        if type(limits) is not limit_type or (
            type(frontier_limits) is not CapturedWebLimits
            or type(policy) is not ImpactPolicy or not callable(clock)
        ):
            raise ValueError("page capture requires exact typed limits, policy and clock")

        checked_limits = limit_type(limits.max_body_bytes, limits.request_timeout_seconds,
                                    limits.timeout_seconds)
        checked_frontier = CapturedWebLimits(frontier_limits.max_anchor_work,
                                            frontier_limits.max_candidates)
        body = KnownBody(expected_body)

        if body.size_bytes > checked_limits.max_body_bytes:
            raise ValueError("page capture reviewed body does not fit its selected quota")

        source, target = WebSource(source)

        if type(source.endpoint.method) is not str:
            raise ValueError("page capture requires exact canonical structural source fields")

        _, address, _, _, _ = Destination(target.value)
        WebText(scope_id)
        RequireIdentifier(scope_id, "scope_id")
        self._workspace = LocalWorkspaceStore(workspace_root)
        self._scope = LocalScopeStore(self._workspace.root)
        self._model = LocalModelStore(self._workspace.root)
        self._evidence = BoundedPageEvidenceStore(self._workspace.root / "evidence")
        self._adapter = NativeLoopbackPageAdapter(self._evidence.Read, renderer=renderer)
        self._renderer = renderer
        self._capability = PAGE_CAPTURE_CAPABILITY if renderer is PageRenderer.NATIVE else (
            PAGE_BROWSER_CAPABILITY)
        self._source = source
        self._target = target
        self._address = Target(TargetKind.IP, address)
        self._expected_body = body
        self._scope_id = scope_id
        self._policy = policy
        self._clock = clock
        self.limits = checked_limits
        self.frontier_limits = checked_frontier

    @property
    def Descriptor(self) -> AdapterDescriptor:
        """Return the separate SAFE declaration without acquisition or permission shortcuts.

        Returns:
            Immutable provider/version/capability metadata from the existing adapter contract.
        """

        return self._adapter.Descriptor

    def CurrentContext(self) -> PolicyContext:
        """Read actual current scope and require its workspace binding before owner policy.

        Returns:
            Exact current owning scope/policy/source URL and literal-IP destination context.
        """

        scope = self._scope.Open(self._scope_id)

        if scope.workspace_id != self._source.endpoint.workspace_id:
            raise PermissionError("page capture scope belongs to another workspace")

        return PolicyContext(scope, self._policy, self._target, (self._address, self._target))

    def Now(self) -> datetime:
        """Read fresh aware UTC time without retaining input-derived clock failure text.

        Returns:
            Newly read aware clock time normalized to UTC.
        """

        at = self._clock()
        RequireTime(at)

        return at.astimezone(timezone.utc)

    async def Run(self, context: JobContext) -> None:
        """Run one governed worker then retain evidence before one saved model/event transition.

        A pre-Save failure retains the prior model. Evidence survives later failure.
        Save acknowledgement, cancellation and event failure after commit never imply rollback.

        Args:
            context: Exact owning job context with matching workspace/provider/scope attribution.

        Raises:
            JobError: Fixed authorization/provider/output/normalization/storage/deadline failure.
            asyncio.CancelledError: Owner cancellation after governed child cleanup.
        """

        try:
            workspace = self._workspace.Open()
            self._model.Open()

        except (OSError, ValueError):
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Could not open page acquisition state")) from None

        if type(context) is not JobContext or (
            context.Spec.workspace_id != workspace.workspace_id
            or context.Spec.provider_id != PAGE_CAPTURE_PROVIDER_ID
            or context.Spec.scope_reference != "scope:" + self._scope_id
            or self._source.endpoint.workspace_id != workspace.workspace_id
        ):
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                "Page acquisition context does not match its owners")) from None

        try:
            async with asyncio.timeout(self.limits.timeout_seconds):
                context.CheckCancellation()

                await self.Acquire(context)

        except TimeoutError:
            raise JobError(JobFailure(JobFailureCode.TIMEOUT,
                "Page acquisition deadline exceeded; inspect retained artifacts and model")) \
                from None

    async def Acquire(
        self, context: JobContext, *,
        before_commit: Callable[[], Awaitable[None]] | None = None,
        publish_progress: bool = True,
    ) -> CapturedWebFrontier:
        """Execute the pinned one-request plan and validate terminal output before persistence.

        Args:
            context: Current validated owning job, including cancellation and evidence boundaries.
            before_commit: Optional traversal-owned ordered admission after raw interpretation;
                model composition and fresh final authority checks follow this await.
            publish_progress: Preserve one-page progress by default; traversal owns its counters.

        Returns:
            The retained verified frontier after the owning model Save and event publication.
        """

        if self._renderer is PageRenderer.PLAYWRIGHT_OFFLINE:
            if context.Spec.timeout_seconds < self.limits.timeout_seconds + 1:
                raise JobError(JobFailure(JobFailureCode.PROVIDER,
                    "Browser page job budget must include provider cleanup and custody margin"))

            from fuzzy1337.executors.owned_process import RequireLinuxOwnership

            try:
                RequireLinuxOwnership()

            except LocalExecutionError:
                raise JobError(JobFailure(JobFailureCode.PROVIDER,
                    "Linux browser descendant ownership is unavailable")) from None

        invocation = self._adapter.PrepareInvocation(AdapterRequest(self._capability,
            self._target.Reference(), ImpactLevel.SAFE, {"url": self._target.value,
                "timeout_seconds": self.limits.request_timeout_seconds,
                "max_body_bytes": self.limits.max_body_bytes,
                "fixture_id": self._expected_body.fixture_id}))
        capability = next(item for item in CapabilityDescriptors(self.Descriptor)
                          if item.identifier == self._capability)

        def OnEvent(event: ExecutionEvent) -> None:
            """Publish just the two lifecycle heartbeats; never forward raw stream chunks."""

            if event.kind in (ExecutionEventKind.STARTED, ExecutionEventKind.COMPLETED):
                context.Heartbeat()

        try:
            initial_context = self.CurrentContext()
            pinned = initial_context.scope
            pinned_dict = pinned.ToDict()
            grant = PolicyEngine().Authorize(invocation, capability, initial_context, at=self.Now())
            started = self.Now().isoformat()
            request = LocalExecutionRequest(invocation, capability, grant.authorization,
                resources=ExecutionResources(MAX_RECORD_BYTES, MAX_STDERR_BYTES, 0.5))

            def LaunchContext() -> PolicyContext:
                """Reread full pinned scope at the existing final synchronous governed launch."""

                current = self.CurrentContext()

                if current.scope.ToDict() != pinned_dict or (
                    current.scope.revision != pinned.revision
                ):
                    raise PermissionError("page capture launch scope snapshot changed")

                return current

            executor = GovernedLocalExecutor(self._workspace.root, clock=self._clock)

            if self._renderer is PageRenderer.PLAYWRIGHT_OFFLINE:
                result = await executor.Execute(request, grant=grant,
                    context_provider=LaunchContext, on_event=OnEvent,
                    cancellation=context.Cancellation, own_descendants=True)

            else:
                result = await executor.Execute(request, grant=grant,
                    context_provider=LaunchContext, on_event=OnEvent,
                    cancellation=context.Cancellation)

        except PermissionError:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                "Page acquisition execution was denied")) from None

        except LocalExecutionError:
            raise JobError(JobFailure(JobFailureCode.PROVIDER,
                "Could not launch or clean up page acquisition")) from None

        except (OSError, ValueError):
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Could not read current page acquisition authority")) from None

        try:
            result = ValidateResult(result)
            self._adapter.ValidateInvocation(invocation)

        except (ValueError, TypeError, AttributeError, OverflowError):
            raise JobError(JobFailure(JobFailureCode.NORMALIZATION,
                "Page acquisition executor facts violated their contract")) from None

        if result.termination is ExecutionTermination.OUTPUT_LIMIT:
            raise JobError(JobFailure(JobFailureCode.OUTPUT_LIMIT,
                "Page acquisition output budget exceeded")) from None

        if result.termination is ExecutionTermination.CANCELLATION:
            raise asyncio.CancelledError

        if result.termination is ExecutionTermination.TIMEOUT:
            raise JobError(JobFailure(JobFailureCode.TIMEOUT,
                "Page worker deadline exceeded")) from None

        try:
            if result.stderr:
                raise ValueError("stderr cannot become retained acquisition evidence")

            parser = ParseRecord if self._renderer is PageRenderer.NATIVE else ParseBrowserRecord
            record = parser(result.stdout, self._target.value,
                            self._expected_body, self.limits.max_body_bytes)
            error_code = record.get("error")
            exits = ERROR_EXITS if self._renderer is PageRenderer.NATIVE else (
                {**ERROR_EXITS, **BROWSER_ERROR_EXITS})

            if error_code is not None:
                if result.execution.state is not ExecutionState.FAILED or (
                    result.execution.exit_code != exits[str(error_code)]
                ):
                    raise ValueError("worker failure record and terminal outcome disagree")

            elif result.execution.state is not ExecutionState.SUCCEEDED or (
                result.execution.exit_code != 0
            ):
                raise ValueError("worker page record and terminal outcome disagree")

            tool_version = PAGE_CAPTURE_VERSION if self._renderer is PageRenderer.NATIVE else (
                str(record["chromium_version"]) if error_code is None else None)
            provenance = EvidenceProvenance(context.Spec.workspace_id, context.Spec.scope_reference,
                PAGE_CAPTURE_PROVIDER_ID, PAGE_CAPTURE_VERSION, tool_version, started,
                self.Now().isoformat(), InvocationDigest(invocation), result.execution)

        except (ValueError, TypeError, AttributeError, OverflowError):
            raise JobError(JobFailure(JobFailureCode.NORMALIZATION,
                "Page output violated its closed safe record contract")) from None

        stdout_record = context.CaptureEvidence(result.stdout, "stdout", "application/json",
                                               provenance).evidence

        if error_code is not None:
            if self._renderer is PageRenderer.PLAYWRIGHT_OFFLINE and "body_base64" in record:
                try:
                    partial_body = DecodeBody(record, self._expected_body)
                    partial_record = context.CaptureEvidence(partial_body, "response-body",
                                                             "text/html", provenance).evidence
                    self.VerifyEvidence(stdout_record, result.stdout, provenance, "stdout")
                    self.VerifyEvidence(partial_record, partial_body, provenance, "response-body")

                except (ValueError, TypeError, AttributeError, OverflowError, OSError,
                        EvidenceError):
                    raise JobError(JobFailure(JobFailureCode.NORMALIZATION,
                        "Could not verify failed browser acquisition source custody")) from None

            code = JobFailureCode.TIMEOUT if error_code in ("timeout", "renderer-timeout") else (
                JobFailureCode.PROVIDER)
            raise JobError(JobFailure(code, "Closed synthetic page acquisition failed")) from None

        body = DecodeBody(record, self._expected_body)
        body_record = context.CaptureEvidence(body, "response-body", "text/html",
                                             provenance).evidence
        context.CheckCancellation()

        try:
            self.VerifyEvidence(stdout_record, result.stdout, provenance, "stdout")
            self.VerifyEvidence(body_record, body, provenance, "response-body")
            self._adapter.NormalizeReport(AdapterReport(invocation, result.execution,
                                                        (stdout_record.reference,)))
            frontier = ReadCapturedWebFrontier(self._workspace.root, self._source, body_record,
                self._scope_id, at=self.Now(), limits=self.frontier_limits)

            if FrontierDigest(frontier) != frontier.frontier_digest or (
                frontier.scope_reference != pinned.Reference()
                or frontier.scope_revision != pinned.revision
                or frontier.scope_sha256 != hashlib.sha256(
                    CanonicalModelJson(pinned_dict)).hexdigest()
                or grant.plan.scope_sha256 != Digest(pinned_dict)
            ):
                raise PermissionError("page capture frontier does not bind the launch snapshot")

        except PermissionError:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                "Page interpretation scope differs from current launch authority")) from None

        except (ValueError, TypeError, AttributeError, OverflowError, OSError, EvidenceError):
            raise JobError(JobFailure(JobFailureCode.NORMALIZATION,
                "Could not verify captured page artifacts and lexical frontier")) from None

        if before_commit is not None:
            await before_commit()

        context.CheckCancellation()

        try:
            state = self._model.Open()
            provenance_model = ModelProvenance(PAGE_CAPTURE_PROVIDER_ID, context.Spec.job_id,
                provenance.finished_at, context.Spec.scope_reference, self._target.Reference(),
                PAGE_CAPTURE_VERSION, (stdout_record.reference, body_record.reference),
                result.execution)
            by_identity = {item.Reference(): item for item in state.Objects(ObjectKind.ENDPOINT)}
            identity = self._source.endpoint.Identity().Reference()
            previous = RequestsFromObject(by_identity[identity]) if identity in by_identity else ()
            templates = {template.Reference(): template for template in (*previous, self._source)}
            source_patch = ProjectRequests(tuple(templates[key] for key in sorted(templates)),
                                           provenance=(provenance_model,))
            candidate_refs = {entry.template.endpoint.Identity().Reference()
                              for entry in frontier.entries}
            existing = tuple(by_identity[key]
                             for key in sorted(candidate_refs & by_identity.keys()))
            projection = ProjectCapturedWebFrontier(frontier, existing=existing)
            attributes = {key: value for key, value in record.items() if key != "body_base64"}
            attributes.update({
                "source_request_reference": self._source.Reference(),
                "source_target_reference": self._target.Reference(),
                "stdout_manifest_id": stdout_record.evidence_id,
                "body_manifest_id": body_record.evidence_id,
                "invocation_sha256": InvocationDigest(invocation),
                "launch_plan_intent_sha256": grant.plan.intent_sha256,
                "authorization_id": grant.authorization.authorization_id,
                "launch_policy_scope_sha256": grant.plan.scope_sha256,
                "launch_policy_scope_revision": grant.plan.scope_revision,
                "policy_sha256": grant.plan.policy_sha256,
                "policy_revision": grant.plan.policy_revision,
                "prior_model_sha256": hashlib.sha256(
                    CanonicalModelJson(state.ToDict())).hexdigest(),
                "prior_model_revision": state.revision,
                "frontier_digest": frontier.frontier_digest,
                "frontier_scope_sha256": frontier.scope_sha256,
                "frontier_scope_revision": frontier.scope_revision,
                "frontier_checked_at": frontier.checked_at,
                "frontier_anchor_count": frontier.anchor_count,
                "frontier_processed_anchors": frontier.processed_anchors,
                "frontier_complete": frontier.complete,
                "frontier_discarded_candidates": frontier.discarded_candidates,
                "frontier_truncation_reasons": frontier.truncation_reasons,
            })
            kind = "http.synthetic-page" if self._renderer is PageRenderer.NATIVE else (
                "http.synthetic-page-browser")
            source_observation = Observation(kind, identity, attributes,
                                             provenance_model)
            updated, delta = state.Apply(objects=(source_patch, *projection.object_patches),
                observations=(source_observation, *projection.observations))

            if len(CanonicalModelJson(updated.ToDict())) > MAX_MODEL_BYTES:
                raise ValueError("proposed page model exceeds its owning size budget")

        except (OSError, ValueError, TypeError, AttributeError, OverflowError):
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Could not compose the current page acquisition model")) from None

        context.CheckCancellation()

        try:
            self.FinalAuthority(pinned, pinned_dict, grant, frontier, invocation, capability)

        except PermissionError:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                "Page authority changed or expired before model Save; evidence retained")) from None

        except (OSError, ValueError):
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Could not verify final page authority before model Save")) from None

        # No separate consumer I/O, composition or stale clock intervenes before owner Save.
        try:
            self._model.Save(updated, expected_revision=state.revision)

        except WorkspaceConflictError:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Page model revision conflict; captured evidence retained")) from None

        except WorkspaceBusyError:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Page model writer is busy; captured evidence retained")) from None

        except (OSError, ValueError):
            self.ReportSaveFailure(state, updated)

        context.CheckCancellation()

        try:
            context.ModelChanged(delta)

        except (JobError, ValueError, RuntimeError):
            raise JobError(JobFailure(JobFailureCode.OUTPUT_LIMIT,
                "Page model committed; model event was not delivered")) from None

        context.CheckCancellation()

        if not publish_progress:
            return frontier

        try:
            context.Progress(1, 1)

        except (JobError, ValueError, RuntimeError):
            raise JobError(JobFailure(JobFailureCode.OUTPUT_LIMIT,
                "Page model committed; progress event was not delivered")) from None

        return frontier

    def VerifyEvidence(self, record: EvidenceRecord, expected: bytes,
                       provenance: EvidenceProvenance, role: str) -> None:
        """Revalidate supplied/actual full manifests and exact bytes with role-specific Get/Read.

        Args:
            record: Exact owning manifest returned from the job attachment boundary.
            expected: Already admitted exact worker stdout or decoded closed body.
            provenance: Exact prepared collection metadata and actual terminal execution.
            role: Explicit stdout or response-body profile, without arbitrary roles.
        """

        if type(record) is not EvidenceRecord or (
            type(record.reference) is not EvidenceReference
            or type(record.provenance) is not EvidenceProvenance
            or type(record.schema_version) is not int
            or record.schema_version != 1 or type(record.evidence_id) is not str
            or len(record.evidence_id) != 71
        ):
            raise ValueError("page capture evidence manifest shape is invalid")

        for name in ("workspace_id", "scope_reference", "source_id", "source_version",
                     "tool_version", "started_at", "finished_at", "invocation_sha256"):
            if name == "tool_version" and self._renderer is PageRenderer.PLAYWRIGHT_OFFLINE and (
                provenance.tool_version is None
            ):
                if record.provenance.tool_version is not None or provenance.execution is None or (
                    provenance.execution.state is not ExecutionState.FAILED
                ):
                    raise ValueError("unknown browser tool version requires a failed execution")

                continue

            WebText(getattr(record.provenance, name))

        Execution(record.provenance.execution)
        reference = record.reference

        if reference.role != role or record.provenance != provenance or (
            reference.size_bytes != len(expected) or type(reference.size_bytes) is not int
            or reference.sha256 != hashlib.sha256(expected).hexdigest()
            or reference.locator != "blobs/sha256/" + reference.sha256
            or reference.media_type != ("application/json" if role == "stdout" else "text/html")
            or EvidenceRecord(reference, provenance) != record
        ):
            raise ValueError("page capture full manifest differs from the actual worker collection")

        actual = self._evidence.Get(record.evidence_id)

        if actual != record or self._evidence.Read(actual.reference) != expected:
            raise ValueError("page capture actual full artifact differs from collection")

    def FinalAuthority(self, pinned: ScopeSnapshot, pinned_dict: dict[str, object],
                       grant: PolicyGrant, frontier: CapturedWebFrontier,
                       invocation: AdapterInvocation, capability: CapabilityDescriptor) -> None:
        """Reread full scope plus fresh consent after every evidence/model composition boundary.

        Args:
            pinned: Full immutable scope snapshot used by the actual launch plan.
            pinned_dict: Exact owning ToDict representation retained before grant issuance.
            grant: Original launch grant and policy-owned snapshot/plan digest.
            frontier: Actual body consumer's separately serialized scope digest/revision.
            invocation: Exact prepared original worker invocation.
            capability: Exact trusted declared synthetic-page capability.
        """

        if type(invocation) is not AdapterInvocation or (
            type(capability) is not CapabilityDescriptor
        ):
            raise ValueError("page capture final plan inputs must be exact owner records")

        current = self.CurrentContext()
        payload = current.scope.ToDict()
        model_digest = hashlib.sha256(CanonicalModelJson(payload)).hexdigest()
        policy_digest = Digest(payload)

        if payload != pinned_dict or current.scope.revision != pinned.revision or (
            policy_digest != grant.plan.scope_sha256 or model_digest != frontier.scope_sha256
            or frontier.scope_revision != current.scope.revision
            or frontier.scope_reference != current.scope.Reference()
        ):
            raise PermissionError("page capture final snapshot or owning digests changed")

        fresh = self.Now()

        if self._renderer is PageRenderer.PLAYWRIGHT_OFFLINE:
            PolicyEngine().Validate(grant, invocation, capability, current, at=fresh)

        plan = PolicyEngine().Plan(invocation, capability, current, at=fresh)

        if plan != grant.plan or not current.scope.Check(self._target, at=fresh).Allowed() or (
            not current.scope.Check(self._address, at=fresh).Allowed()
        ):
            raise PermissionError("page capture final current consent or plan changed")

    def ReportSaveFailure(self, previous: ModelState, proposed: ModelState) -> None:
        """Reopen through the owner after an ambiguous acknowledgement without claiming rollback.

        Args:
            previous: Current model snapshot originally used for exact composition.
            proposed: Exact proposed transition whose Save acknowledgement failed.
        """

        message = "Page model Save acknowledgement is uncertain; reopen required; evidence retained"

        try:
            current = self._model.Open()

        except (OSError, ValueError):
            pass

        else:
            if current == proposed:
                message = "Page model committed; Save acknowledgement failed; evidence retained"

            elif current == previous:
                message = "Page model was not committed; captured evidence retained"

        raise JobError(JobFailure(JobFailureCode.STORAGE, message)) from None
