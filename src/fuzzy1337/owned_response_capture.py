# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""First-party closed response acquisition on existing policy, process, job and evidence owners."""

from __future__ import annotations

import asyncio
import math
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ExecutionState, ImpactLevel
from fuzzy1337.artifact_inputs import ArtifactPathInfo, PhysicalIdentity
from fuzzy1337.evidence import EvidenceProvenance
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionResources,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutionResult,
)
from fuzzy1337.executors.contracts import ExecutionEvent, ExecutionEventKind, ExecutionTermination
from fuzzy1337.jobs import JobContext, JobError, JobFailure, JobFailureCode
from fuzzy1337.owned_response_custody import (
    _CATALOG_FAMILY,
    _CONTENT_FAMILY,
    CAPABILITY_ID,
    PROVIDER_ID,
    Canonical,
    DirectoryIdentity,
    OwnedResponseCapture,
    OwnedResponseEvidenceStore,
    PublishCapture,
    RequireResponseFamily,
    ResponseDestination,
    ResponseFamily,
    ValidateControlResult,
    ValidateRequest,
    ValidateResult,
)
from fuzzy1337.policy import (
    GovernedLocalExecutor,
    PolicyContext,
    PolicyEngine,
    PolicyGrant,
    RequireTime,
    UtcNow,
)
from fuzzy1337.scope import Target, TargetKind

OWNED_RESPONSE_CAPABILITY = CapabilityDescriptor(CAPABILITY_ID, PROVIDER_ID, ImpactLevel.SAFE)


def SupportedPlatform() -> bool:
    """Identify the actual supported private-execution platform, without a portable fallback.

    Returns:
        True only on actual Linux; deterministic units can isolate this module-local view.
    """

    return sys.platform == "linux"


def RuntimeWorkPath(path: Path) -> str:
    """Render the selected physical work path under the supported runtime's POSIX grammar.

    Args:
        path: Original absolute physical work directory.

    Returns:
        Exact original runtime path spelling, never a searched or caller-supplied environment.
    """

    return path.as_posix()


def RuntimeExecutable() -> str:
    """Select the original trusted installed interpreter without PATH search.

    Returns:
        Absolute original interpreter spelling for the fixed installed module recipe.
    """

    return sys.executable


def PrepareResponseInvocation(url: str, *,
                                   _family: ResponseFamily = _CATALOG_FAMILY
                                   ) -> AdapterInvocation:
    """Describe the exact installed SAFE invocation without private files, contact or grant.

    Args:
        url: Exact closed literal source URL.
        _family: Immutable catalog or content binding; selects the fixed worker and recipe.

    Returns:
        Original fixed recipe suitable for canonical descriptive policy planning.
    """

    ResponseDestination(url, _family)

    return AdapterInvocation(
        _family.provider_id,
        AdapterRequest(
            _family.capability_id, Target(TargetKind.URL, url).Reference(), ImpactLevel.SAFE,
            {"url": url} if _family is _CATALOG_FAMILY else {"url": url, "retain_response": True}
        ),
        (RuntimeExecutable(), "-I", "-B", "-m", _family.worker_module, url),
        10,
        "1",
    )


@dataclass(frozen=True, slots=True)
class OwnedResponseAuthority:
    """Fresh executing owner and separate workflow approval beside existing policy context."""

    context: PolicyContext
    owner_reference: str
    workflow_approved: bool
    retain_response: bool = False

    def __post_init__(self) -> None:
        """Reject ambiguous owner/approval inputs without equating consent attester and actor."""

        if (
            type(self.context) is not PolicyContext
            or type(self.owner_reference) is not str
            or (
                not 1 <= len(self.owner_reference) <= 512
                or any(c in self.owner_reference for c in "\r\n\x00")
                or type(self.workflow_approved) is not bool
                or type(self.retain_response) is not bool
            )
        ):
            raise ValueError("owned response requires exact current authority inputs")


@dataclass(frozen=True, slots=True)
class PreparedOwnedResponseCapture:
    """Frozen original request/grant and physical work identities for one trusted attempt."""

    request: LocalExecutionRequest
    grant: PolicyGrant
    projection: bytes
    operation: Path
    operation_identity: tuple[int, int, int, int, int]
    work_identity: tuple[int, int, int, int, int]
    workspace_identity: tuple[int, int]


class OwnedResponseCaptureProvider:
    """Run one closed acquisition; no provider enrollment, model Save, HAR or Java capability."""

    def __init__(
        self,
        workspace_root: Path,
        url: str,
        authority_provider: Callable[[], OwnedResponseAuthority],
        *,
        approve_workflow: bool,
        retain_response: bool = False,
        _family: ResponseFamily = _CATALOG_FAMILY,
        clock: Callable[[], datetime] = UtcNow,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        """Configure a first-party attempt without a socket or grant.

        Args:
            workspace_root: Explicit existing physical owning workspace.
            url: Exact closed literal owned source URL.
            authority_provider: Trusted fresh context, executing owner and current approval reader.
            approve_workflow: Separate exact explicit workflow approval, never a capability grant.
            clock: Aware current policy/evidence clock.
            monotonic: Current process monotonic budget clock.
        """

        ResponseDestination(url, _family)

        if (
            type(approve_workflow) is not bool
            or not approve_workflow
            or type(retain_response) is not bool
            or (_family is _CONTENT_FAMILY and not retain_response)
            or (not callable(authority_provider) or not callable(clock) or not callable(monotonic))
        ):
            raise ValueError("owned response requires explicit workflow approval")

        root = Path(workspace_root).absolute()
        info = ArtifactPathInfo(root, directory=True)
        self.root = root
        self.url = url
        self._family = RequireResponseFamily(_family)
        self._retained = retain_response
        self._authority = authority_provider
        self._clock = clock
        self._monotonic = monotonic
        self._last_tick: float | None = None
        self._root_identity = (info.st_dev, info.st_ino)
        self._approved = approve_workflow
        self.prepared: PreparedOwnedResponseCapture | None = None
        self.capture: OwnedResponseCapture | None = None
        self.store = OwnedResponseEvidenceStore(root / "evidence", _family=self._family)
        self._used = False
        self._interrupted = False
        self._timed_out = False
        self._process_started = False
        self._cleanup_confirmed = False
        self._owner_cancelled = False
        self._work_removed = False
        self._origin: float | None = None
        self._final_origin: float | None = None
        self._capture_binding: bytes | None = None
        self._source_identity: tuple[int, int, int, int, int] | None = None
        self._context: JobContext | None = None
        self._owner_task: asyncio.Task[object] | None = None

    def Tick(self) -> float:
        """Read a finite nonregressing monotonic budget clock without granting extra time.

        Returns:
            Current finite monotonic seconds, with no deadline renewal.
        """

        value = self._monotonic()

        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or (
                not math.isfinite(value)
                or value < 0
                or self._last_tick is not None
                and value < self._last_tick
            )
        ):
            raise ValueError("owned response monotonic clock differs")

        self._last_tick = float(value)

        return float(value)

    def Now(self) -> datetime:
        """Read a fresh aware clock value without echoing caller failures.

        Returns:
            Actual aware current time for existing policy and evidence normalization.
        """

        at = self._clock()
        RequireTime(at)

        return at

    def Current(self, context: JobContext) -> PolicyContext:
        """Read exact current owner, target, source scope and explicit workflow approval.

        Args:
            context: Original owning running job.

        Returns:
            Existing current PolicyContext without a separate authority store.
        """

        authority = self._authority()
        address = Target(TargetKind.IP, ResponseDestination(self.url, self._family)[0])
        target = Target(TargetKind.URL, self.url)

        if (
            type(authority) is not OwnedResponseAuthority
            or not self._approved
            or (
                not authority.workflow_approved
                or (self._family is _CONTENT_FAMILY
                    and (not self._retained or not authority.retain_response))
                or authority.owner_reference != context.Spec.owner_reference
                or authority.context.scope.workspace_id != context.Spec.workspace_id
                or authority.context.scope.Reference() != context.Spec.scope_reference
                or authority.context.target != target
                or set(authority.context.destinations) != {target, address}
            )
        ):
            raise PermissionError("owned response current owner or source authority changed")

        return authority.context

    def Prepare(self, context: JobContext) -> PreparedOwnedResponseCapture:
        """Build one original immutable request and private work after current authority checks.

        Args:
            context: Original owning job with the fixed timeout/provider.

        Returns:
            Frozen exact approved request plus original physical workspace/work bindings.
        """

        if (
            not SupportedPlatform()
            or context.Spec.provider_id != self._family.provider_id
            or (context.Spec.timeout_seconds != 30)
        ):
            raise ValueError("owned response parent requires its Linux fixed job profile")

        current = self.Current(context)
        operation = self.root / ("owned-response-" + uuid.uuid4().hex)
        invocation = (PrepareOwnedResponseInvocation(self.url)
                      if self._family is _CATALOG_FAMILY else
                      PrepareResponseInvocation(self.url, _family=self._family))
        capability = CapabilityDescriptor(self._family.capability_id, self._family.provider_id,
                                          ImpactLevel.SAFE)
        grant = PolicyEngine().Authorize(invocation, capability, current, at=self.Now())

        if grant.authorization.granted_privileges:
            raise PermissionError("owned response fixed profile grants no privileges")

        self.store.root.mkdir(mode=0o700, exist_ok=True)
        ArtifactPathInfo(self.store.root, directory=True)
        operation.mkdir(mode=0o700)
        work = operation / "work"
        work.mkdir(mode=0o700)
        environment = {key: "" for key in ("PATH", "COMSPEC", "PATHEXT", "SYSTEMROOT", "WINDIR")}
        environment.update(
            LANG="C", LC_ALL="C", TEMP=RuntimeWorkPath(work), TMP=RuntimeWorkPath(work)
        )
        request = LocalExecutionRequest(
            invocation,
            capability,
            grant.authorization,
            work.relative_to(self.root).as_posix(),
            environment,
            ExecutionResources(self._family.stdout_bytes, 1, 0.5),
        )
        projection = Canonical(request)
        from fuzzy1337.owned_response_custody import ParseCanonical

        ValidateRequest(ParseCanonical(projection, 16384), self.url, _family=self._family)

        return PreparedOwnedResponseCapture(
            request,
            grant,
            projection,
            operation,
            DirectoryIdentity(operation),
            DirectoryIdentity(work),
            self._root_identity,
        )

    def CheckPrepared(
        self,
        prepared: PreparedOwnedResponseCapture,
        context: JobContext,
        origin: float,
        *,
        live_work: bool = True,
    ) -> PolicyContext:
        """Recheck the whole actual shared request where the existing facade requests fresh context.

        Args:
            prepared: Original frozen request and physical work association.
            context: Actual original running job.
            origin: Shared monotonic provider origin, never renewed.
            live_work: Launch requires live work; persistence uses the original cleanup proof.

        Returns:
            Fresh existing policy context after full fixed-request validation.
        """

        root = ArtifactPathInfo(self.root, directory=True)

        if Canonical(prepared.request) != prepared.projection or (
            (root.st_dev, root.st_ino) != prepared.workspace_identity
            or DirectoryIdentity(prepared.operation) != prepared.operation_identity
            or live_work
            and DirectoryIdentity(prepared.operation / "work") != prepared.work_identity
            or self.Tick() - origin >= 28
            or context.Cancellation.is_set()
        ):
            raise PermissionError("owned response fixed request or physical authority changed")

        current = self.Current(context)
        PolicyEngine().Validate(
            prepared.grant,
            prepared.request.invocation,
            prepared.request.capability,
            current,
            at=self.Now(),
        )

        return current

    async def Execute(
        self, prepared: PreparedOwnedResponseCapture, context: JobContext, origin: float
    ) -> LocalExecutionResult:
        """Bridge all cancellation to the one original owner and await its cleanup.

        Args:
            prepared: Exact original request/grant.
            context: Original running job and cooperative cancellation source.
            origin: Shared original monotonic provider origin.

        Returns:
            Actual terminal result after owned process cleanup, never an abandoned task.
        """

        bridge = asyncio.Event()
        started = self.Tick()

        def Current() -> PolicyContext:
            """Repeat whole-request and fresh authority at the existing launch boundary.

            Returns:
                Fresh canonical context for existing policy revalidation.
            """

            if bridge.is_set():
                raise PermissionError("owned response launch was cancelled")

            return self.CheckPrepared(prepared, context, origin)

        def OnEvent(event: ExecutionEvent) -> None:
            """Project only bounded original lifecycle liveness, never stream contents.

            Args:
                event: Original executor control or transient stream fragment.
            """

            if event.kind is ExecutionEventKind.STARTED:
                self._process_started = True
                if self.Tick() - started > 2:
                    raise ValueError("owned response startup budget expired")

                context.Heartbeat()

            elif event.kind is ExecutionEventKind.COMPLETED:
                context.Heartbeat()

        self.CheckPrepared(prepared, context, origin)
        executor = GovernedLocalExecutor(self.root, clock=self._clock)
        task = asyncio.create_task(
            executor.Execute(
                prepared.request,
                grant=prepared.grant,
                context_provider=Current,
                on_event=OnEvent,
                cancellation=bridge,
                own_descendants=False,
            )
        )
        cancelled = asyncio.create_task(context.Cancellation.wait())

        try:
            done, _ = await asyncio.wait(
                (task, cancelled), timeout=12, return_when=asyncio.FIRST_COMPLETED
            )

            if task not in done:
                self._interrupted = context.Cancellation.is_set()
                self._timed_out = not self._interrupted
                bridge.set()

        except asyncio.CancelledError:
            self._interrupted = True
            bridge.set()

        finally:
            cancelled.cancel()
            try:
                await asyncio.gather(cancelled, return_exceptions=True)

            except asyncio.CancelledError:
                self._interrupted = True
                bridge.set()

        while True:
            try:
                result = await asyncio.shield(task)
                break

            except asyncio.CancelledError:
                if task.cancelled():
                    self._owner_cancelled = True
                    raise

                self._interrupted = True
                bridge.set()

        self._cleanup_confirmed = True

        if self.Tick() - started > 16:
            self._timed_out = True

        return result

    def CaptureBinding(self, capture: OwnedResponseCapture) -> bytes:
        """Freeze original acknowledged fields without declaring a model/workspace Save.

        Args:
            capture: Original provider-owned admitted capture.

        Returns:
            Canonical original request/manifest/result-fragment association.
        """

        outcome = capture.outcome

        if outcome is None:
            raise ValueError("owned response persistence needs admitted original outcome")

        return Canonical(
            {
                "request": capture.request,
                "records": capture.records,
                "receipt_id": capture.receipt_id,
                "refusal": capture.refusal,
                "execution": outcome.execution,
                "termination": outcome.termination,
                "stdout_hex": outcome.stdout.hex(),
                "stderr_hex": outcome.stderr.hex(),
                "events": [
                    {
                        "sequence": e.sequence,
                        "kind": e.kind,
                        "data_hex": e.data.hex(),
                        "termination": e.termination,
                    }
                    for e in outcome.events
                ],
            }
        )

    def ValidatePersistence(self, context: JobContext, capture: OwnedResponseCapture) -> None:
        """Revalidate original authority at each Save boundary after intentional work cleanup.

        Args:
            context: Same still-running owning job used by acquisition.
            capture: Exact original acknowledged successful self-owned capture.

        Raises:
            JobError: Original association, current authority or shared remaining budget differs.
        """

        try:
            context.CheckCancellation()
            owner_task = self._owner_task

            if owner_task is None:
                raise PermissionError("owned response original owning task is absent")

            owner_finished = owner_task.done()

            if (
                capture is not self.capture
                or type(capture) is not OwnedResponseCapture
                or context is not self._context
                or asyncio.current_task() is not owner_task
                or owner_finished
                or (
                    self.prepared is None
                    or capture.request is not self.prepared.request
                    or capture.receipt_id is None
                    or capture.refusal is not None
                    or not self._cleanup_confirmed
                    or not self._work_removed
                    or self._capture_binding is None
                    or self.CaptureBinding(capture) != self._capture_binding
                    or PhysicalIdentity(ArtifactPathInfo(capture.stage / "admitted.json"))
                    != self._source_identity
                    or self._origin is None
                    or self._final_origin is None
                )
            ):
                raise PermissionError("owned response original persistence association differs")

            if self.Tick() - self._origin > 28 or self.Tick() - self._final_origin > 2:
                raise TimeoutError

            self.CheckPrepared(self.prepared, context, self._origin, live_work=False)

        except PermissionError:
            raise JobError(
                JobFailure(
                    JobFailureCode.AUTHORIZATION, "Owned response persistence authority was denied"
                )
            ) from None

        except TimeoutError:
            raise JobError(
                JobFailure(
                    JobFailureCode.TIMEOUT, "Owned response original persistence budget expired"
                )
            ) from None

        except (OSError, ValueError, RuntimeError):
            raise JobError(
                JobFailure(
                    JobFailureCode.AUTHORIZATION,
                    "Owned response original persistence proof differs",
                )
            ) from None

    async def Run(self, context: JobContext) -> None:
        """Admit original outcome before safe custody, retaining staging without product Save.

        Args:
            context: Existing original running job, without registry or core API changes.

        Raises:
            JobError: Actual authority, execution, admission, deadline or custody failed.
            asyncio.CancelledError: Original caller/job cancellation after owned cleanup/custody.
        """

        if self._used:
            raise JobError(
                JobFailure(JobFailureCode.PROVIDER, "Owned response attempt was already used")
            )

        self._used = True
        self._context = context
        self._owner_task = asyncio.current_task()
        origin = self.Tick()
        self._origin = origin
        prepared: PreparedOwnedResponseCapture | None = None

        try:
            context.CheckCancellation()
            prepared = self.Prepare(context)
            self.prepared = prepared

            if self.Tick() - origin > 2:
                raise TimeoutError

            started = self.Now().isoformat()
            result = await self.Execute(prepared, context, origin)
            custody_started = self.Tick()
            ValidateControlResult(result, _family=self._family)

            if Canonical(prepared.request) != prepared.projection:
                raise PermissionError("owned response actual full request changed")
            refusal: str | None = None

            try:
                admitted = ValidateResult(result, self.url, _family=self._family)
                refusal = str(admitted["error"]) if admitted["outcome"] == "refused" else None

            except ValueError:
                admitted = None
                refusal = "stderr-unadmitted" if result.stderr else "record-unadmitted"

                if result.termination is ExecutionTermination.OUTPUT_LIMIT:
                    refusal = "output-limit"

                elif result.termination is ExecutionTermination.TIMEOUT:
                    refusal = "execution-incomplete"

                elif result.execution.state is ExecutionState.CANCELLED:
                    refusal = "cancelled"

            provenance = EvidenceProvenance(
                context.Spec.workspace_id,
                context.Spec.scope_reference,
                self._family.provider_id,
                "1",
                "1",
                started,
                self.Now().isoformat(),
                InvocationDigest(prepared.request.invocation),
                result.execution,
            )
            self.capture = PublishCapture(
                context,
                self.store,
                prepared.operation,
                prepared.request,
                result,
                provenance,
                admitted=admitted,
                refusal=refusal,
            )

            if self.capture.receipt_id is None:
                raise JobError(
                    JobFailure(JobFailureCode.STORAGE, "Owned response custody is incomplete")
                )

            if result.termination is ExecutionTermination.OUTPUT_LIMIT:
                raise JobError(
                    JobFailure(
                        JobFailureCode.OUTPUT_LIMIT, "Owned response actual output budget exceeded"
                    )
                )

            if result.termination is ExecutionTermination.TIMEOUT:
                raise JobError(
                    JobFailure(
                        JobFailureCode.TIMEOUT, "Owned response actual worker deadline exceeded"
                    )
                )

            if result.execution.state is ExecutionState.CANCELLED or (
                self._interrupted or context.Cancellation.is_set()
            ):
                raise asyncio.CancelledError

            if self._timed_out or self.Tick() - custody_started > 8 or (self.Tick() - origin > 28):
                raise TimeoutError

            if refusal is not None:
                raise JobError(
                    JobFailure(JobFailureCode.PROVIDER, "Owned response acquisition was refused")
                )

            self._capture_binding = self.CaptureBinding(self.capture)
            self._source_identity = PhysicalIdentity(
                ArtifactPathInfo(self.capture.stage / "admitted.json")
            )
            final = self.Tick()
            self._final_origin = final
            self.CheckPrepared(prepared, context, origin)

            if self.Tick() - final > 2 or self.Tick() - origin > 28:
                raise TimeoutError

        except asyncio.CancelledError:
            raise

        except JobError:
            raise

        except PermissionError:
            raise JobError(
                JobFailure(
                    JobFailureCode.AUTHORIZATION, "Owned response current authority was denied"
                )
            ) from None

        except TimeoutError:
            raise JobError(
                JobFailure(JobFailureCode.TIMEOUT, "Owned response inclusive budget expired")
            ) from None

        except (OSError, ValueError, RuntimeError):
            raise JobError(
                JobFailure(
                    JobFailureCode.PROVIDER, "Owned response fixed execution could not complete"
                )
            ) from None

        finally:
            if (
                prepared is not None
                and not self._owner_cancelled
                and (self._cleanup_confirmed or not self._process_started)
            ):
                work = prepared.operation / "work"

                try:
                    if DirectoryIdentity(work) != prepared.work_identity:
                        raise ValueError("owned response original work changed")

                    work.rmdir()
                    self._work_removed = True

                except (OSError, ValueError):
                    raise JobError(
                        JobFailure(
                            JobFailureCode.PROVIDER,
                            "Owned response private work cleanup is unverified",
                        )
                    ) from None


def PrepareOwnedResponseInvocation(url: str) -> AdapterInvocation:
    """Describe the exact installed SAFE invocation without private files, contact or grant.

    Args:
        url: Exact closed literal source URL.

    Returns:
        Original fixed recipe suitable for canonical descriptive policy planning.
    """

    return PrepareResponseInvocation(url)
