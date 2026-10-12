# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental governed native discovery into shared evidence, jobs and durable model state."""

from __future__ import annotations

import asyncio
import inspect
import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import cast

from fuzzy1337.adapters import (
    AdapterDescriptor,
    AdapterReport,
    AdapterRequest,
    ExecutionState,
    ImpactLevel,
)
from fuzzy1337.adapters.contracts import RequireIdentifier
from fuzzy1337.adapters.native_http import (
    DISCOVERY_VERSION,
    NATIVE_HTTP_CAPABILITY,
    NATIVE_HTTP_MAX_RECORD_BYTES,
    NATIVE_HTTP_PROVIDER_ID,
    Endpoint,
    NativeHttpAdapter,
    NativeHttpRecordError,
    ParseRecord,
    RequestTimeout,
)
from fuzzy1337.evidence import EvidenceError, EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptors,
    ExecutionResources,
    InvocationDigest,
    LocalExecutionRequest,
)
from fuzzy1337.executors.contracts import ExecutionEvent, ExecutionTermination
from fuzzy1337.executors.local import LocalExecutionError
from fuzzy1337.jobs import JobContext, JobError, JobFailure, JobFailureCode
from fuzzy1337.model import LocalModelStore, ModelProvenance, ObjectIdentity, ObjectKind
from fuzzy1337.policy import (
    GovernedLocalExecutor,
    ImpactPolicy,
    PolicyContext,
    PolicyEngine,
    UtcNow,
)
from fuzzy1337.scope import LocalScopeStore, Target, TargetKind
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceBusyError, WorkspaceConflictError

__all__ = [
    "DISCOVERY_VERSION", "NATIVE_HTTP_PROVIDER_ID", "NATIVE_HTTP_CAPABILITY",
    "DiscoveryLimits", "NativeDiscoveryProvider",
]


@dataclass(frozen=True, slots=True)
class DiscoveryLimits:
    """Finite sequential endpoint/time/rate bounds; no target expansion is permitted."""

    max_endpoints: int = 8
    request_timeout_seconds: float = 3.0
    interval_seconds: float = 0.2
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        """Reject bool/nonfinite bounds and cap endpoints at sixteen and runtime at sixty."""

        if type(self.max_endpoints) is not int or not 1 <= self.max_endpoints <= 16:
            raise ValueError("max_endpoints must be an integer from 1 through 16")

        RequestTimeout(self.request_timeout_seconds)

        for name, lower, upper in (("interval_seconds", 0.05, 10), ("timeout_seconds", 0.05, 60)):
            value = getattr(self, name)

            if isinstance(value, bool) or not isinstance(value, (int, float)) or (
                not lower <= value <= upper or not math.isfinite(value)
            ):
                raise ValueError(f"{name} is outside the finite discovery bounds")

    @property
    def FirstUpdateBudgetSeconds(self) -> float:
        """Return nominal probe plus startup budget, capped by the total deadline.

        Returns:
            Seconds until the first observed update under available local execution;
            operating-system scheduling and storage are not a real-time guarantee.
        """

        return min(self.timeout_seconds, self.request_timeout_seconds + 1)


class NativeDiscoveryProvider:
    """Run explicitly approved literal endpoints through governed jobs and the shared model."""

    def __init__(
        self, workspace_root: Path, targets: tuple[Target, ...], scope_id: str,
        policy: ImpactPolicy,
        *, limits: DiscoveryLimits = DiscoveryLimits(), clock: Callable[[], datetime] = UtcNow,
        context_validator: Callable[[PolicyContext], None] | None = None,
    ) -> None:
        """Validate a finite sensor plan without I/O or starting any worker.

        Args:
            workspace_root: Caller-owned existing workspace with scope/model/evidence partitions.
            targets: Unique exact literal-IP URL targets, without inferred endpoints.
            scope_id: Existing persisted scope whose consent is rechecked at each launch.
            policy: Explicit operator capability/impact permission; default policy grants nothing.
            limits: Finite sequential request and total runtime budgets.
            clock: Aware UTC authority clock shared with the governed executor.
            context_validator: Optional trusted synchronous consumer guard over fresh immutable
                context; must return None or raise to deny. It cannot replace core policy checks.

        Raises:
            ValueError: Targets, policy, root, scope identifier or limits are unsupported.
        """

        if not isinstance(limits, DiscoveryLimits) or not isinstance(policy, ImpactPolicy):
            raise ValueError("native discovery requires typed limits and impact policy")

        if context_validator is not None and not callable(context_validator):
            raise ValueError("context_validator must be callable when supplied")

        if not isinstance(targets, tuple) or not 1 <= len(targets) <= limits.max_endpoints:
            raise ValueError("native discovery requires a nonempty bounded target tuple")

        for target in targets:
            if not isinstance(target, Target) or target.kind is not TargetKind.URL:
                raise ValueError("native discovery targets must be exact URL records")

            Endpoint(target.value)

        if len(set(targets)) != len(targets):
            raise ValueError("native discovery endpoints must not be duplicated")

        RequireIdentifier(scope_id, "scope_id")
        self._workspace = LocalWorkspaceStore(workspace_root)
        self._scope = LocalScopeStore(self._workspace.root)
        self._model = LocalModelStore(self._workspace.root)
        self._evidence = LocalEvidenceStore(self._workspace.root / "evidence")
        self._adapter = NativeHttpAdapter(self._evidence.Read)
        self._targets = targets
        self._scope_id = scope_id
        self._policy = policy
        self._clock = clock
        self._context_validator = context_validator
        self.limits = limits

    @property
    def Descriptor(self) -> AdapterDescriptor:
        """Return native.http SAFE metadata; inspection grants no execution authority.

        Returns:
            Existing adapter descriptor shared by policy and Quick Scan consumers.
        """

        return self._adapter.Descriptor

    async def Run(self, context: JobContext) -> None:
        """Acquire finite endpoint observations and publish only saved verified model deltas.

        Workspace/scope/model creation belongs to the consumer. Raw output is
        admitted to evidence only after its strict non-sensitive grammar is checked.
        Earlier saved deltas survive later denial, timeout, cancellation or failure.

        Args:
            context: Existing ScanJob owner of event, cancellation and raw evidence boundaries.

        Raises:
            JobError: Authorization, storage, normalization, deadline or worker failure.
            asyncio.CancelledError: Cooperative/forced cancellation after worker cleanup.
        """

        try:
            workspace = self._workspace.Open()
            self._model.Open()

        except (OSError, ValueError) as error:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                                      "Could not open discovery state")) from error

        if context.Spec.workspace_id != workspace.workspace_id or (
            context.Spec.provider_id != NATIVE_HTTP_PROVIDER_ID
            or context.Spec.scope_reference != "scope:" + self._scope_id
        ):
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                                      "Discovery context does not match the owning job"))

        try:
            async with asyncio.timeout(self.limits.timeout_seconds):
                for index, target in enumerate(self._targets):
                    context.CheckCancellation()
                    await self.Acquire(context, target)
                    context.Progress(index + 1, len(self._targets))

                    if index + 1 < len(self._targets):
                        try:
                            await asyncio.wait_for(context.Cancellation.wait(),
                                                   self.limits.interval_seconds)

                        except TimeoutError:
                            pass

                        context.CheckCancellation()

        except TimeoutError as error:
            raise JobError(JobFailure(JobFailureCode.TIMEOUT,
                                      "Native discovery deadline exceeded")) from error

    async def Acquire(self, context: JobContext, target: Target) -> None:
        """Execute one pinned endpoint and persist its attributable sensor interpretation.

        Args:
            context: Current owning job whose evidence store uses the workspace partition.
            target: One validated canonical URL from the constructor's finite plan.

        Raises:
            JobError: Current scope/launch, worker, parser, integrity or storage fails.
            asyncio.CancelledError: The job or owned worker is cancelled.
        """

        _, address, port, _ = Endpoint(target.value)
        invocation = self._adapter.PrepareInvocation(AdapterRequest(
            NATIVE_HTTP_CAPABILITY, target.Reference(), ImpactLevel.SAFE,
            {"url": target.value, "timeout_seconds": self.limits.request_timeout_seconds},
        ))
        capability = CapabilityDescriptors(self.Descriptor)[0]

        def CurrentContext() -> PolicyContext:
            """Reread current persisted scope immediately at authorization and launch."""

            current = PolicyContext(self._scope.Open(self._scope_id), self._policy, target,
                                    (Target(TargetKind.IP, address), target))

            if self._context_validator is not None:
                response = cast(Callable[[PolicyContext], object], self._context_validator)(current)

                if response is not None:
                    if inspect.iscoroutine(response):
                        response.close()

                    raise PermissionError("context_validator must synchronously return None")

            return current

        started = self._clock().isoformat()

        def OnEvent(event: ExecutionEvent) -> None:
            """Publish bounded liveness without copying subprocess stream bytes."""

            context.Heartbeat()

        try:
            grant = PolicyEngine().Authorize(invocation, capability, CurrentContext(),
                                             at=self._clock())
            request = LocalExecutionRequest(invocation, capability, grant.authorization,
                resources=ExecutionResources(NATIVE_HTTP_MAX_RECORD_BYTES, 1024, 0.1))
            executor = GovernedLocalExecutor(self._workspace.root, clock=self._clock)
            result = await executor.Execute(request, grant=grant, context_provider=CurrentContext,
                                            on_event=OnEvent, cancellation=context.Cancellation)

        except PermissionError as error:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                                      "Native discovery execution was denied")) from error

        except LocalExecutionError as error:
            raise JobError(JobFailure(JobFailureCode.PROVIDER,
                                      "Could not launch native discovery")) from error

        except (OSError, ValueError) as error:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                                      "Could not read current discovery authority")) from error

        if result.execution.state is ExecutionState.CANCELLED:
            raise asyncio.CancelledError

        if result.termination is ExecutionTermination.OUTPUT_LIMIT:
            raise JobError(JobFailure(JobFailureCode.OUTPUT_LIMIT,
                                      "Native discovery output budget exceeded"))

        if result.termination is ExecutionTermination.TIMEOUT:
            raise JobError(JobFailure(JobFailureCode.TIMEOUT, "Native probe deadline exceeded"))

        try:
            record = ParseRecord(result.stdout, target.value)

        except NativeHttpRecordError as error:
            raise JobError(JobFailure(JobFailureCode.NORMALIZATION,
                                      "Native output violated its safe record contract")) from error

        artifact = context.CaptureEvidence(result.stdout, "stdout", "application/json",
            EvidenceProvenance(context.Spec.workspace_id, context.Spec.scope_reference,
                NATIVE_HTTP_PROVIDER_ID, DISCOVERY_VERSION, DISCOVERY_VERSION, started,
                self._clock().isoformat(), InvocationDigest(invocation), result.execution))

        if record.get("error") == "timeout":
            raise JobError(JobFailure(JobFailureCode.TIMEOUT, "Native probe deadline exceeded"))

        if result.execution.state is not ExecutionState.SUCCEEDED or "error" in record:
            raise JobError(JobFailure(JobFailureCode.PROVIDER,
                                      "Native endpoint observation failed"))

        context.CheckCancellation()
        report = AdapterReport(invocation, result.execution, (artifact.evidence.reference,))
        host = "host:" + address
        natural_port = f"{host}/tcp/{port}"
        bindings = {
            host: ObjectIdentity(context.Spec.workspace_id, ObjectKind.HOST, address),
            natural_port: ObjectIdentity(context.Spec.workspace_id, ObjectKind.PORT, natural_port),
            natural_port + "/service": ObjectIdentity(
                context.Spec.workspace_id, ObjectKind.SERVICE, natural_port,
            ),
            target.Reference(): ObjectIdentity(context.Spec.workspace_id, ObjectKind.ENDPOINT,
                                               target.value),
        }

        try:
            normalized = self._adapter.NormalizeReport(report)

        except (ValueError, OSError, EvidenceError) as error:
            raise JobError(JobFailure(JobFailureCode.NORMALIZATION,
                                      "Could not verify native discovery evidence")) from error

        try:
            state = self._model.Open()
            updated, delta = state.ApplyAdapterResult(normalized, bindings, ModelProvenance(
                NATIVE_HTTP_PROVIDER_ID, context.Spec.job_id, self._clock().isoformat(),
                context.Spec.scope_reference, target.Reference(), DISCOVERY_VERSION,
                report.evidence, report.execution,
            ))
            self._model.Save(updated, expected_revision=state.revision)

        except (OSError, ValueError, WorkspaceBusyError, WorkspaceConflictError) as error:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                                      "Could not persist native discovery model")) from error

        context.ModelChanged(delta)
