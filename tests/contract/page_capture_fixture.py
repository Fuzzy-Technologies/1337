# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent closed HTML/wire/oracle inputs and actual owner-backed acquisition fixtures."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.jobs import JobSpec, ScanJob
from fuzzy1337.model import LocalModelStore
from fuzzy1337.page_capture import (
    PAGE_CAPTURE_CAPABILITY,
    PAGE_CAPTURE_PROVIDER_ID,
    KnownSyntheticHtmlBody,
    LocalPageCaptureProvider,
    PageCaptureLimits,
)
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.requests import Endpoint, RequestTemplate
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)
FIXTURES = Path(__file__).parent / "fixtures"


def Body() -> bytes:
    """Read the independent LF-pinned reviewed body without deriving it from implementation."""

    return (FIXTURES / "local-page-capture.v1.html").read_bytes()


def Wire() -> bytes:
    """Read the independent exact CRLF/LF wire without text conversion or producer rendering."""

    return (FIXTURES / "local-page-capture.response.v1.http").read_bytes()


def Oracle() -> dict:
    """Load the independent handwritten expected behavior, without updating any expectation."""

    return json.loads((FIXTURES / "local-page-capture.oracle.v1.json").read_bytes())


@dataclass(frozen=True)
class Fixture:
    """Keep explicit workspace/source/scope/policy state through actual production owners."""

    root: Path
    source: RequestTemplate
    scope: ScopeSnapshot
    policy: ImpactPolicy

    @classmethod
    def Create(cls, root: Path, origin: str = "http://127.0.0.1:32123", *,
               unicode_consent: bool = False, valid_until: str | None = None) -> Fixture:
        """Create owned synthetic state and register exactly source/IP/eligible/excluded URLs."""

        LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned page fixture"), "synthetic")
        LocalModelStore(root).Create()
        targets = tuple(Target(TargetKind.URL, origin + path) for path in (
            "/docs/index", "/alpha", "/docs/next", "/zeta", "/blocked",
        ))
        address = Target(TargetKind.IP, "::1" if "[::1]" in origin else "127.0.0.1")
        scope = ScopeSnapshot("local", "synthetic", ScopeAuthorization(
            AuthorizationState.GRANTED,
            "owner:\u0422\u0438\u043c\u0443\u0440" if unicode_consent else "owner:test",
            "approval:\u0441\u0438\u043d\u0442\u0435\u0442\u0438\u043a\u0430"
            if unicode_consent else "approval:synthetic",
            valid_until=valid_until,
        ), targets=(*targets, address), allow=(*targets, address), exclusions=(targets[-1],))
        saved = LocalScopeStore(root).Create(scope)
        policy = ImpactPolicy("local", permissions=(CapabilityPermission(
            PAGE_CAPTURE_CAPABILITY, PAGE_CAPTURE_PROVIDER_ID, ImpactLevel.SAFE,
        ),))

        return cls(root, RequestTemplate(Endpoint("synthetic", origin, "/docs/index")),
                   saved, policy)

    def Provider(self, *, limits: PageCaptureLimits = PageCaptureLimits(),
                 clock: Callable[[], datetime] = lambda: NOW) -> LocalPageCaptureProvider:
        """Construct the actual provider without launch or an authorization shortcut."""

        return LocalPageCaptureProvider(self.root, self.source,
            KnownSyntheticHtmlBody("owned-loopback-html.v1"), "local", self.policy,
            limits=limits, clock=clock)

    def Job(self, *, provider: LocalPageCaptureProvider | None = None,
            max_events: int = 4096, job_id: str = "job:page-capture") -> ScanJob:
        """Bind the actual producer to the job and unchanged evidence attachment owner."""

        return ScanJob(JobSpec(job_id, "synthetic", "scope:local", "owner:test",
            PAGE_CAPTURE_PROVIDER_ID, 15), self.Provider() if provider is None else provider,
            evidence_store=LocalEvidenceStore(self.root / "evidence"), max_events=max_events)


def Run(job: ScanJob):
    """Start/wait using the assembled ordinary job lifecycle without an ad-hoc worker bypass."""

    async def StartAndWait():
        """Wait for actual terminal state after child ownership and cleanup."""

        job.Start()

        return await job.Wait()

    return asyncio.run(StartAndWait())


def WorkspaceBytes(root: Path) -> bytes:
    """Collect only this synthetic workspace's retained files for privacy assertions."""

    return b"\n".join(path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file())
