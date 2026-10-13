# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent reviewed traversal bodies and ordinary workspace/scope/job composition."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.adapters.page_capture import (
    PAGE_CAPTURE_CAPABILITY,
    PAGE_CAPTURE_PROVIDER_ID,
    KnownSyntheticHtmlBody,
)
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.jobs import JobSpec, ScanJob
from fuzzy1337.model import LocalModelStore
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
from fuzzy1337.web_traversal import LocalWebTraversalProvider, OwnedTraversalPage
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)
PATHS = ("/index", "/alpha", "/beta", "/shared")
EXPECTED_COMMIT_PATHS = ("/index", "/alpha", "/beta", "/shared")
FIXTURES = Path(__file__).parent / "fixtures"


def Body(path: str) -> bytes:
    """Read exact handwritten LF-pinned synthetic markup without producer-generated expectations."""

    return (FIXTURES / ("web-traversal." + path[1:] + ".v1.html")).read_bytes()


@dataclass(frozen=True)
class Fixture:
    """Retain explicit actual first-party owners and selected sources for a traversal test."""

    root: Path
    origin: str
    pages: tuple[OwnedTraversalPage, ...]
    policy: ImpactPolicy

    @classmethod
    def Create(cls, root: Path, origin: str = "http://127.0.0.1:32123") -> Fixture:
        """Create owned state and exact allow/exclusion rules, without inferred crawl consent."""

        LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned traversal fixture"),
                                         "synthetic")
        LocalModelStore(root).Create()
        urls = tuple(Target(TargetKind.URL, origin + path)
                     for path in (*PATHS, "/blocked", "/unselected"))
        address = Target(TargetKind.IP, "127.0.0.1")
        LocalScopeStore(root).Create(ScopeSnapshot("local", "synthetic", ScopeAuthorization(
            AuthorizationState.GRANTED, "owner:test", "approval:owned-traversal"),
            targets=(*urls, address), allow=(*urls, address), exclusions=(urls[-2],)))
        policy = ImpactPolicy("local", permissions=(CapabilityPermission(
            PAGE_CAPTURE_CAPABILITY, PAGE_CAPTURE_PROVIDER_ID, ImpactLevel.SAFE),))
        pages = tuple(OwnedTraversalPage(RequestTemplate(Endpoint("synthetic", origin, path)),
            KnownSyntheticHtmlBody("owned-traversal-" + path[1:] + ".v1")) for path in PATHS)

        return cls(root, origin, pages, policy)

    def Provider(self, **kwargs) -> LocalWebTraversalProvider:
        """Compose the actual controller with the ordinary current policy/evidence/model owners."""

        return LocalWebTraversalProvider(self.root, self.pages[0].source, self.pages,
                                         "local", self.policy, clock=lambda: NOW, **kwargs)

    def Job(self, provider: LocalWebTraversalProvider, *, timeout_seconds: float = 60,
            max_events: int = 4096) -> ScanJob:
        """Bind the traversal to its actual matching single-loop ScanJob and evidence store."""

        return ScanJob(JobSpec("job:traversal", "synthetic", "scope:local", "owner:test",
            PAGE_CAPTURE_PROVIDER_ID, timeout_seconds), provider,
            evidence_store=LocalEvidenceStore(self.root / "evidence"), max_events=max_events)


def Run(job: ScanJob):
    """Start and await the actual owner terminal state after every child has been drained."""

    async def StartAndWait():
        """Own the asynchronous lifecycle through the ordinary job interface."""

        job.Start()

        return await job.Wait()

    return asyncio.run(StartAndWait())
