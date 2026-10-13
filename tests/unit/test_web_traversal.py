# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic finite traversal input, selection and runtime-owner contract tests."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import socket
from collections.abc import Iterator
from dataclasses import replace

import pytest

from fuzzy1337.adapters.page_capture import KnownBody, KnownSyntheticHtmlBody
from fuzzy1337.jobs import JobFailureCode, JobSnapshot, JobSpec, JobState, ScanJob
from fuzzy1337.policy import ImpactPolicy
from fuzzy1337.requests import Endpoint, RequestTemplate
from fuzzy1337.web_traversal import (
    LocalWebTraversalProvider,
    OwnedTraversalPage,
    WebTraversalLimits,
)
from tests.contract.web_traversal_fixture import PATHS, Body, Fixture


@pytest.fixture(scope="module")
def owned_traversal_runner() -> Iterator[asyncio.Runner]:
    """Initialize the owned Windows self-pipe before the function-scoped network guard."""

    with asyncio.Runner() as runner:
        runner.get_loop()
        yield runner


@pytest.fixture
def traversal_runner(owned_traversal_runner: asyncio.Runner) -> Iterator[asyncio.Runner]:
    """Reuse the initialized loop and drain remaining tasks at every isolated test boundary."""

    yield owned_traversal_runner

    async def Cleanup() -> None:
        """Cancel and await every remaining test-owned task without reopening an event loop."""

        pending = asyncio.all_tasks() - {asyncio.current_task()}

        for task in pending:
            task.cancel()

        await asyncio.gather(*pending, return_exceptions=True)

    owned_traversal_runner.run(Cleanup())


def RunJob(job: ScanJob, runner: asyncio.Runner) -> JobSnapshot:
    """Exercise the actual owning job lifecycle on the preinitialized guarded loop."""

    async def StartAndWait() -> JobSnapshot:
        """Start and await the actual terminal job without constructing another loop."""

        job.Start()

        return await job.Wait()

    return runner.run(StartAndWait())


def test_TraversalRunnerPreservesNetworkDenial(traversal_runner, monkeypatch):
    """Preinitialized loop reuse never permits provider connections or guarded loop recreation."""

    def ReopenLoop():
        """Reject accidental lazy self-pipe construction inside the guarded test phase."""

        raise AssertionError("Guarded traversal tests must reuse their initialized event loop")

    monkeypatch.setattr(asyncio.events, "new_event_loop", ReopenLoop)

    async def CheckConnections():
        """Prove that every unchanged unit connection tripwire remains active on the owned loop."""

        with socket.socket() as connection:
            for callback in (connection.connect, connection.connect_ex, socket.create_connection):
                with pytest.raises(RuntimeError, match="Unit tests must not access the network"):
                    callback(("127.0.0.1", 9))

    traversal_runner.run(CheckConnections())


@pytest.mark.parametrize("path", PATHS)
def test_ReviewedTraversalCatalogMatchesIndependentExactBytes(path):
    """Each selected catalog ID is bound to the handwritten owned body's exact SHA and size."""

    body = Body(path)
    selected = KnownSyntheticHtmlBody("owned-traversal-" + path[1:] + ".v1")
    assert selected.size_bytes == len(body), "Reviewed traversal body size changed"
    assert selected.sha256 == hashlib.sha256(body).hexdigest(), "Reviewed body digest changed"
    assert KnownBody(selected) is selected, "Validated catalog selection was replaced"


@pytest.mark.parametrize("field,value", [
    ("max_pages", 0), ("max_pages", 17), ("max_pages", True),
    ("max_depth", -1), ("max_depth", 5), ("max_depth", True),
    ("concurrency", 0), ("concurrency", 5), ("concurrency", 1.0),
    ("max_total_body_bytes", 0), ("max_total_body_bytes", 1048577),
    ("start_interval_seconds", 0), ("start_interval_seconds", 1.01),
    ("start_interval_seconds", True), ("start_interval_seconds", float("nan")),
    ("timeout_seconds", 0), ("timeout_seconds", 61), ("timeout_seconds", float("inf")),
])
def test_TraversalBudgetsRejectCoercionOrExpansion(field, value):
    """Closed runtime quotas reject invalid and nonfinite values before any owner work."""

    with pytest.raises(ValueError):
        WebTraversalLimits(**{field: value})


@pytest.mark.parametrize("selection", ["list", "empty", "too-many", "object", "duplicate",
                                       "foreign-origin", "missing-seed", "changed-seed"])
def test_ExplicitPageSelectionRefusesAmbiguousOrExpandedInputs(tmp_path, selection):
    """An explicit finite same-origin seed/catalog binding is required before acquisition."""

    fixture = Fixture.Create(tmp_path / "workspace")
    pages = fixture.pages
    source = pages[0].source

    if selection == "list":
        pages = list(pages)

    elif selection == "empty":
        pages = ()

    elif selection == "too-many":
        pages = pages * 5

    elif selection == "object":
        pages = (object(),)

    elif selection == "duplicate":
        pages = (pages[0], pages[0])

    elif selection == "foreign-origin":
        pages = (pages[0], OwnedTraversalPage(RequestTemplate(Endpoint("synthetic",
            "http://127.0.0.1:32124", "/alpha")), pages[1].expected_body))

    elif selection == "missing-seed":
        pages = pages[1:]

    else:
        source = replace(source, endpoint=replace(source.endpoint, workspace_id="different"))

    with pytest.raises(ValueError):
        LocalWebTraversalProvider(fixture.root, source, pages, "local", fixture.policy)

    assert not tuple((fixture.root / "evidence").rglob("*.json")), (
        "Refused selection wrote acquisition records"
    )


@pytest.mark.parametrize("field,value", [("max_pages", True), ("timeout_seconds", float("nan"))])
def test_CopiedLimitsCannotBypassNestedValidation(tmp_path, field, value):
    """Frozen-wrapper copies do not substitute malformed profile limits."""

    fixture = Fixture.Create(tmp_path / "workspace")
    limits = copy.copy(WebTraversalLimits())
    object.__setattr__(limits, field, value)

    with pytest.raises(ValueError):
        fixture.Provider(limits=limits)


@pytest.mark.parametrize("field,value", [("sha256", "0" * 64), ("size_bytes", True)])
def test_CopiedPageCatalogCannotApproveOtherBodyBytes(tmp_path, field, value):
    """A selected URL still requires exact original finite-catalog derived fields."""

    fixture = Fixture.Create(tmp_path / "workspace")
    body = copy.copy(fixture.pages[0].expected_body)
    object.__setattr__(body, field, value)
    page = copy.copy(fixture.pages[0])
    object.__setattr__(page, "expected_body", body)

    with pytest.raises(ValueError):
        LocalWebTraversalProvider(fixture.root, page.source, (page,), "local", fixture.policy)


@pytest.mark.parametrize("field,value", [("workspace_id", "foreign"),
                                         ("scope_reference", "scope:foreign"),
                                         ("provider_id", "native.http")])
def test_JobOwnershipMismatchNeverStartsAcquisition(tmp_path, field, value, traversal_runner):
    """Controller context attribution cannot reuse a different workspace, scope or provider."""

    fixture = Fixture.Create(tmp_path / "workspace")
    provider = fixture.Provider()
    spec = replace(JobSpec("job:foreign", "synthetic", "scope:local", "owner:test",
                           "native.loopback-page"), **{field: value})
    snapshot = RunJob(ScanJob(spec, provider), traversal_runner)
    assert snapshot.state is JobState.FAILED, "Mismatched context was accepted"
    assert snapshot.failure.code is JobFailureCode.AUTHORIZATION, "Ownership denial was hidden"
    assert not provider.CompletedUrls, "Mismatched job fabricated completed pages"
    assert provider.UnselectedCandidates == 0, "Preparation fabricated lexical discovery"


def test_NoImplicitPolicyPermissionFromCatalogOrLoopback(tmp_path, traversal_runner):
    """Known safe body bytes and local URLs never create capability execution authority."""

    fixture = Fixture.Create(tmp_path / "workspace")
    provider = LocalWebTraversalProvider(fixture.root, fixture.pages[0].source, fixture.pages,
                                         "local", ImpactPolicy("deny"))
    snapshot = RunJob(fixture.Job(provider), traversal_runner)
    assert snapshot.state is JobState.FAILED, "Catalog selection bypassed current policy"
    assert snapshot.failure.code is JobFailureCode.AUTHORIZATION, "Policy failure was hidden"
    assert not snapshot.artifacts, "Denied policy retained invented acquisition artifacts"
    assert provider.Descriptor.adapter_id == "native.loopback-page", "Authority owner changed"
