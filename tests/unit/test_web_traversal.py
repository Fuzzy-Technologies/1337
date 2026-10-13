# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic finite traversal input, selection and runtime-owner contract tests."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace

import pytest

from fuzzy1337.adapters.page_capture import KnownBody, KnownSyntheticHtmlBody
from fuzzy1337.jobs import JobFailureCode, JobSpec, JobState, ScanJob
from fuzzy1337.policy import ImpactPolicy
from fuzzy1337.requests import Endpoint, RequestTemplate
from fuzzy1337.web_traversal import (
    LocalWebTraversalProvider,
    OwnedTraversalPage,
    WebTraversalLimits,
)
from tests.contract.web_traversal_fixture import PATHS, Body, Fixture, Run


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
def test_JobOwnershipMismatchNeverStartsAcquisition(tmp_path, field, value):
    """Controller context attribution cannot reuse a different workspace, scope or provider."""

    fixture = Fixture.Create(tmp_path / "workspace")
    provider = fixture.Provider()
    spec = replace(JobSpec("job:foreign", "synthetic", "scope:local", "owner:test",
                           "native.loopback-page"), **{field: value})
    snapshot = Run(ScanJob(spec, provider))
    assert snapshot.state is JobState.FAILED, "Mismatched context was accepted"
    assert snapshot.failure.code is JobFailureCode.AUTHORIZATION, "Ownership denial was hidden"
    assert not provider.CompletedUrls, "Mismatched job fabricated completed pages"
    assert provider.UnselectedCandidates == 0, "Preparation fabricated lexical discovery"


def test_NoImplicitPolicyPermissionFromCatalogOrLoopback(tmp_path):
    """Known safe body bytes and local URLs never create capability execution authority."""

    fixture = Fixture.Create(tmp_path / "workspace")
    provider = LocalWebTraversalProvider(fixture.root, fixture.pages[0].source, fixture.pages,
                                         "local", ImpactPolicy("deny"))
    snapshot = Run(fixture.Job(provider))
    assert snapshot.state is JobState.FAILED, "Catalog selection bypassed current policy"
    assert snapshot.failure.code is JobFailureCode.AUTHORIZATION, "Policy failure was hidden"
    assert not snapshot.artifacts, "Denied policy retained invented acquisition artifacts"
    assert provider.Descriptor.adapter_id == "native.loopback-page", "Authority owner changed"
