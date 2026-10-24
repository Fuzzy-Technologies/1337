# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic crawl authority and reservation boundary checks without transport."""

from dataclasses import replace

import pytest

from fuzzy1337.native_crawl import (
    CurrentCrawlAuthority,
    NativeCrawlAuthority,
    NativeCrawlAuthorityDeniedError,
    NativeCrawlLimits,
)
from fuzzy1337.policy import ImpactPolicy
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

URLS = ("http://127.0.0.1:32123/index", "http://127.0.0.1:32123/leaf")


@pytest.fixture
def selection(tmp_path):
    """Create real canonical owners with independent consent attestation and actor metadata."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned content crawl"), "crawl")
    urls = tuple(Target(TargetKind.URL, value) for value in URLS)
    targets = (*urls, Target(TargetKind.IP, "127.0.0.1"))
    LocalScopeStore(root).Create(ScopeSnapshot("local", "crawl", ScopeAuthorization(
        AuthorizationState.GRANTED, "attester:independent", "consent:owned-crawl"),
        targets=targets, allow=targets))

    return root, urls


def Authority(selection, **kwargs):
    """Read the actual fresh helper using explicit original actor attribution."""

    root, urls = selection

    return CurrentCrawlAuthority(root, "local", urls[0], urls, "actor:operator",
        lambda: ImpactPolicy("local"), False, **kwargs)


def test_CurrentReaderKeepsAttesterIndependentAndRereadsTrustedActor(selection):
    """Two boundaries consult the trusted callback afresh without attester substitution."""

    calls = []

    def Actor():
        """Return selected actor attribution without claiming external authentication."""

        calls.append(True)

        return "actor:operator"

    first = Authority(selection, current_owner_provider=Actor)
    second = Authority(selection, current_owner_provider=Actor)
    assert first == second and len(calls) == 2, "Every authority boundary must refresh attribution."
    assert first.owner_reference != first.context.scope.authorization.authority_reference, (
        "The independent consent attester must never replace the executing actor."
    )
    assert first.workflow_approved is False, "A descriptive reader cannot manufacture approval."


@pytest.mark.parametrize("value", (None, 1, True, "actor:changed"))
def test_InvalidOrChangedTrustedActorRefusesWithoutEcho(selection, value):
    """Current actor mismatch is a fixed denial rather than normalized or echoed attribution."""

    with pytest.raises(NativeCrawlAuthorityDeniedError, match="attribution changed"):
        Authority(selection, current_owner_provider=lambda: value)


def test_TrustedActorReaderFailureIsSanitized(selection):
    """Callback failures deny without exposing their original values or text."""

    def Broken():
        """Model a trusted external attribution source becoming unavailable."""

        raise RuntimeError("private-attribution-marker")

    with pytest.raises(NativeCrawlAuthorityDeniedError, match="attribution unavailable") as error:
        Authority(selection, current_owner_provider=Broken)

    assert "private" not in str(error.value), (
        "Reader failure text must remain outside product data."
    )


@pytest.mark.parametrize("field,value", (
    ("max_pages", True), ("max_pages", 17), ("max_depth", 5), ("concurrency", 0),
    ("concurrency", 5), ("max_total_body_bytes", 1048577),
    ("start_interval_seconds", 0.01), ("timeout_seconds", float("inf")),
    ("max_body_bytes", 65537), ("request_timeout_ms", 49), ("request_timeout_ms", 5001),
))
def test_LimitsRejectCoercionsAndUnboundedAdmission(field, value):
    """No reservation or timing bound may silently widen beyond the reviewed profile."""

    with pytest.raises(ValueError):
        replace(NativeCrawlLimits(), **{field: value})


def test_ApprovalWrapperRequiresExactBoolean(selection):
    """Truthiness is insufficient to select the independent SAFE workflow opt-in."""

    authority = Authority(selection)

    with pytest.raises(ValueError, match="exact authority"):
        NativeCrawlAuthority(authority.context, authority.owner_reference, 1)


@pytest.mark.parametrize("mode", ("duplicate", "unsorted", "source-absent", "off-origin"))
def test_CompleteSelectionCannotChangeShapeBeforeCurrentAuthority(selection, mode):
    """Current source context retains the finite complete sorted same-origin selection."""

    root, urls = selection
    selected = {"duplicate": (urls[0], urls[0]), "unsorted": tuple(reversed(urls)),
        "source-absent": (urls[1],), "off-origin": (
            urls[0], Target(TargetKind.URL, "http://127.0.0.1:32124/leaf"))}[mode]

    with pytest.raises(ValueError):
        CurrentCrawlAuthority(root, "local", urls[0], selected, "actor:operator",
            lambda: ImpactPolicy("local"), False)
