# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Prove native hierarchy completion and bounded GitHub writes without a live token."""

import copy
import io
import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request

import pytest

from tools import complete_features
from tools.complete_features import (
    CompletedChildren,
    CompleteFeatures,
    GitHubApi,
    IsLocalIssue,
    IsOpenFeature,
    Main,
    NoRedirect,
)

REPOSITORY = "Fuzzy-Technologies/1337"


def Issue(
    number: int, issue_type: str = "Task", state: str = "closed", reason: str | None = "completed",
) -> dict[str, Any]:
    """Create one native REST issue fixture with an explicit repository identity."""

    return {
        "number": number, "type": {"name": issue_type}, "state": state, "state_reason": reason,
        "url": f"https://api.github.com/repos/{REPOSITORY}/issues/{number}",
    }


class MemoryApi(GitHubApi):
    """Model issue state and native child membership while recording every mutation."""

    def __init__(self, issues: list[dict[str, Any]], children: dict[int, list[int]]) -> None:
        """Keep an isolated issue store and hierarchy for one reconciliation."""

        self.repository = REPOSITORY
        self.issues = {issue["number"]: copy.deepcopy(issue) for issue in issues}
        self.children = copy.deepcopy(children)
        self.writes: list[tuple[str, str, dict[str, Any] | None]] = []

    def List(self, path: str) -> list[dict[str, Any]]:
        """Return snapshots rather than mutable references to the live fake state."""

        if path == "/issues?state=open":
            return copy.deepcopy([issue for issue in self.issues.values()
                                  if issue["state"] == "open"])

        number = int(path.split("/")[2])

        return copy.deepcopy([self.issues[child] for child in self.children.get(number, [])])

    def Request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        """Apply mutations and make their ordering observable to the test."""

        number = int(path.split("/")[2])

        if method == "GET":
            return copy.deepcopy(self.issues[number])

        self.writes.append((method, path, payload))

        if method == "PATCH":
            assert payload is not None, "The fake received a mutation without a body"
            self.issues[number].update(payload)

        return {}


def test_CompletedChildrenCloseParentWithEvidenceAndRepeatSafely() -> None:
    """Catch up an already-ready Feature and avoid repeated comments or closure."""

    api = MemoryApi([Issue(13, "Feature", "open", None), Issue(20), Issue(21), Issue(22)],
                    {13: [22, 20, 21]})

    assert CompleteFeatures(api) == [13], "The ready Feature was not reconciled"
    assert [method for method, _, _ in api.writes] == ["POST", "PATCH"], (
        "Evidence must precede closure"
    )
    assert api.writes[0][1] == "/issues/13/comments", "Evidence was attached to the wrong issue"
    assert api.writes[0][2] is not None, "The evidence comment has no body"
    assert "#20, #21, #22" in api.writes[0][2]["body"], "The comment omitted verified children"
    assert api.writes[1][2] == {"state": "closed", "state_reason": "completed"}, (
        "Feature closure must retain the completed state reason"
    )
    assert CompleteFeatures(api) == [], "A closed Feature was processed again"
    assert len(api.writes) == 2, "Repeated reconciliation duplicated writes"


@pytest.mark.parametrize("state, reason", [
    ("open", None), ("closed", "not_planned"), ("closed", "duplicate"), ("closed", None),
])
def test_UncompletedChildKeepsFeatureOpen(state: str, reason: str | None) -> None:
    """An incomplete or cancelled Task is not evidence of Feature completion."""

    api = MemoryApi([Issue(29, "Feature", "open", None), Issue(35),
                     Issue(36, state=state, reason=reason)], {29: [35, 36]})

    assert CompleteFeatures(api) == [], "An incomplete or cancelled child allowed closure"
    assert api.writes == [], "An unready Feature received mutations"


def test_EmptyFeatureAndTitleOrLabelImitationsStayOpen() -> None:
    """Only native Type and a nonempty native hierarchy authorize Feature closure."""

    impostor = Issue(14, "Task", "open", None)
    impostor.update({"title": "Feature: looks complete", "labels": [{"name": "feature"}]})
    api = MemoryApi([Issue(13, "Feature", "open", None), impostor, Issue(20)], {14: [20]})

    assert CompleteFeatures(api) == [], "An empty or label-only Feature allowed closure"
    assert api.writes == [], "A Feature imitation received mutations"


def test_ReadyAncestorsCloseAfterTheirNestedFeatures() -> None:
    """Reconcile a parent listed before its child Feature without requiring another merge."""

    api = MemoryApi([Issue(1, "Feature", "open", None), Issue(2, "Feature", "open", None),
                     Issue(3)], {1: [2], 2: [3]})

    assert CompleteFeatures(api) == [2, 1], "The ready ancestor was not reconciled in the same run"


@pytest.mark.parametrize("change", ["reopen", "add_child", "close_parent", "change_type"])
def test_ConcurrentHierarchyOrParentChangesPreventClosure(
    change: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Re-read both the native parent and children before any write."""

    api = MemoryApi([Issue(13, "Feature", "open", None), Issue(20), Issue(21)], {13: [20]})
    original = api.Request
    reads = 0

    def RequestWithEdit(method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        """Simulate an editor changing the verified state between read snapshots."""

        nonlocal reads
        reads += method == "GET"

        if reads == 2:
            if change == "reopen":
                api.issues[20]["state"] = "open"

            elif change == "add_child":
                api.children[13].append(21)

            elif change == "close_parent":
                api.issues[13]["state"] = "closed"

            else:
                api.issues[13]["type"] = {"name": "Task"}

        return original(method, path, payload)

    monkeypatch.setattr(api, "Request", RequestWithEdit)

    assert CompleteFeatures(api) == [], "A changed hierarchy allowed stale closure"
    assert api.writes == [], "Concurrent edits were ignored before mutation"


@pytest.mark.parametrize("issue", [
    None, {}, Issue(-1), {**Issue(1), "number": True},
    {**Issue(1), "url": "https://api.github.com/repos/elsewhere/project/issues/1"},
    {**Issue(1), "pull_request": {}}, {**Issue(1), "url": None},
])
def test_ForeignPrAndMalformedIdentitiesAreRejected(issue: Any) -> None:
    """Native relationships never authorize writes to another repository or a PR."""

    assert not IsLocalIssue(issue, REPOSITORY), "An invalid identity passed the repository boundary"
    assert not IsOpenFeature(issue, REPOSITORY), "An invalid identity was considered a Feature"
    assert CompletedChildren([issue], REPOSITORY) == (), "An invalid child established completion"


def test_DuplicateChildrenAndMissingNativeTypeAreRejected() -> None:
    """Fail closed on duplicate membership and untyped Feature-like records."""

    assert CompletedChildren([Issue(20), Issue(20)], REPOSITORY) == (), "Duplicate children passed"
    assert not IsOpenFeature({**Issue(13, "Feature", "open"), "type": None}, REPOSITORY), (
        "A missing native Type was inferred from other fields"
    )
    assert CompletedChildren([Issue(20), Issue(21)], REPOSITORY) == (20, 21), (
        "A valid completed child set was rejected"
    )


def test_ParentClosedBeforeFirstReadIsSkipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Do not mutate a Feature another actor already completed after the initial listing."""

    api = MemoryApi([Issue(13, "Feature", "open", None), Issue(20)], {13: [20]})
    monkeypatch.setattr(api, "Request", lambda *args: Issue(13, "Feature"))

    assert CompleteFeatures(api) == [], "An externally closed Feature was processed"
    assert api.writes == [], "The job overwrote another actor's Feature closure"


def test_PaginationReadsPastFullPagesBeforeDeciding(monkeypatch: pytest.MonkeyPatch) -> None:
    """An incomplete child on a later page must remain visible to the completion rule."""

    api = GitHubApi(REPOSITORY, "test-token")
    pages = [[Issue(number) for number in range(1, 101)], [Issue(101, state="open", reason=None)]]
    calls = []

    def ReadPage(method: str, path: str) -> Any:
        """Supply a complete first page and an incomplete child on the second page."""

        calls.append((method, path))

        return pages.pop(0)

    monkeypatch.setattr(api, "Request", ReadPage)
    children = api.List("/issues/13/sub_issues")

    assert len(children) == 101, "Native child pagination discarded the second page"
    assert CompletedChildren(children, REPOSITORY) == (), "A later open child was ignored"
    assert calls[-1][1].endswith("?per_page=100&page=2"), "Pagination did not advance"
    pages.append([])

    assert api.List("/issues?state=open") == [], "An empty collection was not retained"
    assert calls[-1][1] == "/issues?state=open&per_page=100&page=1", "Query parameters were lost"


@pytest.mark.parametrize("response", [{}, [None], "not a collection"])
def test_InvalidCollectionsFailClosed(response: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Malformed native collection responses are errors, not empty complete child sets."""

    api = GitHubApi(REPOSITORY, "test-token")
    monkeypatch.setattr(api, "Request", lambda *args: response)

    with pytest.raises(ValueError, match="invalid issue collection"):
        api.List("/issues?state=open")


def test_PaginationLimitFailsClosed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A bounded pagination limit must never produce partial completion evidence."""

    api = GitHubApi(REPOSITORY, "test-token")
    monkeypatch.setattr(complete_features, "MAX_PAGES", 1)
    monkeypatch.setattr(api, "Request", lambda *args: [Issue(20)] * 100)

    with pytest.raises(ValueError, match="pagination"):
        api.List("/issues?state=open")


def test_RequestBoundsAuthenticationTimeoutAndMutationBody(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constrain the token to the chosen API destination and a bounded network call."""

    api = GitHubApi(REPOSITORY, "test-token")
    calls = []

    def Open(request: Request, timeout: int) -> io.BytesIO:
        """Capture the request without accessing any external service."""

        calls.append((request, timeout))

        return io.BytesIO(b'{"state":"closed"}')

    monkeypatch.setattr(api.opener, "open", Open)
    assert api.Request("PATCH", "/issues/13", {"state": "closed"}) == {"state": "closed"}, (
        "The response JSON was not decoded"
    )
    request, timeout = calls[0]
    assert request.full_url == f"https://api.github.com/repos/{REPOSITORY}/issues/13", (
        "The request escaped the selected repository"
    )
    assert request.get_header("Authorization") == "Bearer test-token", "Job authentication was lost"
    assert timeout == 30 and request.data is not None, "The bounded mutation contract changed"
    assert json.loads(request.data) == {"state": "closed"}, "The mutation body was corrupted"
    assert NoRedirect().redirect_request(
        request, None, 301, "Moved", {}, "https://elsewhere",
    ) is None, "Redirects must not forward repository authentication"


def test_HttpFailureStopsWritesAndKeepsCredentialOutOfDiagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An API error is surfaced without exposing response bodies or authentication."""

    api = GitHubApi(REPOSITORY, "test-token")

    def Fail(request: Request, timeout: int) -> None:
        """Simulate an API rejection whose response contains private information."""

        raise HTTPError(request.full_url, 403, "test-token", {}, None)

    monkeypatch.setattr(api.opener, "open", Fail)

    with pytest.raises(RuntimeError, match="HTTP 403") as error:
        CompleteFeatures(api)

    assert "test-token" not in str(error.value), "Private HTTP diagnostics leaked into the error"


def test_FailedEvidenceCommentPreventsFeatureClosure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A Feature is not closed if its acceptance-state comment could not be recorded."""

    api = MemoryApi([Issue(13, "Feature", "open", None), Issue(20)], {13: [20]})
    original = api.Request

    def RejectComment(method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        """Reject only the first write after successful hierarchy verification."""

        if method == "POST":
            raise RuntimeError("Comment rejected")

        return original(method, path, payload)

    monkeypatch.setattr(api, "Request", RejectComment)

    with pytest.raises(RuntimeError, match="Comment rejected"):
        CompleteFeatures(api)

    assert api.issues[13]["state"] == "open" and not api.writes, "Closure bypassed missing evidence"


@pytest.mark.parametrize("repository", ["owner", "../repo", "owner/..", "a/b/c", "a/b?x=1"])
def test_InvalidRepositoryCannotReceiveToken(repository: str) -> None:
    """Reject destination strings that could escape the explicit repository scope."""

    with pytest.raises(ValueError, match="owner/name"):
        GitHubApi(repository, "test-token")


def test_CliRequiresTokenAndReportsVerifiedOutcome(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Missing credentials fail, while a successful bounded reconciliation returns zero."""

    monkeypatch.delenv("GH_TOKEN", raising=False)
    assert Main(["--repository", REPOSITORY]) == 1, "Missing credentials did not fail the CLI"
    assert "GH_TOKEN is required" in capsys.readouterr().err, "The credential diagnostic was lost"
    monkeypatch.setenv("GH_TOKEN", "test-token")
    monkeypatch.setattr(complete_features, "CompleteFeatures", lambda api: [13])

    assert Main(["--repository", REPOSITORY]) == 0, "A verified run did not return success"
    assert "1 completed" in capsys.readouterr().out, "The CLI lost its completion summary"


def test_PostMergeWorkflowChainsTrustedReconciliationWithoutCancellingTaskClosures() -> None:
    """Keep the write-enabled job on trusted develop and after native Task closure."""

    root = Path(__file__).resolve().parents[2]
    workflow = (root / ".github/workflows/close-merged-tasks.yml").read_text(encoding="utf-8")
    task_job, feature_job = workflow.split("  complete-parent-features:", 1)

    assert 'issue.type?.name !== "Task"' in task_job, "PR references can bypass Feature checks"
    assert "concurrency:" not in task_job, "Coalescing can drop a Task-closing event"
    assert "needs: close-linked-tasks" in feature_job, "Features can run before Task closure"
    assert "ref: develop" in feature_job, "The write-enabled job no longer uses trusted source"
    assert "cancel-in-progress: false" in feature_job, "Feature writes can be interrupted"
    assert "persist-credentials: false" in feature_job, "Checkout persisted repository credentials"
    assert "github.event.pull_request.head" not in feature_job, "Unmerged code obtained authority"
