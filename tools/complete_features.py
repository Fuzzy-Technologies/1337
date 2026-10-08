# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Complete native GitHub Features only after all native children are completed."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Sequence
from typing import Any
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

PAGE_SIZE = 100
MAX_PAGES = 100
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class NoRedirect(HTTPRedirectHandler):
    """Reject moved resources instead of forwarding repository write authority."""

    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str,
    ) -> None:
        """Decline every redirect; urllib reports the HTTP failure to the caller.

        Args:
            req: Original authenticated request.
            fp: Original response stream.
            code: Redirect status.
            msg: Redirect reason.
            headers: Response headers.
            newurl: Destination which must not receive credentials.
        """

        return None


class GitHubApi:
    """Bound authenticated requests to one explicitly selected GitHub repository."""

    def __init__(self, repository: str, token: str) -> None:
        """Validate the destination and retain credentials only for HTTP requests.

        Args:
            repository: Repository in owner/name form.
            token: Job-scoped token with issue read/write permission.

        Raises:
            ValueError: The repository is invalid or credentials are absent.
        """

        if not REPOSITORY_PATTERN.fullmatch(repository) or any(
            part in {".", ".."} for part in repository.split("/")
        ):
            raise ValueError("Expected a repository in owner/name form.")

        if not token.strip():
            raise ValueError("GH_TOKEN is required.")

        self.repository = repository
        self.base_url = f"https://api.github.com/repos/{repository}"
        self.token = token
        self.opener = build_opener(NoRedirect())

    def Request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        """Send a bounded JSON request without following resource redirects.

        Args:
            method: HTTP method selected by the reconciliation code.
            path: Repository-relative issue endpoint.
            payload: Optional mutation body.

        Returns:
            Decoded JSON response from GitHub.

        Raises:
            RuntimeError: GitHub returns a failed HTTP status.
            ValueError: The response is not valid JSON.
            OSError: The network request fails or times out.
        """

        request = Request(
            self.base_url + path,
            data=None if payload is None else json.dumps(payload).encode("utf-8"),
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2026-03-10",
                "User-Agent": "1337-feature-completion",
            },
        )

        try:
            with self.opener.open(request, timeout=30) as response:
                return json.load(response)

        except HTTPError as error:
            raise RuntimeError(f"GitHub {method} {path} failed (HTTP {error.code}).") from None

    def List(self, path: str) -> list[dict[str, Any]]:
        """Read every page or fail rather than interpreting a partial child list.

        Args:
            path: Repository issue or native sub-issue collection endpoint.

        Returns:
            Complete collection of issue objects.

        Raises:
            ValueError: A response is malformed or the pagination limit is exceeded.
        """

        result: list[dict[str, Any]] = []
        separator = "&" if "?" in path else "?"

        for page in range(1, MAX_PAGES + 1):
            items = self.Request("GET", f"{path}{separator}per_page={PAGE_SIZE}&page={page}")

            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                raise ValueError("GitHub returned an invalid issue collection.")

            result.extend(items)

            if len(items) < PAGE_SIZE:
                return result

        raise ValueError("GitHub issue pagination exceeded the bounded limit.")


def IsLocalIssue(issue: Any, repository: str) -> bool:
    """Reject PRs, malformed issue identities, and native children from other repositories.

    Args:
        issue: Native REST issue object.
        repository: The only repository this job may modify.

    Returns:
        Whether the issue has a valid local REST identity.
    """

    if not isinstance(issue, dict):
        return False

    number = issue.get("number")
    url = issue.get("url")

    return (
        type(number) is int and number > 0 and "pull_request" not in issue
        and isinstance(url, str) and url.lower()
        == f"https://api.github.com/repos/{repository}/issues/{number}".lower()
    )


def IsOpenFeature(issue: Any, repository: str) -> bool:
    """Use native issue Type, never labels or title keywords, to identify a parent Feature.

    Args:
        issue: Native REST issue object.
        repository: Current repository boundary.

    Returns:
        Whether this is an open local Feature eligible for child inspection.
    """

    return (
        IsLocalIssue(issue, repository) and issue.get("state") == "open"
        and isinstance(issue.get("type"), dict) and issue["type"].get("name") == "Feature"
    )


def CompletedChildren(children: list[dict[str, Any]], repository: str) -> tuple[int, ...]:
    """Require a nonempty, unique native child set closed specifically as completed.

    Args:
        children: Full paginated native sub-issue list.
        repository: Current repository boundary.

    Returns:
        Sorted child numbers, or an empty tuple when completion is not established.
    """

    if not children or any(
        not IsLocalIssue(child, repository) or child.get("state") != "closed"
        or child.get("state_reason") != "completed" for child in children
    ):
        return ()

    numbers = tuple(sorted(child["number"] for child in children))

    return numbers if len(set(numbers)) == len(numbers) else ()


def CompleteFeatures(api: GitHubApi) -> list[int]:
    """Reconcile open Features, including ready ancestors and previously completed work.

    Args:
        api: Repository-bounded GitHub client.

    Returns:
        Feature numbers successfully closed in this run.

    Raises:
        ValueError: A GitHub collection is malformed or cannot be fully enumerated.
        RuntimeError: A GitHub request fails; no unverified Feature is closed.
    """

    pending = [issue["number"] for issue in api.List("/issues?state=open")
               if IsOpenFeature(issue, api.repository)]
    completed: list[int] = []

    while pending:
        remaining: list[int] = []

        for number in pending:
            path = f"/issues/{number}"

            if not IsOpenFeature(api.Request("GET", path), api.repository):
                continue

            children = CompletedChildren(api.List(f"{path}/sub_issues"), api.repository)

            if not children:
                remaining.append(number)
                continue

            # Re-read both boundaries before writing: another editor may change the hierarchy.
            if (
                not IsOpenFeature(api.Request("GET", path), api.repository)
                or CompletedChildren(api.List(f"{path}/sub_issues"), api.repository) != children
            ):
                remaining.append(number)
                continue

            references = ", ".join(f"#{child}" for child in children)
            api.Request("POST", f"{path}/comments", {"body": (
                "Feature completion verified against the native sub-issue hierarchy: "
                f"all {len(children)} children ({references}) are closed as `completed`. "
                "Closing this Feature as completed under the owner-requested automation rule."
            )})
            api.Request("PATCH", path, {"state": "closed", "state_reason": "completed"})
            completed.append(number)
            print(f"Completed Feature #{number}: {references}.")

        if len(remaining) == len(pending):
            break

        pending = remaining

    return completed


def Main(argv: Sequence[str] | None = None) -> int:
    """Run trusted post-merge reconciliation using the job-scoped GH_TOKEN.

    Args:
        argv: Optional argument sequence for focused CLI tests.

    Returns:
        Zero after a complete reconciliation, one after a failed verification.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    arguments = parser.parse_args(argv)

    try:
        api = GitHubApi(arguments.repository, os.environ.get("GH_TOKEN", ""))
        completed = CompleteFeatures(api)
        print(f"Feature reconciliation finished: {len(completed)} completed.")

        return 0

    except (OSError, RuntimeError, ValueError) as error:
        print(f"Feature reconciliation failed: {error}", file=sys.stderr)

        return 1


if __name__ == "__main__":
    raise SystemExit(Main())
