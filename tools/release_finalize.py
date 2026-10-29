# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Create one explicitly dispatched annotated 0.3.0 tag after exact current-master acceptance."""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
from pathlib import Path

try:
    from tools import release_delivery as delivery

except ModuleNotFoundError:
    import release_delivery as delivery

RELEASE_VERSION = "0.3.0"
RELEASE_TAG = "v0.3.0"
OWNED_ORIGINS = frozenset({"https://github.com/Fuzzy-Technologies/1337",
                           "https://github.com/Fuzzy-Technologies/1337.git"})


def DispatchContext(event: str, repository: str, reference: str,
                    version: str, attempt: str) -> None:
    """Refuse foreign, branch/tag-confused or retried finalizer dispatches before source work.

    Args:
        event: Actual GitHub event, never derived from a caller URL.
        repository: Actual workflow repository identity.
        reference: Actual selected workflow ref.
        version: Fixed manual version selection.
        attempt: Original workflow run attempt; retries are not automatic release recovery.
    """

    if (event, repository, reference, version, attempt) != (
        "workflow_dispatch", delivery.REPOSITORY, "refs/heads/master", RELEASE_VERSION, "1"
    ):
        raise ValueError("Finalization requires the original fixed master workflow dispatch")


def RemoteRefs(root: Path) -> dict[str, str]:
    """Observe only current owned-origin master and the exact release tag, without changing refs.

    Args:
        root: Reviewed checkout whose expanded fetch/push URLs were already verified.
    Returns:
        At most two exact original remote ref identities; no guessed absence on transport failure.
    """

    raw = delivery.Git(root, "ls-remote", "--refs", "origin", "refs/heads/master",
                       "refs/tags/" + RELEASE_TAG)
    references = {}

    if len(raw) > 4096:
        raise ValueError("Finalization remote reference response exceeds its finite bound")

    for line in raw.splitlines():
        parts = line.split("\t")

        if len(parts) != 2 or delivery.COMMIT.fullmatch(parts[0]) is None or parts[1] not in {
            "refs/heads/master", "refs/tags/" + RELEASE_TAG
        } or parts[1] in references:
            raise ValueError("Finalization remote references are ambiguous or outside the release")

        references[parts[1]] = parts[0]

    return references


def Preflight(root: Path, expected_master_sha: str, *, tagged: bool = False) -> dict:
    """Require exact clean current master, owned origin and matching finite release metadata.

    Args:
        root: Explicit master checkout, not a guessed parent repository.
        expected_master_sha: Operator-selected exact reviewed current master commit.
        tagged: Verify the just-created local annotated tag before push; remote tags still refuse.
    Returns:
        Descriptive exact source and package facts, without issuing publication authority.
    """

    root = root.resolve(strict=True)

    if delivery.COMMIT.fullmatch(expected_master_sha) is None:
        raise ValueError("Finalization requires the exact full expected master SHA")

    if Path(delivery.Git(root, "rev-parse", "--show-toplevel")).resolve() != root or (
        delivery.Git(root, "symbolic-ref", "--short", "HEAD") != "master"
        or delivery.Git(root, "rev-parse", "HEAD") != expected_master_sha
        or delivery.Git(root, "rev-parse", "refs/remotes/origin/master") != expected_master_sha
        or delivery.Git(root, "status", "--porcelain")
    ):
        raise ValueError("Finalization requires an exact clean current master checkout")

    for direction in ((), ("--push",)):
        if delivery.Git(root, "remote", "get-url", *direction, "--all", "origin") not in (
            OWNED_ORIGINS
        ):
            raise ValueError("Finalization origin must be the exact owned GitHub repository")

    project = delivery.SourceMetadata(root, RELEASE_VERSION)
    local = delivery.Git(root, "tag", "--list", "--format=%(refname)", RELEASE_TAG)

    if not tagged and local:
        raise ValueError("Finalization refuses every existing local release tag")

    if tagged:
        delivery.SourceFacts(root, RELEASE_TAG, expected_master_sha)

    remote = RemoteRefs(root)

    if remote.get("refs/heads/master") != expected_master_sha or (
        "refs/tags/" + RELEASE_TAG in remote
    ):
        raise ValueError("Finalization current remote master or release tag changed")

    return {"schema_version": 1, "repository": delivery.REPOSITORY, "project": delivery.PROJECT,
        "version": RELEASE_VERSION, "tag": RELEASE_TAG, "commit": expected_master_sha,
        "tree": delivery.Git(root, "rev-parse", "HEAD^{tree}"),
        "requires_python": project["requires-python"]}


def PushTag(root: Path) -> None:
    """Push one new annotated tag with only builtin short-lived job-token authentication.

    Args:
        root: Exact accepted checkout containing the newly created local tag.
    """

    token = os.environ.get("GITHUB_TOKEN")

    if not token:
        raise ValueError("Finalization requires the builtin job token")

    authorization = base64.b64encode(("x-access-token:" + token).encode()).decode()
    environment = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
        "GIT_CONFIG_VALUE_0": "AUTHORIZATION: basic " + authorization}
    result = subprocess.run(["git", "-c", "core.fsmonitor=false", "push", "--porcelain", "origin",
        "refs/tags/" + RELEASE_TAG + ":refs/tags/" + RELEASE_TAG], cwd=root, env=environment,
        capture_output=True, text=True, timeout=30, check=False)
    rows = [line.split("\t") for line in result.stdout.splitlines() if "\t" in line]

    if result.returncode != 0 or len(rows) != 1 or rows[0][0] != "*" or rows[0][1] != (
        "refs/tags/" + RELEASE_TAG + ":refs/tags/" + RELEASE_TAG
    ):
        raise ValueError("Finalization new-tag push was not exclusively acknowledged")


def Finalize(root: Path, expected_master_sha: str) -> dict:
    """Attempt one accepted annotated tag and non-force push without retries or rollback.

    Args:
        root: Exact reviewed clean master checkout.
        expected_master_sha: Explicit current-master commit already selected by the operator.
    Returns:
        Actual tag identity and original named-master acceptance after acknowledged new-tag push.
    """

    if not os.environ.get("GITHUB_TOKEN"):
        raise ValueError("Finalization requires the builtin job token before tag creation")

    source = Preflight(root, expected_master_sha)
    checks = delivery.MasterChecks(expected_master_sha)

    if Preflight(root, expected_master_sha) != source:
        raise ValueError("Finalization source changed after original master acceptance")

    subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "user.name=github-actions[bot]",
        "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "tag", "-a", RELEASE_TAG, expected_master_sha, "-m", "1337 Security Workbench v0.3.0"],
        cwd=root, check=True, capture_output=True, timeout=30)
    Preflight(root, expected_master_sha, tagged=True)
    tag_object = delivery.Git(root, "rev-parse", "refs/tags/" + RELEASE_TAG)
    PushTag(root)
    remote = RemoteRefs(root)

    if remote.get("refs/tags/" + RELEASE_TAG) != tag_object or remote.get(
        "refs/heads/master"
    ) != expected_master_sha:
        raise ValueError("Finalization original remote tag/master acknowledgement differs")

    return {**source, "tag_object": tag_object, "tag_type": "tag", "master_checks": checks}


def Main(arguments: list[str] | None = None) -> int:
    """Run the finite manual finalizer without package upload or workflow dispatch.

    Args:
        arguments: Explicit command-line arguments, or the original process arguments.
    Returns:
        Zero only after the original finalization acknowledgement was written.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--expected-master-sha", required=True)
    parser.add_argument("--version", choices=(RELEASE_VERSION,), required=True)
    parser.add_argument("--output", required=True, type=Path)
    selected = parser.parse_args(arguments)

    try:
        DispatchContext(os.environ.get("GITHUB_EVENT_NAME", ""),
            os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_REF", ""),
            selected.version, os.environ.get("GITHUB_RUN_ATTEMPT", ""))
        result = Finalize(selected.root, selected.expected_master_sha)
        delivery.WriteJson(selected.output, result)

    except (OSError, ValueError, subprocess.SubprocessError):
        print("Release finalization refused; inspect original source and gate evidence.")

        return 1

    print(json.dumps(result, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
