# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Recover one original 0.3.0 publication without rebuilding or moving its product tag."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path

try:
    from tools import release_delivery as delivery

except ModuleNotFoundError:
    import release_delivery as delivery

VERSION = "0.3.0"
PRODUCT_TAG = "v0.3.0"
PRODUCT_COMMIT = "04a2ea7f83fa57cda887e916df02daea8eb7313a"
PRODUCT_TREE = "c68d7271cde0a2f7c5a8579af8b9c2d9dda21a5d"
PRODUCT_TAG_OBJECT = "955aa1f5d85e2ca7a8d04e316d5b4f178b7bffa7"
RECOVERY_BRANCH = "fix/release-publication-recovery"
RECOVERY_TAG = "v-publish-recovery-0.3.0-1"
RECOVERY_PR = 388
PRODUCER_RUN = 40950150194
PRODUCER_ATTEMPT = 1
PRODUCER_ARTIFACT = 12931865374
PRODUCER_DIGEST = "sha256:f30831d5bf9b6fb8f1adf46673e3a4b33060de8bff44299688e645bdd6aef8f3"
CHECKSUMS_SHA256 = "5ba67d64eb1a528491edf20a8a0655991656a78683d329f10483d88bdeb51edf"
WHEEL_SHA256 = "39009b6988a8fa16bc9d29f9b509a1e3c211c1551c6862d456597983d6471bea"
BUILD_JOB = 123715882133
PUBLISH_JOB = 123716173988
OWNED_ORIGINS = frozenset({"https://github.com/Fuzzy-Technologies/1337",
                           "https://github.com/Fuzzy-Technologies/1337.git"})
INDEX_URL = "https://pypi.org/pypi/1337/0.3.0/json"


def IndexAbsent() -> dict:
    """Accept only an original exact-version 404 from the fixed public PyPI endpoint.

    Returns:
        A bounded absence observation, without inferring project ownership or name reservation.
    """

    request = urllib.request.Request(INDEX_URL, headers={"Accept": "application/json"})

    try:
        with urllib.request.build_opener(delivery.NoRedirect()).open(request, timeout=20):
            raise ValueError("Recovery refuses an existing version or unknown index response")

    except urllib.error.HTTPError as error:
        try:
            if error.code != 404 or error.geturl() != INDEX_URL:
                raise ValueError("Recovery requires an exact original version 404") from error

        finally:
            error.close()

    return {"url": INDEX_URL, "version": VERSION, "http_status": 404,
            "observation": "exact-version-absent"}


def DispatchContext(expected_sha: str, *, operational: bool) -> None:
    """Require the original manual dispatch of the exact reviewed branch or operational tag.

    Args:
        expected_sha: Immutable reviewed recovery-code commit selected by the operator.
        operational: True only for the separately reviewed publisher continuation.
    """

    reference = "refs/tags/" + RECOVERY_TAG if operational else "refs/heads/" + RECOVERY_BRANCH
    filename = "release.yml" if operational else "release-finalize.yml"
    expected_workflow = delivery.REPOSITORY + "/.github/workflows/" + filename + "@" + reference

    if delivery.COMMIT.fullmatch(expected_sha) is None or (
        os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or os.environ.get("GITHUB_REPOSITORY") != delivery.REPOSITORY
        or os.environ.get("GITHUB_REF") != reference
        or os.environ.get("GITHUB_RUN_ATTEMPT") != "1"
        or os.environ.get("GITHUB_SHA") != expected_sha
        or os.environ.get("GITHUB_WORKFLOW_SHA") != expected_sha
        or os.environ.get("GITHUB_WORKFLOW_REF") != expected_workflow
    ):
        raise ValueError("Recovery needs the original exact reviewed workflow dispatch")


def OwnedCheckout(root: Path) -> Path:
    """Verify one explicitly selected clean repository with its exact owned fetch/push origin.

    Args:
        root: Physical checkout selected by the reviewed workflow.
    Returns:
        Its resolved repository root after actual read-only Git validation.
    """

    root = root.resolve(strict=True)

    if Path(delivery.Git(root, "rev-parse", "--show-toplevel")).resolve() != root or (
        delivery.Git(root, "status", "--porcelain")
    ):
        raise ValueError("Recovery needs a clean exact repository checkout")

    for direction in ((), ("--push",)):
        if delivery.Git(root, "remote", "get-url", *direction, "--all", "origin") not in (
            OWNED_ORIGINS
        ):
            raise ValueError("Recovery origin must be the exact owned repository")

    return root


def ProductFacts(product_root: Path) -> dict:
    """Retain the unchanged original strict current-master product-source contract.

    Args:
        product_root: Clean checkout of the existing original annotated product tag.
    Returns:
        Original source facts only after tag object, commit and tree match their fixed identities.
    """

    root = OwnedCheckout(product_root)
    source = delivery.SourceFacts(root, PRODUCT_TAG, PRODUCT_COMMIT)

    if source["commit"] != PRODUCT_COMMIT or source["tree"] != PRODUCT_TREE or (
        delivery.Git(root, "rev-parse", "refs/tags/" + PRODUCT_TAG) != PRODUCT_TAG_OBJECT
    ):
        raise ValueError("Recovery cannot replace the original product tag or source")

    return source


def CodeFacts(code_root: Path, product_root: Path, expected_sha: str) -> dict:
    """Bind recovery control code separately from the immutable original product source.

    Args:
        code_root: Clean recovery-code checkout; no product artifact is built from it.
        product_root: Independently checked original product checkout.
        expected_sha: Exact reviewed recovery commit.
    Returns:
        Explicitly distinct recovery-code and original-product identities.
    """

    if delivery.COMMIT.fullmatch(expected_sha) is None or expected_sha == PRODUCT_COMMIT:
        raise ValueError("Recovery needs a distinct full reviewed control-code commit")

    root = OwnedCheckout(code_root)

    if delivery.Git(root, "rev-parse", "HEAD") != expected_sha or (
        delivery.Git(root, "rev-parse", "refs/remotes/origin/" + RECOVERY_BRANCH) != expected_sha
        or delivery.Git(root, "rev-parse", "refs/remotes/origin/master") != PRODUCT_COMMIT
        or delivery.Git(root, "rev-parse", "refs/tags/" + PRODUCT_TAG) != PRODUCT_TAG_OBJECT
    ):
        raise ValueError("Recovery code, branch or unchanged original master differs")

    return {"recovery_commit": expected_sha,
        "recovery_tree": delivery.Git(root, "rev-parse", "HEAD^{tree}"),
        "recovery_branch": RECOVERY_BRANCH, "recovery_tag": RECOVERY_TAG,
        "product_source": ProductFacts(product_root)}


def RecoveryChecks(recovery_sha: str, fetch: Callable[[str], dict] = delivery.GitHubJson) -> dict:
    """Require the latest exact-head PR388 readiness jobs and their actual execution steps.

    Args:
        recovery_sha: Reviewed immutable recovery-code commit, never the old product commit.
        fetch: Fixed-repository read-only GitHub API transport.
    Returns:
        All eleven successful workflow attempts and their 23 mandatory PR jobs.
    """

    if delivery.COMMIT.fullmatch(recovery_sha) is None:
        raise ValueError("Recovery checks require a full source commit")

    accepted = []

    for filename, master_required in delivery.MASTER_JOBS.items():
        required = {name: steps for name, steps in master_required.items()
                    if name != "deploy-pages"}
        query = urllib.parse.urlencode({"head_sha": recovery_sha, "event": "pull_request",
                                       "branch": RECOVERY_BRANCH, "per_page": 100})
        value = fetch(f"/repos/{delivery.REPOSITORY}/actions/workflows/{filename}/runs?{query}")
        runs = value["workflow_runs"]

        if not runs or len(runs) > 100 or any(type(r["run_number"]) is not int for r in runs):
            raise ValueError("Recovery readiness workflow evidence is absent or ambiguous")

        run = max(runs, key=lambda item: item["run_number"])
        pulls = run["pull_requests"]

        if (run["event"] != "pull_request" or run["head_branch"] != RECOVERY_BRANCH
            or run["head_sha"] != recovery_sha or run["head_repository"]["full_name"] != (
                delivery.REPOSITORY
            ) or run["path"] != ".github/workflows/" + filename
            or run["status"] != "completed" or run["conclusion"] != "success"
            or type(run["id"]) is not int or run["id"] <= 0
            or type(run["run_attempt"]) is not int or run["run_attempt"] <= 0
            or len(pulls) != 1 or type(pulls[0]["number"]) is not int
            or pulls[0]["number"] != RECOVERY_PR or pulls[0]["head"]["sha"] != recovery_sha):
            raise ValueError("The latest exact recovery PR readiness run has not succeeded")

        jobs = fetch(f"/repos/{delivery.REPOSITORY}/actions/runs/{run['id']}/attempts/"
                     f"{run['run_attempt']}/jobs?per_page=100")

        if type(jobs["total_count"]) is not int or jobs["total_count"] != len(jobs["jobs"]) or (
            len(jobs["jobs"]) > 100
        ):
            raise ValueError("Recovery jobs must be complete within one bounded page")

        for name, expected in required.items():
            matches = [j for j in jobs["jobs"] if j["name"] == name]

            if len(matches) != 1 or matches[0]["status"] != "completed" or (
                matches[0]["conclusion"] != "success"
            ):
                raise ValueError("Recovery required job is absent, skipped or unsuccessful")

            steps = matches[0]["steps"]

            if not any(s["status"] == "completed" and s["conclusion"] == "success"
                       for s in steps):
                raise ValueError("Recovery required actual execution step did not succeed")

            for step_name in expected:
                matches = [s for s in steps if s["name"] == step_name]

                if len(matches) != 1 or matches[0]["status"] != "completed" or (
                    matches[0]["conclusion"] != "success"
                ):
                    raise ValueError("Recovery required actual execution step did not succeed")

        accepted.append({"workflow": filename, "run_id": run["id"],
            "attempt": run["run_attempt"], "jobs": sorted(required),
            "url": f"https://github.com/{delivery.REPOSITORY}/actions/runs/{run['id']}"})

    return {"schema_version": 1, "commit": recovery_sha, "event": "pull_request",
            "branch": RECOVERY_BRANCH, "pull_request": RECOVERY_PR,
            "accepted_workflows": accepted}


def OriginalProducer(fetch: Callable[[str], dict] = delivery.GitHubJson) -> dict:
    """Verify the fixed failed pre-upload run and its original immutable successful build artifact.

    Args:
        fetch: Fixed-repository read-only Actions API transport.
    Returns:
        The original producer identity; no replacement build or artifact selection is admitted.
    """

    prefix = f"/repos/{delivery.REPOSITORY}/actions"
    run = fetch(f"{prefix}/runs/{PRODUCER_RUN}")

    if (run["id"] != PRODUCER_RUN or type(run["run_attempt"]) is not int
        or run["run_attempt"] != PRODUCER_ATTEMPT or run["head_sha"] != PRODUCT_COMMIT
        or run["head_branch"] != PRODUCT_TAG or run["event"] != "workflow_dispatch"
        or run["path"] != ".github/workflows/release.yml"
        or run["head_repository"]["full_name"] != delivery.REPOSITORY
        or run["status"] != "completed" or run["conclusion"] != "failure"):
        raise ValueError("Recovery producer must be the fixed original failed publication run")

    jobs = fetch(f"{prefix}/runs/{PRODUCER_RUN}/attempts/{PRODUCER_ATTEMPT}/jobs?per_page=100")

    if type(jobs["total_count"]) is not int or jobs["total_count"] != len(jobs["jobs"]) or (
        len(jobs["jobs"]) > 100
    ):
        raise ValueError("Original producer job evidence is incomplete")

    required = {
        "Refuse branch publication before source execution": ("success", None),
        "Validate annotated release and build distributions once": ("success", BUILD_JOB),
        "Publish the validated distributions through Trusted Publishing": ("failure", PUBLISH_JOB),
        "Verify the actual clean PyPI installation": ("skipped", None),
        "Publish the existing-tag release card and exact assets": ("skipped", None),
    }

    for name, (conclusion, job_id) in required.items():
        matches = [j for j in jobs["jobs"] if j["name"] == name]

        if len(matches) != 1 or matches[0]["status"] != "completed" or (
            matches[0]["conclusion"] != conclusion
            or job_id is not None and matches[0]["id"] != job_id
        ):
            raise ValueError("Original producer build or failed publication identity differs")

    artifacts = fetch(f"{prefix}/runs/{PRODUCER_RUN}/artifacts?per_page=100")

    if type(artifacts["total_count"]) is not int or artifacts["total_count"] != len(
        artifacts["artifacts"]
    ) or len(artifacts["artifacts"]) > 100:
        raise ValueError("Original artifact evidence is incomplete")

    selected = [a for a in artifacts["artifacts"] if a["id"] == PRODUCER_ARTIFACT]

    if len(selected) != 1:
        raise ValueError("Original publication artifact is unavailable")

    artifact = selected[0]

    if (artifact["name"] != "release-distributions" or artifact["expired"] is not False
        or artifact["digest"] != PRODUCER_DIGEST or type(artifact["size_in_bytes"]) is not int
        or not 0 < artifact["size_in_bytes"] <= 256 * 1024 * 1024
        or artifact["workflow_run"]["id"] != PRODUCER_RUN
        or artifact["workflow_run"]["head_sha"] != PRODUCT_COMMIT):
        raise ValueError("Original artifact source, expiration or digest differs")

    return {"run_id": PRODUCER_RUN, "attempt": PRODUCER_ATTEMPT,
        "artifact_id": PRODUCER_ARTIFACT, "artifact_digest": PRODUCER_DIGEST,
        "checksums_sha256": CHECKSUMS_SHA256, "build_job_id": BUILD_JOB,
        "failed_publisher_job_id": PUBLISH_JOB}


def RemoteRefs(root: Path) -> dict[str, str]:
    """Observe only the original source refs and the fixed recovery refs at the owned origin.

    Args:
        root: Clean owned-origin recovery checkout.
    Returns:
        Original bounded remote identities; transport failure never implies tag absence.
    """

    allowed = {"refs/heads/master", "refs/heads/" + RECOVERY_BRANCH,
               "refs/tags/" + PRODUCT_TAG, "refs/tags/" + RECOVERY_TAG}
    raw = delivery.Git(root, "ls-remote", "--refs", "origin", *sorted(allowed))

    if len(raw) > 8192:
        raise ValueError("Recovery remote reference response exceeds its bound")

    result = {}

    for line in raw.splitlines():
        fields = line.split("\t")

        if len(fields) != 2 or delivery.COMMIT.fullmatch(fields[0]) is None or (
            fields[1] not in allowed or fields[1] in result
        ):
            raise ValueError("Recovery remote references are ambiguous or foreign")

        result[fields[1]] = fields[0]

    return result


def RequireRemote(root: Path, expected_sha: str, *, tagged: bool) -> dict:
    """Refuse source/branch drift and require either absent or exact original recovery-tag state.

    Args:
        root: Independently checked recovery checkout.
        expected_sha: Exact reviewed recovery commit.
        tagged: True after creation or while consuming the existing operational tag.
    Returns:
        Observed original remote references after validation.
    """

    refs = RemoteRefs(root)

    if refs.get("refs/heads/master") != PRODUCT_COMMIT or refs.get(
        "refs/heads/" + RECOVERY_BRANCH
    ) != expected_sha or refs.get("refs/tags/" + PRODUCT_TAG) != PRODUCT_TAG_OBJECT:
        raise ValueError("Original product or reviewed recovery remote source changed")

    if tagged:
        if delivery.Git(root, "cat-file", "-t", "refs/tags/" + RECOVERY_TAG) != "tag" or (
            delivery.Git(root, "rev-parse", "refs/tags/" + RECOVERY_TAG + "^{commit}") != (
                expected_sha)
            or refs.get("refs/tags/" + RECOVERY_TAG) != delivery.Git(
                root, "rev-parse", "refs/tags/" + RECOVERY_TAG)
        ):
            raise ValueError("Operational tag is not the exact existing reviewed annotated object")

    elif "refs/tags/" + RECOVERY_TAG in refs or delivery.Git(
        root, "tag", "--list", "--format=%(refname)", RECOVERY_TAG
    ):
        raise ValueError("Recovery finalization refuses every existing operational tag")

    return refs


def OriginalWheelInstall(smoke: dict, wheel: Path) -> None:
    """Verify original producer installation evidence while preserving its original absolute URI.

    Args:
        smoke: Unmodified original clean-install receipt from the sealed producer bundle.
        wheel: Relocated copy of the unchanged original wheel; never a rebuilt distribution.
    """

    installed = smoke["pip_install"]["install"]

    if (smoke["source"] != "local-wheel" or smoke["state"] != "verified-installed-demo"
        or smoke["version"] != VERSION or smoke["model_revision"] != 3 or len(installed) != 1
        or smoke["demo"]["state"] != "completed"
        or smoke["demo"]["target_teardown_completed"] is not True):
        raise ValueError("Original clean-wheel execution receipt differs")

    package = installed[0]

    if (package["metadata"]["name"] != delivery.PROJECT
        or package["metadata"]["version"] != VERSION
        or package["download_info"]["url"] != (
            "file:///home/runner/work/_temp/release-bundle/dist/1337-0.3.0-py3-none-any.whl")
        or package["download_info"]["archive_info"]["hashes"]["sha256"] != WHEEL_SHA256
        or hashlib.sha256(delivery.Read(wheel)).hexdigest() != WHEEL_SHA256):
        raise ValueError("Original installed wheel identity differs from unchanged bundle bytes")


def Validate(code_root: Path, product_root: Path, bundle: Path, expected_sha: str,
             fetch: Callable[[str], dict] = delivery.GitHubJson) -> dict:
    """Accept only the original sealed producer files for the reviewed tagged continuation.

    Args:
        code_root: Exact reviewed recovery-code checkout.
        product_root: Separate original product-tag checkout, with original master unchanged.
        bundle: Downloaded original artifact; this function never writes or reseals it.
        expected_sha: Exact reviewed control-code SHA selected before dispatch.
        fetch: Fixed-repository read-only Actions API transport.
    Returns:
        A separate recovery receipt identifying original bytes and both source roles.
    """

    DispatchContext(expected_sha, operational=True)
    facts = CodeFacts(code_root, product_root, expected_sha)
    RequireRemote(code_root, expected_sha, tagged=True)
    checks = RecoveryChecks(expected_sha, fetch)
    producer = OriginalProducer(fetch)
    master_checks = delivery.MasterChecks(PRODUCT_COMMIT, fetch)
    manifest = delivery.Verify(bundle, CHECKSUMS_SHA256)
    source = facts["product_source"]

    if manifest["source"] != source or delivery.Json(delivery.Read(
        bundle / "source.json", delivery.MAX_JSON_BYTES
    )) != source or delivery.Json(delivery.Read(
        bundle / "master-checks.json", delivery.MAX_JSON_BYTES
    )) != master_checks:
        raise ValueError("Original bundle source or master execution evidence differs")

    delivery.VerifyDocumentationTransfer(bundle / "api-docs", source)
    metadata = delivery.DistributionMetadata(bundle / "dist", VERSION, source["requires_python"])

    if delivery.Json(delivery.Read(bundle / "distribution-metadata.json")) != metadata:
        raise ValueError("Original distribution metadata receipt differs")

    OriginalWheelInstall(delivery.Json(delivery.Read(bundle / "clean-install.json")),
                         bundle / "dist/1337-0.3.0-py3-none-any.whl")

    if delivery.VALIDATION_MARKER in delivery.Read(bundle / "RELEASE_NOTES.md").decode():
        raise ValueError("Original release card does not retain actual validation evidence")

    if CodeFacts(code_root, product_root, expected_sha) != facts:
        raise ValueError("Recovery source changed during original-artifact validation")

    RequireRemote(code_root, expected_sha, tagged=True)
    index_observation = IndexAbsent()

    return {"schema_version": 1, "state": "verified-original-publication-handoff", **facts,
        "producer": producer, "recovery_checks": checks, "master_checks": master_checks,
        "checksums_sha256": CHECKSUMS_SHA256, "wheel_sha256": WHEEL_SHA256,
        "index_observation": index_observation}


def RecoveryJson(path: str) -> dict:
    """Read the fixed recovery PR or delegate to the unchanged bounded Actions transport.

    Args:
        path: Exact PR388 endpoint or an admitted owned-repository Actions evidence path.
    Returns:
        The bounded original JSON object without forwarding authorization across redirects.
    """

    if path != f"/repos/{delivery.REPOSITORY}/pulls/388":
        return delivery.GitHubJson(path)

    token = os.environ.get("GITHUB_TOKEN")

    if not token:
        raise ValueError("Recovery PR evidence requires the runner's read-only job token")

    request = urllib.request.Request("https://api.github.com" + path, headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"})

    with urllib.request.build_opener(delivery.NoRedirect()).open(request, timeout=30) as response:
        return delivery.Json(response.read(delivery.MAX_JSON_BYTES + 1))


def DocumentationSelection(bundle: Path, expected_sha: str,
                          fetch: Callable[[str], dict] = RecoveryJson) -> dict:
    """Select the unchanged original API archive only for the exact open recovery PR gate.

    Args:
        bundle: Fixed original producer artifact downloaded without altering its sealed files.
        expected_sha: Recovery PR head observed by the actual pull-request workflow event.
        fetch: Fixed-repository read-only GitHub API transport.
    Returns:
        Ordinary documentation composer inputs after complete original-byte verification.
    """

    if delivery.COMMIT.fullmatch(expected_sha) is None or (
        os.environ.get("GITHUB_EVENT_NAME") != "pull_request"
        or os.environ.get("GITHUB_REPOSITORY") != delivery.REPOSITORY
        or os.environ.get("GITHUB_REF") != "refs/pull/388/merge"
        or os.environ.get("GITHUB_HEAD_REF") != RECOVERY_BRANCH
    ):
        raise ValueError("Original pre-publication documentation is limited to recovery PR388")

    pull = fetch(f"/repos/{delivery.REPOSITORY}/pulls/{RECOVERY_PR}")

    if (pull["number"] != RECOVERY_PR or pull["state"] != "open" or pull["draft"] is not False
        or pull["head"]["sha"] != expected_sha or pull["head"]["ref"] != RECOVERY_BRANCH
        or pull["head"]["repo"]["full_name"] != delivery.REPOSITORY
        or pull["base"]["ref"] != "develop"):
        raise ValueError("Documentation requires the current ready owned recovery PR head")

    OriginalProducer(fetch)
    manifest = delivery.Verify(bundle, CHECKSUMS_SHA256)
    source = delivery.Json(delivery.Read(bundle / "source.json", delivery.MAX_JSON_BYTES))

    if source != {"commit": PRODUCT_COMMIT, "tree": PRODUCT_TREE, "tag": PRODUCT_TAG,
        "tag_type": "tag", "version": VERSION, "project": delivery.PROJECT,
        "repository": delivery.REPOSITORY, "requires_python": ">=3.11", "schema_version": 1,
        "source_date_epoch": 1793304738} or manifest["source"] != source:
        raise ValueError("Recovery documentation must retain the exact original product source")

    transfer = delivery.VerifyDocumentationTransfer(bundle / "api-docs", source)
    archive = bundle / "api-docs/1337-0.3.0-api-docs.tar.gz"

    return {"release_version": "", "retained_archive": str(archive.resolve(strict=True)),
            "retained_sha256": transfer["sha256"]}


def PushOperationalTag(root: Path) -> None:
    """Attempt one literal non-force operational-tag push using only the builtin short-lived token.

    Args:
        root: Exact clean reviewed recovery checkout with its newly created annotated tag.
    """

    token = os.environ.get("GITHUB_TOKEN")

    if not token:
        raise ValueError("Recovery tag push requires the builtin job token")

    authorization = base64.b64encode(("x-access-token:" + token).encode()).decode()
    environment = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
        "GIT_CONFIG_VALUE_0": "AUTHORIZATION: basic " + authorization}
    ref = "refs/tags/" + RECOVERY_TAG
    result = subprocess.run(["git", "-c", "core.fsmonitor=false", "push", "--porcelain", "origin",
        ref + ":" + ref], cwd=root, env=environment, capture_output=True, text=True,
        timeout=30, check=False)
    rows = [line.split("\t") for line in result.stdout.splitlines() if "\t" in line]

    if result.returncode != 0 or len(rows) != 1 or rows[0][0] != "*" or rows[0][1] != (
        ref + ":" + ref
    ):
        raise ValueError("Recovery new operational-tag push was not exclusively acknowledged")


def FinalizeRecovery(code_root: Path, product_root: Path, expected_sha: str,
                     fetch: Callable[[str], dict] = delivery.GitHubJson) -> dict:
    """Create one operational execution tag after original source and exact PR readiness acceptance.

    Args:
        code_root: Exact clean reviewed recovery branch checkout.
        product_root: Original product-tag checkout, whose original master must remain unchanged.
        expected_sha: Operator-selected reviewed recovery commit.
        fetch: Fixed-repository read-only API transport for actual job evidence.
    Returns:
        Original acknowledgement only after one successful tag push and exact remote readback.
    """

    DispatchContext(expected_sha, operational=False)

    if not os.environ.get("GITHUB_TOKEN"):
        raise ValueError("Recovery finalization requires the builtin job token before mutation")

    facts = CodeFacts(code_root, product_root, expected_sha)
    RequireRemote(code_root, expected_sha, tagged=False)
    checks = RecoveryChecks(expected_sha, fetch)
    producer = OriginalProducer(fetch)
    master_checks = delivery.MasterChecks(PRODUCT_COMMIT, fetch)

    if CodeFacts(code_root, product_root, expected_sha) != facts:
        raise ValueError("Recovery source changed after execution acceptance")

    RequireRemote(code_root, expected_sha, tagged=False)
    index_observation = IndexAbsent()
    subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "user.name=github-actions[bot]",
        "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com", "tag", "-a",
        RECOVERY_TAG, expected_sha, "-m", "Operational same-byte publication recovery for v0.3.0"],
        cwd=code_root, check=True, capture_output=True, timeout=30)

    if delivery.Git(code_root, "cat-file", "-t", "refs/tags/" + RECOVERY_TAG) != "tag" or (
        delivery.Git(code_root, "rev-parse", "refs/tags/" + RECOVERY_TAG + "^{commit}") != (
            expected_sha)
    ):
        raise ValueError("New operational tag is not the reviewed annotated source object")

    PushOperationalTag(code_root)
    RequireRemote(code_root, expected_sha, tagged=True)

    return {"schema_version": 1, "state": "acknowledged-operational-tag", **facts,
        "operational_tag_object": delivery.Git(code_root, "rev-parse", "refs/tags/" + RECOVERY_TAG),
        "producer": producer, "recovery_checks": checks, "master_checks": master_checks,
        "index_observation": index_observation}


def Main(arguments: list[str] | None = None) -> int:
    """Expose the finite one-time recovery acknowledgement and unchanged-bundle validation commands.

    Args:
        arguments: Explicit CLI arguments or the workflow's original process argument vector.
    Returns:
        Zero only after original facts were validated and the separate receipt was created.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("validate", "finalize"))
    parser.add_argument("--code-root", type=Path, required=True)
    parser.add_argument("--product-root", type=Path, required=True)
    parser.add_argument("--expected-recovery-sha", required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    selected = parser.parse_args(arguments)

    if selected.operation == "validate" and selected.bundle is None:
        parser.error("validate requires the unchanged original --bundle")

    if selected.operation == "finalize" and selected.bundle is not None:
        parser.error("finalize does not consume a publication bundle")

    try:
        if selected.output.exists() or selected.output.is_symlink():
            raise ValueError("Recovery acknowledgement must not replace an existing file")

        protected = [selected.code_root, selected.product_root]

        if selected.bundle is not None:
            protected.append(selected.bundle)

        if any(selected.output.resolve().is_relative_to(root.resolve()) for root in protected):
            raise ValueError("Recovery acknowledgement must remain outside checkouts and originals")

        if selected.operation == "validate":
            result = Validate(selected.code_root, selected.product_root, selected.bundle,
                              selected.expected_recovery_sha)

        else:
            result = FinalizeRecovery(selected.code_root, selected.product_root,
                                      selected.expected_recovery_sha)

        delivery.WriteJson(selected.output, result)

    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("Publication recovery refused; retain and inspect the original source and artifacts.")

        return 1

    print(json.dumps(result, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
