# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite recovery source, original-byte custody and one-attempt publication authority contracts."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import subprocess
import tarfile
import urllib.error
import zipfile
from types import SimpleNamespace

import pytest

from tools import release_delivery as delivery
from tools import release_recovery as recovery

SHA = "a" * 40
CARD = "\n".join(("## Digest", "## What's Changed", "## Validation",
    delivery.VALIDATION_MARKER, "## Breaking Changes", "## Try it from source", "## Notes"))


def Git(root, *arguments):
    """Execute real Git only inside the test-owned physical temporary repository."""

    return subprocess.run(["git", *arguments], cwd=root, check=True, capture_output=True,
                          text=True, timeout=10).stdout.strip()


def Context(monkeypatch, sha=SHA, *, operational=False):
    """Declare one exact synthetic dispatch without contacting a runner or granting a real token."""

    ref = "refs/tags/" + recovery.RECOVERY_TAG if operational else (
        "refs/heads/" + recovery.RECOVERY_BRANCH)
    workflow = "release.yml" if operational else "release-finalize.yml"

    for key, value in {"GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": delivery.REPOSITORY, "GITHUB_REF": ref,
        "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": sha, "GITHUB_WORKFLOW_SHA": sha,
        "GITHUB_WORKFLOW_REF": delivery.REPOSITORY + "/.github/workflows/" + workflow + "@" + ref,
        "GITHUB_TOKEN": "owned-inert-job-token"}.items():
        monkeypatch.setenv(key, value)


def ApiInputs(sha):
    """Retain independent API-shaped product, PR, producer and immutable artifact observations."""

    workflows, jobs = {}, {}

    for event, branch, source, offset in (("push", "master", recovery.PRODUCT_COMMIT, 100),
        ("pull_request", recovery.RECOVERY_BRANCH, sha, 200)):
        for index, (filename, required) in enumerate(delivery.MASTER_JOBS.items(), 1):
            run_id = offset + index
            run = {"id": run_id, "run_number": 5, "run_attempt": 1, "event": event,
                "head_branch": branch, "head_sha": source,
                "head_repository": {"full_name": delivery.REPOSITORY},
                "path": ".github/workflows/" + filename, "status": "completed",
                "conclusion": "success", "pull_requests": [
                    {"number": 388, "head": {"sha": sha}}] if event == "pull_request" else []}
            workflows[event, filename] = {"workflow_runs": [run]}
            rows = [{"name": name, "status": "completed", "conclusion": "success", "steps": [
                {"name": step, "status": "completed", "conclusion": "success"}
                for step in steps or ("Actual deployment",)]} for name, steps in required.items()
                if event == "push" or name != "deploy-pages"]
            jobs[run_id] = {"total_count": len(rows), "jobs": rows}

    producer = {"id": recovery.PRODUCER_RUN, "run_attempt": 1,
        "head_sha": recovery.PRODUCT_COMMIT, "head_branch": "v0.3.0",
        "event": "workflow_dispatch", "path": ".github/workflows/release.yml",
        "head_repository": {"full_name": delivery.REPOSITORY},
        "status": "completed", "conclusion": "failure"}
    producer_jobs = {"total_count": 5, "jobs": [
        {"name": "Refuse branch publication before source execution", "id": 11,
         "status": "completed", "conclusion": "success"},
        {"name": "Validate annotated release and build distributions once",
         "id": recovery.BUILD_JOB, "status": "completed", "conclusion": "success"},
        {"name": "Publish the validated distributions through Trusted Publishing",
         "id": recovery.PUBLISH_JOB, "status": "completed", "conclusion": "failure"},
        {"name": "Verify the actual clean PyPI installation", "id": 14,
         "status": "completed", "conclusion": "skipped"},
        {"name": "Publish the existing-tag release card and exact assets", "id": 15,
         "status": "completed", "conclusion": "skipped"}]}
    artifacts = {"total_count": 1, "artifacts": [{"id": recovery.PRODUCER_ARTIFACT,
        "name": "release-distributions", "expired": False, "digest": recovery.PRODUCER_DIGEST,
        "size_in_bytes": 31629727, "workflow_run": {
            "id": recovery.PRODUCER_RUN, "head_sha": recovery.PRODUCT_COMMIT}}]}
    calls = []

    def Fetch(path):
        """Expose only the intended immutable read endpoints; unexpected selection fails."""

        calls.append(path)
        prefix = f"/repos/{delivery.REPOSITORY}/actions/runs/{recovery.PRODUCER_RUN}"

        if path == prefix:
            return producer

        if path == prefix + "/attempts/1/jobs?per_page=100":
            return producer_jobs

        if path == prefix + "/artifacts?per_page=100":
            return artifacts

        if "/workflows/" in path:
            filename = path.split("/workflows/", 1)[1].split("/runs?", 1)[0]
            event = "pull_request" if "event=pull_request" in path else "push"

            return workflows[event, filename]

        run_id = int(path.split("/runs/", 1)[1].split("/", 1)[0])
        assert path.endswith("/attempts/1/jobs?per_page=100")

        return jobs[run_id]

    return SimpleNamespace(workflows=workflows, jobs=jobs, producer=producer,
        producer_jobs=producer_jobs, artifacts=artifacts, calls=calls, fetch=Fetch)


@pytest.fixture
def owned(tmp_path, monkeypatch):
    """Own real separate product/control checkouts; replace only external API/ref observations."""

    product = tmp_path / "product"
    product.mkdir()
    Git(product, "init", "--initial-branch=master")
    Git(product, "config", "user.name", "Owned recovery test")
    Git(product, "config", "user.email", "owned@example.invalid")
    (product / "docs/releases").mkdir(parents=True)
    (product / "pyproject.toml").write_text(
        '[project]\nname="1337"\nversion="0.3.0"\nrequires-python=">=3.11"\n', encoding="utf-8")
    (product / "uv.lock").write_text('[[package]]\nname="1337"\nversion="0.3.0"\n',
                                   encoding="utf-8")
    (product / "CHANGELOG.md").write_text("### Patch 0 — v0.3.0\n", encoding="utf-8")
    (product / "docs/releases/v0.3.0.md").write_text(CARD, encoding="utf-8")
    Git(product, "add", ".")
    Git(product, "commit", "-m", "Owned original product")
    original = Git(product, "rev-parse", "HEAD")
    Git(product, "tag", "-a", "v0.3.0", "-m", "Owned original annotated product")
    original_tag = Git(product, "rev-parse", "v0.3.0")
    Git(product, "remote", "add", "origin", "https://github.com/Fuzzy-Technologies/1337.git")
    Git(product, "update-ref", "refs/remotes/origin/master", original)
    code = tmp_path / "code"
    Git(product, "worktree", "add", "-b", recovery.RECOVERY_BRANCH, str(code))
    (code / "control.txt").write_text("Distinct reviewed recovery control", encoding="utf-8")
    Git(code, "add", "control.txt")
    Git(code, "commit", "-m", "Owned recovery control")
    sha = Git(code, "rev-parse", "HEAD")
    Git(code, "update-ref", "refs/remotes/origin/" + recovery.RECOVERY_BRANCH, sha)
    monkeypatch.setattr(recovery, "PRODUCT_COMMIT", original)
    monkeypatch.setattr(recovery, "PRODUCT_TREE", Git(product, "rev-parse", "HEAD^{tree}"))
    monkeypatch.setattr(recovery, "PRODUCT_TAG_OBJECT", original_tag)
    refs = {"refs/heads/master": original, "refs/tags/v0.3.0": original_tag,
            "refs/heads/" + recovery.RECOVERY_BRANCH: sha}
    monkeypatch.setattr(recovery, "RemoteRefs", lambda root: refs.copy())
    monkeypatch.setattr(recovery, "IndexAbsent", lambda: {"http_status": 404})
    Context(monkeypatch, sha)

    return SimpleNamespace(code=code, product=product, sha=sha, refs=refs, api=ApiInputs(sha))


@pytest.mark.parametrize("operational", [False, True])
def test_ExactManualWorkflowIdentityIsAccepted(monkeypatch, operational):
    """Finalizer and publisher have distinct literal workflow/ref authority contracts."""

    Context(monkeypatch, operational=operational)
    recovery.DispatchContext(SHA, operational=operational)


@pytest.mark.parametrize("key,value", [("GITHUB_EVENT_NAME", "push"),
    ("GITHUB_REPOSITORY", "foreign/1337"), ("GITHUB_REF", "refs/heads/master"),
    ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_SHA", "b" * 40),
    ("GITHUB_WORKFLOW_SHA", "b" * 40), ("GITHUB_WORKFLOW_REF", "foreign/release.yml")])
@pytest.mark.parametrize("operational", [False, True])
def test_EachForeignDispatchDimensionRefusesBeforeSource(monkeypatch, key, value, operational):
    """An approved source SHA alone cannot grant branch, workflow, repository or retry authority."""

    Context(monkeypatch, operational=operational)
    monkeypatch.setenv(key, value)

    with pytest.raises(ValueError, match="exact reviewed workflow dispatch"):
        recovery.DispatchContext(SHA, operational=operational)


def test_ActualGitKeepsProductAndRecoveryProvenanceDistinct(owned):
    """The immutable product tag remains at master while reviewed control code has its own tree."""

    facts = recovery.CodeFacts(owned.code, owned.product, owned.sha)
    assert facts["recovery_commit"] == owned.sha != facts["product_source"]["commit"]
    assert facts["product_source"]["tree"] == Git(owned.product, "rev-parse", "HEAD^{tree}")
    assert Git(owned.product, "cat-file", "-t", "v0.3.0") == "tag"


@pytest.mark.parametrize("fault", ["wrong-code", "dirty-code", "tracking-code", "master",
    "origin", "push-origin", "product-tag", "product-dirty", "product-tree", "nested"])
def test_ActualGitSourceDriftRefusesBeforeRecoveryTagCreation(owned, monkeypatch, fault):
    """Each independently changed authority input remains causal before any release mutation."""

    code, product, sha = owned.code, owned.product, owned.sha

    if fault == "wrong-code":
        sha = "0" * 40
    elif fault == "dirty-code":
        (code / "dirty").write_text("Uncommitted", encoding="utf-8")
    elif fault == "tracking-code":
        Git(code, "update-ref", "refs/remotes/origin/" + recovery.RECOVERY_BRANCH, "HEAD~1")
    elif fault == "master":
        Git(code, "update-ref", "refs/remotes/origin/master", owned.sha)
    elif fault in {"origin", "push-origin"}:
        Git(code, "remote", "set-url", *(["--push"] if fault == "push-origin" else []),
            "origin", "https://example.invalid/foreign.git")
    elif fault == "product-tag":
        monkeypatch.setattr(recovery, "PRODUCT_TAG_OBJECT", "0" * 40)
    elif fault == "product-dirty":
        (product / "dirty").write_text("Uncommitted", encoding="utf-8")
    elif fault == "product-tree":
        monkeypatch.setattr(recovery, "PRODUCT_TREE", "0" * 40)
    else:
        code = code / "docs"

    with pytest.raises((ValueError, subprocess.SubprocessError)):
        recovery.CodeFacts(code, product, sha)

    assert Git(owned.product, "tag", "--list", recovery.RECOVERY_TAG) == ""


def test_RecoveryRequiresAllElevenReadinessWorkflowsAndTwentyThreeActualJobs():
    """Retain every product check while omitting only the master Pages deployment."""

    api = ApiInputs(SHA)
    value = recovery.RecoveryChecks(SHA, api.fetch)
    assert len(value["accepted_workflows"]) == 11
    assert sum(len(item["jobs"]) for item in value["accepted_workflows"]) == 23
    assert all("deploy-pages" not in item["jobs"] for item in value["accepted_workflows"])


@pytest.mark.parametrize("fault", ["absent", "draft-skip", "wrong-pr", "wrong-pr-head",
    "foreign-repo", "wrong-event", "wrong-branch", "wrong-source", "workflow-path",
    "latest-failed", "incomplete-jobs", "duplicate-job", "skipped-job", "missing-step",
    "skipped-step", "duplicate-step", "duplicate-failed-step"])
def test_ReadinessCannotBorrowOldOrSkippedOrForeignEvidence(fault):
    """Each source, readiness, named-job and named-step boundary fails independently."""

    api = ApiInputs(SHA)
    item = api.workflows["pull_request", "python-quality.yml"]
    run = item["workflow_runs"][0]
    jobs = api.jobs[run["id"]]

    if fault == "absent":
        item["workflow_runs"] = []
    elif fault == "draft-skip":
        run["conclusion"] = "skipped"
    elif fault == "wrong-pr":
        run["pull_requests"][0]["number"] = 387
    elif fault == "wrong-pr-head":
        run["pull_requests"][0]["head"]["sha"] = "b" * 40
    elif fault == "foreign-repo":
        run["head_repository"]["full_name"] = "foreign/1337"
    elif fault in {"wrong-event", "wrong-branch", "wrong-source", "workflow-path"}:
        run[{"wrong-event": "event", "wrong-branch": "head_branch", "wrong-source": "head_sha",
             "workflow-path": "path"}[fault]] = "foreign"
    elif fault == "latest-failed":
        later = copy.deepcopy(run)
        later.update(run_number=6, conclusion="failure")
        item["workflow_runs"].append(later)
    elif fault == "incomplete-jobs":
        jobs["total_count"] += 1
    elif fault == "duplicate-job":
        jobs["jobs"].append(copy.deepcopy(jobs["jobs"][0]))
        jobs["total_count"] += 1
    elif fault == "skipped-job":
        jobs["jobs"][0]["conclusion"] = "skipped"
    elif fault == "missing-step":
        jobs["jobs"][0]["steps"] = []
    elif fault == "skipped-step":
        jobs["jobs"][0]["steps"][0]["conclusion"] = "skipped"
    else:
        duplicate = copy.deepcopy(jobs["jobs"][0]["steps"][0])

        if fault == "duplicate-failed-step":
            duplicate["conclusion"] = "failure"

        jobs["jobs"][0]["steps"].append(duplicate)

    with pytest.raises(ValueError):
        recovery.RecoveryChecks(SHA, api.fetch)


@pytest.mark.parametrize("fault", [None, "run-source", "run-attempt", "run-path", "build",
    "publisher", "publisher-id", "truncated", "missing-artifact", "expired", "digest",
    "artifact-run", "artifact-source", "size"])
def test_OriginalProducerCannotBeReplacedByAnotherBuildOrArtifact(fault):
    """A successful replacement build is never original same-byte recovery evidence."""

    api = ApiInputs(SHA)
    artifact = api.artifacts["artifacts"][0]

    if fault == "run-source":
        api.producer["head_sha"] = "b" * 40
    elif fault == "run-attempt":
        api.producer["run_attempt"] = 2
    elif fault == "run-path":
        api.producer["path"] = ".github/workflows/foreign.yml"
    elif fault == "build":
        api.producer_jobs["jobs"][1]["conclusion"] = "failure"
    elif fault == "publisher":
        api.producer_jobs["jobs"][2]["conclusion"] = "success"
    elif fault == "publisher-id":
        api.producer_jobs["jobs"][2]["id"] += 1
    elif fault == "truncated":
        api.producer_jobs["total_count"] += 1
    elif fault == "missing-artifact":
        artifact["id"] += 1
    elif fault == "expired":
        artifact["expired"] = True
    elif fault == "digest":
        artifact["digest"] = "sha256:" + "b" * 64
    elif fault == "artifact-run":
        artifact["workflow_run"]["id"] += 1
    elif fault == "artifact-source":
        artifact["workflow_run"]["head_sha"] = "b" * 40
    elif fault == "size":
        artifact["size_in_bytes"] = 256 * 1024 * 1024 + 1

    if fault is None:
        assert recovery.OriginalProducer(api.fetch)["artifact_id"] == recovery.PRODUCER_ARTIFACT
    else:
        with pytest.raises(ValueError):
            recovery.OriginalProducer(api.fetch)


def Bundle(root, source, checks, monkeypatch):
    """Seal actual bounded synthetic archives and receipts for independent custody checks."""

    (root / "dist").mkdir(parents=True)
    metadata = b"Metadata-Version: 2.5\nName: 1337\nVersion: 0.3.0\nRequires-Python: >=3.11\n"
    wheel = root / "dist/1337-0.3.0-py3-none-any.whl"

    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("1337-0.3.0.dist-info/METADATA", metadata)

    with tarfile.open(root / "dist/1337-0.3.0.tar.gz", "w:gz") as archive:
        member = tarfile.TarInfo("1337-0.3.0/PKG-INFO")
        member.size = len(metadata)
        archive.addfile(member, io.BytesIO(metadata))

    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    monkeypatch.setattr(recovery, "WHEEL_SHA256", digest)
    smoke = {"source": "local-wheel", "state": "verified-installed-demo", "version": "0.3.0",
        "model_revision": 3, "demo": {"state": "completed", "target_teardown_completed": True},
        "pip_install": {"install": [{"metadata": {"name": "1337", "version": "0.3.0"},
            "download_info": {"url": "file:///home/runner/work/_temp/release-bundle/dist/"
                "1337-0.3.0-py3-none-any.whl", "archive_info": {"hashes": {"sha256": digest}}}}]}}

    for name, value in {"source.json": source, "master-checks.json": checks,
        "distribution-metadata.json": delivery.DistributionMetadata(root / "dist", "0.3.0",
            ">=3.11"), "clean-install.json": smoke}.items():
        delivery.WriteJson(root / name, value)

    (root / "RELEASE_NOTES.md").write_text(CARD.replace(delivery.VALIDATION_MARKER,
        "Original named execution links"), encoding="utf-8")
    (root / "api-docs").mkdir()
    (root / "api-docs/1337-0.3.0-api-docs.tar.gz").write_bytes(b"Original delegated transfer")
    (root / "api-docs/1337-0.3.0-api-docs.manifest.json").write_text("{}", encoding="utf-8")
    delivery.WriteJson(root / "release-manifest.json", {"schema_version": 1, "source": source,
        "files": delivery.Inventory(root)})
    (root / "SHA256SUMS").write_text("".join(f"{v['sha256']}  {name}\n" for name, v in (
        delivery.Inventory(root).items())), encoding="ascii")
    monkeypatch.setattr(recovery, "CHECKSUMS_SHA256", hashlib.sha256(
        (root / "SHA256SUMS").read_bytes()).hexdigest())

    return root


@pytest.mark.parametrize("fault", [None, "wheel-byte", "unlisted", "source", "checks",
                                  "metadata", "receipt"])
def test_ValidatePreservesOriginalBytesAndDelegatesOriginalDocumentation(owned, tmp_path,
                                                                      monkeypatch, fault):
    """Real hashing and metadata checks cannot accept mutation or silently reseal the original."""

    Context(monkeypatch, owned.sha, operational=True)
    Git(owned.code, "tag", "-a", recovery.RECOVERY_TAG, "-m", "Owned operational execution")
    owned.refs["refs/tags/" + recovery.RECOVERY_TAG] = Git(
        owned.code, "rev-parse", recovery.RECOVERY_TAG)
    source = recovery.ProductFacts(owned.product)
    checks = delivery.MasterChecks(recovery.PRODUCT_COMMIT, owned.api.fetch)
    bundle = Bundle(tmp_path / "bundle", source, checks, monkeypatch)
    calls = []

    def Documentation(path, facts):
        """Record only the separately tested strict transfer verifier boundary."""

        calls.append((path, facts))

    monkeypatch.setattr(delivery, "VerifyDocumentationTransfer", Documentation)

    if fault == "wheel-byte":
        with (bundle / "dist/1337-0.3.0-py3-none-any.whl").open("ab") as output:
            output.write(b"Changed")
    elif fault == "unlisted":
        (bundle / "unlisted").write_text("Unexpected", encoding="utf-8")
    elif fault in {"source", "checks", "metadata", "receipt"}:
        name = {"source": "source.json", "checks": "master-checks.json",
            "metadata": "distribution-metadata.json", "receipt": "clean-install.json"}[fault]
        (bundle / name).write_text("{}", encoding="utf-8")

    before = delivery.Inventory(bundle)

    if fault:
        with pytest.raises(ValueError):
            recovery.Validate(owned.code, owned.product, bundle, owned.sha, owned.api.fetch)
    else:
        result = recovery.Validate(owned.code, owned.product, bundle, owned.sha, owned.api.fetch)
        assert result["state"] == "verified-original-publication-handoff"
        assert result["product_source"] == source and result["recovery_commit"] == owned.sha
        assert result["producer"]["artifact_id"] == recovery.PRODUCER_ARTIFACT
        assert calls == [(bundle / "api-docs", source)]

    assert delivery.Inventory(bundle) == before, "Validation must never reseal or modify originals"


def test_FinalizerCreatesOnlyOneOperationalTagAfterAllGates(owned, monkeypatch):
    """Actual annotated tag creation follows readiness/source checks and one acknowledged push."""

    pushes = []

    def Push(root):
        """Acknowledge only the test-owned annotated operational object in external ref state."""

        pushes.append(root)
        owned.refs["refs/tags/" + recovery.RECOVERY_TAG] = Git(root, "rev-parse",
                                                               recovery.RECOVERY_TAG)

    monkeypatch.setattr(recovery, "PushOperationalTag", Push)
    result = recovery.FinalizeRecovery(owned.code, owned.product, owned.sha, owned.api.fetch)
    assert result["state"] == "acknowledged-operational-tag" and pushes == [owned.code]
    assert Git(owned.code, "cat-file", "-t", recovery.RECOVERY_TAG) == "tag"
    assert Git(owned.code, "rev-parse", recovery.RECOVERY_TAG + "^{commit}") == owned.sha
    assert Git(owned.product, "rev-parse", "v0.3.0") == recovery.PRODUCT_TAG_OBJECT
    assert Git(owned.product, "rev-parse", "master") == recovery.PRODUCT_COMMIT

    with pytest.raises(ValueError, match="every existing operational tag"):
        recovery.FinalizeRecovery(owned.code, owned.product, owned.sha, owned.api.fetch)

    assert len(pushes) == 1


@pytest.mark.parametrize("fault", [None, "event", "repository", "workflow-ref", "head-ref",
    "sha", "pull-number", "pull-state", "draft", "pull-sha", "pull-ref", "pull-repo",
    "pull-base", "source-epoch", "source-tag", "source-tree", "unlisted", "archive-byte",
    "transfer"])
def test_RecoveryDocumentationUsesOnlyOriginalSealedArchiveForExactReadyPr(
    owned, tmp_path, monkeypatch, fault,
):
    """Keep original docs bytes; reject foreign events, ownership, source and corruption."""

    for key, value in {"GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": delivery.REPOSITORY, "GITHUB_REF": "refs/pull/388/merge",
        "GITHUB_HEAD_REF": recovery.RECOVERY_BRANCH}.items():
        monkeypatch.setenv(key, value)

    pull = {"number": 388, "state": "open", "draft": False,
        "head": {"sha": owned.sha, "ref": recovery.RECOVERY_BRANCH,
                 "repo": {"full_name": delivery.REPOSITORY}}, "base": {"ref": "develop"}}
    source = recovery.ProductFacts(owned.product)
    source["source_date_epoch"] = 1793304738

    if fault == "source-epoch":
        source["source_date_epoch"] += 1

    elif fault == "source-tag":
        source["tag"] = "v0.3.1"

    elif fault == "source-tree":
        source["tree"] = "b" * 40

    bundle = Bundle(tmp_path / "bundle", source, {}, monkeypatch)
    archive = bundle / "api-docs/1337-0.3.0-api-docs.tar.gz"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    calls = []

    def Fetch(path):
        """Declare the current PR independently of the fixed original producer response."""

        return pull if path == f"/repos/{delivery.REPOSITORY}/pulls/388" else owned.api.fetch(path)

    def Transfer(directory, facts):
        """Observe the existing separately tested archive verifier, including its refusal."""

        calls.append((directory, facts))

        if fault == "transfer":
            raise ValueError("Original transfer verifier refused archive")

        return {"sha256": digest}

    monkeypatch.setattr(delivery, "VerifyDocumentationTransfer", Transfer)
    environment = {"event": "GITHUB_EVENT_NAME", "repository": "GITHUB_REPOSITORY",
        "workflow-ref": "GITHUB_REF", "head-ref": "GITHUB_HEAD_REF"}

    if fault in environment:
        monkeypatch.setenv(environment[fault], "foreign")

    elif fault == "pull-number":
        pull["number"] = 389

    elif fault == "pull-state":
        pull["state"] = "closed"

    elif fault == "draft":
        pull["draft"] = True

    elif fault == "pull-sha":
        pull["head"]["sha"] = "b" * 40

    elif fault == "pull-ref":
        pull["head"]["ref"] = "foreign"

    elif fault == "pull-repo":
        pull["head"]["repo"]["full_name"] = "foreign/1337"

    elif fault == "pull-base":
        pull["base"]["ref"] = "master"

    elif fault == "unlisted":
        (bundle / "unexpected").write_bytes(b"Foreign")

    elif fault == "archive-byte":
        archive.write_bytes(b"Changed archive")

    before = delivery.Inventory(bundle)

    if fault:
        with pytest.raises(ValueError):
            recovery.DocumentationSelection(bundle, "invalid" if fault == "sha" else owned.sha,
                                             Fetch)

    else:
        result = recovery.DocumentationSelection(bundle, owned.sha, Fetch)
        assert result == {"release_version": "", "retained_archive": str(archive.resolve()),
                          "retained_sha256": digest}, "Original archive selection differs"
        assert calls == [(bundle / "api-docs", source)], "Strict transfer verifier was not used"
        assert owned.api.calls, "Original producer provenance must actually be checked"
        requests = []

        def Open(request, *, timeout):
            """Exercise both real default transports against original API-shaped observations."""

            assert timeout == 30, "API request lost its finite timeout"
            assert request.full_url.startswith("https://api.github.com/repos/" +
                delivery.REPOSITORY + "/"), "API request escaped the owned repository"
            assert request.get_header("Authorization") == "Bearer owned-inert-job-token", (
                "API request did not use the isolated inert job token")
            requests.append(request.full_url)
            path = request.full_url.removeprefix("https://api.github.com")

            return io.BytesIO(json.dumps(Fetch(path)).encode())

        def Opener(handler):
            """Preserve the real authorization-bearing no-redirect handler selection."""

            assert isinstance(handler, delivery.NoRedirect), "Token-bearing redirects were allowed"

            return SimpleNamespace(open=Open)

        monkeypatch.setattr(recovery.urllib.request, "build_opener", Opener)
        assert recovery.DocumentationSelection(bundle, owned.sha) == result, (
            "Default API transport changed the accepted original archive")
        assert requests[0].endswith("/pulls/388") and len(requests) == 4, (
            "Default transport did not check the exact PR and three producer endpoints")

    assert delivery.Inventory(bundle) == before, "Docs selection must preserve every original byte"


@pytest.mark.parametrize("fault", ["token", "other-pr", "foreign-host", "fragment", "oversize"])
def test_RecoveryPrTransportCannotExpandOrReadUnboundedResponses(monkeypatch, fault):
    """Admit one exact PR path and preserve Actions transport restrictions."""

    monkeypatch.setenv("GITHUB_TOKEN", "owned-inert-job-token")
    path = f"/repos/{delivery.REPOSITORY}/pulls/388"

    if fault == "token":
        monkeypatch.delenv("GITHUB_TOKEN")

    elif fault == "other-pr":
        path = path.replace("388", "389")

    elif fault == "foreign-host":
        path = "https://foreign.invalid" + path

    elif fault == "fragment":
        path += "#foreign"

    def Open(request, *, timeout):
        """Return a bounded oversized inert response only for the original fixed request."""

        assert fault == "oversize" and timeout == 30, "Invalid API request reached the transport"
        assert request.full_url == "https://api.github.com" + path, "API request changed endpoint"

        return io.BytesIO(b" " * (delivery.MAX_JSON_BYTES + 1))

    monkeypatch.setattr(recovery.urllib.request, "build_opener",
                        lambda handler: SimpleNamespace(open=Open))

    with pytest.raises(ValueError):
        recovery.RecoveryJson(path)


@pytest.mark.parametrize("fault", [None, "uri", "name", "version", "hash", "wheel-byte",
    "source", "state", "revision", "teardown", "duplicate"])
def test_OriginalWheelReceiptKeepsProducerPathAndExactBytes(tmp_path, monkeypatch, fault):
    """A relocated bundle must retain original producer attribution without changing its receipt."""

    wheel = tmp_path / "original.whl"
    wheel.write_bytes(b"Owned exact original wheel")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    monkeypatch.setattr(recovery, "WHEEL_SHA256", digest)
    package = {"metadata": {"name": "1337", "version": "0.3.0"}, "download_info": {
        "url": "file:///home/runner/work/_temp/release-bundle/dist/1337-0.3.0-py3-none-any.whl",
        "archive_info": {"hashes": {"sha256": digest}}}}
    smoke = {"source": "local-wheel", "state": "verified-installed-demo", "version": "0.3.0",
        "model_revision": 3, "demo": {"state": "completed", "target_teardown_completed": True},
        "pip_install": {"install": [package]}}

    if fault == "uri":
        package["download_info"]["url"] = wheel.as_uri()
    elif fault in {"name", "version"}:
        package["metadata"][fault] = "foreign"
    elif fault == "hash":
        package["download_info"]["archive_info"]["hashes"]["sha256"] = "0" * 64
    elif fault == "wheel-byte":
        wheel.write_bytes(b"Changed original wheel")
    elif fault in {"source", "state"}:
        smoke[fault] = "foreign"
    elif fault == "revision":
        smoke["model_revision"] = 4
    elif fault == "teardown":
        smoke["demo"]["target_teardown_completed"] = False
    elif fault == "duplicate":
        smoke["pip_install"]["install"].append(copy.deepcopy(package))

    if fault:
        with pytest.raises(ValueError):
            recovery.OriginalWheelInstall(smoke, wheel)
    else:
        recovery.OriginalWheelInstall(smoke, wheel)


@pytest.mark.parametrize("fault", ["local-lightweight", "local-annotated", "remote"])
def test_FinalizerRefusesEveryExistingOperationalTag(owned, fault):
    """Even the same expected target must not turn a later dispatch into tag reuse or overwrite."""

    if fault == "local-lightweight":
        Git(owned.code, "tag", recovery.RECOVERY_TAG)
    elif fault == "local-annotated":
        Git(owned.code, "tag", "-a", recovery.RECOVERY_TAG, "-m", "Existing owned execution")
    else:
        owned.refs["refs/tags/" + recovery.RECOVERY_TAG] = "0" * 40

    before = Git(owned.code, "show-ref", "--tags")

    with pytest.raises(ValueError, match="every existing operational tag"):
        recovery.FinalizeRecovery(owned.code, owned.product, owned.sha, owned.api.fetch)

    assert Git(owned.code, "show-ref", "--tags") == before


@pytest.mark.parametrize("raw", ["", "0" * 8193,
    "0" * 40 + "\trefs/heads/foreign", "not-a-sha\trefs/heads/master",
    "0" * 40 + "\trefs/heads/master\textra",
    ("0" * 40 + "\trefs/heads/master\n") * 2])
def test_RemoteReferenceObservationIsBoundedAndUnambiguous(tmp_path, monkeypatch, raw):
    """Unknown response or transport failure never supplies an invented absent-tag observation."""

    calls = []

    def Observe(root, *arguments):
        """Return a fixed original reference response without external network access."""

        calls.append(arguments)

        return raw

    monkeypatch.setattr(delivery, "Git", Observe)

    if raw == "":
        assert recovery.RemoteRefs(tmp_path) == {}
    else:
        with pytest.raises(ValueError):
            recovery.RemoteRefs(tmp_path)

    assert len(calls) == 1 and calls[0][:3] == ("ls-remote", "--refs", "origin")


@pytest.mark.parametrize("fault", ["readiness", "producer", "master", "remote", "index", "token"])
def test_FinalizerRefusesBeforeAnyTagOrPushWhenARequiredGateFails(owned, monkeypatch, fault):
    """No required external observation can be replaced by creation followed by a later refusal."""

    if fault == "readiness":
        owned.api.workflows["pull_request", "python-quality.yml"]["workflow_runs"] = []
    elif fault == "producer":
        owned.api.producer["conclusion"] = "success"
    elif fault == "master":
        owned.api.workflows["push", "python-quality.yml"]["workflow_runs"] = []
    elif fault == "remote":
        owned.refs["refs/heads/master"] = owned.sha
    elif fault == "index":
        def Refuse():
            """Represent an existing version or failed public index observation."""

            raise ValueError("No exact original 404")

        monkeypatch.setattr(recovery, "IndexAbsent", Refuse)
    else:
        monkeypatch.delenv("GITHUB_TOKEN")

    with pytest.raises(ValueError):
        recovery.FinalizeRecovery(owned.code, owned.product, owned.sha, owned.api.fetch)

    assert Git(owned.code, "tag", "--list", recovery.RECOVERY_TAG) == ""


@pytest.mark.parametrize("status,url", [(404, recovery.INDEX_URL), (403, recovery.INDEX_URL),
    (500, recovery.INDEX_URL), (404, "https://example.invalid/foreign")])
def test_IndexAbsenceAcceptsOnlyExactOriginal404(monkeypatch, status, url):
    """A failed, redirected or forbidden lookup cannot authorize any public upload."""

    calls = []

    class Opener:
        """Return one controlled original HTTP response without external network access."""

        def open(self, request, timeout):
            """Record the fixed unauthenticated GET and its finite deadline."""

            calls.append((request.full_url, request.get_method(), timeout, request.headers))

            raise urllib.error.HTTPError(url, status, "Owned response", {}, io.BytesIO())

    def Build(handler):
        """Require the actual redirect-denying transport boundary."""

        assert isinstance(handler, delivery.NoRedirect)

        return Opener()

    monkeypatch.setattr(recovery.urllib.request, "build_opener", Build)

    if status == 404 and url == recovery.INDEX_URL:
        assert recovery.IndexAbsent()["http_status"] == 404
    else:
        with pytest.raises(ValueError):
            recovery.IndexAbsent()

    assert calls == [(recovery.INDEX_URL, "GET", 20, {"Accept": "application/json"})]


@pytest.mark.parametrize("success", [True, False])
def test_IndexSuccessOrTransportFailureDoesNotBecomeAbsence(monkeypatch, success):
    """Neither a published version nor a missing original response can count as an exact 404."""

    class Response:
        """Own one bounded ordinary successful response context."""

        def __enter__(self):
            """Expose an observed successful response without any JSON body requirement."""

            return self

        def __exit__(self, *arguments):
            """Release the owned response without swallowing a refusal."""

            return False

    def Open(*arguments, **kwargs):
        """Return success or a causal transport error; never synthesize a 404."""

        if not success:
            raise TimeoutError("Owned missing index response")

        return Response()

    monkeypatch.setattr(recovery.urllib.request, "build_opener", lambda handler: SimpleNamespace(
        open=Open))

    with pytest.raises((ValueError, TimeoutError)):
        recovery.IndexAbsent()


@pytest.mark.parametrize("stdout,status", [(None, 0), ("", 0), ("=\twrong\tup to date\n", 0),
    ("*\trefs/tags/foreign:refs/tags/foreign\t[new tag]\n", 0), (None, 1)])
def test_OperationalPushRequiresOneExclusiveNewTagAcknowledgement(tmp_path, monkeypatch,
                                                                  stdout, status):
    """Unknown acknowledgements preserve failure without a retry, force flag or tag rollback."""

    calls = []
    monkeypatch.setenv("GITHUB_TOKEN", "owned-inert-job-token")
    ref = "refs/tags/" + recovery.RECOVERY_TAG
    output = f"*\t{ref}:{ref}\t[new tag]\n" if stdout is None else stdout

    def Run(arguments, **kwargs):
        """Capture only the intended owned push vector and return a controlled acknowledgement."""

        calls.append((arguments, kwargs))

        return SimpleNamespace(returncode=status, stdout=output)

    monkeypatch.setattr(recovery.subprocess, "run", Run)

    if stdout is None and status == 0:
        recovery.PushOperationalTag(tmp_path)
    else:
        with pytest.raises(ValueError):
            recovery.PushOperationalTag(tmp_path)

    assert len(calls) == 1 and calls[0][0][-1] == ref + ":" + ref
    assert "--force" not in calls[0][0] and "--delete" not in calls[0][0]
    assert all("owned-inert-job-token" not in argument for argument in calls[0][0])


def test_MainNeverWritesRecoveryAcknowledgementIntoOriginalBundle(tmp_path, monkeypatch):
    """Output placement must not mutate the sealed producer inventory even after valid review."""

    code, product, bundle = (tmp_path / name for name in ("code", "product", "bundle"))

    for root in (code, product, bundle):
        root.mkdir()

    status = recovery.Main(["validate", "--code-root", str(code), "--product-root", str(product),
        "--bundle", str(bundle), "--expected-recovery-sha", SHA,
        "--output", str(bundle / "receipt.json")])
    assert status == 1 and not any(bundle.iterdir())
