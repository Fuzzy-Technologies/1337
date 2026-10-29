# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned real-Git release finalization and pre-source workflow authority contracts."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from tools import release_delivery as delivery
from tools import release_finalize as finalize

CARD = "\n".join(("## Digest", "## What's Changed", "## Validation",
    delivery.VALIDATION_MARKER, "## Breaking Changes", "## Try it from source", "## Notes"))


def Git(root, *arguments):
    """Use actual Git only in this test's explicitly owned repository."""

    return subprocess.run(["git", *arguments], cwd=root, check=True, text=True,
        capture_output=True, timeout=10).stdout.strip()


@pytest.fixture
def owned(tmp_path, monkeypatch):
    """Create real commits and refs; replace only the external transport observation."""

    root = tmp_path / "source"
    root.mkdir()
    Git(root, "init", "--initial-branch=master")
    Git(root, "config", "user.name", "Owned release test")
    Git(root, "config", "user.email", "owned@example.invalid")
    (root / "docs/releases").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname="1337"\nversion="0.3.0"\nrequires-python=">=3.11"\n')
    (root / "uv.lock").write_text('[[package]]\nname="1337"\nversion="0.3.0"\n')
    (root / "CHANGELOG.md").write_text("### Patch 0 — v0.3.0\n")
    (root / "docs/releases/v0.3.0.md").write_text(CARD)
    Git(root, "add", ".")
    Git(root, "commit", "-m", "Owned exact release metadata")
    head = Git(root, "rev-parse", "HEAD")
    Git(root, "update-ref", "refs/remotes/origin/master", head)
    Git(root, "remote", "add", "origin", "https://github.com/Fuzzy-Technologies/1337.git")
    references = {"refs/heads/master": head}
    monkeypatch.setattr(finalize, "RemoteRefs", lambda selected: references.copy())
    monkeypatch.setenv("GITHUB_TOKEN", "owned-inert-job-token")

    return root, head, references


def test_PreflightUsesActualCleanMasterAndMatchingOwnedMetadata(owned):
    """No fabricated Git observations can establish the clean source authority in this case."""

    root, head, _ = owned
    facts = finalize.Preflight(root, head)
    assert facts["commit"] == head and facts["tree"] == Git(root, "rev-parse", "HEAD^{tree}"), (
        "Finalization must bind the actual selected commit and tree")
    assert facts["version"] == "0.3.0" and Git(root, "tag", "--list") == "", (
        "Read-only preflight cannot create the release tag")


@pytest.mark.parametrize("fault", ["expected-sha", "short-sha", "branch", "dirty", "tracking",
    "metadata", "card", "origin", "push-origin", "local-lightweight", "local-annotated",
    "remote-tag", "remote-master", "nested-root"])
def test_IndependentActualGitSourceFailuresNeverReachTagCreation(owned, fault):
    """Each source authority failure is causal before any release mutation."""

    root, head, remote = owned
    selected_root, expected = root, head

    if fault == "expected-sha":
        expected = "0" * 40
    elif fault == "short-sha":
        expected = head[:12]
    elif fault == "branch":
        Git(root, "switch", "-c", "feature/owned")
    elif fault == "dirty":
        (root / "untracked").write_text("Owned uncommitted input")
    elif fault == "tracking":
        Git(root, "update-ref", "-d", "refs/remotes/origin/master")
    elif fault in {"metadata", "card"}:
        path = root / ("pyproject.toml" if fault == "metadata" else "docs/releases/v0.3.0.md")
        path.write_text(path.read_text().replace("0.3.0", "0.3.1") if fault == "metadata" else
            path.read_text().replace(delivery.VALIDATION_MARKER, ""))
        Git(root, "add", ".")
        Git(root, "commit", "-m", "Owned causal metadata refusal")
        expected = Git(root, "rev-parse", "HEAD")
        Git(root, "update-ref", "refs/remotes/origin/master", expected)
        remote["refs/heads/master"] = expected
    elif fault in {"origin", "push-origin"}:
        Git(root, "remote", "set-url", *( ["--push"] if fault == "push-origin" else []),
            "origin", "https://example.invalid/foreign.git")
    elif fault == "local-lightweight":
        Git(root, "tag", "v0.3.0", head)
    elif fault == "local-annotated":
        Git(root, "tag", "-a", "v0.3.0", head, "-m", "Existing owned annotated tag")
    elif fault == "remote-tag":
        remote["refs/tags/v0.3.0"] = head
    elif fault == "remote-master":
        remote["refs/heads/master"] = "0" * 40
    else:
        selected_root = root / "docs"

    original_tags = Git(root, "tag", "--list")

    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        finalize.Preflight(selected_root, expected)

    assert Git(root, "tag", "--list") == original_tags, (
        "Failed source preflight must preserve all original tag identities")


def test_TaggedPreflightRefusesActualLightweightTag(owned):
    """The post-creation mode still verifies annotation with the existing release source guard."""

    root, head, _ = owned
    Git(root, "tag", "v0.3.0", head)

    with pytest.raises(ValueError, match="tag, event"):
        finalize.Preflight(root, head, tagged=True)


def test_FinalizeCreatesOneActualAnnotatedTagAndNonforceOwnedPush(owned, tmp_path, monkeypatch):
    """The mutation oracle is an independently owned bare Git repository, never GitHub."""

    root, head, remote = owned
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(bare)], check=True, capture_output=True,
        timeout=10)
    calls = []

    def Gates(selected):
        """Observe the actual absence of the tag before granting the inert master evidence."""

        assert selected == head and Git(root, "tag", "--list") == "", (
            "Actual master acceptance must precede tag mutation")
        calls.append("gates")

        return {"owned": "named master evidence"}

    def Push(selected):
        """Exercise the same non-force tag refspec only against the owned bare repository."""

        calls.append("push")
        Git(selected, "push", "--porcelain", str(bare), "refs/tags/v0.3.0:refs/tags/v0.3.0")
        remote["refs/tags/v0.3.0"] = Git(bare, "rev-parse", "refs/tags/v0.3.0")

    monkeypatch.setattr(delivery, "MasterChecks", Gates)
    monkeypatch.setattr(finalize, "PushTag", Push)
    result = finalize.Finalize(root, head)
    assert calls == ["gates", "push"] and result["tag_type"] == "tag", (
        "One actual gate observation and one push must produce an annotated acknowledgement")
    assert Git(bare, "cat-file", "-t", "refs/tags/v0.3.0") == "tag" and (
        Git(bare, "rev-parse", "refs/tags/v0.3.0^{commit}") == head
    ), "The original remote tag must be annotated and resolve to the exact accepted master"

    with pytest.raises(ValueError, match="existing local"):
        finalize.Finalize(root, head)

    assert calls == ["gates", "push"], "An existing tag must never retry the gate or push"


@pytest.mark.parametrize("fault", ["gate-refusal", "moved-master", "created-remote-tag",
                                   "no-token"])
def test_MasterGateAndFreshRefChangesPreventActualTagMutation(owned, monkeypatch, fault):
    """A successful initial preflight cannot authorize a mutation after independent drift."""

    root, head, remote = owned
    calls = []

    def Gates(selected):
        """Introduce a causal change during the original master-evidence boundary."""

        calls.append(selected)

        if fault == "gate-refusal":
            raise ValueError("Owned required master job did not execute")
        if fault == "moved-master":
            remote["refs/heads/master"] = "0" * 40
        if fault == "created-remote-tag":
            remote["refs/tags/v0.3.0"] = head

        return {"owned": True}

    monkeypatch.setattr(delivery, "MasterChecks", Gates)

    if fault == "no-token":
        monkeypatch.delenv("GITHUB_TOKEN")

    with pytest.raises(ValueError):
        finalize.Finalize(root, head)

    assert Git(root, "tag", "--list") == "" and len(calls) == (0 if fault == "no-token" else 1), (
        "Refusal must precede actual tag creation, without reusing or retrying gate authority")


@pytest.mark.parametrize("status,row", [(1, ""),
    (0, "=\trefs/tags/v0.3.0:refs/tags/v0.3.0\t[up to date]"),
    (0, "*\trefs/tags/v0.3.1:refs/tags/v0.3.1\t[new tag]"),
    (0, "*\trefs/tags/v0.3.0:refs/tags/v0.3.0\t[new tag]")])
def test_PushUsesOnlyBuiltinEphemeralAuthenticationAndExactNewTagAck(tmp_path, monkeypatch,
                                                                   status, row):
    """A race producing up-to-date or another ref is not a new-tag acknowledgement."""

    observed = []

    def Run(arguments, **options):
        """Capture the inert transport seam without making any network request."""

        observed.append((arguments, options))

        return SimpleNamespace(returncode=status, stdout=row)

    monkeypatch.setenv("GITHUB_TOKEN", "owned-inert-job-token")
    monkeypatch.setattr(finalize.subprocess, "run", Run)

    if status == 0 and row.startswith("*\trefs/tags/v0.3.0:"):
        finalize.PushTag(tmp_path)
    else:
        with pytest.raises(ValueError, match="acknowledged"):
            finalize.PushTag(tmp_path)

    arguments, options = observed[0]
    assert arguments == ["git", "-c", "core.fsmonitor=false", "push", "--porcelain", "origin",
        "refs/tags/v0.3.0:refs/tags/v0.3.0"], "Only the literal non-force exact refspec may push"
    assert options["timeout"] == 30 and "GITHUB_TOKEN" not in options["env"] and (
        options["env"]["GIT_CONFIG_GLOBAL"] == os.devnull
    ), "The token must only inhabit the child HTTP header, never argv, global config or files"
    assert not any("owned-inert-job-token" in value for value in arguments), (
        "Secret values cannot appear in command arguments")


@pytest.mark.parametrize("raw", ["", "0" * 40 + "\trefs/heads/foreign", "x\trefs/heads/master",
    "0" * 40 + "\trefs/heads/master\n" + "0" * 40 + "\trefs/heads/master", "x" * 4097])
def test_RemoteObservationNeverGuessesMissingRefsFromMalformedTransport(tmp_path, monkeypatch, raw):
    """Only a successfully parsed literal remote response may indicate tag absence."""

    monkeypatch.setattr(delivery, "Git", lambda *args: raw)

    if raw == "":
        assert finalize.RemoteRefs(tmp_path) == {}, "No refs still fails the required-master caller"
    else:
        with pytest.raises(ValueError):
            finalize.RemoteRefs(tmp_path)


def Workflow(name):
    """Read the actual workflow source as the authority oracle."""

    path = Path(__file__).resolve().parents[2] / ".github/workflows" / name

    return yaml.safe_load(path.read_text())


@pytest.mark.parametrize("field,value", [("GITHUB_EVENT_NAME", "push"),
    ("GITHUB_REPOSITORY", "foreign/1337"), ("GITHUB_REF", "refs/heads/develop"),
    ("GITHUB_REF", "refs/tags/v0.3.0"), ("GITHUB_RUN_ATTEMPT", "2"),
    ("SELECTED_VERSION", "0.3.1"), ("EXPECTED_MASTER_SHA", "abc")])
@pytest.mark.skipif(os.name != "posix", reason="Actual Linux workflow guards use a POSIX shell")
def test_FinalizerInlineContextGuardRefusesBeforeAnyCheckout(tmp_path, field, value):
    """Execute the actual first inline shell guard with independently controlled event facts."""

    job = Workflow("release-finalize.yml")["jobs"]["finalize"]
    environment = {"PATH": os.defpath, "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": delivery.REPOSITORY, "GITHUB_REF": "refs/heads/master",
        "GITHUB_RUN_ATTEMPT": "1", "SELECTED_VERSION": "0.3.0", "EXPECTED_MASTER_SHA": "a" * 40,
        field: value}
    result = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c",
        job["steps"][0]["run"]], cwd=tmp_path, env=environment, timeout=10, capture_output=True)
    assert result.returncode != 0 and "uses" not in job["steps"][0], (
        "Foreign/retried authority must fail before any checkout or repository-source execution")


@pytest.mark.parametrize("reference,version,status", [("refs/heads/master", "0.3.0", 1),
    ("refs/tags/v0.3.0", "0.3.0", 0), ("refs/tags/v0.3.1", "0.3.0", 1)])
@pytest.mark.skipif(os.name != "posix", reason="Actual Linux workflow guards use a POSIX shell")
def test_ManualPublisherBranchSelectionActuallyFailsPreflight(tmp_path, reference, version, status):
    """Manual branch selection is an executed failure rather than an all-skipped success."""

    preflight = Workflow("release.yml")["jobs"]["preflight"]
    environment = {"PATH": os.defpath, "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": delivery.REPOSITORY, "GITHUB_REF": reference,
        "SELECTED_VERSION": version}
    result = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c",
        preflight["steps"][0]["run"]], cwd=tmp_path, env=environment, timeout=10,
        capture_output=True)
    assert (result.returncode != 0) == bool(status) and "if" not in preflight, (
        "Only the fixed existing tag continues; refused manual branches run a failing job")


def test_FinalizerAndPublisherWorkflowAuthorityRemainSeparate():
    """No job combines tag write, dispatch write and registry OIDC authority."""

    workflow = Workflow("release-finalize.yml")
    events = workflow.get("on", workflow.get(True))
    assert set(events) == {"workflow_dispatch"} and events["workflow_dispatch"]["inputs"][
        "version"]["options"] == ["0.3.0"], "Finalization must be a fixed explicit manual action"
    jobs = workflow["jobs"]
    assert set(jobs) == {"finalize", "dispatch-existing-tag"}, "No implicit publisher belongs here"
    assert jobs["finalize"]["permissions"] == {"contents": "write", "actions": "read"} and (
        jobs["dispatch-existing-tag"]["permissions"] == {"contents": "read", "actions": "write"}
    ), "Tag creation and subsequent workflow dispatch must use different bounded job tokens"
    assert workflow["concurrency"]["cancel-in-progress"] is False and all(
        "id-token" not in job["permissions"] for job in jobs.values()
    ), "Tag creation cannot be cancelled or acquire registry publication identity"
    command = jobs["dispatch-existing-tag"]["steps"][-1]["run"]
    assert "git cat-file -t refs/tags/v0.3.0" in command and "git ls-remote --refs" in command and (
        "gh workflow run release.yml --repo Fuzzy-Technologies/1337 --ref v0.3.0 -f version=0.3.0"
        in command
    ), "Explicit continuation must use only the existing annotated current-master release tag"
    assert delivery.MASTER_JOBS["native-configuration-product.yml"] == {
        "Installed configuration product / Linux x86_64": (
            "Require eleven executed current-revision cases and original evidence",)
    }, "The actual eleven-case product gate must be required before tag creation"


@pytest.mark.parametrize("filename", ["owned-content-header-acceptance.yml",
                                      "zap-inert-acceptance.yml"])
@pytest.mark.parametrize("event,draft,marker,expected", [
    ("push", True, False, True), ("pull_request", False, False, True),
    ("pull_request", True, False, False), ("pull_request", True, True, True),
    ("workflow_dispatch", False, True, False)])
def test_ExistingAcceptanceEnrollmentPreservesDraftsAndActuallyAdmitsMaster(
    filename, event, draft, marker, expected
):
    """Evaluate each actual workflow condition, including syntax and its draft checkpoint branch."""

    workflow = Workflow(filename)
    events = workflow.get("on", workflow.get(True))
    assert events["push"] == {"branches": ["master"]} and events["pull_request"][
        "branches"] == ["develop", "master"], "Ready release PRs and stable pushes need real gates"

    required = delivery.MASTER_JOBS[filename]
    jobs = [job for job in workflow["jobs"].values() if job["name"] in required]
    assert len(jobs) == len(required), "Every named release gate must have an actual workflow job"

    for job in jobs:
        context = SimpleNamespace(event_name=event, event=SimpleNamespace(
            pull_request=SimpleNamespace(draft=draft, body=job["if"] if marker else "")))
        expression = job["if"].replace("||", "or").replace("&&", "and").replace("false", "False")
        observed = eval(expression, {"__builtins__": {}}, {
            "github": context, "contains": lambda body, text: text in body})
        assert observed is expected, (
            "Actual jobs must admit master/ready PRs and retain explicit draft guards")


@pytest.mark.parametrize("fault", [None, "event", "repository", "reference", "version", "attempt"])
def test_SourceDispatchContextRequiresTheOriginalFixedManualSelection(fault):
    """The source guard independently refuses each foreign workflow fact on every platform."""

    arguments = {"event": "workflow_dispatch", "repository": delivery.REPOSITORY,
        "reference": "refs/heads/master", "version": "0.3.0", "attempt": "1"}

    if fault:
        arguments[fault] = "foreign"

        with pytest.raises(ValueError, match="original fixed master"):
            finalize.DispatchContext(**arguments)

    else:
        assert finalize.DispatchContext(**arguments) is None, (
            "The original finite manual context must pass without mutation")


def test_RemoteObservationRetainsExactOriginalMasterAndTag(tmp_path, monkeypatch):
    """A valid original read carries both refs without synthesizing a local tag identity."""

    raw = "a" * 40 + "\trefs/heads/master\n" + "b" * 40 + "\trefs/tags/v0.3.0"
    monkeypatch.setattr(delivery, "Git", lambda *args: raw)
    assert finalize.RemoteRefs(tmp_path) == {
        "refs/heads/master": "a" * 40, "refs/tags/v0.3.0": "b" * 40
    }, "Original tag and master identities must remain distinct"


def test_PushWithoutBuiltinTokenRefusesBeforeTransport(tmp_path, monkeypatch):
    """No fallback credentials or ambient Git transport may replace the short-lived token."""

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    with pytest.raises(ValueError, match="builtin job token"):
        finalize.PushTag(tmp_path)


def test_FinalizerCliWritesOnlyOriginalAcknowledgement(tmp_path, monkeypatch, capsys):
    """The source entry point retains the acknowledged result after its context guard."""

    for key, value in {"GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": delivery.REPOSITORY, "GITHUB_REF": "refs/heads/master",
        "GITHUB_RUN_ATTEMPT": "1"}.items():
        monkeypatch.setenv(key, value)

    expected = {"schema_version": 1, "commit": "a" * 40, "version": "0.3.0"}
    monkeypatch.setattr(finalize, "Finalize", lambda root, commit: expected)
    output = tmp_path / "ack.json"
    arguments = ["--root", str(tmp_path), "--expected-master-sha", "a" * 40,
        "--version", "0.3.0", "--output", str(output)]
    assert finalize.Main(arguments) == 0 and delivery.Json(output.read_bytes()) == expected, (
        "The CLI must write only the actual completed finalizer result")
    assert '"commit"' in capsys.readouterr().out, "The successful acknowledgement must be visible"
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    refused = tmp_path / "refused.json"
    arguments[-1] = str(refused)
    assert finalize.Main(arguments) == 1 and not refused.exists(), (
        "A refused context cannot create a success acknowledgement")
    assert "refused" in capsys.readouterr().out, "Failure must remain explicit to the operator"


def test_UnconfirmedPostPushRefsRetainLocalTagAndNeverRetry(owned, monkeypatch):
    """Lost remote acknowledgement is explicit incomplete work, never repaired silently."""

    root, head, _ = owned
    pushes = []
    monkeypatch.setattr(delivery, "MasterChecks", lambda selected: {"owned": True})
    monkeypatch.setattr(finalize, "PushTag", lambda selected: pushes.append(selected))

    with pytest.raises(ValueError, match="remote tag/master acknowledgement"):
        finalize.Finalize(root, head)

    assert pushes == [root] and Git(root, "cat-file", "-t", "refs/tags/v0.3.0") == "tag", (
        "Failed acknowledgement must preserve the original attempted tag and single push")
