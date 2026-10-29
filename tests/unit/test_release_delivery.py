# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic release source, evidence and same-byte publication contracts."""

from __future__ import annotations

import copy
import io
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from tools import release_delivery as delivery

SHA = "a" * 40
TREE = "b" * 40
VERSION = "0.3.0"
SOURCE = {"schema_version": 1, "repository": delivery.REPOSITORY, "project": "1337",
    "version": VERSION, "tag": "v0.3.0", "commit": SHA, "tree": TREE,
    "tag_type": "tag", "requires_python": ">=3.11"}
SMOKE = {"version": VERSION, "state": "verified-installed-demo"}
CARD = ("## Digest\n\nA bounded installed preview.\n\n## What's Changed\n\n"
        "## Validation\n\n" + delivery.VALIDATION_MARKER + "\n\n## Breaking Changes\n\n"
        "None.\n\n## Try it from source\n\nUse the exact tag.\n\n## Notes\n\nExperimental.\n")


def SourceInputs(root, monkeypatch):
    """Create marked metadata and replace only Git observations, not source validation."""

    (root / "docs/releases").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname="1337"\nversion="0.3.0"\nrequires-python=">=3.11"\n')
    (root / "uv.lock").write_text('[[package]]\nname="1337"\nversion="0.3.0"\n')
    (root / "CHANGELOG.md").write_text("### Patch 0 — v0.3.0\n")
    (root / "docs/releases/v0.3.0.md").write_text(CARD)
    facts = {("rev-parse", "HEAD"): SHA, ("cat-file", "-t", "refs/tags/v0.3.0"): "tag",
        ("rev-parse", "refs/tags/v0.3.0^{commit}"): SHA,
        ("rev-parse", SHA + "^{commit}"): SHA,
        ("rev-parse", "refs/remotes/origin/master"): SHA,
        ("status", "--porcelain"): "", ("rev-parse", "HEAD^{tree}"): TREE}
    monkeypatch.setattr(delivery, "Git", lambda selected, *arguments: facts[arguments])

    return facts


@pytest.mark.parametrize("tag", ["0.3.0", "v0.3", "v0.3.0a1", "v00.3.0", "v0.3.0/x"])
def test_ReleaseTagGrammarRefusesAmbiguousVersions(tmp_path, tag):
    """Only the explicitly selected final numeric release scheme reaches Git or metadata I/O."""

    with pytest.raises(ValueError, match="exact vX.Y.Z"):
        delivery.SourceFacts(tmp_path, tag, SHA)


def test_AnnotatedMasterSourceKeepsExactMetadata(tmp_path, monkeypatch):
    """A clean existing annotated master tag binds package, lock, card and source identities."""

    SourceInputs(tmp_path, monkeypatch)
    assert delivery.SourceFacts(tmp_path, "v0.3.0", SHA) == SOURCE, (
        "Release source must bind exact source and version without claiming publication")


@pytest.mark.parametrize("key", ["lightweight", "tag-target", "event-target", "master", "dirty",
    "package-name", "package-version", "lock-version", "card-marker", "card-section", "changelog"])
def test_SourceIdentityAndPublicationMetadataDriftRefuse(tmp_path, monkeypatch, key):
    """Every independent source and release-document identity remains a failing gate."""

    facts = SourceInputs(tmp_path, monkeypatch)
    keys = {"lightweight": ("cat-file", "-t", "refs/tags/v0.3.0"),
        "tag-target": ("rev-parse", "refs/tags/v0.3.0^{commit}"),
        "event-target": ("rev-parse", SHA + "^{commit}"),
        "master": ("rev-parse", "refs/remotes/origin/master"),
        "dirty": ("status", "--porcelain")}

    if key in keys:
        facts[keys[key]] = "commit" if key == "lightweight" else "c" * 40

    else:
        path = tmp_path / {"package-name": "pyproject.toml", "package-version": "pyproject.toml",
            "lock-version": "uv.lock", "card-marker": "docs/releases/v0.3.0.md",
            "card-section": "docs/releases/v0.3.0.md", "changelog": "CHANGELOG.md"}[key]
        text = path.read_text()
        text = (text.replace('name="1337"', 'name="foreign"') if key == "package-name" else
            text.replace("0.3.0", "0.3.1") if "version" in key or key == "changelog" else
            text.replace(delivery.VALIDATION_MARKER, "") if key == "card-marker" else
            text.replace("## Digest", "## Summary"))
        path.write_text(text)

    with pytest.raises(ValueError):
        delivery.SourceFacts(tmp_path, "v0.3.0", SHA)


def GateInputs():
    """Freeze API-shaped master push attempts and real named-job/step requirements."""

    runs, jobs = {}, {}

    for index, (filename, required) in enumerate(delivery.MASTER_JOBS.items(), 1):
        runs[filename] = {"workflow_runs": [{"id": index, "run_number": 5, "run_attempt": 2,
            "event": "push", "head_branch": "master", "head_sha": SHA,
            "head_repository": {"full_name": delivery.REPOSITORY},
            "path": ".github/workflows/" + filename, "status": "completed",
            "conclusion": "success"}]}
        rows = [{"name": name, "status": "completed", "conclusion": "success", "steps": [
            {"name": step, "status": "completed", "conclusion": "success"}
            for step in expected or ("Actual deployment",)]} for name, expected in required.items()]
        jobs[index] = {"total_count": len(rows), "jobs": rows}

    def Fetch(path):
        """Return only the exact requested workflow attempt or its job list."""

        if "/workflows/" in path:
            return runs[path.split("/workflows/")[1].split("/")[0]]

        return jobs[int(path.split("/runs/")[1].split("/")[0])]

    return runs, jobs, Fetch


def test_MasterEvidenceUsesActualNamedJobsAndCurrentAttempt():
    """Allow unrelated skipped diagnostics without credit for actual required execution."""

    _, jobs, fetch = GateInputs()
    jobs[1]["jobs"].append({"name": "Optional diagnostic", "conclusion": "skipped"})
    jobs[1]["total_count"] += 1
    evidence = delivery.MasterChecks(SHA, fetch)
    assert evidence["commit"] == SHA and len(evidence["accepted_workflows"]) == 6, (
        "Master acceptance must retain each exact successful workflow attempt")
    assert len(evidence["accepted_workflows"][0]["jobs"]) == 8, (
        "Skipped diagnostics must never count as required successful jobs")


@pytest.mark.parametrize("fault", ["missing-run", "older-success", "wrong-commit", "fork", "pr",
    "develop", "wrong-file", "pending", "failed", "bool-id", "missing-job", "skip-job",
    "failed-job", "missing-step", "skip-step", "empty-steps", "incomplete-page", "bool-count"])
def test_MasterEvidenceRejectsMissingSkippedOrForeignExecution(fault):
    """Old green summaries and skipped jobs/steps cannot establish release acceptance."""

    runs, jobs, fetch = GateInputs()
    run = runs["python-quality.yml"]["workflow_runs"][0]
    job = jobs[1]["jobs"][0]

    if fault == "missing-run":
        runs["python-quality.yml"]["workflow_runs"] = []

    elif fault == "older-success":
        latest = copy.deepcopy(run)
        latest.update(run_number=6, conclusion="failure")
        runs["python-quality.yml"]["workflow_runs"].append(latest)

    elif fault in {"wrong-commit", "pr", "develop", "wrong-file", "pending", "failed", "bool-id"}:
        key, value = {"wrong-commit": ("head_sha", "d" * 40), "pr": ("event", "pull_request"),
            "develop": ("head_branch", "develop"), "wrong-file": ("path", "foreign.yml"),
            "pending": ("status", "in_progress"), "failed": ("conclusion", "failure"),
            "bool-id": ("id", True)}[fault]
        run[key] = value

    elif fault == "fork":
        run["head_repository"]["full_name"] = "foreign/1337"

    elif fault == "missing-job":
        job["name"] = "A different successful job"

    elif fault in {"skip-job", "failed-job"}:
        job["conclusion"] = "skipped" if fault == "skip-job" else "failure"

    elif fault == "missing-step":
        job["steps"][0]["name"] = "No actual quality gate"

    elif fault == "skip-step":
        job["steps"][0]["conclusion"] = "skipped"

    elif fault == "empty-steps":
        job["steps"] = []

    else:
        jobs[1]["total_count"] = True if fault == "bool-count" else 1000

    with pytest.raises(ValueError):
        delivery.MasterChecks(SHA, fetch)


def Distributions(root, *, version=VERSION, wheel_version=None, sdist_name="1337",
                  duplicate=False):
    """Build tiny marked metadata archives; these are never installed or uploaded."""

    root.mkdir()
    wheel = root / f"1337-{version}-py3-none-any.whl"
    metadata = f"Name: 1337\nVersion: {wheel_version or version}\nRequires-Python: >=3.11\n"

    with zipfile.ZipFile(wheel, "w") as archive:
        name = f"1337-{version}.dist-info/METADATA"
        archive.writestr(name, metadata)

        if duplicate:
            with pytest.warns(UserWarning, match="Duplicate name"):
                archive.writestr(name, metadata)

    with tarfile.open(root / f"1337-{version}.tar.gz", "w:gz") as archive:
        raw = f"Name: {sdist_name}\nVersion: {version}\nRequires-Python: >=3.11\n".encode()
        member = tarfile.TarInfo(f"1337-{version}/PKG-INFO")
        member.size = len(raw)
        archive.addfile(member, io.BytesIO(raw))


def Bundle(root):
    """Seal one finite synthetic artifact handoff with actual-shaped source evidence."""

    root.mkdir()
    Distributions(root / "dist")
    _, _, fetch = GateInputs()

    return delivery.Seal(root, SOURCE, delivery.MasterChecks(SHA, fetch), SMOKE, CARD.encode())


def test_ReleaseHandoffKeepsOriginalDistributionMetadataAndByteDigests(tmp_path):
    """One sealed producer handoff verifies without rebuilding its two distribution archives."""

    root = tmp_path / "bundle"
    receipt = Bundle(root)
    manifest = delivery.Verify(root, receipt["checksums_sha256"])
    assert manifest["source"] == SOURCE and len(manifest["files"]) == 7, (
        "The manifest must retain exact distributions, source, installed and validation evidence")
    assert delivery.VALIDATION_MARKER not in (root / "RELEASE_NOTES.md").read_text(), (
        "Published notes must contain actual master validation links rather than a draft marker")
    assert "named execution jobs passed" in (root / "RELEASE_NOTES.md").read_text(), (
        "The release card must name the exact accepted master workflow evidence")


@pytest.mark.parametrize("fault", ["changed-wheel", "extra", "missing", "checksums", "hash",
    "manifest", "symlink", "hidden", "hardlink"])
def test_HandoffVerificationRefusesTamperAndUnlistedMaterial(tmp_path, fault):
    """The independent producer digest and closed inventory bind every handed-off byte."""

    root = tmp_path / "bundle"
    receipt = Bundle(root)

    if fault == "changed-wheel":
        (root / "dist/1337-0.3.0-py3-none-any.whl").write_bytes(b"changed")

    elif fault in {"extra", "hidden"}:
        (root / ("extra.txt" if fault == "extra" else ".hidden")).write_text("unlisted")

    elif fault == "missing":
        (root / "source.json").unlink()

    elif fault == "checksums":
        (root / "SHA256SUMS").write_text("foreign checksum list")

    elif fault == "manifest":
        (root / "release-manifest.json").write_text("{}")

    elif fault == "symlink":
        (root / "linked").symlink_to(root / "source.json")

    elif fault == "hardlink":
        (root / "linked").hardlink_to(root / "source.json")

    else:
        receipt["checksums_sha256"] = "0" * 64

    with pytest.raises(ValueError):
        delivery.Verify(root, receipt["checksums_sha256"])


@pytest.mark.parametrize("fault", ["wheel-version", "sdist-name", "duplicate", "python"])
def test_DistributionMetadataMustMatchTheAnnotatedRelease(tmp_path, fault):
    """Labels and archive filenames cannot substitute for exact original distribution headers."""

    root = tmp_path / "dist"
    Distributions(root, wheel_version="0.2.1" if fault == "wheel-version" else VERSION,
        sdist_name="foreign" if fault == "sdist-name" else "1337", duplicate=fault == "duplicate")

    with pytest.raises(ValueError):
        delivery.DistributionMetadata(root, VERSION, ">=3.12" if fault == "python" else ">=3.11")


def IndexInstall(manifest):
    """Describe a marked public-index pip report whose artifact hash is independently known."""

    digest = manifest["files"]["dist/1337-0.3.0-py3-none-any.whl"]["sha256"]

    return {"source": "pypi", "state": "verified-installed-demo", "version": VERSION,
        "pip_install": {"install": [{"metadata": {"name": "1337", "version": VERSION},
            "download_info": {"url": "https://files.pythonhosted.org/packages/owned/package.whl",
                "archive_info": {"hashes": {"sha256": digest}}}}]}}


@pytest.mark.parametrize("fault", [None, "local", "version", "multiple", "digest", "http",
    "foreign-host", "credentials", "query"])
def test_PostPyPIInstallRequiresOriginalWheelAndPublicIndex(tmp_path, fault):
    """A clean installed version alone cannot authenticate which wheel PyPI actually supplied."""

    root = tmp_path / "bundle"
    receipt = Bundle(root)
    manifest = delivery.Verify(root, receipt["checksums_sha256"])
    smoke = IndexInstall(manifest)
    package = smoke["pip_install"]["install"][0]

    if fault == "local":
        smoke["source"] = "local-wheel"

    elif fault == "version":
        package["metadata"]["version"] = "0.2.1"

    elif fault == "multiple":
        smoke["pip_install"]["install"].append(copy.deepcopy(package))

    elif fault == "digest":
        package["download_info"]["archive_info"]["hashes"]["sha256"] = "0" * 64

    elif fault is not None:
        package["download_info"]["url"] = {
            "http": "http://files.pythonhosted.org/packages/file.whl",
            "foreign-host": "https://foreign.invalid/packages/file.whl",
            "credentials": "https://user:synthetic@files.pythonhosted.org/packages/file.whl",
            "query": "https://files.pythonhosted.org/packages/file.whl?different=1"}[fault]

    if fault is None:
        delivery.VerifyIndexInstall(smoke, manifest)

    else:
        with pytest.raises(ValueError):
            delivery.VerifyIndexInstall(smoke, manifest)


@pytest.mark.parametrize("raw", [b"", b"{}" * 2, b"[]", b'{"a":1,"a":2}', b'{"x":NaN}',
                                b"x" * (delivery.MAX_JSON_BYTES + 1)],
    ids=("empty", "two-objects", "array", "duplicate", "nan", "oversized"))
def test_StrictReleaseJsonRefusesAmbiguousOrUnboundedData(raw):
    """Public release metadata cannot hide overwritten identities or unbounded decoder inputs."""

    with pytest.raises((ValueError, json.JSONDecodeError)):
        delivery.Json(raw)


def test_ReleaseApiRequiresExactRepositoryAndNoRedirects(monkeypatch):
    """A fake read token never leaves the fixed repository route or follows redirects."""

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    with pytest.raises(ValueError, match="read-only GitHub token"):
        delivery.GitHubJson("/repos/Fuzzy-Technologies/1337/actions/runs")

    with pytest.raises(ValueError, match="this repository"):
        delivery.GitHubJson("/repos/foreign/1337/actions/runs")

    with pytest.raises(ValueError, match="redirects"):
        delivery.NoRedirect().redirect_request(None, None, 302, None, None, "https://foreign")


def test_WriteAndInvokeRetainNoClobberAndActualExitStatus(tmp_path, monkeypatch):
    """Release metadata refuses replacement and unexpected installed-command failure."""

    path = tmp_path / "new.json"
    delivery.WriteJson(path, {"actual": True})

    with pytest.raises(FileExistsError):
        delivery.WriteJson(path, {})

    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=4))

    with pytest.raises(ValueError, match="unexpected exit"):
        delivery.Invoke(("inert",), tmp_path)

    retained = json.loads((tmp_path / "commands.jsonl").read_text())
    assert retained["argv"] == ["inert"] and retained["exit_code"] == 4, (
        "Even a rejected command must retain its exact invocation and actual exit status")


def SmokeCommands(root, monkeypatch, fault=None):
    """Provide deterministic CLI-shaped outputs; never claim these fixtures are real installs."""

    commands = []

    def Invoke(arguments, cwd, expected=0):
        """Emulate only the fixed bounded installed command family and its owned files."""

        commands.append((arguments, expected))
        response = ""

        if "install" in arguments:
            delivery.WriteJson(root / "pip-install.json", {"install": []})

        elif arguments[-1] == "--version":
            response = "1337 " + ("0.2.1" if fault == "version" else VERSION)

        elif "demo" in arguments:
            if expected == 3:
                response = json.dumps({"state": "denied", "failure": "approval_required"})

                if fault == "planning-created-root":
                    (root / "demo").mkdir()

            elif expected == 0:
                (root / "demo/reports").mkdir(parents=True)
                (root / "demo/reports/model.json").write_bytes(b'{"original":true}')
                response = json.dumps({"state": "completed",
                    "target_teardown_completed": fault != "teardown"})

            elif fault == "clobber":
                (root / "demo/reports/model.json").write_bytes(b"changed")

        elif "workspace" in arguments:
            response = json.dumps({"model_revision": 2 if fault == "revision" else 3})

        elif "export" in arguments:
            (root / "reopened.json").write_bytes(
                b"different" if fault == "export" else b'{"original":true}')

        return SimpleNamespace(stdout=response, returncode=expected)

    monkeypatch.setattr(delivery, "Invoke", Invoke)

    return commands


@pytest.mark.parametrize("local", [True, False], ids=("wheel", "index"))
def test_InstalledSmokeDeclaresIsolatedInputsAndChecksActualOutputs(tmp_path, monkeypatch, local):
    """The smoke coordinator fixes install provenance, approval, reopen and no-clobber checks."""

    root = tmp_path / "owned-install"
    commands = SmokeCommands(root, monkeypatch)
    wheel = tmp_path / "1337-0.3.0-py3-none-any.whl" if local else None
    result = delivery.Smoke(root, VERSION, wheel)
    assert result["state"] == "verified-installed-demo" and result["model_revision"] == 3, (
        "The result must be derived from the checked installed command outputs")
    assert result["source"] == ("local-wheel" if local else "pypi"), (
        "Local wheel validation and public index validation must remain distinct")
    installer = commands[1][0]
    assert "--isolated" in installer and "--no-deps" in installer and (
        "--no-cache-dir" in installer and installer[installer.index("--retries") + 1] == "0"
    ), "The clean install must avoid ambient pip settings, dependencies, cache and hidden retries"
    assert ("--no-index" in installer) is local and (
        installer[-1] == (str(wheel) if local else "1337==0.3.0")
    ), "The exact local artifact or exact public release version must be selected"
    assert len(commands) == 10 and commands[5][1] == 3 and commands[-1][1] == 2, (
        "Planning refusal and existing-root refusal must be required actual outcomes")


@pytest.mark.parametrize("fault", ["version", "planning-created-root", "teardown", "revision",
                                  "export", "clobber"])
def test_InstalledSmokeRefusesBrokenProductOutcomes(tmp_path, monkeypatch, fault):
    """No installed version, target cleanup, revision, report or no-clobber error becomes green."""

    root = tmp_path / "owned-install"
    SmokeCommands(root, monkeypatch, fault)

    with pytest.raises(ValueError):
        delivery.Smoke(root, VERSION)


def test_InstalledSmokeRefusesExistingRootAndInvalidVersion(tmp_path):
    """A rerun never resets an existing install root or broadens the selected version."""

    with pytest.raises(ValueError, match="new owned directory"):
        delivery.Smoke(tmp_path, VERSION)

    with pytest.raises(ValueError, match="exact version"):
        delivery.Smoke(tmp_path / "missing", "0.3.0a1")


def test_ReleaseWorkflowSeparatesBuildRegistryAndGitHubAuthority():
    """The actual workflow never publishes from PRs, rebuilds after approval or shares OIDC."""

    root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load((root / ".github/workflows/release.yml").read_text())
    events = workflow.get("on", workflow.get(True))
    assert events == {"push": {"tags": ["v*"]}}, "Only an existing tag push may publish"
    assert workflow["permissions"] == {"contents": "read"}, "Default authority must be read-only"
    assert workflow["concurrency"]["cancel-in-progress"] is False, (
        "An in-progress registry upload must not be cancelled by a later same-tag attempt")
    jobs = workflow["jobs"]
    assert set(jobs) == {"build", "publish-pypi", "verify-pypi", "github-release"}, (
        "One build, upload, actual-index verification and release publication boundary is required")
    assert jobs["build"]["permissions"] == {"contents": "read", "actions": "read"}, (
        "Build and master acceptance must have no publication token")
    publish = jobs["publish-pypi"]
    assert publish["needs"] == "build" and publish["permissions"] == {"id-token": "write"}, (
        "Only the separate publisher may obtain the project-bound OIDC identity")
    assert publish["environment"] == {"name": "pypi", "url": "https://pypi.org/p/1337"}, (
        "PyPI-side publisher configuration must name the exact protected workflow environment")
    assert len(publish["steps"]) == 3 and all("checkout" not in str(step.get("uses", ""))
        for step in publish["steps"]), "The OIDC job cannot build, install or check out source"
    action = publish["steps"][-1]
    assert action["uses"] == (
        "pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e"
    ) and action["with"] == {"packages-dir": "release-bundle/dist/", "attestations": True,
        "skip-existing": False, "verify-metadata": True}, (
        "The checksum-pinned publisher must attest exact artifacts and refuse existing versions")
    assert jobs["verify-pypi"]["needs"] == ["build", "publish-pypi"] and (
        jobs["github-release"]["needs"] == ["build", "verify-pypi"]
    ), "GitHub release publication must wait for actual PyPI clean-install verification"
    assert jobs["github-release"]["permissions"] == {"contents": "write"}, (
        "GitHub asset publication has no PyPI OIDC or unrelated write privilege")
    command = jobs["github-release"]["steps"][-1]["run"]
    assert "gh release create" in command and "--verify-tag" in command and "--latest" in (
        command), "GitHub publication must reuse the existing verified tag without update semantics"


@pytest.mark.parametrize("command", ["source", "gates", "smoke", "seal", "verify", "verify-index"])
def test_ReleaseCliDispatchKeepsExplicitOwnedInputs(tmp_path, monkeypatch, command):
    """The CLI dispatches only the declared finite operation and writes a new result."""

    for name in ("source", "checks", "smoke"):
        delivery.WriteJson(tmp_path / (name + ".json"), {"inert": True})

    (tmp_path / "card.md").write_text(CARD)
    expected = {"observed": command}
    monkeypatch.setattr(delivery, "SourceFacts", lambda *args: expected)
    monkeypatch.setattr(delivery, "MasterChecks", lambda *args: expected)
    monkeypatch.setattr(delivery, "Smoke", lambda *args: expected)
    monkeypatch.setattr(delivery, "Seal", lambda *args: expected)
    monkeypatch.setattr(delivery, "Verify", lambda *args: expected)
    monkeypatch.setattr(delivery, "VerifyIndexInstall", lambda *args: None)
    output = tmp_path / "output.json"
    assert delivery.Main([command, "--root", str(tmp_path), "--source",
        str(tmp_path / "source.json"), "--checks", str(tmp_path / "checks.json"), "--smoke",
        str(tmp_path / "smoke.json"), "--card", str(tmp_path / "card.md"), "--output",
        str(output)]) == 0, "The finite command must report its actual successful dispatch"
    assert json.loads(output.read_bytes()) == expected, "The retained result must match dispatch"
