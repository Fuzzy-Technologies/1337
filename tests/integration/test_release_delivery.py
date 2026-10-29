# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise the actual release installer against an original locally built distribution."""

import json
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from tools import release_delivery as delivery

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_ReleaseCleanWheelInstallRunsOwnedDemoAndReopensOriginalModel(tmp_path):
    """Build a real wheel and run the release coordinator outside the source checkout."""

    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    version = project["version"]
    distributions = tmp_path / "dist"
    result = subprocess.run((sys.executable, "-m", "build", "--no-isolation", "--outdir",
        str(distributions)), cwd=ROOT, capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    metadata = delivery.DistributionMetadata(distributions, version, project["requires-python"])
    receipt = delivery.Smoke(tmp_path / "installed", version,
        distributions / f"1337-{version}-py3-none-any.whl")
    commands = [json.loads(line) for line in
        (tmp_path / "installed/commands.jsonl").read_text().splitlines()]
    assert metadata["artifacts"] == ["sdist", "wheel"], (
        "Both original archives must retain their actual package metadata")
    assert receipt["state"] == "verified-installed-demo" and receipt["source"] == "local-wheel", (
        "Only actual successful clean installation and owned demo outcomes can pass")
    assert receipt["demo"]["target_teardown_completed"] is True, (
        "The installed demo must verify target teardown before recording success")
    assert len(commands) == 10 and all(item["exit_code"] == item["expected_exit_code"]
                                     for item in commands), (
        "Every actual installed command must preserve its original invocation and exit status")
    assert receipt["pip_install"]["install"][0]["metadata"]["version"] == version, (
        "The real clean environment must install the selected original wheel version")


@pytest.mark.integration
def test_ActualGitTagMustBeAnnotatedCleanAndOnCurrentMaster(tmp_path):
    """Validate actual Git object types and source refs in an isolated fixture repository."""

    root = tmp_path / "fixture-source"
    (root / "docs/releases").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname="1337"\nversion="0.3.0"\nrequires-python=">=3.11"\n')
    (root / "uv.lock").write_text('[[package]]\nname="1337"\nversion="0.3.0"\n')
    (root / "CHANGELOG.md").write_text("### Patch 0 — v0.3.0\n")
    card = "\n".join(("## Digest", "## What's Changed", "## Validation",
        delivery.VALIDATION_MARKER, "## Breaking Changes", "## Try it from source", "## Notes"))
    (root / "docs/releases/v0.3.0.md").write_text(card)
    arguments = ("git", "-c", "user.name=Release Fixture", "-c",
        "user.email=release-fixture@example.invalid", "-c", "commit.gpgsign=false", "-c",
        "tag.gpgsign=false", "-c", "core.hooksPath=" + str(tmp_path / "no-hooks"))

    for operation in (("init", "--initial-branch=master"), ("add", "."),
                      ("commit", "-m", "Marked release fixture")):
        subprocess.run((*arguments, *operation), cwd=root, capture_output=True, check=True,
                       timeout=30)

    commit = delivery.Git(root, "rev-parse", "HEAD")

    for operation in (("update-ref", "refs/remotes/origin/master", commit),
                      ("tag", "-a", "v0.3.0", "-m", "Marked annotated fixture")):
        subprocess.run((*arguments, *operation), cwd=root, capture_output=True, check=True,
                       timeout=30)

    facts = delivery.SourceFacts(root, "v0.3.0", commit)
    assert facts["commit"] == commit and facts["tag_type"] == "tag", (
        "Actual annotated objects, clean tracked source and exact master must agree")
    (root / "untracked.txt").write_text("Marked dirty source")

    with pytest.raises(ValueError, match="clean checkout"):
        delivery.SourceFacts(root, "v0.3.0", commit)

    (root / "untracked.txt").unlink()
    subprocess.run((*arguments, "tag", "-d", "v0.3.0"), cwd=root, check=True,
                   capture_output=True, timeout=30)
    subprocess.run((*arguments, "tag", "v0.3.0"), cwd=root, check=True,
                   capture_output=True, timeout=30)

    with pytest.raises(ValueError, match="Release tag"):
        delivery.SourceFacts(root, "v0.3.0", commit)
