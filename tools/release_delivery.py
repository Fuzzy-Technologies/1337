# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bind release source, executed master gates and immutable distribution handoffs.

This tool never creates a tag, grants publication authority or uploads a package.
The reviewed release workflow owns its separate PyPI and GitHub publication jobs.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tomllib
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable
from email.parser import BytesParser
from pathlib import Path

REPOSITORY = "Fuzzy-Technologies/1337"
PROJECT = "1337"
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
COMMIT = re.compile(r"[a-f0-9]{40}\Z")
VALIDATION_MARKER = "<!-- RELEASE_VALIDATION -->"
MASTER_JOBS = {
    "python-quality.yml": {
        **{f"Python {python} / {system}": ("Run repository quality gate",)
           for python, system in (("3.11", "ubuntu-24.04"), ("3.14", "ubuntu-24.04"),
                                  ("3.12", "windows-2022"), ("3.13", "macos-15"))},
        "Offline browser page acceptance": (
            "Verify real browser descendant cancellation and timeout",
            "Verify real offline DOM and original source custody"),
        "Container configuration and quality": ("Run container quality gate",),
        "Synthetic lab lifecycle": (
            "Verify safe target contract", "Verify attack-path mini lifecycle"),
        "Pinned external target regression": (
            "Execute installed native scanner against three fresh pinned targets",
            "Execute one target-free installed Nuclei prerequisite",
            "Require original target-free Nuclei prerequisite evidence"),
    },
    "documentation.yml": {
        "deterministic-documentation": (
            "Build a reproducible static reference from a clean installed wheel",
            "Compose and verify the single Pages artifact"),
        "deploy-pages": (),
    },
    "nmap-acceptance.yml": {"Nmap 7.992 / owned TCP-connect product": (
        "Execute genuine SDK and installed CLI against pytest-owned loopback only",)},
    "nuclei-acceptance.yml": {"Nuclei 3.4.10 / owned loopback": (
        "Execute genuine provider against pytest-owned loopback only",)},
    "trivy-acceptance.yml": {"Trivy 0.75.0 / owned offline archive": (
        "Run genuine adapter acceptance with no external network interface or route",
        "Require executed native configuration compatibility evidence")},
    "native-configuration-material.yml": {"Installed read helper / Linux x86_64": (
        "Require four executed cases and original bounded receipts",)},
}


def Json(raw: bytes) -> dict:
    """Decode one bounded strict object without duplicate keys or nonfinite constants.

    Args:
        raw: Original UTF-8 JSON bytes with a finite size limit.
    Returns:
        The unambiguous decoded metadata object.
    """

    def Pairs(values):
        """Reject duplicate object members before they can overwrite a release identity."""

        result = {}

        for key, value in values:
            if key in result:
                raise ValueError("Release JSON repeats a key")

            result[key] = value

        return result

    def Constant(value):
        """Reject JSON extensions that cannot identify a reproducible release."""

        raise ValueError("Release JSON contains a nonfinite constant")

    if type(raw) is not bytes or not 0 < len(raw) <= MAX_JSON_BYTES:
        raise ValueError("Release JSON exceeds its finite byte limit")

    value = json.loads(raw, object_pairs_hook=Pairs, parse_constant=Constant)

    if type(value) is not dict:
        raise ValueError("Release JSON must be an object")

    return value


def WriteJson(path: Path, value: dict) -> None:
    """Create new canonical public release metadata without replacing existing evidence.

    Args:
        path: New owned output file, which must not already exist.
        value: Finite public metadata to serialize canonically.
    """

    with path.open("xb") as output:
        output.write((json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode())


def Read(path: Path, maximum: int = MAX_FILE_BYTES) -> bytes:
    """Read one bounded ordinary singly linked file without observed symbolic aliases.

    Args:
        path: Original material whose observed ancestry must not contain symlinks.
        maximum: Inclusive finite byte limit.
    Returns:
        Original bytes matching the observed ordinary file size.
    """

    for component in (*reversed(path.absolute().parents), path.absolute()):
        metadata = component.lstat()

        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("Release material cannot traverse symbolic links")

    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or not (
        0 <= metadata.st_size <= maximum
    ):
        raise ValueError("Release material must be a bounded singly linked ordinary file")

    with path.open("rb") as source:
        raw = source.read(maximum + 1)

    if len(raw) != metadata.st_size or len(raw) > maximum:
        raise ValueError("Release material changed or exceeded its byte limit")

    return raw


def Git(root: Path, *arguments: str) -> str:
    """Run a bounded read-only Git command with literal arguments and retained failure status.

    Args:
        root: Reviewed source checkout.
        *arguments: Explicit read-only Git operation and operands.
    Returns:
        Stripped standard output after successful completion.
    """

    return subprocess.run(("git", "-c", "core.fsmonitor=false", *arguments), cwd=root,
        check=True, capture_output=True, text=True, timeout=30).stdout.strip()


def SourceFacts(root: Path, tag: str, event_sha: str) -> dict:
    """Require an existing annotated final-version tag on the exact current master commit.

    Args:
        root: Clean reviewed source checkout with complete tag and master refs.
        tag: Exact existing annotated vX.Y.Z tag.
        event_sha: Full commit or annotated-tag identity from the push event.
    Returns:
        Validated package, source, tree and tag identities.
    """

    version = tag.removeprefix("v")

    if tag != "v" + version or VERSION.fullmatch(version) is None or (
        COMMIT.fullmatch(event_sha) is None
    ):
        raise ValueError("Release requires an exact vX.Y.Z tag and full event SHA")

    head = Git(root, "rev-parse", "HEAD")

    if Git(root, "cat-file", "-t", "refs/tags/" + tag) != "tag" or (
        Git(root, "rev-parse", "refs/tags/" + tag + "^{commit}") != head
        or Git(root, "rev-parse", event_sha + "^{commit}") != head
        or Git(root, "rev-parse", "refs/remotes/origin/master") != head
        or Git(root, "status", "--porcelain")
    ):
        raise ValueError("Release tag, event, clean checkout and current master must agree")

    project = tomllib.loads(Read(root / "pyproject.toml").decode())["project"]
    lock = tomllib.loads(Read(root / "uv.lock").decode())
    locked = [item for item in lock["package"] if item["name"] == PROJECT]
    card = Read(root / "docs/releases" / (tag + ".md")).decode()

    if project["name"] != PROJECT or project["version"] != version or len(locked) != 1 or (
        locked[0]["version"] != version or card.count(VALIDATION_MARKER) != 1
        or not all(section in card for section in (
            "## Digest", "## What's Changed", "## Validation", "## Breaking Changes",
            "## Try it from source", "## Notes"))
        or f"v{version}" not in Read(root / "CHANGELOG.md").decode()
    ):
        raise ValueError("Release package, lock, changelog and structured release card must agree")

    return {"schema_version": 1, "repository": REPOSITORY, "project": PROJECT,
        "version": version, "tag": tag, "commit": head,
        "tree": Git(root, "rev-parse", "HEAD^{tree}"), "tag_type": "tag",
        "requires_python": project["requires-python"]}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Prevent authorization-bearing release API requests from following redirects."""

    def redirect_request(self, request: object, source: object, code: int, message: object,
                         headers: object, new_url: str) -> None:
        """Refuse redirects rather than forwarding a job token to another destination.

        Args:
            request: Original urllib request, never forwarded.
            source: Original response stream.
            code: Redirect status supplied by urllib.
            message: Original redirect status description.
            headers: Original response headers.
            new_url: Unadmitted redirect destination.
        """

        raise ValueError("Release API redirects are unadmitted")


def GitHubJson(path: str) -> dict:
    """Read only the fixed repository API using the runner's short-lived read token.

    Args:
        path: Fixed-repository Actions API path with bounded query parameters.
    Returns:
        Original bounded and unambiguous API response object.
    """

    if not path.startswith("/repos/" + REPOSITORY + "/actions/") or any(
        value in path for value in ("..", "\\", "\r", "\n", "#")
    ):
        raise ValueError("Release API path must address this repository's Actions evidence")

    token = os.environ.get("GITHUB_TOKEN")

    if not token:
        raise ValueError("Release master evidence needs the runner's read-only GitHub token")

    request = urllib.request.Request("https://api.github.com" + path, headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"})

    with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
        return Json(response.read(MAX_JSON_BYTES + 1))


def MasterChecks(commit: str, fetch: Callable[[str], dict] = GitHubJson) -> dict:
    """Require named executed jobs and steps from each latest exact-master push attempt.

    Args:
        commit: Exact full master source SHA selected for the release.
        fetch: Read-only fixed-repository API transport.
    Returns:
        Accepted workflow attempt identities and their required actual jobs.
    """

    if COMMIT.fullmatch(commit) is None:
        raise ValueError("Master evidence requires one full commit SHA")

    accepted = []

    for filename, required in MASTER_JOBS.items():
        query = urllib.parse.urlencode({"head_sha": commit, "event": "push",
                                       "branch": "master", "per_page": 100})
        value = fetch(f"/repos/{REPOSITORY}/actions/workflows/{filename}/runs?{query}")
        runs = value["workflow_runs"]

        if not runs or len(runs) > 100 or any(type(run["run_number"]) is not int for run in runs):
            raise ValueError("Required master workflow evidence is missing or ambiguous")

        run = max(runs, key=lambda item: item["run_number"])

        if (run["event"] != "push" or run["head_branch"] != "master"
            or run["head_sha"] != commit or run["head_repository"]["full_name"] != REPOSITORY
            or run["path"] != ".github/workflows/" + filename
            or run["status"] != "completed" or run["conclusion"] != "success"
            or type(run["id"]) is not int or type(run["run_attempt"]) is not int
            or run["id"] <= 0 or run["run_attempt"] <= 0):
            raise ValueError("Required exact-master push workflow has not succeeded")

        jobs = fetch(f"/repos/{REPOSITORY}/actions/runs/{run['id']}/attempts/"
                     f"{run['run_attempt']}/jobs?per_page=100")

        if type(jobs["total_count"]) is not int or jobs["total_count"] != len(jobs["jobs"]):
            raise ValueError("Master job evidence must be complete within one bounded page")

        for name, required_steps in required.items():
            matches = [job for job in jobs["jobs"] if job["name"] == name]

            if len(matches) != 1 or matches[0]["status"] != "completed" or (
                matches[0]["conclusion"] != "success"
            ):
                raise ValueError("A required named master job is absent, skipped or unsuccessful")

            steps = matches[0]["steps"]

            if not any(step["status"] == "completed" and step["conclusion"] == "success"
                       for step in steps) or any(not any(
                step["name"] == expected and step["status"] == "completed"
                and step["conclusion"] == "success" for step in steps)
                for expected in required_steps):
                raise ValueError("Required actual master execution steps have not succeeded")

        accepted.append({"workflow": filename, "run_id": run["id"],
            "attempt": run["run_attempt"], "jobs": sorted(required),
            "url": f"https://github.com/{REPOSITORY}/actions/runs/{run['id']}"})

    return {"schema_version": 1, "commit": commit, "event": "push", "branch": "master",
            "accepted_workflows": accepted}


def Inventory(root: Path) -> dict[str, dict]:
    """Inventory only finite ordinary bundle files; reject hidden paths and unreviewed entries.

    Args:
        root: Owned original bundle or retained demo directory.
    Returns:
        Relative names mapped to original sizes and SHA-256 identities.
    """

    result = {}

    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)

        if path.is_symlink() or any(part.startswith(".") for part in relative.parts):
            raise ValueError("Release bundle cannot contain aliases or hidden files")

        if path.is_dir():
            continue

        raw = Read(path)
        result[relative.as_posix()] = {"size_bytes": len(raw),
                                      "sha256": hashlib.sha256(raw).hexdigest()}

    return result


def DistributionMetadata(directory: Path, version: str, requires_python: str) -> dict:
    """Read bounded original wheel/sdist metadata without extraction or importing package code.

    Args:
        directory: Owned directory containing both original distributions.
        version: Exact final source version required in both archives.
        requires_python: Exact reviewed source Python compatibility declaration.
    Returns:
        Matching distribution metadata without importing or extracting content.
    """

    wheel = directory / f"{PROJECT}-{version}-py3-none-any.whl"
    sdist = directory / f"{PROJECT}-{version}.tar.gz"
    texts = {}

    with zipfile.ZipFile(io.BytesIO(Read(wheel))) as archive:
        members = [item for item in archive.infolist()
                   if item.filename == f"{PROJECT}-{version}.dist-info/METADATA"]

        if len(members) != 1 or not 0 < members[0].file_size <= 262144:
            raise ValueError("Release wheel requires one bounded original METADATA")

        with archive.open(members[0]) as source:
            texts["wheel"] = source.read(262145)

    with tarfile.open(fileobj=io.BytesIO(Read(sdist)), mode="r:gz") as archive:
        members = []
        total = 0

        for index, item in enumerate(archive):
            total += item.size

            if index >= 4096 or not 0 <= item.size <= MAX_FILE_BYTES or total > 2 * MAX_FILE_BYTES:
                raise ValueError("Release sdist inventory exceeds its finite member/byte budgets")

            if item.name == f"{PROJECT}-{version}/PKG-INFO":
                members.append(item)

        if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size <= 262144:
            raise ValueError("Release sdist requires one bounded regular original PKG-INFO")

        source = archive.extractfile(members[0])

        if source is None:
            raise ValueError("Release sdist metadata is unavailable")

        with source:
            texts["sdist"] = source.read(262145)

    expected = {"Name": PROJECT, "Version": version, "Requires-Python": requires_python}

    for raw in texts.values():
        metadata = BytesParser().parsebytes(raw)

        if len(raw) > 262144 or any(metadata.get_all(key) != [value]
                                   for key, value in expected.items()):
            raise ValueError("Release distribution metadata differs from its annotated source")

    return {"schema_version": 1, "project": PROJECT, "version": version,
            "requires_python": requires_python, "artifacts": sorted(texts)}


def Seal(root: Path, source: dict, checks: dict, smoke: dict, card: bytes) -> dict:
    """Seal original distributions and actual evidence without rebuilding or relabeling bytes.

    Args:
        root: New owned bundle containing only the original dist directory.
        source: Validated annotated source identities.
        checks: Actual accepted master job evidence.
        smoke: Actual checked clean local-wheel installation result.
        card: Reviewed release card with one validation marker.
    Returns:
        Independent checksum-file and manifest hashes for the immutable handoff.
    """

    version = source["version"]
    expected = {f"{PROJECT}-{version}.tar.gz", f"{PROJECT}-{version}-py3-none-any.whl"}

    names = set(path.name for path in (root / "dist").iterdir())

    if VERSION.fullmatch(version) is None or names != expected or (
        set(root.iterdir()) != {root / "dist"} or checks["commit"] != source["commit"] or
        smoke["version"] != version or smoke["state"] != "verified-installed-demo"
    ):
        raise ValueError("Release sealing needs exact distributions and matching actual evidence")

    metadata = DistributionMetadata(root / "dist", version, source["requires_python"])

    if card.decode().count(VALIDATION_MARKER) != 1:
        raise ValueError("Release notes require exactly one validation marker")

    links = "\n".join(f"- [{item['workflow']}]({item['url']}) — named execution jobs passed."
                      for item in checks["accepted_workflows"])
    notes = card.decode().replace(VALIDATION_MARKER, links + (
        "\n- Clean wheel installation, installed CLI and owned demo/reopen/export passed; "
        "see the attached clean-install.json."))

    if VALIDATION_MARKER in notes or not links:
        raise ValueError("Release notes require actual accepted master validation links")

    (root / "RELEASE_NOTES.md").write_bytes(notes.encode())
    WriteJson(root / "source.json", source)
    WriteJson(root / "master-checks.json", checks)
    WriteJson(root / "clean-install.json", smoke)
    WriteJson(root / "distribution-metadata.json", metadata)
    manifest = {"schema_version": 1, "source": source, "files": Inventory(root)}
    WriteJson(root / "release-manifest.json", manifest)
    inventory = Inventory(root)
    checksums = "".join(f"{value['sha256']}  {name}\n" for name, value in inventory.items())
    (root / "SHA256SUMS").write_bytes(checksums.encode("ascii"))

    return {"schema_version": 1, "version": version,
            "checksums_sha256": hashlib.sha256(checksums.encode()).hexdigest(),
            "manifest_sha256": hashlib.sha256(Read(root / "release-manifest.json")).hexdigest()}


def Verify(root: Path, checksums_sha256: str) -> dict:
    """Rehash the entire same-byte handoff against the producer's independently retained digest.

    Args:
        root: Downloaded immutable original publication bundle.
        checksums_sha256: Independent checksum-file digest from the build job.
    Returns:
        Original manifest only after every file and closed inventory agrees.
    """

    if re.fullmatch(r"[a-f0-9]{64}", checksums_sha256) is None or (
        hashlib.sha256(Read(root / "SHA256SUMS", MAX_JSON_BYTES)).hexdigest() != checksums_sha256
    ):
        raise ValueError("Release handoff checksum identity differs")

    manifest = Json(Read(root / "release-manifest.json", MAX_JSON_BYTES))
    actual = Inventory(root)
    files = {name: value for name, value in actual.items()
             if name not in {"SHA256SUMS", "release-manifest.json"}}

    if manifest.get("schema_version") != 1 or manifest.get("files") != files:
        raise ValueError("Release handoff is incomplete or contains changed/unlisted material")

    expected = "".join(f"{value['sha256']}  {name}\n" for name, value in actual.items()
                       if name != "SHA256SUMS")

    if Read(root / "SHA256SUMS") != expected.encode("ascii"):
        raise ValueError("Release checksum list differs from the exact handed-off inventory")

    return manifest


def Invoke(arguments: tuple[str, ...], cwd: Path, expected: int = 0) -> subprocess.CompletedProcess:
    """Keep each installed CLI exit status and reject unexpected failure without a hidden retry.

    Args:
        arguments: Exact literal command vector without shell interpretation.
        cwd: Owned installation directory outside the source checkout.
        expected: Required actual process exit code.
    Returns:
        Original command output after retaining its invocation and actual status.
    """

    result = subprocess.run(arguments, cwd=cwd, capture_output=True, text=True, timeout=120,
                            check=False, env={**os.environ, "PYTHONPATH": ""})

    with (cwd / "commands.jsonl").open("a", encoding="utf-8") as evidence:
        evidence.write(json.dumps({"argv": arguments, "cwd": str(cwd),
            "expected_exit_code": expected, "exit_code": result.returncode}) + "\n")

    if result.returncode != expected:
        raise ValueError("Release installed command returned an unexpected exit status")

    return result


def Smoke(root: Path, version: str, wheel: Path | None = None) -> dict:
    """Install outside the source checkout and exercise one owned demo, denial and offline reuse.

    Args:
        root: New owned environment and demo directory outside the checkout.
        version: Exact final package version to install and observe.
        wheel: Original wheel for offline validation; None selects the public index.
    Returns:
        Actual checked installation, owned demo and original offline model evidence.
    """

    if VERSION.fullmatch(version) is None or root.exists():
        raise ValueError("Installed release smoke needs an exact version and new owned directory")

    root.mkdir(parents=True)
    environment = root / "environment"
    Invoke((sys.executable, "-m", "venv", str(environment)), root)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    cli = python.parent / ("1337.exe" if os.name == "nt" else "1337")
    selection = ("--no-index", str(wheel)) if wheel is not None else (
        "--index-url", "https://pypi.org/simple", "--only-binary=:all:", PROJECT + "==" + version)
    Invoke((str(python), "-m", "pip", "--isolated", "install", "--no-cache-dir", "--no-deps",
        "--retries", "0", "--timeout", "30", "--report", str(root / "pip-install.json"),
        *selection), root)
    observed = Invoke((str(cli), "--version"), root).stdout.strip()

    if observed != "1337 " + version:
        raise ValueError("Installed package version differs from the selected release")

    Invoke((str(cli), "help"), root)
    Invoke((str(cli), "doctor"), root)
    demo = root / "demo"
    denied = Json(Invoke((str(cli), "demo", "local", str(demo), "--json"), root, 3).stdout.encode())

    if denied["state"] != "denied" or denied["failure"] != "approval_required" or demo.exists():
        raise ValueError("Installed demo planning cannot create a target or imply approval")

    completed = Json(Invoke((str(cli), "demo", "local", str(demo), "--approve-safe-http",
                            "--json"), root).stdout.encode())

    if completed["state"] != "completed" or completed["target_teardown_completed"] is not True:
        raise ValueError("Installed release demo did not complete with verified target teardown")

    reopened = Json(Invoke((str(cli), "workspace", "open", str(demo / "workspace"),
                           "--json"), root).stdout.encode())
    export = root / "reopened.json"
    Invoke((str(cli), "report", "export", str(demo / "workspace"), "--format", "json",
            "--output", str(export), "--json"), root)

    if Read(export) != Read(demo / "reports/model.json") or reopened["model_revision"] != 3:
        raise ValueError("Installed offline reopen/export differs from its retained original model")

    before = Inventory(demo)
    Invoke((str(cli), "demo", "local", str(demo), "--approve-safe-http", "--json"), root, 2)

    if Inventory(demo) != before:
        raise ValueError("Installed existing-root refusal changed retained original material")

    installation = Json(Read(root / "pip-install.json", MAX_JSON_BYTES))

    return {"schema_version": 1, "state": "verified-installed-demo", "version": version,
        "source": "local-wheel" if wheel is not None else "pypi", "model_revision": 3,
        "model_sha256": hashlib.sha256(Read(export)).hexdigest(),
        "pip_install": installation, "demo": completed}


def VerifyIndexInstall(smoke: dict, manifest: dict) -> None:
    """Join the actual clean PyPI installation report to the exact validated original wheel.

    Args:
        smoke: Actual public-index clean-install and installed CLI result.
        manifest: Independently verified original release bundle manifest.
    """

    version = manifest["source"]["version"]
    installed = smoke["pip_install"]["install"]

    if smoke["source"] != "pypi" or smoke["state"] != "verified-installed-demo" or (
        smoke["version"] != version or len(installed) != 1
    ):
        raise ValueError("Postpublication verification requires one actual clean PyPI installation")

    package = installed[0]
    location = urllib.parse.urlsplit(package["download_info"]["url"])
    digest = manifest["files"][f"dist/{PROJECT}-{version}-py3-none-any.whl"]["sha256"]

    if package["metadata"]["name"] != PROJECT or package["metadata"]["version"] != version or (
        location.scheme != "https" or location.hostname != "files.pythonhosted.org"
        or location.username is not None or location.password is not None
        or location.port not in (None, 443) or location.query or location.fragment
        or not location.path.startswith("/packages/")
        or package["download_info"]["archive_info"]["hashes"]["sha256"] != digest
    ):
        raise ValueError("The installed PyPI wheel differs from the validated release artifact")


def Main(arguments: list[str] | None = None) -> int:
    """Expose preflight, master evidence, sealing, verification and clean-install commands.

    Args:
        arguments: Explicit CLI selection, or None for the process command line.
    Returns:
        Zero only after the requested finite operation actually succeeds.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("source", "gates", "smoke", "seal", "verify",
                                           "verify-index"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--sha")
    parser.add_argument("--version")
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--checks", type=Path)
    parser.add_argument("--smoke", type=Path)
    parser.add_argument("--card", type=Path)
    parser.add_argument("--checksums-sha256")
    selected = parser.parse_args(arguments)

    if selected.command == "source":
        result = SourceFacts(selected.root, selected.tag or "", selected.sha or "")

    elif selected.command == "gates":
        result = MasterChecks(selected.sha or "")

    elif selected.command == "smoke":
        result = Smoke(selected.root, selected.version or "", selected.wheel)

    elif selected.command == "seal":
        if not all((selected.source, selected.checks, selected.smoke, selected.card)):
            parser.error("seal requires source, checks, smoke and card files")

        result = Seal(selected.root, Json(Read(selected.source)), Json(Read(selected.checks)),
                      Json(Read(selected.smoke)), Read(selected.card))

    elif selected.command == "verify":
        result = Verify(selected.root, selected.checksums_sha256 or "")

    else:
        if selected.smoke is None:
            parser.error("verify-index requires the actual clean PyPI smoke file")

        result = Verify(selected.root, selected.checksums_sha256 or "")
        VerifyIndexInstall(Json(Read(selected.smoke)), result)

    if selected.output is not None:
        WriteJson(selected.output, result)

    print(json.dumps(result, sort_keys=True, allow_nan=False))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
