# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Own a real disposable GitLab server and registered shell runner for the public template.

The opt-in caller must provide a fresh Linux Docker host. Synthetic credentials
remain in private local memory/files; only verified credential-free evidence is
published. This module never contacts a pre-existing GitLab account or instance.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import io
import json
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ExecutionState, ImpactLevel
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    ExecutionEventKind,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutor,
)

SERVER = ("gitlab/gitlab-ce:19.5.1-ce.0@sha256:"
          "939572df24c6517d0408d7355cafef3f7c6defa9d248201151a88361fc411242")
RUNNER_VERSION = "19.5.1"
RUNNER_SIZE_BYTES = 141918698
RUNNER_SHA256 = "0e11e71404352e67d286269aee397ec8e2825e0fc91a12f60c04cef0b85edb85"
RUNNER_URL = ("https://gitlab-runner-downloads.s3.amazonaws.com/v" + RUNNER_VERSION
              + "/binaries/gitlab-runner-linux-amd64")
TEMPLATE = "docs/examples/ci/gitlab-ci.yml"
TOKEN_PATTERN = re.compile(rb"gl(?:pat|rt|cbt|ptt)-[A-Za-z0-9_-]{16,}")
MAX_RESPONSE = 32 * 1024 * 1024

LOCAL_DOCKER_HOST = "unix:///var/run/docker.sock"
PYTHON_IMAGE = ("python:3.12-slim-bookworm@sha256:"
    "623674a14ef93d052bb9b0de4dbf5f28eb578a35263838941cc8aa43213c1487")


class RunnerSession:
    """Keep canonical descendant ownership responsive while synchronous API polling runs."""

    def __init__(self, binary: Path, config: Path, private: Path, deadline: float):
        """Bind only the explicitly opted-in fixture invocation and private Docker controls."""

        allowance = int(deadline - time.monotonic())

        if allowance < 1:
            raise ValueError("Owned runner deadline expired before launch")

        invocation = AdapterInvocation("fixture.gitlab-runner", AdapterRequest(
            "fixture.owned-gitlab", "owned:disposable-gitlab", ImpactLevel.SAFE),
            (str(binary), "run", "--config", str(config), "--working-directory", str(private)),
            allowance, RUNNER_VERSION)
        self.request = LocalExecutionRequest(invocation,
            CapabilityDescriptor("fixture.owned-gitlab", "fixture.gitlab-runner", ImpactLevel.SAFE),
            ExecutionAuthorization("fixture-opt-in", "owned:disposable-gitlab",
                "fixture-explicit-host-opt-in", InvocationDigest(invocation)),
            environment={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(private / "home"),
                "LANG": "C", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
                "DOCKER_HOST": LOCAL_DOCKER_HOST, "DOCKER_CONFIG": str(private / "docker")})
        self.executor = LocalExecutor(private)
        self.started = threading.Event()
        self.loop = None
        self.cancellation = None
        self.outcome = None
        self.error = None
        self.thread = threading.Thread(target=self.Worker, name="owned-gitlab-runner", daemon=False)

    def Worker(self):
        """Run the sole canonical owner; retain private outcomes without logging their streams."""

        async def Execute():
            """Observe original start and keep cancellation in the executor's own event loop."""

            self.loop = asyncio.get_running_loop()
            self.cancellation = asyncio.Event()

            def Observe(event):
                """Acknowledge only the original canonical process-start event."""

                if event.kind is ExecutionEventKind.STARTED:
                    self.started.set()

            self.outcome = await self.executor.Execute(self.request, on_event=Observe,
                cancellation=self.cancellation, own_descendants=True)

        try:
            asyncio.run(Execute())

        except BaseException as error:
            self.error = error

        finally:
            self.started.set()

    def Start(self):
        """Require original start before the real server may hand this runner a job."""

        self.thread.start()

        if not self.started.wait(10):
            raise ValueError("Canonical owned runner did not acknowledge start")

        self.Check()

    def Check(self):
        """Reject a failed or prematurely ended runner rather than trusting API progress."""

        if self.error is not None or not self.thread.is_alive() or self.outcome is not None:
            raise ValueError("Canonical owned runner ended before its platform cohort")

    def Stop(self):
        """Join original descendant cleanup before any private controls may be erased."""

        if self.thread.is_alive() and self.loop is not None and self.cancellation is not None:
            self.loop.call_soon_threadsafe(self.cancellation.set)

        self.thread.join(20)

        if self.thread.is_alive() or self.error is not None or self.outcome is None:
            raise ValueError("Canonical owned runner cleanup remains unconfirmed")

        outcome = self.outcome

        if not (outcome.execution.state is ExecutionState.CANCELLED and
            outcome.termination is ExecutionTermination.CANCELLATION) and not (
            outcome.termination is ExecutionTermination.PROCESS_EXIT and
            outcome.execution.exit_code == 0
        ):
            raise ValueError("Canonical owned runner did not stop with an admitted outcome")

        return {"state": outcome.execution.state.value, "termination": outcome.termination.value,
            "stdout_sha256": hashlib.sha256(outcome.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(outcome.stderr).hexdigest()}


def Json(raw: bytes) -> dict:
    """Decode a bounded original API or product object without accepting other root types."""

    if not 0 < len(raw) <= MAX_RESPONSE:
        raise ValueError("GitLab evidence exceeds its finite byte budget")

    value = json.loads(raw)

    if type(value) is not dict:
        raise ValueError("GitLab evidence must be an object")

    return value


def PublicBytes(raw: bytes, forbidden: tuple[bytes, ...]) -> None:
    """Refuse authentication bytes before any original stream or decoded ZIP member is public."""

    if TOKEN_PATTERN.search(raw) or any(value and value in raw for value in forbidden):
        raise ValueError("GitLab evidence contains unpublishable authentication material")


def Publish(path: Path, raw: bytes, forbidden: tuple[bytes, ...]) -> None:
    """Refuse credential-bearing evidence before creating a public original-byte file."""

    PublicBytes(raw, forbidden)

    with path.open("xb") as output:
        output.write(raw)


def Resources(directory: Path) -> dict:
    """Fail closed before acquisition unless this Linux host has the agreed actual capacity."""

    memory = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    result = {"system": platform.system(), "machine": platform.machine(),
        "cpus": os.cpu_count(), "memory_bytes": int(memory["MemTotal"].split()[0]) * 1024,
        "free_bytes": shutil.disk_usage(directory).free}

    if result["system"] != "Linux" or result["machine"] != "x86_64" or (
        type(result["cpus"]) is not int or result["cpus"] < 4
        or result["memory_bytes"] < 14 * 1024**3 or result["free_bytes"] < 30 * 1024**3
    ):
        raise ValueError("Real GitLab requires Linux amd64, four CPUs, 14 GiB RAM and 30 GiB free")

    return result


def Command(arguments: tuple[str, ...], timeout: float, *, data: bytes | None = None,
            cwd: Path | None = None) -> bytes:
    """Run one literal bounded private command without printing streams or credential state."""

    result = subprocess.run(arguments, cwd=cwd, input=data, capture_output=True,
        timeout=timeout, check=False, env={"PATH": "/usr/local/bin:/usr/bin:/bin",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0"})

    if result.returncode != 0 or len(result.stdout) > MAX_RESPONSE:
        raise ValueError("An owned GitLab platform operation did not complete successfully")

    return result.stdout


def NoRedirect():
    """Create a urllib redirect handler that cannot forward an owned authentication header."""

    def Redirect(request, source, code, message, headers, new_url):
        """Reject every redirect; no token may be forwarded to another destination."""

        raise ValueError("Owned GitLab API redirects are unadmitted")

    handler = urllib.request.HTTPRedirectHandler()
    handler.redirect_request = Redirect

    return handler


def ReadBounded(request, limit: int, deadline: float, *,
                expected_size: int | None = None) -> bytes:
    """Read original response bytes within one allowance without ambient proxies or redirects."""

    remaining = deadline - time.monotonic()

    if remaining <= 0:
        raise ValueError("Owned HTTP acquisition deadline expired")

    chunks = []
    count = 0
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    with opener.open(request, timeout=min(30, remaining)) as response:
        if expected_size is not None and (
            expected_size != limit or response.headers.get("Content-Length") != str(expected_size)
        ):
            raise ValueError("Official runner response length differs from its pinned byte count")

        while True:
            if time.monotonic() >= deadline:
                raise ValueError("Owned HTTP acquisition deadline expired")

            chunk = response.read1(min(65536, limit + 1 - count))

            if not chunk:
                break

            count += len(chunk)

            if count > limit:
                raise ValueError("Owned HTTP response exceeds its finite byte limit")

            chunks.append(chunk)

    if expected_size is not None and count != expected_size:
        raise ValueError("Official runner response is truncated before its pinned byte count")

    return b"".join(chunks)


def WaitReady(port: int, deadline: float) -> None:
    """Poll only owned startup transport failures within the original finite boot allowance."""

    boot_end = min(deadline, time.monotonic() + 900)

    while time.monotonic() < boot_end:
        try:
            ReadBounded(f"http://127.0.0.1:{port}/-/readiness", 65536,
                min(boot_end, time.monotonic() + 5))

            return

        except (urllib.error.URLError, TimeoutError, ConnectionError):
            time.sleep(1)

    raise ValueError("Real GitLab did not become ready within its fixed boot deadline")


def RunnerBytes(deadline: float) -> bytes:
    """Admit only the exact original provider length and unchanged vendor checksum before writes."""

    binary = ReadBounded(RUNNER_URL, RUNNER_SIZE_BYTES, deadline,
        expected_size=RUNNER_SIZE_BYTES)

    if len(binary) != RUNNER_SIZE_BYTES or hashlib.sha256(binary).hexdigest() != RUNNER_SHA256:
        raise ValueError("Official real GitLab runner binary failed its fixed size and checksum")

    return binary


class Api:
    """Keep one generated credential private and constrain requests to one owned loopback port."""

    def __init__(self, port: int, token: str, deadline: float | None = None):
        """Bind the independently observed local published port and generated bootstrap token."""

        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("GitLab API requires one exact owned loopback port")

        self.base = f"http://127.0.0.1:{port}/api/v4"
        self.token = token
        self.deadline = deadline

    def Bytes(self, path: str, method: str = "GET", value: dict | None = None) -> bytes:
        """Return bounded original response bytes without exposing private request headers."""

        if not path.startswith("/") or any(part in path for part in ("..", "\\", "\r", "\n",
                                                                     "?", "#")):
            raise ValueError("GitLab API path must remain a literal owned resource")

        request = urllib.request.Request(self.base + path, method=method,
            data=None if value is None else json.dumps(value).encode(), headers={
                "PRIVATE-TOKEN": self.token, "Content-Type": "application/json"})

        return ReadBounded(request, MAX_RESPONSE, self.deadline or time.monotonic() + 30)

    def Object(self, path: str, method: str = "GET", value: dict | None = None) -> dict:
        """Decode one original owned API object while retaining no credential-bearing request."""

        return Json(self.Bytes(path, method, value))


def Artifact(raw: bytes, source: str, approved: bool, forbidden: tuple[bytes, ...] = ()) -> dict:
    """Verify real server-uploaded originals rather than accepting green logs or job summaries."""

    members = {}
    total = 0

    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for index, entry in enumerate(archive.infolist()):
            name = PurePosixPath(entry.filename)
            total += entry.file_size
            mode = entry.external_attr >> 16

            if (index >= 1024 or total > MAX_RESPONSE or entry.file_size > MAX_RESPONSE
                or name.is_absolute() or ".." in name.parts or "\\" in entry.filename
                or entry.filename in members or stat.S_ISLNK(mode)):
                raise ValueError("GitLab original artifact inventory is unadmitted")

            if not entry.is_dir():
                members[entry.filename] = archive.read(entry)
                PublicBytes(members[entry.filename], forbidden)

    if members.get("source-commit.txt", b"").decode().strip() != source:
        raise ValueError("GitLab job did not retain the exact public source commit")

    result = Json(members["artifacts/ci-result.json"])
    plan = Json(members["artifacts/plan-process.json"])

    if plan["exit_status"] != 3 or Json(plan["stdout"].encode())["failure"] != "approval_required":
        raise ValueError("Actual installed GitLab planning did not refuse unapproved execution")

    if approved:
        if (result["state"] != "completed" or result["exit_status"] != 0
            or result["model_revision"] != 3 or result["verified_evidence_records"] != 3
            or result["target_teardown_completed"] is not True
            or result["no_clobber_verified"] is not True):
            raise ValueError("Actual approved GitLab product outcomes did not complete")

        original = members["artifacts/demo/reports/model.json"]
        report = Json(original)
        model = json.dumps(report["model"], ensure_ascii=False, allow_nan=False, sort_keys=True,
                           separators=(",", ":")).encode()

        if original != members["artifacts/reopened-model.json"] or hashlib.sha256(
            model
        ).hexdigest() != result["snapshot_sha256"] or (
            report["snapshot_sha256"] != result["snapshot_sha256"]
            or report["model_revision"] != 3 or report["scan_completeness"] != "not-assessed"
        ):
            raise ValueError("GitLab retained model differs from its actual reopened export")

        evidence = Json(members["artifacts/demo/evidence-index.json"])
        target = Json(members["artifacts/demo/target.json"])

        if len(evidence["records"]) != 3 or evidence["verified_acquisitions"] != 3 or (
            target["teardown_completed"] is not True or [
                (item["path"], item["status"]) for item in target["requests"]
            ] != [("/", 200), ("/health", 204), ("/redirect", 302)]
        ):
            raise ValueError("Actual GitLab target and original acquisition inventory differ")

        for record in evidence["records"]:
            material = record["material_path"]
            path = PurePosixPath(material)

            if path.is_absolute() or ".." in path.parts or "\\" in material or (
                path.as_posix() != material
            ):
                raise ValueError("Original GitLab acquisition path escapes its retained demo")

            acquired = members["artifacts/demo/" + material]
            reference = record["record"]["reference"]

            if len(acquired) != reference["size_bytes"] or hashlib.sha256(
                acquired
            ).hexdigest() != reference["sha256"]:
                raise ValueError("Actual GitLab original acquisition bytes changed")

    elif result["state"] != "denied" or result["exit_status"] != 3 or (
        result["failure"] != "predeclared_local_demo_approval_required"
        or any(name.startswith("artifacts/demo/") for name in members)
    ):
        raise ValueError("Actual unapproved GitLab job did not refuse before target/root creation")

    return result


def RunnerConfig(path: Path, api: Api, token: str, private: Path) -> None:
    """Generate private real shell-runner configuration without tokens in argv or environment."""

    text = ("concurrent = 1\ncheck_interval = 1\n[[runners]]\nname = 'owned-1337'\n"
        + "executor = 'shell'\nshell = 'bash'\nlimit = 1\n"
        + "url = " + json.dumps(api.base.removesuffix("/api/v4")) + "\n"
        + "clone_url = " + json.dumps(api.base.removesuffix("/api/v4")) + "\n"
        + "token = " + json.dumps(token) + "\n"
        + "builds_dir = " + json.dumps(str(private / "builds")) + "\n"
        + "cache_dir = " + json.dumps(str(private / "cache")) + "\n")
    path.write_text(text)
    path.chmod(0o600)


def Cleanup(owner: str, jobs: list[int], private: Path, session,
            expected_identity: tuple[int, int] | None = None,
            network_identity: str | None = None) -> dict:
    """Retain private controls until the canonical owner and every scoped resource stop."""

    deadline = time.monotonic() + 120

    def Checked(arguments, timeout):
        """Spend one cleanup allowance against the same explicitly selected local daemon."""

        remaining = deadline - time.monotonic()

        if remaining <= 0:
            raise ValueError("Owned GitLab cleanup deadline expired")

        if arguments[0] == "docker":
            arguments = ("docker", "--host", LOCAL_DOCKER_HOST, "--config",
                str(private / "docker"), *arguments[1:])

        return Command(arguments, min(timeout, remaining))

    def RequirePrivate():
        """Refuse replacement controls before Docker may consume its private configuration."""

        observed = private.lstat()

        if not stat.S_ISDIR(observed.st_mode) or (expected_identity is not None and
            (observed.st_dev, observed.st_ino) != expected_identity
        ):
            raise ValueError("Private GitLab control directory identity changed before cleanup")

    runner = None if session is None else session.Stop()
    RequirePrivate()

    for job in jobs:
        found = Checked(("docker", "ps", "-aq", "--filter", f"name=^/1337-demo-{job}$"), 15)

        if found.strip():
            identity = found.decode().strip()

            if re.fullmatch(r"[a-f0-9]{12,64}", identity) is None:
                raise ValueError("Owned job container identity is unadmitted")

            observed = Json(Checked(("docker", "inspect", "--format", "{{json .}}", identity), 15))

            if observed["Name"] != f"/1337-demo-{job}" or (
                observed["Config"]["Image"] != f"1337-demo:{job}"
            ):
                raise ValueError("Owned job container provenance changed")

            Checked(("docker", "rm", "--force", "--volumes", identity), 15)

        if Checked(("docker", "image", "ls", "-q", "--filter",
                    f"reference=1337-demo:{job}"), 15).strip():
            Checked(("docker", "image", "rm", f"1337-demo:{job}"), 15)

    for family in ("ps", "volume", "network"):
        arguments = (("docker", "ps", "-aq") if family == "ps" else
                     ("docker", family, "ls", "-q"))
        if family == "network":
            arguments = (*arguments, "--no-trunc")

        found = Checked((*arguments, "--filter", "label=1337.owner=" + owner), 15)

        for name in found.decode().splitlines():
            if family == "ps":
                actual = Checked(("docker", "inspect", "--format", "{{.Name}}", name),
                                 15).decode().strip()

                if actual != "/" + owner or re.fullmatch(r"[a-f0-9]{12,64}", name) is None:
                    raise ValueError("GitLab cleanup encountered an unadmitted container")

                selected = ("docker", "rm", "--force", "--volumes", name)

            elif family == "network":
                if re.fullmatch(r"[a-f0-9]{64}", name) is None or name != network_identity:
                    raise ValueError("GitLab cleanup encountered an unadmitted network identity")

                network = Json(Checked(("docker", "network", "inspect", "--format",
                    "{{json .}}", name), 15))

                if network.get("Id") != name or network.get("Name") != owner or (
                    type(network.get("Labels")) is not dict
                    or network["Labels"].get("1337.owner") != owner
                ):
                    raise ValueError("GitLab cleanup network identity, name or ownership changed")

                selected = ("docker", "network", "rm", name)

            else:
                allowed = {owner + "-" + suffix for suffix in ("config", "logs", "data")}

                if name not in allowed:
                    raise ValueError("GitLab cleanup encountered an unadmitted named resource")

                selected = ("docker", family, "rm", name)

            Checked(selected, 30)

        if Checked((*arguments, "--filter", "label=1337.owner=" + owner), 15).strip():
            raise ValueError("Real GitLab cleanup left owned server resources")

    for job in jobs:
        if Checked(("docker", "ps", "-aq", "--filter", f"name=^/1337-demo-{job}$"),
                   15).strip() or Checked(("docker", "image", "ls", "-q", "--filter",
                   f"reference=1337-demo:{job}"), 15).strip():
            raise ValueError("Real GitLab cleanup left an owned job container or image")

    RequirePrivate()

    shutil.rmtree(private)

    return {"owned_resources_removed": True, "private_controls_removed": True,
        "runner": runner}


def Pipeline(api: Api, project: int, runner_id: int, commit: str, image: str, approved: bool,
             deadline: float, output: Path, forbidden: tuple[bytes, ...], owned_jobs: list) -> int:
    """Run a real manually triggered pipeline and validate its original uploaded bundle."""

    variables = [{"key": "RELEASE_COMMIT", "value": commit},
                 {"key": "PYTHON_IMAGE", "value": image}]

    if approved:
        variables.append({"key": "F1337_APPROVED_LOCAL_DEMO", "value": "1"})

    pipeline = api.Object(f"/projects/{project}/pipeline", "POST", {
        "ref": "main", "variables": variables})
    identity = pipeline["id"]
    end = min(deadline, time.monotonic() + 300)
    created_end = min(end, time.monotonic() + 30)

    while time.monotonic() < created_end:
        jobs = json.loads(api.Bytes(f"/projects/{project}/pipelines/{identity}/jobs"))

        if len(jobs) == 1 and jobs[0]["name"] == "1337-local-demo":
            owned_jobs.append(jobs[0]["id"])
            break

        time.sleep(1)

    else:
        raise ValueError("Real GitLab did not create the exact owned template job")

    api.Object(f"/runners/{runner_id}", "PUT", {"paused": False})

    while time.monotonic() < end:
        pipeline = api.Object(f"/projects/{project}/pipelines/{identity}")

        if pipeline["status"] in {"success", "failed", "canceled", "skipped"}:
            break

        time.sleep(1)

    else:
        api.Object(f"/projects/{project}/pipelines/{identity}/cancel", "POST", {})
        raise ValueError("Actual GitLab pipeline exceeded its fixed deadline")

    jobs = json.loads(api.Bytes(f"/projects/{project}/pipelines/{identity}/jobs"))
    api.Object(f"/runners/{runner_id}", "PUT", {"paused": True})

    if len(jobs) != 1 or jobs[0]["name"] != "1337-local-demo" or (
        pipeline["source"] != "api" or jobs[0]["commit"]["id"] != pipeline["sha"]
        or pipeline["status"] != ("success" if approved else "failed")
        or jobs[0]["status"] != pipeline["status"]
        or not approved and jobs[0].get("failure_reason") != "script_failure"
    ):
        raise ValueError("A skipped, foreign or unexpected GitLab job cannot establish acceptance")

    job = jobs[0]["id"]
    trace = api.Bytes(f"/projects/{project}/jobs/{job}/trace")
    artifact = api.Bytes(f"/projects/{project}/jobs/{job}/artifacts")
    result = Artifact(artifact, commit, approved, forbidden)
    output.mkdir()
    Publish(output / "job-trace.txt", trace, forbidden)
    Publish(output / "artifacts.zip", artifact, forbidden)
    Publish(output / "pipeline.json", json.dumps(pipeline, sort_keys=True).encode(), forbidden)
    Publish(output / "job.json", json.dumps(jobs[0], sort_keys=True).encode(), forbidden)
    Publish(output / "verified-result.json", json.dumps(result, sort_keys=True).encode(), forbidden)

    return job


def Run(source: Path, output: Path, image: str) -> dict:
    """Admit, own, execute and clean one real accountless GitLab template acceptance cohort."""

    if os.environ.get("FUZZY1337_RUN_OWNED_GITLAB_ACCEPTANCE") != "1" or output.exists() or (
        re.fullmatch(r"python:[a-zA-Z0-9._-]+@sha256:[a-f0-9]{64}", image) is None
    ):
        raise ValueError("Real GitLab needs explicit opt-in, a new evidence root and pinned Python")

    deadline = time.monotonic() + 1500
    resources = Resources(source)
    owner = "f1337-gitlab-" + secrets.token_hex(8)
    private = Path(tempfile.mkdtemp(prefix=owner + "-"))
    private.chmod(0o700)
    (private / "docker").mkdir(mode=0o700)
    (private / "home").mkdir(mode=0o700)
    private_stat = private.stat()
    private_identity = (private_stat.st_dev, private_stat.st_ino)

    def Checked(arguments, timeout, **options):
        """Spend one cohort allowance using the same literal local Docker endpoint."""

        remaining = deadline - time.monotonic()

        if remaining <= 0:
            raise ValueError("Owned GitLab cohort deadline expired")

        if arguments[0] == "docker":
            arguments = ("docker", "--host", LOCAL_DOCKER_HOST, "--config",
                str(private / "docker"), *arguments[1:])

        return Command(arguments, min(timeout, remaining), **options)

    token = secrets.token_hex(10)
    forbidden = (token.encode(),)
    session = None
    network_identity = None
    owned_jobs = []
    successful = False

    try:
        commit = Checked(("git", "rev-parse", "HEAD"), 30, cwd=source).decode().strip()

        if re.fullmatch(r"[a-f0-9]{40}", commit) is None or Checked(
            ("git", "status", "--porcelain"), 30, cwd=source
        ).strip():
            raise ValueError("GitLab acceptance requires one exact clean reviewed source commit")

        tree = Checked(("git", "rev-parse", "HEAD^{tree}"), 30, cwd=source).decode().strip()
        template = (source / TEMPLATE).read_bytes()
        daemon = Json(Checked(("docker", "info", "--format", "{{json .}}"), 30))
        docker_free = shutil.disk_usage(daemon["DockerRootDir"]).free

        if daemon["OSType"] != "linux" or docker_free < 30 * 1024**3:
            raise ValueError("Actual Docker storage must independently admit 30 GiB free")

        resources["docker_free_bytes"] = docker_free

        if Checked(("docker", "ps", "-aq", "--filter", "name=^/1337-demo-"), 15).strip() or Checked(
            ("docker", "image", "ls", "-q", "--filter", "reference=1337-demo:*"), 15
        ).strip():
            raise ValueError("GitLab template acceptance requires a fresh owned Docker host")

        output.mkdir(parents=True)
        Publish(output / "resources.json", json.dumps(resources, sort_keys=True).encode(), ())

        binary = RunnerBytes(min(deadline, time.monotonic() + 60))

        runner = private / "gitlab-runner"
        runner.write_bytes(binary)
        runner.chmod(0o700)
        Checked(("docker", "pull", SERVER), 180)
        network_identity = Checked(("docker", "network", "create", "--label",
            "1337.owner=" + owner, owner), 30).decode().strip()

        if re.fullmatch(r"[a-f0-9]{64}", network_identity) is None:
            raise ValueError("Created GitLab network did not retain its full original identity")

        for suffix in ("config", "logs", "data"):
            Checked(("docker", "volume", "create", "--label", "1337.owner=" + owner,
                     owner + "-" + suffix), 30)

        (private / "bootstrap-token").write_text(token)
        (private / "bootstrap-token").chmod(0o600)
        script = ("user = User.find_by_username('root')\n"
            "token = user.personal_access_tokens.create!(name: 'Owned acceptance', "
            "scopes: ['api', 'create_runner'], expires_at: 1.day.from_now)\n"
            "token.set_token(File.read('/owned-private/bootstrap-token'))\n"
            "token.save!\n")
        (private / "bootstrap.rb").write_text(script)
        settings = ("external_url 'http://gitlab.1337.test'; letsencrypt['enable']=false; "
            "puma['worker_processes']=0; sidekiq['concurrency']=5; "
            "prometheus_monitoring['enable']=false; gitlab_kas['enable']=false; "
            "gitlab_rails['usage_ping_enabled']=false; gitlab_rails['gitlab_email_enabled']=false")
        Checked(("docker", "run", "-d", "--name", owner, "--network", owner,
            "--hostname", "gitlab.1337.test", "--label", "1337.owner=" + owner,
            "--publish", "127.0.0.1::80", "--shm-size", "256m", "--cpus", "3",
            "--memory", "10g", "--memory-swap", "10g", "--pids-limit", "2048",
            "--env", "GITLAB_OMNIBUS_CONFIG=" + settings,
            "--volume", owner + "-config:/etc/gitlab", "--volume", owner + "-logs:/var/log/gitlab",
            "--volume", owner + "-data:/var/opt/gitlab",
            "--volume", str(private) + ":/owned-private:ro", SERVER), 60)
        ports = Checked(("docker", "port", owner, "80/tcp"), 30).decode().strip()

        if re.fullmatch(r"127\.0\.0\.1:[0-9]+", ports) is None:
            raise ValueError("Real GitLab must publish only one owned loopback HTTP port")

        port = int(ports.rsplit(":", 1)[1])
        WaitReady(port, deadline)

        Checked(("docker", "exec", owner, "gitlab-rails", "runner",
                 "/owned-private/bootstrap.rb"), 120)
        api = Api(port, token, deadline)
        project = api.Object("/projects", "POST", {"name": "owned-1337", "visibility": "private",
            "shared_runners_enabled": False, "auto_devops_enabled": False,
            "build_timeout": 900})["id"]
        registration = api.Object("/user/runners", "POST", {"runner_type": "project_type",
            "project_id": project, "description": "owned-1337", "tag_list": ["docker-shell"],
            "run_untagged": False, "locked": True, "maximum_timeout": 900, "paused": True})
        runner_token = registration["token"]
        forbidden = (*forbidden, runner_token.encode())
        config = private / "config.toml"
        RunnerConfig(config, api, runner_token, private)
        Checked((str(runner), "verify", "--config", str(config)), 30)
        api.Object(f"/projects/{project}/repository/commits", "POST", {"branch": "main",
            "commit_message": "Exact reviewed public GitLab template", "actions": [{
                "action": "create", "file_path": ".gitlab-ci.yml", "content": template.decode()}]})
        session = RunnerSession(runner, config, private, deadline)
        session.Start()

        for approved in (False, True):
            session.Check()
            Pipeline(api, project, registration["id"], commit, image, approved, deadline,
                output / ("approved" if approved else "unapproved"), forbidden, owned_jobs)
            session.Check()

        successful = True

    finally:
        cleanup = Cleanup(owner, owned_jobs, private, session, private_identity, network_identity)

        if output.is_dir():
            Publish(output / "cleanup.json",
                json.dumps(cleanup, sort_keys=True).encode(), forbidden)

    if not successful:
        raise ValueError("Real GitLab cohort did not complete")

    result = {"schema_version": 1, "state": "verified-real-gitlab", "source_commit": commit,
        "source_tree": tree, "template_sha256": hashlib.sha256(template).hexdigest(),
        "server": SERVER,
        "runner_version": RUNNER_VERSION, "runner_sha256": RUNNER_SHA256,
        "runner_size_bytes": len(binary),
        "executor": "shell", "job_ids": owned_jobs, "owned_resources_removed": True}
    Publish(output / "result.json", json.dumps(result, sort_keys=True).encode(), forbidden)

    return result


def Verify(output: Path, source: Path) -> dict:
    """Reopen originals and reject skips, partial cleanup or another source revision."""

    commit = Command(("git", "rev-parse", "HEAD"), 10, cwd=source).decode().strip()
    tree = Command(("git", "rev-parse", "HEAD^{tree}"), 10, cwd=source).decode().strip()
    result = Json((output / "result.json").read_bytes())
    cleanup = Json((output / "cleanup.json").read_bytes())
    resources = Json((output / "resources.json").read_bytes())
    runner = cleanup.get("runner")
    template_sha256 = hashlib.sha256((source / TEMPLATE).read_bytes()).hexdigest()

    if (result.get("state") != "verified-real-gitlab" or result.get("schema_version") != 1
        or result.get("source_commit") != commit or result.get("source_tree") != tree
        or result.get("server") != SERVER or result.get("runner_version") != RUNNER_VERSION
        or result.get("runner_sha256") != RUNNER_SHA256
        or result.get("runner_size_bytes") != RUNNER_SIZE_BYTES or result.get("executor") != "shell"
        or result.get("template_sha256") != template_sha256
        or result.get("owned_resources_removed") is not True
        or cleanup.get("owned_resources_removed") is not True
        or cleanup.get("private_controls_removed") is not True or type(runner) is not dict
        or (runner.get("state"), runner.get("termination")) not in {
            ("cancelled", "cancellation"), ("succeeded", "process_exit")}
        or any(re.fullmatch(r"[a-f0-9]{64}", runner.get(role + "_sha256", "")) is None
            for role in ("stdout", "stderr"))
        or resources.get("system") != "Linux" or resources.get("machine") != "x86_64"
        or resources.get("cpus", 0) < 4 or resources.get("memory_bytes", 0) < 14 * 1024**3
        or any(resources.get(key, 0) < 30 * 1024**3
            for key in ("free_bytes", "docker_free_bytes"))
    ):
        raise ValueError("Real GitLab originals do not prove exact source, resources and cleanup")

    identities = []
    pipelines = []

    for approved in (False, True):
        directory = output / ("approved" if approved else "unapproved")
        job = Json((directory / "job.json").read_bytes())
        pipeline = Json((directory / "pipeline.json").read_bytes())
        original = (directory / "artifacts.zip").read_bytes()
        verified = Artifact(original, commit, approved)
        PublicBytes((directory / "job-trace.txt").read_bytes(), ())

        if (type(job.get("id")) is not int or job["id"] <= 0
            or type(pipeline.get("id")) is not int or pipeline["id"] <= 0
            or job.get("name") != "1337-local-demo" or pipeline.get("source") != "api"
            or job.get("pipeline", {}).get("id") != pipeline["id"]
            or job.get("commit", {}).get("id") != pipeline.get("sha")
            or pipeline.get("status") != ("success" if approved else "failed")
            or job.get("status") != pipeline["status"]
            or not approved and job.get("failure_reason") != "script_failure"
            or Json((directory / "verified-result.json").read_bytes()) != verified
        ):
            raise ValueError("Real GitLab original jobs differ from the admitted two pipelines")

        identities.append(job["id"])
        pipelines.append(pipeline["id"])

    if len(set(identities)) != 2 or len(set(pipelines)) != 2 or result.get("job_ids") != identities:
        raise ValueError("Real GitLab requires two distinct actually executed owned jobs")

    return result


def RequireExecuted(path: Path) -> None:
    """Reject a green workflow whose sole real GitLab cohort failed, skipped or never ran."""

    if not 0 < path.stat().st_size <= 1024 * 1024:
        raise ValueError("Real GitLab JUnit is missing or exceeds its finite limit")

    root = ElementTree.fromstring(path.read_bytes())
    cases = list(root.iter("testcase"))

    if len(cases) != 1 or cases[0].get("name") != "test_PublicTemplateRunsOnOwnedGitLab" or any(
        list(root.iter(tag)) for tag in ("failure", "error", "skipped")
    ):
        raise ValueError("Real GitLab requires its one actually executed successful pytest cohort")


def Main() -> int:
    """Expose only the explicit real-platform cohort; failures never become synthetic PASS."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--junit", type=Path)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python-image", default=PYTHON_IMAGE)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.absolute()
    if args.verify:
        if args.junit is None:
            raise ValueError("Real GitLab verification requires original pytest JUnit")

        RequireExecuted(args.junit)

    result = Verify(output, source) if args.verify else Run(source, output, args.python_image)
    print(json.dumps(result, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
