# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Inert admission and evidence contracts; these tests never run GitLab or Docker."""

import hashlib
import io
import json
import os
import stat
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.functional import owned_gitlab_platform as platform

COMMIT = "a" * 40
CANONICAL_MODEL = b'{"original":"marked-test-only"}'
MODEL_DIGEST = hashlib.sha256(CANONICAL_MODEL).hexdigest()
MODEL = json.dumps({"model": json.loads(CANONICAL_MODEL), "model_revision": 3,
    "snapshot_sha256": MODEL_DIGEST, "scan_completeness": "not-assessed"}).encode()


@pytest.fixture(autouse=True)
def ForbidRuntime(monkeypatch):
    """Forbid every platform acquisition/launch in this deterministic contract cohort."""

    def Forbidden(*arguments, **options):
        """Fail if an inert contract crosses a process or network boundary."""

        raise AssertionError("Inert GitLab contracts cannot launch processes or contact services")

    monkeypatch.setattr(platform, "Command", Forbidden)
    monkeypatch.setattr(platform.urllib.request, "urlopen", Forbidden)
    monkeypatch.setattr(platform.urllib.request.OpenerDirector, "open", Forbidden)
    monkeypatch.setattr(platform.subprocess, "run", Forbidden)
    monkeypatch.setattr(platform.subprocess, "Popen", Forbidden)


def Artifacts(approved, *, fault=None):
    """Construct explicitly synthetic original-shaped GitLab artifact bytes, never real evidence."""

    result = {"state": "completed" if approved else "denied", "exit_status": 0 if approved else 3,
        "failure": "predeclared_local_demo_approval_required", "model_revision": 3,
        "verified_evidence_records": 3, "target_teardown_completed": True,
        "no_clobber_verified": True, "snapshot_sha256": MODEL_DIGEST}
    plan = {"exit_status": 3, "stdout": json.dumps({"failure": "approval_required"})}
    files = {"source-commit.txt": COMMIT.encode(), "artifacts/ci-result.json": json.dumps(
        result).encode(), "artifacts/plan-process.json": json.dumps(plan).encode()}

    if approved:
        files.update({"artifacts/demo/reports/model.json": MODEL,
            "artifacts/reopened-model.json": MODEL,
            "artifacts/demo/target.json": json.dumps({"teardown_completed": True,
                "requests": [{"path": path, "status": status} for path, status in
                    (("/", 200), ("/health", 204), ("/redirect", 302))]}).encode()})
        records = []

        for index in range(3):
            name = f"evidence/{index}.txt"
            raw = ("marked-original-" + str(index)).encode()
            files["artifacts/demo/" + name] = raw
            records.append({"material_path": name, "record": {"reference": {
                "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}}})

        files["artifacts/demo/evidence-index.json"] = json.dumps({
            "records": records, "verified_acquisitions": 3}).encode()

    if fault == "source":
        files["source-commit.txt"] = b"b" * 40

    elif fault == "export":
        files["artifacts/reopened-model.json"] = b"changed"

    elif fault in {"revision", "teardown", "status"}:
        key, value = {"revision": ("model_revision", 2),
            "teardown": ("target_teardown_completed", False), "status": ("exit_status", 0)}[fault]
        result[key] = value
        files["artifacts/ci-result.json"] = json.dumps(result).encode()

    elif fault == "unexpected-root":
        files["artifacts/demo/unexpected.txt"] = b"created before approval"

    elif fault == "traversal":
        files["../foreign.txt"] = b"unadmitted"

    elif fault == "original-acquisition":
        files["artifacts/demo/evidence/0.txt"] = b"changed original bytes"

    output = io.BytesIO()

    with platform.zipfile.ZipFile(output, "w") as archive:
        for name, raw in files.items():
            archive.writestr(name, raw)

    return output.getvalue()


@pytest.mark.parametrize("approved", [False, True], ids=("unapproved", "approved"))
def test_OriginalArtifactRequiresIndependentPlanAndRetainedModel(approved):
    """Require the expected refusal or exact complete original model/reopen chain."""

    result = platform.Artifact(Artifacts(approved), COMMIT, approved)
    assert result["state"] == ("completed" if approved else "denied"), (
        "The verifier must keep actual approved and denied outcomes distinct")


@pytest.mark.parametrize("approved,fault", [(True, "source"), (True, "export"),
    (True, "revision"), (True, "teardown"), (False, "status"), (False, "unexpected-root"),
    (True, "traversal"), (True, "original-acquisition")])
def test_OriginalArtifactRejectsDriftAndPrematureExecution(approved, fault):
    """No changed source, report, cleanup, revision or unapproved target becomes accepted."""

    with pytest.raises(ValueError):
        platform.Artifact(Artifacts(approved, fault=fault), COMMIT, approved)


@pytest.mark.parametrize("raw", [b"private-owned-auth", b"glrt-" + b"a" * 32],
                         ids=("generated-secret", "unknown-job-token"))
def test_AuthenticationMaterialNeverReachesPublishedOriginalFiles(tmp_path, raw):
    """Refuse original evidence rather than redact it and misrepresent unchanged raw bytes."""

    destination = tmp_path / "trace.txt"

    with pytest.raises(ValueError, match="authentication material"):
        platform.Publish(destination, raw, (b"private-owned-auth",))

    assert not destination.exists(), "Rejected credentials must never create a published file"


def test_PublicOriginalBytesRemainExactAndNoClobber(tmp_path):
    """Only credential-free originals may be retained, and evidence cannot be replaced."""

    destination = tmp_path / "trace.txt"
    platform.Publish(destination, b"marked trace", (b"private-owned-auth",))
    assert destination.read_bytes() == b"marked trace", "Published originals must remain exact"

    with pytest.raises(FileExistsError):
        platform.Publish(destination, b"replacement", ())


def test_CompressedArtifactCannotHideAnAuthenticationToken():
    """Inspect original decoded member bytes before retaining a compressed GitLab ZIP."""

    output = io.BytesIO()

    with platform.zipfile.ZipFile(output, "w", compression=platform.zipfile.ZIP_DEFLATED) as data:
        data.writestr("artifacts/diagnostic.txt", b"glrt-" + b"a" * 32)

    with pytest.raises(ValueError, match="authentication material"):
        platform.Artifact(output.getvalue(), COMMIT, False)


@pytest.mark.parametrize("fault", [None, "cpu", "memory", "disk", "system", "machine"])
def test_RealResourceAdmissionFailsClosedBeforeAnyAcquisition(tmp_path, monkeypatch, fault):
    """Documented minimums require actual observations, never a hosted-runner label alone."""

    monkeypatch.setattr(platform.platform, "system", lambda: "Windows" if fault == "system"
                        else "Linux")
    monkeypatch.setattr(platform.platform, "machine", lambda: "arm64" if fault == "machine"
                        else "x86_64")
    monkeypatch.setattr(platform.os, "cpu_count", lambda: 2 if fault == "cpu" else 4)
    monkeypatch.setattr(Path, "read_text", lambda selected: "MemTotal: " + str(
        8 * 1024**2 if fault == "memory" else 16 * 1024**2) + " kB\n")
    monkeypatch.setattr(platform.shutil, "disk_usage", lambda selected: SimpleNamespace(
        free=(14 if fault == "disk" else 40) * 1024**3))

    if fault is None:
        assert platform.Resources(tmp_path)["free_bytes"] == 40 * 1024**3, (
            "Admitted capacity must preserve the actual filesystem observation")

    else:
        with pytest.raises(ValueError, match="Real GitLab requires"):
            platform.Resources(tmp_path)


@pytest.mark.parametrize("path", ["https://foreign.invalid", "/projects/../users", "/p?x=1"])
def test_PrivateApiCannotChangeOriginOrInterpretQueryPaths(path):
    """Authentication never leaves the exact admitted loopback endpoint."""

    api = platform.Api(8929, "marked-private-unit-token")

    with pytest.raises(ValueError, match="literal owned resource"):
        api.Bytes(path)

    with pytest.raises(ValueError, match="redirects"):
        platform.NoRedirect().redirect_request(None, None, 302, None, None, "https://foreign")


def test_PrivateRunnerConfigurationKeepsTokensOutOfCommandArguments(tmp_path):
    """API registration and a private config bind a real shell executor without token flags."""

    path = tmp_path / "config.toml"
    api = platform.Api(8929, "bootstrap-test-only")
    platform.RunnerConfig(path, api, "runner-test-only", tmp_path)
    value = tomllib.loads(path.read_text())["runners"][0]
    assert value["executor"] == "shell" and value["token"] == "runner-test-only", (
        "The private real-runner config must bind its actual shell executor and auth token")

    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, (
            "The Linux authentication-bearing local runner configuration must remain owner-only")


@pytest.mark.parametrize("foreign", [False, True], ids=("already-clean", "foreign-volume"))
def test_CleanupRetainsPrivateStateUntilEveryOwnedResourceIsConfirmed(
    tmp_path, monkeypatch, foreign
):
    """Missing resources are harmless; a foreign named resource is never deleted as a fallback."""

    private = tmp_path / "private"
    private.mkdir()
    (private / "config.toml").write_text("marked-private-unit-token")
    commands = []

    def Command(arguments, timeout):
        """Return only observed empty ownership lists or a deliberately foreign volume."""

        commands.append(arguments)

        return b"foreign-volume\n" if foreign and "volume" in arguments else b""

    monkeypatch.setattr(platform, "Command", Command)

    if foreign:
        with pytest.raises(ValueError, match="unadmitted named resource"):
            platform.Cleanup("owned-fixture", [], private, None)

    else:
        platform.Cleanup("owned-fixture", [], private, None)

    assert private.exists() is foreign, (
        "Unknown ownership must retain private controls; confirmed cleanup must erase them")
    assert all("rm" not in command for command in commands), (
        "A foreign resource or already empty ownership list must never cause deletion")



def test_UnconfirmedRunnerRetainsControlsBeforeAnyDockerCall(tmp_path):
    """An unknown canonical process outcome forbids both Docker cleanup and private erasure."""

    class UnknownOwner:
        """Represent only an unconfirmed inert canonical owner outcome."""

        def Stop(self):
            """Refuse a cleanup proof without launching or signalling any process."""

            raise ValueError("unconfirmed fixture owner")

    with pytest.raises(ValueError, match="unconfirmed fixture owner"):
        platform.Cleanup("owned-fixture", [], tmp_path, UnknownOwner())

    assert tmp_path.exists(), "An unconfirmed owner must preserve all private controls"


def test_PrivatePathReplacementCannotEraseEitherDirectory(tmp_path, monkeypatch):
    """A path swapped after acquisition never authorizes removal of its replacement."""

    private = tmp_path / "private"
    private.mkdir()
    observed = private.stat()
    moved = tmp_path / "retained-original"
    private.rename(moved)
    private.mkdir()
    with pytest.raises(ValueError, match="identity changed"):
        platform.Cleanup("owned-fixture", [], private, None, (observed.st_dev, observed.st_ino))

    assert private.exists() and moved.exists(), "Neither unknown replacement nor original may erase"


def test_ExpiredHttpAllowanceRefusesBeforeNetwork(monkeypatch):
    """No acquisition may begin after its single absolute allowance has already expired."""

    monkeypatch.setattr(platform.time, "monotonic", lambda: 10.0)

    with pytest.raises(ValueError, match="deadline expired"):
        platform.Api(8929, "inert-token", 9.0).Bytes("/projects")


def test_HttpReadCapsOriginalBodyAndDisablesAmbientProxy(monkeypatch):
    """An explicitly inert response proves during-read caps and the closed loopback transport."""

    handlers = []

    class Response(io.BytesIO):
        """Supply original-shaped bytes without opening a socket."""

        def ReadOne(self, amount):
            """Mirror a bounded single read from the in-memory fixture stream."""

            return self.read(amount)

        read1 = ReadOne

    class Opener:
        """Supply one deliberately oversized inert response."""

        def Open(self, request, timeout):
            """Return synthetic bytes without following the provided URL."""

            return Response(b"12345")

        open = Open

    def Build(*selected):
        """Record exact transport handlers without creating a network connection."""

        handlers.extend(selected)

        return Opener()

    monkeypatch.setattr(platform.urllib.request, "build_opener", Build)

    with pytest.raises(ValueError, match="byte limit"):
        platform.ReadBounded("http://127.0.0.1/inert", 4, platform.time.monotonic() + 1)

    assert isinstance(handlers[0], platform.urllib.request.ProxyHandler), (
        "The private transport must replace ambient proxy discovery")
    assert handlers[0].proxies == {}, "The private loopback request must never use ambient proxies"


def test_CanonicalRunnerOwnsDescendantsAndJoinsBeforeHashOnlyProof(tmp_path, monkeypatch):
    """An inert canonical executor exercises original start, cancellation and completed join."""

    import asyncio

    from fuzzy1337.adapters import AdapterExecution
    from fuzzy1337.executors import ExecutionEvent

    observed = []

    class InertExecutor:
        """Expose canonical callback semantics without creating any process."""

        def __init__(self, root):
            """Retain the exact private workspace selected by the fixture."""

            observed.append(root)

        async def Execute(self, request, *, on_event, cancellation, own_descendants):
            """Acknowledge original-shaped start then await the owner's real cancel event."""

            observed.append((request, own_descendants))
            on_event(ExecutionEvent(0, platform.ExecutionEventKind.STARTED))
            await asyncio.wait_for(cancellation.wait(), 2)

            return SimpleNamespace(execution=AdapterExecution(ExecutionState.CANCELLED, None, 0.1),
                termination=platform.ExecutionTermination.CANCELLATION,
                stdout=b"inert-private-stream", stderr=b"")

    from fuzzy1337.adapters import ExecutionState

    monkeypatch.setattr(platform, "LocalExecutor", InertExecutor)
    session = platform.RunnerSession(tmp_path / "runner", tmp_path / "config", tmp_path,
        platform.time.monotonic() + 10)
    session.Start()
    proof = session.Stop()
    request, descendants = observed[1]
    assert descendants is True, "Real runner execution must opt into canonical descendant ownership"
    assert request.environment["DOCKER_HOST"] == platform.LOCAL_DOCKER_HOST, (
        "Runner jobs and fixture Docker operations must select the same local daemon")
    assert not session.thread.is_alive(), "Private cleanup proof requires the original owner joined"
    assert proof["stdout_sha256"] == hashlib.sha256(b"inert-private-stream").hexdigest(), (
        "Public cleanup proof may retain hashes, never private runner stream bytes")
    assert b"inert-private-stream" not in json.dumps(proof).encode(), (
        "Original private runner logs cannot enter published cleanup metadata")



@pytest.mark.parametrize("fault", [None, "skipped", "missing", "failure"])
def test_RealGitLabJUnitRejectsUnexecutedOrFailedCases(tmp_path, fault):
    """The required platform gate accepts exactly one executed passing ordinary pytest case."""

    path = tmp_path / "junit.xml"
    case = '<testcase name="test_PublicTemplateRunsOnOwnedGitLab">'
    case += '' if fault in {None, "missing"} else '<' + fault + '/>'
    case += '</testcase>'
    path.write_text('<testsuites><testsuite>' + ('' if fault == "missing" else case)
                    + '</testsuite></testsuites>')

    if fault is None:
        platform.RequireExecuted(path)

    else:
        with pytest.raises(ValueError, match="actually executed"):
            platform.RequireExecuted(path)


@pytest.mark.parametrize("fault", [None, "cleanup", "source", "resource", "duplicate-job",
    "pipeline", "artifact", "skipped", "runner-size"])
def test_FinalPlatformGateReopensActualShapedOriginals(tmp_path, monkeypatch, fault):
    """Synthetic causals prove the verifier refuses custody drift without launching a platform."""

    source = tmp_path / "source"
    template = source / platform.TEMPLATE
    template.parent.mkdir(parents=True)
    template.write_bytes(b"marked unchanged template")
    output = tmp_path / "originals"
    output.mkdir()
    result = {"schema_version": 1, "state": "verified-real-gitlab", "source_commit": COMMIT,
        "source_tree": "b" * 40, "server": platform.SERVER,
        "runner_version": platform.RUNNER_VERSION,
        "runner_sha256": platform.RUNNER_SHA256, "runner_size_bytes": platform.RUNNER_SIZE_BYTES,
        "executor": "shell", "job_ids": [101, 102],
        "owned_resources_removed": True, "template_sha256": hashlib.sha256(
            template.read_bytes()).hexdigest()}
    cleanup = {"owned_resources_removed": True, "private_controls_removed": True,
        "runner": {"state": "cancelled", "termination": "cancellation",
            "stdout_sha256": "c" * 64, "stderr_sha256": "d" * 64}}
    resources = {"system": "Linux", "machine": "x86_64", "cpus": 4,
        "memory_bytes": 16 * 1024**3, "free_bytes": 40 * 1024**3,
        "docker_free_bytes": 40 * 1024**3}

    if fault == "cleanup":
        cleanup["private_controls_removed"] = False

    elif fault == "source":
        result["source_commit"] = "e" * 40

    elif fault == "resource":
        resources["docker_free_bytes"] = 20 * 1024**3

    elif fault == "runner-size":
        result["runner_size_bytes"] -= 1

    for name, value in (("result", result), ("cleanup", cleanup), ("resources", resources)):
        (output / (name + ".json")).write_text(json.dumps(value))

    for index, approved in enumerate((False, True)):
        directory = output / ("approved" if approved else "unapproved")
        directory.mkdir()
        pipeline = {"id": 201 + index, "source": "api", "sha": "f" * 40,
            "status": "success" if approved else "failed"}
        job = {"id": 101 + index, "name": "1337-local-demo", "pipeline": {"id": 201 + index},
            "commit": {"id": "f" * 40}, "status": pipeline["status"],
            "failure_reason": "script_failure"}

        if approved and fault == "duplicate-job":
            job["id"] = 101

        elif approved and fault == "pipeline":
            job["pipeline"]["id"] = 299

        elif approved and fault == "skipped":
            job["status"] = "skipped"

        raw = Artifacts(approved, fault="original-acquisition" if (
            approved and fault == "artifact") else None)
        (directory / "artifacts.zip").write_bytes(raw)
        (directory / "job-trace.txt").write_bytes(b"marked original-shaped trace")

        for name, value in (("job", job), ("pipeline", pipeline),
            ("verified-result", platform.Artifact(Artifacts(approved), COMMIT, approved))):
            (directory / (name + ".json")).write_text(json.dumps(value))

    def Command(arguments, timeout, *, cwd):
        """Return only the explicitly synthetic source commit and tree expected by this case."""

        return ("b" * 40 if arguments[-1] == "HEAD^{tree}" else COMMIT).encode()

    monkeypatch.setattr(platform, "Command", Command)

    if fault is None:
        assert platform.Verify(output, source) == result, (
            "Exact original-shaped inputs must remain distinguishable from corrupted proofs")

    else:
        with pytest.raises(ValueError):
            platform.Verify(output, source)



def test_PlatformWorkflowUsesSameOrdinaryCohortAndStrictGate():
    """Draft diagnosis and final shared CI must exercise the same public-template platform path."""

    import re

    import yaml

    path = Path(__file__).resolve().parents[2] / ".github/workflows/owned-gitlab-acceptance.yml"
    workflow = yaml.safe_load(path.read_text())
    job = workflow["jobs"]["owned-gitlab"]
    steps = {step["name"]: step for step in job["steps"]}
    execute = steps["Execute actual owned GitLab approval cohort"]
    gate = steps["Require executed GitLab cohort and original platform evidence"]
    assert workflow["permissions"] == {"contents": "read"}, (
        "The owned GitLab cohort must never receive publishing or repository-write permission")
    assert all("runner." not in str(value) for value in job.get("env", {}).values()), (
        "GitHub cannot evaluate runner context in job-level env; the cohort would never start")
    assert execute["env"] == gate["env"] == {
        "FUZZY1337_GITLAB_EVIDENCE": "${{ runner.temp }}/owned-gitlab-original-evidence"
    }, "Execution and original verification must share one runtime-scoped evidence directory"
    assert "draft == false" in job["if"] and "owned-gitlab-product-checkpoint" in job["if"], (
        "The same source path must serve final ready CI and explicitly selected Draft diagnosis")
    assert "tests/functional/test_owned_gitlab_product.py" in execute["run"] and (
        "--no-cov -n 0" in execute["run"] and "--junitxml" in execute["run"]
        and "--tb=short" in execute["run"]
    ), "Ordinary serial pytest must retain JUnit without dumping private fixture arguments"
    assert "--verify" in gate["run"] and "--junit" in gate["run"], (
        "Workflow success must require independently reopened originals and zero skipped cohorts")
    assert "if" not in execute and "if" not in gate, (
        "An enrolled lane cannot silently skip actual execution or its original-evidence gate")
    assert job["timeout-minutes"] == 40 and execute["timeout-minutes"] == 29, (
        "The outer job must leave bounded setup, cleanup, gate and original-retention time")
    assert all(re.fullmatch(r"[^@]+@[a-f0-9]{40}", step["uses"]) for step in job["steps"]
               if "uses" in step), "Every external action requires an immutable reviewed commit pin"
    assert steps["Preserve original GitLab jobs and cleanup evidence"]["if"] == "always()", (
        "Available partial original diagnostics must survive an actual platform failure")



@pytest.mark.parametrize("fault", [None, "missing-length", "wrong-length", "truncated",
    "overrun", "checksum"])
def test_OfficialRunnerRequiresExactOriginalLengthAndUnchangedChecksum(monkeypatch, fault):
    """An inert transport proves admission before any runner bytes can be written or executed."""

    payload = b"inert-provider-binary"
    expected_size = len(payload)
    observed = []

    class Response(io.BytesIO):
        """Expose explicitly synthetic original response metadata and bounded stream reads."""

        def __init__(self, raw, headers):
            """Bind an inert body and the original-shaped response length header."""

            super().__init__(raw)
            self.headers = headers

        def ReadOne(self, amount):
            """Read only requested inert fixture bytes without network or filesystem access."""

            observed.append(amount)

            return self.read(amount)

        read1 = ReadOne

    class Opener:
        """Return one explicitly inert provider response with one selected admission fault."""

        def Open(self, request, timeout):
            """Expose the literal selected URL without making an actual request."""

            assert request == platform.RUNNER_URL, (
                "Acquisition cannot change the pinned provider URL")
            header = {} if fault == "missing-length" else {"Content-Length": str(
                expected_size + (1 if fault == "wrong-length" else 0))}
            body = payload[:-1] if fault == "truncated" else payload + (
                b"X" if fault == "overrun" else b"")

            return Response(body, header)

        open = Open

    monkeypatch.setattr(platform, "RUNNER_SIZE_BYTES", expected_size)
    monkeypatch.setattr(platform, "RUNNER_SHA256", "0" * 64 if fault == "checksum" else
        hashlib.sha256(payload).hexdigest())
    monkeypatch.setattr(platform.urllib.request, "build_opener", lambda *handlers: Opener())

    if fault is None:
        assert platform.RunnerBytes(platform.time.monotonic() + 1) == payload, (
            "Only exact original-sized and checksum-bound bytes may reach private installation")

    else:
        with pytest.raises(ValueError):
            platform.RunnerBytes(platform.time.monotonic() + 1)

        if fault in {"missing-length", "wrong-length"}:
            assert not observed, (
                "Header mismatch must refuse before reading any provider body bytes")


def test_RunnerSpecificSizeDoesNotRelaxOtherAcquisitionOrArtifactBudgets():
    """The vendor's original byte length is a fixed provider contract, never a generic cap bump."""

    assert platform.RUNNER_VERSION == "19.5.1" and platform.RUNNER_SIZE_BYTES == 141918698, (
        "The exact runner artifact must remain tied to its observed official version and length")
    assert platform.RUNNER_SHA256 == (
        "0e11e71404352e67d286269aee397ec8e2825e0fc91a12f60c04cef0b85edb85"
    ), "The original vendor checksum must remain unchanged when binding its correct byte length"
    assert platform.MAX_RESPONSE == 32 * 1024 * 1024, (
        "Runner-specific admission cannot enlarge API, trace or uploaded artifact budgets")



@pytest.mark.parametrize("fault", [None, "foreign-name", "foreign-label", "changed-id",
    "name-instead-of-id", "truncated-id", "missing-labels", "replacement-id"])
def test_NetworkCleanupBindsFullOriginalIdentityAndObservedOwnership(tmp_path, monkeypatch, fault):
    """Actual-shaped network IDs require independent exact-name/label/identity confirmation."""

    owner = "owned-fixture"
    identity = "a" * 64
    private = tmp_path / "private"
    private.mkdir()
    observed = private.stat()
    commands = []
    reads = []
    network = {"Id": "b" * 64 if fault == "changed-id" else identity,
        "Name": "foreign" if fault == "foreign-name" else owner,
        "Labels": {"1337.owner": "foreign" if fault == "foreign-label" else owner}}

    if fault == "missing-labels":
        network["Labels"] = None

    def Command(arguments, timeout):
        """Supply inert original-shaped network metadata without any Docker operation."""

        commands.append(arguments)
        suffix = arguments[5:]

        if suffix[:2] == ("network", "ls"):
            assert "--no-trunc" in suffix, (
                "Cleanup must enumerate the full original network identity")
            reads.append(True)

            if len(reads) == 1:
                selected = owner if fault == "name-instead-of-id" else (
                    identity[:12] if fault == "truncated-id" else
                    "b" * 64 if fault == "replacement-id" else identity)

                return (selected + "\n").encode()

        if suffix[:2] == ("network", "inspect"):
            assert suffix[-1] == identity, (
                "Inspection must use the observed original full network ID")

            return json.dumps(network).encode()

        return b""

    monkeypatch.setattr(platform, "Command", Command)

    if fault is None:
        proof = platform.Cleanup(owner, [], private, None,
            (observed.st_dev, observed.st_ino), identity)
        assert proof["private_controls_removed"] is True and not private.exists(), (
            "Exact owned-network removal and empty readback permit private cleanup")
        assert any(command[5:] == ("network", "rm", identity) for command in commands), (
            "Cleanup must remove only the original inspected network ID")

    else:
        with pytest.raises(ValueError, match="network"):
            platform.Cleanup(owner, [], private, None,
            (observed.st_dev, observed.st_ino), identity)

        assert private.exists(), "Unknown network ownership must retain private controls"
        assert not any("rm" in command for command in commands), (
            "A foreign, shortened, renamed or mismatched network must never be removed")


@pytest.mark.parametrize("failure", [ConnectionResetError, ConnectionAbortedError,
    ConnectionRefusedError, TimeoutError, platform.urllib.error.URLError])
def test_OwnedStartupTransportFailureCanBecomeReadyWithinOriginalAllowance(monkeypatch, failure):
    """Owned startup tolerates transport initialization without masking API failures."""

    observed = []
    sleeps = []

    def Read(request, limit, deadline):
        """Reset the first inert startup response and then expose an original-shaped success."""

        observed.append((request, limit, deadline))

        if len(observed) == 1:
            raise failure("marked inert startup transport failure")

        return b"ready"

    monkeypatch.setattr(platform, "ReadBounded", Read)
    monkeypatch.setattr(platform.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(platform.time, "sleep", lambda value: sleeps.append(value))
    platform.WaitReady(8929, 900.0)
    assert len(observed) == 2 and sleeps == [1], (
        "Only the failed startup observation may consume the existing bounded poll interval")
    assert all(item == ("http://127.0.0.1:8929/-/readiness", 65536, 15.0)
               for item in observed), "Startup cannot change origin, response cap or read allowance"


@pytest.mark.parametrize("fault", ["deadline", "validation"])
def test_StartupPollingDoesNotMaskValidationOrExtendExpiredAllowance(monkeypatch, fault):
    """Expired deadlines and non-transport validation failures remain terminal."""

    reads = []
    sleeps = []

    def Read(*arguments):
        """Represent a non-transport validation refusal without opening any connection."""

        reads.append(arguments)
        raise ValueError("marked original admission failure")

    monkeypatch.setattr(platform, "ReadBounded", Read)
    monkeypatch.setattr(platform.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(platform.time, "sleep", lambda value: sleeps.append(value))

    with pytest.raises(ValueError, match="fixed boot deadline" if fault == "deadline" else
                       "original admission failure"):
        platform.WaitReady(8929, 9.0 if fault == "deadline" else 900.0)

    assert not sleeps and len(reads) == (0 if fault == "deadline" else 1), (
        "A terminal validation or expired budget must never create another startup attempt")



def test_PersistentStartupResetCannotRenewTheOriginalBootDeadline(monkeypatch):
    """Repeated transport initialization failures stop at the original shared cohort deadline."""

    clock = [0.0]
    reads = []

    def Read(request, limit, deadline):
        """Represent a persistent inert reset while retaining every selected read deadline."""

        reads.append(deadline)
        raise ConnectionResetError("marked inert permanent startup reset")

    def Sleep(value):
        """Advance only the deterministic logical clock, without a real delay."""

        clock[0] += value

    monkeypatch.setattr(platform, "ReadBounded", Read)
    monkeypatch.setattr(platform.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(platform.time, "sleep", Sleep)

    with pytest.raises(ValueError, match="fixed boot deadline"):
        platform.WaitReady(8929, 2.0)

    assert reads == [2.0, 2.0] and clock[0] == 2.0, (
        "Startup resets cannot renew the original allowance or trigger another expired read")
