# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Inert committed-context and Docker projection contracts; no Git or Docker process executes."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import subprocess
import sys
import urllib.request

import pytest

from tests.functional import external_nuclei_host as host

LINUX_CONTEXT = pytest.mark.skipif(sys.platform != "linux", reason="Context modes require Linux")
OWNER = "a" * 32
REVISION = "b" * 40
BASE_ID = "sha256:" + "c" * 64
IMAGE_ID = "sha256:" + "d" * 64
RECIPE = b'ENTRYPOINT ["/usr/bin/env","-i","/opt/python","-I"]\nCMD ["--prerequisites"]\n'


@pytest.fixture(autouse=True)
def ForbidActualCommands(monkeypatch):
    """Refuse all subprocess/download paths rather than treating synthetic metadata as execution."""

    def Forbidden(*arguments, **options):
        """Fail if a supposedly inert contract attempts any Git, Docker or provider command."""

        raise AssertionError("Host core contracts cannot launch or acquire anything")

    for module, attribute in ((subprocess, "Popen"), (subprocess, "run"),
                              (asyncio, "create_subprocess_exec"), (urllib.request, "urlopen")):
        monkeypatch.setattr(module, attribute, Forbidden)


def GitRow(name, raw=b"inert", *, mode="100644", kind="blob", size=None, blob=None):
    """Serialize labeled fixture-shaped Git metadata without consulting an actual repository."""

    identifier = blob or hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw,
                                      usedforsecurity=False).hexdigest()

    return (f"{mode} {kind} {identifier} {len(raw) if size is None else size}\t{name}\0").encode()


def OwnedContext(tmp_path, monkeypatch, files=None):
    """Create only synthetic source/evidence directories and replace the repository boundary."""

    repository = tmp_path / "inert-repository"
    repository.mkdir()
    monkeypatch.setattr(host, "REPOSITORY", repository)
    destination = (repository / "functional-evidence/external-nuclei-prerequisites"
                   / "run-0123456789ab/context")
    destination.parent.mkdir(parents=True)
    entries = files if files is not None else {
        "src/example.py": b"inert source bytes\n", "empty": b""}
    inventory = b""

    for name, raw in entries.items():
        source = repository / name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(raw)
        source.chmod(0o644)
        inventory += GitRow(name, raw)

    return repository, destination, inventory


def Images():
    """Return declared synthetic Docker image metadata, never actual inspected facts."""

    base = {"id": BASE_ID, "os": "linux", "architecture": "amd64",
        "labels": {host.SOURCE_LABEL: REVISION}, "layers": ["sha256:" + "1" * 64],
        "env": ["INERT_IMAGE_SETTING=source-owned"]}
    image = {**base, "id": IMAGE_ID, "user": "1337:1337",
        "layers": [*base["layers"], "sha256:" + "2" * 64], "entrypoint": [
            "/usr/bin/env", "-i", "/opt/python", "-I"],
        "cmd": ["--prerequisites"], "volumes": None, "ports": None}

    return base, image


def Container():
    """Declare synthetic container metadata from the approved finite resource profile."""

    _, image = Images()

    return {"id": "e" * 64, "name": "/fuzzy-1337-nuclei-preflight-" + OWNER[:12],
        "image_id": IMAGE_ID, "source_revision": REVISION, "owner": OWNER, "user": "1337:1337",
        "entrypoint": image["entrypoint"], "cmd": ["--prerequisites"], "env": image["env"],
        "host": {"network": "none", "readonly": True, "privileged": False, "init": True,
            "binds": None, "ports": None, "cap_drop": ["ALL"], "cap_add": None,
            "devices": [], "device_requests": None, "volumes_from": None,
            "security": ["no-new-privileges:true"], "memory": 268435456, "cpu": 1000000000,
            "pids": 64, "tmpfs": {"/tmp": host.TMPFS}, "pid_mode": "", "ipc_mode": "private",
            "uts_mode": "", "userns_mode": "", "auto_remove": False,
            "restart": {"Name": "no", "MaximumRetryCount": 0}, "publish_all": False,
            "extra_hosts": [], "links": None, "groups": None}, "mounts": [], "restart_count": 0,
        "state": {"Status": "created", "Running": False, "Paused": False, "Restarting": False,
            "OOMKilled": False, "Dead": False, "Pid": 0, "ExitCode": 0, "Error": "",
            "StartedAt": host.ZERO_TIME, "FinishedAt": host.ZERO_TIME}}


def test_ContextLimitsAreExplicitAndMeasuredInventoryFitsOnlyAsMetadata():
    """The source bounds cover the measured tree without claiming a build or copying real source."""

    assert (host.CONTEXT_FILES, host.CONTEXT_BYTES, host.CONTEXT_FILE_BYTES) == (
        2048, 32 * 1024 * 1024, 4 * 1024 * 1024
    ), "The approved measured990file/19,876,411byte context requires finite explicit budgets."
    identity = host.SourceInventory(GitRow("inert", b"fixture"))["inert"]
    assert identity["size_bytes"] == 7 and identity["mode"] == "100644", (
        "The parser must preserve exact declared source identity, not infer execution success."
    )


@pytest.mark.parametrize("raw", [b"", b"not-nul-terminated", GitRow("../outside"),
    GitRow("/absolute"), GitRow("a\\outside"), GitRow(".git/config"),
    GitRow("nested/.git/config"), GitRow("nested/.venv/config"), GitRow("_build/evidence"),
    GitRow("alias", mode="120000"), GitRow("submodule", kind="commit"),
    GitRow("bad", blob="g" * 40), GitRow("large", size=host.CONTEXT_FILE_BYTES + 1),
    GitRow("same") + GitRow("same"), GitRow("file") + GitRow("file/child")],
    ids=["empty", "framing", "parent", "absolute", "backslash", "git", "nested-git", "nested-env",
         "ignored", "symlink",
         "submodule", "blob", "size", "duplicate", "parent-file"])
def test_ContextInventoryRejectsUnsafeOrUnboundedSource(raw):
    """Unsafe paths, nonordinary Git entries and ambiguous identities refuse before copying."""

    with pytest.raises(ValueError):
        host.SourceInventory(raw)


@pytest.mark.parametrize("limit", ["CONTEXT_FILES", "CONTEXT_BYTES", "INVENTORY_BYTES"],
                         ids=["files", "bytes", "metadata"])
def test_ContextInventoryBoundsApplyBeforeAnyCopy(monkeypatch, limit):
    """Inventory exhaustion is a source refusal, never an instruction to copy a partial tree."""

    monkeypatch.setattr(host, limit, 1)

    with pytest.raises(ValueError):
        host.SourceInventory(GitRow("one") + GitRow("two"))


@LINUX_CONTEXT
def test_ContextSnapshotKeepsExactGitBytesAndExcludesUntrackedFiles(tmp_path, monkeypatch):
    """Copy fixture-described bytes, including empty files, without reading local state."""

    repository, destination, inventory = OwnedContext(tmp_path, monkeypatch)
    (repository / "untracked-inert-private-file").write_bytes(b"must never be copied")
    copied = host.SnapshotContext(destination, inventory)
    assert set(copied) == {"src/example.py", "empty"}, (
        "Context custody must be limited to the complete validated committed inventory."
    )
    assert (destination / "src/example.py").read_bytes() == b"inert source bytes\n", (
        "Copied context bytes must equal the exact Git blob snapshot."
    )
    assert not (destination / "untracked-inert-private-file").exists(), (
        "Untracked or ignored local data cannot enter Docker context through directory copying."
    )
    assert copied["empty"]["sha256"] == hashlib.sha256(b"").hexdigest(), (
        "Legitimate empty committed files still need exact hash custody."
    )


@LINUX_CONTEXT
@pytest.mark.parametrize("failure", ["bytes", "mode", "outside", "link"],
                         ids=["blob", "mode", "destination", "symlink"])
def test_ContextSnapshotRefusesChangedOrExternalMaterial(tmp_path, monkeypatch, failure):
    """Changed source, aliases and arbitrary destinations cannot inherit committed identity."""

    repository, destination, inventory = OwnedContext(tmp_path, monkeypatch)

    if failure == "bytes":
        (repository / "src/example.py").write_bytes(b"changed source bytes")

    elif failure == "mode":
        (repository / "src/example.py").chmod(0o755)

    elif failure == "outside":
        destination = tmp_path / "arbitrary-outside-context"

    else:
        original = repository / "src/example.py"
        original.unlink()
        original.symlink_to(repository / "untracked-inert-private-file")
        (repository / "untracked-inert-private-file").write_bytes(b"inert alias target")

    with pytest.raises(ValueError):
        host.SnapshotContext(destination, inventory)


@pytest.mark.parametrize("platform", ["win32", "darwin"], ids=["windows", "macos"])
def test_ContextMaterializationRefusesUnsupportedPlatformBeforeWrites(
    tmp_path, monkeypatch, platform,
):
    """Unsupported identifiers are logical refusals, never emulated Linux mode evidence."""

    monkeypatch.setattr(host.sys, "platform", platform)

    with pytest.raises(ValueError, match="requires Linux"):
        host.SnapshotContext(tmp_path / "absent", GitRow("inert"))

    assert list(tmp_path.iterdir()) == [], "Unsupported copying must not create or read a context."


def test_DockerAuthorityIgnoresInheritedRoutingAndKeepsFixedLocalSocket(tmp_path, monkeypatch):
    """Pure argv selection must not consult host Docker context, config or endpoint environment."""

    monkeypatch.setattr(host, "REPOSITORY", tmp_path)
    monkeypatch.setenv("DOCKER_HOST", "tcp://inert.invalid:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "inert-remote-context")
    config = (tmp_path / "functional-evidence/external-nuclei-prerequisites"
              / "run-0123456789ab/docker-config")
    argv = host.DockerCommand(config, "image", "inspect", IMAGE_ID)
    assert argv == ("/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config",
                    str(config), "image", "inspect", IMAGE_ID), (
        "Local authority must be explicit without reading inherited configuration or secrets."
    )


@pytest.mark.parametrize("override", ["--host=tcp://inert.invalid", "-Htcp://inert.invalid",
    "-H", "--context", "-cother", "--config"],
    ids=["host", "short-host", "H", "context", "c", "config"])
def test_DockerAuthorityRefusesEndpointOrConfigOverrides(tmp_path, monkeypatch, override):
    """Global option aliases cannot reroute a later Docker invocation after its fixed prefix."""

    monkeypatch.setattr(host, "REPOSITORY", tmp_path)
    config = (tmp_path / "functional-evidence/external-nuclei-prerequisites"
              / "run-0123456789ab/docker-config")

    with pytest.raises(ValueError, match="fixed local socket"):
        host.DockerCommand(config, "info", override)


def test_DeclaredSyntheticImageAndContainerProjectionsAreAdmittedWithoutMutation():
    """Fixture metadata exercises admission logic without claiming any real inspected resource."""

    base, image = Images()
    container = Container()
    original = copy.deepcopy(container)
    host.AdmitImage(base, image, REVISION, BASE_ID, IMAGE_ID, RECIPE)
    host.AdmitContainer(container, image, OWNER, REVISION)
    assert container == original, (
        "Neutral readback normalization must never overwrite original data."
    )


@pytest.mark.parametrize("field,value", [("id", BASE_ID), ("architecture", "arm64"),
    ("user", "root"), ("cmd", ["--path", "/metrics"]), ("entrypoint", ["/bin/sh"]),
    ("layers", ["sha256:" + "3" * 64]), ("volumes", {"/host": {}}),
    ("env", ["HOST_SECRET=inert-fixture"])],
    ids=["id", "platform", "user", "case", "entrypoint", "ancestry", "volume", "environment"])
def test_ImageAdmissionRejectsSourcePlatformOrInvocationDrift(field, value):
    """Matching labels cannot excuse a changed image identity, platform, ancestry or entry point."""

    base, image = Images()
    image[field] = value

    with pytest.raises(ValueError):
        host.AdmitImage(base, image, REVISION, BASE_ID, IMAGE_ID, RECIPE)


@pytest.mark.parametrize("field,value", [("network", "host"), ("readonly", 1),
    ("privileged", True), ("binds", ["/var/run/docker.sock:/socket"]), ("memory", 0),
    ("pid_mode", "host"), ("ipc_mode", ""), ("devices", [{}]), ("tmpfs", {}),
    ("unknown-default", True)],
    ids=["network", "boolean", "privileged", "bind", "memory", "pid", "ipc", "device", "tmp",
         "unknown"])
def test_ContainerAdmissionRejectsWidenedOrUnknownHostProjection(field, value):
    """Undeclared Docker defaults and widened host access remain refusals before any start."""

    container = Container()
    container["host"][field] = value

    with pytest.raises(ValueError):
        host.AdmitContainer(container, Images()[1], OWNER, REVISION)


@pytest.mark.parametrize("field,value", [("owner", "f" * 32), ("image_id", BASE_ID),
    ("source_revision", "f" * 40), ("user", "0:0"), ("cmd", ["--prepare"]),
    ("restart_count", False)], ids=["owner", "image", "source", "user", "command", "restart-type"])
def test_ContainerAdmissionRequiresExactCreatedOwnershipAndConfig(field, value):
    """Only the exact new owned image/container and finite prerequisite command may be admitted."""

    container = Container()
    container[field] = value

    with pytest.raises(ValueError):
        host.AdmitContainer(container, Images()[1], OWNER, REVISION)


def Termination():
    """Describe synthetic post-exit state independently from output or Docker CLI success."""

    return {**Container()["state"], "Status": "exited", "StartedAt": "2026-10-29T00:00:00Z",
            "FinishedAt": "2026-10-29T00:00:01Z"}


def test_ActualTerminationIsASeparateAdmissionRequirement():
    """An independently read stopped-state projection can pass without granting case acceptance."""

    host.AdmitTermination(Termination(), 0)


@pytest.mark.parametrize("field,value", [("Running", True), ("Pid", 123), ("ExitCode", 137),
    ("ExitCode", False), ("OOMKilled", True), ("Status", "running"),
    ("StartedAt", host.ZERO_TIME), ("FinishedAt", "2026-10-28T00:00:00Z"),
    ("FinishedAt", "2026-10-29T00:00:01")],
    ids=["running", "pid", "exit", "boolean", "oom", "status", "zero", "order", "naive"])
def test_TerminationRefusesLiveFailedOomOrUnprovenState(field, value):
    """CLI exit or a successful-looking bundle cannot replace independent final readback."""

    state = Termination()
    state[field] = value

    with pytest.raises(ValueError):
        host.AdmitTermination(state, 0)


@LINUX_CONTEXT
def test_InvalidInventoryRefusesBeforeCreatingContext(tmp_path, monkeypatch):
    """Complete inventory validation precedes even the first owned destination directory."""

    _, destination, _ = OwnedContext(tmp_path, monkeypatch)

    with pytest.raises(ValueError):
        host.SnapshotContext(destination, GitRow("inert-alias", mode="120000"))

    assert not destination.exists(), "Invalid committed material must not begin context copying."


@LINUX_CONTEXT
def test_ContextParentAliasRefusesBeforeAnyOutsideRead(tmp_path, monkeypatch):
    """Validate source parents from the repository outward before opening a linked child."""

    repository, destination, _ = OwnedContext(tmp_path, monkeypatch, {"ordinary": b"inert"})
    outside = tmp_path / "inert-sibling-not-repository"
    outside.mkdir()
    (outside / "child").write_bytes(b"inert outside fixture")
    (repository / "alias").symlink_to(outside, target_is_directory=True)
    original = host.Path.open

    def Open(path, *arguments, **options):
        """Refuse a fixture alias read so traversal cannot be mistaken for a later hash mismatch."""

        if path == repository / "alias/child":
            raise AssertionError("Symbolic source parent must refuse before reading its child")

        return original(path, *arguments, **options)

    monkeypatch.setattr(host.Path, "open", Open)

    with pytest.raises(ValueError, match="symbolic source"):
        host.SnapshotContext(destination, GitRow("alias/child", b"inert outside fixture"))


@LINUX_CONTEXT
def test_ContextSnapshotPreservesDeclaredExecutableGitMode(tmp_path, monkeypatch):
    """A committed executable keeps Linux modes without executing its fixture bytes."""

    repository, destination, _ = OwnedContext(tmp_path, monkeypatch,
                                             {"inert.sh": b"never execute\n"})
    (repository / "inert.sh").chmod(0o755)
    copied = host.SnapshotContext(destination,
        GitRow("inert.sh", b"never execute\n", mode="100755"))
    assert copied["inert.sh"]["mode"] == "100755" and (
        (destination / "inert.sh").stat().st_mode & 0o111 == 0o111
    ), "Snapshot permissions must preserve the declared Git executable bit on real Linux."


def test_MissingNeutralContainerFieldCannotBeAssumed():
    """Omitted inspect fields cannot inherit a convenient neutral Docker default."""

    container = Container()
    del container["host"]["binds"]

    with pytest.raises(ValueError, match="missing or unknown"):
        host.AdmitContainer(container, Images()[1], OWNER, REVISION)


def test_DockerConfigMustRemainInsideTheOwnedEvidenceRun(tmp_path, monkeypatch):
    """An arbitrary host config/home path cannot replace the future owner's new empty directory."""

    monkeypatch.setattr(host, "REPOSITORY", tmp_path)

    with pytest.raises(ValueError, match="owned empty config"):
        host.DockerCommand(tmp_path / "inert-host-home", "info")


@pytest.mark.parametrize("restart_count", [1, False], ids=["restarted", "boolean"])
def test_TerminationRequiresOriginalZeroIntegerRestartCount(restart_count):
    """A restarted or ill-typed state cannot establish a single completed prerequisite run."""

    with pytest.raises(ValueError, match="terminate successfully"):
        host.AdmitTermination(Termination(), restart_count)


@pytest.mark.parametrize("started,finished,accepted", [
    ("00:00:00.000000002Z", "00:00:00.000000001Z", False),
    ("00:00:00.000000001Z", "00:00:00.000000001Z", True),
    ("00:00:00.000000001Z", "00:00:00.000000002Z", True),
    ("00:00:00.123456789Z", "00:00:00.123456788Z", False),
    ("00:00:00.123456Z", "00:00:00.123456001Z", True),
    ("00:00:00.1Z", "00:00:00.100000000Z", True),
    ("00:00:00.999999999Z", "00:00:01Z", True),
    ("01:00:00.000000001+01:00", "00:00:00.000000002Z", True),
    ("01:00:00.000000002+01:00", "00:00:00.000000001Z", False),
    ("00:00:00.0000000001Z", "00:00:01Z", False),
], ids=["reversed-nanos", "equal-nanos", "ordered-nanos", "reversed-submicro",
    "six-to-nine", "equal-padding", "second-boundary", "ordered-offset",
    "reversed-offset", "unsupported-precision"])
def test_TerminationComparesOriginalNanosecondsWithoutTruncation(started, finished, accepted):
    """Synthetic Docker times preserve exact fractional order without claiming a real run."""

    state = Termination()
    state.update(StartedAt="2026-10-29T" + started, FinishedAt="2026-10-29T" + finished)

    if accepted:
        host.AdmitTermination(state, 0)

    else:
        with pytest.raises(ValueError, match="ordered aware timestamps"):
            host.AdmitTermination(state, 0)


class InertExecution:
    """Mimic only the existing process-owner protocol, with no child or daemon.

    Args:
        stdout: Original synthetic binary stdout.
        stderr: Original synthetic binary stderr.
        code: Labeled worker status.
        blocked: Wait for termination instead of immediate completion.
        refuse: Refuse private cleanup verification.
    """

    def __init__(self, stdout=b"\xfforiginal\x00", stderr=b"", code=0, blocked=False, refuse=False):
        """Initialize finite stream readers and a synthetic termination event."""

        self.process = self
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdout.feed_data(stdout)
        self.stderr.feed_data(stderr)
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self.returncode = None
        self.worker_returncode = None
        self.verified = False
        self.receipt = None
        self.closed = False
        self.stopped = False
        self.blocked = blocked
        self.refuse = refuse
        self.code = code
        self.event = asyncio.Event()
        self.wait = self.WaitProcess
        self.terminate = self.Terminate
        self.kill = self.Kill

    async def WaitProcess(self):
        """Return the synthetic status after any declared termination dependency."""

        if self.blocked:
            await self.event.wait()

        self.returncode = self.code

        return self.code

    async def Wait(self):
        """Simulate the reused owner's exit-and-private-receipt protocol."""

        await self.wait()
        self.Verify()

        return self.worker_returncode

    def Verify(self):
        """Refuse or bind the explicitly labeled synthetic cleanup receipt."""

        if self.refuse:
            raise ValueError("inert cleanup refusal")

        self.worker_returncode = self.code
        self.verified = True
        self.receipt = {"inert": True}

    def Terminate(self):
        """Release a blocked fake worker without signaling any process."""

        self.stopped = True
        self.event.set()

    def Kill(self):
        """Release the same synthetic event for forced-exit contracts."""

        self.terminate()

    def Close(self):
        """Record protocol closure without operating on a descriptor."""

        self.closed = True


async def CaptureInert(tmp_path, monkeypatch, **options):
    """Run bounded capture with a fake owner and synthetic repository only.

    Args:
        tmp_path: New pytest-owned directory.
        monkeypatch: Scoped replacement of the process-owner handoff.
        options: Fake-owner fields; optional stdout_limit selects a small byte cap.

    Returns:
        Original capture result, fake owner and command directory.
    """

    _, context, _ = OwnedContext(tmp_path, monkeypatch)
    limit = options.pop("stdout_limit", 1024)
    fake = InertExecution(**options)

    async def Start(*arguments):
        """Return the fake protocol object without creating a process."""

        return fake

    monkeypatch.setattr(host, "StartOwnedExecution", Start)
    directory = context.parent / "command"
    result = await host.CaptureCommand(directory, ("inert",), host.REPOSITORY,
                                       {"HOME": "inert"}, 1, limit, 1024)

    return result, fake, directory


@LINUX_CONTEXT
@pytest.mark.parametrize("code", [0, 7], ids=["zero", "nonzero"])
def test_HostCommandOriginalBinaryAndWorkerStatus(tmp_path, monkeypatch, code):
    """Keep binary originals and worker status without text decoding or success invention."""

    result, fake, directory = asyncio.run(CaptureInert(tmp_path, monkeypatch, code=code))
    assert (directory / "stdout.raw").read_bytes() == b"\xfforiginal\x00", (
        'Original bytes, worker status and private cleanup must remain independently truthful.'
    )
    assert result["exit_code"] == code and result["streams_complete"] is True, (
        'Original bytes, worker status and private cleanup must remain independently truthful.'
    )
    assert result["cleanup_confirmed"] is True and fake.closed, (
        'Original bytes, worker status and private cleanup must remain independently truthful.'
    )


@LINUX_CONTEXT
@pytest.mark.parametrize("role", ["stdout", "stderr"], ids=["stdout", "stderr"])
def test_HostCommandOverflowKeepsOneWitnessAndStops(tmp_path, monkeypatch, role):
    """The first over-budget byte is retained and overflow cannot become completed capture."""

    with pytest.raises(ValueError, match="capture exhausted"):
        asyncio.run(CaptureInert(tmp_path, monkeypatch, **{role: b"x" * 1025}))

    directory = next(host.REPOSITORY.glob("functional-evidence/*/run-*/command"))
    result = host.StrictJson((directory / "command.json").read_bytes())
    assert len((directory / (role + ".raw")).read_bytes()) == 1025, (
        'Overflow must retain exactly one witness and refuse successful capture.'
    )
    assert result["capture_exhausted"] == role and result["streams_complete"] is False, (
        'Overflow must retain exactly one witness and refuse successful capture.'
    )
    assert result["cleanup_confirmed"] is True, (
        'Overflow must retain exactly one witness and refuse successful capture.'
    )


@LINUX_CONTEXT
def test_HostCommandDeadlineSeparatesCleanupFromCompletion(tmp_path, monkeypatch):
    """A terminated fake command retains its deadline refusal even after confirmed CLI cleanup."""

    with pytest.raises(TimeoutError):
        asyncio.run(CaptureInert(tmp_path, monkeypatch, blocked=True))

    directory = next(host.REPOSITORY.glob("functional-evidence/*/run-*/command"))
    result = host.StrictJson((directory / "command.json").read_bytes())
    assert result["timed_out"] is True and result["cleanup_confirmed"] is True, (
        'Deadline refusal must survive confirmed CLI cleanup.'
    )
    assert result["streams_complete"] is False, (
        'Deadline refusal must survive confirmed CLI cleanup.'
    )


@LINUX_CONTEXT
def test_HostCommandCleanupRefusalPreservesCaptureFailure(tmp_path, monkeypatch):
    """The overflow remains primary while failed private cleanup is separately recorded."""

    with pytest.raises(ValueError, match="capture exhausted") as failure:
        asyncio.run(CaptureInert(tmp_path, monkeypatch, stdout=b"x" * 1025, refuse=True))

    directory = next(host.REPOSITORY.glob("functional-evidence/*/run-*/command"))
    result = host.StrictJson((directory / "command.json").read_bytes())
    assert result["cleanup_confirmed"] is False and result["cleanup_error"] == "ValueError", (
        'Keep the capture error primary and retain separate cleanup refusal.'
    )
    assert any("cleanup unconfirmed" in note for note in failure.value.__notes__), (
        'Keep the capture error primary and retain separate cleanup refusal.'
    )


@pytest.mark.parametrize("platform", ["win32", "darwin"], ids=["windows", "macos"])
def test_HostCommandUnsupportedBeforeWrites(tmp_path, monkeypatch, platform):
    """Unsupported host ownership refuses before opening original capture files."""

    monkeypatch.setattr(host.sys, "platform", platform)

    with pytest.raises(ValueError, match="require Linux"):
        asyncio.run(host.CaptureCommand(tmp_path / "unwritten", ("inert",), tmp_path, {}, 1, 1, 1))

    assert list(tmp_path.iterdir()) == [], (
        'Unsupported ownership must refuse before any output write.'
    )


@LINUX_CONTEXT
@pytest.mark.parametrize("field", ["directory", "cwd"], ids=["output-parent", "cwd-parent"])
def test_HostCommandRejectsParentTraversalBeforeWrites(tmp_path, monkeypatch, field):
    """Lexically prefixed parent paths cannot escape the owner boundary."""

    _, context, _ = OwnedContext(tmp_path, monkeypatch)
    directory, cwd = context.parent / "command", host.REPOSITORY

    if field == "directory":
        directory = context.parent / ".." / ".." / "escaped"

    else:
        cwd = host.REPOSITORY / ".." / "escaped"

    with pytest.raises(ValueError, match="owned paths"):
        asyncio.run(host.CaptureCommand(directory, ("inert",), cwd, {}, 1, 8, 8))

    assert not (context.parent / "command").exists(), (
        'Parent traversal must refuse before opening capture files.'
    )


@LINUX_CONTEXT
def test_HostCommandOverflowContinuesFlowControlledDrain(tmp_path, monkeypatch):
    """Require post-overflow draining before the fake supervisor can complete its pipe wait."""

    async def Scenario():
        """Require drain-after-witness before the fake supervisor can verify its receipt."""

        _, context, _ = OwnedContext(tmp_path, monkeypatch)
        fake = InertExecution(blocked=True)
        drained = asyncio.Event()

        class FlowReader:
            """Expose overflow then EOF only while the reader continues draining."""

            def __init__(self):
                """Begin with an unread over-budget chunk."""

                self.reads = 0
                self.read = self.Read

            async def Read(self, maximum):
                """Advance finite synthetic flow control without a transport or process."""

                self.reads += 1

                if self.reads == 1:
                    return b"x" * 70000

                drained.set()
                fake.event.set()

                return b""

        fake.stdout = FlowReader()

        async def Start(*arguments):
            """Return the flow-dependent fake owner."""

            return fake

        monkeypatch.setattr(host, "StartOwnedExecution", Start)

        with pytest.raises(ValueError, match="capture exhausted"):
            await host.CaptureCommand(context.parent / "command", ("inert",), host.REPOSITORY,
                                      {}, 1, 8, 8)

        assert drained.is_set() and fake.closed and fake.verified, (
            'Flow-control/cancellation cleanup must drain, close and retain its original receipt.'
        )
        assert (context.parent / "command/stdout.raw").read_bytes() == b"x" * 9, (
            'Flow-control/cancellation cleanup must drain, close and retain its original receipt.'
        )

    asyncio.run(Scenario())


@LINUX_CONTEXT
def test_HostCommandRepeatedCancellationStillClosesAndRetains(tmp_path, monkeypatch):
    """Repeated caller cancellation cannot interrupt the finalizer's joins or original receipt."""

    async def Scenario():
        """Cancel during command wait and again during delayed synthetic cleanup."""

        _, context, _ = OwnedContext(tmp_path, monkeypatch)
        fake = InertExecution(blocked=True)
        started, finalizing, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

        def Stop():
            """Delay fake exit so a second cancellation intersects finalization."""

            finalizing.set()

        async def Wait():
            """Wait for a controlled inert cleanup release."""

            await release.wait()
            fake.returncode = 0
            fake.Verify()

            return 0

        async def Start(*arguments):
            """Signal ownership handoff to the synthetic cancellation driver."""

            started.set()

            return fake

        fake.terminate, fake.Wait = Stop, Wait
        monkeypatch.setattr(host, "StartOwnedExecution", Start)
        task = asyncio.create_task(host.CaptureCommand(context.parent / "command", ("inert",),
            host.REPOSITORY, {}, 1, 1024, 1024))
        await started.wait()
        await asyncio.sleep(0)
        task.cancel()
        await finalizing.wait()
        task.cancel()
        await asyncio.sleep(0)
        release.set()

        with pytest.raises(asyncio.CancelledError):
            await task

        result = host.StrictJson((context.parent / "command/command.json").read_bytes())
        assert fake.closed and result["cleanup_confirmed"] is True, (
            'Flow-control/cancellation cleanup must drain, close and retain its original receipt.'
        )
        assert result["interrupted"] == "CancelledError", (
            'Flow-control/cancellation cleanup must drain, close and retain its original receipt.'
        )

    asyncio.run(Scenario())


def RawImage(image, owner=OWNER):
    """Express labeled synthetic image projections as Docker-shaped original JSON."""

    return {"Id": image["id"], "Os": image["os"], "Architecture": image["architecture"],
        "RootFS": {"Layers": image["layers"]}, "Config": {"Labels": {
            **image["labels"], host.OWNER_LABEL: owner}, "Env": image["env"],
            "User": image.get("user", "workbench"), "Entrypoint": image.get("entrypoint"),
            "Cmd": image.get("cmd"), "Volumes": image.get("volumes"),
            "ExposedPorts": image.get("ports"), "OnBuild": None, "Healthcheck": None}}


def RawContainer():
    """Return complete declared Docker-shaped fixture data without consulting a daemon."""

    value = Container()
    fields = {"network": "NetworkMode", "readonly": "ReadonlyRootfs", "privileged": "Privileged",
        "init": "Init", "binds": "Binds", "ports": "PortBindings", "cap_drop": "CapDrop",
        "cap_add": "CapAdd", "devices": "Devices", "device_requests": "DeviceRequests",
        "volumes_from": "VolumesFrom", "security": "SecurityOpt", "memory": "Memory",
        "cpu": "NanoCpus", "pids": "PidsLimit", "tmpfs": "Tmpfs", "pid_mode": "PidMode",
        "ipc_mode": "IpcMode", "uts_mode": "UTSMode", "userns_mode": "UsernsMode",
        "auto_remove": "AutoRemove", "restart": "RestartPolicy", "publish_all": "PublishAllPorts",
        "extra_hosts": "ExtraHosts", "links": "Links", "groups": "GroupAdd"}
    settings = {fields[key]: item for key, item in value["host"].items()}
    settings.update(Dns=[], DnsOptions=[], DnsSearch=[], Sysctls={}, StorageOpt={},
        CgroupParent="", ContainerIDFile="", Runtime="runc", CgroupnsMode="private")

    return {"Id": value["id"], "Name": value["name"], "Image": IMAGE_ID,
        "Config": {"Labels": {host.OWNER_LABEL: OWNER, host.SOURCE_LABEL: REVISION},
            "Image": IMAGE_ID, "User": value["user"], "Entrypoint": value["entrypoint"],
            "Cmd": value["cmd"], "Env": value["env"], "OpenStdin": False, "StdinOnce": False,
            "Tty": False, "StopTimeout": 5, "Healthcheck": None}, "HostConfig": settings,
        "Mounts": [], "State": value["state"], "RestartCount": 0,
        "NetworkSettings": {"Networks": {"none": {"IPAddress": "", "GlobalIPv6Address": "",
                                                    "Gateway": "", "IPv6Gateway": ""}}}}


class InertHost(host.PrerequisiteHost):
    """Exercise the actual lifecycle against finite labeled command replies only.

    Args:
        inventory: Synthetic Git metadata for pytest-owned source files.
        fault: One bounded causal failure selected by a short explicit identifier.
    """

    def __init__(self, inventory, fault=None):
        """Initialize fake daemon resources and retain every internally requested command."""

        super().__init__()
        self.inventory = inventory
        self.fault = fault
        base, image = Images()
        self.raw_images = {BASE_ID: RawImage(base), IMAGE_ID: RawImage(image)}
        self.raw_container = RawContainer()
        self.present_tags = {}
        self.container_present = False
        self.calls = []

    async def Command(self, role, arguments, **options):
        """Return synthetic originals and record fixed lifecycle arguments, never invoke capture."""

        self.calls.append((role, arguments, options))
        raw = b""

        if role.endswith("-identity"):
            raw = (REVISION + "\n" + "e" * 40 + "\n").encode()

        elif role == "source-inventory":
            raw = self.inventory

        elif role == "daemon":
            raw = b'{"os":"linux","architecture":"amd64"}'

        elif role.endswith("-build"):
            identifier = BASE_ID if role == "base-build" else IMAGE_ID
            tag = self.tags[0 if role == "base-build" else 1]
            self.present_tags[tag] = identifier
            (self.root / (role.removesuffix("-build") + ".iid")).write_text(identifier + "\n")

        elif role == "create":
            self.container_present = True
            raw = (self.raw_container["Id"] + "\n").encode()

        elif role == "attach":
            self.raw_container["State"] = Termination()
            raw = b"inert-original-bundle"

            if self.fault == "attach-running":
                self.raw_container["State"].update(Status="running", Running=True, Pid=77)

                raise ValueError("inert attach left an owned running container")

        elif "inspect" in arguments:
            identifier = arguments[-1]
            value = self.raw_container if arguments[0] == "container" else self.raw_images[
                self.present_tags.get(identifier, identifier)]
            raw = host.Canonical(value).encode()

        elif role in ("cleanup-owner-list", "cleanup-absence"):
            raw = (self.raw_container["Id"] + "\n").encode() if self.container_present else b""

        elif role in ("cleanup-tag-list", "cleanup-tag-absence"):
            tag = arguments[-1].removeprefix("reference=")
            raw = (self.present_tags[tag] + "\n").encode() if tag in self.present_tags else b""

        elif role == "cleanup-remove":
            self.container_present = False

        elif role == "cleanup-tag-remove":
            self.present_tags.pop(arguments[-1])

        elif role == "cleanup-kill":
            self.raw_container["State"].update(Status="exited", Running=False, Pid=0)

        if self.fault == role:
            raise ValueError("inert causal fault: " + role)

        if self.fault == "oom" and role == "container-after":
            value = host.StrictJson(raw)
            value["State"]["OOMKilled"] = True
            raw = host.Canonical(value).encode()

        if self.fault == "owner" and role == "container-before":
            self.raw_container["Config"]["Labels"][host.OWNER_LABEL] = "f" * 32
            raw = host.Canonical(self.raw_container).encode()

        if self.fault == "network" and role == "container-before":
            self.raw_container["HostConfig"]["NetworkMode"] = "bridge"
            raw = host.Canonical(self.raw_container).encode()

        if self.fault == "tag-drift" and role == "base-tag-after":
            value = host.StrictJson(raw)
            value["Id"] = IMAGE_ID
            raw = host.Canonical(value).encode()

        return {"exit_code": 0}, raw


@pytest.fixture
def inert_lifecycle(tmp_path, monkeypatch):
    """Replace only actual host/process discovery; retain the real lifecycle/state predicates."""

    files = {"Dockerfile": b"inert development recipe", host.RECIPE_PATH: RECIPE,
             "src/fuzzy1337/inert.py": b"inert package"}
    _, context, inventory = OwnedContext(tmp_path, monkeypatch, files)
    monkeypatch.setattr(host, "uuid4", lambda: type("Identity", (), {"hex": OWNER})())
    original = host.Path.is_file
    monkeypatch.setattr(host.Path, "is_file", lambda path: path.as_posix() in (
        "/usr/bin/docker", "/usr/bin/git") or original(path))
    monkeypatch.setattr(host.os, "access", lambda *arguments: True)
    monkeypatch.setattr(host.platform, "machine", lambda: "x86_64")
    context.parent.rmdir()

    def Bundle(raw, output, source, revision):
        """Record isolated bundle admission after requiring the synthetic original/source."""

        assert raw == b"inert-original-bundle" and revision == REVISION, (
            'Bundle admission must receive the exact original bytes and committed source.'
        )
        assert source[host.RECIPE_PATH]["sha256"] == hashlib.sha256(RECIPE).hexdigest(), (
            'Bundle admission must receive the exact original bytes and committed source.'
        )

        return {"inert": True}

    monkeypatch.setattr(host, "BindBundle", Bundle)

    return inventory


@LINUX_CONTEXT
def test_HostLifecycleOneBuildPairAndOneOfflineAttach(inert_lifecycle):
    """Successful synthetic source exercises ordered admission, one attach and verified cleanup."""

    runtime = InertHost(inert_lifecycle)
    receipt = asyncio.run(runtime.Run())
    roles = [role for role, _, _ in runtime.calls]
    assert receipt["status"] == "completed-prerequisites", (
        'The finite lifecycle must preserve admission order, isolation and verified cleanup.'
    )
    assert roles.count("base-build") == roles.count("runner-build") == roles.count("attach") == 1, (
        'The finite lifecycle must preserve admission order, isolation and verified cleanup.'
    )
    assert roles.index("container-before") < roles.index("attach") < (
        roles.index("container-after")
    ), (
        'The finite lifecycle must preserve admission order, isolation and verified cleanup.'
    )
    assert roles.index("container-after") < roles.index("cleanup-remove"), (
        'The finite lifecycle must preserve admission order, isolation and verified cleanup.'
    )
    assert not runtime.container_present and not runtime.present_tags and (
        not runtime.context.exists()
    ), (
        'The finite lifecycle must preserve admission order, isolation and verified cleanup.'
    )
    create = next(arguments for role, arguments, _ in runtime.calls if role == "create")
    assert create[-2:] == (IMAGE_ID, "--prerequisites") and "--network" in create, (
        'The finite lifecycle must preserve admission order, isolation and verified cleanup.'
    )
    assert create[create.index("--network") + 1] == "none", (
        'The finite lifecycle must preserve admission order, isolation and verified cleanup.'
    )
    assert ("--label", host.OWNER_LABEL + "=" + OWNER) == create[-4:-2], (
        'The finite lifecycle must preserve admission order, isolation and verified cleanup.'
    )
    runner = next(arguments for role, arguments, _ in runtime.calls if role == "runner-build")
    assert "WORKBENCH_IMAGE=" + runtime.tags[0] in runner and "--pull=false" in runner, (
        'The finite lifecycle must preserve admission order, isolation and verified cleanup.'
    )
    assert runtime.environment == {"HOME": str(runtime.root / "home"),
        "PATH": "/usr/local/bin:/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}, (
        'The finite lifecycle must preserve admission order, isolation and verified cleanup.'
    )


@LINUX_CONTEXT
@pytest.mark.parametrize("fault", ["network", "owner", "tag-drift", "oom", "create", "attach",
    "cleanup-remove", "cleanup-absence", "runner-build", "attach-running"],
    ids=["pre-network", "pre-owner", "base-drift", "post-oom", "ambiguous-create", "attach-fail",
         "remove-fail", "absence-unknown", "backend-unknown", "running-cleanup"])
def test_HostLifecycleFailuresNeverBecomeAcceptance(inert_lifecycle, fault):
    """Each isolated failure stays failed while finally attempts only verified owned cleanup."""

    runtime = InertHost(inert_lifecycle, fault)

    with pytest.raises((ValueError, ExceptionGroup)):
        asyncio.run(runtime.Run())

    receipt = host.StrictJson((runtime.root / "host.json").read_bytes())
    assert receipt["status"] == "failed" and receipt["cleanup"], (
        'A refused lifecycle must fail and clean only its proven owned resources.'
    )
    roles = [role for role, _, _ in runtime.calls]
    assert "cleanup-tag-list" in roles, (
        'A refused lifecycle must fail and clean only its proven owned resources.'
    )

    if fault in ("network", "owner", "tag-drift", "runner-build"):
        assert "attach" not in roles, (
            'A refused lifecycle must fail and clean only its proven owned resources.'
        )

    if fault == "owner":
        assert "cleanup-remove" not in roles, (
            'A refused lifecycle must fail and clean only its proven owned resources.'
        )

    if fault == "create":
        assert "cleanup-remove" in roles, (
            'A refused lifecycle must fail and clean only its proven owned resources.'
        )

    if fault == "attach-running":
        assert roles.index("cleanup-kill") < roles.index("cleanup-wait") < (
            roles.index("cleanup-stopped")
        ) < roles.index("cleanup-remove"), (
            "Owned running containers require kill/wait and independent stopped readback before rm."
        )

    if fault in ("cleanup-remove", "cleanup-absence", "runner-build"):
        assert receipt["cleanup_failure"] == "ExceptionGroup", (
            'A refused lifecycle must fail and clean only its proven owned resources.'
        )


@pytest.mark.parametrize("value,expected", [(None, False), ("", False), ("linux-amd64", True)],
                         ids=["absent", "empty", "enabled"])
def test_HostLifecycleSelectionIsExplicit(value, expected):
    """Selection is a pure explicit gate and never discovers Docker."""

    assert host.Enabled(value) is expected, (
        'Only the exact enabled value may discover local tooling.'
    )


def test_HostLifecycleInvalidSelectionRefuses():
    """A mistyped opt-in is an enabled setup failure rather than a passing skip."""

    with pytest.raises(ValueError, match="explicit"):
        host.Enabled("true")


def BundleFixture(directory):
    """Write labeled finite stage originals and matching synthetic source/provisioning inventories.

    Args:
        directory: New pytest-owned bundle root; no image, wheel or binary is materialized.

    Returns:
        Synthetic source inventory and mutable original manifest for causal refusal oracles.
    """

    directory.mkdir()
    source = {}

    for name in (*host.SUPPORT_FILES,):
        source["tests/functional/" + name] = {"sha256": hashlib.sha256(name.encode()).hexdigest(),
                                               "size_bytes": len(name)}

    source[host.RECIPE_PATH] = {"sha256": hashlib.sha256(RECIPE).hexdigest(), "size_bytes": 1}
    source["labs/external/benchmark/templates/prometheus-exposition.yaml"] = {
        "sha256": host.TEMPLATE_SHA256, "size_bytes": host.TEMPLATE_BYTES}
    package = {}

    for name in host.MODULES:
        relative = name.replace(".", "/") + ".py"
        package[relative] = {"sha256": hashlib.sha256(name.encode()).hexdigest(),
                             "size_bytes": len(name)}
        source["src/fuzzy1337/" + relative] = package[relative]

    outcome = {"status": "completed-prerequisites", "version_probe": "completed",
        "go_template_validation": "completed", "governed_no_home_compatibility": "not-established",
        "configured_target_inputs": [], "independent_server_contact_count": None}
    manifest = {"schema_version": 1, "source_revision": REVISION,
        "status": "material-prepared-prerequisites-not-run", "asset_url": host.ASSET_URL,
        "recipe_sha256": source[host.RECIPE_PATH]["sha256"],
        "support_sha256": {name: source["tests/functional/" + name]["sha256"]
                           for name in host.SUPPORT_FILES},
        "installed": {"installed": {"source_revision": REVISION,
            "package_path": "/opt/benchmark-runtime/lib/python3.11/site-packages/fuzzy1337",
            "distribution_version": "inert", "runner_sha256": source[
                "tests/functional/external_nuclei_runner.py"]["sha256"],
            "wheel": {"path": "/opt/benchmark-wheel/inert.whl", "size_bytes": 1,
                       "sha256": "a" * 64},
            "module_sha256": {name: package[name.replace(".", "/") + ".py"]["sha256"]
                              for name in host.MODULES}},
            "package_files": package, "coverage": {
                "package_content": "all ordinary fuzzy1337 files",
                "actual_import_modules": list(host.MODULES),
                "excluded_generated": ["__pycache__/**", "*.pyc"],
                "excluded_content": ["distribution metadata", "dependencies"]}},
        "material": {"archive": {"sha256": host.ARCHIVE_SHA256, "size_bytes": host.ARCHIVE_BYTES,
            "path": "/opt/benchmark-download/" + host.ARCHIVE_NAME},
            "version_probe": "not-run", "go_template_validation": "not-run",
            "release_inventory": [{"name": "nuclei", "size_bytes": 1,
                                    "crc_verified": True, "crc32": "aaaaaaaa"}],
            "executable": {"path": "/opt/benchmark-material/nuclei", "sha256": "b" * 64,
                           "size_bytes": 1},
            "profile": {"templates": [{"path": "/opt/benchmark-material/prometheus-exposition.yaml",
                "sha256": host.TEMPLATE_SHA256, "size_bytes": host.TEMPLATE_BYTES}],
                "configuration_path": "/opt/benchmark-material/operator-config.yaml"}}}
    host.WriteJson(directory / "image-provisioning.json", manifest)
    host.WriteJson(directory / "prerequisites.json", outcome)
    environment = {"HOME": "/tmp/nuclei-prerequisites/home",
        "XDG_CONFIG_HOME": "/tmp/nuclei-prerequisites/home/config",
        "XDG_CACHE_HOME": "/tmp/nuclei-prerequisites/home/cache",
        "TMPDIR": "/tmp/nuclei-prerequisites/home/tmp"}
    arguments = {"version": ["/opt/benchmark-material/nuclei", "-version", "-duc"],
        "validate": ["/opt/benchmark-material/nuclei", "-validate", "-t",
            "/opt/benchmark-material/prometheus-exposition.yaml", "-config",
            "/opt/benchmark-material/operator-config.yaml", "-duc", "-ni", "-no-stdin", "-pt",
            "http", "-nc"]}

    for name, argv in arguments.items():
        stage = directory / name
        stage.mkdir()
        host.WriteJson(stage / "invocation.json", {"argv": argv, "environment": environment,
            "provider_timeout_seconds": 3, "stdout_capture_bytes": 4 * 1024 * 1024,
            "stderr_capture_bytes": 65536, "stdout_interpretation_bytes": 16384
                if name == "version" else 2 * 1024 * 1024,
            "stderr_interpretation_bytes": 16384, "original_file_ceiling_bytes": 2 * 1024 * 1024,
            "basis": "target-free-explicit-home-prerequisite"})
        host.WriteJson(stage / "process.json", {"exit_code": 0, "streams_complete": True,
            "timed_out": False, "capture_exhausted": None, "launch_error": None,
            "capture_error": None, "interrupted": None, "cleanup_error": None,
            "duration_seconds": 0.1})
        (stage / "stdout.raw").write_bytes(b"Nuclei Engine Version: v3.4.10" if name == "version"
                                          else b"All templates validated successfully")
        (stage / "stderr.raw").write_bytes(b"")

    return source, manifest


@pytest.mark.parametrize("fault", [None, "source", "support", "recipe", "archive", "wheel",
    "module", "binary", "template", "target", "timeout", "output", "version", "outcome"],
    ids=["bound", "source", "support", "recipe", "archive", "wheel", "module", "binary",
         "template", "target-argv", "timeout", "validation-bytes", "version-bytes", "outcome"])
def test_HostBundleOriginalEvidenceAndSourceBinding(tmp_path, fault):
    """Only exact synthetic source/material and original stage evidence pass bundle admission."""

    from tests.functional.external_native_runner import ExportBundle

    directory = tmp_path / "bundle"
    source, manifest = BundleFixture(directory)

    if fault in ("source", "support", "recipe", "archive", "wheel", "module", "binary",
                 "template"):
        paths = {"source": ("source_revision",),
            "support": ("support_sha256", host.SUPPORT_FILES[0]),
            "recipe": ("recipe_sha256",), "archive": ("material", "archive", "sha256"),
            "wheel": ("installed", "installed", "wheel", "path"),
            "module": ("installed", "installed", "module_sha256", host.MODULES[0]),
            "binary": ("material", "executable", "sha256"),
            "template": ("material", "profile", "configuration_path")}
        value = manifest

        for key in paths[fault][:-1]:
            value = value[key]

        value[paths[fault][-1]] = "inert changed identity"
        host.WriteJson(directory / "image-provisioning.json", manifest)

    if fault in ("target", "timeout", "outcome"):
        relative = {"target": "validate/invocation.json", "timeout": "validate/process.json",
                    "outcome": "prerequisites.json"}[fault]
        value = host.StrictJson((directory / relative).read_bytes())

        if fault == "target":
            value["argv"].extend(["-u", "http://inert.invalid"])

        elif fault == "timeout":
            value["timed_out"] = True

        else:
            value["status"] = "failed"

        host.WriteJson(directory / relative, value)

    if fault in ("output", "version"):
        (directory / ("validate" if fault == "output" else "version") / "stdout.raw").write_bytes(
            b"labeled fixture without required success receipt")

    outcome = host.StrictJson((directory / "prerequisites.json").read_bytes())
    raw = ExportBundle(directory, outcome).encode()

    if fault is None:
        bundle = host.BindBundle(raw, tmp_path / "imported", source, REVISION)
        assert len(bundle["files"]) == 10, (
            'Bound original bundle files and their hash inventory must survive admission.'
        )
        assert (tmp_path / "bundle-inventory.json").exists(), (
            'Bound original bundle files and their hash inventory must survive admission.'
        )

    else:
        with pytest.raises(ValueError):
            host.BindBundle(raw, tmp_path / "imported", source, REVISION)


@pytest.mark.parametrize("field", ["OpenStdin", "Tty", "Healthcheck"],
                         ids=["stdin", "tty", "healthcheck"])
def test_HostProjectionRefusesAdditionalInitialization(field):
    """Unknown interactive or healthcheck initialization cannot reach pre-start admission."""

    raw = RawContainer()
    raw["Config"][field] = True

    with pytest.raises(ValueError):
        host.ContainerProjection(raw)


def test_HostProjectionMissingDaemonDefaultRefuses():
    """Absent runtime readback cannot silently become an accepted neutral default."""

    raw = RawContainer()
    del raw["HostConfig"]["Runtime"]

    with pytest.raises(KeyError):
        host.ContainerProjection(raw)


def test_HostFunctionalDisabledSkipsBeforeOwnerConstruction(monkeypatch):
    """Invoke only the disabled fixture function; no functional pytest or Docker discovery runs."""

    from tests.functional import test_external_nuclei_prerequisites as functional

    def Forbidden():
        """Reject owner construction if disabled selection crosses its boundary."""

        raise AssertionError("Disabled fixture attempted host discovery")

    monkeypatch.delenv(host.SELECTION, raising=False)
    monkeypatch.setattr(functional, "PrerequisiteHost", Forbidden)

    with pytest.raises(pytest.skip.Exception, match="UNRUN"):
        functional.nuclei_prerequisite.__wrapped__()


@LINUX_CONTEXT
def test_HostLifecyclePrimaryFailureSurvivesCleanupRefusal(inert_lifecycle, monkeypatch):
    """A separate removal failure annotates the original attach failure without replacing it."""

    runtime = InertHost(inert_lifecycle, "attach")
    command = runtime.Command

    async def RefuseRemoval(role, arguments, **options):
        """Inject a second independent daemon-cleanup failure after the primary refusal."""

        if role == "cleanup-remove":
            raise OSError("inert removal refused")

        return await command(role, arguments, **options)

    monkeypatch.setattr(runtime, "Command", RefuseRemoval)

    with pytest.raises(ValueError, match="inert causal fault: attach") as failure:
        asyncio.run(runtime.Run())

    assert any("Independent Docker cleanup failed" in note for note in failure.value.__notes__), (
        "The primary attach refusal must retain its separate cleanup failure annotation."
    )
    receipt = host.StrictJson((runtime.root / "host.json").read_bytes())
    assert receipt["failure"]["exception_type"] == "ValueError" and (
        receipt["cleanup_failure"] == "ExceptionGroup"
    ), "The host receipt must keep primary and cleanup failures separate."


@pytest.mark.parametrize("platform", ["win32", "darwin"], ids=["windows", "macos"])
def test_HostFunctionalEnabledIncompatibleFailsBeforeDiscovery(monkeypatch, platform):
    """An enabled incompatible host fails setup instead of becoming a passing skip."""

    from tests.functional import test_external_nuclei_prerequisites as functional

    monkeypatch.setenv(host.SELECTION, "linux-amd64")
    monkeypatch.setattr(host.sys, "platform", platform)

    with pytest.raises(ValueError, match="native Linux/amd64"):
        functional.nuclei_prerequisite.__wrapped__()


@LINUX_CONTEXT
def test_HostLifecycleCommandBindsLocalAuthorityAndOriginalBytes(tmp_path, monkeypatch):
    """The command adapter passes fixed routing and explicit environment to the reused owner."""

    OwnedContext(tmp_path, monkeypatch)
    runtime = host.PrerequisiteHost()
    (runtime.root / "commands").mkdir(parents=True)
    runtime.environment = {"HOME": str(runtime.root / "home"), "PATH": "/usr/bin:/bin"}
    captured = []

    async def Capture(directory, argv, cwd, environment, seconds, stdout_bytes, stderr_bytes):
        """Return labeled protocol success while retaining only synthetic original bytes."""

        captured.append((argv, environment, seconds, stdout_bytes, stderr_bytes))
        directory.mkdir()
        (directory / "stdout.raw").write_bytes(b"\xffinert")

        return {"exit_code": 0, "cleanup_confirmed": True, "streams_complete": True,
            "timed_out": False, "capture_exhausted": None, "launch_error": None,
            "capture_error": None, "cleanup_error": None, "interrupted": None}

    monkeypatch.setattr(host, "CaptureCommand", Capture)
    monkeypatch.setenv("DOCKER_HOST", "tcp://inert.invalid:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "inert-foreign")
    _, raw = asyncio.run(runtime.Command("metadata", ("version",)))
    argv, environment, seconds, stdout_bytes, stderr_bytes = captured[0]
    assert argv == ("/usr/bin/docker", "--host", host.LOCAL_DOCKER, "--config",
                    str(runtime.config), "version"), (
        "Inherited remote Docker routing must never replace the explicit local endpoint."
    )
    assert environment == runtime.environment and "DOCKER_HOST" not in environment, (
        "Only the explicit owned process environment may cross the supervisor boundary."
    )
    assert raw == b"\xffinert" and (seconds, stdout_bytes, stderr_bytes) == (15, 262144, 262144), (
        "Metadata capture must retain original binary bytes within its declared finite budgets."
    )


@LINUX_CONTEXT
@pytest.mark.parametrize("kind", ["size", "alias"], ids=["oversized", "symbolic-alias"])
def test_HostLifecycleIidIsBoundedOrdinaryMaterial(inert_lifecycle, monkeypatch, kind):
    """Completed build output cannot make the owner read an unbounded or aliased iid file."""

    runtime = InertHost(inert_lifecycle)
    command = runtime.Command

    async def ChangeIid(role, arguments, **options):
        """Replace only synthetic build-written material before its ordinary-file admission."""

        result = await command(role, arguments, **options)

        if role == "base-build":
            iid = runtime.root / "base.iid"

            if kind == "size":
                iid.write_bytes(b"x" * 81)

            else:
                iid.unlink()
                iid.symlink_to(runtime.root / "not-an-image-id")

        return result

    monkeypatch.setattr(runtime, "Command", ChangeIid)

    with pytest.raises(ValueError, match="ordinary bounded private file"):
        asyncio.run(runtime.Run())

    assert "create" not in [role for role, _, _ in runtime.calls], (
        "Invalid iid custody must refuse before any container is created."
    )


@LINUX_CONTEXT
def test_HostFunctionalEnabledMissingDockerFails(monkeypatch):
    """An explicitly enabled missing local Docker binary fails rather than silently skipping."""

    from tests.functional import test_external_nuclei_prerequisites as functional

    original = host.Path.is_file
    monkeypatch.setenv(host.SELECTION, "linux-amd64")
    monkeypatch.setattr(host.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(host.Path, "is_file", lambda path: False
        if path.as_posix() == "/usr/bin/docker" else original(path))

    with pytest.raises(ValueError, match="fixed local Docker and Git"):
        functional.nuclei_prerequisite.__wrapped__()


@LINUX_CONTEXT
@pytest.mark.parametrize("boundary", ["kill", "remove"], ids=["kill-primary", "remove-cancel"])
def test_HostLifecycleRepeatedCancellationShieldsOwnedCleanup(
    inert_lifecycle, monkeypatch, boundary,
):
    """Repeated outer cancellation cannot skip owned cleanup or hide the primary failure."""

    async def Scenario():
        """Pause fake cleanup and verify its finalizer survives two caller cancellations."""

        runtime = InertHost(inert_lifecycle, "attach-running" if boundary == "kill" else None)
        command = runtime.Command
        entered, release = asyncio.Event(), asyncio.Event()

        async def DelayCleanup(role, arguments, **options):
            """Hold only the selected owned cleanup operation without starting any process."""

            if role == "cleanup-" + boundary:
                entered.set()
                await release.wait()

            return await command(role, arguments, **options)

        monkeypatch.setattr(runtime, "Command", DelayCleanup)
        task = asyncio.create_task(runtime.Run())
        await entered.wait()
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        release.set()

        if boundary == "kill":
            with pytest.raises(ValueError, match="inert attach left") as failure:
                await task

            assert any("Caller cancellation retained" in note
                       for note in failure.value.__notes__), (
                "The original attach failure must stay primary while cancellation is retained."
            )

        else:
            with pytest.raises(asyncio.CancelledError):
                await task

        roles = [role for role, _, _ in runtime.calls]
        assert roles.index("cleanup-stopped") < roles.index("cleanup-remove") < (
            roles.index("cleanup-absence")
        ), "Stopped state, removal and absence must all finish despite caller cancellation."
        assert not runtime.container_present and not runtime.present_tags, (
            "Repeated cancellation must not silently abandon known-owned container/image cleanup."
        )
        receipt = host.StrictJson((runtime.root / "host.json").read_bytes())
        assert receipt["status"] == "failed" and (
            receipt["caller_cancellations_during_cleanup"] == 2
        ), "The final receipt must refuse acceptance and preserve both caller cancellations."
        assert receipt["failure"]["exception_type"] == (
            "ValueError" if boundary == "kill" else "CancelledError"
        ), "The first failure must distinguish original attach refusal from caller cancellation."

    asyncio.run(Scenario())
