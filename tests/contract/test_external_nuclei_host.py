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
