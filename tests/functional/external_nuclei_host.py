# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bound committed-context custody and offline Docker prerequisite ownership for the lab.

Commands run only through explicit host-owner calls. CLI descendant cleanup does
not prove Docker daemon/container termination; those require separate readback.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import sys
import time
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from fuzzy1337.executors.owned_process import StartOwnedExecution

from .external_native_runner import ImportBundle, SafePath, StrictJson, WriteJson
from .external_nuclei_image import ASSET_URL, SUPPORT_FILES, PrerequisiteArguments
from .external_nuclei_runner import (
    ARCHIVE_BYTES,
    ARCHIVE_NAME,
    ARCHIVE_SHA256,
    CONFIG_SHA256,
    EMPTY_CONFIG,
    MODULES,
    TEMPLATE_BYTES,
    TEMPLATE_SHA256,
    VERSION,
)

REPOSITORY = Path(__file__).absolute().parents[2]
CONTEXT_FILES = 2048
CONTEXT_BYTES = 32 * 1024 * 1024
CONTEXT_FILE_BYTES = 4 * 1024 * 1024
INVENTORY_BYTES = 256 * 1024
CONTEXT_LOCAL_ROOTS = frozenset({"_build", "functional-evidence", "artifacts",
                                 "evidence", "reports", "logs"})
OWNER_LABEL = "org.fuzzy1337.nuclei-prerequisite-owner"
SOURCE_LABEL = "org.opencontainers.image.revision"
LOCAL_DOCKER = "unix:///var/run/docker.sock"
TMPFS = "rw,noexec,nosuid,nodev,size=64m,uid=1337,gid=1337,mode=0700"
ZERO_TIME = "0001-01-01T00:00:00Z"
ACCEPTED_BASE = "2bac21f6d215449ee0295b597d1c43fe8c714f6f"
SELECTION = "FUZZY1337_EXTERNAL_NUCLEI_PREREQUISITES"
RECIPE_PATH = "labs/external/benchmark/nuclei-runner.Dockerfile"


def Canonical(value: object) -> str:
    """Compare JSON projections without conflating integer and boolean fields.

    Args:
        value: JSON-compatible inspect projection, never an environment dump.

    Returns:
        Deterministic strict JSON, preserving scalar type distinctions.

    Raises:
        ValueError: Nonfinite numbers are present.
        TypeError: The projection contains unsupported values.
    """

    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def SourceInventory(raw: bytes) -> dict[str, dict]:
    """Validate the entire finite Git tree inventory before any context copy.

    Args:
        raw: Original bounded `git ls-tree -r -l -z ACTUAL_HEAD` stdout.

    Returns:
        Safe ordinary tracked paths with exact Git blob, size and executable mode.

    Raises:
        ValueError: Inventory limits, paths, modes, identities or parent aliases refuse.
        UnicodeError: Git paths/metadata are not valid UTF-8/ASCII.
    """

    if not raw or len(raw) > INVENTORY_BYTES or not raw.endswith(b"\0"):
        raise ValueError("Nuclei committed context inventory is missing or oversized")

    entries = raw[:-1].split(b"\0")

    if len(entries) > CONTEXT_FILES:
        raise ValueError("Nuclei committed context exceeds its file budget")

    files = {}
    total = 0

    for entry in entries:
        metadata, name = entry.split(b"\t", 1)
        mode, kind, blob, size = metadata.split()
        relative = SafePath(name.decode("utf-8"))
        name = relative.as_posix()

        if name in files or any(part in {".git", ".venv"} for part in relative.parts) or (
            relative.parts[0] in CONTEXT_LOCAL_ROOTS
            or mode not in {b"100644", b"100755"} or kind != b"blob"
            or re.fullmatch(b"[a-f0-9]{40}", blob) is None
            or not size.isdigit() or not 0 <= int(size) <= CONTEXT_FILE_BYTES
        ):
            raise ValueError("Nuclei committed context requires unique bounded ordinary Git blobs")

        total += int(size)

        if total > CONTEXT_BYTES:
            raise ValueError("Nuclei committed context exceeds its aggregate byte budget")

        files[name] = {"git_blob": blob.decode("ascii"), "size_bytes": int(size),
                       "mode": mode.decode("ascii")}

    for name in files:
        if any(parent.as_posix() in files for parent in SafePath(name).parents):
            raise ValueError("Nuclei committed context has a file/directory alias")

    return dict(sorted(files.items()))


def SnapshotContext(destination: Path, raw_inventory: bytes) -> dict[str, dict]:
    """Copy exact committed bytes with Linux modes beneath new repository evidence.

    Args:
        destination: New `functional-evidence/external-nuclei-prerequisites/run-HEX/context`
            beneath this helper's repository, with twelve lowercase hexadecimal run digits.
        raw_inventory: Original Git inventory; all budgets are checked before creation.

    Returns:
        Copied file identities binding the Git blob, exact byte length and SHA-256.

    Raises:
        ValueError: The platform, destination, aliases or committed byte identities refuse.
        OSError: Source or new context files cannot be accessed safely.

    A failed copy leaves its partial owned directory unaccepted for later cleanup;
    it never falls back to home paths, ignored files or another source checkout.
    """

    if sys.platform != "linux":
        raise ValueError("Nuclei committed context copying requires Linux file-mode semantics")

    inventory = SourceInventory(raw_inventory)
    evidence = REPOSITORY / "functional-evidence/external-nuclei-prerequisites"

    if not destination.is_absolute() or not destination.is_relative_to(evidence) or (
        re.fullmatch(r"run-[a-f0-9]{12}/context", destination.relative_to(evidence).as_posix())
        is None
    ):
        raise ValueError("Nuclei context destination must be a new owned repository evidence path")

    for component in reversed(destination.parents):
        if component.is_relative_to(REPOSITORY) and component.is_symlink():
            raise ValueError("Nuclei context cannot traverse a symbolic directory")

    destination.mkdir(mode=0o700)
    copied = {}

    for name, identity in inventory.items():
        source = REPOSITORY.joinpath(*SafePath(name).parts)

        for component in (*reversed(source.parents), source):
            if component.is_relative_to(REPOSITORY) and component.is_symlink():
                raise ValueError("Nuclei committed context refuses symbolic source aliases")

        metadata = source.lstat()

        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or (
            metadata.st_size != identity["size_bytes"]
            or bool(metadata.st_mode & 0o111) != (identity["mode"] == "100755")
        ):
            raise ValueError("Nuclei context source mode/size differs from its committed inventory")

        with source.open("rb") as stream:
            raw = stream.read(CONTEXT_FILE_BYTES + 1)

        # Git SHA-1 is its repository object format, not a new cryptographic trust decision.
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw,
                            usedforsecurity=False).hexdigest()

        if len(raw) != identity["size_bytes"] or blob != identity["git_blob"]:
            raise ValueError("Nuclei context bytes differ from the exact committed Git blob")

        output = destination.joinpath(*SafePath(name).parts)
        output.parent.mkdir(parents=True, exist_ok=True)

        with output.open("xb") as stream:
            stream.write(raw)

        output.chmod(0o755 if identity["mode"] == "100755" else 0o644)
        copied[name] = {**identity, "sha256": hashlib.sha256(raw).hexdigest()}

    return copied


def DockerCommand(configuration: Path, *arguments: str) -> tuple[str, ...]:
    """Bind future Docker commands to the fixed local socket and owned empty config.

    Args:
        configuration: Future owner's new config directory under its repository evidence run.
        arguments: Internally constructed Docker subcommand/arguments, never caller shell text.

    Returns:
        Explicit local-endpoint argv. No process is started or inherited environment consulted.

    Raises:
        ValueError: The config path escapes the owned run or arguments attempt endpoint overrides.

    The later owner must create the directory empty and pass only its new HOME and
    fixed PATH environment; this pure constructor does not establish that lifecycle.
    """

    prefix = REPOSITORY / "functional-evidence/external-nuclei-prerequisites"

    if not configuration.is_absolute() or not configuration.is_relative_to(prefix) or (
        re.fullmatch(r"run-[a-f0-9]{12}/docker-config",
                     configuration.relative_to(prefix).as_posix()) is None
        or any(argument.startswith(("-H", "-c", "--host", "--context", "--config"))
               for argument in arguments)
    ):
        raise ValueError("Nuclei Docker authority requires fixed local socket "
                         "and owned empty config")

    return ("/usr/bin/docker", "--host", LOCAL_DOCKER, "--config", str(configuration), *arguments)


def AdmitImage(base: dict, image: dict, revision: str, base_id: str, image_id: str,
               recipe: bytes) -> None:
    """Admit a projected actual image against the built base and exact tracked recipe.

    Args:
        base: Actual base image projection with identity/platform/source/layers/env.
        image: Actual runner projection, including user/entrypoint/cmd/volumes/ports.
        revision: Future root-composed actual clean committed source revision.
        base_id: Immutable ID read from the completed base build's iid file.
        image_id: Immutable ID read from the completed runner build's iid file.
        recipe: Exact committed Dockerfile bytes from the owned context snapshot.

    Raises:
        ValueError: Any immutable/platform/source/ancestry/entrypoint boundary differs.
        KeyError: A required inspect projection field is missing; admission fails closed.
    """

    entries = [line.removeprefix(b"ENTRYPOINT ") for line in recipe.splitlines()
               if line.startswith(b"ENTRYPOINT ")]

    if len(entries) != 1 or re.fullmatch("[a-f0-9]{40}", revision) is None or any(
        re.fullmatch("sha256:[a-f0-9]{64}", value) is None for value in (base_id, image_id)
    ):
        raise ValueError("Nuclei image admission requires exact source, IDs "
                         "and one tracked entrypoint")

    entrypoint = StrictJson(entries[0])

    for record, identifier in ((base, base_id), (image, image_id)):
        if record["id"] != identifier or record["os"] != "linux" or (
            record["architecture"] != "amd64" or record["labels"].get(SOURCE_LABEL) != revision
            or not isinstance(record["layers"], list) or not record["layers"]
            or any(re.fullmatch("sha256:[a-f0-9]{64}", layer) is None for layer in record["layers"])
        ):
            raise ValueError("Nuclei image source/platform/content identity is incompatible")

    if base["env"] is not None and (
        not isinstance(base["env"], list) or not all(type(item) is str for item in base["env"])
    ):
        raise ValueError("Nuclei base image environment projection is malformed")

    if not isinstance(entrypoint, list) or not all(type(item) is str for item in entrypoint) or (
        entrypoint[:2] != ["/usr/bin/env", "-i"]
        or image["user"] != "1337:1337" or image["entrypoint"] != entrypoint
        or image["cmd"] != ["--prerequisites"] or image["env"] != base["env"]
        or image["volumes"] not in (None, {}) or image["ports"] not in (None, {})
        or len(image["layers"]) <= len(base["layers"])
        or image["layers"][:len(base["layers"])] != base["layers"]
    ):
        raise ValueError("Nuclei runner image differs from its immutable base/entrypoint boundary")


def AdmitContainer(value: dict, image: dict, owner: str, revision: str) -> None:
    """Require the complete declared pre-start projection, never permissive Docker defaults.

    Args:
        value: Actual projected container identity/config/host/mount/state fields.
            The later owner retains the original complete Docker inspect separately.
        image: Already admitted immutable runner image projection.
        owner: Fresh 32-digit lowercase hex ownership label created by the future fixture.
        revision: Actual root-composed clean committed source revision.

    Raises:
        ValueError: Identity, ownership, startup state or a declared isolation field differs.
        KeyError: Required inspect fields are missing; no launch may follow.
    """

    if re.fullmatch("[a-f0-9]{32}", owner) is None or (
        re.fullmatch("[a-f0-9]{64}", value["id"]) is None
        or value["name"] != "/fuzzy-1337-nuclei-preflight-" + owner[:12]
        or value["image_id"] != image["id"] or value["source_revision"] != revision
        or image["labels"].get(SOURCE_LABEL) != revision
        or value["owner"] != owner or value["user"] != "1337:1337"
        or value["entrypoint"] != image["entrypoint"] or value["cmd"] != ["--prerequisites"]
        or value["env"] != image["env"]
    ):
        raise ValueError("Nuclei container identity/source/owner/config is incompatible")

    expected = {"network": "none", "readonly": True, "privileged": False, "init": True,
        "binds": [], "ports": {}, "cap_drop": ["ALL"], "cap_add": [], "devices": [],
        "device_requests": [], "volumes_from": [], "security": ["no-new-privileges:true"],
        "memory": 268435456, "cpu": 1000000000, "pids": 64, "tmpfs": {"/tmp": TMPFS},
        "pid_mode": "", "ipc_mode": "private", "uts_mode": "", "userns_mode": "",
        "auto_remove": False, "restart": {"Name": "no", "MaximumRetryCount": 0},
        "publish_all": False, "extra_hosts": [], "links": [], "groups": []}
    host = dict(value["host"])

    if set(host) != set(expected):
        raise ValueError("Nuclei pre-start host projection has missing or unknown fields")

    for field in ("binds", "cap_add", "devices", "device_requests", "volumes_from",
                  "extra_hosts", "links", "groups"):
        if host.get(field) is None:
            host[field] = []

    if host.get("ports") is None:
        host["ports"] = {}

    mounts = value["mounts"]
    state = {"Status": "created", "Running": False, "Paused": False, "Restarting": False,
        "OOMKilled": False, "Dead": False, "Pid": 0, "ExitCode": 0, "Error": "",
        "StartedAt": ZERO_TIME, "FinishedAt": ZERO_TIME}

    if Canonical(host) != Canonical(expected) or mounts not in ([], [{
        "Type": "tmpfs", "Destination": "/tmp", "Source": "",
    }]) or Canonical(value["state"]) != Canonical(state) or (
        type(value["restart_count"]) is not int or value["restart_count"] != 0
    ):
        raise ValueError("Nuclei pre-start isolation projection differs from its declared boundary")


def AdmitTermination(state: dict, restart_count: int) -> None:
    """Require actual successful stopped state before accepting a prerequisite bundle.

    Original RFC3339 fractions through nine digits remain integer nanoseconds;
    aware whole seconds handle offsets without floating-point or microsecond loss.

    Args:
        state: Original post-exit Docker State object, independently read before removal.
        restart_count: Original Docker restart count; no restarted run receives acceptance.

    Raises:
        ValueError: State is live, unsuccessful/OOM, restarted or lacks real times.
        KeyError: Required original state fields are absent.
    """

    expected = {"Status": "exited", "Running": False, "Paused": False, "Restarting": False,
                "OOMKilled": False, "Dead": False, "Pid": 0, "ExitCode": 0, "Error": ""}

    if Canonical({name: state[name] for name in expected}) != Canonical(expected) or (
        type(restart_count) is not int or restart_count != 0
    ):
        raise ValueError("Nuclei prerequisite container did not terminate successfully")

    moments: list[tuple[datetime, int]] = []

    for field in ("StartedAt", "FinishedAt"):
        match = re.fullmatch(
            r"([0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2})"
            r"(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})", state[field])

        if match is None:
            raise ValueError("Nuclei container termination requires actual "
                             "ordered aware timestamps")

        whole = datetime.fromisoformat(match[1] + match[3].replace("Z", "+00:00"))

        if whole.tzinfo is None or (field == "StartedAt" and whole.year == 1):
            raise ValueError("Nuclei container termination requires actual "
                             "ordered aware timestamps")

        moments.append((whole, int((match[2] or "").ljust(9, "0"))))

    if moments[1] < moments[0]:
        raise ValueError("Nuclei container termination requires actual ordered aware timestamps")


async def CaptureCommand(directory: Path, argv: tuple[str, ...], cwd: Path,
                         environment: dict[str, str], seconds: int,
                         stdout_bytes: int, stderr_bytes: int) -> dict:
    """Reuse Linux owned descendants with finite original captures and one whole deadline.

    Args:
        directory: New command directory beneath the owning repository evidence run.
        argv: Internal noninteractive Git/fixed-local Docker argv, never caller shell text.
        cwd: Owning repository/context directory; no external or parent-traversal path.
        environment: Explicit owned HOME/fixed PATH and declared Git isolation values.
        seconds: Whole startup/command deadline, at most300 seconds.
        stdout_bytes: Original stdout budget at most16MiB, plus one overflow witness.
        stderr_bytes: Original stderr budget at most16MiB, plus one overflow witness.

    Returns:
        Worker status, original stream hashes and distinct capture/deadline/cleanup facts.

    Raises:
        ValueError: Platform/paths/budgets refuse or capture exceeds its byte ceiling.
        OSError: Process ownership or original evidence cannot be accessed.
        BaseException: Primary launch/capture/cancellation failure follows shielded cleanup.

    Overflow signals refusal immediately but continues draining without retaining
    further bytes, preventing pipe flow control from stranding supervisor.wait.
    The entire finalizer, including forced wait, task joins, descriptor closure
    and evidence retention, is shielded from repeated caller cancellation.
    CLI cleanup never proves Docker backend/container termination.
    """

    prefix = REPOSITORY / "functional-evidence/external-nuclei-prerequisites"

    if sys.platform != "linux" or not directory.is_absolute() or not cwd.is_absolute() or (
        any(".." in path.parts for path in (directory, cwd))
        or not directory.is_relative_to(prefix) or not cwd.is_relative_to(REPOSITORY)
        or any(type(limit) is not int or not 0 < limit <= 16 * 1024 * 1024
               for limit in (stdout_bytes, stderr_bytes))
        or type(seconds) is not int or not 0 < seconds <= 300
    ):
        raise ValueError("Nuclei host commands require Linux owned paths and finite budgets")

    for path in (directory.parent, cwd):
        for component in (*reversed(path.parents), path):
            if component.is_relative_to(REPOSITORY) and component.is_symlink():
                raise ValueError("Nuclei host command paths cannot traverse symbolic aliases")

    directory.mkdir(mode=0o700)
    started = time.monotonic()
    result = {"argv": list(argv), "cwd": str(cwd), "environment": environment,
        "timeout_seconds": seconds, "stdout_limit_bytes": stdout_bytes,
        "stderr_limit_bytes": stderr_bytes, "exit_code": None, "timed_out": False,
        "capture_exhausted": None, "launch_error": None, "capture_error": None,
        "cleanup_error": None, "interrupted": None, "streams_complete": False,
        "cleanup_receipt": None, "cleanup_confirmed": False}
    owned, primary, joined = None, None, None
    tasks = []
    overflow = asyncio.get_running_loop().create_future()
    stdout = (directory / "stdout.raw").open("xb")

    try:
        stderr = (directory / "stderr.raw").open("xb")

    except BaseException:
        stdout.close()

        raise

    async def Pump(reader, output, limit, role):
        """Retain bounded originals, then discard-drain after signaling overflow.

        Args:
            reader: Binary stream from the existing Linux supervisor.
            output: Newly owned original-byte evidence file.
            limit: Original-byte ceiling before refusal.
            role: Fixed stdout/stderr diagnostic role.

        Raises:
            OSError: Original stream reading/writing fails.
        """

        count = 0

        while raw := await reader.read(65536):
            retained = raw[:max(0, limit + 1 - count)]
            output.write(retained)
            count += len(retained)

            if count > limit and not overflow.done():
                result["capture_exhausted"] = role
                overflow.set_result(ValueError("Nuclei host " + role
                                               + " original capture exhausted"))

    try:
        owned = await asyncio.wait_for(StartOwnedExecution(argv, cwd, environment, environment),
                                       timeout=seconds)
        tasks = [asyncio.create_task(Pump(owned.process.stdout, stdout, stdout_bytes, "stdout")),
                 asyncio.create_task(Pump(owned.process.stderr, stderr, stderr_bytes, "stderr")),
                 asyncio.create_task(owned.Wait())]
        joined = asyncio.gather(*tasks)
        done, _ = await asyncio.wait((joined, overflow), return_when=asyncio.FIRST_COMPLETED,
            timeout=max(0.0, seconds - (time.monotonic() - started)))

        if overflow in done:
            raise overflow.result()

        if joined not in done:
            raise TimeoutError("Nuclei host command deadline exhausted")

        joined.result()
        result["streams_complete"] = True

    except BaseException as error:
        primary = error

        if isinstance(error, TimeoutError):
            result["timed_out"] = True

        elif isinstance(error, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)):
            result["interrupted"] = type(error).__name__

        else:
            result["launch_error" if owned is None else "capture_error"] = type(error).__name__

    async def Finalize():
        """Bound stop/drain/receipt verification and retain failure facts inside one shield.

        Raises:
            OSError: Evidence retention fails after process closure.
        """

        nonlocal primary

        try:
            if owned is not None:
                try:
                    if owned.process.returncode is None:
                        owned.process.terminate()

                    await asyncio.wait_for(asyncio.shield(asyncio.gather(
                        *tasks, return_exceptions=True)), timeout=5)

                    if not owned.verified:
                        owned.Verify()

                    result["cleanup_confirmed"] = True

                except Exception as error:
                    result["cleanup_error"] = type(error).__name__

                    try:
                        if owned.process.returncode is None:
                            owned.process.kill()

                        # returncode can be set before asyncio's pipe transports finish.
                        await asyncio.wait_for(owned.process.wait(), timeout=3)

                    except Exception as forced_error:
                        error.add_note("Forced supervisor wait unconfirmed: "
                                       + type(forced_error).__name__)

                    if primary is None:
                        primary = error

                    else:
                        primary.add_note("Host command cleanup unconfirmed: "
                                         + type(error).__name__)

                finally:
                    for task in tasks:
                        if not task.done():
                            task.cancel()

                    await asyncio.gather(*tasks, return_exceptions=True)

                    if joined is not None:
                        await asyncio.gather(joined, return_exceptions=True)

                    result["exit_code"] = owned.worker_returncode
                    result["cleanup_receipt"] = owned.receipt

                    try:
                        owned.Close()

                    except OSError as error:
                        result["cleanup_confirmed"] = False
                        result["cleanup_error"] = type(error).__name__

                        if primary is None:
                            primary = error

                        else:
                            primary.add_note("Owned descriptor closure failed: "
                                             + type(error).__name__)

        finally:
            overflow.cancel()
            result["duration_seconds"] = time.monotonic() - started

            try:
                stdout.flush()
                stderr.flush()

                for role in ("stdout", "stderr"):
                    raw = (directory / (role + ".raw")).read_bytes()
                    result[role] = {"size_bytes": len(raw),
                                    "sha256": hashlib.sha256(raw).hexdigest()}

                WriteJson(directory / "command.json", result)

            except OSError as error:
                if primary is None:
                    primary = error

                else:
                    primary.add_note("Original host evidence write failed: " + type(error).__name__)

            finally:
                stdout.close()
                stderr.close()

    finalizer = asyncio.create_task(Finalize())

    while not finalizer.done():
        try:
            await asyncio.shield(finalizer)

        except asyncio.CancelledError as error:
            if primary is None:
                primary = error
                result["interrupted"] = type(error).__name__

    try:
        finalizer.result()

    except BaseException as error:
        if primary is None:
            primary = error

        else:
            primary.add_note("Host finalization failed: " + type(error).__name__)

    if primary is not None:
        raise primary

    return result


def Enabled(selection: str | None) -> bool:
    """Select one explicit Linux prerequisite mode before discovering any host tooling.

    Args:
        selection: Opt-in value; absent/empty disables the fixture.

    Returns:
        Whether the exact linux-amd64 prerequisite was selected.

    Raises:
        ValueError: A nonempty unsupported selection was supplied.
    """

    if selection not in (None, "", "linux-amd64"):
        raise ValueError("Nuclei prerequisites require explicit linux-amd64 selection")

    return selection == "linux-amd64"


def ImageProjection(raw: dict) -> dict:
    """Project retained Docker image JSON without substituting absent required fields.

    Args:
        raw: Original single-image inspect object retained by the command owner.

    Returns:
        The fields required by the unchanged immutable-image admission predicate.

    Raises:
        KeyError: A required original field is absent.
        ValueError: An image declares initialization outside the reviewed recipe.
    """

    config = raw["Config"]

    if config.get("OnBuild") not in (None, []) or config.get("Healthcheck") is not None:
        raise ValueError("Nuclei images cannot declare additional initialization")

    return {"id": raw["Id"], "os": raw["Os"], "architecture": raw["Architecture"],
        "labels": config["Labels"], "layers": raw["RootFS"]["Layers"], "env": config["Env"],
        "user": config["User"], "entrypoint": config["Entrypoint"], "cmd": config["Cmd"],
        "volumes": config["Volumes"], "ports": config["ExposedPorts"]}


def ContainerProjection(raw: dict) -> dict:
    """Project original inspect JSON and refuse undeclared interactive/namespace overrides.

    Args:
        raw: Complete retained single-container Docker inspect object.

    Returns:
        Explicit identity/config/host/state projection for the reviewed predicates.

    Raises:
        KeyError: Required Docker readback is absent.
        ValueError: Additional initialization, interactive input or network aliases appear.
    """

    config, settings = raw["Config"], raw["HostConfig"]
    neutral = {"Dns": (None, []), "DnsOptions": (None, []), "DnsSearch": (None, []),
        "Sysctls": (None, {}), "StorageOpt": (None, {}), "CgroupParent": ("",),
        "ContainerIDFile": ("",), "Runtime": ("runc",), "CgroupnsMode": ("private",)}

    if any(config[name] is not False for name in ("OpenStdin", "StdinOnce", "Tty")) or (
        config.get("Healthcheck") is not None
        or type(config["StopTimeout"]) is not int or config["StopTimeout"] != 5
        or any(settings[name] not in accepted for name, accepted in neutral.items())
        or set(raw["NetworkSettings"]["Networks"]) != {"none"}
    ):
        raise ValueError("Nuclei container has unsupported input, initialization "
                         "or daemon defaults")

    network = raw["NetworkSettings"]["Networks"]["none"]

    if any(network[name] not in ("", None) for name in (
        "IPAddress", "GlobalIPv6Address", "Gateway", "IPv6Gateway"
    )) or config["Image"] != raw["Image"]:
        raise ValueError("Nuclei container network/image readback differs "
                         "from its offline identity")

    fields = {"network": "NetworkMode", "readonly": "ReadonlyRootfs", "privileged": "Privileged",
        "init": "Init", "binds": "Binds", "ports": "PortBindings", "cap_drop": "CapDrop",
        "cap_add": "CapAdd", "devices": "Devices", "device_requests": "DeviceRequests",
        "volumes_from": "VolumesFrom", "security": "SecurityOpt", "memory": "Memory",
        "cpu": "NanoCpus", "pids": "PidsLimit", "tmpfs": "Tmpfs", "pid_mode": "PidMode",
        "ipc_mode": "IpcMode", "uts_mode": "UTSMode", "userns_mode": "UsernsMode",
        "auto_remove": "AutoRemove", "restart": "RestartPolicy", "publish_all": "PublishAllPorts",
        "extra_hosts": "ExtraHosts", "links": "Links", "groups": "GroupAdd"}

    return {"id": raw["Id"], "name": raw["Name"], "image_id": raw["Image"],
        "source_revision": config["Labels"][SOURCE_LABEL], "owner": config["Labels"][OWNER_LABEL],
        "user": config["User"], "entrypoint": config["Entrypoint"], "cmd": config["Cmd"],
        "env": config["Env"], "host": {name: settings[field] for name, field in fields.items()},
        "mounts": [{key: mount[key] for key in ("Type", "Destination", "Source")}
                   for mount in raw["Mounts"]],
        "state": raw["State"], "restart_count": raw["RestartCount"]}


def BindBundle(raw: bytes, output: Path, source: dict, revision: str) -> dict:
    """Import original bounded evidence and bind the prerequisite to this committed context.

    Args:
        raw: Original attached stdout, bounded separately from its JSON interpretation.
        output: New owned import directory; originals are never overwritten.
        source: Exact committed-context path/hash/size inventory captured before building.
        revision: Actual clean composed HEAD, not a provider grant or claimed case result.

    Returns:
        Original bundle with all file hashes, after strict source/stage/material admission.

    Raises:
        ValueError: Bundle, source/material/installed-origin or target-free stage facts differ.
        KeyError: Required original files or metadata are absent.
        OSError: Original imported evidence cannot be retained.
    """

    bundle = ImportBundle(raw, output)
    required = {"image-provisioning.json", "prerequisites.json", *(
        name + "/" + field for name in ("version", "validate")
        for field in ("invocation.json", "process.json", "stdout.raw", "stderr.raw"))}
    exported = {record["path"] for record in bundle["files"]}

    if not required <= exported or any(
        name not in required and not name.startswith("home/") for name in exported
    ):
        raise ValueError("Nuclei original bundle contains missing or undeclared prerequisite files")

    expected = {"status": "completed-prerequisites", "version_probe": "completed",
        "go_template_validation": "completed", "governed_no_home_compatibility": "not-established",
        "configured_target_inputs": [], "independent_server_contact_count": None}
    outcome = StrictJson((output / "prerequisites.json").read_bytes())

    if Canonical(bundle["outcome"]) != Canonical(expected) or Canonical(outcome) != (
        Canonical(expected)
    ) or (output / "failure.json").exists():
        raise ValueError("Nuclei imported outcome is not the target-free prerequisite")

    manifest = StrictJson((output / "image-provisioning.json").read_bytes())
    material, installed = manifest["material"], manifest["installed"]
    origin = installed["installed"]
    package = {name.removeprefix("src/fuzzy1337/"): {
        "sha256": record["sha256"], "size_bytes": record["size_bytes"]}
        for name, record in source.items() if name.startswith("src/fuzzy1337/")}
    support = {name: source["tests/functional/" + name]["sha256"] for name in SUPPORT_FILES}
    coverage = {"package_content": "all ordinary fuzzy1337 files",
        "actual_import_modules": list(MODULES), "excluded_generated": ["__pycache__/**", "*.pyc"],
        "excluded_content": ["distribution metadata", "dependencies"]}
    wheel = origin["wheel"]
    package_path = Path(origin["package_path"])

    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1 or (
        manifest["status"] != "material-prepared-prerequisites-not-run"
        or manifest["source_revision"] != revision or origin["source_revision"] != revision
        or manifest["asset_url"] != ASSET_URL or manifest["support_sha256"] != support
        or manifest["recipe_sha256"] != source[RECIPE_PATH]["sha256"]
        or installed["package_files"] != package or installed["coverage"] != coverage
        or not package_path.is_relative_to("/opt/benchmark-runtime")
        or "site-packages" not in package_path.parts or package_path.name != "fuzzy1337"
        or Path(wheel["path"]).parent != Path("/opt/benchmark-wheel")
        or not Path(wheel["path"]).name.endswith(".whl")
        or re.fullmatch("[a-f0-9]{64}", wheel["sha256"]) is None
        or type(wheel["size_bytes"]) is not int or not 0 < wheel["size_bytes"] <= 2 * 1024 * 1024
        or origin["runner_sha256"] != support["external_nuclei_runner.py"]
        or material["archive"]["sha256"] != ARCHIVE_SHA256
        or material["archive"]["size_bytes"] != ARCHIVE_BYTES
        or material["archive"]["path"] != "/opt/benchmark-download/" + ARCHIVE_NAME
    ):
        raise ValueError("Nuclei installed wheel/material does not bind to this committed source")

    for name in MODULES:
        relative = name.replace(".", "/") + ".py"

        if relative not in package:
            relative = name.replace(".", "/") + "/__init__.py"

        if origin["module_sha256"][name] != package[relative]["sha256"]:
            raise ValueError("Nuclei imported module differs from committed package bytes")

    binary = material["executable"]
    profile = material["profile"]
    template = profile["templates"]
    executable_members = [member for member in material["release_inventory"]
                          if member["name"] == "nuclei"]

    if binary["path"] != "/opt/benchmark-material/nuclei" or (
        re.fullmatch("[a-f0-9]{64}", binary["sha256"]) is None
        or type(binary["size_bytes"]) is not int
        or not 0 < binary["size_bytes"] <= 128 * 1024 * 1024
        or len(template) != 1 or template[0]["sha256"] != TEMPLATE_SHA256
        or template[0]["size_bytes"] != TEMPLATE_BYTES
        or template[0]["path"] != "/opt/benchmark-material/prometheus-exposition.yaml"
        or profile["configuration_path"] != "/opt/benchmark-material/operator-config.yaml"
        or source["labs/external/benchmark/templates/prometheus-exposition.yaml"]["sha256"]
            != TEMPLATE_SHA256
        or material["version_probe"] != "not-run"
        or material["go_template_validation"] != "not-run"
        or len(executable_members) != 1
        or executable_members[0]["size_bytes"] != binary["size_bytes"]
        or executable_members[0]["crc_verified"] is not True
        or re.fullmatch("[a-f0-9]{8}", executable_members[0]["crc32"]) is None
    ):
        raise ValueError("Nuclei binary/template/configuration material identity is incompatible")

    environment = {"HOME": "/tmp/nuclei-prerequisites/home",
        "XDG_CONFIG_HOME": "/tmp/nuclei-prerequisites/home/config",
        "XDG_CACHE_HOME": "/tmp/nuclei-prerequisites/home/cache",
        "TMPDIR": "/tmp/nuclei-prerequisites/home/tmp"}
    arguments = {"version": [binary["path"], "-version", "-duc"], "validate": [binary["path"],
        "-validate", "-t", template[0]["path"], "-config", profile["configuration_path"],
        "-duc", "-ni", "-no-stdin", "-pt", "http", "-nc"]}

    for name, argv in arguments.items():
        invocation = StrictJson((output / name / "invocation.json").read_bytes())
        process = StrictJson((output / name / "process.json").read_bytes())
        maximum = 16384 if name == "version" else 2 * 1024 * 1024
        expected_invocation = {"argv": argv, "environment": environment,
            "provider_timeout_seconds": 3, "stdout_capture_bytes": 4 * 1024 * 1024,
            "stderr_capture_bytes": 65536, "stdout_interpretation_bytes": maximum,
            "stderr_interpretation_bytes": 16384, "original_file_ceiling_bytes": 2 * 1024 * 1024,
            "basis": "target-free-explicit-home-prerequisite"}
        stdout = (output / name / "stdout.raw").read_bytes()
        stderr = (output / name / "stderr.raw").read_bytes()

        expected_process = {"exit_code": 0, "streams_complete": True, "timed_out": False,
            "capture_exhausted": None, "launch_error": None, "capture_error": None,
            "interrupted": None, "cleanup_error": None}

        if Canonical(invocation) != Canonical(expected_invocation) or (
            Canonical({key: process[key] for key in expected_process})
                != Canonical(expected_process)
            or type(process["duration_seconds"]) not in (int, float)
            or not 0 <= process["duration_seconds"] <= 8
            or len(stdout) > maximum or len(stderr) > 16384
        ):
            raise ValueError("Nuclei original prerequisite process receipt is incomplete")

        combined = stdout + stderr

        if name == "version" and re.findall(
            rb"Nuclei Engine Version:\s*v?([0-9A-Za-z.+-]+)", combined
        ) != [VERSION.encode("ascii")]:
            raise ValueError("Nuclei original version bytes do not identify exact pinned engine")

        if name == "validate" and b"All templates validated successfully" not in combined:
            raise ValueError("Nuclei original exact-template validation receipt is absent")

    generated = [record for record in bundle["files"] if record["path"].startswith("home/")]
    WriteJson(output.parent / "bundle-inventory.json", {"files": [{key: value for key, value
        in record.items() if key != "data_base64"} for record in bundle["files"]],
        "generated_home_files": [record["path"] for record in generated],
        "wheel_identity_basis": "image-local original wheel; installed package/import bytes bound "
                                "by reviewed image inventory, wheel bytes not exported",
        "binary_identity_basis": "checksum-verified archive extraction in inspected image; "
                                 "no independently predeclared executable digest",
        "empty_operator_config_sha256": CONFIG_SHA256})

    return bundle


class PrerequisiteHost:
    """Own one committed-image build and offline prerequisite container, with separate cleanup.

    Construction performs no discovery. Run creates a private repository evidence
    run and retains original command streams/inspect/bundle artifacts. No target,
    application case or governed-provider environment is configured here.
    """

    def __init__(self):
        """Assign private identities without reading environment or contacting a daemon."""

        self.owner = uuid4().hex
        self.root = (REPOSITORY / "functional-evidence/external-nuclei-prerequisites"
                     / ("run-" + self.owner[:12]))
        self.context = self.root / "context"
        self.config = self.root / "docker-config"
        self.name = "fuzzy-1337-nuclei-preflight-" + self.owner[:12]
        self.tags = ["fuzzy1337-nuclei-base-" + self.owner,
                     "fuzzy1337-nuclei-runner-" + self.owner]
        self.images = {}
        self.container = None
        self.created = False
        self.backend_unknown = False
        self.index = 0
        self.revision = ""
        self.tree = ""
        self.environment = {}
        self.receipt = {"status": "failed", "commands": [], "cleanup": [],
            "configured_target_inputs": [], "governed_no_home_compatibility": "not-established"}

    def Command(self, role: str, arguments: tuple[str, ...], *, docker: bool = True,
                seconds: int = 15, limit: int = 256 * 1024, stderr: int | None = None,
                require: bool = True, cwd: Path | None = None) -> tuple[dict, bytes]:
        """Retain a finite owned command before any interpretation of its original stdout.

        Args:
            role: Internal short evidence role; no user-controlled command fragment.
            arguments: Internal argv suffix; Docker always uses fixed local authority.
            docker: Select fixed Docker routing or the explicit Git binary.
            seconds: Whole deadline, bounded by CaptureCommand.
            limit: Original stdout ceiling in bytes.
            stderr: Separate stderr ceiling; defaults to the stdout ceiling.
            require: Refuse a nonzero worker exit when true; cleanup readbacks may inspect it.
            cwd: Owned context or repository directory, never an external snapshot.

        Returns:
            Original process metadata and original stdout bytes.

        Raises:
            ValueError: Exit/completion/cleanup facts refuse acceptance.
            OSError: Private originals cannot be retained.
            BaseException: Original owned-command failure propagates after bounded cleanup.
        """

        self.index += 1
        directory = self.root / "commands" / f"{self.index:03d}-{role}"
        argv = DockerCommand(self.config, *arguments) if docker else (
            "/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
            *arguments)
        self.receipt["commands"].append({"role": role, "directory": str(directory),
                                          "argv": list(argv)})
        result = asyncio.run(CaptureCommand(directory, argv, cwd or REPOSITORY,
            self.environment, seconds, limit, limit if stderr is None else stderr))
        raw = (directory / "stdout.raw").read_bytes()

        if result["cleanup_confirmed"] is not True or result["streams_complete"] is not True or (
            any(result[field] for field in ("timed_out", "capture_exhausted", "launch_error",
                "capture_error", "cleanup_error", "interrupted"))
            or require and (type(result["exit_code"]) is not int or result["exit_code"] != 0)
        ):
            raise ValueError("Nuclei host command did not complete: " + role)

        return result, raw

    def Inspect(self, kind: str, identifier: str, role: str) -> dict:
        """Retain actual original JSON and decode one image/container readback.

        Args:
            kind: Fixed image or container selector.
            identifier: Known immutable ID or this run's unique image tag.
            role: Internal command evidence role.

        Returns:
            Single complete inspect object; required projection occurs separately.

        Raises:
            ValueError: The command or single-object JSON readback refuses.
            OSError: Original bytes cannot be retained.
        """

        _, raw = self.Command(role, (kind, "inspect", "--format", "{{json .}}", identifier))
        value = StrictJson(raw)

        if not isinstance(value, dict):
            raise ValueError("Nuclei inspect requires one original object")

        return value

    def Source(self, role: str) -> tuple[str, str]:
        """Require exact accepted-base ancestry and clean committed repository provenance.

        Args:
            role: Fixed before/after evidence discriminator.

        Returns:
            Actual full HEAD and tree object IDs.

        Raises:
            ValueError: Dirty/untracked source, ancestry or exact identity refuses.
            OSError: Bounded original Git evidence cannot be retained.
        """

        _, raw = self.Command(role + "-identity", ("rev-parse", "HEAD", "HEAD^{tree}"),
                              docker=False)
        values = raw.decode("ascii").splitlines()

        if len(values) != 2 or any(re.fullmatch("[a-f0-9]{40}", value) is None for value in values):
            raise ValueError("Nuclei host source requires exact committed HEAD/tree")

        self.Command(role + "-clean", ("diff", "--quiet", "--no-ext-diff", "--no-textconv",
                                       "HEAD", "--"), docker=False)
        _, untracked = self.Command(role + "-untracked", (
            "ls-files", "--others", "--exclude-standard", "-z"), docker=False)
        self.Command(role + "-base", ("merge-base", "--is-ancestor", ACCEPTED_BASE, values[0]),
                     docker=False)

        if untracked:
            raise ValueError("Nuclei host context requires no untracked nonignored source")

        return values[0], values[1]

    def Build(self, tag: str, role: str, arguments: tuple[str, ...], seconds: int) -> dict:
        """Build exactly once and bind the owned tag to its original iid and source labels.

        Args:
            tag: Unique run-owned tag checked absent before any build.
            role: Fixed base or runner evidence role.
            arguments: Internal target/recipe/base-reference arguments.
            seconds: Declared base300s or runner180s deadline.

        Returns:
            Complete original immutable image inspect object.

        Raises:
            ValueError: Build, iid, ownership or tag identity refuses.
            OSError: Original image ID/readback cannot be retained.
            BaseException: Interrupted build leaves backend quiescence explicitly unknown.
        """

        _, existing = self.Command(role + "-tag-absent", ("image", "ls", "--quiet", "--no-trunc",
            "--filter", "reference=" + tag))

        if existing.strip():
            raise ValueError("Nuclei unique image tag already exists; it is not owned")

        iid = self.root / (role + ".iid")
        self.backend_unknown = True
        self.Command(role + "-build", ("build", "--pull=false", "--iidfile", str(iid),
            "--tag", tag, "--label", SOURCE_LABEL + "=" + self.revision,
            "--label", OWNER_LABEL + "=" + self.owner, *arguments, str(self.context)),
            seconds=seconds, limit=16 * 1024 * 1024)
        metadata = iid.lstat()

        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 80:
            raise ValueError("Nuclei image iid must be an ordinary bounded private file")

        with iid.open("rb") as stream:
            identifier = stream.read(81)

        if len(identifier) > 80 or re.fullmatch(rb"sha256:[a-f0-9]{64}\n?", identifier) is None:
            raise ValueError("Nuclei completed build omitted its exact immutable image ID")

        image_id = identifier.decode("ascii").strip()
        self.images[tag] = image_id
        value = self.Inspect("image", image_id, role + "-id-inspect")
        tagged = self.Inspect("image", tag, role + "-tag-inspect")

        if value["Id"] != image_id or tagged["Id"] != image_id or (
            value["Config"]["Labels"].get(OWNER_LABEL) != self.owner
            or value["Config"]["Labels"].get(SOURCE_LABEL) != self.revision
        ):
            raise ValueError("Nuclei actual image source/owner/tag identity differs")

        self.backend_unknown = False

        return value

    def OwnedContainer(self, raw: dict, identifier: str) -> None:
        """Prove exact owned identity before any destructive daemon operation.

        Args:
            raw: Original actual container inspect readback.
            identifier: Full ID returned or reconciled by owner-label query.

        Raises:
            ValueError: ID/name/image/source/owner differs; no deletion is authorized.
            KeyError: Required identity readback is absent.
        """

        if re.fullmatch("[a-f0-9]{64}", identifier) is None or raw["Id"] != identifier or (
            raw["Name"] != "/" + self.name
            or raw["Image"] != self.images.get(self.tags[1])
            or raw["Config"]["Labels"].get(OWNER_LABEL) != self.owner
            or raw["Config"]["Labels"].get(SOURCE_LABEL) != self.revision
        ):
            raise ValueError("Nuclei cleanup cannot establish exact owned container identity")

    def Close(self) -> None:
        """Unconditionally reconcile and remove only proven owned IDs/tags, retaining failures.

        Raises:
            BaseExceptionGroup: Cleanup/backend state is unknown or an owned resource survives.

        CLI descendant cleanup never substitutes for these daemon readbacks.
        A failed ambiguous create remains failed even if its owned ID is recovered.
        """

        failures = []

        try:
            _, raw = self.Command("cleanup-owner-list", ("container", "ls", "--all", "--quiet",
                "--no-trunc", "--filter", "label=" + OWNER_LABEL + "=" + self.owner))
            identifiers = raw.decode("ascii").splitlines()

            if len(identifiers) > 1 or any(re.fullmatch("[a-f0-9]{64}", item) is None
                                           for item in identifiers):
                raise ValueError("Nuclei owned-container reconciliation is ambiguous")

            if self.container is not None and self.container not in identifiers:
                raise ValueError("Nuclei known container disappeared before verified cleanup")

            for identifier in identifiers:
                before = self.Inspect("container", identifier, "cleanup-before")
                self.OwnedContainer(before, identifier)

                if before["State"]["Running"] is True:
                    self.Command("cleanup-kill", ("container", "kill", identifier), seconds=10)
                    self.Command("cleanup-wait", ("container", "wait", identifier), seconds=15)

                stopped = self.Inspect("container", identifier, "cleanup-stopped")
                self.OwnedContainer(stopped, identifier)
                state = stopped["State"]

                if state["Running"] is not False or state["Paused"] is not False or (
                    state["Restarting"] is not False or type(state["Pid"]) is not int
                    or state["Pid"] != 0
                ):
                    raise ValueError("Nuclei daemon has not confirmed container termination")

                self.Command("cleanup-remove", ("container", "rm", "--force", "--volumes",
                                                identifier), seconds=20)

            _, remaining = self.Command("cleanup-absence", ("container", "ls", "--all", "--quiet",
                "--no-trunc", "--filter", "label=" + OWNER_LABEL + "=" + self.owner))

            if remaining.strip():
                raise ValueError("Nuclei owned container remains after removal")

            self.receipt["cleanup"].append({"container_absent": True})

        except BaseException as error:
            failures.append(error)
            self.receipt["cleanup"].append({"container_error": type(error).__name__})

        for tag in reversed(self.tags):
            try:
                _, present = self.Command("cleanup-tag-list", ("image", "ls", "--quiet",
                    "--no-trunc", "--filter", "reference=" + tag))

                if present.strip():
                    value = self.Inspect("image", tag, "cleanup-tag-inspect")
                    identifier = value["Id"]

                    if value["Config"]["Labels"].get(OWNER_LABEL) != self.owner or (
                        value["Config"]["Labels"].get(SOURCE_LABEL) != self.revision
                        or identifier != self.images.get(tag)
                    ):
                        raise ValueError("Nuclei tag cleanup cannot establish owned immutable ID")

                    self.Command("cleanup-tag-remove", ("image", "rm", tag), seconds=20)

                _, remaining = self.Command("cleanup-tag-absence", ("image", "ls", "--quiet",
                    "--no-trunc", "--filter", "reference=" + tag))

                if remaining.strip():
                    raise ValueError("Nuclei owned image tag remains after removal")

                self.receipt["cleanup"].append({"tag": tag, "absent": True})

            except BaseException as error:
                failures.append(error)
                self.receipt["cleanup"].append({"tag": tag, "error": type(error).__name__})

        if self.backend_unknown:
            failures.append(ValueError("Nuclei interrupted build backend cleanup is unconfirmed"))
            self.receipt["cleanup"].append({"build_backend_quiescence": "unconfirmed"})

        try:
            if self.context.is_symlink():
                raise ValueError("Nuclei owned context became a symbolic alias")

            if self.context.exists():
                shutil.rmtree(self.context)

        except BaseException as error:
            failures.append(error)
            self.receipt["cleanup"].append({"context_error": type(error).__name__})

        if failures:
            raise BaseExceptionGroup("Nuclei prerequisite cleanup unconfirmed", failures)

    def Run(self) -> dict:
        """Build/inspect the committed image and attach one offline prerequisite invocation.

        Returns:
            Successful prerequisite-only host receipt after verified daemon cleanup.

        Raises:
            ValueError: Enabled host/source/image/container/bundle requirements refuse.
            OSError: Fixed local tools or private original evidence are unavailable.
            BaseException: Primary failure propagates with separate retained cleanup facts.
        """

        if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
            raise ValueError("Enabled Nuclei prerequisites require native Linux/amd64")

        for executable in (Path("/usr/bin/docker"), Path("/usr/bin/git")):
            if not executable.is_file() or not os.access(executable, os.X_OK):
                raise ValueError("Enabled Nuclei prerequisites require fixed local Docker and Git")

        for component in (*reversed(self.root.parents), self.root):
            if component.is_relative_to(REPOSITORY) and component.is_symlink():
                raise ValueError("Nuclei host evidence cannot traverse symbolic aliases")

        self.root.mkdir(parents=True, mode=0o700)

        for path in (self.root / "commands", self.root / "home", self.config):
            path.mkdir(mode=0o700)

        (self.config / "config.json").write_bytes(EMPTY_CONFIG)
        (self.config / "config.json").chmod(0o600)
        self.environment = {"HOME": str(self.root / "home"), "PATH": "/usr/local/bin:/usr/bin:/bin",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0"}
        primary = None

        try:
            _, info = self.Command("daemon", ("info", "--format",
                '{"os":{{json .OSType}},"architecture":{{json .Architecture}}}'))
            daemon = StrictJson(info)

            if daemon not in ({"os": "linux", "architecture": "x86_64"},
                               {"os": "linux", "architecture": "amd64"}):
                raise ValueError("Nuclei fixed local daemon must be native Linux/amd64")

            self.revision, self.tree = self.Source("before")
            _, inventory = self.Command("source-inventory", ("ls-tree", "-r", "-l", "-z",
                self.revision), docker=False, limit=INVENTORY_BYTES)
            declared = SourceInventory(inventory)
            WriteJson(self.root / "context-declaration.json", {"revision": self.revision,
                "tree": self.tree, "file_count": len(declared),
                "size_bytes": sum(record["size_bytes"] for record in declared.values()),
                "file_limit": CONTEXT_FILES, "byte_limit": CONTEXT_BYTES,
                "file_byte_limit": CONTEXT_FILE_BYTES, "basis": "validated before copying"})
            source = SnapshotContext(self.context, inventory)
            WriteJson(self.root / "context-inventory.json", {"revision": self.revision,
                "tree": self.tree, "files": source, "file_limit": CONTEXT_FILES,
                "byte_limit": CONTEXT_BYTES, "file_byte_limit": CONTEXT_FILE_BYTES})
            base = self.Build(self.tags[0], "base", ("--target", "development"), 300)
            runner = self.Build(self.tags[1], "runner", ("--file", str(self.context / RECIPE_PATH),
                "--build-arg", "WORKBENCH_IMAGE=" + self.tags[0], "--build-arg",
                "SOURCE_REVISION=" + self.revision), 180)
            base_after = self.Inspect("image", self.tags[0], "base-tag-after")
            runner_after = self.Inspect("image", self.tags[1], "runner-tag-after")

            if base_after["Id"] != base["Id"] or runner_after["Id"] != runner["Id"] or (
                self.Source("after") != (self.revision, self.tree)
            ):
                raise ValueError("Nuclei source/base/runner transport tag changed during build")

            image = ImageProjection(runner)
            AdmitImage(ImageProjection(base), image, self.revision, base["Id"], runner["Id"],
                       (self.context / RECIPE_PATH).read_bytes())
            arguments = PrerequisiteArguments(self.name, runner["Id"])
            create = (*arguments[1:-2], "--label", OWNER_LABEL + "=" + self.owner,
                      *arguments[-2:])
            self.created = True
            _, raw = self.Command("create", create, seconds=20)
            identifier = raw.decode("ascii").strip()

            if re.fullmatch("[a-f0-9]{64}", identifier) is None:
                raise ValueError("Nuclei create did not return one exact container ID")

            self.container = identifier
            before = self.Inspect("container", identifier, "container-before")
            self.OwnedContainer(before, identifier)
            projection = ContainerProjection(before)
            AdmitContainer(projection, image, self.owner, self.revision)
            _, original = self.Command("attach", ("container", "start", "--attach", identifier),
                seconds=40, limit=12 * 1024 * 1024, stderr=65536)
            after = self.Inspect("container", identifier, "container-after")
            self.OwnedContainer(after, identifier)
            final = ContainerProjection(after)

            if Canonical({key: value for key, value in final.items()
                          if key not in ("state", "restart_count")}) != Canonical({
                key: value for key, value in projection.items()
                if key not in ("state", "restart_count")
            }):
                raise ValueError("Nuclei container configuration changed after attachment")

            AdmitTermination(after["State"], after["RestartCount"])
            BindBundle(original, self.root / "imported", source, self.revision)
            self.receipt.update(status="completed-prerequisites", source_revision=self.revision,
                                source_tree=self.tree, image_id=runner["Id"],
                                container_id=identifier)

        except BaseException as error:
            primary = error
            self.receipt["failure"] = {"exception_type": type(error).__name__}

        finally:
            try:
                self.Close()

            except BaseException as error:
                self.receipt["status"] = "failed"
                self.receipt["cleanup_failure"] = type(error).__name__

                if primary is None:
                    primary = error

                else:
                    primary.add_note("Independent Docker cleanup failed: " + type(error).__name__)

            try:
                WriteJson(self.root / "host.json", self.receipt)

            except OSError as error:
                if primary is None:
                    primary = error

                else:
                    primary.add_note("Host result evidence failed: " + type(error).__name__)

        if primary is not None:
            raise primary

        return self.receipt
