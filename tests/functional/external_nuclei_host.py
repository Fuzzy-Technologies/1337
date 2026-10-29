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
import re
import stat
import sys
import time
from datetime import datetime
from pathlib import Path

from fuzzy1337.executors.owned_process import StartOwnedExecution

from .external_native_runner import SafePath, StrictJson, WriteJson

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
    """Reuse Linux owned descendants with one finite binary command capture/deadline.

    Args:
        directory: New private command directory beneath the owned repository evidence run.
        argv: Internally authorized noninteractive Git or fixed-local Docker arguments.
        cwd: Existing owning repository/context directory; never a caller home path.
        environment: Explicit newly owned HOME/fixed PATH and declared Git isolation values.
        seconds: Whole command deadline, including supervisor startup, at most300 seconds.
        stdout_bytes: Original stdout budget, at most16MiB; one overflow witness is retained.
        stderr_bytes: Original stderr budget, at most16MiB; one overflow witness is retained.

    Returns:
        Actual worker exit, separate capture/deadline flags and verified private cleanup receipt.

    Raises:
        ValueError: Linux/path/budgets refuse, or an original capture exceeds its finite ceiling.
        OSError: Private evidence or the owned process cannot be accessed.
        Exception: Original launch/capture/cleanup failures propagate after evidence retention.
        BaseException: Cancellation propagates after shielded bounded owned cleanup.

    All original bytes remain separate files. Failure cleanup never replaces the
    primary exception. A confirmed CLI cleanup receipt says nothing about backend
    build work or a container: the host lifecycle must inspect those independently.
    """

    prefix = REPOSITORY / "functional-evidence/external-nuclei-prerequisites"

    if sys.platform != "linux" or not directory.is_absolute() or (
        not directory.is_relative_to(prefix) or not cwd.is_relative_to(REPOSITORY)
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
    owned = None
    tasks = []
    joined = None
    primary = None

    with (directory / "stdout.raw").open("xb") as stdout, (
        directory / "stderr.raw"
    ).open("xb") as stderr:
        async def Pump(reader, output, limit, role):
            """Retain finite original stream bytes plus one explicit overflow witness.

            Args:
                reader: Binary stream owned by the existing Linux supervisor.
                output: Newly created original-byte evidence file.
                limit: Declared retained-byte ceiling before overflow refusal.
                role: Fixed stdout/stderr role for machine-readable refusal attribution.

            Raises:
                ValueError: The role exceeds its finite byte budget.
                OSError: Original evidence cannot be written or read.
            """

            count = 0

            while raw := await reader.read(min(65536, limit - count + 1)):
                output.write(raw)
                count += len(raw)

                if count > limit:
                    result["capture_exhausted"] = role

                    raise ValueError("Nuclei host " + role + " original capture exhausted")

        try:
            owned = await asyncio.wait_for(StartOwnedExecution(argv, cwd, environment, environment),
                                            timeout=seconds)
            process = owned.process
            tasks = [asyncio.create_task(Pump(process.stdout, stdout, stdout_bytes, "stdout")),
                     asyncio.create_task(Pump(process.stderr, stderr, stderr_bytes, "stderr")),
                     asyncio.create_task(owned.Wait())]
            joined = asyncio.gather(*tasks)

            await asyncio.wait_for(asyncio.shield(joined),
                                   timeout=max(0.0, seconds - (time.monotonic() - started)))
            result["streams_complete"] = True

        except BaseException as error:
            primary = error

            if isinstance(error, TimeoutError):
                result["timed_out"] = True

            elif isinstance(error, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)):
                result["interrupted"] = type(error).__name__

            else:
                result["launch_error" if owned is None else "capture_error"] = type(error).__name__

        finally:
            if owned is not None:
                async def Cleanup():
                    """Stop the existing supervisor, join bounded streams and verify its receipt.

                    Raises:
                        Exception: Supervisor exit or descendant cleanup remains unconfirmed.
                    """

                    if owned.process.returncode is None:
                        owned.process.terminate()

                    await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True),
                                           timeout=5)

                    if not owned.verified:
                        owned.Verify()

                cleanup = asyncio.create_task(Cleanup())

                try:
                    while not cleanup.done():
                        try:
                            await asyncio.shield(cleanup)

                        except asyncio.CancelledError as error:
                            if primary is None:
                                primary = error
                                result["interrupted"] = type(error).__name__

                    cleanup.result()
                    result["cleanup_confirmed"] = True

                except Exception as error:
                    result["cleanup_error"] = type(error).__name__

                    try:
                        if owned.process.returncode is None:
                            owned.process.kill()
                            await asyncio.wait_for(owned.process.wait(), timeout=3)

                    except Exception as forced_error:
                        error.add_note("Forced supervisor exit unconfirmed: "
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
                    owned.Close()

            result["duration_seconds"] = time.monotonic() - started

            try:
                stdout.flush()
                stderr.flush()
                WriteJson(directory / "command.json", result)

            except OSError as error:
                if primary is None:
                    primary = error

                else:
                    primary.add_note("Original host evidence write failed: " + type(error).__name__)

    if primary is not None:
        raise primary

    return result
