# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Own private containerd/Docker lifetimes for one finite installed no-egress product lane."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path

MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_CHILDREN = 256


@dataclass(frozen=True)
class ProcessFact:
    """Original kernel PID/start-time/group observations, independent of a mutable PID spelling."""

    pid: int
    parent: int
    group: int
    started: int
    state: str


def Process(pid: int) -> ProcessFact | None:
    """Read bounded original Linux process identity without command lines or environment values.

    Args:
        pid: Explicit kernel process identifier.

    Returns:
        Current physical identity, or None only when the process disappeared before observation.
    """

    try:
        with Path(f"/proc/{pid}/stat").open("rb") as source:
            raw = source.read(4097)
    except (FileNotFoundError, ProcessLookupError):
        return None
    if len(raw) > 4096 or b") " not in raw:
        raise ValueError("Owned process identity is not a bounded Linux stat record")
    fields = raw.rsplit(b") ", 1)[1].split()
    return ProcessFact(pid, int(fields[1]), int(fields[2]), int(fields[19]), fields[0].decode())


def Descendants() -> dict[int, ProcessFact]:
    """Observe current recursive or adopted children of this dedicated subreaper process.

    Returns:
        Finite current descendants with their PID/start-time/process-group facts.
    """

    facts = {}
    for path in Path("/proc").iterdir():
        if path.name.isdecimal():
            observed = Process(int(path.name))
            if observed is not None:
                facts[observed.pid] = observed
    selected = {os.getpid()}
    while additional := {fact.pid for fact in facts.values() if fact.parent in selected} - selected:
        selected.update(additional)
        if len(selected) > MAX_CHILDREN:
            raise ValueError("Owned daemon lane exceeded its finite descendant inventory")
    return {pid: facts[pid] for pid in selected - {os.getpid()}}


def SignalOriginalChildren(current: dict[int, ProcessFact], selected_signal: int) -> None:
    """Signal only reobserved original PID/start-time identities, never a reused or unknown process.

    Args:
        current: Original observed recursive/adopted descendants of this dedicated subreaper.
        selected_signal: Fixed termination or kill signal chosen by the bounded cleanup owner.

    Raises:
        ValueError: Original identity or disappearance is unconfirmed; unknown processes refuse.
    """

    for pid, fact in current.items():
        try:
            descriptor = os.pidfd_open(pid, 0)
        except ProcessLookupError:
            if Process(pid) is not None:
                raise ValueError("Owned child disappearance is unconfirmed")
            continue
        try:
            actual = Process(pid)
            if actual is not None and actual.started != fact.started:
                raise ValueError("Owned child identity changed before signal")
            if actual is not None and actual.state != "Z":
                try:
                    signal.pidfd_send_signal(descriptor, selected_signal)
                except ProcessLookupError:
                    # The descriptor still names the exited original, never a reused PID.
                    pass
        finally:
            os.close(descriptor)


def ProtectedParent(parent: Path) -> tuple[int, int]:
    """Require root-owned physical ancestors with no actor-writable directory entries.

    Args:
        parent: Explicit existing parent selected for root-owned daemon temporary state.
    Returns:
        Physical parent identity, rechecked before deleting the owned child directory.
    """

    if not parent.is_absolute() or parent.resolve(strict=True) != parent:
        raise ValueError("Owned daemon parent must be a physical absolute directory")
    for selected in (parent, *parent.parents):
        info = selected.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Owned daemon parent has an actor-writable or non-root ancestor")
    info = parent.lstat()
    return info.st_dev, info.st_ino


def ReapAdoptedChildren(current: dict[int, ProcessFact], direct: set[int]) -> list[tuple[int, int]]:
    """Reap only original adopted zombies; direct Popen owners retain their own wait status.

    Args:
        current: Original observed descendants of this dedicated subreaper.
        direct: Direct Popen children whose poll method exclusively owns their wait status.
    Returns:
        Original kernel wait statuses for confirmed adopted zombies only.
    """

    reaped = []
    for pid, fact in current.items():
        if pid in direct or fact.parent != os.getpid() or fact.state != "Z":
            continue
        actual = Process(pid)
        if actual != fact:
            raise ValueError("Adopted child identity changed before reap")
        observed, status = os.waitpid(pid, os.WNOHANG)
        if observed:
            reaped.append((observed, status))
    return reaped


def ExactExecutable(path: Path) -> tuple[Path, str]:
    """Select an explicitly named physical executable and record its bounded original byte hash.

    Args:
        path: Operator-supplied absolute fixture tool path, never discovered through ambient PATH.

    Returns:
        Physical absolute selected path and its original SHA-256.
    """

    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Fixture tool must have an explicit absolute path")
    selected = path.resolve(strict=True)
    info = selected.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not info.st_mode & 0o111 or (
        not 1 <= info.st_size <= 256 * 1024 * 1024
    ):
        raise ValueError("Fixture tool is not a bounded physical executable")
    with selected.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    after = selected.lstat()
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink")
    if any(getattr(after, name) != getattr(info, name) for name in fields):
        raise ValueError("Fixture executable changed during observation")
    return selected, digest


def RequireNoEgress(host: str) -> str:
    """Require an actual independent namespace without external interfaces or routes.

    Args:
        host: Original host network namespace identity recorded before unshare.

    Returns:
        Actual selected no-egress network namespace identity.
    """

    current = os.readlink("/proc/self/ns/net")
    if current == host or socket.if_nameindex() != [(1, "lo")]:
        raise ValueError("Owned daemon lane lacks a separate loopback-only namespace")
    routes = Path("/proc/net/route").read_text().splitlines()[1:]
    if routes or any(line.split()[0] != "0" * 32 for line in
                     Path("/proc/net/ipv6_route").read_text().splitlines()):
        raise ValueError("Owned daemon lane contains an external network route")
    return current


def Main() -> int:
    """Run one bounded root-owned lifecycle and preserve diagnostics before any exact-root cleanup.

    Returns:
        Actual pytest status only after confirmed shutdown; four for lifecycle/cleanup uncertainty.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("docker", "dockerd", "containerd", "python", "repository"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("uid", "gid"):
        parser.add_argument("--" + name, type=int, required=True)
    parser.add_argument("--host-netns", required=True)
    parser.add_argument("--source-head", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.uid <= 0 or args.gid <= 0:
        raise ValueError("Owned lane requires a root owner and explicit non-root test actor")
    # Establish kernel support before starting any owned daemon.
    descriptor = os.pidfd_open(os.getpid(), 0)
    os.close(descriptor)
    own_process = Process(os.getpid())
    if own_process is None or own_process.parent != os.getppid() or (
        own_process.group != os.getpgrp()
    ):
        raise ValueError("Original kernel identity is unavailable before daemon launch")
    network = RequireNoEgress(args.host_netns)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "Could not establish owned lane child subreaper")
    binaries = {name: ExactExecutable(getattr(args, name))
                for name in ("docker", "dockerd", "containerd")}
    repository = args.repository.resolve(strict=True)
    if repository != Path.cwd() or args.python != repository / ".venv/bin/python" or (
        not args.python.is_file()
    ):
        raise ValueError("Owned lane requires its explicit installed virtualenv interpreter")
    source = subprocess.run(["/usr/bin/git", "rev-parse", "HEAD"],
        capture_output=True, timeout=3, check=True, env={"PATH": "/usr/bin:/bin"})
    if source.stdout.decode().strip() != args.source_head or len(args.source_head) != 40:
        raise ValueError("Owned lane source differs from its exact enrolled head")
    output = repository / "functional-evidence/local-image-product"
    output.mkdir(parents=True, exist_ok=False)
    os.chown(output, args.uid, args.gid)
    lifecycle = output / "lifecycle"
    lifecycle.mkdir(mode=0o755)
    root_parent = Path("/run")
    parent_identity = ProtectedParent(root_parent)
    root = Path(tempfile.mkdtemp(prefix="1337-local-image-owned-", dir=root_parent))
    root.chmod(0o750)
    os.chown(root, 0, args.gid)
    root_identity = (root.stat().st_dev, root.stat().st_ino)
    home = root / "home"
    home.mkdir(mode=0o700)
    config = root / "client"
    config.mkdir(mode=0o700)
    (config / "config.json").write_bytes(b"{}\n")
    (config / "config.json").chmod(0o600)
    os.chown(config, args.uid, args.gid)
    os.chown(config / "config.json", args.uid, args.gid)
    containerd_config = root / "containerd.toml"
    containerd_config.write_text('version = 2\ndisabled_plugins = ["io.containerd.grpc.v1.cri"]\n')
    containerd_config.chmod(0o600)
    daemon_config = root / "daemon.json"
    daemon_config.write_text('{"features":{"containerd-snapshotter":false}}\n')
    daemon_config.chmod(0o600)
    endpoint = root / "docker.sock"
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C", "LC_ALL": "C",
                   "XDG_CONFIG_HOME": str(home), "XDG_RUNTIME_DIR": str(home)}
    processes: list[subprocess.Popen] = []
    streams = []
    known: dict[int, ProcessFact] = {}
    reaped_statuses: list[tuple[int, int]] = []
    status = 4
    cleanup_confirmed = False
    failure: str | None = None
    started = time.monotonic()

    def Observe(*, enforce_log_budget: bool = True) -> dict[int, ProcessFact]:
        """Track original child identities and enforce finite logs during every lifecycle phase.

        Args:
            enforce_log_budget: Disable only while stopping already owned processes after failure.

        Returns:
            Current recursive/adopted descendants with no invented liveness evidence.
        """

        current = Descendants()
        for pid, fact in current.items():
            prior = known.get(pid)
            if prior is not None and prior.started != fact.started:
                raise ValueError("Owned child PID identity was unexpectedly reused")
            known[pid] = fact
        if len(known) > MAX_CHILDREN or (enforce_log_budget and any(
            path.stat().st_size > MAX_LOG_BYTES for path in lifecycle.glob("*.log")
        )):
            raise ValueError("Owned lifecycle exceeded its finite child or diagnostic budget")
        return current

    def Launch(name: str, argv: list[str], *, env: dict[str, str] = environment,
               ) -> subprocess.Popen:
        """Start a fixed private fixture process with a separate original session and bounded logs.

        Args:
            name: Fixed diagnostic basename.
            argv: Fixed explicit tool recipe without shell or ambient daemon selection.
            env: Complete explicitly constructed process environment.

        Returns:
            Actual retained process handle, also owned by this subreaper.
        """

        stream = (lifecycle / (name + ".log")).open("xb")
        streams.append(stream)
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream,
            stderr=subprocess.STDOUT, env=env, start_new_session=True, shell=False)
        processes.append(process)
        Observe()
        return process

    try:
        containerd = Launch("containerd", [str(binaries["containerd"][0]), "--config",
            str(containerd_config), "--root", str(root / "containerd-root"), "--state",
            str(root / "containerd-state"), "--address", str(root / "containerd.sock")])
        deadline = time.monotonic() + 15
        while not (root / "containerd.sock").exists():
            Observe()
            if containerd.poll() is not None or time.monotonic() >= deadline:
                raise ValueError("Owned private containerd did not become ready within its budget")
            time.sleep(0.05)
        daemon = Launch("dockerd", [str(binaries["dockerd"][0]), "--config-file",
            str(daemon_config),
            "--host", "unix://" + str(endpoint), "--containerd", str(root / "containerd.sock"),
            "--data-root", str(root / "docker-data"), "--exec-root", str(root / "docker-exec"),
            "--pidfile", str(root / "dockerd.pid"), "--storage-driver", "vfs", "--group",
            str(args.gid), "--bridge=none", "--iptables=false", "--ip6tables=false",
            "--ip-forward=false", "--ip-masq=false", "--userland-proxy=false"])
        deadline = time.monotonic() + 20
        while True:
            Observe()
            if daemon.poll() is not None or time.monotonic() >= deadline:
                raise ValueError("Owned Docker did not become ready within its budget")
            if endpoint.exists():
                probe = subprocess.run([str(binaries["docker"][0]), "--host", "unix://" +
                    str(endpoint), "--config", str(config), "version", "--format",
                    "{{json .Server}}"],
                    stdin=subprocess.DEVNULL, capture_output=True, env=environment,
                    timeout=3, check=False)
                if len(probe.stdout) > 1024 * 1024 or len(probe.stderr) > 64 * 1024:
                    raise ValueError("Owned Docker readiness response exceeded its finite budget")
                if probe.returncode == 0:
                    server = json.loads(probe.stdout)
                    break
            time.sleep(0.05)
        socket_info = endpoint.lstat()
        if not stat.S_ISSOCK(socket_info.st_mode) or stat.S_IMODE(socket_info.st_mode) != 0o660:
            raise ValueError("Owned Docker endpoint is not the selected private 0660 Unix socket")
        receipt = {"schema_version": 1, "owned_daemon": True, "ambient_containerd": False,
            "network_namespace": network, "root_identity": root_identity,
            "source_commit": args.source_head,
            "docker_client_sha256": binaries["docker"][1], "server": server,
            "binaries": {key: {"path": str(value[0]), "sha256": value[1]}
                         for key, value in binaries.items()},
            "socket_mode_inode": list(socket_info[:2]),
            "processes": [asdict(fact) for fact in Observe().values()]}
        receipt_path = lifecycle / "startup.json"
        receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
        test_env = {**environment, "HOME": str(config),
            "FUZZY1337_RUN_LOCAL_IMAGE_PRODUCT_ACCEPTANCE": "1",
            "FUZZY1337_RUN_NATIVE_IMAGE_PRODUCT_ACCEPTANCE": "1",
            "FUZZY1337_LOCAL_DOCKER_BINARY": str(binaries["docker"][0]),
            "FUZZY1337_LOCAL_DOCKER_SOCKET": str(endpoint),
            "FUZZY1337_LOCAL_DOCKER_CONFIG": str(config),
            "FUZZY1337_LOCAL_DOCKER_PROVENANCE": str(receipt_path),
            "FUZZY1337_TRIVY_HOST_NETNS": args.host_netns}
        for name in ("BINARY", "CACHE", "PROVISIONING"):
            key = "FUZZY1337_TRIVY_" + name
            selected = os.environ.get(key)
            if not selected:
                raise ValueError("Required pinned Trivy fixture material is absent")
            test_env[key] = selected
        test = Launch("pytest", ["/usr/bin/setpriv", "--reuid=" + str(args.uid),
            "--regid=" + str(args.gid), "--clear-groups", str(args.python), "-m", "pytest",
            "tests/functional/test_local_image_product.py", "-q", "-n", "0", "--no-cov",
            "-o", "addopts=", "--junitxml=" + str(output / "pytest.xml")], env=test_env)
        deadline = time.monotonic() + 240
        while test.poll() is None:
            Observe()
            if time.monotonic() >= deadline:
                raise ValueError("Owned installed product cohort exceeded its finite deadline")
            time.sleep(0.05)
        status = test.returncode
    except Exception as error:
        failure = type(error).__name__
    finally:
        try:
            direct = {process.pid: known[process.pid] for process in processes
                      if process.pid in known}
            SignalOriginalChildren(direct, signal.SIGTERM)
            for grace, selected_signal in ((5, signal.SIGTERM), (5, signal.SIGKILL)):
                deadline = time.monotonic() + grace
                while True:
                    current = Observe(enforce_log_budget=False)
                    for process in processes:
                        process.poll()
                    SignalOriginalChildren(current, selected_signal)
                    reaped_statuses.extend(ReapAdoptedChildren(
                        current, {process.pid for process in processes}))
                    if not Descendants() and all(process.poll() is not None
                                                 for process in processes):
                        cleanup_confirmed = True
                        break
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.05)
                if cleanup_confirmed:
                    break
            if not cleanup_confirmed:
                raise ValueError("Owned descendants remain after bounded cleanup")
            if ProtectedParent(root_parent) != parent_identity:
                raise ValueError("Owned daemon parent identity changed before cleanup")
            current_root = root.lstat()
            if stat.S_ISLNK(current_root.st_mode) or (
                current_root.st_dev, current_root.st_ino
            ) != root_identity:
                raise ValueError("Owned daemon root identity changed before cleanup")
            mounts = [line.split()[4].replace("\\040", " ") for line in
                      Path("/proc/self/mountinfo").read_text().splitlines()]
            if any(path == str(root) or path.startswith(str(root) + "/") for path in mounts):
                raise ValueError("Owned daemon root has an unknown nested mount; retained")
            shutil.rmtree(root)
        except Exception as error:
            cleanup_confirmed = False
            failure = "Cleanup" + type(error).__name__
        for stream in streams:
            stream.close()
        final = {"schema_version": 1, "cleanup_confirmed": cleanup_confirmed,
            "pytest_exit_code": status, "failure_category": failure,
            "reaped_wait_statuses": reaped_statuses,
            "process_exit_codes": [{"pid": process.pid, "exit_code": process.returncode}
                                   for process in processes],
            "duration_seconds": time.monotonic() - started,
            "observed_children": [asdict(fact) for fact in known.values()],
            "owned_root_retained": root.exists()}
        (lifecycle / "shutdown.json").write_text(json.dumps(final, sort_keys=True, indent=2) + "\n")
        for path in lifecycle.iterdir():
            os.chown(path, args.uid, args.gid)
        log = lifecycle / "pytest.log"
        if log.exists():
            with log.open("rb") as stream:
                stream.seek(max(0, log.stat().st_size - 16384))
                sys.stdout.buffer.write(stream.read(16384))
        sys.stdout.flush()
    return status if cleanup_confirmed and failure is None else 4


if __name__ == "__main__":
    raise SystemExit(Main())
