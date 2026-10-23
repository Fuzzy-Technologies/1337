# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Own finite Linux process descendants for independent executor cleanup acceptance."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def RecordIdentity(root: Path, role: str) -> None:
    """Record only this fixture process's PID and kernel start identity in its owned directory."""

    metadata = Path("/proc/self/stat").read_text(encoding="ascii")
    started = int(metadata.rsplit(")", 1)[1].split()[19])
    document = {"role": role, "pid": os.getpid(), "started_ticks": started}
    temporary = root / (role + ".pending")
    temporary.write_text(json.dumps(document), encoding="utf-8")
    temporary.replace(root / (role + ".json"))


def WaitFor(path: Path, deadline: float) -> None:
    """Wait for an explicit owned readiness file within a finite emergency lifetime."""

    while not path.is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError("Owned descendant readiness was not acknowledged")

        time.sleep(0.01)


def Hold(root: Path, deadline: float) -> None:
    """Stay alive only until the owner releases this fixture or its emergency lifetime expires."""

    while not (root / "release").is_file() and time.monotonic() < deadline:
        time.sleep(0.01)


def Child(root: Path, role: str) -> subprocess.Popen[bytes]:
    """Start only this exact fixture script as a detached child without inherited output pipes."""

    return subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve()),
        str(root), "--role", role], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, start_new_session=True)


def Main() -> int:
    """Create the controlled root, detached branch and detached leaf, without network activity."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--role", choices=("root", "branch", "leaf"), default="root")
    parser.add_argument("--mode", choices=("normal", "hold", "output"), default="normal")
    parser.add_argument("--exit-code", choices=(0, 17), type=int, default=0)
    arguments = parser.parse_args()
    deadline = time.monotonic() + 10
    root = arguments.root
    RecordIdentity(root, arguments.role)

    if arguments.role == "leaf":
        (root / "ready").write_text("owned detached leaf ready", encoding="ascii")
        Hold(root, deadline)

        return 0

    Child(root, "leaf" if arguments.role == "branch" else "branch")
    WaitFor(root / "ready", deadline)

    if arguments.role == "branch":
        Hold(root, deadline)

        return 0

    sys.stdout.buffer.write(b"owned-root-stdout\n")
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(b"owned-root-stderr\n")
    sys.stderr.buffer.flush()

    if arguments.mode == "output":
        sys.stdout.buffer.write(b"owned-output\n" * 1024)
        sys.stdout.buffer.flush()

    if arguments.mode != "normal":
        Hold(root, deadline)

    return arguments.exit_code


if __name__ == "__main__":
    raise SystemExit(Main())
