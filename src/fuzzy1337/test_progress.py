# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded partial pytest diagnostics, separate from authoritative JUnit evidence.

Loaded explicitly by the developer runner, never by normal CLI startup. Files contain hashes
and sanitized unparameterized labels, not full test identifiers or captured test output.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

if TYPE_CHECKING:
    from pytest import Config, TestReport

KIND = "1337-test-progress"
MAX_WORKERS = 12
MAX_BYTES = 1024 * 1024
MAX_LINES = 10000
MAX_LINE_BYTES = 2048
MAX_SUMMARY_BYTES = 8192
MAX_DURATION_MS = 10_800_000
WORKERS = ("serial", *(f"gw{index}" for index in range(MAX_WORKERS)))
SAFE_LABEL = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def ProgressDirectory(report_path: Path) -> Path:
    """Derive the fixed diagnostic directory next to one JUnit report.

    Args:
        report_path: Existing runner-selected JUnit destination.

    Returns:
        Sibling directory with the fixed progress suffix.
    """

    return report_path.with_suffix(".progress")


def RegularFile(path: Path) -> bool:
    """Check an existing diagnostic file without following filesystem links.

    Args:
        path: Exact diagnostic child path to inspect.

    Returns:
        True for one regular file with one link and no Windows reparse attribute.
    """

    metadata = path.lstat()
    return (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
            and not getattr(metadata, "st_file_attributes", 0) & 0x400)


def ValidDirectory(path: Path) -> bool:
    """Check the exact diagnostic directory without following links.

    Args:
        path: Fixed runner-derived progress directory.

    Returns:
        True for a directory without a symlink or Windows reparse attribute.
    """

    metadata = path.lstat()
    return (stat.S_ISDIR(metadata.st_mode)
            and not getattr(metadata, "st_file_attributes", 0) & 0x400)


def OpenRegular(path: Path) -> BinaryIO:
    """Open an existing bounded diagnostic without following a final-component link.

    Args:
        path: Exact fixed diagnostic child path.

    Returns:
        Caller-owned binary stream for the checked regular file.

    Raises:
        OSError: The path is linked, replaced or otherwise unsupported.
    """

    if not RegularFile(path):
        raise OSError
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    stream = os.fdopen(descriptor, "rb")
    metadata = os.fstat(stream.fileno())
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        stream.close()
        raise OSError
    return stream


def ValidHeader(value: object, worker: str) -> bool:
    """Validate the exact typed ownership header.

    Args:
        value: Bounded parsed JSON header.
        worker: Expected fixed worker identity.

    Returns:
        True only for the exact versioned worker header.
    """

    return (isinstance(value, list) and len(value) == 3 and value[0] == KIND
            and type(value[1]) is int and value[1] == 1 and value[2] == worker)


def PrepareProgress(report_path: Path) -> bool:
    """Clear only recognized diagnostic children after checking every existing child.

    Args:
        report_path: Runner-selected JUnit destination whose sibling is owned by this plugin.

    Returns:
        True when a fresh bounded directory is available; false without deleting unknown files.
    """

    directory = ProgressDirectory(report_path)
    try:
        directory.mkdir(exist_ok=True)
        if not ValidDirectory(directory):
            return False
        children = []
        for child in directory.iterdir():
            children.append(child)
            if len(children) > MAX_WORKERS + 1:
                return False
        for child in children:
            if not RegularFile(child):
                return False
            with OpenRegular(child) as stream:
                if child.name == "summary.json":
                    data = stream.read(MAX_SUMMARY_BYTES + 1)
                    if len(data) > MAX_SUMMARY_BYTES:
                        return False
                    value = json.loads(data)
                    if not isinstance(value, dict) or value.get("kind") != KIND:
                        return False
                    if type(value.get("schema")) is not int or value["schema"] != 1:
                        return False
                elif child.stem in WORKERS and child.suffix == ".jsonl":
                    if not ValidHeader(json.loads(stream.readline(256)), child.stem):
                        return False
                else:
                    return False
        for child in children:
            child.unlink()
        return True
    except (OSError, ValueError, RecursionError):
        return False


def SafeLabel(node_id: str) -> str:
    """Remove directories and parameter values before retaining a short diagnostic label.

    Args:
        node_id: Pytest-owned complete identifier, never persisted verbatim.

    Returns:
        Bounded ASCII basename and function/class label without parameters.
    """

    label = node_id.split("[", 1)[0].replace("\\", "/").rsplit("/", 1)[-1]
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", label)[:160] or "unknown"


class ProgressRecorder:
    """Buffer completed test protocols in one bounded worker-owned file.

    Args:
        directory: Fresh runner-owned progress directory.
        worker: Fixed serial or gw0..gw11 worker identity.
        clock: Monotonic clock; injectable for deterministic flush tests.
    """

    def __init__(
        self, directory: Path, worker: str, *, clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Open one exclusive stream and flush its fixed ownership header."""

        self.stream: BinaryIO | None = None
        self.clock = clock
        self.last_flush = clock()
        self.buffer = bytearray()
        self.buffer_count = 0
        self.written = 0
        self.stopped = False
        self.pending: tuple[str, str, int, str, str] | None = None
        if worker not in WORKERS:
            return
        try:
            if ValidDirectory(directory):
                self.stream = (directory / f"{worker}.jsonl").open("xb")
                self.Append([KIND, 1, worker])
                self.Flush()
        except OSError:
            self.Close()

    def Append(self, value: list[object]) -> None:
        """Buffer one compact bounded record or a fixed truncation marker.

        Args:
            value: Closed protocol header, complete record or fixed marker.
        """

        if self.stream is None or self.stopped:
            return
        encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
        if self.written + len(self.buffer) + len(encoded) + 32 > MAX_BYTES:
            self.buffer.extend(b'["truncated"]\n')
            self.stopped = True
            self.Flush()
            return
        self.buffer.extend(encoded)
        self.buffer_count += 1
        if self.buffer_count >= 32 or self.clock() - self.last_flush >= 5:
            self.Flush()

    def Flush(self) -> None:
        """Flush a bounded chunk without per-test synchronization or background threads."""

        if self.stream is None:
            return
        try:
            self.stream.write(self.buffer)
            self.stream.flush()
            self.written += len(self.buffer)
            self.buffer.clear()
            self.buffer_count = 0
            self.last_flush = self.clock()
        except OSError:
            self.buffer.clear()
            self.Close()

    def Close(self) -> None:
        """Close the diagnostic stream without changing pytest acceptance."""

        if self.stream is not None:
            try:
                self.stream.close()
            except OSError:
                pass
            self.stream = None

    def pytest_runtest_logreport(self, report: TestReport) -> None:
        """Record only a complete setup/call/teardown protocol.

        Args:
            report: Pytest phase report; captured output is never inspected or retained.
        """

        node_id, phase, outcome, duration = (
            report.nodeid, report.when, report.outcome, report.duration,
        )
        if (not isinstance(node_id, str) or len(node_id) > 8192
                or phase not in ("setup", "call", "teardown")
                or outcome not in ("passed", "failed", "skipped")
                or type(duration) not in (int, float)
                or not 0 <= duration <= MAX_DURATION_MS / 1000
                or not math.isfinite(duration)):
            self.pending = None
            self.Append(["incomplete"])
            return
        duration_ms = round(duration * 1000)
        if phase == "setup":
            if self.pending is not None:
                self.Append(["incomplete"])
            self.pending = (node_id, outcome, duration_ms, phase, outcome)
            return
        if self.pending is None or self.pending[0] != node_id:
            self.Append(["incomplete"])
            self.pending = None
            return
        _, previous, elapsed, last_phase, setup = self.pending
        combined = "failed" if "failed" in (previous, outcome) else (
            "skipped" if "skipped" in (previous, outcome) else "passed"
        )
        elapsed += duration_ms
        if elapsed > MAX_DURATION_MS or (
            phase == "call" and (last_phase != "setup" or setup != "passed")
        ):
            self.pending = None
            self.Append(["incomplete"])
        elif phase == "teardown":
            if last_phase == "call" or (last_phase == "setup" and setup != "passed"):
                digest = hashlib.sha256(node_id.encode("utf-8", errors="surrogatepass")).hexdigest()
                self.Append([digest, SafeLabel(node_id), elapsed, combined])
            else:
                self.Append(["incomplete"])
            self.pending = None
        else:
            self.pending = (node_id, combined, elapsed, phase, setup)

    def pytest_sessionfinish(self) -> None:
        """Persist the last chunk while keeping interrupted cases explicitly incomplete."""

        if self.pending is not None:
            self.Append(["incomplete"])
        self.Flush()
        self.Close()


def ConfigureProgress(config: Config) -> None:
    """Register one recorder only in a serial process or bounded xdist worker.

    Args:
        config: Pytest configuration containing the existing JUnit destination.
    """

    if not config.getoption("--1337-progress", default=False):
        return
    worker_input = getattr(config, "workerinput", None)
    if worker_input is None and config.getoption("numprocesses", default=0):
        return
    worker = worker_input.get("workerid") if isinstance(worker_input, dict) else "serial"
    destination = config.getoption("xmlpath", default=None)
    if worker not in WORKERS or not isinstance(destination, str):
        return
    recorder = ProgressRecorder(ProgressDirectory(Path(destination)), worker)
    config.pluginmanager.register(recorder, "1337-progress-recorder")


def SaveProgressSummary(
    report_path: Path, *, timed_out: bool, worker_limit_exceeded: bool = False,
) -> dict[str, Any]:
    """Save bounded partial diagnostics without treating them as JUnit acceptance.

    Args:
        report_path: Original runner-owned JUnit destination.
        timed_out: Whether the whole pytest subprocess exceeded its unchanged deadline.
        worker_limit_exceeded: Explicit worker selection exceeded the diagnostic worker cap.

    Returns:
        Diagnostic-only partial summary with counts of complete retained protocols.
    """

    summary: dict[str, Any] = {
        "kind": KIND, "schema": 1, "diagnostic_only": True, "partial": True,
        "timed_out": timed_out, "completed": 0, "passed": 0, "failed": 0, "skipped": 0,
        "workers": [], "truncated": worker_limit_exceeded, "unavailable": False, "incomplete": 0,
        "malformed": 0, "slowest": [],
    }
    directory = ProgressDirectory(report_path)
    seen: set[str] = set()
    slowest: list[list[Any]] = []
    try:
        if not ValidDirectory(directory):
            raise OSError
        files = []
        for path in directory.iterdir():
            if path.name != "summary.json":
                files.append(path)
            if len(files) > MAX_WORKERS:
                summary["truncated"] = True
                break
        for path in sorted(files)[:MAX_WORKERS]:
            if (path.stem not in WORKERS or path.suffix != ".jsonl"
                    or not RegularFile(path)):
                summary["unavailable"] = True
                continue
            with OpenRegular(path) as stream:
                if not ValidHeader(json.loads(stream.readline(256)), path.stem):
                    summary["unavailable"] = True
                    continue
                summary["workers"].append(path.stem)
                consumed = stream.tell()
                for _ in range(MAX_LINES):
                    line = stream.readline(MAX_LINE_BYTES + 1)
                    if not line:
                        break
                    consumed += len(line)
                    if (consumed > MAX_BYTES or len(line) > MAX_LINE_BYTES
                            or not line.endswith(b"\n")):
                        summary["truncated"] = True
                        break
                    try:
                        value = json.loads(line)
                    except (ValueError, RecursionError):
                        summary["malformed"] += 1
                        continue
                    if value == ["truncated"]:
                        summary["truncated"] = True
                    elif value == ["incomplete"]:
                        summary["incomplete"] += 1
                    elif (isinstance(value, list) and len(value) == 4
                          and isinstance(value[0], str) and DIGEST.fullmatch(value[0])
                          and isinstance(value[1], str) and SAFE_LABEL.fullmatch(value[1])
                          and type(value[2]) is int and 0 <= value[2] <= MAX_DURATION_MS
                          and value[3] in ("passed", "failed", "skipped")
                          and value[0] not in seen):
                        seen.add(value[0])
                        summary["completed"] += 1
                        summary[value[3]] += 1
                        slowest.append(value)
                        slowest.sort(key=lambda item: (-item[2], item[0]))
                        del slowest[10:]
                    else:
                        summary["malformed"] += 1
                else:
                    summary["truncated"] = bool(stream.read(1)) or summary["truncated"]
        summary["unavailable"] |= not summary["workers"]
        summary["slowest"] = slowest
        target = directory / "summary.json"
        encoded = json.dumps(summary, separators=(",", ":")).encode() + b"\n"
        if len(encoded) > MAX_SUMMARY_BYTES:
            raise OSError
        with target.open("xb") as stream:
            stream.write(encoded)
    except (OSError, ValueError, RecursionError):
        summary["unavailable"] = True
    return summary
