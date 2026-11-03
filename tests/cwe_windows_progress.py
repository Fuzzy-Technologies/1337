# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Opt-in Windows CWE diagnostics; flushed partial observations never replace JUnit.

Only the guarded CI job loads this plugin. Fixed worker streams contain hashed identifiers
and short labels, never captured output, parameters, locations or exception messages.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import xml.etree.ElementTree as xml
from collections import Counter
from pathlib import Path
from typing import BinaryIO

from pytest import Config, TestReport

ROOT = Path(__file__).absolute().parents[1]
PARTS = ("functional-evidence", "cwe-windows-diagnostic", "progress")
WORKERS = tuple(f"gw{index}" for index in range(12))
MAX_BYTES = 1024 * 1024
MAX_EVENTS = 10000
MAX_EVENT_BYTES = 2048
TERMINAL_RESERVE = 512
SAFE_LABEL = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
MAX_JUNIT_BYTES = 64 * 1024 * 1024
EXPECTED_CLASSES = {
    "tests.contract.test_intelligence_cwe_selection_contract": 132,
    "tests.integration.test_intelligence_cwe_selection_composition": 13,
    "tests.unit.test_intelligence_cwe_selection": 34,
    "tests.unit.test_intelligence_cwe_xml": 59,
    "tests.unit.test_intelligence_cwe_zip": 89,
}


def Directory(root: Path) -> Path:
    """Create only fixed children after rejecting linked or reparse-point ancestors."""

    current = root

    for part in (None, *PARTS):
        if part is not None:
            current = current / part
            current.mkdir(exist_ok=True)

        metadata = current.lstat()

        if (not stat.S_ISDIR(metadata.st_mode)
                or getattr(metadata, "st_file_attributes", 0) & 0x400):
            raise OSError("Diagnostic directories must be ordinary owned directories.")

    return current


def Identity(node_id: str) -> tuple[str, str, bool]:
    """Hash a bounded original identity and retain only a safe unparameterized short label."""

    if type(node_id) is not str:
        return "", "unavailable", True

    truncated = len(node_id) > 8192
    bounded = node_id[:8192]
    digest = hashlib.sha256(bounded.encode("utf-8", errors="replace")).hexdigest()
    label = bounded.split("[", 1)[0].replace("\\", "/").rsplit("/", 1)[-1]

    return digest, label if SAFE_LABEL.fullmatch(label) else "unavailable", truncated


class Recorder:
    """Write one exclusive bounded worker stream with immediate flush and explicit truncation."""

    def __init__(self, directory: Path, worker: str) -> None:
        """Open a fixed worker filename exclusively, without overwriting prior evidence."""

        if worker not in WORKERS:
            raise OSError("Unsupported diagnostic worker.")

        descriptor = os.open(directory / f"{worker}.jsonl",
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0), 0o600)
        self.stream: BinaryIO | None = os.fdopen(descriptor, "wb")
        self.used = 0
        self.events = 0
        self.Append({"kind": "cwe-windows-progress", "schema": 1, "worker": worker,
                     "partial": True, "diagnostic_only": True})

    def Store(self, event: dict[str, object]) -> None:
        """Write and flush one finite event; I/O failure cannot change pytest outcomes."""

        if self.stream is None:
            return

        payload = (json.dumps(event, ensure_ascii=True, allow_nan=False,
                              separators=(",", ":")) + "\n").encode("ascii")

        if len(payload) > MAX_EVENT_BYTES or self.used + len(payload) > MAX_BYTES:
            self.Close()

            return

        try:
            self.stream.write(payload)
            self.stream.flush()
            self.used += len(payload)

        except OSError:
            self.Close()

    def Append(self, event: dict[str, object]) -> None:
        """Reserve terminal space and stop with a truthful marker when any quota is reached."""

        size = len(json.dumps(event, ensure_ascii=True, allow_nan=False).encode("ascii")) + 1

        if (self.events >= MAX_EVENTS or size > MAX_EVENT_BYTES
                or self.used + size > MAX_BYTES - TERMINAL_RESERVE):
            self.Store({"event": "truncated", "partial": True, "diagnostic_only": True})
            self.Close()

            return

        self.events += 1
        self.Store(event)

    def Close(self) -> None:
        """Close only this owned stream, tolerating unavailable diagnostic storage."""

        if self.stream is not None:
            try:
                self.stream.close()

            except OSError:
                pass

            self.stream = None

    def pytest_runtest_logstart(self, nodeid: str, location: object) -> None:
        """Flush a case-start sentinel without retaining pytest locations or parameters."""

        digest, label, truncated = Identity(nodeid)
        self.Append({"event": "start", "node_sha256": digest, "label": label,
                     "identity_truncated": truncated,
                     "hash_scope": "first_8192_characters" if truncated else "full_identity"})

    def pytest_runtest_logreport(self, report: TestReport) -> None:
        """Flush only admitted phase and outcome fields, never report payloads."""

        digest, label, truncated = Identity(report.nodeid)

        if (report.when not in ("setup", "call", "teardown")
                or report.outcome not in ("passed", "failed", "skipped")):
            self.Append({"event": "unsupported_report", "partial": True})

            return

        self.Append({"event": "report", "node_sha256": digest, "label": label,
                     "identity_truncated": truncated,
                     "hash_scope": "first_8192_characters" if truncated else "full_identity",
                     "phase": report.when, "outcome": report.outcome})

    def pytest_sessionfinish(self) -> None:
        """Record observed session finish without claiming complete or successful test evidence."""

        self.Append({"event": "session_finished", "partial": True, "diagnostic_only": True})
        self.Close()


def pytest_configure(config: Config) -> None:
    """Register only bounded xdist workers; explicitly ignore the controller and serial runs."""

    worker_input = getattr(config, "workerinput", None)

    if not isinstance(worker_input, dict) or worker_input.get("workerid") not in WORKERS:
        return

    try:
        recorder = Recorder(Directory(ROOT), worker_input["workerid"])

    except OSError:
        return

    config.pluginmanager.register(recorder, "cwe-windows-worker-progress")


def VerifyJunit(path: Path) -> bool:
    """Require the exact original 327-case successful unskipped JUnit population."""

    try:
        metadata = path.lstat()

        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or getattr(metadata, "st_file_attributes", 0) & 0x400
                or metadata.st_size > MAX_JUNIT_BYTES):
            return False

        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))

        with os.fdopen(descriptor, "rb") as stream:
            actual = os.fstat(stream.fileno())

            if (actual.st_ino != metadata.st_ino or actual.st_dev != metadata.st_dev
                    or actual.st_size > MAX_JUNIT_BYTES):
                return False

            payload = stream.read(MAX_JUNIT_BYTES + 1)

        if (len(payload) > MAX_JUNIT_BYTES or b"<!DOCTYPE" in payload
                or b"<!ENTITY" in payload):
            return False

        root = xml.fromstring(payload)

        if root.tag != "testsuites":
            return False

        suites = list(root)

        if not suites or any(suite.tag != "testsuite" for suite in suites):
            return False

        cases = [case for suite in suites for case in suite if case.tag == "testcase"]

        if (len(cases) != 327
                or Counter(case.get("classname") for case in cases) != EXPECTED_CLASSES
                or len({(case.get("classname"), case.get("name")) for case in cases}) != 327
                or any(not case.get("name") for case in cases)
                or any(node.tag in ("failure", "error", "skipped", "xfail")
                       for node in root.iter())):
            return False

        for suite in suites:
            if (int(suite.get("tests", "-1")) != len(suite.findall("testcase"))
                    or any(int(suite.get(key, "-1")) != 0
                           for key in ("failures", "errors", "skipped"))):
                return False

        return True

    except (OSError, ValueError, xml.ParseError):
        return False


def Main() -> int:
    """Emit fixed diagnostic acceptance facts without substituting for the full quality gate."""

    try:
        path = Directory(ROOT).parent / "selection.xml"
        accepted = VerifyJunit(path)

    except OSError:
        accepted = False

    print(json.dumps({"kind": "cwe-windows-junit-verification", "schema": 1,
                      "expected_cases": 327, "accepted": accepted,
                      "diagnostic_only": True, "full_gate_replaced": False}, sort_keys=True))

    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(Main())
