# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Run the saved-report acceptance cases in one interpreter and retain their JUnit evidence."""

from __future__ import annotations

import sys
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from xml.etree import ElementTree

import pytest

CASES = (
    ("integration/test_finding_persistence", "VerifiedFindingReplayMatchesOfflineShowcaseMarker",
     ("",)),
    ("integration/test_report_export",
     "ProductCliExportsExactSavedSnapshotAndPreservesAllSourceTruth", ("json", "sarif")),
    ("integration/test_report_export", "SelectedWorkspaceRelocationPreservesReportBytes", ("",)),
    ("unit/test_report_commands", "AnyRetainedEvidenceOrOwningContextFailurePreventsOutput",
     ("missing", "corrupt", "foreign", "manifest", "scope", "foreign-scope", "corrupt-scope")),
    ("unit/test_report_commands", "ChangedSavedInputIsRejectedWithoutSubstitutingNewRevision",
     ("model", "workspace")),
    ("unit/test_report_commands", "EmptyWorkspaceExportsWithoutScopeOrCleanScanClaim", ("",)),
    ("contract/test_report_export_formats_contract",
     "ExplicitFormatPublishesExactAcceptedSdkBytesAndVersionOneOutcome",
     ("json", "sarif", "html", "junit")),
)
PROCESS_EVENTS = frozenset({
    "subprocess.Popen", "os.fork", "os.forkpty", "os.posix_spawn", "os.spawn", "os.exec",
    "os.system", "os.startfile", "_winapi.CreateProcess", "pty.spawn",
})


class OfflineGuard:
    """Record and refuse process or socket requests during each complete pytest case."""

    def __init__(self) -> None:
        """Keep the attempt visible even if the product catches the exception."""

        self.active = False
        self.covered = 0
        self.attempts: set[str] = set()

    def Audit(self, event: str, arguments: tuple[object, ...]) -> None:
        """Refuse audited process creation and socket operations in the selected tests."""

        if self.active and (event.startswith("socket.") or event in PROCESS_EVENTS):
            self.attempts.add(event)
            raise RuntimeError(f"Offline acceptance refused runtime operation {event}")

    @pytest.fixture(autouse=True)
    def ProtectExecution(self) -> Iterator[None]:
        """Guard the selected cases from fixture setup through teardown."""

        self.active = True
        self.covered += 1

        try:
            yield

        finally:
            self.active = False


def Main(receipt: Path) -> int:
    """Require every named case to execute, pass once and retain an attributable JUnit result."""

    expected = Counter()
    selection = []

    for module, name, variants in CASES:
        selection.append(f"tests/{module}.py::test_{name}")

        for variant in variants:
            case = f"test_{name}[{variant}]" if variant else f"test_{name}"
            expected[("tests." + module.replace("/", "."), case)] += 1

    guard = OfflineGuard()
    sys.addaudithook(guard.Audit)
    status = pytest.main(["-o", "addopts=", "--strict-config", "--strict-markers", "-q",
                          f"--junitxml={receipt}", *selection], plugins=[guard])

    if status:
        return int(status)

    report = ElementTree.parse(receipt)
    actual = Counter((case.get("classname"), case.get("name")) for case in report.iter("testcase"))

    if actual != expected or guard.covered != expected.total():
        raise ValueError("Every named case must run once with the offline guard active")

    if any(report.find(f".//{tag}") is not None for tag in ("skipped", "failure", "error")):
        raise ValueError("Offline acceptance contains a skipped or failed case")

    if guard.attempts:
        raise ValueError(f"Offline acceptance attempted forbidden operations: {guard.attempts}")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main(Path(sys.argv[1])))
