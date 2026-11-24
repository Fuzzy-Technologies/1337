# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Classify a complete NUL-delimited Git raw diff for the saved-report acceptance profile."""

from __future__ import annotations

import sys

REPORT_FILES = frozenset({
    b"docs/DEMO.md", b"docs/REPORTING.md", b"docs/REPORT_EXPORT.md",
    b"src/fuzzy1337/report_commands.py", b"src/fuzzy1337/report_formats.py",
    b"src/fuzzy1337/reporting.py", b"tests/unit/test_reporting.py",
    b"tests/unit/test_report_commands.py", b"tests/integration/test_report_export.py",
    b"tests/contract/test_report_export_formats_contract.py",
})


def SavedReportOnly(changes: bytes) -> bool:
    """Admit existing regular report files and their changelog entry on an unambiguous diff."""

    records = changes.split(b"\0")

    if records[-1] or len(records) < 3 or len(records) % 2 != 1:
        return False

    changed = set()

    for header, path in zip(records[:-1:2], records[1::2], strict=True):
        fields = header.split()

        if len(fields) != 5 or fields[:2] != [b":100644", b"100644"] or fields[4] != b"M":
            return False

        if path not in REPORT_FILES and path != b"CHANGELOG.md":
            return False

        changed.add(path)

    return bool(changed & REPORT_FILES)


if __name__ == "__main__":
    print("saved-report" if SavedReportOnly(sys.stdin.buffer.read()) else "full")
