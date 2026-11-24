# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Keep the read-only CI route and its required-check dependency conservative."""

from pathlib import Path

import yaml

from tools.saved_report_scope import SavedReportOnly


def test_OnlyUnambiguousReportModificationsSelectOfflineAcceptance():
    """Mixed changes, gate edits and non-regular entries retain the full acceptance profile."""

    header = b":100644 100644 612451f 1563805 M\0"
    report = header + b"src/fuzzy1337/reporting.py\0"
    changelog = header + b"CHANGELOG.md\0"
    assert SavedReportOnly(report + changelog), "A report change may carry its changelog"
    assert SavedReportOnly(header + b"docs/REPORT_EXPORT.md\0"), "The report guide is read-only"
    rejected = (
        b"", changelog, report.rstrip(b"\0"), report + header,
        report + header + b"src/fuzzy1337/executor.py\0",
        report + header + b"tools/saved_report_acceptance.py\0",
        header + b"docs/REPORT_EXPORT.md\nother\0",
        report.replace(b":100644", b":120000"), report.replace(b"100644 ", b"100755 "),
        report.replace(b" M\0", b" R100\0"), report.replace(b" M\0", b" D\0"),
        report.replace(b" M\0", b" A\0"), report + header + b"uv.lock\0",
    )

    for candidate in rejected:
        assert not SavedReportOnly(candidate), f"Unexpected read-only admission: {candidate!r}"


def test_OfflineFailureReachesTheRequiredContainerCheck():
    """A failed or skipped acceptance job cannot make the protected check succeed by skipping."""

    path = Path(__file__).resolve().parents[2] / ".github/workflows/python-quality.yml"
    jobs = yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"]
    required = jobs["container-quality"]
    decision = required["steps"][0]
    assert required["needs"] == "saved-report-acceptance" and "!cancelled()" in required["if"], (
        "The protected check must evaluate failed and skipped prerequisites"
    )
    assert decision["if"] == "needs.saved-report-acceptance.result != 'success'"
    assert decision["run"] == "exit 1", "Only a successfully executed policy job may proceed"
    external = jobs["external-targets"]
    assert external["needs"] == "saved-report-acceptance"
    prefix = "needs.saved-report-acceptance.outputs.profile == 'full' &&"
    assert external["if"].startswith(prefix), (
        "Only the full profile may start the external job"
    )
