# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Keep the read-only CI route and its required-check dependency conservative."""

from pathlib import Path

import pytest
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
    assert "if" not in decision and decision["env"] == {
        "ROUTING_RESULT": "${{ needs.saved-report-acceptance.result }}",
        "INTEGRATION_PROFILE": "${{ needs.saved-report-acceptance.outputs.integration_profile }}",
    }, "The first unconditional guard must retain the actual prerequisite result and scope"
    assert 'test "$ROUTING_RESULT" = success' in decision["run"] and (
        'full|passive)' in decision["run"] and '*) exit 1' in decision["run"]
    ), "Only a successfully executed and explicitly admitted policy job may proceed"
    external = jobs["external-targets"]
    assert external["needs"] == "saved-report-acceptance", (
        'External acceptance must wait for the independently classified report '
        'profile'
    )
    prefix = "needs.saved-report-acceptance.outputs.integration_profile == 'full' &&"
    assert external["if"].startswith(prefix), (
        "Only the full profile may start the external job"
    )


def test_OfflineGuardRetainsAttemptsAndReleasesItsWholeCaseScope():
    """Both known process and socket operations refuse while ordinary audit events remain inert."""

    from tools.saved_report_acceptance import OfflineGuard

    guard = OfflineGuard()
    guard.Audit("subprocess.Popen", ())
    assert not guard.attempts, (
        'The offline guard must retain forbidden attempts and release only its '
        'completed case scope'
    )
    scope = OfflineGuard.ProtectExecution.__wrapped__(guard)
    next(scope)
    assert guard.active and guard.covered == 1, (
        'The offline guard must retain forbidden attempts and release only its '
        'completed case scope'
    )
    guard.Audit("ordinary.fixture", ())

    for event in ("subprocess.Popen", "socket.connect"):
        with pytest.raises(RuntimeError, match="Offline acceptance refused"):
            guard.Audit(event, ())

    with pytest.raises(StopIteration):
        next(scope)

    assert not guard.active and guard.attempts == {"subprocess.Popen", "socket.connect"}, (
        'The offline guard must retain forbidden attempts and release only its '
        'completed case scope'
    )


@pytest.mark.parametrize("mutation", [
    "none", "status", "missing", "duplicate", "skipped", "failure", "error", "unguarded", "attempt",
])
def test_OfflineAcceptanceRequiresItsExactExecutedAndGuardedJunit(tmp_path, monkeypatch, mutation):
    """The real verifier refuses missing, failed, skipped or unguarded proof."""

    from xml.etree import ElementTree

    from tools import saved_report_acceptance as acceptance

    hooks = []
    monkeypatch.setattr(acceptance.sys, "addaudithook", hooks.append)
    receipt = tmp_path / "owned.xml"

    def Execute(arguments, plugins):
        """Produce deliberately varied receipts through the exact fixed selection interface."""

        guard, = plugins
        assert len(hooks) == 1 and f"--junitxml={receipt}" in arguments, (
            'Saved-report acceptance must use its exact guarded cases and return the '
            'original pytest status'
        )
        root = ElementTree.Element("testsuite")

        for module, name, variants in acceptance.CASES:
            assert f"tests/{module}.py::test_{name}" in arguments, (
                'Saved-report acceptance must use its exact guarded cases and return the '
                'original pytest status'
            )

            for variant in variants:
                case = f"test_{name}[{variant}]" if variant else f"test_{name}"
                ElementTree.SubElement(root, "testcase",
                    classname="tests." + module.replace("/", "."), name=case)
                guard.covered += int(mutation != "unguarded")

        if mutation == "missing":
            root.remove(root[0])

        elif mutation == "duplicate":
            root.append(root[0])

        elif mutation in {"skipped", "failure", "error"}:
            ElementTree.SubElement(root[0], mutation)

        elif mutation == "attempt":
            guard.attempts.add("socket.connect")

        ElementTree.ElementTree(root).write(receipt)

        return int(mutation == "status")

    monkeypatch.setattr(acceptance.pytest, "main", Execute)

    if mutation in {"none", "status"}:
        assert acceptance.Main(receipt) == int(mutation == "status"), (
            'Saved-report acceptance must use its exact guarded cases and return the '
            'original pytest status'
        )

    else:
        with pytest.raises(ValueError):
            acceptance.Main(receipt)
