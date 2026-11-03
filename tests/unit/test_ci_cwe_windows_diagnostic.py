# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Guard the opt-in CWE diagnostic without replacing or widening the Windows full gate."""

import hashlib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/native-ci-diagnostic.yml"
SELECTION = (
    "tests/unit/test_intelligence_cwe_selection.py",
    "tests/unit/test_intelligence_cwe_xml.py",
    "tests/unit/test_intelligence_cwe_zip.py",
    "tests/contract/test_intelligence_cwe_selection_contract.py",
    "tests/integration/test_intelligence_cwe_selection_composition.py",
)


def Job():
    """Read the actual new job from the guarded repository workflow."""

    return yaml.safe_load(WORKFLOW.read_text())["jobs"]["cwe-selected-windows"]


@pytest.mark.parametrize("line_ending", [b"\n", b"\r\n"], ids=["git-lf", "windows-crlf"])
def test_ExistingNativeBaselineRemainsByteIdentical(line_ending: bytes) -> None:
    """Preserve exact Git-content bytes across LF and Windows CRLF checkout representations."""

    canonical = WORKFLOW.read_bytes().replace(b"\r\n", b"\n")
    assert b"\r" not in canonical, "A lone carriage return must not enter canonical Git content."
    checkout = canonical.replace(b"\n", line_ending)
    original = checkout.replace(b"\r\n", b"\n").split(b"  cwe-selected-windows:\n", 1)[0]
    assert hashlib.sha256(original).hexdigest() == (
        "0fb492d0061d73c9474c8729fd51b1599578520ec1d02e628fffc30a1ee76742"
    ), "The canonical Git bytes of the original native workflow/job must remain identical."


def test_NewDiagnosticRequiresSameRepositoryDraftAndExactMarker():
    """Neither an ordinary ready PR nor an unmarked or foreign Draft can run the subset."""

    job = Job()
    assert " ".join(job["if"].split()) == (
        "${{ github.event_name == 'pull_request' && github.event.pull_request.draft == true "
        "&& github.event.pull_request.head.repo.full_name == github.repository "
        "&& contains(github.event.pull_request.body, '[cwe-windows-diagnostic-checkpoint]') }}"
    ), "The diagnostic must require all three explicit same-repository Draft admission guards."
    assert job["runs-on"] == "windows-2022" and job["timeout-minutes"] == 5, (
        "The new diagnostic must retain its own finite five-minute actual Windows profile."
    )
    assert "needs" not in job and not job.get("continue-on-error", False), (
        "The separate diagnostic cannot replace a full gate or suppress its own failures."
    )


def test_ProvisioningUsesExactHeadAndPinnedLockedRuntime():
    """The diagnostic must exercise proposed source under the standard locked Windows runtime."""

    steps = Job()["steps"]
    assert steps[0]["uses"] == (
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    ) and steps[0]["with"] == {
        "ref": "${{ github.event.pull_request.head.sha }}", "persist-credentials": False,
    }, "Checkout must pin the proposed head and retain no credentials."
    assert steps[1]["uses"] == (
        "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0"
    ) and steps[1]["with"] == {"python-version": "3.13"}, "Python provisioning must stay pinned."
    assert [step["run"] for step in steps[2:4]] == [
        "python -m pip install uv==0.11.33", "uv sync --locked --extra dev --python 3.13",
    ], "Only the standard pinned uv and locked development dependencies may be installed."


def test_ExactSelectionKeepsDiagnosticBudgetsAndPreservesNativeExitCode():
    """The five-file two-worker diagnostic retains original stdout and actual pytest status."""

    step = Job()["steps"][4]
    assert step["timeout-minutes"] == 3 and step["shell"] == "pwsh", (
        "The diagnostic step must finish within its own finite three-minute ceiling."
    )
    assert step["env"] == {"PYTHONPATH": "tests"}, (
        "Only this job may explicitly expose its checkout-only diagnostic plugin."
    )
    command = step["run"]
    lines = [line.strip().removesuffix("`").strip() for line in command.splitlines()]
    actual = tuple(line for line in lines if line.startswith("tests/"))
    assert actual == SELECTION, "The diagnostic must run exactly the original five CWE files."
    assert "-p cwe_windows_progress -n 2 --dist=load -o addopts='' --no-cov -vv" in command, (
        "The fixed independent diagnostic profile cannot inherit full-gate coverage or workers."
    )
    assert "--timeout=30 --timeout-method=thread --durations=20" in command, (
        "Cases must preserve their explicit thirty-second thread timeout and duration evidence."
    )
    assert "--junitxml=functional-evidence/cwe-windows-diagnostic/selection.xml" in command, (
        "Authoritative JUnit must have a distinct fixed path."
    )
    assert "2>&1 | Tee-Object -FilePath functional-evidence/cwe-windows-diagnostic/pytest.log" in (
        command
    ), "Both original streams must be retained while GitHub receives streamed output."
    assert "$testExit = $LASTEXITCODE\n" in command and (
        "$testExit | Set-Content functional-evidence/cwe-windows-diagnostic/exit-code.txt\n"
    ) in command, "PowerShell Tee must preserve and retain the actual original pytest exit."
    assert command.endswith(
        "uv run --locked --extra dev python tests/cwe_windows_progress.py `\n"
        "  2>&1 | Tee-Object -FilePath "
        "functional-evidence/cwe-windows-diagnostic/verification.json\n"
        "$verificationExit = $LASTEXITCODE\n"
        "if ($testExit -ne 0) { exit $testExit }\n"
        "exit $verificationExit\n"
    ), "Zero pytest exit must also require exact unskipped original JUnit acceptance."
    assert not any(value in command for value in (
        "1337-dev", "--cov=", "--maxfail", "--collect-only", "||", "--timeout=120",
    )), "The subset must not invoke or weaken the canonical full gate."


def test_ArtifactsAreAlwaysRetainedAndMissingEvidenceIsAnError():
    """Failure and timeout evidence must upload with headroom and explicit missing-file failure."""

    step = Job()["steps"][-1]
    assert step["if"] == "always()" and step["uses"] == (
        "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"
    ), "Original diagnostic artifacts must upload after passed, failed or interrupted tests."
    assert step["with"] == {
        "name": "selected-cwe-windows-diagnostic",
        "path": "functional-evidence/cwe-windows-diagnostic/",
        "if-no-files-found": "error", "retention-days": 7,
    }, "Artifact identity, ownership, retention and missing-evidence failure must stay fixed."
