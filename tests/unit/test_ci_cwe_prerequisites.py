# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Keep original-source CWE research isolated from ordinary and untrusted CI work."""

import shlex
from pathlib import Path

import yaml


def Workflow():
    """Read the real static workflow without importing or executing source research."""

    path = Path(__file__).resolve().parents[2] / ".github/workflows/intel-source-acceptance.yml"

    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_ResearchRequiresOwnDraftMarkerAndNeverEnrollsOtherSourceJobs():
    """A foreign PR, ready PR or unrelated checkpoint must not request these external reads."""

    jobs = Workflow()["jobs"]
    marker = "[cwe-prerequisite-checkpoint]"
    condition = " ".join(jobs["cwe-prerequisites"]["if"].split())
    assert condition == (
        "github.event.pull_request.draft && "
        "github.event.pull_request.head.repo.full_name == github.repository && "
        f"contains(github.event.pull_request.body, '{marker}')"
    ), "CWE research lost its same-repository draft and explicit-checkpoint admission"
    assert all(marker not in job.get("if", "") for name, job in jobs.items()
               if name != "cwe-prerequisites"), "Research marker launched unrelated source profiles"


def test_ResearchBindsHeadAndPreservesFailuresWithoutRunningFullGate():
    """One bounded opt-in pytest selection retains originals even when retrieval refuses."""

    job = Workflow()["jobs"]["cwe-prerequisites"]
    steps = job["steps"]
    assert steps[0]["with"] == {
        "ref": "${{ github.event.pull_request.head.sha }}", "persist-credentials": "false",
    }, "Research checkout is not bound to the exact credential-free proposed head"
    executions = [step for step in steps
                  if "FUZZY1337_RUN_CWE_PREREQUISITES" in step.get("env", {})]
    assert len(executions) == 1, "Research must have exactly one explicitly enabled execution"
    execution = executions[0]
    assert execution["env"] == {"FUZZY1337_RUN_CWE_PREREQUISITES": "1"}, (
        "Research must not enable another external or full integration profile")
    assert shlex.split(execution["run"]) == [
        "uv", "run", "--locked", "--extra", "dev", "pytest",
        "tests/integration/test_cwe_source_prerequisites.py", "-n", "0", "--no-cov", "-q",
        "--junitxml=functional-evidence/cwe-prerequisites.xml",
    ], "Research expanded beyond its single original-source prerequisite selection"
    assert int(execution["timeout-minutes"]) <= 3 and int(job["timeout-minutes"]) <= 8, (
        "The finite original-source research deadline was enlarged")
    assert steps[-1]["if"] == "always()" and steps[-1]["with"]["if-no-files-found"] == "error", (
        "Failure must retain original facts and missing artifacts cannot be silently accepted")
    assert not any(step.get("continue-on-error") == "true" for step in steps), (
        "Research refusal must remain a failing result")
