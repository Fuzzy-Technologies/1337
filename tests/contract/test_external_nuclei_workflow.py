# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Isolated draft-only no-HOME workflow enrollment and hostile original-result gate contracts."""

from __future__ import annotations

import ast
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.contract.test_external_nuclei_host import BundleFixture

REPOSITORY = Path(__file__).absolute().parents[2]
JOB = "nuclei-governed-prerequisite-checkpoint"
MARKER = "[nuclei-governed-prerequisite-checkpoint]"


def Workflow():
    """Read actual enrollment, or an explicitly selected local proposal for source-only review."""

    selected = os.environ.get("FUZZY1337_NUCLEI_GOVERNED_WORKFLOW_PROPOSAL")
    path = REPOSITORY / ("_build/nuclei-governed/proposed.yml" if selected == "1" else
                         ".github/workflows/python-quality.yml")

    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_GovernedPrerequisiteJobEnrollsOnlyOneExplicitDraftNoHomeTest():
    """The new marker must not launch any prior target, native, prerequisite or full-gate job."""

    workflow = Workflow()
    jobs = workflow["jobs"]
    job = jobs[JOB]
    assert " ".join(job["if"].split()) == (
        "github.event_name == 'pull_request' && github.event.pull_request.draft == true "
        f"&& contains(github.event.pull_request.body, '{MARKER}')"
    ) and all(MARKER not in str(value) for key, value in jobs.items() if key != JOB), (
        "Only the exact draft marker may enroll the separate genuine no-HOME checkpoint"
    )
    assert set(job) == {"if", "name", "runs-on", "timeout-minutes", "steps"} and (
        job["runs-on"] == "ubuntu-24.04" and job["timeout-minutes"] == 20
    ), "The probe must remain a bounded single Linux job with no target environment or matrix"
    steps = job["steps"]
    assert len(steps) == 7 and all(not step.get("continue-on-error", False) for step in steps), (
        "Exactly one selected execution, original-result gate and always-upload must run"
    )
    reference = jobs["external-targets"]["steps"]
    assert steps[0]["uses"] == reference[0]["uses"] and steps[0]["with"] == {
        "ref": "${{ github.event.pull_request.head.sha }}", "persist-credentials": False,
        "fetch-depth": 0,
    }, "The actual current committed source and accepted-base ancestry must remain provable"
    assert steps[1] == reference[1] and steps[2] == reference[2] and steps[3] == reference[3], (
        "The new probe must reuse pinned Python, uv and locked provisioning without another runtime"
    )
    selector = ("tests/functional/test_external_nuclei_governed_prerequisites.py::"
                "test_InstalledImageRunsExactGovernedEnvironmentWithoutHome")
    assert shlex.split(steps[4]["run"]) == ["uv", "run", "--locked", "--extra", "dev", "pytest",
        selector, "-o", "addopts=", "--no-cov", "-n0", "-v", "--timeout=600",
        "--timeout-method=signal",
        "--junitxml=functional-evidence/nuclei-governed-prerequisites.xml",
    ] and steps[4]["env"] == {
        "FUZZY1337_EXTERNAL_NUCLEI_GOVERNED_PREREQUISITES": "linux-amd64"
    }, "No application case, native cohort, explicit-HOME selection or full suite belongs here"
    assert steps[4]["timeout-minutes"] == 17 and steps[5]["timeout-minutes"] == 1, (
        "The signal deadline must leave bounded independent Docker cleanup time"
    )
    assert steps[5]["env"] == {
        "NUCLEI_GOVERNED_SOURCE_HEAD": "${{ github.event.pull_request.head.sha }}"
    } and steps[6]["uses"] == reference[-1]["uses"] and steps[6]["if"] == "always()", (
        "Original result verification must bind the actual head and preserve failed-run evidence"
    )
    assert steps[6]["with"] == {"name": "nuclei-governed-prerequisite-original-evidence",
        "path": "functional-evidence/external-nuclei-prerequisites/\n"
                "functional-evidence/nuclei-governed-prerequisites.xml\n",
        "if-no-files-found": "error", "retention-days": 14,
    }, "The exact original JUnit and host/raw-image evidence must survive failed checkpoints"


@pytest.mark.parametrize("mutation", [None, "skip", "hidden-home", "failed-host", "bad-source",
                                      "cleanup", "old-home-receipt"])
def test_GovernedWorkflowGateRequiresExactExecutedOriginals(tmp_path, mutation):
    """Execute only the stdlib result reader against visibly synthetic prerequisite originals."""

    step = Workflow()["jobs"][JOB]["steps"][5]
    script = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    imports = {node.names[0].name if isinstance(node, ast.Import) else node.module
        for node in ast.parse(script).body if isinstance(node, (ast.Import, ast.ImportFrom))}
    assert imports == {"json", "re", "sys", "pathlib", "xml.etree"}, (
        "The acceptance gate may only read originals; it cannot rerun or repair a prerequisite"
    )
    owner, head, tree = "a" * 32, "b" * 40, "c" * 40
    root = tmp_path / "functional-evidence/external-nuclei-prerequisites" / ("run-" + owner[:12])
    root.mkdir(parents=True)
    _, _ = BundleFixture(root / "imported")
    host = {"status": "completed-governed-prerequisites", "source_revision": head,
        "source_tree": tree, "image_id": "sha256:" + "e" * 64, "container_id": "f" * 64,
        "configured_target_inputs": [], "governed_no_home_compatibility": "established",
        "cleanup": [{"container_absent": True},
            {"tag": "fuzzy1337-nuclei-runner-" + owner, "absent": True},
            {"tag": "fuzzy1337-nuclei-base-" + owner, "absent": True}]}
    (root / "base.iid").write_text("sha256:" + "d" * 64)
    (root / "runner.iid").write_text(host["image_id"])
    (root / "context-inventory.json").write_text(json.dumps({"revision": head, "tree": tree}))
    imported = root / "imported"
    outcome = json.loads((imported / "prerequisites.json").read_bytes())
    outcome.update(status="completed-governed-prerequisites",
                   governed_no_home_compatibility="established")
    (imported / "prerequisites.json").write_text(json.dumps(outcome))

    for name in ("version", "validate"):
        path = imported / name / "invocation.json"
        invocation = json.loads(path.read_bytes())
        invocation.update(environment={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
            basis="target-free-governed-no-home-prerequisite",
            cwd="/tmp/nuclei-governed-prerequisites/" + name)

        if mutation == "hidden-home":
            invocation["environment"]["HOME"] = "/tmp/hidden-home"

        if mutation == "old-home-receipt":
            invocation["basis"] = "target-free-explicit-home-prerequisite"

        path.write_text(json.dumps(invocation))

    if mutation == "failed-host":
        host["status"] = "failed"

    elif mutation == "bad-source":
        host["source_revision"] = "0" * 40

    elif mutation == "cleanup":
        host["cleanup"][0]["container_absent"] = False

    (root / "host.json").write_text(json.dumps(host))
    skipped = "1" if mutation == "skip" else "0"
    junit = f'<testsuites><testsuite tests="1" failures="0" errors="0" skipped="{skipped}">'
    junit += ('<testcase classname="tests.functional.test_external_nuclei_governed_prerequisites" '
        'name="test_InstalledImageRunsExactGovernedEnvironmentWithoutHome"/></testsuite></testsuites>')
    (tmp_path / "functional-evidence/nuclei-governed-prerequisites.xml").write_text(junit)
    script_path = tmp_path / "read-original-no-home-gate.py"
    script_path.write_text(script)
    argv = [sys.executable, "-I", "-B", str(script_path), head, head + "\n" + tree]
    result = subprocess.run(argv, cwd=tmp_path, capture_output=True, check=False, timeout=5)
    assert (result.returncode == 0) is (mutation is None), (
        "Only one exact executed no-HOME prerequisite with complete source/cleanup may pass"
    )


def test_ComparisonFinalReadyEnrollmentPreservesSeparateOriginalCohorts():
    """Six new application cases stay separate from the prior native and target-free commands."""

    proposed = os.environ.get("FUZZY1337_NUCLEI_COMPARISON_WORKFLOW_PROPOSAL") == "1"
    path = REPOSITORY / ("_build/nuclei-comparison/proposed.yml" if proposed else
                         ".github/workflows/python-quality.yml")
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    job = workflow["jobs"]["external-targets"]
    steps = {step["name"]: step for step in job["steps"]}
    selected = steps["Execute six fresh comparative Nuclei application cases"]
    gate = steps["Require six original Nuclei application observations"]
    condition = ("github.event_name == 'push' || (github.event_name == 'pull_request' "
                 "&& github.event.pull_request.draft == false)")
    assert all(" ".join(step["if"].split()) == condition for step in (selected, gate)), (
        "The six invocations require final readiness; draft prerequisite proof stays separate"
    )
    assert selected["timeout-minutes"] == 20 and job["timeout-minutes"] == 61 and (
        gate["timeout-minutes"] == 1
    ), "The new bounded application step must preserve the prior cohort's wall budget"
    assert shlex.split(selected["run"]) == ["uv", "run", "--locked", "--extra", "dev", "pytest",
        "tests/functional/test_external_nuclei_benchmark.py", "-o", "addopts=", "--no-cov", "-n0",
        "-v", "--timeout=900", "--timeout-method=signal",
        "--junitxml=functional-evidence/nuclei-comparison.xml",
    ] and selected["env"] == {"FUZZY1337_EXTERNAL_NUCLEI_BENCHMARK": "juice-shop"}, (
        "Only the unchanged target's six serial track/case slots may execute in this new step"
    )
    assert "tests.functional.external_nuclei_comparison_gate" in gate["run"] and (
        gate["env"] == {"NUCLEI_COMPARISON_SOURCE_HEAD": "${{ github.event_name == 'pull_request' "
            "&& github.event.pull_request.head.sha || github.sha }}"}
        and gate["run"].startswith('source_identity="$(git rev-parse HEAD HEAD^{tree})"\n')
    ), "Read-only original acceptance must bind the actual current workflow source and tree"
    assert "tests/functional/test_external_native_benchmark.py" in steps[
        "Execute installed native scanner against three fresh pinned targets"]["run"] and (
        "tests/functional/test_external_nuclei_prerequisites.py" in steps[
            "Execute one target-free installed Nuclei prerequisite"]["run"]
    ), "The three native cases and original target-free prerequisite remain separately selected"
    upload = steps["Preserve external target evidence"]
    assert upload["if"] == "always()" and "functional-evidence/nuclei-comparison.xml\n" in (
        upload["with"]["path"]
    ), "Successful and failed new cases must retain original JUnit and host/image evidence"


def test_ApplicationCheckpointEnrollsOnlySixCasesAndTheSameOriginalGate():
    """One explicit draft job exercises product cases without enrolling older proof cohorts."""

    workflow = yaml.safe_load((REPOSITORY / ".github/workflows/python-quality.yml").read_text(
        encoding="utf-8"))
    jobs = workflow["jobs"]
    name = "nuclei-application-product-checkpoint"
    marker = "[nuclei-application-product-checkpoint]"
    job = jobs[name]
    assert " ".join(job["if"].split()) == (
        "github.event_name == 'pull_request' && github.event.pull_request.draft == true "
        f"&& contains(github.event.pull_request.body, '{marker}')"
    ) and all(marker not in str(value) for key, value in jobs.items() if key != name), (
        "The exact draft marker must not launch any legacy target, prerequisite or full-gate job"
    )
    assert set(job) == {"if", "name", "runs-on", "timeout-minutes", "steps"} and (
        job["runs-on"] == "ubuntu-24.04" and job["timeout-minutes"] == 25
    ), "One finite Linux job must leave setup, evidence verification and cleanup time"
    steps = job["steps"]
    reference = jobs["external-targets"]["steps"]
    assert len(steps) == 7 and all(not step.get("continue-on-error", False) for step in steps), (
        "The checkpoint requires one six-case selection, its original gate and always evidence"
    )
    assert steps[0]["uses"] == reference[0]["uses"] and steps[0]["with"] == {
        "ref": "${{ github.event.pull_request.head.sha }}", "persist-credentials": False,
        "fetch-depth": 0,
    } and steps[1:4] == reference[1:4], (
        "Exact current source ancestry, pinned Python/uv and locked provisioning must be reused"
    )
    final = {step["name"]: step for step in reference}
    assert steps[4] == {key: value for key, value in final[
        "Execute six fresh comparative Nuclei application cases"].items() if key != "if"}, (
        "Draft diagnosis must execute the same six ordinary installed product cases as final CI"
    )
    gate = steps[5]
    final_gate = final["Require six original Nuclei application observations"]
    assert gate["run"] == final_gate["run"] and gate["timeout-minutes"] == 1 and (
        gate["env"] == {"NUCLEI_COMPARISON_SOURCE_HEAD": (
            "${{ github.event.pull_request.head.sha }}")}
        and "if" not in gate
    ), "The same read-only six-original gate must bind this actual exact draft head and tree"
    assert steps[6]["if"] == "always()" and steps[6]["uses"] == reference[-1]["uses"] and (
        steps[6]["with"] == {"name": "nuclei-application-product-original-evidence",
            "path": "functional-evidence/external-nuclei-prerequisites/\n"
                    "functional-evidence/nuclei-comparison.xml\n",
            "if-no-files-found": "error", "retention-days": 14}
    ), "Original host/image/target/provider bytes and six-case JUnit must survive failures"
