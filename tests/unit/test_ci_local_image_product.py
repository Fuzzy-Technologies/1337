# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Source enrollment and causal evidence-gate controls using explicitly inert receipt fixtures."""

import json
from pathlib import Path

import pytest
import yaml

REPOSITORY = Path(__file__).parents[2]
HEAD = "1" * 40


def Workflow():
    """Read the dedicated ordinary workflow without launching any runtime or provider."""

    return yaml.safe_load((REPOSITORY / ".github/workflows/local-image-product.yml").read_text(
        encoding="utf-8"))


def test_LocalImageWorkflowBindsExactHeadInstalledWheelAndPinnedPrerequisites():
    """Dedicated acceptance must retain installed source and its private daemon boundary."""

    workflow = Workflow()
    assert workflow["permissions"] == {"contents": "read"} and len(workflow["jobs"]) == 1, (
        "The dedicated cohort must keep bounded read-only repository permissions."
    )
    job = workflow["jobs"]["owned-local-image"]
    condition = " ".join(job["if"].split())
    assert "github.event.pull_request.draft == false" in condition and (
        "[local-image-product-checkpoint]" in condition
        and "github.event_name == 'push'" in condition
    ), "Ready integration and enrolled draft feedback must exercise the same actual lane."
    steps = job["steps"]
    checkout = steps[0]
    assert checkout["with"] == {"ref": "${{ github.event.pull_request.head.sha || github.sha }}",
        "fetch-depth": 0, "persist-credentials": False}, (
        "Actual source must bind the exact enrolled PR head with full history and no credentials."
    )
    assert "git rev-parse HEAD" in steps[1]["run"] and job["timeout-minutes"] == 15, (
        "An exact source readback and finite cohort budget must precede actual runtime."
    )
    assert [step["uses"] for step in steps if "uses" in step] == [
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    ], "The new lane must retain the same exact reviewed action revisions."
    install = next(step["run"] for step in steps if step["name"].startswith("Synchronize"))
    assert "uv sync --locked" in install and "uv build --wheel --no-sources" in install and (
        "--no-deps --reinstall dist/*.whl" in install and "-I -c" in install
    ), "The genuine installed boundary must replace editable source with the built wheel."
    existing = yaml.safe_load((REPOSITORY / ".github/workflows/trivy-acceptance.yml").read_text(
        encoding="utf-8"))
    original = next(step["run"] for step in existing["jobs"]["owned-offline"]["steps"]
                    if step["name"].startswith("Provision checksum"))
    proposed = next(step["run"] for step in steps if step["name"].startswith("Provision checksum"))
    assert proposed == original, (
        "Existing independent Trivy release/DB provisioning pins must remain."
    )
    runtime = next(step for step in steps if step["name"].startswith("Run installed product"))
    assert runtime["timeout-minutes"] == 6 and (
        "sudo unshare --net -- env -i" in runtime["run"]
    ) and (
        "tests/fixtures/local_image/owned_product_lane.py" in runtime["run"]
        and "--containerd /usr/bin/containerd" in runtime["run"]
        and '--source-head "$ENROLLED_HEAD"' in runtime["run"]
    ), "Only the exact-head owned-daemon manager may launch this bounded no-egress cohort."
    assert steps[-1]["if"] == "always()", "Actual failure diagnostics must remain available."


@pytest.mark.parametrize("change", ("valid", "skip", "no-cases", "cleanup", "head", "model"))
def test_ActualEvidenceGateRejectsMissingSkippedOrUnconfirmedFacts(tmp_path, monkeypatch, change):
    """The ordinary gate requires original JUnit, lifecycle and model facts."""

    root = tmp_path / "functional-evidence/local-image-product"
    lifecycle = root / "lifecycle"
    lifecycle.mkdir(parents=True)
    oracle_path = tmp_path / "tests/fixtures/trivy/product_oracle.v1.json"
    oracle_path.parent.mkdir(parents=True)
    cases = [{"case_id": "present", "expected_selected_advisory_match": True},
             {"case_id": "fixed", "expected_selected_advisory_match": False}]
    oracle_path.write_text(json.dumps({"cases": cases}))
    (lifecycle / "startup.json").write_text(json.dumps({"source_commit": HEAD,
        "owned_daemon": True, "ambient_containerd": False}))
    shutdown = {"cleanup_confirmed": change != "cleanup", "owned_root_retained": False,
                "pytest_exit_code": 0, "failure_category": None}
    (lifecycle / "shutdown.json").write_text(json.dumps(shutdown))
    prefix = "test_InstalledLocalExportThenExplicitNativeScanPreservesConfigAndFinding["
    xml_cases = []
    for case in cases:
        directory = root / case["case_id"]
        directory.mkdir()
        (directory / "result.json").write_text(json.dumps({
            "outcome": "selected-two-phase-assertions-passed",
            "selected_advisory_match": case["expected_selected_advisory_match"],
            "scan_completeness": "not-assessed", "model_revision": 0 if change == "model" else 1}))
        xml_cases.append('<testcase name="' + prefix + case["case_id"] + ']">' + (
            "<skipped/>" if change == "skip" else "") + "</testcase>")
    (root / "pytest.xml").write_text("<testsuite>" + (
        "" if change == "no-cases" else "".join(xml_cases)) + "</testsuite>")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ENROLLED_HEAD", "2" * 40 if change == "head" else HEAD)
    command = next(step["run"] for step in Workflow()["jobs"]["owned-local-image"]["steps"]
                   if step["name"].startswith("Require actual two-case"))
    source = command.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    if change == "valid":
        exec(compile(source, "inert-workflow-evidence-control", "exec"), {})
    else:
        with pytest.raises(ValueError):
            exec(compile(source, "inert-workflow-evidence-control", "exec"), {})
