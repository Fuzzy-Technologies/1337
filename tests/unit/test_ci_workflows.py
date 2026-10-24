# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Protect draft feedback, final integration triggers and required full-job execution."""

from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOWS = {
    "python-quality.yml": {"quality", "browser-page-quality", "container-quality", "synthetic-lab",
                           "external-targets"},
    "documentation.yml": {"deterministic-documentation"},
    "nuclei-acceptance.yml": {"owned-loopback"},
    "nmap-acceptance.yml": {"owned-loopback"},
    "trivy-acceptance.yml": {"owned-offline"},
}
INTEGRATION_CONDITION = (
    "github.event_name == 'push' || (github.event_name == 'pull_request' "
    "&& github.event.pull_request.draft == false)"
)
NATIVE_IMAGE_FEATURE_CONDITION = (
    INTEGRATION_CONDITION + " || (github.event_name == 'pull_request' "
    "&& github.event.pull_request.draft == true "
    "&& contains(github.event.pull_request.body, '[native-image-feature-checkpoint]'))"
)
NATIVE_PROTOCOL_FEATURE_CONDITION = (
    INTEGRATION_CONDITION + " || (github.event_name == 'pull_request' "
    "&& github.event.pull_request.draft == true "
    "&& contains(github.event.pull_request.body, '[native-image-protocol-checkpoint]'))"
)
BROWSER_FEATURE_CONDITION = (
    INTEGRATION_CONDITION + " || (github.event_name == 'pull_request' "
    "&& github.event.pull_request.draft == true "
    "&& contains(github.event.pull_request.body, '[browser-feature-checkpoint]'))"
)


def Workflow(name: str) -> dict[str, Any]:
    """Read the actual workflow configuration without evaluating GitHub expressions."""

    path = Path(__file__).resolve().parents[2] / ".github" / "workflows" / name

    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", WORKFLOWS)
def test_FinalReadinessAndDraftTransitionsTriggerTheSameConcurrencyOwner(name: str) -> None:
    """Readiness starts final checks and returning to draft cancels their existing run."""

    workflow = Workflow(name)
    events = workflow.get("on", workflow.get(True))
    assert set(events) == {"pull_request", "push"}, "Integration acquired an unexpected trigger."
    assert events["pull_request"] == {
        "branches": ["develop", "master"],
        "types": ["opened", "reopened", "synchronize", "ready_for_review", "converted_to_draft"],
    }, "Final readiness, later heads and draft cancellation must remain explicit PR events."
    assert events["push"] == {"branches": ["master"]}, (
        "Integration into develop must not repeat the full gate after merge."
    )
    concurrency = workflow["concurrency"]
    assert concurrency["cancel-in-progress"] is True, "Stale integration runs must be cancelled."
    assert concurrency["group"].endswith("-${{ github.ref }}"), (
        "All lifecycle events for the same PR must share the cancellation owner."
    )


@pytest.mark.parametrize("name", WORKFLOWS)
def test_EveryHeavyJobWaitsForFinalReadinessWithoutWeakeningTheGate(name: str) -> None:
    """Draft work skips heavy jobs while ready PRs and stable pushes retain required checks."""

    workflow = Workflow(name)
    jobs = workflow["jobs"]
    expected = WORKFLOWS[name] | ({"deploy-pages"} if name == "documentation.yml" else set())
    assert set(jobs) == expected, "The integration job inventory changed unexpectedly."
    assert workflow["permissions"] == {"contents": "read"}, "PR authority expanded."

    for job_id in WORKFLOWS[name]:
        job = jobs[job_id]
        condition = " ".join(str(job.get("if", "")).split())
        expected_condition = (
            BROWSER_FEATURE_CONDITION if job_id == "browser-page-quality"
            else NATIVE_PROTOCOL_FEATURE_CONDITION if job_id == "quality"
            else NATIVE_IMAGE_FEATURE_CONDITION if name == "trivy-acceptance.yml"
            else INTEGRATION_CONDITION)
        assert condition == expected_condition, (
            f"{name}/{job_id} lost its final gate or explicit feature checkpoint."
        )
        assert job.get("continue-on-error", False) is False, "Full gate failures became advisory."
        assert job["steps"], "Required integration work was replaced with an empty job."


def test_DocumentationTestsUseParallelWorkersAndKeepBranchCoverage() -> None:
    """Independent documentation modules must share bounded xdist execution and real coverage."""

    steps = Workflow("documentation.yml")["jobs"]["deterministic-documentation"]["steps"]
    command = next(step["run"] for step in steps
                   if step.get("name") == (
                       "Exercise documentation boundaries and enforce per-tool branch coverage"))
    assert "-n auto --dist=loadscope" in command, "Documentation tests lost process parallelism."
    assert "--cov=tools --cov-branch" in command, "Parallel documentation lost branch measurement."
    assert "fuzzy1337.coverage_gate" in command, "Parallel documentation lost its per-tool gate."


def test_OfflineBrowserAcceptanceRequiresAnInstalledEngineAndSeparatesTheOwnedFixedPort() -> None:
    """Genuine engine acceptance cannot become a skipped test or parallel fixed-port race."""

    job = Workflow("python-quality.yml")["jobs"]["browser-page-quality"]
    assert job["runs-on"] == "ubuntu-24.04", "Linux descendant acceptance moved platforms."
    commands = tuple(step for step in job["steps"] if "run" in step)
    assert any("uv sync --locked --extra dev --extra browser" in step["run"]
               for step in commands), "The pinned optional browser dependency was not installed."
    assert any("python -m playwright install chromium --only-shell" in step["run"]
               for step in commands), "Actual pinned Chromium installation was omitted."
    tests = tuple(step for step in commands if "test_browser_page_execution.py" in step["run"])
    assert len(tests) == 2, "Browser acceptance no longer separates owner and fixed-port cases."

    for step in tests:
        assert step["env"]["FUZZY1337_RUN_PLAYWRIGHT_ACCEPTANCE"] == "1", (
            "Genuine browser acceptance may silently skip a missing engine or Linux capability."
        )
        assert "--no-cov" in step["run"] and "--junitxml=" in step["run"], (
            "Focused genuine acceptance lost bounded execution or retained result evidence."
        )

    assert "-n 2 --dist=load " in tests[0]["run"] and "-m 'not serial'" in tests[0]["run"], (
        "Independent browser owner cases lost bounded worker parallelism."
    )
    assert "-n 0" in tests[1]["run"] and "-m serial" in tests[1]["run"], (
        "The owned browser resource sink can race another fixed-port test."
    )


def test_NmapAcceptanceRequiresGenuinePinnedProviderAndProductOracle() -> None:
    """The genuine provider lane cannot silently skip its installed SDK/CLI acceptance."""

    steps = Workflow("nmap-acceptance.yml")["jobs"]["owned-loopback"]["steps"]
    acquisition = next(step["run"] for step in steps
                       if step.get("name") == "Acquire checksum-pinned official Nmap source")
    assert "https://nmap.org/dist/nmap-7.992.tar.bz2" in acquisition, (
        "Genuine acceptance lost the exact official source archive."
    )
    assert "0c12660eddbf7eabeff6996cb0c044a4eadf2bb0c6fbcb340d6cf72b1caee402" in acquisition, (
        "Genuine acceptance lost its independently verified upstream checksum."
    )
    selected = next(step for step in steps if step.get("name") == (
        "Execute genuine SDK and installed CLI against pytest-owned loopback only"))
    assert selected["env"]["FUZZY1337_RUN_NMAP_ACCEPTANCE"] == "1", (
        "Missing optional-provider opt-in would silently skip required genuine acceptance."
    )
    assert selected["env"]["F1337_NMAP_TEST_EXECUTABLE"].endswith(
        "/nmap-7.992/install/bin/nmap"
    ), "Genuine acceptance must select the installed pinned executable."
    assert "tests/functional/test_nmap_product_loopback.py" in selected["run"], (
        "Parser-only or synthetic tests cannot replace actual product acceptance."
    )
    assert "-n 2 --dist=load" in selected["run"], "Focused acceptance lost bounded workers."

    for step in steps:
        command = step.get("run", "")

        if command.startswith("python - <<'PY'\n"):
            source = command.removeprefix("python - <<'PY'\n").removesuffix("PY\n")
            compile(source, "nmap-acceptance.yml:" + step["name"], "exec")


def test_NativeImageProductAcceptanceRequiresActualIsolatedSdkAndInstalledCli() -> None:
    """Required native product execution keeps pinning, no egress and both independent cases."""

    job = Workflow("trivy-acceptance.yml")["jobs"]["owned-offline"]
    command = next(step["run"] for step in job["steps"] if step.get("name") == (
        "Run genuine adapter acceptance with no external network interface or route"))
    assert "sudo unshare --net -- setpriv" in command and "env -i PATH=/usr/bin:/bin" in command, (
        "Genuine image execution lost its separate no-egress namespace or cleared environment."
    )
    assert "FUZZY1337_RUN_NATIVE_IMAGE_PRODUCT_ACCEPTANCE=1" in command, (
        "Missing native product prerequisites could silently skip required acceptance."
    )

    for selected in ("BINARY", "CACHE", "PROVISIONING", "HOST_NETNS"):
        assert f"FUZZY1337_TRIVY_{selected}=" in command, (
            "Actual native product acceptance lost explicit pinned provisioning material."
        )

    assert "tests/integration/test_trivy_native.py" in command and (
        "tests/functional/test_native_image_product.py" in command
    ), "Original adapter acceptance and the independent real SDK/CLI oracle are both required."
    assert "-n 2 --dist=load" in command, (
        "Independent owned archive cases lost bounded parallelism."
    )
    upload = next(step for step in job["steps"] if step.get("name") == (
        "Preserve actual native provider evidence"))
    assert upload["if"] == "always()" and (
        "functional-evidence/native-image-product/" in upload["with"]["path"]
    ), "Actual acquired product evidence must survive failures as well as successes."


def test_NativeImageProtocolCheckpointRunsFocusedParallelCasesBeforeTheFinalGate() -> None:
    """Portable protocol diagnosis cannot launch or replace the ordinary complete gate."""

    job = Workflow("python-quality.yml")["jobs"]["quality"]
    steps = {step.get("name"): step for step in job["steps"]}
    feature = steps["Run focused native image protocol checks"]
    condition = " ".join(feature["if"].split())
    assert condition == (
        "github.event_name == 'pull_request' && github.event.pull_request.draft == true "
        "&& contains(github.event.pull_request.body, '[native-image-protocol-checkpoint]')"
    ), "Focused protocol checks must require the explicit draft checkpoint."
    assert "-n 2 --dist=loadscope" in feature["run"], "Protocol checks lost bounded parallelism."
    assert feature["timeout-minutes"] == 5 and "--timeout=30" in feature["run"], (
        "The focused protocol step or individual cases lost their finite diagnostic deadline."
    )
    assert "--max-worker-restart=0" in feature["run"] and "pytest -q -x " in feature["run"], (
        "A failed focused case must stop diagnosis without automatic worker replacement."
    )
    assert "--no-cov" in feature["run"] and "--junitxml=" in feature["run"], (
        "The feature checkpoint must retain results without impersonating full coverage."
    )
    selectors = (
        "tests/unit/test_native_image_material_worker.py",
        "tests/unit/test_native_image_observation.py",
        "tests/unit/test_native_image_bounded_capture.py",
        "tests/unit/test_native_image_control_identity.py",
        "tests/unit/test_native_image_policy.py",
        "tests/unit/test_native_image_policy_oracle.py",
        "tests/unit/test_native_image_workflow.py",
        "tests/contract/test_native_image_cli.py",
    )
    assert all(path in feature["run"] for path in selectors), (
        "Native protocol regression selection lost a reviewed producer or consumer."
    )
    root = Path(__file__).resolve().parents[2]
    assert all((root / path).is_file() for path in selectors), (
        "The focused protocol checkpoint names a missing test module."
    )
    full = steps["Run repository quality gate"]
    assert " ".join(full["if"].split()) == INTEGRATION_CONDITION, (
        "The complete gate must run unchanged at final readiness."
    )
    assert "1337-dev check" in full["run"], "Final integration no longer runs the complete gate."
