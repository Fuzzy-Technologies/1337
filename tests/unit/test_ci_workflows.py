# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Protect draft feedback, final integration triggers and required full-job execution."""

import ast
import json
import shlex
import subprocess
import sys
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
NATIVE_CONFIGURATION_FEATURE_CONDITION = (
    NATIVE_IMAGE_FEATURE_CONDITION + " || (github.event_name == 'pull_request' "
    "&& github.event.pull_request.draft == true "
    "&& contains(github.event.pull_request.body, "
    "'[native-configuration-compatibility-checkpoint]'))"
)
INSTALLED_CONFIGURATION_MATERIAL_CONDITION = (
    INTEGRATION_CONDITION + " || (github.event_name == 'pull_request' "
    "&& github.event.pull_request.draft == true "
    "&& contains(github.event.pull_request.body, '<!-- native-config-material-2115 -->'))"
)
NATIVE_PROTOCOL_FEATURE_CONDITION = (
    INTEGRATION_CONDITION + " || (github.event_name == 'pull_request' "
    "&& github.event.pull_request.draft == true "
    "&& contains(github.event.pull_request.body, '[native-image-protocol-checkpoint]'))"
)
PORTABLE_PROTOCOL_FEATURE_CONDITION = (
    NATIVE_PROTOCOL_FEATURE_CONDITION + " || (github.event_name == 'pull_request' "
    "&& github.event.pull_request.draft == true "
    "&& contains(github.event.pull_request.body, '[owned-response-protocol-checkpoint]'))"
)
BROWSER_FEATURE_CONDITION = (
    INTEGRATION_CONDITION + " || (github.event_name == 'pull_request' "
    "&& github.event.pull_request.draft == true "
    "&& contains(github.event.pull_request.body, '[browser-feature-checkpoint]'))"
)
NUCLEI_PREREQUISITE_CONDITION = (
    "github.event_name == 'pull_request' && github.event.pull_request.draft == true "
    "&& contains(github.event.pull_request.body, '[nuclei-prerequisite-checkpoint]')"
)
NUCLEI_PREREQUISITE_EXECUTION_CONDITION = (
    INTEGRATION_CONDITION + " || (" + NUCLEI_PREREQUISITE_CONDITION + ")"
)
EXTERNAL_NATIVE_FEATURE_CONDITION = (
    INTEGRATION_CONDITION + " || (github.event_name == 'pull_request' "
    "&& github.event.pull_request.draft == true "
    "&& contains(github.event.pull_request.body, '[native-external-checkpoint]'))"
    + " || (" + NUCLEI_PREREQUISITE_CONDITION + ")"
)
NATIVE_CRAWL_PORTABILITY_JOBS = {
    "native-crawl-windows-portability", "native-crawl-container-portability",
}
NATIVE_CRAWL_PORTABILITY_CONDITION = (
    "github.event_name == 'pull_request' && github.event.pull_request.draft == true "
    "&& contains(github.event.pull_request.body, '[native-crawl-portability-checkpoint]')"
)
OWNED_TRAVERSAL_RATE_JOB = "owned-traversal-rate-checkpoint"
OWNED_TRAVERSAL_RATE_CONDITION = (
    "github.event_name == 'pull_request' && github.event.pull_request.draft == true "
    "&& contains(github.event.pull_request.body, '[owned-traversal-rate-checkpoint]')"
)
NUCLEI_CONTRACT_WINDOWS_JOB = "nuclei-contract-windows-checkpoint"
NUCLEI_GOVERNED_PREREQUISITE_JOB = "nuclei-governed-prerequisite-checkpoint"
NUCLEI_APPLICATION_PRODUCT_JOB = "nuclei-application-product-checkpoint"


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

    if name == "python-quality.yml":
        expected |= NATIVE_CRAWL_PORTABILITY_JOBS | {
            OWNED_TRAVERSAL_RATE_JOB, NUCLEI_CONTRACT_WINDOWS_JOB,
            NUCLEI_GOVERNED_PREREQUISITE_JOB, NUCLEI_APPLICATION_PRODUCT_JOB}

    assert set(jobs) == expected, "The integration job inventory changed unexpectedly."
    assert workflow["permissions"] == {"contents": "read"}, "PR authority expanded."

    for job_id in WORKFLOWS[name]:
        job = jobs[job_id]
        condition = " ".join(str(job.get("if", "")).split())
        expected_condition = (
            EXTERNAL_NATIVE_FEATURE_CONDITION if job_id == "external-targets"
            else BROWSER_FEATURE_CONDITION if job_id == "browser-page-quality"
            else PORTABLE_PROTOCOL_FEATURE_CONDITION if job_id == "quality"
            else NATIVE_CONFIGURATION_FEATURE_CONDITION if name == "trivy-acceptance.yml"
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


def test_ReadyFullChecksStopOnFailureWithoutNarrowingTheirSuccessfulGate() -> None:
    """Full gates retain all checks and finite profile budgets with fail-fast execution."""

    jobs = Workflow("python-quality.yml")["jobs"]
    full = next(step for step in jobs["quality"]["steps"]
        if step.get("name") == "Run repository quality gate")
    assert " ".join(full["if"].split()) == INTEGRATION_CONDITION, (
        "Only existing Ready/push integration events may start the full Python check."
    )
    assert " ".join(full["run"].split()) == (
        "uv run --locked --extra dev 1337-dev check --fail-fast "
        "--suite-timeout ${{ matrix.suite_timeout_seconds || 600 }}"
    ), "The full matrix must preserve its complete gate and original platform suite budget."
    container = jobs["container-quality"]
    assert " ".join(container["if"].split()) == INTEGRATION_CONDITION, (
        "The complete container gate must retain its original Ready/push condition."
    )
    command = next(step["run"] for step in container["steps"]
        if step.get("name") == "Run container quality gate")
    assert " ".join(command.split()) == (
        'LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" '
        "docker compose --profile quality run --rm quality 1337-dev check --fail-fast "
        "--suite-timeout 900"
    ), "Container CI must keep mapped ownership and run the same complete supported check."
    assert container["timeout-minutes"] == 20, "Container CI must retain its finite job ceiling."

    for selected in (full["run"], command):
        assert not any(option in selected for option in (
            "--jobs", "--timeout", "--serial", "--no-cov", "tests/",
        )), (
            "Fail-fast cannot select a partial suite or change worker, deadline "
            "or coverage defaults."
        )


@pytest.mark.parametrize("job_id", sorted(NATIVE_CRAWL_PORTABILITY_JOBS))
def test_CrawlPortabilityJobsRequireDraftMarkerAndRetainTheirOwnEvidence(job_id: str) -> None:
    """Parallel focused portability diagnostics cannot replace a final ready integration job."""

    job = Workflow("python-quality.yml")["jobs"][job_id]
    assert " ".join(job["if"].split()) == NATIVE_CRAWL_PORTABILITY_CONDITION, (
        "Portability diagnosis must require the explicit draft-only marker."
    )
    assert "needs" not in job and job.get("continue-on-error", False) is False, (
        "Independent portability jobs must run concurrently and fail on real prerequisite errors."
    )
    assert 1 <= job["timeout-minutes"] <= 10, "Focused jobs must keep finite short ceilings."
    commands = [step["run"] for step in job["steps"] if "run" in step]
    assert not any("1337-dev check" in command for command in commands), (
        "A draft checkpoint cannot start the full repository gate."
    )
    upload, = (step for step in job["steps"] if "upload-artifact@" in step.get("uses", ""))
    assert upload["if"] == "always()" and set(upload["with"]["path"].splitlines()) == {
        "functional-evidence/native-crawl-portability/", "functional-evidence/native-crawl/",
    }, "JUnit and original owned-case evidence must survive both successful and failed diagnosis."
    assert upload["with"]["retention-days"] == 7, "Diagnostic retention must remain bounded."


def test_WindowsCrawlCheckpointSelectsOnlyTwoUnitsAndOneActualCancellation() -> None:
    """The Windows lane isolates loop fixtures and actual worker/socket settlement without mocks."""

    job = Workflow("python-quality.yml")["jobs"]["native-crawl-windows-portability"]
    assert job["runs-on"] == "windows-2022", "The diagnostic must exercise actual Windows."
    steps = {step["name"]: step for step in job["steps"]}
    assert steps["Select Python"]["with"]["python-version"] == "3.12", (
        "The diagnostic must use the failing shared Windows Python profile."
    )
    units = steps["Run focused Windows crawl units"]
    genuine = steps["Run one genuine Windows crawl cancellation case"]
    def Selectors(command: str) -> set[str]:
        """Read only declared pytest paths without executing their workflow shell command."""

        return {token for token in shlex.split(command) if token.startswith("tests/")}

    assert Selectors(units["run"]) == {
        "tests/unit/test_native_crawl_workflow.py", "tests/unit/test_native_crawl_commands.py",
    }, "The focused unit lane must not select unrelated suites."
    assert Selectors(genuine["run"]) == {
        "tests/functional/test_native_crawl_product.py::"
        "test_ActualSdkCallerCancellationSettlesOriginalWorkerAndSocket",
    }, "One actual installed SDK cancellation case is required, not a fake or parser-only test."
    assert "-n 2 --dist=loadscope" in units["run"] and "--timeout=30" in units["run"], (
        "Independent units must keep two bounded workers and short per-case deadlines."
    )
    assert "-n 0" in genuine["run"] and "--timeout=60" in genuine["run"], (
        "The single original socket/worker case keeps its own serial bounded owner."
    )

    for step in (units, genuine):
        assert "-o addopts='' --no-cov" in step["run"] and "--junitxml=" in step["run"], (
            "Partial checks must clear whole-suite coverage and retain their actual JUnit."
        )
        assert 1 <= step["timeout-minutes"] <= 3, "Focused steps need their original finite caps."


def test_TraversalRateCheckpointKeepsExactBoundedWindowsSelectionsAndOriginalEvidence() -> None:
    """The draft-only new regression lane preserves final gates and earlier portability owners."""

    jobs = Workflow("python-quality.yml")["jobs"]
    job = jobs[OWNED_TRAVERSAL_RATE_JOB]
    assert " ".join(job["if"].split()) == OWNED_TRAVERSAL_RATE_CONDITION, (
        "The new feature must require its own explicit marker and an actual draft PR."
    )
    assert job["runs-on"] == "windows-2022" and job["timeout-minutes"] == 8, (
        "The failing Windows profile needs one bounded eight-minute job."
    )
    assert "needs" not in job and job.get("continue-on-error", False) is False, (
        "Independent feature feedback must neither wait for nor soften other gates."
    )
    steps = {step["name"]: step for step in job["steps"]}
    prior = {step["name"]: step
        for step in jobs["native-crawl-windows-portability"]["steps"]}
    assert list(steps) == [
        "Check out source", "Select Python", "Install pinned uv",
        "Synchronize locked environment",
        "Run pure rate deadline and timeout classification regressions",
        "Run the two affected genuine traversal cases", "Preserve focused traversal rate evidence",
    ], "The feature lane must not acquire extra setup, test or full-gate commands."

    for name in ("Check out source", "Select Python", "Install pinned uv",
                 "Synchronize locked environment"):
        assert steps[name] == prior[name], "The checkpoint must reuse existing pinned setup."

    units = steps["Run pure rate deadline and timeout classification regressions"]
    genuine = steps["Run the two affected genuine traversal cases"]
    unit_tokens, genuine_tokens = shlex.split(units["run"]), shlex.split(genuine["run"])
    unit_selectors = {token for token in unit_tokens if token.startswith("tests/")}
    expected_rate = {
        f"tests/unit/{module}::test_RateGateRechecksOriginalDeadlineAfterEarlyWake[{outcome}]"
        for module in ("test_web_traversal.py", "test_native_crawl.py")
        for outcome in ("complete", "cancel", "budget")
    }
    assert unit_selectors == expected_rate | {
        "tests/unit/test_test_runner.py::"
        "test_IncidentalTimeoutTextCannotRelabelAnOrdinaryJunitFailure",
        "tests/unit/test_test_runner.py::"
        "test_PinnedPytestTimeoutFailureMessagesRetainCallAndFixtureExpiry",
    }, "Only the six new rate cases and the two new parser parameter groups may run."
    assert {token for token in genuine_tokens if token.startswith("tests/")} == {
        "tests/integration/test_web_traversal_execution.py::"
        "test_ActualAsyncTraversalPreservesOrderedCommitsAndIndependentOracle",
        "tests/functional/test_native_crawl_product.py::"
        "test_ActualSdkChangesFetchesAtSameSeedAndPreservesOrderedOriginalState",
    }, "Only the failed legacy interval and changed same-seed native case may execute."
    assert "-n 2 --dist=loadscope --max-worker-restart=0" in units["run"], (
        "Pure regression groups must keep two process workers without automatic replacement."
    )
    assert "-n 0" in genuine["run"] and "--timeout=90" in genuine["run"], (
        "Actual target lifecycles need their serial owner and finite per-case deadline."
    )
    assert units["timeout-minutes"] == 2 and genuine["timeout-minutes"] == 4, (
        "The two feature steps lost their independent short deadlines."
    )
    assert "--timeout=30" in units["run"], "Pure cases must retain their short deadline."

    for step in (units, genuine):
        assert "-o addopts='' --no-cov" in step["run"] and (
            "--timeout-method=thread" in step["run"]
        ), "Partial checks must clear full coverage and retain the portable timeout owner."
        assert "continue-on-error" not in step and "if" not in step, (
            "Feature regressions must retain ordinary failure and step-order semantics."
        )

    assert "--junitxml=functional-evidence/owned-traversal-rate/windows-pure.xml" in units["run"], (
        "Pure regression results must retain their own focused JUnit."
    )
    assert "--junitxml=functional-evidence/owned-traversal-rate/windows-genuine.xml" in (
        genuine["run"]
    ), "Actual traversal results must retain their own focused JUnit."
    upload = steps["Preserve focused traversal rate evidence"]
    assert upload["if"] == "always()" and upload["uses"] == (
        prior["Preserve focused Windows crawl evidence"]["uses"]
    ), "Failed feature checks still need the existing pinned upload action."
    assert set(upload["with"]["path"].splitlines()) == {
        "functional-evidence/owned-traversal-rate/", "functional-evidence/native-crawl/",
    } and upload["with"]["retention-days"] == 7, (
        "Focused JUnit and actual original acquisitions need bounded retained custody."
    )
    assert all("1337-dev check" not in step.get("run", "") for step in job["steps"]), (
        "The diagnostic must not launch or replace a full integration gate."
    )
    full = next(step for step in jobs["quality"]["steps"]
        if step.get("name") == "Run repository quality gate")
    assert " ".join(full["if"].split()) == INTEGRATION_CONDITION, (
        "The existing final Ready/push gate must remain unchanged."
    )


def test_ContainerCrawlCheckpointOverridesOnlyTheExistingQualityCommand() -> None:
    """The actual development image preserves mapped ownership and original source proof."""

    job = Workflow("python-quality.yml")["jobs"]["native-crawl-container-portability"]
    assert job["runs-on"] == "ubuntu-24.04", "The existing container host profile changed."
    steps = {step["name"]: step for step in job["steps"]}
    assert steps["Build existing development image"]["run"] == (
        "docker compose --profile quality build quality"
    ), "Feature diagnosis must build only the existing development service."
    selected = steps["Run one genuine crawl worker through quality override"]
    command = selected["run"]
    assert 'LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)"' in command and (
        "docker compose --profile quality run --rm quality pytest" in command
    ), "Container diagnosis must preserve original UID/GID mapping and quality entrypoint."
    selectors = {token for token in shlex.split(command) if token.startswith("tests/")}
    assert selectors == {
        "tests/integration/test_native_crawl_worker_execution.py::"
        "test_InstalledWorkerBindsActualGetBodyAndHandwrittenFrontier[positive-/entry]",
    }, "Only the actual installed positive seed worker is selected."
    assert "-n 0 -o addopts='' --no-cov" in command and "--timeout=60" in command and (
        "--junitxml=" in command
    ), "The single real worker needs bounded ordinary pytest and retained outcome evidence."
    assert "--entrypoint" not in command and "--privileged" not in command, (
        "The feature lane cannot replace or weaken the existing container boundary."
    )


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


@pytest.mark.parametrize(("step_name", "marker", "selectors"), (
    ("Run focused native image protocol checks", "native-image-protocol-checkpoint", (
        "tests/unit/test_native_image_material_worker.py",
        "tests/unit/test_native_image_observation.py",
        "tests/unit/test_native_image_bounded_capture.py",
        "tests/unit/test_native_image_control_identity.py",
        "tests/unit/test_native_image_policy.py",
        "tests/unit/test_native_image_policy_oracle.py",
        "tests/unit/test_native_image_workflow.py",
        "tests/contract/test_native_image_cli.py",
    )),
    ("Run focused owned response protocol checks", "owned-response-protocol-checkpoint", (
        "tests/unit/test_owned_response_capture.py",
        "tests/unit/test_owned_response_capture_worker.py",
        "tests/unit/test_owned_response_parent.py",
        "tests/unit/test_owned_response_workflow.py",
        "tests/unit/test_response_commands.py",
        "tests/unit/test_native_image_workflow.py",
        "tests/integration/test_owned_response_worker_execution.py",
    )),
))
def test_PortableProtocolCheckpointRunsFocusedParallelCasesBeforeTheFinalGate(
    step_name: str, marker: str, selectors: tuple[str, ...],
) -> None:
    """Portable protocol diagnosis cannot launch or replace the ordinary complete gate."""

    job = Workflow("python-quality.yml")["jobs"]["quality"]
    steps = {step.get("name"): step for step in job["steps"]}
    feature = steps[step_name]
    condition = " ".join(feature["if"].split())
    assert condition == (
        "github.event_name == 'pull_request' && github.event.pull_request.draft == true "
        f"&& contains(github.event.pull_request.body, '[{marker}]')"
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
    assert all(path in feature["run"] for path in selectors), (
        "Protocol regression selection lost a declared producer or consumer."
    )
    root = Path(__file__).resolve().parents[2]
    assert all((root / path).is_file() for path in selectors), (
        "The focused protocol checkpoint names a missing test module."
    )
    assert len({Path(path).stem for path in selectors}) == len(selectors), (
        "Portable checkpoint modules cannot share a prepend-mode pytest import name."
    )
    full = steps["Run repository quality gate"]
    assert " ".join(full["if"].split()) == INTEGRATION_CONDITION, (
        "The complete gate must run unchanged at final readiness."
    )
    assert "1337-dev check" in full["run"], "Final integration no longer runs the complete gate."
    assert full["env"]["FUZZY1337_RUN_OWNED_RESPONSE_PRODUCT_ACCEPTANCE"] == (
        "${{ runner.os == 'Linux' && '1' || '0' }}"
    ), "Linux final product acceptance must fail on unavailable acquisition prerequisites."


def test_NativeConfigurationCheckpointPreservesFullReadyGateAndSkipsImageDatabase() -> None:
    """The draft-only five-case proof stays separate from full native acceptance and DB material."""

    job = Workflow("trivy-acceptance.yml")["jobs"]["owned-offline"]
    environment = {key: " ".join(value.split()) for key, value in job["env"].items()}
    assert environment["CONFIGURATION_CHECKPOINT"] == (
        "${{ github.event_name == 'pull_request' && github.event.pull_request.draft == true "
        "&& contains(github.event.pull_request.body, "
        "'[native-configuration-compatibility-checkpoint]') && '1' || '0' }}"
    ), "Only an explicit draft config checkpoint may omit image acceptance and its database"
    assert environment["FULL_ACCEPTANCE"] == (
        "${{ (github.event_name == 'push' || github.event.pull_request.draft == false) "
        "&& '1' || '0' }}"
    ), "Ready and stable-push events must select every required native acceptance cohort"
    steps = {step["name"]: step for step in job["steps"]}
    provision = steps["Provision checksum-pinned Trivy and digest-pinned official database"]["run"]
    tree = ast.parse(provision.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
    database_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess" and node.func.attr == "run"]
    guarded_calls = [node for statement in tree.body if isinstance(statement, ast.If)
        and ast.unparse(statement.test) == "not configuration_only" for node in ast.walk(statement)
        if node in database_calls]
    assert len(database_calls) == len(guarded_calls) == 1 and (
        "--download-db-only" in ast.unparse(database_calls[0])
    ), "Config-only proof cannot download an image DB; full acceptance must retain provisioning"
    run = steps["Run genuine adapter acceptance with no external network interface or route"]["run"]
    assert 'if [[ "$CONFIGURATION_CHECKPOINT" == "1" ]]; then\n' in run and (
        'selected_tests=("${configuration_tests[@]}")' in run
        and 'elif [[ "$FULL_ACCEPTANCE" == "1" ]]; then\n' in run
        and 'selected_tests=("${original_tests[@]}" "${configuration_tests[@]}")' in run
        and 'selected_tests=("${original_tests[@]}")' in run
    ), "Draft config, full acceptance and existing image checkpoints lost their distinct selections"
    assert "configuration_tests=(tests/integration/test_trivy_native_configuration.py)" in run and (
        all(path in run for path in ("tests/integration/test_trivy_native.py",
            "tests/functional/test_native_image_product.py",
            "tests/functional/test_ci_native_image_product.py"))
    ), "The complete required native cohort cannot lose any original or new product interface"
    assert "FUZZY1337_RUN_NATIVE_CONFIGURATION_COMPATIBILITY=1" in run and (
        "--junitxml=functional-evidence/native-configuration-compatibility/pytest.xml" in run
        and "--no-cov -q -n 2 --dist=load" in run and "sudo unshare --net -- setpriv" in run
    ), "Genuine config proof requires declared prerequisites, actual JUnit and original no-egress"
    verify = steps["Require executed native configuration compatibility evidence"]
    assert verify["if"] == (
        "env.CONFIGURATION_CHECKPOINT == '1' || env.FULL_ACCEPTANCE == '1'"
    ) and all(token in verify["run"] for token in (
        'len(cases) != 5', '{"skipped", "failure", "error"}',
        '"selected-compatibility-assertions-passed"', '"embedded_loader"',
    )), "A successful process alone cannot hide skipped cases or missing original native evidence"
    upload = steps["Preserve actual native provider evidence"]
    assert upload["if"] == "always()" and (
        "functional-evidence/native-configuration-compatibility/" in upload["with"]["path"]
    ), "Native compatibility diagnostics must survive failed or incomplete genuine execution"


def test_ContentHeaderStaleModelCheckpointSelectsOnlyItsInstalledCasCase() -> None:
    """The draft-only CAS checkpoint retains one exact installed case and its original evidence."""

    workflow = Workflow("owned-content-header-acceptance.yml")
    jobs = workflow["jobs"]
    old_jobs = {"installed-content-header", "actor-denied-content-header",
        "policy-denied-content-header", "fixed-content-header", "body-decoy-content-header",
        "approval-denied-content-header"}
    assert set(jobs) == old_jobs | {"stale-model-cas-content-header",
        "post-model-ack-expiry-content-header", "ipv6-worker-content-header",
        "content-unit-windows-checkpoint"}, (
        "The finite workflow must retain six original jobs and separate CAS/expiry cases."
    )
    job = jobs["stale-model-cas-content-header"]
    marker = "[owned-content-header-stale-model-cas-checkpoint]"
    assert " ".join(job["if"].split()) == (
        "github.event_name == 'pull_request' && github.event.pull_request.draft == true "
        f"&& contains(github.event.pull_request.body, '{marker}')"
    ), "Only the explicit draft CAS marker may launch this one genuine case."
    assert all(marker not in jobs[name]["if"] for name in old_jobs), (
        "The CAS marker cannot enroll an already accepted cohort."
    )
    events = workflow.get("on", workflow.get(True))
    assert workflow["permissions"] == {"contents": "read"} and set(events) == {
        "pull_request", "push"} and events["push"] == {"branches": ["master"]}, (
        "Master jobs remain read-only; this checkpoint's exact draft condition is unchanged."
    )
    assert events["pull_request"] == {
        "branches": ["develop", "master"],
        "types": ["opened", "reopened", "synchronize", "ready_for_review",
            "converted_to_draft", "edited"],
    }, "Body-marker edits must trigger the checkpoint while retaining every existing PR event."
    assert job["runs-on"] == "ubuntu-24.04" and job["timeout-minutes"] == 6 and (
        job["env"] == {"FUZZY1337_RUN_OWNED_CONTENT_HEADER_ACCEPTANCE": "1"}
        and "strategy" not in job and not job.get("continue-on-error", False)
    ), "The one installed Linux case requires its opt-in and finite non-advisory job."
    steps = job["steps"]
    assert steps[0] == {**jobs["installed-content-header"]["steps"][0], "with": {
        "ref": "${{ github.event.pull_request.head.sha }}", "persist-credentials": False
    }} and (
        steps[1:4] == jobs["installed-content-header"]["steps"][1:4]
    ), (
        "The CAS job must reuse the reviewed head checkout and pinned locked provisioning."
    )
    checkout = steps[0]["with"]
    assert checkout["ref"] == "${{ github.event.pull_request.head.sha }}" and (
        checkout["persist-credentials"] is False
    ), "Only the selected original PR head may enter the installed-source proof."
    assert len(steps) == 7 and all(not step.get("continue-on-error", False) for step in steps), (
        "The finite checkpoint must not acquire extra execution or advisory evidence checks."
    )
    selector = (
        "tests/functional/test_owned_content_response_sdk_pipeline.py::"
        "test_InstalledFreshStaleModelRevisionContentHeaderPipelinePreservesAcquiredState"
    )
    junit = "functional-evidence/owned-content-header-stale-model-cas.xml"
    assert shlex.split(steps[4]["run"]) == [
        "uv", "run", "--locked", "--extra", "dev", "pytest", selector,
        "-q", "-x", "-n0", "--no-cov", "--timeout=150", "--timeout-method=thread",
        "--junitxml=" + junit,
    ] and steps[4]["timeout-minutes"] == 3, (
        "Exactly one serial installed CAS case must run with fail-fast, JUnit and fixed bounds."
    )
    assert shlex.split(steps[5]["run"]) == [
        "uv", "run", "--locked", "--extra", "dev", "python", "-m",
        "tests.contract.owned_content_response_ci_revision_evidence",
        junit, "functional-evidence/owned-content-sdk",
    ] and "if" not in steps[5], (
        "The existing original-evidence checker must reject missing, skipped or unbound CAS proof."
    )
    upload = steps[6]
    assert upload["if"] == "always()" and (
        upload["uses"] == jobs["installed-content-header"]["steps"][-1]["uses"]
        and upload["with"] == {
            "name": "owned-content-header-stale-model-cas-original-evidence",
            "path": junit + "\nfunctional-evidence/owned-content-sdk/\n",
            "retention-days": 14, "if-no-files-found": "error",
        }
    ), "The separate CAS artifact must retain original JUnit and pipeline bytes even on failure."


def test_ContentHeaderPostModelAckExpiryCheckpointSelectsOnlyItsInstalledPartialCase() -> None:
    """The separate draft-only expiry checkpoint proves only its one original partial outcome."""

    workflow = Workflow("owned-content-header-acceptance.yml")
    jobs = workflow["jobs"]
    job_id = "post-model-ack-expiry-content-header"
    old_jobs = {"installed-content-header", "actor-denied-content-header",
        "policy-denied-content-header", "fixed-content-header", "body-decoy-content-header",
        "approval-denied-content-header", "stale-model-cas-content-header"}
    assert set(jobs) == old_jobs | {job_id, "ipv6-worker-content-header",
        "content-unit-windows-checkpoint"}, (
        "Only one expiry job may extend the seven existing jobs."
    )
    job = jobs[job_id]
    marker = "[owned-content-header-post-model-ack-expiry-checkpoint]"
    assert " ".join(job["if"].split()) == (
        "github.event_name == 'pull_request' && github.event.pull_request.draft == true "
        f"&& contains(github.event.pull_request.body, '{marker}')"
    ), "Only the explicit draft expiry marker may launch this one installed partial-state case."
    assert all(marker not in jobs[name]["if"] for name in old_jobs), (
        "The expiry marker cannot reenroll an already accepted case."
    )
    events = workflow.get("on", workflow.get(True))
    assert workflow["permissions"] == {"contents": "read"} and set(events) == {
        "pull_request", "push"} and events["push"] == {"branches": ["master"]}, (
        "Canonical master jobs remain read-only; this expiry job remains behind its draft guard."
    )
    assert events["pull_request"] == {"branches": ["develop", "master"], "types": [
        "opened", "reopened", "synchronize", "ready_for_review", "converted_to_draft", "edited",
    ]}, "The expiry marker must retain supported body-edit admission and all original PR events."
    assert job["runs-on"] == "ubuntu-24.04" and job["timeout-minutes"] == 6 and (
        job["env"] == {"FUZZY1337_RUN_OWNED_CONTENT_HEADER_ACCEPTANCE": "1"}
        and "strategy" not in job and not job.get("continue-on-error", False)
    ), "The single installed expiry fixture requires bounded, opted-in, non-advisory Linux work."
    steps = job["steps"]
    assert len(steps) == 7 and all(not step.get("continue-on-error", False) for step in steps), (
        "Expiry execution cannot acquire extra children or advisory evidence checks."
    )
    assert steps[0] == {**jobs["installed-content-header"]["steps"][0], "with": {
        "ref": "${{ github.event.pull_request.head.sha }}", "persist-credentials": False
    }} and steps[1:4] == jobs["installed-content-header"]["steps"][1:4], (
        "Expiry must reuse the original exact-head checkout and pinned locked provisioning."
    )
    assert steps[0]["with"] == {"ref": "${{ github.event.pull_request.head.sha }}",
        "persist-credentials": False}, "Only the selected PR head may enter the installed proof."
    selector = (
        "tests/functional/test_owned_content_response_sdk_pipeline.py::"
        "test_InstalledFreshPostModelAckExpiryContentHeaderPipelinePreservesPartialState"
    )
    junit = "functional-evidence/owned-content-header-post-model-ack-expiry.xml"
    assert shlex.split(steps[4]["run"]) == [
        "uv", "run", "--locked", "--extra", "dev", "pytest", selector,
        "-q", "-x", "-n0", "--no-cov", "--timeout=150", "--timeout-method=thread",
        "--junitxml=" + junit,
    ] and steps[4]["timeout-minutes"] == 3, (
        "Exactly one serial expiry case must run with fail-fast, original JUnit and fixed limits."
    )
    assert shlex.split(steps[5]["run"]) == [
        "uv", "run", "--locked", "--extra", "dev", "python", "-m",
        "tests.contract.owned_content_response_ci_expiry_evidence",
        junit, "functional-evidence/owned-content-sdk",
    ] and "if" not in steps[5], (
        "The unchanged strict checker must require original ACK/expiry and exact partial state."
    )
    upload = steps[6]
    assert upload["if"] == "always()" and (
        upload["uses"] == jobs["installed-content-header"]["steps"][-1]["uses"]
        and upload["with"] == {
            "name": "owned-content-header-post-model-ack-expiry-original-evidence",
            "path": junit + "\nfunctional-evidence/owned-content-sdk/\n",
            "retention-days": 14, "if-no-files-found": "error",
        }
    ), "Original expiry JUnit, installation, raw processes and custody must survive failed checks."


def test_ContentHeaderIpv6WorkerCheckpointSelectsOnlyItsInstalledWorkerCase() -> None:
    """Keep one draft-only IPv6 installed-worker case separate from SDK and Finding acceptance."""

    workflow = Workflow("owned-content-header-acceptance.yml")
    jobs = workflow["jobs"]
    job_id = "ipv6-worker-content-header"
    old_jobs = {"installed-content-header", "actor-denied-content-header",
        "policy-denied-content-header", "fixed-content-header", "body-decoy-content-header",
        "approval-denied-content-header", "stale-model-cas-content-header",
        "post-model-ack-expiry-content-header"}
    assert set(jobs) == old_jobs | {job_id, "content-unit-windows-checkpoint"}, (
        "Only one worker-only IPv6 job may extend the eight existing finite cases."
    )
    job = jobs[job_id]
    marker = "[owned-content-header-ipv6-worker-checkpoint]"
    assert " ".join(job["if"].split()) == (
        "github.event_name == 'pull_request' && github.event.pull_request.draft == true "
        f"&& contains(github.event.pull_request.body, '{marker}')"
    ), "Only this draft worker marker may enroll IPv6; ready behavior stays exact."
    assert all(marker not in jobs[name]["if"] for name in old_jobs), (
        "The worker-only IPv6 marker cannot reenroll any accepted case."
    )
    events = workflow.get("on", workflow.get(True))
    assert workflow["permissions"] == {"contents": "read"} and set(events) == {
        "pull_request", "push"} and events["push"] == {"branches": ["master"]}, (
        "Canonical master jobs remain read-only; this IPv6 worker remains behind its draft guard."
    )
    assert events["pull_request"] == {"branches": ["develop", "master"], "types": [
        "opened", "reopened", "synchronize", "ready_for_review", "converted_to_draft", "edited",
    ]}, "The worker marker requires supported body-edit admission and every original PR event."
    assert set(job) == {"if", "name", "runs-on", "timeout-minutes", "env", "steps"} and (
        job["name"] == "Installed IPv6 content worker only with original wire and settled owners"
        and job["runs-on"] == "ubuntu-24.04" and job["timeout-minutes"] == 6
        and job["env"] == {"FUZZY1337_RUN_OWNED_CONTENT_HEADER_ACCEPTANCE": "1"}
    ), "The installed worker needs bounded opted-in Linux work without extra job controls."
    steps = job["steps"]
    assert len(steps) == 7 and all(not step.get("continue-on-error", False) for step in steps), (
        "Worker enrollment cannot add runtime children or advisory checks."
    )
    assert steps[0] == {**jobs["installed-content-header"]["steps"][0], "with": {
        "ref": "${{ github.event.pull_request.head.sha }}", "persist-credentials": False
    }} and steps[1:4] == jobs["installed-content-header"]["steps"][1:4], (
        "The worker must reuse original exact-head checkout and pinned locked provisioning."
    )
    assert steps[0]["with"] == {"ref": "${{ github.event.pull_request.head.sha }}",
        "persist-credentials": False}, "Only the selected reviewed PR head enters installed proof."
    selector = (
        "tests/functional/test_owned_content_response_sdk_pipeline.py::"
        "test_InstalledMissingHeaderContentWorkerIpv6RetainsOriginalsAndSettledOwners"
    )
    junit = "functional-evidence/owned-content-header-ipv6-worker.xml"
    assert shlex.split(steps[4]["run"]) == [
        "uv", "run", "--locked", "--extra", "dev", "pytest", selector,
        "-q", "-x", "-n0", "--no-cov", "--timeout=150", "--timeout-method=thread",
        "--junitxml=" + junit,
    ] and steps[4]["timeout-minutes"] == 3 and "if" not in steps[4], (
        "Exactly one serial IPv6 worker must run with fixed limits and original JUnit; no skips."
    )
    assert shlex.split(steps[5]["run"]) == [
        "uv", "run", "--locked", "--extra", "dev", "python", "-m",
        "tests.contract.owned_content_response_ci_ipv6_worker_evidence",
        junit, "functional-evidence/owned-content-sdk",
    ] and "if" not in steps[5], (
        "The unchanged original checker must require installation wire peer and cleanup facts only."
    )
    upload = steps[6]
    assert upload["if"] == "always()" and (
        upload["uses"] == jobs["installed-content-header"]["steps"][-1]["uses"]
        and upload["with"] == {
            "name": "owned-content-header-ipv6-worker-original-evidence",
            "path": junit + "\nfunctional-evidence/owned-content-sdk/\n",
            "retention-days": 14, "if-no-files-found": "error",
        }
    ), "Original IPv6 worker JUnit streams and source owners must survive failed execution/checks."


def test_ContentUnitWindowsCheckpointRequiresOnlyExplicitDraftAdmission() -> None:
    """Keep focused Windows diagnostics separate from installed cases and final full gates."""

    workflow = Workflow("owned-content-header-acceptance.yml")
    job_id = "content-unit-windows-checkpoint"
    job = workflow["jobs"][job_id]
    marker = "[owned-content-unit-windows-checkpoint]"
    assert " ".join(job["if"].split()) == (
        "github.event_name == 'pull_request' && github.event.pull_request.draft == true "
        f"&& contains(github.event.pull_request.body, '{marker}')"
    ), "Only the explicit draft Windows marker may launch focused unit diagnostics."
    assert all(marker not in value["if"] for name, value in workflow["jobs"].items()
        if name != job_id), "The Windows marker cannot reenroll any installed acceptance case."
    assert set(job) == {"if", "name", "runs-on", "timeout-minutes", "steps"} and (
        job["runs-on"] == "windows-2022" and job["timeout-minutes"] == 8
    ), "Focused Windows diagnostics require one bounded non-advisory runner without opt-in effects."
    steps = job["steps"]
    assert len(steps) == 7 and all(not step.get("continue-on-error", False) for step in steps), (
        "Focused units require setup, one execution, a strict gate and always-retained JUnit."
    )
    original = workflow["jobs"]["installed-content-header"]["steps"]
    assert steps[0] == {**original[0], "with": {
        "ref": "${{ github.event.pull_request.head.sha }}", "persist-credentials": False
    }} and steps[1]["uses"] == original[1]["uses"] and (
        steps[1]["with"] == {"python-version": "3.12"} and steps[2] == original[2]
        and steps[3]["run"] == "uv sync --locked --extra dev --python 3.12"
    ), "Windows diagnostics must keep exact-head checkout and pinned locked Python provisioning."
    junit = "functional-evidence/owned-content-unit-windows.xml"
    assert shlex.split(steps[4]["run"]) == [
        "uv", "run", "--locked", "--extra", "dev", "pytest", "tests/unit", "-k",
        "owned_content_response or native_content_response_header_workflow",
        "-q", "-n2", "--no-cov", "--junitxml=" + junit,
    ] and steps[4]["timeout-minutes"] == 3 and "if" not in steps[4], (
        "The bounded unit selection must report every failure without fail-fast or fullgate."
    )
    assert steps[5]["shell"] == "python" and "if" not in steps[5], (
        "The original JUnit gate must run in the selected Python without a platform shell."
    )
    assert steps[6]["if"] == "always()" and steps[6]["uses"] == original[-1]["uses"] and (
        steps[6]["with"] == {"name": "owned-content-unit-windows-original-evidence",
            "path": junit, "retention-days": 14, "if-no-files-found": "error"}
    ), "Original Windows unit results must survive both success and failure."


@pytest.mark.parametrize("case_xml, accepted", [
    ('<testcase name="passed"/>', True),
    ('<testcase name="passed"/><testcase name="skip"><skipped/></testcase>', True),
    ("", False),
    ('<testcase name="skip"><skipped/></testcase>', False),
    ('<testcase name="failed"><failure/></testcase>', False),
    ('<testcase name="errored"><error/></testcase>', False),
], ids=("executed", "executed-with-skip", "empty", "only-skips", "failure", "error"))
def test_ContentUnitWindowsGateRejectsMissingExecutionAndFailedCases(
    tmp_path: Path, case_xml: str, accepted: bool,
) -> None:
    """Exercise the actual read-only JUnit gate with labeled synthetic unit outcomes.

    Args:
        tmp_path: Isolated pytest-owned result directory; no scanner or external tool runs.
        case_xml: Explicit synthetic testcase fragments with completed or refused outcomes.
        accepted: Whether actual successful execution exists without failures or errors.
    """

    job = Workflow("owned-content-header-acceptance.yml")["jobs"]["content-unit-windows-checkpoint"]
    script = job["steps"][5]["run"]
    path = tmp_path / "functional-evidence/owned-content-unit-windows.xml"
    path.parent.mkdir()
    path.write_text("<testsuites><testsuite>" + case_xml + "</testsuite></testsuites>",
                    encoding="utf-8")
    result = subprocess.run([sys.executable, "-c", script], cwd=tmp_path,
                            capture_output=True, text=True, timeout=10, check=False)
    assert (result.returncode == 0) is accepted, (
        "Only original-shaped JUnit with actual executed cases and no failures/errors may pass."
    )


def test_InstalledConfigurationMaterialWorkflowRequiresExplicitAdmission() -> None:
    """Keep the dedicated helper cohort limited to readiness and its explicit draft marker."""

    workflow = Workflow("native-configuration-material.yml")
    assert set(workflow["jobs"]) == {"installed-read-helper"}, (
        "Installed configuration source must declare exactly its one dedicated read-helper job"
    )
    job = workflow["jobs"]["installed-read-helper"]
    assert " ".join(job["if"].split()) == INSTALLED_CONFIGURATION_MATERIAL_CONDITION, (
        "Installed helper job must require readiness or its exact dedicated draft marker"
    )
    assert job["runs-on"] == "ubuntu-24.04" and job["timeout-minutes"] == 15, (
        "Installed helper source must retain one bounded ordinary Linux x86_64 lane"
    )
    steps = {step["name"]: step for step in job["steps"]}
    assert steps["Check out exact source"]["with"]["ref"] == job["env"]["MATERIAL_SOURCE_SHA"] == (
        "${{ github.event.pull_request.head.sha || github.sha }}"
    ), "Installed acceptance must build the exact proposed head rather than an unrelated revision"
    assert all(1 <= step["timeout-minutes"] <= 5 for step in steps.values()), (
        "Each installed helper preparation, execution and retention step needs its finite deadline"
    )
    prepare = steps["Build installed wheel and provision read-only pinned input"]["run"]
    assert "native_configuration_material_acceptance.py prepare" in prepare and (
        '--repository "$GITHUB_WORKSPACE"' in prepare
        and '--root "$RUNNER_TEMP/native-configuration-material"' in prepare
    ), "Installed helper preparation must build the exact checkout into a fresh outside environment"
    run = steps["Run four installed helper cases with loopback only"]["run"]
    assert "sudo unshare --net -- setpriv" in run and "env -i" in run and (
        'cd "$lane/run"' in run
        and '"$lane/environment/bin/python" -I "$lane/run/material_acceptance.py"' in run
        and 'FUZZY1337_CONFIGURATION_MATERIAL_CONTEXT="$lane/context.json"' in run
        and "--clear-groups" in run
    ), "Installed cases must retain the isolated interpreter and ordinary loopback-only owner"
    source = (Path(__file__).resolve().parents[2] / ".github/workflows/"
              "native-configuration-material.yml").read_text()
    assert all(token not in source for token in ("checkpoint]", "--version", "--download-db-only",
        "test_trivy_native", "1337-dev check", "FUZZY1337_RUN_NATIVE_")), (
        "Dedicated lane must exclude legacy checkpoints, providers, databases and previous cohorts"
    )
    verify = steps["Require four executed cases and original bounded receipts"]["run"]
    assert "native_configuration_material_acceptance.py verify" in verify, (
        "Dedicated source must require the exact four-case original receipt verifier"
    )
    upload = steps["Preserve bounded helper metadata and original streams"]
    assert upload["if"] == "always()" and upload["with"]["path"] == (
        "${{ runner.temp }}/native-configuration-material/evidence/"
    ), "Only bounded original metadata and streams may upload, including failed-case diagnostics"


@pytest.mark.parametrize("draft,body,expected", (
    (True, "Ordinary draft work", False),
    (True, "<!-- native-config-material-2115 -->", True),
    (False, "Ready for review", True),
), ids=("draft-without-marker", "draft-with-exact-marker", "ready"))
def test_InstalledConfigurationAdmissionUsesActualWorkflowCondition(draft, body, expected) -> None:
    """Interpret only the real condition's closed grammar to prove its three PR admission states."""

    condition = Workflow("native-configuration-material.yml")["jobs"]["installed-read-helper"]["if"]
    tree = ast.parse(condition.replace("||", " or ").replace("&&", " and "), mode="eval")
    context = {"github.event_name": "pull_request", "github.event.pull_request.draft": draft,
               "github.event.pull_request.body": body}

    def Admit(node):
        """Interpret only equality, boolean composition and substring checks without execution."""

        if isinstance(node, ast.Expression):
            return Admit(node.body)

        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            values = [Admit(value) for value in node.values]

            return all(values) if isinstance(node.op, ast.And) else any(values)

        if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1 and (
            isinstance(node.ops[0], ast.Eq)
        ):
            return Admit(node.left) == Admit(node.comparators[0])

        if isinstance(node, ast.Attribute) and ast.unparse(node) in context:
            return context[ast.unparse(node)]

        if isinstance(node, ast.Name) and node.id in {"true", "false"}:
            return node.id == "true"

        if isinstance(node, ast.Constant) and type(node.value) is str:
            return node.value

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and (
            node.func.id == "contains" and len(node.args) == 2 and not node.keywords
        ):
            haystack, needle = (Admit(argument) for argument in node.args)

            if type(haystack) is not str or type(needle) is not str:
                raise ValueError("Admission contains requires two literal or contextual strings")

            return needle in haystack

        raise ValueError("Workflow admission escaped its closed test grammar")

    assert Admit(tree) is expected, (
        "Actual dedicated workflow admission must match the explicit draft/readiness state"
    )


def test_InstalledConfigurationWorkersRegisterRealIsolationAndPreserveFixedSelection() -> None:
    """Register the actual pytest hook and inspect real execnet argv without starting workers."""

    import execnet
    import xdist.newhooks
    from _pytest.config import PytestPluginManager
    from execnet.gateway_io import popen_args

    from tests.fixtures.trivy import native_configuration_material_acceptance as helper

    interpreter = "/owned installed/environment/bin/python"
    plugin = helper.InstalledWorkers(interpreter)
    manager = PytestPluginManager()
    manager.add_hookspecs(xdist.newhooks)
    manager.register(plugin)
    specs = [execnet.XSpec("popen"), execnet.XSpec("popen")]
    manager.hook.pytest_xdist_setupnodes(config=None, specs=specs)
    assert all(popen_args(spec)[:3] == [interpreter, "-I", "-u"] for spec in specs), (
        "The actual registered callback must isolate both genuine execnet interpreter commands"
    )

    with pytest.raises(ValueError, match="exactly two fresh local workers"):
        manager.hook.pytest_xdist_setupnodes(config=None, specs=[execnet.XSpec("popen")])

    tree = ast.parse(Path(helper.__file__).read_text())
    run = next(node for node in tree.body
               if isinstance(node, ast.FunctionDef) and node.name == "Run")
    tokens = ast.unparse(run)
    assert all(token in tokens for token in ("test_native_configuration_material_execution.py",
        "--no-cov", "'2'", "--dist=loadscope", "--timeout=120", "--max-worker-restart=0",
        "--junitxml=")), (
        "Installed source must preserve the four-case module, bounded workers and actual JUnit"
    )
    assert len(helper.CASE_IDS) == 4 and len(set(helper.CASE_IDS)) == 4, (
        "Required installed helper report identities must remain exactly four unique cases"
    )


@pytest.mark.parametrize("mutation", ("missing-case", "skipped", "error", "stale-head"))
def test_InstalledConfigurationReportGateRejectsIncompleteOrUnexecutedCases(
    tmp_path, monkeypatch, mutation,
) -> None:
    """Reject synthetic missing, skipped, errored and stale JUnit before any acceptance claim."""

    from tests.fixtures.trivy import native_configuration_material_acceptance as helper

    root = tmp_path / "report"
    evidence = root / "evidence"
    evidence.mkdir(parents=True)
    (root / "context.json").write_text(json.dumps({"commit": "a" * 40}))
    monkeypatch.setenv("MATERIAL_SOURCE_SHA", "b" * 40 if mutation == "stale-head" else "a" * 40)
    cases = helper.CASE_IDS[:-1] if mutation == "missing-case" else helper.CASE_IDS
    child = "<skipped/>" if mutation == "skipped" else "<error/>" if mutation == "error" else ""
    xml = "<testsuites><testsuite>" + "".join(
        f'<testcase name="test_InstalledMaterialLifecycle[{case_id}]">{child}</testcase>'
        for case_id in cases) + "</testsuite></testsuites>"
    (evidence / "pytest.xml").write_text(xml)

    with pytest.raises(ValueError, match="current workflow revision|without skips/errors"):
        helper.Verify(root)


def test_NucleiPrerequisiteCheckpointSuppressesEveryOldExternalMode() -> None:
    """Keep draft prerequisite-only admission separate even when legacy markers are combined."""

    workflow = Workflow("python-quality.yml")
    job = workflow["jobs"]["external-targets"]
    mode = NUCLEI_PREREQUISITE_CONDITION
    assert " ".join(job["if"].split()) == EXTERNAL_NATIVE_FEATURE_CONDITION, (
        "Only the original final/native admission and explicit prerequisite mode may run."
    )
    assert job["timeout-minutes"] == 61 and job["runs-on"] == "ubuntu-24.04" and (
        job["env"] == {"FUZZY1337_EXTERNAL_TARGETS": "juice-shop",
            "FUZZY1337_EXTERNAL_NATIVE_BENCHMARK": "juice-shop"}
        and "strategy" not in job and not job.get("continue-on-error", False)
    ), "Final external acceptance must retain prior windows plus the bounded new six-case step."
    steps = {step["name"]: step for step in job["steps"]}
    assert len(steps) == len(job["steps"]) == 12, (
        "The prior ten steps must remain alongside the two final comparative steps."
    )
    checkout = steps["Check out source"]
    assert checkout["with"] == {"persist-credentials": False,
        "ref": ("${{ github.event_name == 'pull_request' "
            "&& github.event.pull_request.head.sha || github.sha }}"),
        "fetch-depth": 0}, (
        "Final and draft prerequisite acceptance require exact source and accepted-base ancestry."
    )
    old = {
        "Execute pinned target through pytest": INTEGRATION_CONDITION,
        "Execute installed native scanner against three fresh pinned targets": (
            "github.event_name != 'pull_request' || github.event.pull_request.draft == false "
            "|| !contains(github.event.pull_request.body, '[native-external-metrics-diagnostic]')"),
        "Capture one separate fresh-target metrics diagnostic": (
            "github.event_name == 'pull_request' && github.event.pull_request.draft == true "
            "&& contains(github.event.pull_request.body, '[native-external-metrics-diagnostic]')"),
    }

    for name, condition in old.items():
        assert " ".join(steps[name]["if"].split()) == f"!({mode}) && ({condition})", (
            "Prerequisite mode must suppress all old work, including mixed-marker bodies."
        )

    selected = steps["Execute one target-free installed Nuclei prerequisite"]
    gate = steps["Require original target-free Nuclei prerequisite evidence"]
    assert all(" ".join(step["if"].split()) == NUCLEI_PREREQUISITE_EXECUTION_CONDITION
        and not step.get(
        "continue-on-error", False) for step in (selected, gate)), (
        "Final readiness must execute and verify prerequisites; "
        "draft-only enrollment stays explicit."
    )
    selector = ("tests/functional/test_external_nuclei_prerequisites.py::"
        "test_InstalledImageRunsOfflineExactNucleiPrerequisites")
    assert shlex.split(selected["run"]) == [
        "uv", "run", "--locked", "--extra", "dev", "pytest", selector,
        "-o", "addopts=", "--no-cov", "-n0", "-v", "--timeout=600",
        "--timeout-method=signal", "--junitxml=functional-evidence/nuclei-prerequisites.xml",
    ] and selected["env"] == {"FUZZY1337_EXTERNAL_NUCLEI_PREREQUISITES": "linux-amd64"}, (
        "Exactly one serial explicit prerequisite may run; no target/case matrix is enrolled."
    )
    assert selected["timeout-minutes"] == 17 and gate["timeout-minutes"] == 1, (
        "A ten-minute signal timeout leaves seven minutes for host cleanup within its step."
    )
    assert gate["env"] == {"NUCLEI_PREREQUISITE_SOURCE_HEAD": (
        "${{ github.event_name == 'pull_request' "
        "&& github.event.pull_request.head.sha || github.sha }}")}, (
        "Gate must bind the exact PR head or stable push revision."
    )
    assert gate["run"].startswith('source_identity="$(git rev-parse HEAD HEAD^{tree})"\n'), (
        "Only read-only checkout metadata may supplement the original source receipt."
    )
    upload = steps["Preserve external target evidence"]
    assert upload["if"] == "always()" and upload["with"] == {
        "name": "external-juice-shop", "path": "functional-evidence/external-juice-shop/\n"
            "functional-evidence/external-native-benchmark/\n"
            "functional-evidence/external-nuclei-prerequisites/\n"
            "functional-evidence/nuclei-prerequisites.xml\n"
            "functional-evidence/nuclei-comparison.xml\n",
        "if-no-files-found": "error", "retention-days": 14,
    }, "The existing always upload must retain both old evidence paths and new originals."


def test_NucleiContractWindowsCheckpointRequiresOnlyExplicitDraftAdmission() -> None:
    """Keep inert Windows contracts separate from real prerequisites, targets and full gates."""

    workflow = Workflow("python-quality.yml")
    jobs = workflow["jobs"]
    job = jobs[NUCLEI_CONTRACT_WINDOWS_JOB]
    marker = "[nuclei-contract-windows-checkpoint]"
    assert " ".join(job["if"].split()) == (
        "github.event_name == 'pull_request' && github.event.pull_request.draft == true "
        f"&& contains(github.event.pull_request.body, '{marker}')"
    ), "Only the explicit draft contract marker may launch this Windows checkpoint."
    assert all(marker not in other.get("if", "") for name, other in jobs.items()
        if name != NUCLEI_CONTRACT_WINDOWS_JOB), (
        "The contract checkpoint must not enroll any target, installed prerequisite or full gate")
    assert set(job) == {"if", "name", "runs-on", "timeout-minutes", "steps"} and (
        job["runs-on"] == "windows-2022" and job["timeout-minutes"] == 8
    ), "The Windows contract checkpoint must retain one bounded non-advisory job."
    steps = job["steps"]
    assert len(steps) == 7 and all(not step.get("continue-on-error", False) for step in steps), (
        "Exactly one contract execution, its original-result gate and evidence upload are required")
    original = jobs["quality"]["steps"]
    assert steps[0]["uses"] == original[0]["uses"] and steps[0]["with"] == {
        "ref": "${{ github.event.pull_request.head.sha }}", "persist-credentials": False,
    }, "Contract results must bind the exact PR head through pinned credential-free checkout."
    assert steps[1]["uses"] == original[1]["uses"] and steps[1]["with"] == {
        "python-version": "3.12"} and steps[2] == original[2] and steps[3]["run"] == (
        "uv sync --locked --extra dev --python 3.12"
    ), "The checkpoint must retain pinned Python provisioning and the locked development extra."
    junit = "functional-evidence/nuclei-contract-windows.xml"
    assert shlex.split(steps[4]["run"]) == [
        "uv", "run", "--locked", "--extra", "dev", "pytest", "tests/contract", "-k",
        "external_nuclei or external_native_benchmark or external_benchmark or external_targets",
        "-q", "-n2", "--no-cov", "--junitxml=" + junit,
    ] and steps[4]["timeout-minutes"] == 3 and "if" not in steps[4], (
        "One bounded contract selection must report every failure without fail-fast or fullsuite")
    assert steps[5]["shell"] == "python" and "if" not in steps[5], (
        "The original JUnit gate must run with the selected Python after successful execution")
    assert steps[6]["if"] == "always()" and steps[6]["uses"] == original[-1]["uses"] and (
        steps[6]["with"] == {"name": "nuclei-contract-windows-original-evidence",
            "path": junit, "retention-days": 14, "if-no-files-found": "error"}
    ), "Original Windows contract results must survive both success and failed execution."


@pytest.mark.parametrize("case_xml, accepted", [
    ('<testcase name="passed"/>', True),
    ('<testcase name="passed"/><testcase name="skip"><skipped/></testcase>', True),
    ("", False),
    ('<testcase name="skip"><skipped/></testcase>', False),
    ('<testcase name="failed"><failure/></testcase>', False),
    ('<testcase name="errored"><error/></testcase>', False),
    (None, False),
], ids=["executed", "executed-with-skip", "empty", "only-skips", "failure", "error", "missing"])
def test_NucleiContractWindowsGateRequiresExecutedOriginalCasesWithoutFailure(
    tmp_path: Path, case_xml: str | None, accepted: bool,
) -> None:
    """Exercise the exact read-only gate against marked synthetic JUnit results only.

    Args:
        tmp_path: Explicit test-owned evidence directory without a target or scanner.
        case_xml: Synthetic original-shaped testcase fragments, or None for missing evidence.
        accepted: Whether actual successful case execution exists without failures or errors.
    """

    job = Workflow("python-quality.yml")["jobs"][NUCLEI_CONTRACT_WINDOWS_JOB]
    path = tmp_path / "functional-evidence/nuclei-contract-windows.xml"

    if case_xml is not None:
        path.parent.mkdir()
        path.write_text("<testsuites><testsuite>" + case_xml + "</testsuite></testsuites>",
            encoding="utf-8")

    result = subprocess.run([sys.executable, "-c", job["steps"][5]["run"]], cwd=tmp_path,
        capture_output=True, text=True, timeout=10, check=False)
    assert (result.returncode == 0) is accepted, (
        "Only original-shaped executed contract cases without failures/errors may satisfy the gate")


@pytest.mark.parametrize("mutation", [None, "junit-missing", "skip", "hidden-skip", "wrong-case",
    "wrong-class", "failed-case", "multiple-cases", "no-run", "multiple-runs", "host-missing",
    "host-failed", "head", "tree", "checkout", "image", "iid", "container", "cleanup",
    "tag", "target", "home-claim", "imported-target", "imported-head", "version-argv",
    "validation-argv", "process", "empty-version", "wrong-version", "empty-validation",
    "stderr-missing"], ids=lambda value: "complete" if value is None else value)
def test_NucleiPrerequisiteGateRejectsSyntheticIncompleteOrForeignEvidence(
    tmp_path: Path, mutation: str | None,
) -> None:
    """Execute only the read-only stdlib gate against labeled synthetic original-shaped files.

    Args:
        tmp_path: Disposable unit root with no Docker, Git harness or provider activity.
        mutation: Short explicit identifier for one rejected metadata/original substitution.
    """

    job = Workflow("python-quality.yml")["jobs"]["external-targets"]
    step = next(row for row in job["steps"] if row["name"] == (
        "Require original target-free Nuclei prerequisite evidence"))
    script = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    tree = ast.parse(script)
    imports = {node.names[0].name if isinstance(node, ast.Import) else node.module
        for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))}
    assert imports == {"json", "re", "sys", "pathlib", "xml.etree"}, (
        "Evidence gate may only read originals with stdlib; no host/helper/runtime imports."
    )
    script_path = tmp_path / "read_only_gate.py"
    script_path.write_text(script)
    head, source_tree, owner = "a" * 40, "b" * 40, "c" * 32
    base_id, image_id, container_id = "sha256:" + "d" * 64, "sha256:" + "e" * 64, "f" * 64
    run = "functional-evidence/external-nuclei-prerequisites/run-" + owner[:12] + "/"
    host = {"status": "completed-prerequisites", "source_revision": head,
        "source_tree": source_tree, "image_id": image_id, "container_id": container_id,
        "configured_target_inputs": [], "governed_no_home_compatibility": "not-established",
        "cleanup": [{"container_absent": True},
            {"tag": "fuzzy1337-nuclei-runner-" + owner, "absent": True},
            {"tag": "fuzzy1337-nuclei-base-" + owner, "absent": True}]}
    outcome = {"status": "completed-prerequisites", "version_probe": "completed",
        "go_template_validation": "completed", "governed_no_home_compatibility": "not-established",
        "configured_target_inputs": [], "independent_server_contact_count": None}
    documents = {run + "host.json": host, run + "base.iid": (base_id + "\n").encode(),
        run + "runner.iid": (image_id + "\n").encode(), run + "context-inventory.json": {
            "revision": head, "tree": source_tree}, run + "imported/prerequisites.json": outcome,
        run + "imported/image-provisioning.json": {"source_revision": head,
            "installed": {"installed": {"source_revision": head}}}}
    arguments = {"version": ["/opt/benchmark-material/nuclei", "-version", "-duc"],
        "validate": ["/opt/benchmark-material/nuclei", "-validate", "-t",
            "/opt/benchmark-material/prometheus-exposition.yaml", "-config",
            "/opt/benchmark-material/operator-config.yaml", "-duc", "-ni", "-no-stdin",
            "-pt", "http", "-nc"]}

    for name, argv in arguments.items():
        prefix = run + "imported/" + name + "/"
        documents[prefix + "invocation.json"] = {"argv": argv,
            "basis": "target-free-explicit-home-prerequisite"}
        documents[prefix + "process.json"] = {"exit_code": 0, "streams_complete": True,
            "timed_out": False, "capture_exhausted": None, "launch_error": None,
            "capture_error": None, "interrupted": None, "cleanup_error": None}
        documents[prefix + "stdout.raw"] = b"Nuclei Engine Version: v3.4.10" if (
            name == "version") else b"All templates validated successfully"
        documents[prefix + "stderr.raw"] = b""

    junit = ('<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
        '<testcase classname="tests.functional.test_external_nuclei_prerequisites" '
        'name="test_InstalledImageRunsOfflineExactNucleiPrerequisites"/>'
        '</testsuite></testsuites>')
    actual_identity = head + "\n" + source_tree

    if mutation == "skip":
        junit = junit.replace('skipped="0"', 'skipped="1"')

    elif mutation == "hidden-skip":
        junit = junit.replace('/>', '><skipped/></testcase>')

    elif mutation in {"wrong-case", "wrong-class"}:
        junit = junit.replace('test_InstalledImageRunsOfflineExactNucleiPrerequisites' if (
            mutation == "wrong-case") else 'tests.functional.test_external_nuclei_prerequisites',
            'unrelated')

    elif mutation == "failed-case":
        junit = junit.replace('failures="0"', 'failures="1"')

    elif mutation == "multiple-cases":
        junit = junit.replace('</testsuite>', '<testcase name="foreign"/></testsuite>')

    elif mutation == "multiple-runs":
        documents[run.replace(owner[:12], "0" * 12) + "host.json"] = host

    elif mutation in {"no-run", "host-missing"}:
        del documents[run + "host.json"]

        if mutation == "no-run":
            documents = {}

    elif mutation == "host-failed":
        host["status"] = "failed"

    elif mutation in {"head", "tree", "image", "container"}:
        host[{"head": "source_revision", "tree": "source_tree", "image": "image_id",
            "container": "container_id"}[mutation]] = "0" * 40

    elif mutation == "checkout":
        actual_identity = "0" * 40 + "\n" + source_tree

    elif mutation == "iid":
        documents[run + "runner.iid"] = (base_id + "\n").encode()

    elif mutation == "cleanup":
        host["cleanup"][0]["container_absent"] = False

    elif mutation == "tag":
        host["cleanup"][2]["tag"] = "foreign"

    elif mutation == "target":
        host["configured_target_inputs"] = ["https://not-a-prerequisite.invalid"]

    elif mutation == "home-claim":
        host["governed_no_home_compatibility"] = "established"

    elif mutation == "imported-target":
        outcome["configured_target_inputs"] = ["foreign"]

    elif mutation == "imported-head":
        documents[run + "imported/image-provisioning.json"]["source_revision"] = "0" * 40

    elif mutation in {"version-argv", "validation-argv"}:
        name = "version" if mutation == "version-argv" else "validate"
        documents[run + "imported/" + name + "/invocation.json"]["argv"].append("-u")

    elif mutation == "process":
        documents[run + "imported/validate/process.json"]["streams_complete"] = False

    elif mutation in {"empty-version", "wrong-version", "empty-validation"}:
        name = "validate" if mutation == "empty-validation" else "version"
        documents[run + "imported/" + name + "/stdout.raw"] = (
            b"Nuclei Engine Version: v0.0.0" if mutation == "wrong-version" else b"")

    elif mutation == "stderr-missing":
        del documents[run + "imported/validate/stderr.raw"]

    for name, value in documents.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if type(value) is bytes else json.dumps(value).encode())

    if mutation != "junit-missing":
        path = tmp_path / "functional-evidence/nuclei-prerequisites.xml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(junit)

    result = subprocess.run([sys.executable, "-I", "-B", str(script_path), head, actual_identity],
        cwd=tmp_path, capture_output=True, timeout=5, check=False)
    assert (result.returncode == 0) is (mutation is None), (
        "Only complete synthetic prerequisite facts may pass the inert gate predicate."
    )
