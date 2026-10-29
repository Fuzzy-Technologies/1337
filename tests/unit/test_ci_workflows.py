# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Protect draft feedback, final integration triggers and required full-job execution."""

import ast
import shlex
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
EXTERNAL_NATIVE_FEATURE_CONDITION = (
    INTEGRATION_CONDITION + " || (github.event_name == 'pull_request' "
    "&& github.event.pull_request.draft == true "
    "&& contains(github.event.pull_request.body, '[native-external-checkpoint]'))"
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
        expected |= NATIVE_CRAWL_PORTABILITY_JOBS | {OWNED_TRAVERSAL_RATE_JOB}

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
    assert set(jobs) == old_jobs | {"stale-model-cas-content-header"}, (
        "The finite content workflow must retain six original jobs and one separate CAS case."
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
    assert workflow["permissions"] == {"contents": "read"} and set(events) == {"pull_request"}, (
        "The checkpoint must retain read-only PR authority without unrelated triggers."
    )
    assert events["pull_request"] == {
        "branches": ["develop"],
        "types": ["opened", "reopened", "synchronize", "ready_for_review",
            "converted_to_draft", "edited"],
    }, "Body-marker edits must trigger the checkpoint while retaining every existing PR event."
    assert job["runs-on"] == "ubuntu-24.04" and job["timeout-minutes"] == 6 and (
        job["env"] == {"FUZZY1337_RUN_OWNED_CONTENT_HEADER_ACCEPTANCE": "1"}
        and "strategy" not in job and not job.get("continue-on-error", False)
    ), "The one installed Linux case requires its opt-in and finite non-advisory job."
    steps = job["steps"]
    assert steps[:4] == jobs["installed-content-header"]["steps"][:4], (
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
