# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Measure complete units, reviewed offline boundaries and changed-module branch coverage."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from xml.etree import ElementTree

from _pytest.junitxml import mangle_test_address

from fuzzy1337.coverage_gate import ValidateReport
from fuzzy1337.test_runner import PytestArguments, RunPytest, TestOptions

BOUNDARIES = (
    "tests/contract/test_external_scanner_comparison_view.py",
    "tests/contract/test_functional_metrics.py",
    "tests/contract/test_functional_report_comparison.py",
    "tests/contract/test_ioc_cli_contract.py",
    "tests/contract/test_page_capture_contract.py",
    "tests/contract/test_tool_adapters.py",
    "tests/e2e/test_html_junit_cli_exports.py",
    "tests/e2e/test_image_sbom_view_cli.py",
    "tests/e2e/test_intelligence_cli.py",
    "tests/e2e/test_ioc_cli.py",
    "tests/integration/test_attack_path_seed_replay.py",
    "tests/integration/test_ioc_command_workflow.py",
    "tests/integration/test_report_export.py",
    "tests/integration/test_security_model_integration.py",
)
# These exact documentation fixtures execute separately with the hashed docs lock.
DOCUMENTATION_SKIPS = frozenset({
    "test_StaticRenderNeverImportsAndKeepsFallbackExplicit",
    "test_RenderRejectsNonInstalledCheckoutSources[inside]",
    "test_RenderRejectsNonInstalledCheckoutSources[missing]",
    "test_RenderRejectsNonInstalledCheckoutSources[uninstalled]",
    "test_RenderRequiresExplicitStaticInspectionContract[allow_inspection-true]",
    "test_RenderRequiresExplicitStaticInspectionContract[force_inspection-true]",
    "test_RenderRequiresExplicitStaticInspectionContract[allow_inspection-missing]",
    "test_RenderRequiresExplicitStaticInspectionContract[force_inspection-missing]",
    "test_RenderCommandLineUsesInstalledFixture",
    "test_RenderRejectsAlreadyImportedRuntime",
    "test_ImmutableRenderPinsUrlsLanguagesSearchSitemapSourceAndArchive",
})


def Collect(selection: Sequence[str], *, serial: bool) -> Counter[tuple[str, str]]:
    """Collect the exact expected JUnit identities without executing a selected test body.

    Args:
        selection: Complete reviewed pytest source selection to inventory independently.
        serial: Whether to collect the declared serial partition instead of parallel cases.

    Returns:
        Exact collected JUnit identities and their required single-execution counts.
    """

    arguments = [sys.executable, "-m", "pytest", *selection, "-o", "addopts=", "--no-cov",
                 "--strict-config", "--strict-markers", "--collect-only", "-q", "-n", "0",
                 "-m", "serial" if serial else "not serial"]
    result = subprocess.run(arguments, check=False, capture_output=True, text=True, timeout=300)

    if result.returncode not in {0, 5}:
        raise RuntimeError("Passive test collection failed")

    expected = Counter()

    for line in result.stdout.splitlines():
        if line.startswith("tests/") and "::" in line:
            address = mangle_test_address(line)
            expected[(".".join(address[:-1]), address[-1])] += 1

    if any(count != 1 for count in expected.values()) or (result.returncode == 5) != (not expected):
        raise ValueError("Passive collection is empty, duplicated or inconsistent")

    return expected


def CheckJunit(path: Path, expected: Counter[tuple[str, str]]) -> dict[str, int]:
    """Require every collected case once and reject failures and undeclared skipped boundaries.

    Args:
        path: Original JUnit result produced by the selected pytest invocation.
        expected: Independently collected complete case inventory for that exact partition.

    Returns:
        Measured collection, pass, declared documentation-skip and unit-case counts.
    """

    report = ElementTree.parse(path)
    actual = Counter()
    skipped = 0

    for case in report.iter("testcase"):
        identity = case.get("classname"), case.get("name")
        actual[identity] += 1

        if case.find("failure") is not None or case.find("error") is not None:
            raise ValueError("Passive JUnit contains a failed case")

        omitted = case.find("skipped")

        if omitted is not None:
            if identity[0] != "tests.unit.test_api_reference" or (
                identity[1] not in DOCUMENTATION_SKIPS
                or omitted.get("message") != (
                    "Strict rendering requires the separate docs tooling lock"
                )
            ):
                raise ValueError("Passive JUnit contains an unexpected skip")

            skipped += 1

    if actual != expected or not actual:
        raise ValueError("Passive JUnit does not match every independently collected case")

    return {"collected": expected.total(), "passed": expected.total() - skipped,
            "known_documentation_skips": skipped,
            "units": sum(count for (owner, _), count in actual.items()
                         if owner.startswith("tests.unit."))}


def ChangedModules(base: str) -> tuple[Path, ...]:
    """Require the actual ancestor and enumerate every changed surviving production module.

    Args:
        base: Exact reviewed integration ancestor commit for the measured candidate tree.

    Returns:
        Sorted existing regular first-party Python modules changed since that ancestor.
    """

    if re.fullmatch(r"[0-9a-f]{40}", base) is None:
        raise ValueError("Passive coverage requires an exact base commit")

    ancestor = subprocess.run(["git", "merge-base", base, "HEAD"], check=True,
                              capture_output=True, text=True).stdout.strip()

    if ancestor != base:
        raise ValueError("Passive coverage base is not the actual integration ancestor")

    changed = subprocess.run(["git", "--no-replace-objects", "diff", "--no-ext-diff",
                              "--no-renames",
                              "--name-status", "-z", base, "HEAD", "--", "src/fuzzy1337"],
                             check=True, capture_output=True).stdout.split(b"\0")

    if changed == [b""]:
        return ()

    if changed[-1] or len(changed) % 2 != 1:
        raise ValueError("Passive production inventory is malformed")

    modules = []

    for status, name in zip(changed[:-1:2], changed[1::2], strict=True):
        path = Path(name.decode("utf-8"))

        if path.suffix != ".py":
            continue

        if status not in {b"A", b"M"} or not path.is_file() or path.is_symlink():
            raise ValueError("Passive production inventory contains a removed or aliased module")

        modules.append(path)

    return tuple(sorted(modules))


def ChangedCoverage(report: dict, modules: Sequence[Path]) -> dict[str, dict]:
    """Apply the unchanged strict coverage algorithm to an explicit scoped source inventory.

    Args:
        report: Original coverage JSON containing measured statement and branch outcomes.
        modules: Complete independently verified inventory of changed production modules.

    Returns:
        Original coverage summaries for the verified modules after their strict gate passes.
    """

    if report.get("meta", {}).get("branch_coverage") is not True:
        raise ValueError("Passive measurement must include branch coverage")

    entries = {}

    with tempfile.TemporaryDirectory(prefix="1337-passive-coverage-") as directory:
        inventory = Path(directory)
        projected = {}

        for path in modules:
            entry = report.get("files", {}).get(path.as_posix())

            if entry is None:
                raise ValueError("Changed production module has no measured coverage")

            copied = inventory / path
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, copied)
            projected[copied.as_posix()] = entry
            entries[path.as_posix()] = entry["summary"]

        if modules and ValidateReport({"meta": report["meta"], "files": projected}, inventory):
            raise ValueError("Changed production module coverage must remain strictly above 80%")

    return entries


def RunSelection(
    selection: Sequence[str], options: TestOptions, *, label: str = "units",
    append: bool = False, configuration: Path | None = None,
) -> dict[str, dict[str, int]]:
    """Run the complete disjoint parallel/serial selection once with fresh shared measurement.

    Args:
        selection: Complete reviewed test source selection, without a case-level filter.
        options: Validated bounded worker, timeout and failure handling configuration.
        label: Explicit evidence partition name used to distinguish original JUnit results.
        append: Whether this selection extends the existing original coverage measurement.
        configuration: Optional explicit subprocess coverage configuration for owned boundaries.

    Returns:
        Exact measured parallel and serial case summaries after their JUnit checks pass.
    """

    for name in selection:
        if not Path(name).exists():
            raise ValueError("A required passive test selection is missing")

    reports = Path("coverage")
    reports.mkdir(exist_ok=True)

    for phase in ("parallel", "serial"):
        (reports / f"passive-{label}-{phase}.xml").unlink(missing_ok=True)

    if not append:
        (reports / "coverage.json").unlink(missing_ok=True)

    expected = {serial: Collect(selection, serial=serial) for serial in (False, True)}

    if not expected[False] or expected[False].keys() & expected[True].keys():
        raise ValueError("Passive test partitions are empty or overlap")

    summaries = {}

    for serial, cases in expected.items():
        if not cases:
            continue

        phase = "serial" if serial else "parallel"
        path = reports / f"passive-{label}-{phase}.xml"
        arguments = PytestArguments("tests/unit", options, path, serial=serial)
        arguments[3:4] = selection
        # Defer the global threshold to the explicit changed-module gate below.
        arguments.extend(("--cov-fail-under=0", "--max-worker-restart=0"))

        if append and not serial:
            arguments.append("--cov-append")

        if configuration is not None:
            arguments.append(f"--cov-config={configuration}")
        code, _ = RunPytest(arguments, path, options.suite_timeout_seconds)

        if code:
            raise RuntimeError("Passive test execution failed; coverage is not accepted")

        summaries[phase] = CheckJunit(path, cases)

    return summaries


def Main(argv: Sequence[str] | None = None) -> int:
    """Run one admitted passive batch; full/master continue to use their existing global gate.

    Args:
        argv: Explicit command arguments, or the process arguments when omitted.

    Returns:
        Zero after measured passive acceptance succeeds, or the recorded failure status.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--suite-timeout", type=int, default=900)
    arguments = parser.parse_args(argv)

    try:
        Path("coverage/passive-acceptance.json").unlink(missing_ok=True)
        modules = ChangedModules(arguments.base)
        options = TestOptions(fail_fast=True, suite_timeout_seconds=arguments.suite_timeout)
        summaries = {"units": RunSelection(("tests/unit",), options)}
        configuration = Path("coverage/passive-boundaries.coveragerc")
        configuration.write_text(
            "[run]\nbranch = True\nsource = fuzzy1337\nrelative_files = True\n"
            "parallel = True\npatch = subprocess\n"
            "[report]\nfail_under = 0\nexclude_lines =\npartial_branches =\n", encoding="utf-8",
        )
        summaries["boundaries"] = RunSelection(
            BOUNDARIES, options, label="boundaries", append=True, configuration=configuration,
        )
        report = json.loads(Path("coverage/coverage.json").read_text(encoding="utf-8"))
        scoped = ChangedCoverage(report, modules)
        receipt = {"scope": "changed-production-modules", "base": arguments.base,
                   "partitions": summaries, "modules": scoped, "global_module_gate": "not-claimed"}
        Path("coverage/passive-acceptance.json").write_text(
            json.dumps(receipt, indent=2, allow_nan=False) + "\n", encoding="utf-8",
        )

    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, ElementTree.ParseError):
        print("Passive test/coverage gate failed; inspect retained test and coverage evidence.",
              file=sys.stderr)
        return 1

    print("Passive units and offline boundaries passed; changed modules are strictly above 80%.")
    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
