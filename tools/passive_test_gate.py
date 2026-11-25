# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Measure admitted passive units or verified test-only files without claiming a global gate."""

from __future__ import annotations

import argparse
import ast
import json
import os
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

try:
    from tools.python_naming import BASELINE, CheckSource

except ModuleNotFoundError:
    from python_naming import BASELINE, CheckSource

MAX_INVENTORY_BYTES = 1024 * 1024
TEST_ONLY_CHECKS = (
    "tests/unit/test_python_style.py",
    "tests/unit/test_source_documentation_headers.py",
    "tests/unit/test_python_naming.py",
    "tests/unit/test_passive_test_gate.py",
    "tests/unit/test_passive_integration.py",
)

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


def ChangedFiles(base: str) -> tuple[str, tuple[dict[str, str], ...]]:
    """Capture one complete regular or irregular raw diff against the actual ancestor.

    Args:
        base: Exact reviewed integration ancestor commit.

    Returns:
        Actual head and complete raw change records, including modes and object identities.
    """

    if re.fullmatch(r"[0-9a-f]{40}", base) is None:
        raise ValueError("Passive coverage requires an exact base commit")

    command = ["git", "--no-replace-objects"]
    head = subprocess.run([*command, "rev-parse", "--verify", "HEAD^{commit}"], check=True,
                          capture_output=True, text=True, timeout=30).stdout.strip()
    ancestor = subprocess.run([*command, "merge-base", "--all", base, head], check=True,
                              capture_output=True, text=True, timeout=30).stdout.strip()

    if re.fullmatch(r"[0-9a-f]{40}", head) is None or ancestor != base:
        raise ValueError("Passive coverage base is not the actual integration ancestor")

    subprocess.run([*command, "diff", "--no-ext-diff", "--quiet", "HEAD", "--"],
                   check=True, capture_output=True, timeout=30)
    raw = subprocess.run([*command, "diff", "--no-ext-diff", "--no-renames", "--raw",
                          "--abbrev=40", "-z", base, head, "--"], check=True,
                         capture_output=True, timeout=30).stdout

    if len(raw) > MAX_INVENTORY_BYTES:
        raise ValueError("Passive change inventory is oversized")

    parts = raw.split(b"\0")

    if parts[-1] or len(parts) % 2 != 1 or len(parts) // 2 > 512:
        raise ValueError("Passive change inventory is malformed")

    changes = []
    seen = set()

    for header, rawPath in zip(parts[:-1:2], parts[1::2], strict=True):
        match = re.fullmatch(rb":([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) "
                             rb"([0-9a-f]{40}) ([AMDT])", header)
        path = rawPath.decode("utf-8")

        if match is None or path in seen or not path or path.startswith("/") or any(
            part in {"", ".", ".."} for part in path.split("/")
        ) or any(ord(character) < 32 or ord(character) == 127 for character in path):
            raise ValueError("Passive change inventory contains an ambiguous path or record")

        seen.add(path)
        changes.append(dict(zip(("old_mode", "new_mode", "old_blob", "new_blob", "status"),
                                (value.decode("ascii") for value in match.groups()),
                                strict=True), path=path))

    return head, tuple(changes)


def ChangedModules(
    base: str, *, changes: Sequence[dict[str, str]] | None = None,
) -> tuple[Path, ...]:
    """Enumerate every surviving changed production module from the same complete inventory.

    Args:
        base: Exact reviewed integration ancestor commit.
        changes: Complete independently captured raw diff, or capture it when omitted.

    Returns:
        Sorted existing regular first-party Python modules changed since that ancestor.
    """

    if changes is None:
        _, changes = ChangedFiles(base)

    modules = []

    for change in changes:
        path = Path(change["path"])

        if not path.as_posix().startswith("src/fuzzy1337/") or path.suffix != ".py":
            continue

        if change["status"] not in {"A", "M"} or change["new_mode"] != "100644" or (
            not path.is_file() or path.is_symlink()
        ):
            raise ValueError("Passive production inventory contains a removed or aliased module")

        modules.append(path)

    return tuple(sorted(modules))


def ReadBlob(reference: str) -> bytes:
    """Read one bounded tracked input without executing it or trusting a working-tree substitute.

    Args:
        reference: Exact diff object identity or a head-owned tracked source path.

    Returns:
        Complete original blob bytes within the inspection ceiling.
    """

    command = ["git", "--no-replace-objects", "cat-file"]
    size = subprocess.run([*command, "-s", reference], check=True, capture_output=True,
                          timeout=30).stdout.strip()

    if not size.isdigit() or len(size) > 8 or int(size) > MAX_INVENTORY_BYTES:
        raise ValueError("Passive inspected blob is oversized")

    raw = subprocess.run([*command, "blob", reference], check=True,
                         capture_output=True, timeout=30).stdout

    if len(raw) != int(size):
        raise ValueError("Passive inspected blob is incomplete")

    return raw


def TestOnlyEvent(base: str, head: str) -> bool:
    """Keep narrowing inside the already admitted Ready develop pull-request invocation.

    Args:
        base: Independently verified actual integration ancestor.
        head: Independently verified actual checked-out commit.

    Returns:
        Whether original event metadata agrees with this exact Ready develop candidate.
    """

    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request" or (
        os.environ.get("GITHUB_BASE_REF") != "develop"
    ):
        return False

    with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as stream:
        raw = stream.read(MAX_INVENTORY_BYTES + 1)

    if len(raw) > MAX_INVENTORY_BYTES:
        return False

    request = json.loads(raw)["pull_request"]

    return (request["draft"] is False and request["base"]["ref"] == "develop"
            and request["base"]["sha"] == base and request["head"]["sha"] == head
            and request["head"]["ref"].startswith("feature/passive-batch-")
            and os.environ.get("GITHUB_HEAD_REF") == request["head"]["ref"])


def LeafTests(files: Sequence[str], head: str) -> bool:
    """Conservatively refuse visible imports, plugins and dynamic uses by other Python modules.

    Args:
        files: Existing reviewed unit modules proposed as complete pytest file selections.
        head: Actual immutable candidate commit containing all possible tracked consumers.

    Returns:
        Whether bounded tracked-source inspection found no external test-module dependency.
    """

    command = ["git", "--no-replace-objects", "grep", "--no-textconv", "-l", "-z", "-F"]

    for path in files:
        command.extend(("-e", Path(path).stem))

    found = subprocess.run([*command, head, "--", "*.py"], check=False,
                           capture_output=True, timeout=30)

    if found.returncode not in {0, 1} or len(found.stdout) > MAX_INVENTORY_BYTES or (
        (found.returncode == 1) != (not found.stdout)
    ):
        raise ValueError("Passive consumer search failed")

    if not found.stdout:
        return True

    if not found.stdout.endswith(b"\0") or found.stdout.count(b"\0") > 512:
        raise ValueError("Passive consumer search is incomplete")

    for entry in found.stdout[:-1].split(b"\0"):
        prefix = (head + ":").encode()

        if not entry.startswith(prefix):
            raise ValueError("Passive consumer identity differs")

        consumer = entry[len(prefix):].decode("utf-8")
        tree = ast.parse(ReadBlob(head + ":" + consumer), type_comments=True)

        for path in files:
            if consumer == path:
                continue

            stem = Path(path).stem
            module = path.removesuffix(".py").replace("/", ".")

            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)) and (
                    stem in (getattr(node, "module", "") or "").split(".")
                    or any(stem in alias.name.split(".") for alias in node.names)
                ):
                    return False

                if isinstance(node, (ast.Name, ast.Attribute)) and (
                    getattr(node, "id", None) == stem or getattr(node, "attr", None) == stem
                ):
                    return False

                if isinstance(node, ast.Constant) and node.value in (stem, module):
                    return False

                if isinstance(node, ast.Call) and ast.unparse(node.func) != (
                    "pytest.mark.parametrize"
                ) and any(isinstance(value, ast.Constant) and isinstance(value.value, str)
                          and stem in value.value for value in ast.walk(node)):
                    return False

    return True


def TestOnlySelection(
    base: str, head: str, changes: Sequence[dict[str, str]],
) -> tuple[tuple[str, ...], str]:
    """Select complete reviewed leaf unit files, otherwise retain the existing passive gate.

    Args:
        base: Actual independently verified integration ancestor commit.
        head: Actual independently verified candidate commit.
        changes: Complete raw change inventory, never selectors supplied by a PR.

    Returns:
        Full file selection and reason, or an empty selection for the existing full passive gate.
    """

    try:
        if not TestOnlyEvent(base, head):
            return (), "ordinary-or-unverified-event"

        files = tuple(change["path"] for change in changes
                      if change["path"] != BASELINE.as_posix())

        if not files or any(re.fullmatch(r"tests/unit/test_[a-z0-9_]+\.py", path) is None
                            for path in files):
            return (), "non-test-or-shared-change"

        if any(path in TEST_ONLY_CHECKS for path in files):
            return (), "shared-ownership-check-change"

        if any(change["status"] != "M" or change["old_mode"] != "100644"
               or change["new_mode"] != "100644"
               or "0" * 40 in (change["old_blob"], change["new_blob"])
               or change["old_blob"] == change["new_blob"] for change in changes):
            return (), "not-existing-regular-modifications"

        removed = Counter()

        for change in changes:
            if change["path"] == BASELINE.as_posix():
                continue

            old, new = (ReadBlob(change[key]).decode("utf-8")
                        for key in ("old_blob", "new_blob"))
            path = Path(change["path"])

            if path.is_symlink() or not path.is_file() or path.read_bytes() != new.encode("utf-8"):
                return (), "working-source-differs"

            before, after = CheckSource(old, path.as_posix()), CheckSource(new, path.as_posix())

            if after - before:
                return (), "new-naming-debt"

            removed.update(before - after)

        if any(kind != "local" for _, kind, _, _ in removed):
            return (), "non-local-baseline-change"

        before = ReadBlob(base + ":" + BASELINE.as_posix()).decode("utf-8")
        after = ReadBlob(head + ":" + BASELINE.as_posix()).decode("utf-8")
        rows = [json.loads(raw) for raw in (before, after)]

        if any(not isinstance(group, list) or any(
            not isinstance(row, list) or len(row) != 4
            or any(not isinstance(value, str) for value in row) for row in group
        ) for group in rows):
            return (), "baseline-row-shape-differs"

        oldRows, newRows = (Counter(tuple(row) for row in group) for group in rows)

        if oldRows - newRows != removed or newRows - oldRows or any(
            path not in files or kind != "local" for path, kind, _, _ in oldRows - newRows
        ):
            return (), "baseline-differs-from-local-removals"

        lines = before.splitlines(keepends=True)
        expected = []

        for line in lines:
            if line.strip().startswith("[") and line.strip() not in {"["}:
                row = tuple(json.loads(line.strip().removesuffix(",")))

                if removed[row]:
                    removed[row] -= 1
                    continue

            expected.append(line)

        if "".join(expected) != after:
            return (), "baseline-has-other-byte-changes"

        if not LeafTests(files, head):
            return (), "shared-or-dynamic-test-module"

    except (OSError, KeyError, TypeError, ValueError, SyntaxError, UnicodeError, RecursionError,
            subprocess.SubprocessError):
        return (), "test-only-inspection-refused"

    return tuple(dict.fromkeys((*files, *TEST_ONLY_CHECKS))), "verified-leaf-unit-changes"


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
    append: bool = False, configuration: Path | None = None, requireFiles: bool = False,
) -> dict[str, dict[str, int]]:
    """Run the complete disjoint parallel/serial selection once with fresh shared measurement.

    Args:
        selection: Complete reviewed test source selection, without a case-level filter.
        options: Validated bounded worker, timeout and failure handling configuration.
        label: Explicit evidence partition name used to distinguish original JUnit results.
        append: Whether this selection extends the existing original coverage measurement.
        configuration: Optional explicit subprocess coverage configuration for owned boundaries.
        requireFiles: Require actual collected cases from every complete quick-profile file.

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

    owners = {owner for cases in expected.values() for owner, _ in cases}

    if requireFiles and any(not any(
        owner == name.removesuffix(".py").replace("/", ".")
        or owner.startswith(name.removesuffix(".py").replace("/", ".") + ".")
        for owner in owners
    ) for name in selection):
        raise ValueError("Passive quick file has no collected cases")

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
        head, changes = ChangedFiles(arguments.base)
        modules = ChangedModules(arguments.base, changes=changes)
        selection, reason = TestOnlySelection(arguments.base, head, changes)
        options = TestOptions(fail_fast=True, suite_timeout_seconds=arguments.suite_timeout)
        summaries = {"units": RunSelection(selection, options, requireFiles=True) if selection
                     else RunSelection(("tests/unit",), options)}

        if not selection:
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
        receipt = {"scope": "test-only" if selection else "changed-production-modules",
                   "base": arguments.base, "head": head, "changes": changes,
                   "selection_reason": reason, "selection": selection or ("tests/unit",),
                   "partitions": summaries, "modules": scoped, "global_module_gate": "not-claimed"}
        Path("coverage/passive-acceptance.json").write_text(
            json.dumps(receipt, indent=2, allow_nan=False) + "\n", encoding="utf-8",
        )

    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, ElementTree.ParseError):
        print("Passive test/coverage gate failed; inspect retained test and coverage evidence.",
              file=sys.stderr)
        return 1

    print("Passive test-only files and required ownership regressions passed." if selection else
          "Passive units and offline boundaries passed; changed modules are strictly above 80%.")
    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
