"""Run focused offline IOC, shell discovery and style checks on exact Git trees."""

import hashlib
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
TEMP = Path(os.environ["RUNNER_TEMP"]).resolve()
PYTHON = [sys.executable, "-I", "-m"]
FEATURE_TESTS = [
    "tests/unit/test_ioc_bundle_candidate_export.py",
    "tests/e2e/test_ioc_bundle_candidate_export_cli.py",
    "tests/unit/test_ioc_bundle.py",
    "tests/unit/test_ioc_commands.py",
    "tests/contract/test_ioc_cli_contract.py",
    "tests/unit/test_shell.py::test_ShellSbomContextualHelpListsBothProfilesWithoutDispatch",
    "tests/unit/test_shell.py::test_ShellHelpAndUsageErrorsRemainCompact",
    "tests/unit/test_shell.py::test_ShellPaletteSearchesLocalCommandsAndCachedContextActions",
    "tests/unit/test_shell.py::test_SbomShellUsesQuotedWindowsPathsWithoutImplicitContextOrRetainedArguments",
    "tests/unit/test_python_style.py::test_RepositoryPythonSourcesFollowCompleteStyleContract",
    "tests/unit/test_source_documentation_headers.py::test_SourceDocumentationAndHeadersMatchContract",
    "tests/unit/test_locale_documentation.py::test_MissingTranslationsRemainHonest",
]
STYLE_TESTS = [
    "tests/unit/test_owned_response_parent.py::test_PortableDiagnosticsObserveFirstOriginalFailureBeforeOrDuringCustody",
    "tests/unit/test_owned_response_parent.py::test_PortableCustodyDiagnosticsIdentifyExactPhysicalFieldWithoutValues",
    "tests/unit/test_owned_response_parent.py::test_FakePosixViewRepairsProvenCrossApiCtimeMismatchOnly",
    "tests/unit/test_owned_response_parent.py::test_FakeClockLateBudgetsNeverBecomeSuccess",
    "tests/unit/test_owned_response_parent.py::test_CoherentUnitViewStillRefusesExactCtimeOnlyMutation",
    "tests/unit/test_runtime_commands.py::test_EveryOriginalReadViewRequiresOnePhysicalLink",
    "tests/unit/test_python_naming.py",
]


def Git(*args):
    return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=ROOT, text=True).strip()


def Check(kind):
    import fuzzy1337
    assert Path(fuzzy1337.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    assert Git("rev-parse", "HEAD") == os.environ[kind.upper() + "_SHA"]
    assert Git("rev-parse", "HEAD^{tree}") == os.environ[kind.upper() + "_TREE"]
    if kind == "feature":
        (TEMP / "tested-src-tree").write_text(Git("rev-parse", "HEAD:src"), encoding="ascii")
        files = FEATURE_TESTS
        source = ["src/fuzzy1337/ioc_commands.py", "src/fuzzy1337/ioc_bundle.py", "src/fuzzy1337/shell.py"]
        subprocess.run([*PYTHON, "mypy", *source], cwd=ROOT, check=True)
    else:
        assert (TEMP / "tested-src-tree").read_text(encoding="ascii") == Git("rev-parse", "HEAD:src")
        files, source = STYLE_TESTS, []
        subprocess.run([sys.executable, "-I", str(TEMP / "private-locals-proof.py")], cwd=ROOT, check=True)
        subprocess.run([sys.executable, "-I", "tools/python_naming.py"], cwd=ROOT, check=True)
    affected = sorted({path.split("::")[0] for path in files})
    subprocess.run([*PYTHON, "ruff", "check", *source, *affected], cwd=ROOT, check=True)
    xml = TEMP / ("offline-" + kind + ".xml")
    subprocess.run([*PYTHON, "pytest", "-o", "addopts=", "--strict-config", "--strict-markers",
                    "--no-cov", "-n", "2", "--dist=loadscope", "--timeout=90",
                    "--rootdir", str(ROOT), "-q", "--junitxml", str(xml), *files], cwd=ROOT, check=True)
    cases = ElementTree.parse(xml).findall(".//testcase")
    counts = Counter(test.attrib["classname"].split(".")[-1] for test in cases)
    assert all(not any(test.find(tag) is not None for tag in ("error", "failure", "skipped"))
               for test in cases)
    assert set(counts) == {Path(path).stem for path in affected}
    if kind == "feature":
        assert counts["test_ioc_bundle_candidate_export"] == 8
        assert counts["test_ioc_bundle_candidate_export_cli"] == 4
    else:
        assert counts == {"test_owned_response_parent": 18, "test_runtime_commands": 3,
                          "test_python_naming": 3}
    summary = {"kind": kind, "head": Git("rev-parse", "HEAD"), "tree": Git("rev-parse", "HEAD^{tree}"),
               "tested_modules": dict(counts), "total": len(cases), "junit_sha256":
               hashlib.sha256(xml.read_bytes()).hexdigest()}
    print("OFFLINE_GROUP_RESULT", json.dumps(summary, sort_keys=True))
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(summary, sort_keys=True, indent=2) + "\n\n")


if __name__ == "__main__":
    Check(sys.argv[1])
