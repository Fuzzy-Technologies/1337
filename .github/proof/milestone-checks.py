"""Run installed, offline acceptance for declaration lookup, version metadata and the CWE catalog."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from importlib import resources
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
TEMP = Path(os.environ["RUNNER_TEMP"]).resolve()
P = [sys.executable, "-I", "-m"]
TESTS = [
    "tests/unit/test_business_commands.py", "tests/e2e/test_business_inspection_cli.py",
    "tests/contract/test_business_events_contract.py",
    "tests/unit/test_extension_commands.py", "tests/unit/test_extension_version_profile.py",
    "tests/e2e/test_extension_version_profile_cli.py",
    "tests/unit/test_intelligence_cwe_commands.py", "tests/unit/test_intelligence_cwe_lookup.py",
    "tests/contract/test_intelligence_cwe_commands_contract.py",
    "tests/integration/test_intelligence_cwe_lookup.py",
    "tests/unit/test_command_registry.py",
    "tests/unit/test_shell.py::test_ShellReportsCommandsDrainsUpdatesAndExitsCleanly",
    "tests/unit/test_shell.py::test_ShellPaletteSearchesLocalCommandsAndCachedContextActions",
    "tests/unit/test_shell.py::test_ShellSbomContextualHelpListsBothProfilesWithoutDispatch",
    "tests/unit/test_cli.py::test_HelpCommandUsesTheCommandRegistry",
    "tests/unit/test_python_style.py::test_RepositoryPythonSourcesFollowCompleteStyleContract",
    "tests/unit/test_source_documentation_headers.py::test_SourceDocumentationAndHeadersMatchContract",
    "tests/unit/test_locale_documentation.py::test_MissingTranslationsRemainHonest",
]


def Run():
    import fuzzy1337
    assert Path(fuzzy1337.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    sources = ["business_commands", "cli", "command_registry", "shell", "extension_commands",
               "intelligence_cwe_commands"]
    sources = ["src/fuzzy1337/" + name + ".py" for name in sources]
    tests = sorted({item.split("::")[0] for item in TESTS})
    subprocess.run([*P, "ruff", "check", *sources, *tests, "tests/business_inspection_helpers.py"],
                   cwd=ROOT, check=True)
    subprocess.run([*P, "mypy", *sources], cwd=ROOT, check=True)
    subprocess.run([sys.executable, "-I", "tools/python_naming.py"], cwd=ROOT, check=True)
    out = TEMP / "group-m3-m5-m9.xml"
    subprocess.run([*P, "pytest", "-o", "addopts=", "--strict-config", "--strict-markers",
                    "--no-cov", "-n", "2", "--dist=loadscope", "--timeout=150",
                    "--rootdir", str(ROOT), "-q", "--junitxml", str(out), *TESTS], cwd=ROOT, check=True)
    cases = ElementTree.parse(out).findall(".//testcase")
    modules = {p[:-3].replace("/", ".") for p in tests}
    counts = Counter()
    for case in cases:
        name = case.attrib["classname"]
        owners = [m for m in modules if name == m or name.startswith(m + ".")]
        assert len(owners) == 1, (name, owners)
        assert not any(case.find(tag) is not None for tag in ("error", "failure", "skipped"))
        counts[owners[0]] += 1
    assert set(counts) == modules
    names = {case.attrib["name"].split("[")[0] for case in cases}
    assert {"test_CleanWheelLooksUpNewIdsFromCopiedOriginalCustodyWithoutExternalInput",
            "test_ConsoleReopensExactOwnerDeclarationAfterRelocationWithoutWriting",
            "test_InstalledModuleProvidesExplicitSemverProfileWithoutChangingDefault"} <= names
    console = str(Path(sys.executable).with_name("1337"))
    example = resources.files("fuzzy1337").joinpath("contracts", "extension-manifest.example.json")
    doc = json.loads(example.read_bytes())
    doc["extension"]["version"] = "1.2.3-" + "7"*5000 + "+" + "0"*5000
    payload = json.dumps(doc).encode()
    assert len(payload) < 65536
    results = []
    with tempfile.TemporaryDirectory(dir=TEMP) as scratch:
        file = Path(scratch) / "manifest.json"
        for size, expected in ((len(payload), 0), (65536, 0), (65537, 2)):
            file.write_bytes(payload.ljust(size, b" "))
            proc = subprocess.run([console, "extension", "validate", str(file),
                                   "--version-profile", "semver-2.0.0", "--json"], cwd=scratch,
                                  capture_output=True, timeout=15, check=False)
            result = json.loads(proc.stdout)
            assert not proc.stderr and proc.returncode == expected, (size, proc.returncode, result.get("failure"))
            assert result["core_compatibility"] == "not-evaluated" and result["extension_activation"] == "not-attempted"
            if expected == 2:
                assert result["failure"] == "input-limit", result.get("failure")
            results.append([size, proc.returncode])
    receipt = {"source": os.environ["APPROVED_SOURCE_SHA"], "tree": os.environ["PRODUCT_TREE"],
               "count": len(cases), "by_module": dict(counts), "semver_envelope": results,
               "junit_sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
               "wheel": json.loads((TEMP / "hosted-proof-wheel.json").read_bytes())}
    print("OFFLINE_MILESTONES_RESULT", json.dumps(receipt, sort_keys=True))
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(receipt, sort_keys=True, indent=2))


if __name__ == "__main__":
    Run()
