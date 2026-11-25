"""One-run verification of the installed CLI and a downloaded four-file report artifact."""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections import Counter
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree
from zipfile import ZipFile

ROOT = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
TEMP = Path(os.environ["RUNNER_TEMP"]).resolve()
SAVED = ROOT / "saved-hosted-proof"
NAMES = {"report.json", "report.junit.xml", "json-export.json", "junit-export.json"}
TESTS = [
    "tests/unit/test_gitlab_retained_report.py", "tests/unit/test_retained_report_ci.py",
    "tests/unit/test_sbom_commands.py", "tests/contract/test_sbom_import_contract.py",
    "tests/integration/test_sbom_import.py", "tests/e2e/test_sbom_cli.py",
    "tests/unit/test_python_style.py", "tests/unit/test_command_registry.py",
    "tests/unit/test_cli.py::test_HelpCommandUsesTheCommandRegistry",
    "tests/unit/test_cli.py::test_CliOptions",
    "tests/unit/test_cli.py::test_NoArgumentsDescribeBootstrap",
    "tests/unit/test_cli.py::test_SbomRegisteredHelpAndGrammarRefusalNeedNoLocalState",
    "tests/unit/test_shell.py::test_ShellPaletteSearchesLocalCommandsAndCachedContextActions",
    "tests/unit/test_shell.py::test_ShellHelpAndUsageErrorsRemainCompact",
    "tests/unit/test_shell.py::test_SbomShellUsesQuotedWindowsPathsWithoutImplicitContextOrRetainedArguments",
]
REQUIRED = {
    "test_SubstitutedReceiptSymlinkCannotPublishOrReadAnExternalSource[json-export.json]",
    "test_SubstitutedReceiptSymlinkCannotPublishOrReadAnExternalSource[junit-export.json]",
    "test_PrecreatedReceiptLinkCannotRedirectTheInitialReceiptWrite",
    "test_RepositoryPythonSourcesFollowCompleteStyleContract",
    "test_InstalledCycloneDxAcquiresOwnedFileAndReplaysOriginalAfterRelocation[config]",
    "test_InstalledCycloneDxAcquiresOwnedFileAndReplaysOriginalAfterRelocation[manifest]",
}


def Digest(data):
    return hashlib.sha256(data).hexdigest()


def SourceBytes():
    return {path.relative_to(SAVED).as_posix(): Digest(path.read_bytes())
            for path in SAVED.rglob("*") if path.is_file()}


def Save(name, data):
    with (TEMP / name).open("x", encoding="utf-8") as stream:
        json.dump(data, stream, sort_keys=True)


def Load(name):
    return json.loads((TEMP / name).read_bytes())


def Focused():
    import fuzzy1337
    assert Path(fuzzy1337.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    python = [sys.executable, "-I", "-m"]
    changed = ["src/fuzzy1337/retained_report_ci.py", "src/fuzzy1337/sbom_commands.py",
               "src/fuzzy1337/command_registry.py"]
    covered = sorted({test.split("::")[0] for test in TESTS})
    subprocess.run([*python, "ruff", "check", *changed, "tests/sbom_helpers.py", *covered],
                   cwd=ROOT, check=True)
    subprocess.run([*python, "mypy", *changed], cwd=ROOT, check=True)
    xml = TEMP / "focused.xml"
    subprocess.run([*python, "pytest", "-o", "addopts=", "--strict-config", "--strict-markers",
                    "--no-cov", "-n", "2", "--dist=loadscope", "--timeout=90",
                    "--rootdir", str(ROOT), "-q", "--junitxml", str(xml), *TESTS],
                   cwd=ROOT, check=True)
    cases = ElementTree.parse(xml).findall(".//testcase")
    names = {case.attrib["name"] for case in cases}
    counts = Counter(case.attrib["classname"].split(".")[-1] for case in cases)
    assert set(counts) == {Path(path).stem for path in covered}
    assert REQUIRED <= names, sorted(REQUIRED - names)
    assert all(not any(case.find(tag) is not None for tag in ("error", "failure", "skipped"))
               for case in cases)
    summary = {"count": len(cases), "by_module": dict(counts), "junit_sha256": Digest(xml.read_bytes())}
    Save("proof-tests.json", summary)
    print("FOCUSED_RESULTS", json.dumps(summary, sort_keys=True))


def Fixture():
    import fuzzy1337
    from fuzzy1337.model import CanonicalModelJson, LocalModelStore
    from pytest import MonkeyPatch
    assert Path(fuzzy1337.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    sys.path.insert(0, str(ROOT))
    from tests.contract.report_export_fixture import Context, DenyExecution
    with MonkeyPatch.context() as patch:
        DenyExecution(patch)
        source, records = Context(ROOT, workspace_id=SAVED.name)
    assert source == SAVED
    state = LocalModelStore(SAVED).Open().ToDict()
    Save("proof-seed.json", {"model": state, "snapshot": Digest(CanonicalModelJson(state)),
                             "records": len(records), "files": SourceBytes()})


def Record():
    run, attempt = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"]
    artifact = os.environ["ARTIFACT_ID"]
    digest = os.environ["ARTIFACT_DIGEST"]
    assert re.fullmatch(r"[1-9][0-9]*", artifact) and re.fullmatch(r"[a-f0-9]{64}", digest)
    bundle = ROOT / f"1337-retained-report-{run}-{attempt}-hosted-proof"
    assert {p.name for p in bundle.iterdir()} == NAMES
    assert all(stat.S_ISREG((bundle / name).lstat().st_mode) for name in NAMES)
    assert SourceBytes() == Load("proof-seed.json")["files"]
    Save("hosted-proof-receipt.json", {"id": artifact, "url": os.environ["ARTIFACT_URL"],
         "archive_sha256": digest, "source": os.environ["APPROVED_SOURCE_SHA"],
         "files": {name: Digest((bundle / name).read_bytes()) for name in sorted(NAMES)}})


def Verify():
    receipt, seed = Load("hosted-proof-receipt.json"), Load("proof-seed.json")
    root = Path(os.environ["DOWNLOAD_ROOT"])
    paths = [p for p in root.rglob("*") if p.is_file()]
    assert len(paths) == 1 and stat.S_ISREG(paths[0].lstat().st_mode)
    archive = paths[0].read_bytes()
    assert Digest(archive) == receipt["archive_sha256"] == os.environ["ARTIFACT_DIGEST"]
    assert receipt["id"] == os.environ["ARTIFACT_ID"]
    with ZipFile(BytesIO(archive)) as zipped:
        assert len(zipped.infolist()) == 4 and set(zipped.namelist()) == NAMES
        assert all(0 < item.file_size <= 32 * 1024 * 1024 and not item.is_dir()
                   for item in zipped.infolist())
        files = {name: zipped.read(name) for name in NAMES}
    assert {k: Digest(v) for k, v in files.items()} == receipt["files"]
    report = json.loads(files["report.json"])
    assert report["model"] == seed["model"] and report["snapshot_sha256"] == seed["snapshot"]
    assert report["scan_completeness"] == "not-assessed"
    xml = ElementTree.fromstring(files["report.junit.xml"])
    props = {p.attrib["name"]: p.attrib["value"] for p in xml.findall("./properties/property")}
    assert props["snapshot_sha256"] == seed["snapshot"] and xml.tag == "testsuite"
    assert (xml.attrib["tests"], xml.attrib["failures"], xml.attrib["skipped"]) == ("4", "2", "2")
    assert len(xml.findall("testcase/failure")) == len(xml.findall("testcase/skipped")) == 2
    for fmt, name in (("json", "report.json"), ("junit", "report.junit.xml")):
        outcome = json.loads(files[fmt + "-export.json"])
        assert outcome["command"] == "report.export" and outcome["format"] == fmt
        assert outcome["status"] == "completed" and outcome["output_published"] is True
        assert outcome["snapshot_sha256"] == seed["snapshot"]
        assert outcome["model_revision"] == report["model_revision"]
        assert outcome["verified_retained_acquisitions"] == seed["records"]
        assert outcome["size_bytes"] == len(files[name]) and outcome["report_sha256"] == Digest(files[name])
    result = {**receipt, "status": "verified", "files_checked": 4,
              "snapshot": seed["snapshot"], "focused": Load("proof-tests.json"),
              "wheel": Load("hosted-proof-wheel.json")}
    print("HOSTED_PROOF_RESULT", json.dumps(result, sort_keys=True))
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf8") as stream:
        stream.write("Verified the downloaded ZIP, both original receipts and the saved model.\n\n")
        stream.write(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    {"focused-tests": Focused, "create-fixture": Fixture,
     "record-receipt": Record, "verify-download": Verify}[sys.argv[1]]()
