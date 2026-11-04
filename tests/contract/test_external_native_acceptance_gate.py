# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Original-shaped inert native gate contracts; these fixtures never execute an application."""

from __future__ import annotations

import copy
import io
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree

import pytest

from tests.functional import external_native_acceptance_gate as gate
from tests.functional.external_benchmark import BuildComparison, LoadPack
from tests.functional.external_native_runner import ExportBundle
from tests.functional.external_native_runtime import NativeBenchmarkRuntime
from tests.functional.external_targets import HttpObservation

HEAD = "b" * 40
TREE = "c" * 40
IMAGE = "sha256:" + "d" * 64
REPOSITORY = Path(__file__).resolve().parents[2]


def WriteJson(path: Path, value) -> None:
    """Retain exact fixture bytes separately from every derived acquisition digest."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def FixtureWheel(repository: Path, *, changed: str | None = None) -> bytes:
    """Create a real inert ZIP with current module bytes; no package or scanner is installed."""

    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in gate.MODULES:
            member = "fuzzy1337/" + name.replace(".", "/") + ".py"
            raw = (repository / "src" / member).read_bytes()
            archive.writestr(member, raw + b"\n# altered inert wheel\n" if name == changed else raw)

    return buffer.getvalue()


def Junit(repository: Path) -> None:
    """Emit a clearly fixture-owned three-case JUnit tree for completeness mutation checks."""

    root = ElementTree.Element("testsuites")
    suite = ElementTree.SubElement(root, "testsuite", tests="3", failures="0", errors="0",
                                  skipped="0")

    for case_id in gate.CASES:
        ElementTree.SubElement(suite, "testcase",
            classname="tests.functional.test_external_native_benchmark",
            name="test_InstalledNativeScannerMatchesRealApplicationCases[" + case_id + "]")

    selected = repository / gate.ROOT / "pytest.xml"
    selected.parent.mkdir(parents=True, exist_ok=True)
    selected.write_bytes(ElementTree.tostring(root))


def NativeGateFixture(tmp_path):
    """Exercise the accepted observation producer with inert local bytes and zero Docker calls."""

    repository = tmp_path / "repository"
    files = ["tests/functional/external_native_runner.py", "labs/external/juice-shop.v1.json",
             "labs/external/benchmark/juice-shop-cases.v1.json", "labs/external/compose.yaml"]
    files.extend("src/fuzzy1337/" + name.replace(".", "/") + ".py" for name in gate.MODULES)

    for relative in files:
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPOSITORY / relative, destination)

    pack, target = LoadPack()
    runtime = NativeBenchmarkRuntime(repository, repository / gate.ROOT, pack, target)
    runtime.source_revision = HEAD
    runtime.image_id = IMAGE
    modules = {name: gate.Digest((repository / "src/fuzzy1337" / (
        name.replace(".", "/") + ".py")).read_bytes()) for name in gate.MODULES}
    wheel_bytes = FixtureWheel(repository)
    observations = []

    for index, case in enumerate(pack["cases"]):
        case_id, path = case["id"], case["path"]
        directory = runtime.output / case_id
        scanner = directory / "scanner"
        scanner.mkdir(parents=True)
        wheel = scanner / "1337-0.3.0-py3-none-any.whl"
        wheel.write_bytes(wheel_bytes)
        source = {"source_revision": HEAD, "package_path": (
            "/opt/benchmark-runtime/lib/python3.13/site-packages/fuzzy1337"),
            "distribution_version": "0.3.0", "python_sha256": "e" * 64,
            "runner_sha256": gate.Digest((repository / files[0]).read_bytes()),
            "effective_body_bytes": 262144, "module_sha256": modules,
            "wheel": {"filename": wheel.name, "size_bytes": len(wheel_bytes),
                      "sha256": gate.Digest(wheel_bytes)}}
        url = "http://127.0.0.1:3000" + path
        body = (b"# HELP sample fixture\n# TYPE sample counter\nsample 1\n" if index == 0 else
                b'{"version":"20.2.0"}' if index == 1 else b"<html>OWASP Juice Shop</html>")
        worker = {"schema_version": 1, "check_id": "native.prometheus-exposition",
            "profile_version": "1", "url": url, "address": "127.0.0.1", "port": 3000,
            "scheme": "http", "status": 200, "media_type": "text/plain" if index == 0 else "other",
            "body_bytes": len(body), "body_sha256": gate.Digest(body), "matched": index == 0}
        invocation = {"argv": ["/opt/benchmark-runtime/bin/python", "-I", "-m",
            "fuzzy1337.native_web_worker", url, "3.0", "native.prometheus-exposition"],
            "scanner_id": "native.web-check", "scanner_version": "1", "scanner_sha256": "e" * 64,
            "rule_sha256": modules["adapters.prometheus_exposition"], "product_revision": HEAD,
            "effective_budget": gate.BUDGET}
        findings = [{"rule_id": "native.prometheus-exposition", "path": path}] if index == 0 else []

        for filename, value in (("provisioning.json", source), ("worker-stdout.json", worker),
                                ("invocation.json", invocation), ("findings.json", findings)):
            WriteJson(scanner / filename, value)

        (scanner / "worker-stderr.json").write_bytes(b"")
        outcome = {"status": "completed", "exit_code": 0,
                   "duration_seconds": 0.05, "target_url": url}
        stdout = ExportBundle(scanner, outcome).encode()
        bundle = json.loads(stdout)
        (directory / "docker.stdout").write_bytes(stdout)
        (directory / "docker.stderr").write_bytes(b"")
        WriteJson(directory / "docker-exit.json", {"argv": ["docker", "start", "--attach",
            (str(index + 1) * 64)], "returncode": 0, "timed_out": False, "duration_seconds": 0.1,
            "stdout_sha256": gate.Digest(stdout), "stderr_sha256": gate.Digest(b"")})
        WriteJson(directory / "bundle-manifest.json", {"schema_version": 1, "outcome": outcome,
            "files": [{key: value for key, value in record.items() if key != "data_base64"}
                      for record in bundle["files"]]})
        control = HttpObservation("127.0.0.1", 3000, path, 200, (), body.decode(), "", False, 0.01)
        lab = SimpleNamespace(observations=[control], provenance={
            "container_id": str(index + 4) * 64,
            "platform_manifest_digest": target["platform_digests"]["linux/amd64"]})
        observation = runtime.Observation(case, directory, lab, outcome,
            control_sha256=None if index == 0 else gate.Digest(body))
        observations.append(observation)

    report = BuildComparison(pack, target, observations, runtime.output)
    WriteJson(runtime.output / "report.json", report)
    Junit(repository)

    return repository, runtime.output, report


def SaveReport(root: Path, report: dict) -> None:
    """Write a caller-mutated report without silently repairing its original role data."""

    WriteJson(root / "report.json", report)


def ChangeRole(root: Path, row: dict, role: str, value) -> None:
    """Update a host-side role with consistent size/hash to expose deeper semantic joins."""

    record = next(item for item in row["execution"]["evidence"] if item["role"] == role)
    selected = root / record["path"]
    WriteJson(selected, value)
    raw = selected.read_bytes()
    record.update(size_bytes=len(raw), sha256=gate.Digest(raw))


def test_ActualObservationProducerFitsReadOnlyGateWithoutScannerExecution(tmp_path):
    """Current producer bytes compose with the gate; inert data is never application acceptance."""

    repository, root, report = NativeGateFixture(tmp_path)
    before = {path: path.read_bytes() for path in repository.rglob("*") if path.is_file()}
    result = gate.Verify(repository, HEAD, TREE)
    assert result == {"executed_cases": 3, "fresh_targets": 3, "native_tp": 1, "native_tn": 2,
        "whole_application_accuracy": None, "source_revision": HEAD, "source_tree": TREE}, (
        "The gate must retain only finite three-case truth and explicit selected identities"
    )
    assert all(path.read_bytes() == raw for path, raw in before.items()), (
        "The original-evidence gate must never repair or rewrite acquired files"
    )


@pytest.mark.parametrize("mutation", ["skip", "failure", "error", "duplicate", "missing",
    "foreign-class", "counts", "doctype"])
def test_JunitCannotPromoteMissingSkippedOrForeignCases(tmp_path, mutation):
    """A successful workflow summary cannot replace three exact original test passes."""

    repository, _, _ = NativeGateFixture(tmp_path)
    path = repository / gate.ROOT / "pytest.xml"
    document = ElementTree.fromstring(path.read_bytes())
    suite = next(document.iter("testsuite"))
    cases = list(document.iter("testcase"))

    if mutation in {"skip", "failure", "error"}:
        ElementTree.SubElement(cases[0], "skipped" if mutation == "skip" else mutation)

    elif mutation == "duplicate":
        cases[1].set("name", cases[0].get("name"))

    elif mutation == "missing":
        suite.remove(cases[-1])

    elif mutation == "foreign-class":
        cases[0].set("classname", "tests.functional.health_smoke")

    elif mutation == "counts":
        suite.set("skipped", "1")

    raw = ElementTree.tostring(document)
    path.write_bytes(b'<!DOCTYPE testsuites [<!ENTITY value "inert">]>' + raw
                     if mutation == "doctype" else raw)

    with pytest.raises(ValueError):
        gate.Verify(repository, HEAD, TREE)


@pytest.mark.parametrize("key,value", [
    ("product_revision", "a" * 40), ("source_revision", "a" * 40),
    ("image_index_digest", "sha256:" + "a" * 64), ("platform_digest", "sha256:" + "a" * 64),
    ("target_url", "https://example.invalid/metrics"), ("reset_contract_sha256", "a" * 64),
    ("network_internal", False), ("published_ports", 1), ("request_count", True),
    ("exit_code", True), ("duration_seconds", 11), ("argv", ["healthcheck-only"]),
    ("scanner_id", "nuclei"), ("scanner_version", "unverified"),
    ("effective_budget", {**gate.BUDGET, "max_requests": 2}),
])
def test_ConsistentReportCannotWidenCurrentNativeCase(tmp_path, key, value):
    """The independent current-head profile refuses stale, broadened or non-executed inputs."""

    repository, root, report = NativeGateFixture(tmp_path)
    report["observations"][0]["execution"][key] = value
    SaveReport(root, report)

    with pytest.raises(ValueError):
        gate.Verify(repository, HEAD, TREE)


@pytest.mark.parametrize("mutation", ["missing-row", "duplicate-row", "missing-role",
    "duplicate-role", "wrong-case-role", "changed-role-bytes", "whole-score", "bad-counts",
    "wrong-kind", "failed", "role-alias"])
def test_OriginalReportRequiresExactDistinctCasesRolesAndFiniteScores(tmp_path, mutation):
    """Completion cannot be borrowed from another track, owner, role, case or aggregate score."""

    repository, root, report = NativeGateFixture(tmp_path)
    row = report["observations"][0]
    records = row["execution"]["evidence"]

    if mutation == "missing-row":
        report["observations"].pop()

    elif mutation == "duplicate-row":
        report["observations"][1] = copy.deepcopy(row)

    elif mutation == "missing-role":
        records.pop()

    elif mutation == "duplicate-role":
        records[-1] = copy.deepcopy(records[0])

    elif mutation == "wrong-case-role":
        records[0]["path"] = records[0]["path"].replace("metrics.exposed", "metrics.json-control")

    elif mutation == "changed-role-bytes":
        (root / records[0]["path"]).write_bytes(b"original byte corruption")

    elif mutation == "whole-score":
        report["whole_application_accuracy"] = 1.0

    elif mutation == "bad-counts":
        report["finite_completed_case_counts"]["native-engine"]["tp"] = 2

    elif mutation == "wrong-kind":
        row["scanner_track"] = "whole1337"

    elif mutation == "failed":
        row["status"] = "failed"

    elif mutation == "role-alias":
        record = records[0]
        alias = root / "metrics.exposed/scanner/alternate.json"
        alias.write_bytes((root / record["path"]).read_bytes())
        record["path"] = alias.relative_to(root).as_posix()

    SaveReport(root, report)

    with pytest.raises(ValueError):
        gate.Verify(repository, HEAD, TREE)


@pytest.mark.parametrize("key,value", [("basis", "invented"), ("approved_attempt_count", True),
    ("approved_attempt_count", 2), ("independent_server_contact_count", 1),
    ("scanner_source_revision", "a" * 40), ("scanner_image_id", "unattributed")])
def test_OriginalAttemptMutationCannotInventContactOrSourceProof(tmp_path, key, value):
    """A repaired hash does not authorize changing attempt meaning or installed attribution."""

    repository, root, report = NativeGateFixture(tmp_path)
    row = report["observations"][0]
    attempt = gate.Json(root, "metrics.exposed/attempt-provenance.json")
    attempt[key] = value
    ChangeRole(root, row, "attempt-provenance", attempt)
    SaveReport(root, report)

    with pytest.raises(ValueError):
        gate.Verify(repository, HEAD, TREE)


def test_SeparateControlCannotBorrowAWorkerVerdictWithoutItsOriginalBody(tmp_path):
    """A negative case requires the independently acquired real media/body control identity."""

    repository, root, report = NativeGateFixture(tmp_path)
    row = report["observations"][1]
    attempt = gate.Json(root, "metrics.json-control/attempt-provenance.json")
    attempt["fixture_http_probes"][-1]["body"] = "unrelated fixture text"
    ChangeRole(root, row, "attempt-provenance", attempt)
    SaveReport(root, report)

    with pytest.raises(ValueError, match="separate genuine"):
        gate.Verify(repository, HEAD, TREE)


def test_FreshTargetIdentityCannotBeReusedWithRepairedRoleHashes(tmp_path):
    """Three current cases require three independently restored target identities."""

    repository, root, report = NativeGateFixture(tmp_path)
    row = report["observations"][1]
    instance = report["observations"][0]["execution"]["target_instance"]
    row["execution"]["target_instance"] = instance
    provenance = gate.Json(root, "metrics.json-control/target-provenance.json")
    provenance["target_instance"] = instance
    ChangeRole(root, row, "target-provenance", provenance)
    SaveReport(root, report)

    with pytest.raises(ValueError, match="distinct fresh"):
        gate.Verify(repository, HEAD, TREE)


@pytest.mark.parametrize("key,value", [("check_id", "native.git-head-exposure"),
    ("url", "http://127.0.0.1:3000/metrics"), ("status", 500), ("matched", True),
    ("media_type", "text/plain")])
def test_OriginalWorkerMustAssessItsExactNativeControl(tmp_path, key, value):
    """A repaired acquisition hash cannot substitute a different check, endpoint or verdict."""

    repository, root, report = NativeGateFixture(tmp_path)
    row = report["observations"][1]
    worker = gate.Json(root, "metrics.json-control/scanner/worker-stdout.json")
    worker[key] = value
    ChangeRole(root, row, "stdout", worker)
    SaveReport(root, report)

    with pytest.raises(ValueError, match="exact complete finite response"):
        gate.Verify(repository, HEAD, TREE)


@pytest.mark.parametrize("mutation", ["cell-score", "other-completed", "other-counts",
    "missing-cell", "bool-count", "pairwise"])
def test_FiniteSummaryCannotFabricateOtherTrackOrWholeApplicationCredit(tmp_path, mutation):
    """The display matrix and counts remain exact consequences of native-only observations."""

    repository, root, report = NativeGateFixture(tmp_path)

    if mutation == "cell-score":
        report["cells"][0]["score"] = "tn"

    elif mutation == "other-completed":
        next(cell for cell in report["cells"] if cell["scanner_track"] == "whole1337")[
            "status"] = "completed"

    elif mutation == "other-counts":
        report["finite_completed_case_counts"]["whole1337"].update(tp=1, unscored=2)

    elif mutation == "missing-cell":
        report["cells"].pop()

    elif mutation == "bool-count":
        report["finite_completed_case_counts"]["native-engine"]["tp"] = True

    elif mutation == "pairwise":
        report["pairwise_conditions"] = [{"equal_budget_and_reset": True}]

    SaveReport(root, report)

    with pytest.raises(ValueError):
        gate.Verify(repository, HEAD, TREE)


@pytest.mark.parametrize("mutation", ["source", "runner", "wheel-member", "wheel-hash"])
def test_InstalledReceiptMustJoinActualCurrentSourceAndWheelBytes(tmp_path, mutation):
    """Consistent replacement metadata cannot substitute for the current wheel members."""

    repository, root, report = NativeGateFixture(tmp_path)
    row = report["observations"][0]
    evidence = {record["role"]: gate.Read(root, record["path"])
                for record in row["execution"]["evidence"]}
    source = gate.Decode(evidence["installed-source"])

    if mutation == "source":
        module = repository / "src/fuzzy1337/native_web.py"
        module.write_bytes(module.read_bytes() + b"\n# current source changed\n")

    elif mutation == "runner":
        runner = repository / "tests/functional/external_native_runner.py"
        runner.write_bytes(runner.read_bytes() + b"\n# current runner changed\n")

    elif mutation == "wheel-member":
        evidence["installed-wheel"] = FixtureWheel(repository, changed="native_web")
        source["wheel"].update(size_bytes=len(evidence["installed-wheel"]),
                                sha256=gate.Digest(evidence["installed-wheel"]))
        evidence["installed-source"] = json.dumps(source).encode()

    elif mutation == "wheel-hash":
        source["wheel"]["sha256"] = "f" * 64
        evidence["installed-source"] = json.dumps(source).encode()

    with pytest.raises(ValueError):
        gate.VerifyInstalled(repository, evidence, HEAD)


@pytest.mark.parametrize("mutation", ["attachment", "exit", "manifest", "bundle-file"])
def test_OriginalDockerAttachmentMustAgreeWithEveryRetainedExportedByte(tmp_path, mutation):
    """A normalized report cannot replace the original finite process-byte attachment."""

    repository, root, report = NativeGateFixture(tmp_path)
    directory = root / "metrics.exposed"

    if mutation == "attachment":
        (directory / "docker.stdout").write_bytes(b"corrupt original attachment")

    elif mutation == "exit":
        exited = gate.Json(directory, "docker-exit.json")
        exited["timed_out"] = True
        WriteJson(directory / "docker-exit.json", exited)

    elif mutation == "manifest":
        manifest = gate.Json(directory, "bundle-manifest.json")
        manifest["files"].pop()
        WriteJson(directory / "bundle-manifest.json", manifest)

    elif mutation == "bundle-file":
        bundle = gate.Decode((directory / "docker.stdout").read_bytes())
        bundle["files"][0]["data_base64"] = "%%%"
        raw = json.dumps(bundle).encode()
        (directory / "docker.stdout").write_bytes(raw)
        exited = gate.Json(directory, "docker-exit.json")
        exited["stdout_sha256"] = gate.Digest(raw)
        WriteJson(directory / "docker-exit.json", exited)

    with pytest.raises(ValueError):
        gate.Verify(repository, HEAD, TREE)


@pytest.mark.parametrize("path", ["../outside", "/absolute", "a//b", "a/./b", "a\\b", "C:alias"])
def test_OriginalReadCannotEscapeOrAliasItsFiniteOwner(tmp_path, path):
    """Cross-platform path aliases are refused before any referenced bytes can be read."""

    with pytest.raises(ValueError, match="path"):
        gate.Read(tmp_path, path)


def test_OriginalReadRejectsHardlinksAndSymbolicLinks(tmp_path):
    """Existing external bytes cannot be admitted through an aliased acquisition pathname."""

    original = tmp_path / "original"
    original.write_bytes(b"inert original")
    linked = tmp_path / "linked"
    os.link(original, linked)

    with pytest.raises(ValueError, match="aliased"):
        gate.Read(tmp_path, "linked")

    linked.unlink()

    try:
        linked.symlink_to(original)

    except OSError:
        pytest.skip("This platform does not permit unprivileged symbolic link creation")

    with pytest.raises(ValueError, match="linked"):
        gate.Read(tmp_path, "linked")


def test_OriginalReadAppliesItsActualCompleteByteCeiling(tmp_path):
    """The reader accepts an exact bound and refuses the next actual byte without truncation."""

    (tmp_path / "original").write_bytes(b"abc")
    assert gate.Read(tmp_path, "original", 3) == b"abc", (
        "An exact permitted original must remain byte-complete"
    )

    with pytest.raises(ValueError, match="oversized"):
        gate.Read(tmp_path, "original", 2)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}'])
def test_OriginalJsonRejectsAmbiguousAndNonfiniteFacts(raw):
    """Neither duplicate source keys nor numeric overflow may silently replace original facts."""

    with pytest.raises(ValueError):
        gate.Decode(raw)


def test_StaleOrMultipleEvidenceOwnersCannotBeSelectedAsLatest(tmp_path):
    """The gate refuses ambiguous previous runs instead of choosing a convenient passing report."""

    repository, root, _ = NativeGateFixture(tmp_path)
    (root.parent / "run-aaaaaaaaaaaa").mkdir()

    with pytest.raises(ValueError, match="exactly one"):
        gate.Verify(repository, HEAD, TREE)


def test_StandaloneGateCliBindsSourceIdentityAndWritesOnlyItsFiniteSummary(tmp_path):
    """The actual command consumes only retained fixtures and refuses a foreign workflow head."""

    repository, _, _ = NativeGateFixture(tmp_path)
    script = REPOSITORY / "tests/functional/external_native_acceptance_gate.py"
    arguments = [sys.executable, str(script), "--head", HEAD, "--identity", HEAD + "\n" + TREE]
    result = subprocess.run(arguments, cwd=repository, capture_output=True, check=False, timeout=10)
    assert result.returncode == 0 and json.loads(result.stdout)["executed_cases"] == 3, (
        "The actual read-only gate CLI must accept the complete producer-shaped fixture"
    )
    arguments[-1] = "a" * 40 + "\n" + TREE
    refused = subprocess.run(arguments, cwd=repository, capture_output=True,
                             check=False, timeout=10)
    assert refused.returncode != 0 and refused.stdout == b"", (
        "A foreign checked-out head cannot emit a successful acceptance summary"
    )
