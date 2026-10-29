# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify one original installed IPv6 worker artifact; no SDK or scanner-effectiveness credit.

The original Build records the whole-wheel digest and nine member/import hashes. The wheel
archive itself is not retained, so this checker cannot independently rehash that absent binary.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree

from tests.contract.owned_content_response_ci_denial_evidence import ReadJson
from tests.contract.owned_content_response_product_runner import (
    CASES,
    AbsoluteRuntimePath,
    AssertContentInstallation,
    AssertContentLauncherEvidence,
    AssertContentSourceFacts,
    AssertOriginalTerminalProcess,
)
from tests.contract.owned_content_response_sdk_entrypoint import BoundedRead
from tests.contract.owned_content_response_worker_launcher import IMPORT_PROBE, WORKER_TIMEOUT

CASE_NAME = "test_InstalledMissingHeaderContentWorkerIpv6RetainsOriginalsAndSettledOwners"
CASE_CLASS = "tests.functional.test_owned_content_response_sdk_pipeline"
CASE_DIRECTORY = "ipv6-worker-missing"
CREDIT = "installed-worker-only"


def Require(condition: bool, message: str) -> None:
    """Reject a missing original invariant without repairing evidence or changing its meaning.

    Args:
        condition: Exact predicate over original observations and independently selected inputs.
        message: Fixed actionable diagnostic without response or rejected input content.

    Raises:
        ValueError: The required original invariant is false.
    """

    if not condition:
        raise ValueError(message)


def Canonical(value: object) -> bytes:
    """Encode the unchanged original NativeCaseEvidence JSON serialization for digest joins.

    Args:
        value: Explicit parsed original JSON document, never an expected runtime substitute.

    Returns:
        Canonical ASCII JSON without nonfinite numbers or trailing bytes.
    """

    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def RequireProcess(directory: Path, argv: tuple[str, ...], cwd: str, timeout: int,
    installation: dict | None = None) -> tuple[dict, bytes, bytes]:
    """Join exact original prelaunch, terminal and complete stdout/stderr streams.

    Args:
        directory: Fixed retained process namespace, never a path followed from artifact values.
        argv: Independently selected fixed operation and original interpreter.
        cwd: Exact original operation directory, without rewriting its recorded path.
        timeout: Fixed source-owned finite process bound.
        installation: Original installation envelope, absent for initial build operations.

    Returns:
        Actual terminal metadata and complete bounded original stdout/stderr bytes.

    Raises:
        ValueError: A prelaunch, terminal, source selection or return status differs.
        AssertionError: The unchanged original-stream oracle rejects missing/truncated evidence.
        OSError: A required original stream or record is missing.
    """

    invocation, process = (ReadJson(directory / name) for name in (
        "invocation.json", "process.json"))
    stdout, stderr = (BoundedRead(directory / name, 1024 * 1024) for name in (
        "stdout.bin", "stderr.bin"))
    Require(invocation == {"schema_version": 1, "argv": list(argv), "cwd": cwd,
        "timeout_seconds": timeout, "stdin": "closed-devnull", "state": "not-launched",
        "returncode": None, "terminal_return_observed": False, "installation": installation},
        "Original fixed prelaunch operation or installation differs")
    Require(type(invocation["schema_version"]) is int and type(
        invocation["timeout_seconds"]) is int, "Prelaunch schema and budget need exact integers")
    Require(all(process[key] == invocation[key] for key in (
        "cwd", "timeout_seconds", "installation")) and type(process["timeout_seconds"]) is int,
        "Terminal directory, fixed budget and installation must retain original selection")
    Require(set(process) == set(invocation) | {"stdout", "stderr"},
        "Successful original process metadata cannot contain extra claims or exception fields")
    AssertOriginalTerminalProcess(process, stdout, stderr, argv=argv)
    Require(process["returncode"] == 0,
        "Every selected original installation/worker process must pass")

    return process, stdout, stderr


def RequireInstallation(directory: Path, selected: dict) -> tuple[dict, dict]:
    """Verify clean-source, offline build/install and actual nine-module isolated import facts.

    Args:
        directory: Fixed original installation artifact namespace shared by the unchanged fixture.
        selected: Independent worker selection with full source commit/tree and installed Python.

    Returns:
        Original installation envelope and original isolated import probe document.

    Raises:
        ValueError: A clean checkpoint, fixed build/install operation or manifest join differs.
        AssertionError: Existing source/wheel/import or original process checks fail.
    """

    identity = ReadJson(directory / "wheel-identity.json")
    Require(type(identity["schema_version"]) is int and identity["schema_version"] == 1,
        "The original wheel identity requires its exact schema integer")
    checkpoint = ReadJson(directory / "source-checkpoint.json")
    envelope = ReadJson(directory / "installation-envelope.json")
    Require(checkpoint == {key: identity[key] for key in (
        "schema_version", "source_commit", "source_tree", "source_modules_sha256")},
        "Original source checkpoint must bind the exact wheel module identities")
    Require(set(envelope) == {"identity", "manifest_sha256"} and envelope["manifest_sha256"] == (
        hashlib.sha256(Canonical(envelope["identity"])).hexdigest()),
        "Original installation manifest digest must reconcile")
    python = selected["python"]
    AbsoluteRuntimePath(python)
    prefix = PurePosixPath(python).parent.parent
    Require(python == str(prefix / "bin/python"),
        "This fixture requires its exact installed Linux Python")
    install_root = prefix.parent
    wheel_name = identity["wheel_name"]
    Require(type(wheel_name) is str and PurePosixPath(wheel_name).name == wheel_name and (
        wheel_name.endswith(".whl")),
        "The original wheel name must be one literal artifact basename")
    wheel = str(install_root / "wheel" / wheel_name)
    first = ReadJson(directory / "process-001-selected-checkpoint/invocation.json")
    source_root = first["cwd"]
    AbsoluteRuntimePath(source_root)
    built = ReadJson(directory / "process-004-build/invocation.json")
    host_python = built["argv"][0]
    AbsoluteRuntimePath(host_python)
    rows = (
        ("selected-checkpoint", ("git", "rev-parse", "HEAD", "HEAD^{tree}"), source_root, 5),
        ("source-status", ("git", "status", "--porcelain"), source_root, 5),
        ("source-checkpoint", ("git", "rev-parse", "HEAD", "HEAD^{tree}"), source_root, 5),
        ("build", (host_python, "-m", "build", "--wheel", "--no-isolation", "--outdir",
            str(install_root / "wheel")), source_root, 40),
        ("create-interpreter", (host_python, "-m", "venv", str(prefix)), str(install_root), 40),
        ("install", (python, "-I", "-B", "-m", "pip", "--isolated", "install", "--no-index",
            "--no-deps", "--no-compile", "--disable-pip-version-check", wheel),
            str(install_root), 40),
        ("import-probe", (python, "-I", "-B", "-c", IMPORT_PROBE), str(install_root), 10),
        ("source-status-final", ("git", "status", "--porcelain"), source_root, 5),
        ("source-checkpoint-final", ("git", "rev-parse", "HEAD", "HEAD^{tree}"), source_root, 5),
    )
    imported = None

    for index, (label, argv, cwd, timeout) in enumerate(rows, start=1):
        _, stdout, stderr = RequireProcess(directory / f"process-{index:03d}-{label}",
            argv, cwd, timeout)

        if "checkpoint" in label:
            Require(stdout.decode("ascii").split() == [selected["source_commit"],
                selected["source_tree"]],
                "All original selected checkpoints must bind the same tree")

        elif label.startswith("source-status"):
            Require(stdout == b"",
                "Original source must remain clean before and after installation")

        elif label == "import-probe":
            imported = json.loads(stdout)
            Require(stderr == b"" and Canonical(imported) == stdout,
                "Actual isolated import probe must be complete, canonical and free of diagnostics")

    Require(len(list(directory.glob("process-*"))) == 9,
        "Only the original nine fixed installation/checkpoint processes may accompany this case")
    AssertContentInstallation(identity, imported,
        commit=selected["source_commit"], tree=selected["source_tree"])
    Require(envelope["identity"] == {
        **identity, "installed_sources": imported["installed_sources"]},
        "Worker installation must retain the actual original wheel and isolated import identity")
    Require(all(PurePosixPath(row["path"]).is_relative_to(prefix)
        for row in imported["installed_sources"].values()),
        "All nine actual imports must belong to the selected installed environment")

    return envelope, imported


def RequireOutcome(junit: Path, retained: Path) -> dict:
    """Require one original IPv6 worker pass and exact installation, wire, peer and cleanup facts.

    Args:
        junit: Explicit original one-case JUnit, never a rerun or combined cohort report.
        retained: Original owned-content-sdk evidence root; artifact path values are never followed.

    Returns:
        Original worker-only result after all existing handwritten/source/process oracles pass.

    Raises:
        ValueError: The selected JUnit, IPv6 case or original artifact joins are not exact.
        AssertionError: Existing immutable wire/source/installation oracles reject the evidence.
        OSError: Required original artifacts or complete streams are missing.
    """

    document = ElementTree.fromstring(BoundedRead(junit, 1024 * 1024))
    suites, cases = list(document.iter("testsuite")), list(document.iter("testcase"))
    Require(len(suites) == len(cases) == 1 and all(suites[0].get(key) == value for key, value in (
        ("tests", "1"), ("failures", "0"), ("errors", "0"), ("skipped", "0"))) and (
        cases[0].get("name") == CASE_NAME and cases[0].get("classname") == CASE_CLASS
        and not any(list(document.iter(kind)) for kind in ("failure", "error", "skipped"))),
        "One selected original IPv6 worker testcase must pass without skips/errors/failures")
    matches = list(retained.glob("run-*/ipv6-worker-missing/worker-result.json"))
    Require(len(matches) == 1, "Exactly one original IPv6 worker result is required")
    case = matches[0].parent
    selected = ReadJson(case / "worker-selection.json")
    Require(set(selected) == {"schema_version", "worker_case", "address", "credit", "source_commit",
        "source_tree", "python"} and type(selected["schema_version"]) is int and (
        selected["schema_version"] == 1 and selected["worker_case"] == "missing"
        and selected["address"] == "::1" and selected["credit"] == CREDIT),
        "Only the explicit missing-header installed IPv6 worker boundary is selected")
    result = ReadJson(matches[0])
    Require(set(result) == {"schema_version", "state", "credit", "result"} and type(
        result["schema_version"]) is int and result["schema_version"] == 1 and (
        result["state"] == "checked-ipv6-worker-original" and result["credit"] == CREDIT),
        "Worker evidence cannot claim SDK authority, Findings or a different acceptance scope")
    actual = result["result"]
    Require(set(actual) == {"installation", "process", "sources", "source_delivery", "worker_case",
        "address", "evidence_paths"} and actual["worker_case"] == "missing" and (
        actual["address"] == "::1" and actual["source_delivery"] == "normal-eof"),
        "No IPv4 fallback, refused worker or incomplete source may satisfy this case")
    installation, imported = RequireInstallation(case.parent / "installation", selected)
    main, sentinel = (ReadJson(case / (name + "-source-final.json"))
        for name in ("main", "sentinel"))
    Require(actual["installation"] == installation and actual["sources"] == {
        "main": main, "sentinel": sentinel},
        "Aggregate result must retain the original independent owners")

    for name, record in (("main", main), ("sentinel", sentinel)):
        Require(ReadJson(case / name / "content-source-final.json") == record,
            "Copied source final must equal the original independently retained owner record")
        Require(record["origin"].startswith("http://[::1]:"),
            "Both owned sources must use literal IPv6")

    url = main["origin"] + CASES["missing"].path
    worker = case / "worker/process-001-worker"
    Require(set(case.rglob("process-*")) == {worker},
        "No extra SDK, helper or repeated worker process may accompany this worker-only case")
    paths = actual["evidence_paths"]
    Require(set(paths) == {"local", "retained", "main_final", "sentinel_final", "worker_process"},
        "Original retained/local artifact ownership fields must remain closed")
    local = AbsoluteRuntimePath(paths["local"])
    Require(paths["main_final"] == str(local / "main/content-source-final.json") and (
        paths["sentinel_final"] == str(local / "sentinel/content-source-final.json")
        and paths["worker_process"] == str(local / "worker/process-001-worker/process.json")),
        "Original evidence paths must join the one selected worker/source owner")
    retained_path = AbsoluteRuntimePath(paths["retained"])
    Require(retained_path.parts[-3:] == ("owned-content-sdk", case.parent.name, CASE_DIRECTORY),
        "Original retained case identity must survive relocation of the artifact archive")
    argv = (selected["python"], "-I", "-B", "-m", "fuzzy1337.owned_content_response_worker", url)
    process, stdout, stderr = RequireProcess(worker, argv, str(local / "launch"),
        WORKER_TIMEOUT, installation)
    Require(len(list((case / "worker").glob("process-*"))) == 1 and actual["process"] == process,
        "Only one original worker process may establish this result; retries are forbidden")
    AssertContentLauncherEvidence("missing", url, installation, imported,
        ReadJson(worker / "invocation.json"), process, stdout, stderr,
        commit=selected["source_commit"], tree=selected["source_tree"], python=selected["python"],
        cwd=str(local / "launch"), timeout_seconds=WORKER_TIMEOUT)
    Require(AssertContentSourceFacts("missing", url, main, sentinel,
        sentinel_origin=sentinel["origin"]) == "normal-eof",
        "Actual IPv6 peers and owners must settle")

    return result


def Main(arguments: list[str] | None = None) -> int:
    """Check explicitly retained originals without launching the worker, targets or SDK.

    Args:
        arguments: Exactly the original selected JUnit and owned evidence root.

    Returns:
        Zero after the one original installed worker boundary passes every check.

    Raises:
        ValueError: Exactly two explicit original evidence paths were not supplied.
    """

    args = sys.argv[1:] if arguments is None else arguments
    Require(len(args) == 2, "Expected original IPv6 worker JUnit and evidence root")
    RequireOutcome(Path(args[0]), Path(args[1]))
    print("Required original IPv6 installed worker: 1 passed, 0 skipped; worker boundary only")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
