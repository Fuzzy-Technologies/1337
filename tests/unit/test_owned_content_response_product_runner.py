# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Mocked acceptance-helper contracts only; no target, worker, build or installed runtime."""

from __future__ import annotations

import copy
import hashlib

import pytest

from tests.contract.owned_content_response_oracle import CaseMatrix
from tests.contract.owned_content_response_product_runner import (
    SOURCE_MODULES,
    AssertContentInstallation,
    AssertContentWorkerCase,
    AssertWorkerCohort,
    WorkerCaseIdentities,
)

PYTHON = "/owned/environment/bin/python"
COMMIT = "1" * 40
TREE = "2" * 40


def Process(stdout: bytes, url: str, code: int) -> dict:
    """Author mocked terminal metadata without launching or claiming an actual process."""

    result = {"schema_version": 1, "state": "returned", "terminal_return_observed": True,
        "returncode": code, "stdin": "closed-devnull", "argv": [PYTHON, "-I", "-B", "-m",
            "fuzzy1337.owned_content_response_worker", url]}

    for role, raw in (("stdout", stdout), ("stderr", b"")):
        result[role] = {"observed": True, "complete_original": True, "timeout_prefix": False,
            "retention_overflow": False, "observed_size_bytes": len(raw),
            "retained_size_bytes": len(raw), "observed_sha256": hashlib.sha256(raw).hexdigest()}

    return result


@pytest.mark.parametrize("case", CaseMatrix(), ids=lambda case: case.name)
@pytest.mark.parametrize("authority", ["127.0.0.1:15432", "[::1]:15432"])
def test_WorkerOracleChecksAdmittedAndRefusedOriginalShapesWithoutExecution(case, authority):
    """All expected source variants exercise pure shape checks, never genuine case acceptance."""

    url = f"http://{authority}{case.path}"
    stdout = case.ExpectedStdout(url)
    process = Process(stdout, url, 0 if case.error is None else 2)
    AssertContentWorkerCase(case.name, url, process, stdout, b"", python=PYTHON)


@pytest.mark.parametrize("mutation", ["timeout", "missing-terminal", "prefix", "overflow",
    "digest", "size", "exit", "argv", "foreign-original", "stderr"])
def test_OriginalWorkerFactsRefuseControlFailuresAndSubstitutedBytes(mutation):
    """No timeout prefix, changed command, foreign wire or invented terminal can satisfy a case."""

    case = next(case for case in CaseMatrix() if case.name == "missing")
    url = f"http://127.0.0.1:15432{case.path}"
    stdout, stderr = case.ExpectedStdout(url), b""
    process = Process(stdout, url, 0)

    if mutation == "timeout":
        process["state"] = "timeout"

    elif mutation == "missing-terminal":
        process["terminal_return_observed"] = False

    elif mutation in ("prefix", "overflow"):
        process["stdout"]["timeout_prefix" if mutation == "prefix" else "retention_overflow"] = True

    elif mutation == "digest":
        process["stdout"]["observed_sha256"] = "0" * 64

    elif mutation == "size":
        process["stdout"]["retained_size_bytes"] -= 1

    elif mutation == "exit":
        process["returncode"] = 2

    elif mutation == "argv":
        process["argv"].remove("-I")

    elif mutation == "foreign-original":
        stdout = b"{}"
        process = Process(stdout, url, 0)

    else:
        stderr = b"unexpected diagnostic"

    with pytest.raises(AssertionError):
        AssertContentWorkerCase(case.name, url, process, stdout, stderr, python=PYTHON)


def Installation() -> tuple[dict, dict]:
    """Create clearly mocked source/wheel/import identities without reading any runtime."""

    modules = {name: hashlib.sha256(name.encode()).hexdigest() for name in SOURCE_MODULES}
    identity = {"schema_version": 1, "source_commit": COMMIT, "source_tree": TREE,
        "source_modules_sha256": modules, "wheel_modules_sha256": dict(modules),
        "wheel_size_bytes": 123, "wheel_sha256": "a" * 64, "distribution_version": "0.0.mock"}
    imported = {"distribution_version": "0.0.mock", "installed_sources": {name: {
        "path": "/owned/environment/lib/python3.12/site-packages/fuzzy1337/" + name,
        "sha256": digest} for name, digest in modules.items()}}

    return identity, imported


def test_ExactPinnedSourceWheelAndInstalledModuleBinding():
    """Pure identity reconciliation requires all fixed modules from one installed package."""

    identity, imported = Installation()
    AssertContentInstallation(identity, imported, commit=COMMIT, tree=TREE)
    identities = WorkerCaseIdentities()
    assert len(identities) == 118 and len(set(identities)) == len(identities), (
        "The frozen matrix requires 59 distinct worker cases in each literal family")


@pytest.mark.parametrize("mutation", [None, "missing", "duplicate", "foreign", "skipped",
    "failed", "xfail"])
def test_WorkerCohortRequiresEachExactIdentityWithZeroSkips(mutation):
    """Reported cohort completeness never converts an omitted or nonpassing identity to green."""

    results = [{"identity": identity, "status": "passed"} for identity in WorkerCaseIdentities()]

    if mutation is None:
        AssertWorkerCohort(results)

        return

    if mutation == "missing":
        results.pop()

    elif mutation == "duplicate":
        results[-1] = dict(results[0])

    elif mutation == "foreign":
        results[0]["identity"] = "worker:foreign:not-the-matrix"

    else:
        results[0]["status"] = mutation

    with pytest.raises(AssertionError):
        AssertWorkerCohort(results)


@pytest.mark.parametrize("mutation", ["tree", "wheel", "import", "missing", "checkout",
    "mixed-root", "relative", "version"])
def test_SourceWheelImportMismatchCannotBecomeInstalledAcceptance(mutation):
    """Source drift, missing owners and import fallback remain explicit failures."""

    identity, imported = copy.deepcopy(Installation())
    name = SOURCE_MODULES[0]

    if mutation == "tree":
        identity["source_tree"] = "3" * 40

    elif mutation == "wheel":
        identity["wheel_modules_sha256"][name] = "b" * 64

    elif mutation == "import":
        imported["installed_sources"][name]["sha256"] = "c" * 64

    elif mutation == "missing":
        del imported["installed_sources"][name]

    elif mutation == "version":
        imported["distribution_version"] = "other"

    else:
        prefix = {"checkout": "/checkout/src/fuzzy1337/",
            "mixed-root": "/other/site-packages/fuzzy1337/",
            "relative": "relative/site-packages/fuzzy1337/"}[mutation]
        imported["installed_sources"][name]["path"] = prefix + name

    with pytest.raises(AssertionError):
        AssertContentInstallation(identity, imported, commit=COMMIT, tree=TREE)
