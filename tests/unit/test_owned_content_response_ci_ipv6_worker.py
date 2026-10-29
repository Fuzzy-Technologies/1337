# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Synthetic IPv6 worker artifact and adapter checks; no build, SDK, process or target executes."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.contract import owned_content_response_ci_ipv6_worker_evidence as checker
from tests.contract import owned_content_response_worker_launcher as launcher
from tests.functional import test_owned_content_response_sdk_pipeline as functional
from tests.unit.test_owned_content_response_product_runner import Installation, Process, SourceFacts


def Fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict]:
    """Construct clearly synthetic original-style records without launching any operation.

    Args:
        tmp_path: Explicit disposable root for inert JSON/XML/stream artifacts.

    Returns:
        Synthetic one-case JUnit, retained root, case directory and mutable artifact mapping.
    """

    identity, imported = Installation()
    identity["wheel_name"] = "1337-0.0.mock-py3-none-any.whl"
    envelope = {"identity": {**identity, "installed_sources": imported["installed_sources"]}}
    envelope["manifest_sha256"] = hashlib.sha256(
        checker.Canonical(envelope["identity"])).hexdigest()
    selected = {"schema_version": 1, "worker_case": "missing", "address": "::1",
        "credit": checker.CREDIT, "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"], "python": "/owned/environment/bin/python"}
    local = "/mock-only/case"
    _, url, main, sentinel, _ = SourceFacts("missing", "::1")
    original_worker = Process(launcher.CASES["missing"].ExpectedStdout(url), url, 0)
    original_worker.update(cwd=local + "/launch", timeout_seconds=10, installation=envelope)
    result = {"installation": envelope, "process": original_worker,
        "sources": {"main": main, "sentinel": sentinel}, "source_delivery": "normal-eof",
        "worker_case": "missing", "address": "::1", "evidence_paths": {"local": local,
            "retained": "/mock-only/owned-content-sdk/run-unit-only/ipv6-worker-missing",
            "main_final": local + "/main/content-source-final.json",
            "sentinel_final": local + "/sentinel/content-source-final.json",
            "worker_process": local + "/worker/process-001-worker/process.json"}}
    documents = {"worker-selection.json": selected, "worker-result.json": {"schema_version": 1,
        "state": "checked-ipv6-worker-original", "credit": checker.CREDIT, "result": result},
        "main-source-final.json": main, "main/content-source-final.json": copy.deepcopy(main),
        "sentinel-source-final.json": sentinel,
        "sentinel/content-source-final.json": copy.deepcopy(sentinel),
        "../installation/wheel-identity.json": identity,
        "../installation/installation-envelope.json": envelope,
        "../installation/source-checkpoint.json": {key: identity[key] for key in (
            "schema_version", "source_commit", "source_tree", "source_modules_sha256")}}

    def Add(prefix: str, argv: tuple[str, ...], cwd: str, timeout: int, stdout: bytes,
        installed: dict | None = None) -> None:
        """Add only marked synthetic complete process/stream records to the inert artifact.

        Args:
            prefix: Fixed synthetic process namespace under this test's owned artifact.
            argv: Independently authored exact fake command, never executed.
            cwd: Original-style fake absolute operation directory.
            timeout: Declared finite fake process bound.
            stdout: Explicit synthetic complete stdout bytes.
            installed: Synthetic manifest envelope for the one worker process only.
        """

        terminal = original_worker if installed is not None else Process(stdout, url, 0)
        terminal.update(argv=list(argv), cwd=cwd, timeout_seconds=timeout, installation=installed)
        documents[prefix + "/process.json"] = terminal
        documents[prefix + "/invocation.json"] = {"schema_version": 1, "argv": list(argv),
            "cwd": cwd, "timeout_seconds": timeout, "stdin": "closed-devnull",
            "state": "not-launched", "returncode": None, "terminal_return_observed": False,
            "installation": installed}
        documents[prefix + "/stdout.bin"] = stdout
        documents[prefix + "/stderr.bin"] = b""

    checkpoint = (identity["source_commit"] + "\n" + identity["source_tree"] + "\n").encode()
    commands = (
        ("selected-checkpoint", ("git", "rev-parse", "HEAD", "HEAD^{tree}"),
            "/source", 5, checkpoint),
        ("source-status", ("git", "status", "--porcelain"), "/source", 5, b""),
        ("source-checkpoint", ("git", "rev-parse", "HEAD", "HEAD^{tree}"),
            "/source", 5, checkpoint),
        ("build", ("/host/bin/python", "-m", "build", "--wheel", "--no-isolation", "--outdir",
            "/owned/wheel"), "/source", 40, b"synthetic build log"),
        ("create-interpreter", ("/host/bin/python", "-m", "venv", "/owned/environment"),
            "/owned", 40, b""),
        ("install", (selected["python"], "-I", "-B", "-m", "pip", "--isolated", "install",
            "--no-index", "--no-deps", "--no-compile", "--disable-pip-version-check",
            "/owned/wheel/" + identity["wheel_name"]), "/owned", 40, b"synthetic install log"),
        ("import-probe", (selected["python"], "-I", "-B", "-c", launcher.IMPORT_PROBE),
            "/owned", 10, checker.Canonical(imported)),
        ("source-status-final", ("git", "status", "--porcelain"), "/source", 5, b""),
        ("source-checkpoint-final", ("git", "rev-parse", "HEAD", "HEAD^{tree}"),
            "/source", 5, checkpoint),
    )

    for index, (label, argv, cwd, timeout, stdout) in enumerate(commands, start=1):
        Add(f"../installation/process-{index:03d}-{label}", argv, cwd, timeout, stdout)

    Add("worker/process-001-worker", (selected["python"], "-I", "-B", "-m",
        "fuzzy1337.owned_content_response_worker", url), local + "/launch", 10,
        launcher.CASES["missing"].ExpectedStdout(url), envelope)
    junit = tmp_path / "ipv6.xml"
    junit.write_text('<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
        f'<testcase classname="{checker.CASE_CLASS}" name="{checker.CASE_NAME}"/>'
        '</testsuite></testsuites>')
    retained = tmp_path / "owned-content-sdk"

    return junit, retained, retained / "run-unit-only/ipv6-worker-missing", documents


def ReplaceStream(documents: dict, prefix: str, raw: bytes) -> None:
    """Keep a synthetic terminal digest consistent while attacking its underlying stdout meaning.

    Args:
        documents: Marked synthetic artifact mapping, never original runtime evidence.
        prefix: Explicit fixed process namespace from the fake artifact.
        raw: Replacement complete stdout used by this one inert negative test.
    """

    documents[prefix + "/stdout.bin"] = raw
    part = documents[prefix + "/process.json"]["stdout"]
    part.update(observed_size_bytes=len(raw), retained_size_bytes=len(raw),
        observed_sha256=hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize("mutation", [None, "skip", "hidden-skip", "wrong-case", "credit",
    "ipv4", "worker-argv", "worker-timeout", "worker-stream", "missing-stderr", "manifest",
    "dirty-before", "dirty-after", "checkpoint", "source-hash", "build-argv", "install-argv",
    "import-source", "extra-process", "peer", "sentinel", "cleanup", "source-wire",
    "copied-source", "retained-path", "extra-sdk-process", "schema", "process-schema"])
def test_SyntheticIpv6ArtifactRequiresOriginalSourceInstallationWireAndCleanup(
    tmp_path: Path, mutation: str | None,
) -> None:
    """Self-consistent synthetic metadata cannot replace this exact IPv6 installed-worker boundary.

    Args:
        tmp_path: Disposable unit-only artifact root.
        mutation: One independently rejected substitution, or None for an inert predicate pass.
    """

    junit, retained, case, documents = Fixture(tmp_path)
    actual = documents["worker-result.json"]["result"]
    worker = "worker/process-001-worker"

    if mutation == "skip":
        junit.write_text(junit.read_text().replace('skipped="0"', 'skipped="1"'))

    elif mutation == "hidden-skip":
        junit.write_text(junit.read_text().replace('/>', '><skipped/></testcase>'))

    elif mutation == "wrong-case":
        junit.write_text(junit.read_text().replace(checker.CASE_NAME, "unrelated_case"))

    elif mutation == "credit":
        documents["worker-result.json"]["credit"] = "SDK-authority-or-Finding"

    elif mutation == "ipv4":
        actual["address"] = "127.0.0.1"

    elif mutation == "worker-argv":
        actual["process"]["argv"][2] = "-E"
        documents[worker + "/invocation.json"]["argv"][2] = "-E"

    elif mutation == "worker-timeout":
        actual["process"]["timeout_seconds"] = 30
        documents[worker + "/invocation.json"]["timeout_seconds"] = 30

    elif mutation == "worker-stream":
        ReplaceStream(documents, worker, b"{}")

    elif mutation == "missing-stderr":
        del documents[worker + "/stderr.bin"]

    elif mutation == "manifest":
        actual["installation"]["manifest_sha256"] = "0" * 64

    elif mutation in ("dirty-before", "dirty-after"):
        label = "002-source-status" if mutation == "dirty-before" else "008-source-status-final"
        ReplaceStream(documents, "../installation/process-" + label, b" M source.py\n")

    elif mutation == "checkpoint":
        ReplaceStream(documents, "../installation/process-009-source-checkpoint-final",
            ("0" * 40 + "\n" + "2" * 40 + "\n").encode())

    elif mutation == "source-hash":
        documents["../installation/wheel-identity.json"]["source_modules_sha256"][
            launcher.SOURCE_MODULES[0]] = "0" * 64

    elif mutation == "build-argv":
        documents["../installation/process-004-build/invocation.json"]["argv"].remove("--no-isolation")

    elif mutation == "install-argv":
        documents["../installation/process-006-install/invocation.json"]["argv"].remove("--no-index")

    elif mutation == "import-source":
        prefix = "../installation/process-007-import-probe"
        imported = json.loads(documents[prefix + "/stdout.bin"])
        next(iter(imported["installed_sources"].values()))["path"] = "/checkout/module.py"
        ReplaceStream(documents, prefix, checker.Canonical(imported))

    elif mutation == "extra-process":
        documents["worker/process-002-worker/invocation.json"] = {}

    elif mutation == "extra-sdk-process":
        documents["process-002-sdk-capture/invocation.json"] = {}

    elif mutation == "process-schema":
        actual["process"]["SDK_authority"] = "unverified foreign claim"

    elif mutation == "schema":
        documents["../installation/wheel-identity.json"]["schema_version"] = True

    elif mutation == "peer":
        actual["sources"]["main"]["accepted_endpoints"]["0"]["peer_address"] = "127.0.0.1"
        documents["main/content-source-final.json"] = copy.deepcopy(actual["sources"]["main"])

    elif mutation == "sentinel":
        actual["sources"]["sentinel"]["counters"]["contacts"] = 1
        documents["sentinel/content-source-final.json"] = copy.deepcopy(
            actual["sources"]["sentinel"])

    elif mutation == "cleanup":
        actual["sources"]["main"]["cleanup_returned"] = False
        documents["main/content-source-final.json"] = copy.deepcopy(actual["sources"]["main"])

    elif mutation == "source-wire":
        actual["sources"]["main"]["contacts"][0]["response_hex"] = "00"
        documents["main/content-source-final.json"] = copy.deepcopy(actual["sources"]["main"])

    elif mutation == "copied-source":
        documents["main/content-source-final.json"]["cleanup_returned"] = False

    elif mutation == "retained-path":
        actual["evidence_paths"]["retained"] = "/mock-only/foreign/run/other-case"

    for name, value in documents.items():
        destination = case / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(value if type(value) is bytes else checker.Canonical(value))

    if mutation is None:
        result = checker.RequireOutcome(junit, retained)
        assert result["credit"] == checker.CREDIT, (
            "Synthetic evidence may claim only its worker boundary")

    else:
        with pytest.raises((AssertionError, ValueError, KeyError, OSError)):
            checker.RequireOutcome(junit, retained)


@pytest.mark.parametrize("unavailable", [False, True])
def test_AdapterCallsOnlyOriginalIpv6RunnerAndNeverSkipsOrFallsBack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unavailable: bool,
) -> None:
    """An explicit runner double tests only argument wiring and propagation, without any runtime.

    Args:
        tmp_path: Disposable original-style observation root.
        monkeypatch: Scoped replacement of the sole runner before the new adapter calls it.
        unavailable: Simulate an unavailable IPv6 listener; its failure must propagate once.
    """

    installed = SimpleNamespace(commit="1" * 40, tree="2" * 40,
        python=Path("/mock-only/environment/bin/python"))
    calls = []

    def Run(selected: object, **options: object) -> dict:
        """Observe fixed arguments only; never launch a worker or owned source.

        Args:
            selected: Exact marked synthetic installed fixture handle.
            options: Explicit original runner keyword selections from the adapter.

        Returns:
            Marked mock result for testing adapter control flow only.

        Raises:
            OSError: The unit scenario explicitly simulates unavailable IPv6.
        """

        calls.append(options)
        assert selected is installed and options["name"] == "missing" and (
            options["address"] == "::1" and options["enabled"] is True
        ), "Adapter must call only the unchanged exact IPv6 runner selection"

        if unavailable:
            raise OSError("synthetic IPv6 unavailable")

        return {"worker_case": "missing", "address": "::1", "source_delivery": "normal-eof"}

    monkeypatch.setattr(launcher, "Run", Run)
    fixture = (installed, tmp_path / "retained")

    if unavailable:
        with pytest.raises(OSError):
            functional.test_InstalledMissingHeaderContentWorkerIpv6RetainsOriginalsAndSettledOwners(
                fixture, tmp_path)

    else:
        functional.test_InstalledMissingHeaderContentWorkerIpv6RetainsOriginalsAndSettledOwners(
            fixture, tmp_path)

    assert len(calls) == 1, "An unavailable IPv6 fixture must not retry, skip or fall back to IPv4"
