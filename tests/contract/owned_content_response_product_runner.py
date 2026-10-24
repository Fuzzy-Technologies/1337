# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure first-slice acceptance checks; no launcher, fixture, installed runtime or enrollment.

These checks consume retained original facts only. Passing mocked contracts is not genuine
worker, SDK or header-v2 acceptance. The later opt-in runner must retain process evidence
before calling them and must independently prove both source owners actually settled.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from tests.contract.owned_content_response_oracle import CaseMatrix

SOURCE_MODULES = ("adapters/owned_content_response.py", "owned_content_response_worker.py",
    "adapters/owned_response_capture.py", "owned_response_capture.py",
    "owned_response_capture_worker.py", "owned_response_custody.py", "owned_response_workflow.py",
    "native_response_headers.py", "native_response_header_workflow.py")
CASES = {case.name: case for case in CaseMatrix()}
MAX_STDOUT_BYTES = 131072


def WorkerCaseIdentities() -> tuple[str, ...]:
    """Name every required matrix case in both families; none may become a runtime skip."""

    return tuple(f"worker:{family}:{name}" for family in ("ipv4", "ipv6") for name in sorted(CASES))


def AssertWorkerCohort(results: list[dict]) -> None:
    """Refuse omitted, duplicate, skipped or foreign worker identities in a later actual run.

    Args:
        results: Later coordinator-owned per-case identity/status facts. This check alone
            does not prove that originals, installed identity or source cleanup were verified.
    """

    required = WorkerCaseIdentities()
    observed = [result["identity"] for result in results]
    assert len(observed) == len(required) and len(set(observed)) == len(observed) and (
        set(observed) == set(required)), "Every exact worker identity is required once"
    assert all(result["status"] == "passed" for result in results), (
        "No skip, expected failure, absent or failed worker result satisfies acceptance")


def AssertContentInstallation(installation: dict, imported: dict, *, commit: str,
    tree: str) -> None:
    """Bind the pinned clean checkpoint, wheel and exact installed module identities.

    Args:
        installation: Original retained installation identity, not reconstructed output.
        imported: Actual consumer import probe document retained with its original process.
        commit: Coordinator-selected immutable source checkpoint.
        tree: Coordinator-selected entire source tree.
    """

    assert installation["schema_version"] == 1 and type(
        installation["schema_version"]) is int, "Installation schema must be an exact integer"
    assert installation["source_commit"] == commit and installation["source_tree"] == tree, (
        "Installed acceptance must bind the selected exact source checkpoint")
    assert all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (commit, tree)), (
        "A shortened or mutable source checkpoint is insufficient")
    sources = installation["source_modules_sha256"]
    wheel = installation["wheel_modules_sha256"]
    observed = imported["installed_sources"]
    assert set(sources) == set(wheel) == set(observed) == set(SOURCE_MODULES), (
        "Every fixed producer, parent, custody, SDK and header module must be observed")
    assert sources == wheel and all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
        for value in sources.values()), "Original wheel bytes must match checkpoint source bytes"
    assert type(installation["wheel_size_bytes"]) is int and (
        0 < installation["wheel_size_bytes"] <= 32 * 1024 * 1024), "Wheel size is unverified"
    assert type(installation["wheel_sha256"]) is str and re.fullmatch(
        r"[0-9a-f]{64}", installation["wheel_sha256"]), "Original wheel digest is unverified"
    assert imported["distribution_version"] == installation["distribution_version"] and (
        type(imported["distribution_version"]) is str and imported["distribution_version"]), (
            "Actual installed distribution identity must remain associated")
    roots = set()

    for name in SOURCE_MODULES:
        item = observed[name]
        path = PurePosixPath(item["path"])
        suffix = "/site-packages/fuzzy1337/" + name
        assert path.is_absolute() and ".." not in path.parts and str(path).endswith(suffix), (
            "Checkout, editable, relative and fallback imports are not installed acceptance")
        assert item["sha256"] == wheel[name], "Imported bytes must match the retained actual wheel"
        roots.add(str(path)[:-len(name)])

    assert len(roots) == 1, "All observed imports must belong to one installed package"


def AssertOriginalTerminalProcess(process: dict, stdout: bytes, stderr: bytes, *,
    argv: tuple[str, ...]) -> None:
    """Require complete raw terminal facts before any worker interpretation.

    Args:
        process: Original NativeProcess terminal metadata, retained before assertions.
        stdout: Entire original retained stdout, never a timeout prefix.
        stderr: Entire original retained stderr, including an observed empty stream.
        argv: Exact independently selected installed invocation.
    """

    assert type(stdout) is bytes and type(stderr) is bytes, "Original streams must be byte values"
    assert process["schema_version"] == 1 and type(process["schema_version"]) is int, (
        "Original process metadata must use the expected schema")
    assert process["argv"] == list(argv) and process["state"] == "returned" and (
        process["terminal_return_observed"] is True), "No timeout or absent terminal is success"
    assert type(process["returncode"]) is int and process["stdin"] == "closed-devnull", (
        "Actual return status and closed input must be retained")

    for role, raw in (("stdout", stdout), ("stderr", stderr)):
        part = process[role]
        assert part["observed"] is True and part["complete_original"] is True and (
            part["timeout_prefix"] is False and part["retention_overflow"] is False), (
                "Unobserved, truncated or timeout-prefix streams cannot establish original bytes")
        assert type(part["observed_size_bytes"]) is int and type(
            part["retained_size_bytes"]) is int and part["observed_size_bytes"] == (
            part["retained_size_bytes"]) == len(raw), "Original stream sizes must reconcile"
        assert part["observed_sha256"] == hashlib.sha256(raw).hexdigest(), (
            "Original retained stream digest must reconcile before decoding")


def AssertContentWorkerCase(name: str, url: str, process: dict, stdout: bytes, stderr: bytes,
    *, python: str) -> None:
    """Compare one terminal original with the independent frozen handwritten source oracle.

    Args:
        name: Required original matrix identity; never a producer-selected case identifier.
        url: Selected literal family/origin and the oracle's exact concrete path.
        process: Retained original terminal process metadata.
        stdout: Complete original worker stdout bytes.
        stderr: Complete original worker stderr bytes.
        python: Independently selected absolute installed interpreter, without fallback.
    """

    assert name in CASES, "An unknown source case cannot satisfy the frozen matrix"
    case = CASES[name]
    selected = urlsplit(url)
    assert selected.hostname in ("127.0.0.1", "::1") and selected.port is not None and (
        1024 <= selected.port <= 65535), "Worker acceptance needs its literal owned source"
    host = "[::1]" if selected.hostname == "::1" else "127.0.0.1"
    assert url == f"http://{host}:{selected.port}{case.path}", (
        "No normalized URL, alternate case path, query or fragment can replace selection")
    assert PurePosixPath(python).is_absolute() and ".." not in PurePosixPath(python).parts, (
        "Worker acceptance requires the selected absolute installed interpreter")
    argv = (python, "-I", "-B", "-m", "fuzzy1337.owned_content_response_worker", url)
    AssertOriginalTerminalProcess(process, stdout, stderr, argv=argv)
    assert stderr == b"" and len(stdout) <= MAX_STDOUT_BYTES, (
        "Worker stderr must be observed empty and original stdout must remain bounded")
    assert process["returncode"] == (0 if case.error is None else 2), (
        "A refusal and an admitted original have distinct actual exit statuses")
    assert stdout == case.ExpectedStdout(url), (
        "Complete worker originals must equal independent source bytes or the exact safe refusal")
