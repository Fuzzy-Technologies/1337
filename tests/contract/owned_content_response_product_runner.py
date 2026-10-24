# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure first-slice acceptance checks; no launcher, fixture, installed runtime or enrollment.

These checks consume retained original facts only. Passing mocked contracts is not genuine
worker, SDK or header-v2 acceptance. The later opt-in runner must retain process evidence
before calling them and must independently prove both source owners actually settled.
"""

from __future__ import annotations

import errno
import hashlib
import math
import re
from pathlib import PurePosixPath, PureWindowsPath
from urllib.parse import urlsplit

from tests.contract.owned_content_response_oracle import CaseMatrix, RequestBytes

SOURCE_MODULES = ("adapters/owned_content_response.py", "owned_content_response_worker.py",
    "adapters/owned_response_capture.py", "owned_response_capture.py",
    "owned_response_capture_worker.py", "owned_response_custody.py", "owned_response_workflow.py",
    "native_response_headers.py", "native_response_header_workflow.py")
CASES = {case.name: case for case in CaseMatrix()}
MAX_STDOUT_BYTES = 131072
HELD_WINDOWS_ERRORS = frozenset((10053, 10054, 10060))


def AbsoluteRuntimePath(value: str) -> PurePosixPath | PureWindowsPath:
    """Admit lexical local absolute paths without resolving or rewriting original values.

    Args:
        value: Original selected interpreter or observed installed source path.

    Returns:
        Its explicit POSIX or Windows-drive path flavor for suffix/root comparison only.
        Drive-relative, root-relative, device/UNC and traversal spellings are refused.
    """

    assert type(value) is str and value and not any(ord(char) < 32 for char in value), (
        "Runtime paths must be nonempty literal text without control characters")
    windows = PureWindowsPath(value)

    if windows.drive or "\\" in value:
        assert re.fullmatch(r"[A-Za-z]:", windows.drive) and windows.is_absolute(), (
            "Windows runtime paths require an explicit local drive and root")
        segments = value[3:].replace("\\", "/").split("/")
        assert ":" not in value[2:], "Windows alternate streams are not runtime paths"
        path: PurePosixPath | PureWindowsPath = windows

    else:
        assert value.startswith("/") and not value.startswith("//"), (
            "POSIX runtime paths require an explicit local absolute root")
        segments = value[1:].split("/")
        path = PurePosixPath(value)

    assert all(part not in ("", ".", "..") for part in segments), (
        "Traversal or implicitly normalized path segments cannot establish installed identity")

    return path


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
        path = AbsoluteRuntimePath(item["path"])
        module_parts = PurePosixPath(name).parts
        suffix = ("site-packages", "fuzzy1337", *module_parts)
        assert path.parts[-len(suffix):] == suffix, (
            "Checkout, editable, relative and fallback imports are not installed acceptance")
        assert item["sha256"] == wheel[name], "Imported bytes must match the retained actual wheel"
        roots.add(path.parents[len(module_parts) - 1])

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
    AbsoluteRuntimePath(python)
    argv = (python, "-I", "-B", "-m", "fuzzy1337.owned_content_response_worker", url)
    AssertOriginalTerminalProcess(process, stdout, stderr, argv=argv)
    assert stderr == b"" and len(stdout) <= MAX_STDOUT_BYTES, (
        "Worker stderr must be observed empty and original stdout must remain bounded")
    assert process["returncode"] == (0 if case.error is None else 2), (
        "A refusal and an admitted original have distinct actual exit statuses")
    assert stdout == case.ExpectedStdout(url), (
        "Complete worker originals must equal independent source bytes or the exact safe refusal")


def AssertFinalSourceOwner(final: dict, origin: str, contacts: int) -> None:
    """Require explicit original post-cleanup facts, including the otherwise untouched sentinel.

    Args:
        final: Unmodified FinalSourceFacts plus its original fixture cleanup fields.
        origin: Independently selected literal source origin.
        contacts: Required original accepted contact count, not inferred from missing records.
    """

    fields = {"schema_version", "target_yielded", "owner_state", "listener_alive",
        "listener_closed", "origin", "counters", "errors", "contacts", "accepted_endpoints",
        "cleanup_returned", "cleanup_failure", "idle_before_local_close"}
    assert set(final) == fields and type(final["schema_version"]) is int and (
        final["schema_version"] == 1), "Absent or foreign final source records are not observations"
    assert final["target_yielded"] is True and final["owner_state"] == "settled" and (
        final["listener_alive"] is False and final["listener_closed"] is True and
        final["cleanup_returned"] is True and final["cleanup_failure"] is None and
        final["idle_before_local_close"] is True), "Original source cleanup must actually settle"
    assert final["origin"] == origin, "Cleanup facts must belong to the selected original source"
    counters = final["counters"]
    keys = {"contacts", "retained_contacts", "contact_overflow", "active_connections",
        "active_handlers", "active_dispatches", "maximum_active_handlers", "completed_responses",
        "errors", "error_overflow"}
    assert set(counters) == keys and all(type(value) is int and 0 <= value <= 64
        for value in counters.values()), "Source counters require bounded exact integers"
    assert type(final["contacts"]) is list and type(final["accepted_endpoints"]) is dict, (
        "Original contact and endpoint collections must retain their schema")
    assert counters["contacts"] == counters["retained_contacts"] == len(final["contacts"]) == (
        contacts), "Original accepts and retained contact records must reconcile"
    assert all(counters[key] == 0 for key in ("contact_overflow", "active_connections",
        "active_handlers", "active_dispatches", "error_overflow")), "No original owner may remain"
    assert type(final["errors"]) is list and len(final["errors"]) == counters["errors"] and all(
        type(error) is str and 1 <= len(error) <= 100 for error in final["errors"]), (
            "Original bounded source mechanism failures must remain visible")
    assert len(final["accepted_endpoints"]) == contacts and counters[
        "completed_responses"] <= contacts, "Endpoint and completion counts require original joins"

    if contacts == 0:
        assert counters["maximum_active_handlers"] == counters["completed_responses"] == (
            counters["errors"]) == 0, "The explicit sentinel must have no contact side effects"

    else:
        assert counters["maximum_active_handlers"] == 1, "One worker requires one source handler"


def AssertOriginalPeerEnd(signal: dict, *, allow_reset: bool) -> None:
    """Require actual timely original peer termination, never local teardown or a guessed EOF.

    Args:
        signal: Original retained HeldPeerSignal record.
        allow_reset: Only the held-response branch accepts a recognized peer reset.
    """

    assert type(signal) is dict and set(signal) == {"kind", "phase", "before_local_close",
        "within_hold", "error_type", "errno", "winerror"}, "Original peer terminal is missing"
    assert signal["phase"] == "peer-receive" and signal["before_local_close"] is True and (
        signal["within_hold"] is True), "Late or local signals cannot establish original peer end"

    if signal["kind"] == "eof":
        assert all(signal[key] is None for key in ("error_type", "errno", "winerror")), (
            "An original EOF cannot be inferred from an error")

    else:
        assert allow_reset and signal["kind"] == "peer-reset" and (
            signal["error_type"] == "ConnectionResetError"), "Normal completion requires actual EOF"
        assert all(value is None or type(value) is int for value in (
            signal["errno"], signal["winerror"])), "Reset numbers must retain exact numeric types"
        assert signal["errno"] is None or signal["errno"] in errno.errorcode or (
            signal["errno"] in HELD_WINDOWS_ERRORS), "Original errno requires its sanitized domain"
        assert signal["winerror"] is None or signal["winerror"] in HELD_WINDOWS_ERRORS, (
            "Original winerror must retain its separately sanitized domain")
        assert signal["errno"] in (54, 104, 10054) or signal["winerror"] == 10054, (
            "An unknown receive error is not positive peer-reset evidence")


def AssertContentSourceFacts(name: str, url: str, main: dict, sentinel: dict, *,
    sentinel_origin: str) -> str:
    """Join one frozen source case to its original contact/peer facts and both settled owners.

    Args:
        name: Independently selected frozen matrix identity.
        url: Exact selected original source URL.
        main: Retained original main FinalSourceFacts, including cleanup fields.
        sentinel: Explicit separate sentinel final facts; absence is never zero contacts.
        sentinel_origin: Independently selected owned no-contact origin.

    Returns:
        Distinct source-delivery classification, never a product acquisition verdict.
    """

    case = CASES[name]
    parsed = urlsplit(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    assert parsed.hostname in ("127.0.0.1", "::1") and parsed.port is not None and (
        1024 <= parsed.port <= 65535), "Source facts need an independently selected literal origin"
    host = "[::1]" if parsed.hostname == "::1" else "127.0.0.1"
    assert url == f"http://{host}:{parsed.port}{case.path}", "Selected source URL must remain exact"
    other = urlsplit(sentinel_origin)
    other_host = "[::1]" if other.hostname == "::1" else "127.0.0.1"
    assert other.hostname in ("127.0.0.1", "::1") and other.port is not None and (
        1024 <= other.port <= 65535 and sentinel_origin == f"http://{other_host}:{other.port}"
        and sentinel_origin != origin), "A distinct literal sentinel owner is required"
    AssertFinalSourceOwner(main, origin, 1)
    AssertFinalSourceOwner(sentinel, sentinel_origin, 0)
    record = main["contacts"][0]
    assert set(record) == {"sequence", "variant", "target", "request_hex", "received_bytes",
        "request_truncated", "response_hex", "sent_bytes", "accepted_at", "deadline_at",
        "active_at_start", "completion_sequence", "admission_state", "failure", "socket_closed",
        "shutdown_error", "shutdown_errno", "close_error", "close_errno"}, (
            "Original contact facts must retain their complete frozen schema")
    request, wire = RequestBytes(url), case.Wire()
    assert record["variant"] == name and record["target"] == case.path and (
        record["request_hex"] == request.hex() and type(record["received_bytes"]) is int
        and record["received_bytes"] == len(request) and record["request_truncated"] is False), (
            "The original complete request must match the selected case and URL")
    assert record["response_hex"] == wire.hex() and type(record["sent_bytes"]) is int and (
        0 <= record["sent_bytes"] <= len(wire)), "Actual sends must retain original source bytes"
    assert type(record["sequence"]) is int and record["sequence"] == 1 and type(
        record["active_at_start"]) is int and record["active_at_start"] == 1, (
            "Original accept and handler ownership must join exactly once")
    assert all(type(record[key]) in (int, float) and math.isfinite(record[key]) for key in (
        "accepted_at", "deadline_at")) and record["accepted_at"] >= 0 and (
        record["deadline_at"] - record["accepted_at"] == 7), "Original source deadline is immutable"
    assert record["socket_closed"] is True and record["close_error"] is False and (
        record["close_errno"] is None), "An unconfirmed original close cannot establish cleanup"
    endpoints = main["accepted_endpoints"]
    assert all(type(key) in (int, str) for key in endpoints) and set(endpoints) in ({0}, {"0"}), (
        "Actual endpoints must join the original contact index")
    peer = endpoints[0] if 0 in endpoints else endpoints["0"]
    assert set(peer) == {"local_address", "local_port", "peer_address", "peer_port",
        "peer_terminal"} and peer["local_address"] == peer["peer_address"] == parsed.hostname, (
            "Actual local and peer addresses must match the selected literal family")
    assert type(peer["local_port"]) is int and peer["local_port"] == parsed.port and type(
        peer["peer_port"]) is int and 1 <= peer["peer_port"] <= 65535, "Actual ports are unverified"

    if record["failure"] is not None:
        assert case.error is not None and case.eof_mode == "close" and (
            record["failure"] == "owned-content-request-failure" and
            record["admission_state"] == "failed" and record["completion_sequence"] is None
            and main["counters"]["completed_responses"] == 0 and
            "owned-content-request-failure" in main["errors"]), (
                "An original source error must remain a refused incomplete delivery")

        return "refused-source-error"

    assert record["sent_bytes"] == len(wire) and type(record["completion_sequence"]) is int and (
        record["completion_sequence"] == main["counters"]["completed_responses"] == 1 and
        main["counters"]["errors"] == 0 and record["shutdown_error"] is False and
        record["shutdown_errno"] is None), "Sent bytes alone do not establish source completion"
    held = case.eof_mode == "hold-until-peer-eof"
    assert record["admission_state"] == ("sent-peer-ended" if held else "completed"), (
        "Normal and held original completion states must remain distinct")
    AssertOriginalPeerEnd(peer["peer_terminal"], allow_reset=held)

    return "held-peer-ended" if held else "normal-eof"


def AssertContentLauncherEvidence(name: str, url: str, installation: dict, imported: dict,
    invocation: dict, process: dict, stdout: bytes, stderr: bytes, *, commit: str, tree: str,
    python: str, cwd: str, timeout_seconds: int) -> None:
    """Reconcile original prelaunch/terminal metadata without launching or fabricating facts.

    Args:
        name: Independently selected frozen worker case.
        url: Exact selected owned source URL.
        installation: Original unchanged NativeInstallation manifest digest and identity envelope.
        imported: Original installed import probe document.
        invocation: Retained NativeProcess prelaunch record, not reconstructed after return.
        process: Retained original terminal metadata.
        stdout: Complete original retained stdout.
        stderr: Complete original retained stderr.
        commit: Independently pinned source commit.
        tree: Independently pinned complete source tree.
        python: Selected absolute installed interpreter.
        cwd: Independently selected isolated launch directory.
        timeout_seconds: Independently selected finite launcher bound.
    """

    AbsoluteRuntimePath(cwd)
    assert type(timeout_seconds) is int and 1 <= timeout_seconds <= 30, "Launch bound is unverified"
    assert set(invocation) == {"schema_version", "argv", "cwd", "timeout_seconds", "stdin",
        "state", "returncode", "terminal_return_observed", "installation"} and type(
        invocation["schema_version"]) is int, "Original prelaunch schema must remain exact"
    assert invocation["state"] == "not-launched" and invocation["returncode"] is None and (
        invocation["terminal_return_observed"] is False), "Original prelaunch intent is required"
    assert invocation["cwd"] == cwd and invocation["timeout_seconds"] == timeout_seconds and type(
        invocation["timeout_seconds"]) is int, "Original launch directory and bound must match"
    assert type(process["timeout_seconds"]) is int, "Terminal launch bound requires exact int type"

    for key in ("schema_version", "argv", "cwd", "timeout_seconds", "stdin", "installation"):
        assert process[key] == invocation[key], "Terminal facts must retain original invocation"

    assert type(installation) is dict and set(installation) == {"manifest_sha256", "identity"}, (
        "The original installation envelope must retain both manifest digest and identity")
    assert type(installation["manifest_sha256"]) is str and re.fullmatch(
        r"[0-9a-f]{64}", installation["manifest_sha256"]), "Original manifest digest is unverified"
    assert invocation["installation"] == installation, (
        "Original invocation must bind its retained selected installation")
    AssertContentInstallation(installation["identity"], imported, commit=commit, tree=tree)
    AssertContentWorkerCase(name, url, process, stdout, stderr, python=python)
