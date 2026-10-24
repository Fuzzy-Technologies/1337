# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Genuine isolated installed native crawl worker against independent mutable original bytes."""

from __future__ import annotations

import hashlib
import json
import subprocess
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace

import pytest

import tests.native_crawl_acceptance_helpers as native_helpers
from tests.native_crawl_acceptance_helpers import (
    AssertNativeRecord,
    AssertNativeWireMetadata,
    AssertZeroNativeContact,
    CanonicalNative,
    NativeAcceptanceGraph,
    NativeCaseEvidence,
    NativeConsumer,
    NativeEnvironment,
    NativeGet,
    NativeInput,
    NativeInstallation,
    NativeIpv6Terminal,
    NativeIpv6Wire,
    NativeProcess,
)
from tests.native_crawl_acceptance_helpers import installed_native_crawl as installed_native_crawl
from tests.native_crawl_acceptance_helpers import native_acceptance_run as native_acceptance_run
from tests.native_crawl_acceptance_helpers import native_case_evidence as native_case_evidence


@pytest.mark.integration
@pytest.mark.parametrize("variant,source", [
    ("positive", "/entry"), ("fixed", "/entry"), ("decoy", "/entry"),
    ("redirect", "/entry"), ("positive", "/branch-a"), ("positive", "/branch-b"),
    ("positive", "/shared"), ("positive", "/leaf/.git/HEAD"),
    ("positive", "/fixed/.git/HEAD"), ("positive", "/html/.git/HEAD"),
])
def test_InstalledWorkerBindsActualGetBodyAndHandwrittenFrontier(
    installed_native_crawl, tmp_path, variant, source, native_case_evidence,
) -> None:
    """Run the fixed packaged worker with one exact argv object and closed stdin, without mocks."""

    with NativeAcceptanceGraph(native_case_evidence) as target:
        target.state.SetVariant(variant)
        document = NativeInput(target, source)
        argument = CanonicalNative(document).decode("ascii")
        argv = (str(installed_native_crawl), "-I", "-m", "fuzzy1337.native_crawl_worker", argument)
        result = NativeProcess(native_case_evidence, "worker", argv, cwd=tmp_path,
            environment=NativeEnvironment(tmp_path / "owned-state"), timeout=8,
            installation=NativeInstallation(installed_native_crawl))
        assert target.state.WaitIdle(), "Worker left original target owners active."
        assert result.returncode == 0 and result.stderr == b"", (
            "Required actual worker acquisition failed: " + repr(result.stderr)
        )
        record = json.loads(result.stdout)
        assert CanonicalNative(record) == result.stdout, (
            "The actual original stdout must be canonical ASCII JSON without a newline."
        )
        assert len(target.state.Observe()) == target.state.Counters()["contacts"] == 1, (
            "One packaged worker may make exactly one original selected GET, without followups."
        )
        AssertNativeRecord(record, document, target.state.Observe()[0], variant=variant)
        assert not target.state.Errors(), "The genuine owned target mechanism reported a failure."


@pytest.mark.integration
@pytest.mark.parametrize("arguments", [(), ("{}",), ("--help",), ("{}", "{}")])
def test_InstalledWorkerInputRefusalMakesZeroOriginalContact(
    installed_native_crawl, tmp_path, arguments, native_case_evidence,
) -> None:
    """Missing, malformed or alternate argv fails closed rather than selecting a fallback target."""

    with NativeAcceptanceGraph(native_case_evidence) as target:
        result = NativeProcess(native_case_evidence, "worker",
            (str(installed_native_crawl), "-I", "-m",
            "fuzzy1337.native_crawl_worker", *arguments), cwd=tmp_path,
            environment=NativeEnvironment(tmp_path / "owned-state"), timeout=8,
            installation=NativeInstallation(installed_native_crawl))
        assert (result.returncode, result.stderr, result.stdout) == (2, b"", CanonicalNative({
            "schema_version": 1, "profile": "owned-loopback-content-crawl.v1",
            "outcome": "refused", "error": "input"})), (
                "The actual installed worker must emit only its exact closed input refusal."
            )
        AssertZeroNativeContact(target)


@pytest.mark.integration
def test_InstalledWorkerRedirectRefusesWithoutDestinationContact(
    installed_native_crawl, tmp_path, native_case_evidence,
) -> None:
    """A selected redirect returns a truthful refusal with no body digest or follow-up request."""

    with NativeAcceptanceGraph(native_case_evidence) as target:
        argument = CanonicalNative(NativeInput(target, "/redirect")).decode("ascii")
        result = NativeProcess(native_case_evidence, "worker",
            (str(installed_native_crawl), "-I", "-m",
            "fuzzy1337.native_crawl_worker", argument), cwd=tmp_path,
            environment=NativeEnvironment(tmp_path / "owned-state"), timeout=8,
            installation=NativeInstallation(installed_native_crawl))
        assert target.state.WaitIdle(), "Redirect refusal left original target ownership active."
        assert (result.returncode, result.stderr, result.stdout) == (2, b"", CanonicalNative({
            "schema_version": 1, "profile": "owned-loopback-content-crawl.v1",
            "outcome": "refused", "error": "response-policy"})), (
                "Redirect work must remain failed/unassessed with no partial body/frontier fields."
            )
        assert [item.target for item in target.state.Observe()] == ["/redirect"] and (
            target.state.Counters()["contacts"] == 1 and not target.state.Errors()
        ), "A redirect Location must cause exactly zero original destination contacts."


@pytest.mark.integration
def test_InstalledIpv6WorkerAndSdkPersistOneTerminalPage(
    installed_native_crawl, tmp_path, native_case_evidence,
) -> None:
    """Require actual IPv6 GET/peer/EOF admission and one genuine SDK CAS/reopen."""

    path = "/native-crawl-terminal"

    with NativeIpv6Terminal(native_case_evidence) as listener:
        url = listener.origin + path
        document = {"schema_version": 1, "profile": "owned-loopback-content-crawl.v1",
            "workspace_id": "native-crawl-acceptance", "seed_url": url, "source_url": url,
            "selected_urls": [url], "max_body_bytes": 16384, "request_timeout_ms": 3000}
        result = NativeProcess(native_case_evidence, "worker-ipv6",
            (str(installed_native_crawl), "-I", "-m", "fuzzy1337.native_crawl_worker",
             CanonicalNative(document).decode("ascii")), cwd=tmp_path,
            environment=NativeEnvironment(tmp_path / "owned-state"), timeout=8,
            installation=NativeInstallation(installed_native_crawl))
        assert result.returncode == 0 and result.stderr == b"", (
            "The required literal IPv6 worker must really run; unsupported capability cannot skip."
        )
        record = json.loads(result.stdout)
        assert CanonicalNative(record) == result.stdout, "IPv6 stdout must stay canonical."
        expected = {"status": 200, "media_type": "text/plain", "outcome": "non-html",
                    "body": "owned-ipv6-terminal\n"}
        AssertNativeWireMetadata(record, NativeIpv6Wire(), expected)
        assert record["input_sha256"] == hashlib.sha256(CanonicalNative(document)).hexdigest() and (
            record["selected_urls_sha256"] == hashlib.sha256(CanonicalNative([url])).hexdigest()
        ), "The actual IPv6 worker must bind its sole original argv input and selected URL set."
        request = NativeGet(listener.origin, path)
        assert record["source"]["address"] == "::1" and (
            record["source"]["port"] == listener.port and
            record["source"]["url"] == url
            and record["source"]["request_size_bytes"] == len(request)
            and record["source"]["request_sha256"] == hashlib.sha256(request).hexdigest()
        ), "Actual IPv6 peer/port and bracketed Host request facts must match the selected literal."
        config = {"workspace": str(tmp_path / "workspace"), "seed_url": url, "selected_urls": [url]}
        setup = NativeConsumer(installed_native_crawl, tmp_path, "setup", config,
                               native_case_evidence)
        output = NativeConsumer(installed_native_crawl, tmp_path, "crawl", config,
                                native_case_evidence)
        summary = output["summary"]
        assert setup["crawl_attester"] != setup["selected_owner"] and summary["state"] == (
            "completed") and summary["completed_urls"] == [url], (
                "IPv6 SDK work needs independent consent and one completed source."
            )
        saves = output["actual_model_saves"]
        assert len(saves) == 1 and saves[0]["exact_acknowledgement"] and (
            saves[0]["expected_revision"] == setup["state"]["model"]["revision"]
            and saves[0]["acknowledged_revision"] == saves[0]["proposed_revision"]
            == saves[0]["prior_revision"] + 1
        ), "The actual IPv6 SDK must perform exactly one acknowledged original model CAS."
        assert summary["custody_status"] == "complete" and (
            len(summary["original_record_ids"]) == 3
        ), (
            "IPv6 SDK success requires its three actual original stream/control acquisitions."
        )
        reopened = NativeConsumer(installed_native_crawl, tmp_path, "inspect", config,
                                  native_case_evidence)
        assert reopened["state"] == output["state"], "IPv6 state must durably reopen."

    assert listener.accepted == 2 and listener.requests == [request, request], (
        "Worker and SDK must each send one exact bracketed-Host GET and no followup connection."
    )


def test_SourceOriginalProcessEvidencePrecedesCallerParseFailure(tmp_path, monkeypatch) -> None:
    """Pure counterexample: bad original output must survive a later caller decode failure."""

    owner = NativeCaseEvidence(tmp_path / "local", tmp_path / "ci")
    original = subprocess.CompletedProcess(("owned-test",), 7, b"not-json", b"owned-stderr")
    monkeypatch.setattr(native_helpers.subprocess, "run", lambda *args, **kwargs: original)
    result = NativeProcess(owner, "owned-failure", ("owned-test",), cwd=tmp_path,
                           environment={}, timeout=1)
    assert result is original, "The wrapper must return the original object unchanged."

    with pytest.raises(json.JSONDecodeError):
        json.loads(result.stdout)

    for root in (owner.local, owner.retained):
        assert (root / "process-001-owned-failure/stdout.bin").read_bytes() == original.stdout and (
            (root / "process-001-owned-failure/stderr.bin").read_bytes() == original.stderr
        ), "Both original byte streams must survive caller failure in scratch and CI retention."
        metadata = json.loads((root / "process-001-owned-failure/process.json").read_bytes())
        assert metadata["argv"] == ["owned-test"] and metadata["returncode"] == 7 and (
            metadata["terminal_return_observed"] is True
        ), "Failed original return/argv truth must precede any caller assertion or decode."


def test_SourceTimeoutRetainsOnlyActualPrefixWithoutInventingTerminalReturn(tmp_path, monkeypatch):
    """Pure counterexample: timeout evidence keeps observed prefixes and unknown terminal return."""

    owner = NativeCaseEvidence(tmp_path / "local", tmp_path / "ci")

    def Timeout(*args, **kwargs):
        """Model only the subprocess timeout seam without running any process or worker."""

        raise subprocess.TimeoutExpired(("owned-test",), 1, output=b"partial-original", stderr=None)

    monkeypatch.setattr(native_helpers.subprocess, "run", Timeout)

    with pytest.raises(subprocess.TimeoutExpired):
        NativeProcess(owner, "owned-timeout", ("owned-test",), cwd=tmp_path,
                      environment={}, timeout=1)

    metadata = json.loads((owner.retained / "process-001-owned-timeout/process.json").read_bytes())
    assert metadata["state"] == "timeout" and metadata["returncode"] is None and (
        metadata["terminal_return_observed"] is False and metadata["stdout"]["timeout_prefix"]
        and not metadata["stdout"]["complete_original"] and not metadata["stderr"]["observed"]
    ), "Timeout custody must not invent completion or unobserved empty stderr."
    assert (owner.retained / "process-001-owned-timeout/stdout.bin").read_bytes() == (
        b"partial-original"), "Only the actual original timeout prefix may be retained."


def test_SourceTargetFinallyRetainsBothOriginsAfterCallerFailure(tmp_path, monkeypatch) -> None:
    """Pure interleaving proves final facts follow both original origin cleanups."""

    owner = NativeCaseEvidence(tmp_path / "local", tmp_path / "ci")
    closed = False
    counters = {"contacts": 0, "contact_overflow": 0, "active_connections": 0,
                "active_handlers": 0, "active_dispatches": 0}
    state = SimpleNamespace(Counters=lambda: dict(counters), Observe=lambda: (),
        Errors=lambda: ("cleanup-observed",) if closed else (), WaitIdle=lambda: True)
    thread = SimpleNamespace(is_alive=lambda: not closed)
    target = SimpleNamespace(state=state, sentinel_state=state, thread=thread,
        sentinel_thread=thread, graph=SimpleNamespace(origin="http://127.0.0.1:49152"),
        sentinel_origin="http://127.0.0.1:49153")

    @contextmanager
    def Owned():
        """Model only deterministic post-yield cleanup without sockets, threads or real targets."""

        nonlocal closed

        try:
            yield target

        finally:
            closed = True

    monkeypatch.setattr(native_helpers, "OwnedNativeCrawlGraph", Owned)

    with pytest.raises(AssertionError, match="owned caller failure"):
        with NativeAcceptanceGraph(owner):
            raise AssertionError("owned caller failure")

    final = json.loads((owner.retained / "target-final.json").read_bytes())
    assert final["owner_state"] == "settled" and (
        final["main"]["errors"] == ["cleanup-observed"] and
        final["sentinel"]["errors"] == ["cleanup-observed"]
    ), "The always-retained original ledger must observe both cleanups even when the case failed."


@pytest.mark.parametrize("field,value", [("http_version", "HTTP/1.0"), ("header_fields", 99),
    ("header_fields", True), ("status", 403), ("media_type", "text/plain"),
    ("outcome", "non-html"), ("complete", False), ("extra-field", "unadmitted")])
def test_SourceIndependentWireAssertionsRejectMisreportedNormalHtmlFacts(field, value) -> None:
    """Pure HTML metadata counterexamples must fail independent wire assertions."""

    body = b"<html><body>owned</body></html>"
    header = (f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n"
              "Content-Type: text/html\r\nConnection: close").encode("ascii")
    zero = dict.fromkeys(("missing-href", "invalid-url", "fragment-only", "non-http", "credentials",
        "query", "off-origin", "unsupported-path", "source-target", "not-admitted"), 0)
    baseline = {"schema_version": 1, "profile": "owned-loopback-content-crawl.v1",
        "outcome": "html",
        "input_sha256": "a" * 64, "selected_urls_sha256": "b" * 64, "source": {},
        "response": {"http_version": "HTTP/1.1", "status": 200, "media_type": "text/html",
            "header_bytes": len(header) + 4, "header_fields": 3, "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest()},
        "frontier": {"complete": True, "anchor_count": 0, "entries": [], "exclusion_counts": zero}}
    wire = header + b"\r\n\r\n" + body
    expected = {"status": 200, "media_type": "text/html", "outcome": "html"}
    AssertNativeWireMetadata(baseline, wire, expected)
    wrong = deepcopy(baseline)

    if field == "outcome" or field == "extra-field":
        wrong[field] = value

    elif field == "complete":
        wrong["frontier"][field] = value

    else:
        wrong["response"][field] = value

    with pytest.raises(AssertionError):
        AssertNativeWireMetadata(wrong, wire, expected)
