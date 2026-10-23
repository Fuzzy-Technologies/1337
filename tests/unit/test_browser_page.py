# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Network-free offline browser profile grammar, refusal and source-custody boundaries."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import socket
from collections.abc import Iterator
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest
from referencing import Registry, Resource

from fuzzy1337 import browser_page_worker as worker
from fuzzy1337 import page_capture as provider_module
from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterReport,
    AdapterRequest,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
)
from fuzzy1337.adapters.browser_page import ParseBrowserRecord
from fuzzy1337.adapters.page_capture import (
    BROWSER_FIXTURE_ID,
    CHROMIUM_VERSION,
    PAGE_BROWSER_CAPABILITY,
    PAGE_BROWSER_PROFILE,
    PAGE_CAPTURE_CAPABILITY,
    PLAYWRIGHT_VERSION,
    BrowserPageCaptureLimits,
    CanonicalRecord,
    KnownSyntheticHtmlBody,
    NativeLoopbackPageAdapter,
    PageCaptureLimits,
    PageCaptureRecordError,
    PageRenderer,
    ParseRecord,
)
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import owned_process
from fuzzy1337.executors.local import LocalExecutionError
from fuzzy1337.jobs import JobFailureCode, JobSpec, JobState, ScanJob
from fuzzy1337.model import LocalModelStore
from fuzzy1337.page_capture import LocalPageCaptureProvider
from fuzzy1337.page_capture_worker import (
    PageBodyPolicyError,
    PageProtocolError,
    PageResponsePolicyError,
)
from fuzzy1337.policy import CapabilityPermission, GovernedLocalExecutor
from fuzzy1337.scope import Target, TargetKind
from tests.contract.page_capture_fixture import NOW, Fixture
from tests.unit.test_page_capture import Result, RunJob

URL = "http://127.0.0.1:32123/docs/index"
BODY = (Path(__file__).parents[1] / "contract/fixtures/browser-dom.owned.v1.html").read_bytes()
BODY_SHA256 = "75d60b34385f3c65068edcde7a37da78db796290b95be0ab9beb2cdc03fe3e71"


@pytest.fixture(scope="module")
def browser_runner() -> Iterator[asyncio.Runner]:
    """Create the owned Windows loop before the unit network guard; tests never launch a browser."""

    with asyncio.Runner() as runner:
        runner.get_loop()
        yield runner


def NativeRecord():
    """Supply independent fixed native metadata over the handwritten423-byte owned fixture."""

    return {"schema_version": 1, "fixture_id": BROWSER_FIXTURE_ID, "url": URL,
        "address": "127.0.0.1", "port": 32123, "scheme": "http", "http_version": "HTTP/1.1",
        "status": 200, "content_type": "text/html", "declared_charset": "utf-8",
        "content_length": 423, "header_size_bytes": 100, "header_count": 2,
        "body_sha256": BODY_SHA256, "body_base64": base64.b64encode(BODY).decode("ascii")}


def BrowserRecord(**changes):
    """Describe a handwritten report contract; this is no claim of real browser execution."""

    return {**NativeRecord(), "renderer_profile": PAGE_BROWSER_PROFILE,
        "input_body_sha256": BODY_SHA256, "playwright_version": PLAYWRIGHT_VERSION,
        "chromium_version": CHROMIUM_VERSION, "dom_sha256": BODY_SHA256, "dom_size_bytes": 423,
        "element_count": 11, "anchor_count": 1, "form_count": 1, "input_count": 1,
        "blocked_request_count": 1, **changes}


def Request(capability=PAGE_BROWSER_CAPABILITY):
    """Bind exact native request fields to the separately permissioned browser capability."""

    return AdapterRequest(capability, Target(TargetKind.URL, URL).Reference(), ImpactLevel.SAFE,
        {"url": URL, "timeout_seconds": 2.0, "fixture_id": BROWSER_FIXTURE_ID,
         "max_body_bytes": 16384})


def test_BrowserGrammarPreservesCompleteNativeInputAndHandwrittenMetrics():
    """Original source bytes and exact engine/profile fields survive independent validation."""

    assert len(BODY) == 423 and hashlib.sha256(BODY).hexdigest() == BODY_SHA256, (
        "The independently owned body fixture changed."
    )
    record = BrowserRecord()
    assert ParseBrowserRecord(CanonicalRecord(record), URL,
        KnownSyntheticHtmlBody(BROWSER_FIXTURE_ID), 16384) == record, "Browser record changed."


@pytest.mark.parametrize("variant", ["success", "error-only", "source-error", "partial", "extra"])
def test_OfflineJsonSchemaRetainsTheSameClosedSuccessAndCompleteSourceFailureProfiles(variant):
    """Resolve only checked-in schemas locally; no remote schema lookup or renderer is involved."""

    contracts = Path(__file__).parents[2] / "contracts"
    native = json.loads((contracts / "page-capture-record.schema.json").read_bytes())
    schema = json.loads((contracts / "browser-page-record.schema.json").read_bytes())
    registry = Registry().with_resource(native["$id"], Resource.from_contents(native))
    validator = jsonschema.Draft202012Validator(schema, registry=registry)
    jsonschema.Draft202012Validator.check_schema(schema)
    record = BrowserRecord()

    if variant in ("error-only", "source-error", "partial"):
        record = {"schema_version": 1, "renderer_profile": PAGE_BROWSER_PROFILE,
                  "error": "renderer"}

        if variant != "error-only":
            record.update(NativeRecord(), input_body_sha256=BODY_SHA256)

        if variant == "partial":
            del record["body_sha256"]

    elif variant == "extra":
        record["unknown"] = "PRIVATE_REPORT_MARKER"

    assert validator.is_valid(record) is (variant not in ("partial", "extra")), (
        "Browser JSON grammar admitted partial source/extra fields or lost a profile."
    )
    jsonschema.Draft202012Validator(native).validate(NativeRecord())


@pytest.mark.parametrize("mutation", [
    {"renderer_profile": "native"}, {"playwright_version": "1.0"},
    {"chromium_version": "156"}, {"input_body_sha256": "f" * 64}, {"dom_sha256": True},
    {"dom_sha256": "F" * 64}, {"element_count": True}, {"element_count": 8193},
    {"anchor_count": 12}, {"form_count": -1}, {"input_count": True},
    {"blocked_request_count": 65}, {"dom_size_bytes": 262145},
    {"body_base64": "unknown"}, {"url": "http://127.0.0.2/docs/index"},
    {"extra": "PRIVATE_DOM_MARKER"}, {"error": "renderer"},
])
def test_BrowserOriginalRecordCannotHidePinsCoercionsBodyOrExtraMetrics(mutation):
    """A different browser/profile/body or incomplete failure cannot become an assessed page."""

    with pytest.raises(PageCaptureRecordError) as error:
        ParseBrowserRecord(CanonicalRecord(BrowserRecord(**mutation)), URL,
            KnownSyntheticHtmlBody(BROWSER_FIXTURE_ID), 16384)

    assert "PRIVATE_DOM_MARKER" not in str(error.value), "Untrusted DOM/report fields escaped."


@pytest.mark.parametrize("complete", [False, True])
def test_RenderFailureAdmitsOnlyNoBodyOrTheEntireVerifiedNativeSourceGroup(complete):
    """Partial-source custody stays truthful without any DOM result or completed frontier."""

    record = {"schema_version": 1, "renderer_profile": PAGE_BROWSER_PROFILE, "error": "renderer"}

    if complete:
        record.update(NativeRecord(), input_body_sha256=BODY_SHA256)

    assert ParseBrowserRecord(CanonicalRecord(record), URL,
        KnownSyntheticHtmlBody(BROWSER_FIXTURE_ID), 16384) == record, "Failure source group changed"

    if complete:
        del record["header_count"]

        with pytest.raises(PageCaptureRecordError):
            ParseBrowserRecord(CanonicalRecord(record), URL,
                KnownSyntheticHtmlBody(BROWSER_FIXTURE_ID), 16384)


@pytest.mark.parametrize("raw", [b'{}\n', b'{}',
    b'{"schema_version":1,"schema_version":1}\n', b'[]\n'])
def test_BrowserParserRequiresOriginalUniqueCanonicalStream(raw):
    """Normalization cannot discard alternative spellings or overwritten original fields."""

    with pytest.raises(PageCaptureRecordError):
        ParseBrowserRecord(raw, URL, KnownSyntheticHtmlBody(BROWSER_FIXTURE_ID), 16384)


def test_SelectedAdapterSeparatesNativeAndBrowserCapabilitiesArgvAndRecordGrammar():
    """An explicit browser selection cannot silently consume a legacy permission or report."""

    raw = CanonicalRecord(BrowserRecord())
    browser = NativeLoopbackPageAdapter(lambda reference: raw,
        renderer=PageRenderer.PLAYWRIGHT_OFFLINE)
    native = NativeLoopbackPageAdapter(lambda reference: raw)
    invocation = browser.PrepareInvocation(Request())
    assert invocation.argv[1:4] == ("-I", "-m", "fuzzy1337.browser_page_worker"), (
        "Browser request did not bind its fixed isolated worker."
    )
    assert invocation.timeout_seconds == 9, "Browser process budget changed."
    assert browser.Descriptor.capabilities == (PAGE_BROWSER_CAPABILITY,), (
        "Browser descriptor inherited native execution permission."
    )
    assert native.Descriptor.capabilities == (PAGE_CAPTURE_CAPABILITY,), (
        "Default native capability metadata changed."
    )

    with pytest.raises(ValueError):
        browser.PrepareInvocation(Request(PAGE_CAPTURE_CAPABILITY))

    with pytest.raises(ValueError):
        native.PrepareInvocation(Request())

    with pytest.raises(PageCaptureRecordError):
        ParseRecord(raw, URL, KnownSyntheticHtmlBody(BROWSER_FIXTURE_ID), 16384)

    digest = hashlib.sha256(raw).hexdigest()
    report = AdapterReport(invocation, AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.1),
        (EvidenceReference("stdout", "blobs/sha256/" + digest, digest,
                           "application/json", len(raw)),))
    result = browser.NormalizeReport(report)
    assert not result.findings and result.observations[0].kind == "http.synthetic-page-browser", (
        "Browser metrics became invented vulnerability findings or a native assessment."
    )


@pytest.mark.parametrize("limit", [15, 15.999, 31, True, float("inf")])
def test_BrowserLimitsReserveReadinessCleanupAndSaveBeyondTheWorkerBudget(limit):
    """The new profile cannot use a native total deadline or omit bounded descendant cleanup."""

    with pytest.raises(ValueError):
        BrowserPageCaptureLimits(timeout_seconds=limit)


def test_BrowserLimitsAreExplicitAndNativeDefaultsAndCeilingStayUnchanged():
    """Renderer readiness/cleanup margin belongs only to the separately selected browser profile."""

    assert BrowserPageCaptureLimits().timeout_seconds == 18, "Browser default budget changed."
    assert BrowserPageCaptureLimits(timeout_seconds=16).timeout_seconds == 16, (
        "Exact browser minimum budget was refused."
    )
    assert PageCaptureLimits().timeout_seconds == 10, "Native default budget changed."

    with pytest.raises(ValueError):
        PageCaptureLimits(timeout_seconds=16)


@pytest.mark.parametrize("failure,error", [
    (ValueError("PRIVATE_ERROR"), "input"), (OSError("PRIVATE_ERROR"), "connection"),
    (socket.timeout("PRIVATE_ERROR"), "timeout"),
    (PageProtocolError("PRIVATE_ERROR"), "protocol"),
    (PageResponsePolicyError("PRIVATE_ERROR"), "response-policy"),
    (PageBodyPolicyError("PRIVATE_ERROR"), "body-policy"),
    (LocalExecutionError("PRIVATE_ERROR"), "renderer-unavailable"),
])
def test_ProbeRefusalNeverImportsOrStartsTheOptionalRenderer(monkeypatch, failure, error):
    """All native acquisition/privacy errors happen before any optional dependency or DOM work."""

    output = io.BytesIO()

    def Probe(*args):
        """Refuse the native acquisition before a source body has been proved."""

        raise failure

    def Render(*args):
        """Reject any attempt to acquire renderer authority from a failed native probe."""

        pytest.fail("A failed native probe reached the optional renderer.")

    monkeypatch.setattr(worker, "RequireLinuxOwnership", lambda: None)
    monkeypatch.setattr(worker, "Probe", Probe)
    monkeypatch.setattr(worker, "Render", Render)
    monkeypatch.setattr(worker, "sys", SimpleNamespace(stdout=SimpleNamespace(buffer=output)))
    status = worker.Main((URL, "2.0", BROWSER_FIXTURE_ID, "16384"))
    raw = output.getvalue()
    record = ParseBrowserRecord(raw, URL, KnownSyntheticHtmlBody(BROWSER_FIXTURE_ID), 16384)
    assert record == {"schema_version": 1, "renderer_profile": PAGE_BROWSER_PROFILE,
                      "error": error}, "Probe refusal gained invented source/DOM metadata."
    assert status != 0 and b"PRIVATE_ERROR" not in raw, "Failed probe leaked private diagnostics."


@pytest.mark.parametrize("failure,error", [
    (worker.BrowserRenderError("renderer-unavailable"), "renderer-unavailable"),
    (worker.BrowserRenderError("renderer-version"), "renderer-version"),
    (worker.BrowserRenderError("renderer-timeout"), "renderer-timeout"),
    (worker.BrowserRenderError("renderer-policy"), "renderer-policy"),
    (worker.BrowserRenderError("PRIVATE_ERROR"), "renderer"),
    (OSError("PRIVATE_ERROR"), "renderer"), (RuntimeError("PRIVATE_ERROR"), "renderer"),
])
def test_RendererFailureRetainsOnlyCompleteVerifiedNativeSourceWithoutDOMAssessment(
    monkeypatch, browser_runner, failure, error,
):
    """Real source custody can survive an unassessed render; an error cannot invent DOM facts."""

    output = io.BytesIO()
    calls = []

    def Probe(*args):
        """Return fixed independently validated source facts before any fake renderer failure."""

        calls.append("native-probe")

        return NativeRecord()

    async def Render(body, expected):
        """Fail after proving the unchanged native body reached this boundary exactly once."""

        assert calls == ["native-probe"] and body == BODY, "Renderer preceded source verification."
        assert expected == KnownSyntheticHtmlBody(BROWSER_FIXTURE_ID), "Body identity changed."
        calls.append("render-refusal")

        raise failure

    monkeypatch.setattr(worker, "RequireLinuxOwnership", lambda: None)
    monkeypatch.setattr(worker, "Probe", Probe)
    monkeypatch.setattr(worker, "Render", Render)
    monkeypatch.setattr(worker, "asyncio", SimpleNamespace(run=browser_runner.run))
    monkeypatch.setattr(worker, "sys", SimpleNamespace(stdout=SimpleNamespace(buffer=output)))
    status = worker.Main((URL, "2.0", BROWSER_FIXTURE_ID, "16384"))
    raw = output.getvalue()
    record = ParseBrowserRecord(raw, URL, KnownSyntheticHtmlBody(BROWSER_FIXTURE_ID), 16384)
    assert record == {**NativeRecord(), "renderer_profile": PAGE_BROWSER_PROFILE, "error": error,
                      "input_body_sha256": BODY_SHA256}, "Failure source custody was partial."
    assert status != 0 and b"PRIVATE_ERROR" not in raw and "dom_sha256" not in record, (
        "Failed renderer claimed completion or leaked private engine/DOM diagnostics."
    )


def test_UnavailableLinuxOwnershipRefusesBeforeTheNativeAcquisition(monkeypatch):
    """The worker cannot rely on merely having Playwright installed on an unsupported owner."""

    output = io.BytesIO()

    def Refuse():
        """Represent missing Linux primitives before the original approved GET."""

        raise LocalExecutionError("PRIVATE_KERNEL_ERROR")

    def Probe(*args):
        """Reject acquisition after missing ownership support."""

        pytest.fail("Missing descendant ownership still acquired a page.")

    monkeypatch.setattr(worker, "RequireLinuxOwnership", Refuse)
    monkeypatch.setattr(worker, "Probe", Probe)
    monkeypatch.setattr(worker, "sys", SimpleNamespace(stdout=SimpleNamespace(buffer=output)))
    assert worker.Main((URL, "2.0", BROWSER_FIXTURE_ID, "16384")) == 78, (
        "Missing Linux ownership did not fail closed before acquisition."
    )
    assert b"PRIVATE_KERNEL_ERROR" not in output.getvalue(), "Kernel diagnostics escaped."


@pytest.mark.parametrize("body", [b"arbitrary", bytearray(BODY), BODY[:-1], b"x" * 423])
def test_RenderBoundaryIndependentlyRefusesArbitraryBytesBeforeAnyOptionalImport(
    monkeypatch, browser_runner, body,
):
    """The internal helper cannot become an alternate arbitrary-content or code entry point."""

    def RefuseImport(*args):
        """Reject any optional dependency access before the exact catalog bytes have been proved."""

        pytest.fail("Unreviewed renderer bytes reached optional dependency discovery.")

    monkeypatch.setattr(worker, "metadata", SimpleNamespace(version=RefuseImport))
    monkeypatch.setattr(worker, "import_module", RefuseImport)

    with pytest.raises(worker.BrowserRenderError, match="renderer-policy"):
        browser_runner.run(worker.Render(body, KnownSyntheticHtmlBody(BROWSER_FIXTURE_ID)))


@pytest.mark.parametrize("mode", [
    "version", "chromium-version", "missing-package", "import", "timeout", "extra-page",
    "websocket", "download", "navigation", "dom-type", "dom-size", "count", "stop",
])
def test_OfflineRendererErrorPathsPreserveFixedControlsAndNeverCompleteAnAssessment(
    monkeypatch, browser_runner, mode,
):
    """Portable API doubles exercise only refusals; actual browser execution remains required CI."""

    output = io.BytesIO()
    callbacks = {}
    facts = {"blocked": 0, "socket_closed": 0, "download_cancelled": 0, "stopped": 0}

    async def Stop():
        """Fail the last close after fixed measurements, without fabricating a successful render."""

        facts["stopped"] += 1
        raise RuntimeError("PRIVATE_ENGINE_DIAGNOSTIC")

    async def Close():
        """Close only this synthetic resource, without touching any actual browser or process."""

    async def Abort(*, error_code):
        """Observe the fixed refusal code and retain no URL or resource contents."""

        assert error_code == "blockedbyclient", "HTTP route was not aborted."
        facts["blocked"] += 1

    async def CloseSocket():
        """Observe refusal without exposing a server-connect operation on the fake socket."""

        facts["socket_closed"] += 1

    async def CancelDownload():
        """Observe download cancellation with no file or path interface."""

        facts["download_cancelled"] += 1

    def On(name, callback):
        """Register only fixed page/download callbacks rather than arbitrary event instructions."""

        callbacks[name] = callback

    async def Route(pattern, callback):
        """Require interception of every browser request before any HTML is supplied."""

        assert pattern == "**/*", "Browser HTTP interception was narrowed."
        callbacks["route"] = callback

    async def SocketRoute(pattern, callback):
        """Require all sockets to be intercepted before any HTML is supplied."""

        assert pattern == "**/*", "Browser WebSocket interception was narrowed."
        callbacks["socket"] = callback

    async def Content():
        """Return fixed known DOM bytes or a malformed/oversized serialization refusal."""

        return b"invalid-type" if mode == "dom-type" else (
            "x" * 262145 if mode == "dom-size" else BODY.decode("utf-8"))

    async def Count():
        """Return a finite count or force the independent fixed-count ceiling to refuse."""

        return 8193 if mode == "count" else 1

    def Locator(selector):
        """Admit four fixed structural selectors, without caller JavaScript or expressions."""

        assert selector in ("*", "a", "form", "input"), "Unapproved DOM query reached the engine."

        return SimpleNamespace(count=Count)

    async def SetContent(body, *, wait_until, timeout):
        """Observe known-body set_content, then inject one controlled route/policy failure."""

        assert body == BODY.decode("utf-8") and wait_until == "load" and 0 < timeout <= 6000, (
            "Renderer body or shared finite operation budget changed."
        )
        await callbacks["route"](SimpleNamespace(abort=Abort))

        if mode == "websocket":
            await callbacks["socket"](SimpleNamespace(close=CloseSocket))

        if mode == "download":
            await callbacks["download"](SimpleNamespace(cancel=CancelDownload))

        if mode == "navigation":
            page.url = "http://unexpected.invalid/"

    async def ClosePage(*, run_before_unload):
        """Refuse the extra page without executing unload handlers."""

        assert run_before_unload is False, "Extra page closure enabled JavaScript unload."

    page = SimpleNamespace(url="about:blank", on=On, set_content=SetContent, content=Content,
        locator=Locator, close=ClosePage)

    async def NewPage():
        """Publish one explicit blank page and optionally one refused unexpected-page event."""

        await callbacks["page"](page)

        if mode == "extra-page":
            await callbacks["page"](page)

        return page

    def SetTimeout(timeout):
        """Reject an unbounded zero or independently renewed browser operation timeout."""

        assert 0 < timeout <= 6000, "Default renderer timeout is unbounded."

    context = SimpleNamespace(on=On, route=Route, route_web_socket=SocketRoute, new_page=NewPage,
        pages=[page], set_default_timeout=SetTimeout, close=Close)

    async def NewContext(**options):
        """Assert the full fixed context policy before any page, request, socket or body exists."""

        assert options == {"offline": True, "java_script_enabled": False,
                           "service_workers": "block", "accept_downloads": False}, (
            "An offline browser control was omitted or weakened."
        )

        return context

    browser = SimpleNamespace(version="unknown" if mode == "chromium-version" else CHROMIUM_VERSION,
                              new_context=NewContext, close=Close)

    async def Launch(**options):
        """Admit fixed headless launch and one shared timeout, without arbitrary launch options."""

        assert set(options) == {"headless", "timeout"} and options["headless"] is True, (
            "Arbitrary browser launch configuration was admitted."
        )
        assert 0 < options["timeout"] <= 6000, "Browser startup renewed or disabled the budget."

        if mode == "timeout":
            raise TimeoutError("PRIVATE_ENGINE_DIAGNOSTIC")

        return browser

    manager = SimpleNamespace(chromium=SimpleNamespace(launch=Launch), stop=Stop)

    async def Start():
        """Return only the controlled API manager and never start a Node driver."""

        return manager

    def Version(package):
        """Return a fixed installed version or an absent optional-dependency refusal."""

        assert package == "playwright", "Unexpected package discovery occurred."

        if mode == "missing-package":
            raise worker.metadata.PackageNotFoundError("PRIVATE_PACKAGE_DIAGNOSTIC")

        return "unknown" if mode == "version" else PLAYWRIGHT_VERSION

    def Import(module):
        """Refuse or supply only the pinned Playwright API after native source verification."""

        assert module == "playwright.async_api" and mode != "version", (
            "An unpinned or unrelated optional module was imported."
        )

        if mode == "import":
            raise ImportError("PRIVATE_MODULE_DIAGNOSTIC")

        return SimpleNamespace(async_playwright=lambda: SimpleNamespace(start=Start))

    monkeypatch.setattr(worker, "metadata", SimpleNamespace(version=Version,
        PackageNotFoundError=worker.metadata.PackageNotFoundError))
    monkeypatch.setattr(worker, "import_module", Import)
    monkeypatch.setattr(worker, "RequireLinuxOwnership", lambda: None)
    monkeypatch.setattr(worker, "Probe", lambda *args: NativeRecord())
    monkeypatch.setattr(worker, "sys", SimpleNamespace(stdout=SimpleNamespace(buffer=output)))
    selected_asyncio = SimpleNamespace(**vars(asyncio))
    selected_asyncio.run = browser_runner.run
    monkeypatch.setattr(worker, "asyncio", selected_asyncio)
    status = worker.Main((URL, "2.0", BROWSER_FIXTURE_ID, "16384"))
    record = ParseBrowserRecord(output.getvalue(), URL,
                                KnownSyntheticHtmlBody(BROWSER_FIXTURE_ID), 16384)
    assert status != 0 and "error" in record and "dom_sha256" not in record, (
        "A controlled renderer error became an assessed DOM or successful browser execution."
    )
    assert record["body_sha256"] == BODY_SHA256 and b"PRIVATE_" not in output.getvalue(), (
        "Failure lost original source custody or exposed engine diagnostics."
    )

    if mode == "websocket":
        assert facts["socket_closed"] == 1, "Unexpected WebSocket was not closed."

    if mode == "download":
        assert facts["download_cancelled"] == 1, "Unexpected download was not cancelled."

    if mode == "stop":
        assert facts["blocked"] == 1 and facts["stopped"] >= 1, "Close failure path was untested."


def BrowserProvider(fixture, *, clock=lambda: NOW):
    """Select separate browser permission, limit type and reviewed body over real owners."""

    policy = replace(fixture.policy, permissions=(CapabilityPermission(PAGE_BROWSER_CAPABILITY,
        "native.loopback-page", ImpactLevel.SAFE),))

    return LocalPageCaptureProvider(fixture.root, fixture.source,
        KnownSyntheticHtmlBody(BROWSER_FIXTURE_ID), "local", policy,
        renderer=PageRenderer.PLAYWRIGHT_OFFLINE, limits=BrowserPageCaptureLimits(), clock=clock)


def BrowserJob(fixture, provider, *, timeout=20):
    """Use the real job/evidence owner with the browser's explicit cleanup/custody margin."""

    return ScanJob(JobSpec("job:browser-unit", "synthetic", "scope:local", "owner:test",
        "native.loopback-page", timeout), provider,
        evidence_store=LocalEvidenceStore(fixture.root / "evidence"))


@pytest.mark.parametrize("renderer,limits", [
    (PageRenderer.NATIVE, BrowserPageCaptureLimits()),
    (PageRenderer.PLAYWRIGHT_OFFLINE, PageCaptureLimits()),
    ("playwright-chromium-offline.v1", BrowserPageCaptureLimits()),
])
def test_ProviderRejectsMismatchedRendererLimitsBeforeAnyAcquisition(tmp_path, renderer, limits):
    """Raw strings/native budgets cannot select unbounded or implicit browser execution."""

    fixture = Fixture.Create(tmp_path / "workspace")

    with pytest.raises(ValueError):
        LocalPageCaptureProvider(fixture.root, fixture.source,
            KnownSyntheticHtmlBody(BROWSER_FIXTURE_ID), "local", fixture.policy,
            renderer=renderer, limits=limits)


@pytest.mark.parametrize("mode", ["owner", "job-budget", "permission"])
def test_BrowserPreflightRefusesBeforeNativeAcquisitionOrAnyWorker(
    tmp_path, monkeypatch, browser_runner, mode,
):
    """Missing ownership, cleanup margin or separate permission cannot start the original GET."""

    fixture = Fixture.Create(tmp_path / "workspace")
    provider = BrowserProvider(fixture)
    before = LocalModelStore(fixture.root).Open()

    def RequireOwner():
        """Model only the Linux capability check and never inspect other test processes."""

        if mode == "owner":
            raise LocalExecutionError("PRIVATE_OWNERSHIP_DIAGNOSTIC")

        if mode == "job-budget":
            pytest.fail("Insufficient job budget reached process ownership setup.")

    async def Execute(*args, **kwargs):
        """Refuse any worker/acquisition after preflight should already have denied it."""

        pytest.fail("Denied browser preflight reached an execution worker.")

    if mode == "permission":
        provider = LocalPageCaptureProvider(fixture.root, fixture.source,
            KnownSyntheticHtmlBody(BROWSER_FIXTURE_ID), "local", fixture.policy,
            renderer=PageRenderer.PLAYWRIGHT_OFFLINE, limits=BrowserPageCaptureLimits())

    monkeypatch.setattr(owned_process, "RequireLinuxOwnership", RequireOwner)
    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)
    job = BrowserJob(fixture, provider, timeout=18 if mode == "job-budget" else 20)
    snapshot = RunJob(job, browser_runner)
    assert snapshot.state is JobState.FAILED and snapshot.failure is not None, (
        "Refused browser preflight did not fail the owning job."
    )
    assert snapshot.failure.code is (JobFailureCode.AUTHORIZATION if mode == "permission"
                                     else JobFailureCode.PROVIDER), "Wrong preflight failure class."
    assert not snapshot.artifacts and LocalModelStore(fixture.root).Open() == before, (
        "Refused preflight acquired evidence or modified canonical state."
    )


@pytest.mark.parametrize("body,error", [(False, "renderer-unavailable"), (True, "renderer"),
                                       (True, "renderer-timeout")])
def test_FailedRendererRetainsVerifiedSourceCustodyWithoutFrontierOrModel(
    tmp_path, monkeypatch, browser_runner, body, error,
):
    """Only error seams are faked; real job/evidence/model owners remain active."""

    fixture = Fixture.Create(tmp_path / "workspace")
    provider = BrowserProvider(fixture)
    before = LocalModelStore(fixture.root).Open()
    record = {"schema_version": 1, "renderer_profile": PAGE_BROWSER_PROFILE, "error": error}

    if body:
        record.update(NativeRecord(), input_body_sha256=BODY_SHA256)

    raw = CanonicalRecord(record)
    result = replace(Result(raw), execution=AdapterExecution(ExecutionState.FAILED,
        124 if error == "renderer-timeout" else 78 if not body else 1, 0.1))

    async def Execute(self, request, **options):
        """Return a failed renderer and assert current source authority plus strong ownership."""

        assert options["own_descendants"] is True, "Browser worker lost descendant ownership."
        assert request.capability.identifier == PAGE_BROWSER_CAPABILITY, (
            "Browser execution reused native permission."
        )
        assert options["context_provider"]().target == provider._target, (
            "Browser launch did not reread the exact source authority."
        )

        return result

    monkeypatch.setattr(owned_process, "RequireLinuxOwnership", lambda: None)
    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)
    snapshot = RunJob(BrowserJob(fixture, provider), browser_runner)
    assert snapshot.state is JobState.FAILED and snapshot.failure is not None, (
        "A failed renderer became completed browser/page work."
    )
    assert snapshot.failure.code is (JobFailureCode.TIMEOUT if error == "renderer-timeout"
                                     else JobFailureCode.PROVIDER), "Wrong renderer failure class."
    assert LocalModelStore(fixture.root).Open() == before, "Failed render committed model state."
    records = tuple(artifact.evidence for artifact in snapshot.artifacts)
    assert {item.reference.role for item in records} == ({"stdout", "response-body"} if body
                                                        else {"stdout"}), (
        "Failure evidence lost complete source custody or invented an unverified body."
    )
    store = LocalEvidenceStore(fixture.root / "evidence")

    for item in records:
        expected = BODY if item.reference.role == "response-body" else raw
        assert store.Read(item.reference) == expected, (
            "Failure evidence changed original verified source bytes."
        )
        assert item.provenance.tool_version is None, "Failed render invented an engine version."


def test_BrowserGrantMustStillBeCurrentAfterAllEvidenceAndModelComposition(
    tmp_path, monkeypatch, browser_runner,
):
    """Post-render grant expiry retains raw custody but cannot become a canonical completed page."""

    fixture = Fixture.Create(tmp_path / "workspace")
    clock = [NOW]
    provider = BrowserProvider(fixture, clock=lambda: clock[0])
    before = LocalModelStore(fixture.root).Open()

    async def Execute(*args, **options):
        """Supply fixed report bytes only for this deterministic final-authority denial path."""

        return Result(CanonicalRecord(BrowserRecord()))

    project = provider_module.ProjectCapturedWebFrontier

    def Project(*args, **kwargs):
        """Advance the current clock after all source-body/frontier interpretation has finished."""

        result = project(*args, **kwargs)
        clock[0] = NOW + timedelta(days=1)

        return result

    monkeypatch.setattr(owned_process, "RequireLinuxOwnership", lambda: None)
    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)
    monkeypatch.setattr(provider_module, "ProjectCapturedWebFrontier", Project)
    snapshot = RunJob(BrowserJob(fixture, provider), browser_runner)
    assert snapshot.state is JobState.FAILED and snapshot.failure is not None, (
        "Expired browser authority became completed canonical page work."
    )
    assert snapshot.failure.code is JobFailureCode.AUTHORIZATION, "Grant expiry lost authority."
    assert len(snapshot.artifacts) == 2 and LocalModelStore(fixture.root).Open() == before, (
        "Expiry lost original evidence or committed model state under an expired grant."
    )
