# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual SDK/job/model composition with finite deterministic executor doubles, never HTTP."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from fuzzy1337 import native_crawl as parent
from fuzzy1337 import native_crawl_workflow as product
from fuzzy1337.adapters import AdapterExecution, ExecutionState, SerializeContract
from fuzzy1337.adapters.native_crawl import (
    EXCLUSION_CODES,
    NATIVE_CRAWL_CAPABILITY,
    NATIVE_CRAWL_PROFILE,
    NATIVE_CRAWL_PROVIDER_ID,
    CanonicalRecord,
    CrawlEndpoint,
    CrawlRequestBytes,
    CrawlTemplate,
    EncodeCrawlInput,
    ParseCrawlInput,
)
from fuzzy1337.executors import (
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    LocalExecutionResult,
)
from fuzzy1337.jobs import JobContext, JobSpec, JobState, ScanJob
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.policy import CapabilityPermission, GovernedLocalExecutor, ImpactPolicy
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

AT = datetime(2026, 10, 24, tzinfo=timezone.utc)
ORIGIN = "http://127.0.0.1:32123"
PATHS = ("/alpha", "/beta", "/index", "/shared", "/unreachable")
URLS = tuple(ORIGIN + path for path in PATHS)
SEED = ORIGIN + "/index"


def Record(document, links):
    """Build controlled typed source metadata solely to exercise parent ownership, not detectors."""

    url = document["source_url"]
    _, address, port, _, _ = CrawlEndpoint(url)
    template = CrawlTemplate(document["workspace_id"], url)
    request = CrawlRequestBytes(url)
    entries = []

    for ordinal, candidate in enumerate(sorted(links), 1):
        selected = CrawlTemplate(document["workspace_id"], candidate)
        entries.append({"url": candidate, "request_reference": selected.Reference(),
            "endpoint_reference": selected.endpoint.Identity().Reference(), "ordinals": [ordinal]})

    return {"schema_version": 1, "profile": NATIVE_CRAWL_PROFILE, "outcome": "html",
        "input_sha256": hashlib.sha256(EncodeCrawlInput(document)).hexdigest(),
        "selected_urls_sha256": hashlib.sha256(
            SerializeContract(document["selected_urls"]).encode("ascii")).hexdigest(),
        "source": {"url": url, "address": address, "port": port,
            "request_reference": template.Reference(),
            "endpoint_reference": template.endpoint.Identity().Reference(),
            "request_size_bytes": len(request),
            "request_sha256": hashlib.sha256(request).hexdigest()},
        "response": {"http_version": "HTTP/1.1", "status": 200, "media_type": "text/html",
            "header_bytes": 64, "header_fields": 2, "body_bytes": 64, "body_sha256": "1" * 64},
        "frontier": {"complete": True, "anchor_count": len(entries), "entries": entries,
            "exclusion_counts": dict.fromkeys(EXCLUSION_CODES, 0)}}


def Result(raw, *, exit_code=0, termination=ExecutionTermination.PROCESS_EXIT, stderr=b""):
    """Return one immutable actual-executor-shaped double with unchanged original stream events."""

    states = {ExecutionTermination.PROCESS_EXIT:
        ExecutionState.SUCCEEDED if exit_code == 0 else ExecutionState.FAILED,
        ExecutionTermination.TIMEOUT: ExecutionState.TIMED_OUT,
        ExecutionTermination.CANCELLATION: ExecutionState.CANCELLED,
        ExecutionTermination.OUTPUT_LIMIT: ExecutionState.CANCELLED}
    execution = AdapterExecution(states[termination], exit_code, 0.01)
    events = [ExecutionEvent(0, ExecutionEventKind.STARTED)]

    if raw:
        events.append(ExecutionEvent(len(events), ExecutionEventKind.STDOUT, raw))

    if stderr:
        events.append(ExecutionEvent(len(events), ExecutionEventKind.STDERR, stderr))

    events.append(ExecutionEvent(len(events), ExecutionEventKind.COMPLETED,
                                 termination=termination))

    return LocalExecutionResult(execution, termination, raw, stderr, tuple(events))


@pytest.fixture
def owned(tmp_path, monkeypatch):
    """Use real canonical owners and only replace the finite governed executor transport seam."""

    root = tmp_path / "workspace"
    workspace = LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Native crawl"), "crawl")
    model_store = LocalModelStore(root)
    initial = model_store.Create()
    unrelated = SecurityObject(ObjectIdentity("crawl", ObjectKind.ASSET, "asset:operator"),
        {"operator_note": "preserve unrelated state"},
        (ModelProvenance("operator.seed", "run:seed", AT.isoformat(), "scope:seed",
                          "target:seed"),))
    model, _ = initial.Apply(objects=(unrelated,))
    model_store.Save(model, expected_revision=initial.revision)
    targets = tuple(Target(TargetKind.URL, url) for url in URLS)
    address = Target(TargetKind.IP, "127.0.0.1")
    LocalScopeStore(root).Create(ScopeSnapshot("local", "crawl", ScopeAuthorization(
        AuthorizationState.GRANTED, "attester:independent", "consent:native-crawl"),
        targets=(*targets, address), allow=(*targets, address)))
    policy = ImpactPolicy("local", permissions=(CapabilityPermission(
        NATIVE_CRAWL_CAPABILITY, NATIVE_CRAWL_PROVIDER_ID, parent.ImpactLevel.SAFE),))
    state = SimpleNamespace(root=root, workspace=workspace, model=model, unrelated=unrelated,
        policy=policy, calls=[], returned=[], graph={SEED: (URLS[0], URLS[1]),
        URLS[0]: (URLS[3],), URLS[1]: (URLS[3],), URLS[3]: (SEED,)},
        before_launch=None, before_return=None, record_change=None, outcome=None, inversion=False,
        validation_clock=lambda: AT)

    async def Execute(_self, request, *, grant, context_provider, on_event=None,
                      cancellation=None, own_descendants=False):
        """Exercise fresh parent launch context and return one unchanged finite execution result."""

        if state.before_launch is not None:
            state.before_launch()

        authority = context_provider()
        parent.PolicyEngine().Validate(grant, request.invocation, request.capability, authority,
                                       at=state.validation_clock())
        document = ParseCrawlInput(request.invocation.argv[-1].encode("ascii"))
        url = document["source_url"]
        state.calls.append(url)

        if state.inversion and url == URLS[0]:
            await state.sibling_done.wait()

        value = Record(document, state.graph.get(url, ()))

        if state.record_change is not None:
            value = state.record_change(value)

        raw = CanonicalRecord(value)
        result = Result(raw, **(state.outcome or {}))

        if on_event is not None:
            on_event(result.events[0])
            on_event(result.events[-1])

        if state.inversion and url == URLS[1]:
            state.sibling_done.set()

        if state.before_return is not None:
            state.before_return()

        state.returned.append(result)

        return result

    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)

    return state


def Run(owned, **kwargs):
    """Run the public actual SDK with no real transport or helper process."""

    return asyncio.run(product.RunNativeCrawl(owned.root, "local", SEED, URLS, "actor:operator",
        lambda: owned.policy, approve_safe_crawl=True, clock=lambda: AT, **kwargs))


def test_ActualSdkPlansWithoutGrantAndCommitsSortedIncrementalSourceFacts(owned, monkeypatch):
    """Planning contacts nothing; inverted completion keeps sorted BFS commits and shared work."""

    plan = product.PlanNativeCrawl(owned.root, "local", SEED, URLS, "actor:operator",
        lambda: owned.policy, clock=lambda: AT)
    assert not owned.calls and not plan.ToDict()["execution_authorized"], (
        "Descriptive planning must create no grant, contact or frontier result."
    )
    owned.inversion = True

    async def Start():
        """Create the completion inversion gate on the same loop that owns all actual tasks."""

        owned.sibling_done = asyncio.Event()

        return await product.RunNativeCrawl(owned.root, "local", SEED, URLS, "actor:operator",
            lambda: owned.policy, approve_safe_crawl=True, clock=lambda: AT)

    summary = asyncio.run(Start())
    expected = (SEED, URLS[0], URLS[1], URLS[3])
    assert summary.ExitCode() == 0 and summary.completed_urls == expected, summary.ToDict()
    assert set(owned.calls) == set(expected) and len(owned.calls) == 4, (
        "Selecting an unreachable URL must not schedule it; shared/cyclic candidates run once."
    )
    state = LocalModelStore(owned.root).Open()
    assert state.revision == owned.model.revision + 4 and summary.workspace_revision == 1, (
        "Each ordered page uses one model CAS; the SDK uses one original workspace CAS."
    )
    assert next(item for item in state.objects if item.identity == owned.unrelated.identity) == (
        owned.unrelated
    ), "Source projection must preserve unrelated operator state and provenance."
    assert not state.Objects(ObjectKind.FINDING), "Crawl discovery must not fabricate Findings."
    assert sum(item.kind.startswith("web.owned-crawl-") for item in state.observations) == 4 + 5, (
        "Each report and discovered link keeps its original fact alongside core model updates."
    )
    assert summary.custody_status == "complete" and len(summary.records) == 12, (
        "Four original reports require four original stream pairs and separate parent receipts."
    )
    assert all(item["persistence"] == "acknowledged" for item in summary.model_saves), (
        "Only exact model Save acknowledgements count as completed pages."
    )
    assert summary.workspace_persistence_status == "acknowledged", summary.ToDict()
    assert LocalWorkspaceStore(owned.root).Open().evidence_record_references == tuple(sorted(
        item.evidence_id for item in summary.records)), "Every retained original ID must reopen."
    originals = [owned.root / "evidence" / item.reference.locator for item in summary.records
                 if item.reference.role == "stdout"]
    assert {path.read_bytes() for path in originals} == {
        result.stdout for result in owned.returned
    }, "Stored stdout must be original bytes, never a parent-generated replacement."


@pytest.mark.parametrize("field,value,expected", (
    ("max_pages", 1, "output_limit"), ("max_depth", 0, "output_limit"),
    ("max_total_body_bytes", 32768, "output_limit"),
))
def test_WholeWaveReservationsRefuseBeforeDispatchWithoutRefund(owned, field, value, expected):
    """Even tiny measured bodies never refund a wave's worst-case body or page reservations."""

    summary = Run(owned, limits=replace(parent.NativeCrawlLimits(), **{field: value}))
    assert summary.snapshot.failure.code.value == expected, summary.ToDict()
    assert owned.calls == [SEED] and summary.completed_urls == (SEED,), (
        "A wave that exceeds its original reservation must launch no sibling request."
    )
    assert LocalModelStore(owned.root).Open().revision == owned.model.revision + 1, (
        "Earlier acknowledged page state must survive a later finite bound refusal."
    )


@pytest.mark.parametrize("boundary", ("plan", "launch", "save"))
def test_CompleteSetAndActualLiteralDenialNeverFallsBack(owned, boundary):
    """A selected but unreachable exclusion remains authoritative at every fresh boundary."""

    def Deny():
        """Exclude one original selected URL through the actual unchanged scope owner."""

        store = LocalScopeStore(owned.root)
        scope = store.Open("local")
        store.Save(replace(scope, exclusions=(Target(TargetKind.URL, URLS[-1]),)))

    if boundary == "plan":
        Deny()

        with pytest.raises(PermissionError):
            Run(owned)

        assert not owned.calls, "Planning denial must contact no source."

        return

    if boundary == "launch":
        owned.before_launch = Deny

    else:
        owned.before_return = Deny

    summary = Run(owned)
    assert summary.ExitCode() == 3 and not summary.completed_urls, summary.ToDict()
    assert LocalModelStore(owned.root).Open() == owned.model, (
        "Current scope drift must prevent every source projection Save."
    )
    assert LocalWorkspaceStore(owned.root).Open() == owned.workspace, (
        "Denied current authority cannot be bypassed by failure-finalizer reference retention."
    )
    assert len(owned.calls) == (0 if boundary == "launch" else 1), (
        "Final launch denial must be zero-contact; Save denial retains the real acquisition only."
    )
    assert len(summary.records) == (0 if boundary == "launch" else 3), (
        "Admitted originals precede model validation, including current Save refusal."
    )


@pytest.mark.parametrize("mode", ("unselected", "extra-field", "refusal"))
def test_InvalidWorkerOutputNeverBecomesRawEvidenceOrSourceFacts(owned, mode):
    """Only a valid closed refusal may retain original stdout; invalid href data stays transient."""

    def Change(value):
        """Inject one controlled invalid output before strict parent admission."""

        if mode == "unselected":
            value["frontier"]["entries"][0]["url"] = ORIGIN + "/private-marker"

        elif mode == "extra-field":
            value["raw-href"] = "private-marker"

        else:
            return {"schema_version": 1, "profile": NATIVE_CRAWL_PROFILE,
                    "outcome": "refused", "error": "html-policy"}

        return value

    owned.record_change = Change

    if mode == "refusal":
        owned.outcome = {"exit_code": 2}

    summary = Run(owned)
    assert summary.ExitCode() == 4 and not summary.completed_urls, summary.ToDict()
    assert LocalModelStore(owned.root).Open() == owned.model, (
        "Refused work is unassessed and must not create a source or security fact."
    )
    assert all(b"private-marker" not in (owned.root / "evidence" / item.reference.locator
        ).read_bytes() for item in summary.records), "Rejected raw hrefs cannot enter evidence."
    roles = {item.reference.role for item in summary.records}
    assert roles == ({"native-crawl-control", "stdout", "stderr"} if mode == "refusal"
                     else {"native-crawl-control"}), (
        "Malformed streams need a separately labeled control receipt with null original roles."
    )
    control = next(item for item in summary.records
                   if item.reference.role == "native-crawl-control")
    value = json.loads((owned.root / "evidence" / control.reference.locator).read_bytes())
    assert (value["original_stdout_id"] is None) == (mode != "refusal"), (
        "Parent control metadata must not impersonate original worker stdout custody."
    )


@pytest.mark.parametrize("termination,expected", (
    (ExecutionTermination.TIMEOUT, "timeout"),
    (ExecutionTermination.OUTPUT_LIMIT, "output_limit"),
    (ExecutionTermination.CANCELLATION, None),
))
def test_ActualTerminationPrecedesEvenACompleteLateReport(owned, termination, expected):
    """Complete-looking metadata cannot rewrite the original executor timeout or cancellation."""

    owned.outcome = {"exit_code": -9, "termination": termination}
    summary = Run(owned)
    assert not summary.completed_urls and LocalModelStore(owned.root).Open() == owned.model, (
        "A late report never makes interrupted work a completed source observation."
    )

    if expected is None:
        assert summary.snapshot.state is JobState.CANCELLED, summary.ToDict()

    else:
        assert summary.snapshot.failure.code.value == expected, summary.ToDict()


@pytest.mark.parametrize("which", ("model", "workspace"))
def test_LostAcknowledgementReportsActualCommitAndNeverRetries(owned, monkeypatch, which):
    """A post-replacement exception retains actual state and makes one original attempt."""

    store_type = LocalModelStore if which == "model" else LocalWorkspaceStore
    original = store_type.Save
    calls = []

    def Save(self, value, *args, **kwargs):
        """Lose only the original acknowledgement after the real owning CAS commits."""

        calls.append(True)
        original(self, value, *args, **kwargs)
        raise OSError("controlled lost acknowledgement")

    monkeypatch.setattr(store_type, "Save", Save)
    summary = Run(owned)
    assert summary.ExitCode() == 4 and len(calls) == 1, summary.ToDict()
    assert LocalModelStore(owned.root).Open().revision == owned.model.revision + (
        1 if which == "model" else 4), (
        "Actual saved state cannot be rolled back or called unchanged."
    )
    status = (summary.model_saves[0]["persistence"] if which == "model"
              else summary.workspace_persistence_status)
    assert status == "observed-committed", (
        "Independent readback must distinguish a committed lost ACK."
    )


@pytest.mark.parametrize("presentation_error", (False, True))
def test_RepeatedCallerCancelSettlesOriginalCleanupAndPreservesFirstFailure(
    owned, monkeypatch, presentation_error,
):
    """A second caller cancellation cannot detach cleanup or replace the first sink error."""

    async def Scenario():
        """Hold original fake transport cleanup under real ScanJob and public SDK ownership."""

        started, cleaning, release, cleaned = (asyncio.Event() for _ in range(4))

        async def Execute(_self, request, **kwargs):
            """Keep cleanup pending until the test's exact owned release barrier."""

            kwargs["context_provider"]()
            kwargs["on_event"](ExecutionEvent(0, ExecutionEventKind.STARTED))
            started.set()

            try:
                await asyncio.Event().wait()

            finally:
                cleaning.set()

                await release.wait()

                cleaned.set()

        def Present(event):
            """Fail presentation once acquisition actually entered its controlled wait."""

            if presentation_error and event.kind.value == "heartbeat":
                raise RuntimeError("original presentation error")

        monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)
        task = asyncio.create_task(product.RunNativeCrawl(owned.root, "local", SEED, URLS,
            "actor:operator", lambda: owned.policy, approve_safe_crawl=True,
            clock=lambda: AT, on_event=Present))

        try:
            await asyncio.wait_for(started.wait(), 1)

            if not presentation_error:
                task.cancel()

            await asyncio.wait_for(cleaning.wait(), 1)
            task.cancel()

            await asyncio.sleep(0)

            assert not task.done() and not cleaned.is_set(), (
                "Repeated caller cancellation must wait for the one actual owned cleanup."
            )
            release.set()

            if presentation_error:
                with pytest.raises(RuntimeError, match="original presentation error"):
                    await asyncio.wait_for(asyncio.shield(task), 1)

            else:
                summary = await asyncio.wait_for(asyncio.shield(task), 1)
                assert summary.snapshot.state is JobState.CANCELLED, summary.ToDict()

            assert cleaned.is_set(), "Public SDK settlement requires actual original cleanup."

        finally:
            release.set()

            if not task.done():
                task.cancel()

            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(Scenario())


@pytest.mark.parametrize("boundary", ("initial", "launch", "save"))
def test_TrustedOwnerDriftDeniesWithoutSubstitutingIndependentAttester(owned, boundary):
    """The same trusted reader participates in SDK plan, final launch and pre-Save authority."""

    actor = ["actor:operator"]

    def Change():
        """Change only the trusted current attribution, keeping independent consent unchanged."""

        actor[0] = "actor:different"

    if boundary == "initial":
        Change()

        with pytest.raises(PermissionError):
            Run(owned, current_owner_provider=lambda: actor[0])

        assert not owned.calls, "Initial current actor denial must be zero-contact."

        return

    if boundary == "launch":
        owned.before_launch = Change

    else:
        owned.before_return = Change

    summary = Run(owned, current_owner_provider=lambda: actor[0])
    assert summary.ExitCode() == 3 and not summary.completed_urls, summary.ToDict()
    assert LocalModelStore(owned.root).Open() == owned.model, (
        "A trusted actor change before Save must preserve original model state."
    )


@pytest.mark.parametrize("field,value", (
    ("owner_reference", "actor:other"), ("workspace_id", "other"),
    ("scope_reference", "scope:other"), ("provider_id", "other.provider"),
))
def test_ProviderRejectsForeignActualJobBeforeExecution(owned, field, value):
    """A valid source permission cannot launder an unrelated actual owner/context association."""

    provider = parent.NativeCrawlProvider(owned.root, "local", SEED, URLS, "actor:operator",
        lambda: owned.policy, approve_safe_crawl=True, clock=lambda: AT)
    spec = replace(JobSpec("job:controlled", "crawl", "scope:local", "actor:operator",
        NATIVE_CRAWL_PROVIDER_ID, 30), **{field: value})

    async def Start():
        """Use the real owner terminal lifecycle without a helper process."""

        job = ScanJob(spec, provider, evidence_store=provider.store)
        job.Start()

        return await job.Wait()

    snapshot = asyncio.run(Start())
    assert snapshot.failure.code.value == "authorization" and not owned.calls, (
        "Every actual workspace/scope/provider/actor mismatch must refuse before acquisition."
    )


@pytest.mark.parametrize("lost_ack", (False, True))
def test_EvidencePublicationFailureRetainsOnlyIndependentlyConfirmedOriginals(
    owned, monkeypatch, lost_ack,
):
    """No original raw publication is retried or promoted to acknowledged capture after failure."""

    original = JobContext.CaptureEvidence
    calls = []

    def Capture(self, data, role, media_type, provenance):
        """Fail exactly the stdout publication, before or after the actual owner commits it."""

        if role == "stdout":
            calls.append(True)

            if lost_ack:
                original(self, data, role, media_type, provenance)

            raise OSError("controlled publication acknowledgement failure")

        return original(self, data, role, media_type, provenance)

    monkeypatch.setattr(JobContext, "CaptureEvidence", Capture)
    summary = Run(owned)
    assert summary.ExitCode() == 4 and len(calls) == 1 and not summary.completed_urls, (
        "Failed raw publication must remain one original failed acquisition attempt."
    )
    assert summary.custody_status == "incomplete", summary.ToDict()
    assert len(summary.records) == (2 if lost_ack else 1), (
        "Only independently found exact original bytes may survive a lost acknowledgement."
    )
    assert LocalModelStore(owned.root).Open() == owned.model, (
        "Recovered storage alone cannot produce model success or a source fact."
    )


def test_ConcurrentCanonicalMutationCannotBeSilentlyRebased(owned, monkeypatch):
    """An original page model CAS conflict preserves actual operator changes without a retry."""

    original = LocalModelStore.Save
    calls = []

    def Save(self, proposed, *, expected_revision):
        """Commit an operator write exactly between original composition and model CAS."""

        calls.append(True)
        before = self.Open()
        extra = SecurityObject(ObjectIdentity("crawl", ObjectKind.ASSET, "asset:concurrent"),
            {"operator_note": "concurrent operator update"}, owned.unrelated.provenance)
        changed, _ = before.Apply(objects=(extra,))
        original(self, changed, expected_revision=before.revision)

        return original(self, proposed, expected_revision=expected_revision)

    monkeypatch.setattr(LocalModelStore, "Save", Save)
    summary = Run(owned)
    assert summary.ExitCode() == 4 and len(calls) == 1, summary.ToDict()
    assert summary.model_saves[0]["persistence"] == "unconfirmed", (
        "A foreign concurrent commit is neither this proposal nor the unchanged prior model."
    )
    assert summary.workspace_persistence_status == "not-attempted", (
        "Finalization cannot silently adopt a foreign canonical model into workspace references."
    )
    assert not LocalModelStore(owned.root).Open().Objects(ObjectKind.ENDPOINT), (
        "The stale source proposal must not replace the real concurrent operator commit."
    )


@pytest.mark.parametrize("media,role,size", (
    ("text/html", "response-body", 1), ("application/json", "stdout", 65537),
    ("application/octet-stream", "stderr", 1),
    ("application/json", "native-crawl-control", 65537),
))
def test_BoundedGetReadProfileRefusesBeforeAnyBlobAllocation(owned, media, role, size):
    """Original report ownership cannot become a generic evidence or body read capability."""

    reference = parent.EvidenceReference(role, "blobs/sha256/" + "1" * 64,
        "1" * 64, media, size)

    with pytest.raises(ValueError):
        parent.NativeCrawlEvidenceStore(owned.root / "evidence").Read(reference)


def test_TerminalCancelledOwnedTaskDoesNotBusyLoop(owned):
    """The repeated-cancel settling helper must distinguish a terminal cancelled child task."""

    async def Scenario():
        """Use only an owned local asyncio task, without transport or process execution."""

        task = asyncio.create_task(asyncio.sleep(0))
        task.cancel()

        await asyncio.gather(task, return_exceptions=True)

        with pytest.raises(RuntimeError, match="cleanup terminated without confirmation"):
            await parent.SettleCrawlTask(task)

    asyncio.run(Scenario())


def test_SynchronousAuthorityReadCannotRenewExpiredOriginalLaunchBudget(owned, monkeypatch):
    """Elapsed original time after a slow fresh authority read prevents the actual launch gate."""

    original = parent.NativeCrawlProvider.Current
    boundaries = []

    def Current(self, url, context=None):
        """Model elapsed final-read time without sleeping or changing a global clock."""

        result = original(self, url, context)

        if context is not None:
            boundaries.append(True)

            if len(boundaries) == 3:
                self._origin -= 100

        return result

    monkeypatch.setattr(parent.NativeCrawlProvider, "Current", Current)
    summary = Run(owned)
    assert summary.snapshot.failure.code.value == "timeout" and not owned.calls, summary.ToDict()
    assert LocalModelStore(owned.root).Open() == owned.model, (
        "A synchronous decision reader cannot renew the original launch or persistence deadline."
    )


@pytest.mark.parametrize("boundary", ("model", "workspace"))
@pytest.mark.parametrize("drift", ("actor", "scope", "policy", "grant-expiry"))
def test_LastCustodyReadDriftCannotBypassTheFinalOriginalSaveGuard(
    owned, monkeypatch, boundary, drift,
):
    """Fresh authority must follow every custody read at both actual canonical Save boundaries."""

    actor, clock = ["actor:operator"], [AT]
    armed = {"boundary": False, "control": False, "reads": 0, "changed": False}
    original_page = parent.NativeCrawlProvider.ValidatePage
    original_persistence = parent.NativeCrawlProvider.ValidatePersistence
    original_verify = parent.NativeCrawlProvider.VerifyRecord
    original_read = parent.NativeCrawlEvidenceStore.Read

    if boundary == "workspace" and drift == "grant-expiry":
        owned.validation_clock = lambda: clock[0]

        def Advance():
            """Issue later page grants later, while every earlier pre-Save grant stays valid."""

            clock[0] += timedelta(seconds=10)

        owned.before_return = Advance

    def ValidatePage(self, context, page):
        """Select the exact last pre-model-Save custody pass rather than initial admission."""

        if boundary == "model" and self.model_saves and (
            self.model_saves[-1]["persistence"] == "not-attempted"
        ):
            armed["boundary"] = True

        try:
            return original_page(self, context, page)

        finally:
            if boundary == "model":
                armed["boundary"] = False

    def ValidatePersistence(self, context):
        """Select the actual workspace guard, excluding earlier standalone ledger readback."""

        if boundary == "workspace":
            armed["boundary"] = True

        try:
            return original_persistence(self, context)

        finally:
            armed["boundary"] = False

    def Verify(self, record):
        """Arm only the final original control record's Get/read pair in the selected guard."""

        armed["control"] = armed["boundary"] and bool(self.pages) and (
            record == self.pages[-1].records[-1])
        armed["reads"] = 0

        try:
            return original_verify(self, record)

        finally:
            armed["control"] = False

    def Read(self, reference):
        """Introduce actual authority drift during the final bounded owning custody Read."""

        data = original_read(self, reference)

        if armed["control"]:
            armed["reads"] += 1

            if armed["reads"] == 2 and not armed["changed"]:
                armed["changed"] = True

                if drift == "actor":
                    actor[0] = "actor:changed"

                elif drift == "scope":
                    store = LocalScopeStore(owned.root)
                    scope = store.Open("local")
                    store.Save(replace(scope, exclusions=(Target(TargetKind.URL, URLS[-1]),)))

                elif drift == "policy":
                    owned.policy = replace(owned.policy, revision=owned.policy.revision + 1)

                else:
                    clock[0] = AT + timedelta(seconds=301)

        return data

    monkeypatch.setattr(parent.NativeCrawlProvider, "ValidatePage", ValidatePage)
    monkeypatch.setattr(parent.NativeCrawlProvider, "ValidatePersistence", ValidatePersistence)
    monkeypatch.setattr(parent.NativeCrawlProvider, "VerifyRecord", Verify)
    monkeypatch.setattr(parent.NativeCrawlEvidenceStore, "Read", Read)
    summary = asyncio.run(product.RunNativeCrawl(owned.root, "local", SEED, URLS,
        "actor:operator", lambda: owned.policy, approve_safe_crawl=True, clock=lambda: clock[0],
        current_owner_provider=lambda: actor[0]))
    assert armed["changed"], "The counterexample must reach the actual last custody read seam."
    assert summary.ExitCode() == 3, summary.ToDict()

    if boundary == "model":
        assert LocalModelStore(owned.root).Open() == owned.model, (
            "Current authority drift during custody reads must prevent the original model Save."
        )

    else:
        assert len(summary.completed_urls) == 4, "Earlier valid model commits remain acknowledged."

    assert LocalWorkspaceStore(owned.root).Open() == owned.workspace, (
        "Current authority drift during final custody reads must prevent workspace Save."
    )


@pytest.mark.parametrize("boundary", ("model", "workspace"))
@pytest.mark.parametrize("callback", ("actor", "policy", "clock"))
def test_FinalValidAuthorityCallbackCancellationCannotReachEitherSave(
    owned, monkeypatch, boundary, callback,
):
    """A trusted callback may cancel cooperatively while returning unchanged valid authority."""

    active = [None]
    cancelled = []
    original_page = parent.NativeCrawlProvider.ValidatePage
    original_persistence = parent.NativeCrawlProvider.ValidatePersistence

    def ValidatePage(self, context, page):
        """Arm only the exact callback-bearing pre-model-Save guard."""

        if boundary == "model" and self.model_saves and (
            self.model_saves[-1]["persistence"] == "not-attempted"
        ):
            active[0] = context

        try:
            return original_page(self, context, page)

        finally:
            if boundary == "model":
                active[0] = None

    def ValidatePersistence(self, context):
        """Arm the original workspace authority guard, never an unrelated reader."""

        if boundary == "workspace":
            active[0] = context

        try:
            return original_persistence(self, context)

        finally:
            active[0] = None

    def Cancel(selected):
        """Set only the original context's cooperative signal without changing authority."""

        if callback == selected and active[0] is not None:
            cancelled.append(True)
            active[0].Cancellation.set()

    def Owner():
        """Return the unchanged trusted actor after an optional cooperative cancellation."""

        Cancel("actor")

        return "actor:operator"

    def Policy():
        """Return the unchanged current typed policy without an authority denial."""

        Cancel("policy")

        return owned.policy

    def Clock():
        """Return the unchanged valid aware grant time after the last callback side effect."""

        Cancel("clock")

        return AT

    monkeypatch.setattr(parent.NativeCrawlProvider, "ValidatePage", ValidatePage)
    monkeypatch.setattr(parent.NativeCrawlProvider, "ValidatePersistence", ValidatePersistence)
    summary = asyncio.run(product.RunNativeCrawl(owned.root, "local", SEED, URLS,
        "actor:operator", Policy, approve_safe_crawl=True, clock=Clock,
        current_owner_provider=Owner))
    assert cancelled and summary.snapshot.state is JobState.CANCELLED, summary.ToDict()

    if boundary == "model":
        assert LocalModelStore(owned.root).Open() == owned.model, (
            "Cancellation set by a valid final authority callback must precede model Save."
        )

    else:
        assert len(summary.completed_urls) == 4, "Earlier valid source commits remain acknowledged."

    assert LocalWorkspaceStore(owned.root).Open() == owned.workspace, (
        "Cancellation set by a valid final authority callback must precede workspace Save."
    )


def test_CancelledFailureRetentionCannotReplaceTheOriginalStorageFailure(owned, monkeypatch):
    """A denied cancellation-finalizer Save preserves the original already-classified failure."""

    active = [None]
    original_guard = parent.NativeCrawlProvider.ValidatePersistence
    calls = []

    def Guard(self, context):
        """Expose only the original active finalizer context to a trusted actor callback."""

        active[0] = context

        try:
            return original_guard(self, context)

        finally:
            active[0] = None

    def Owner():
        """Cancel finalizer forward work while returning the unchanged original valid actor."""

        if active[0] is not None:
            active[0].Cancellation.set()

        return "actor:operator"

    def Save(self, proposal, *, expected_revision):
        """Fail the one original model CAS before replacement, without any hidden retry."""

        calls.append(True)
        raise OSError("controlled original model storage failure")

    monkeypatch.setattr(parent.NativeCrawlProvider, "ValidatePersistence", Guard)
    monkeypatch.setattr(LocalModelStore, "Save", Save)
    summary = Run(owned, current_owner_provider=Owner)
    assert len(calls) == 1 and summary.snapshot.failure.code.value == "storage", summary.ToDict()
    assert summary.workspace_persistence_status == "not-attempted", (
        "Cancelled failure-reference retention cannot attempt or report workspace Save."
    )
    assert LocalWorkspaceStore(owned.root).Open() == owned.workspace, (
        "An optional denied finalizer must preserve actual unchanged canonical workspace state."
    )
