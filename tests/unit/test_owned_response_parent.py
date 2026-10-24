# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic original-event, current-authority and private-custody acquisition regressions."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from fuzzy1337.adapters import AdapterExecution, ExecutionState, ImpactLevel
from fuzzy1337.adapters.owned_response_capture import (
    BytePart,
    Destination,
    RequestBytes,
    ReviewedResponse,
)
from fuzzy1337.evidence import EvidenceStorageError
from fuzzy1337.executors import ExecutionResources, LocalExecutionResult
from fuzzy1337.executors.contracts import ExecutionEvent, ExecutionEventKind, ExecutionTermination
from fuzzy1337.jobs import JobContext, JobError, JobSpec, JobState, ScanJob
from fuzzy1337.owned_response_capture import OwnedResponseAuthority, OwnedResponseCaptureProvider
from fuzzy1337.owned_response_custody import (
    CAPABILITY_ID,
    PROVIDER_ID,
    Canonical,
    OwnedResponseEvidenceStore,
    OwnedResponseStage,
    ParseCanonical,
    ReadPrivate,
    ReconcileOwnedResponse,
    ReplayOwnedResponseCapture,
)
from fuzzy1337.policy import (
    CapabilityPermission,
    GovernedLocalExecutor,
    ImpactPolicy,
    PolicyContext,
)
from fuzzy1337.scope import (
    AuthorizationState,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)

URL = "http://127.0.0.1:32123/zap-passive/missing"
AT = datetime(2026, 10, 24, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def private_system(monkeypatch):
    """Isolate an explicit fake POSIX view without changing global platform or permission claims."""

    import fuzzy1337.owned_response_capture as parent
    import fuzzy1337.owned_response_custody as custody

    monkeypatch.setattr(parent, "SupportedPlatform", lambda: True)

    if sys.platform != "linux":
        monkeypatch.setattr(custody, "NoFollowFlag", lambda: int(getattr(os, "O_NOFOLLOW", 0)))
        monkeypatch.setattr(parent, "RuntimeExecutable", lambda: "/unit/python")
        monkeypatch.setattr(
            parent, "RuntimeWorkPath", lambda path: "/unit/" + path.as_posix().replace(":", "")
        )

    if os.name == "nt":
        path_info = custody.ArtifactPathInfo
        handle_info = custody.ArtifactHandleInfo

        def ModeView(info):
            """Project unit-only POSIX modes without claiming Windows ACL proof."""

            fields = {
                key: getattr(info, key)
                for key in (
                    "st_dev",
                    "st_ino",
                    "st_uid",
                    "st_nlink",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            }
            fields["st_mode"] = stat.S_IFMT(info.st_mode) | (
                0o700 if stat.S_ISDIR(info.st_mode) else 0o600
            )

            return SimpleNamespace(**fields)

        def PathInfo(path, *, directory=False):
            """Retain actual identity/size checks under the unit-only mode view."""

            return ModeView(path_info(path, directory=directory))

        def HandleInfo(descriptor):
            """Retain the actual opened handle identity under the unit-only mode view."""

            return ModeView(handle_info(descriptor))

        monkeypatch.setattr(custody, "ArtifactPathInfo", PathInfo)
        monkeypatch.setattr(custody, "ArtifactHandleInfo", HandleInfo)
        monkeypatch.setattr(parent, "ArtifactPathInfo", PathInfo)


@pytest.fixture(scope="module")
def runner():
    """Initialize the owned loop before unit-network guards, including Windows self-pipe setup."""

    with asyncio.Runner() as loop:
        loop.get_loop()
        yield loop


@pytest.fixture
def custody_diagnostics(monkeypatch):
    """Expose only fixed phase names and static source locations on portable unit failure."""

    import fuzzy1337.owned_response_capture as parent
    import fuzzy1337.owned_response_custody as custody

    failures = []
    observed_errors = []
    original_append = OwnedResponseStage.Append
    original_capture = JobContext.CaptureEvidence
    original_verify = custody.VerifyEvidence
    original_path_info = custody.ArtifactPathInfo
    path_observations = []

    def PathInfo(path, *, directory=False):
        """Remember at most eight original file observations without extra filesystem reads."""

        info = original_path_info(path, directory=directory)

        if not directory:
            path_observations.append((path, info))
            del path_observations[:-8]

        return info

    def MetadataChecks(frame):
        """Compare original failed-read locals using fixed field names and booleans only."""

        local = frame.f_locals
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        before, opened, after = (local.get(key) for key in ("before", "opened", "after"))

        if any(info is None for info in (before, opened, after)):
            return ()

        latest = next(
            (info for path, info in reversed(path_observations) if path == local["path"]), None
        )
        pairs = (("path-before/fd-open", before, opened), ("fd-open/fd-after", opened, after))

        if latest is not None and latest is not before:
            pairs += (("fd-after/path-after", after, latest),)

        return (
            ("byte-cap-exceeded", len(local["raw"]) > local["maximum"]),
            *(
                (label, tuple((key, getattr(left, key) == getattr(right, key)) for key in fields))
                for label, left, right in pairs
            ),
        )

    def RecordFailure(phase, error):
        """Keep one bounded control-only traceback without source bytes, paths or messages."""

        while error is not None and len(failures) < 3:
            if any(error is observed for observed in observed_errors):
                break

            observed_errors.append(error)
            locations = []
            checks = ()
            trace = error.__traceback__

            while trace is not None:
                if trace.tb_frame.f_globals.get("__name__") in (
                    "fuzzy1337.owned_response_capture",
                    "fuzzy1337.owned_response_custody",
                    "fuzzy1337.jobs",
                    "fuzzy1337.evidence",
                    "fuzzy1337.artifact_inputs",
                ):
                    locations.append((trace.tb_frame.f_code.co_name, trace.tb_lineno))

                    if trace.tb_frame.f_code.co_name == "ReadPrivate":
                        checks = MetadataChecks(trace.tb_frame)

                trace = trace.tb_next

            failure = (phase, type(error).__name__, tuple(locations[-4:]))
            failures.append(failure + (checks,) if checks else failure)
            error = error.__cause__ or error.__context__

    def Observe(phase, function):
        """Preserve one original synchronous boundary and its first control-only failure."""

        def Call(*args, **kwargs):
            """Return the original result or observe and rethrow the original exception."""

            try:
                return function(*args, **kwargs)

            except Exception as error:
                RecordFailure(phase, error)
                raise

        return Call

    def ObserveAsync(phase, function):
        """Await the original boundary in the same task without creating an execution owner."""

        async def Call(*args, **kwargs):
            """Preserve the original await and do not replace an earlier observed failure."""

            try:
                return await function(*args, **kwargs)

            except Exception as error:
                if phase != "run" or not failures:
                    RecordFailure(phase, error)

                raise

        return Call

    def Append(self, frame):
        """Preserve the original staging call and expose only its fixed failed phase."""

        try:
            return original_append(self, frame)

        except Exception as error:
            RecordFailure("stage-" + frame["kind"], error)
            raise

    def Capture(self, *args, **kwargs):
        """Preserve original attachment semantics, including an error after real attachment."""

        try:
            return original_capture(self, *args, **kwargs)

        except Exception as error:
            RecordFailure("capture-evidence", error)
            raise

    def Verify(*args, **kwargs):
        """Preserve exact original evidence verification without publishing its diagnostics."""

        try:
            return original_verify(*args, **kwargs)

        except Exception as error:
            RecordFailure("verify-evidence", error)
            raise

    monkeypatch.setattr(OwnedResponseStage, "Append", Append)
    monkeypatch.setattr(JobContext, "CaptureEvidence", Capture)
    monkeypatch.setattr(custody, "VerifyEvidence", Verify)
    monkeypatch.setattr(custody, "ArtifactPathInfo", PathInfo)

    for name, phase in (("Prepare", "prepare"), ("CheckPrepared", "check-prepared")):
        original = getattr(OwnedResponseCaptureProvider, name)
        monkeypatch.setattr(OwnedResponseCaptureProvider, name, Observe(phase, original))

    for name, phase in (("Execute", "execute"), ("Run", "run")):
        original = getattr(OwnedResponseCaptureProvider, name)
        monkeypatch.setattr(OwnedResponseCaptureProvider, name, ObserveAsync(phase, original))

    for name, phase in (
        ("ValidateControlResult", "prestage-control"),
        ("ValidateResult", "prestage-admission"),
        ("PublishCapture", "publish-capture"),
    ):
        original = getattr(parent, name)
        monkeypatch.setattr(parent, name, Observe(phase, original))

    return failures


def PrintCustodyDiagnostics(failures):
    """Print one bounded ASCII control line outside pytest's abbreviated assertion repr."""

    failure = failures[0] if failures else ()
    checks = dict(failure[3]) if len(failure) == 4 else {}
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")

    def Mask(label):
        """Render original equality booleans in fixed DISMC order, marking missing observations."""

        values = dict(checks.get(label, ()))

        return "".join(
            "1" if values.get(key) is True else "0" if values.get(key) is False else "?"
            for key in fields
        )

    phases = {
        "stage-header", "stage-intent", "stage-ack", "stage-finished", "capture-evidence",
        "verify-evidence",
        "prepare", "check-prepared", "execute", "prestage-control", "prestage-admission",
        "publish-capture", "run",
    }
    kinds = {
        "ValueError", "JobError", "EvidenceStorageError", "EvidenceIntegrityError", "OSError",
        "PermissionError", "FileNotFoundError", "RuntimeError",
        "TypeError", "AssertionError",
        "OwnedResponseRecordError",
    }
    functions = {
        "Append", "ReadPrivate", "CaptureEvidence", "Put", "Get", "Read", "VerifyEvidence",
        "PublishStoredBytes", "ReadStoredBytes", "CheckStorageEntry", "ArtifactPathInfo",
        "ArtifactHandleInfo",
        "Prepare", "CheckPrepared", "Execute", "Run", "Tick", "Now", "Current",
        "DirectoryIdentity", "ValidateRequest", "ValidateControlResult", "ValidateResult",
        "PublishCapture", "WriteExclusive", "__init__", "ParseCanonical", "Canonical",
    }
    locations = []

    for name, line in failure[2][-4:] if failure else ():
        if name in functions and type(line) is int and 1 <= line <= 100000:
            locations.append(f"{name}:{line}")

    cap = checks.get("byte-cap-exceeded")
    value = {
        "phase": failure[0] if failure and failure[0] in phases else "unobserved",
        "type": failure[1] if failure and failure[1] in kinds else "unobserved",
        "location": "/".join(locations),
        "order": "DISMC",
        "cap": cap if type(cap) is bool else "?",
        "path_fd": Mask("path-before/fd-open"),
        "fd_fd": Mask("fd-open/fd-after"),
        "fd_path": Mask("fd-after/path-after"),
    }
    print("OWNED_CUSTODY " + json.dumps(value, ensure_ascii=True, separators=(",", ":")))


def Authority(url=URL):
    """Build explicit synthetic policy/scope without confusing consent attester and actor."""

    target = Target(TargetKind.URL, url)
    address = Target(TargetKind.IP, Destination(url)[0])
    scope = ScopeSnapshot(
        "lab",
        "workspace",
        ScopeAuthorization(
            AuthorizationState.GRANTED,
            "attester:independent",
            "consent:owned",
            valid_until=(AT + timedelta(minutes=5)).isoformat(),
        ),
        targets=(target, address),
        allow=(target, address),
    )
    policy = ImpactPolicy(
        "local", permissions=(CapabilityPermission(CAPABILITY_ID, PROVIDER_ID, ImpactLevel.SAFE),)
    )

    return OwnedResponseAuthority(
        PolicyContext(scope, policy, target, (target, address)), "operator:execution", True
    )


def Record(url=URL, error=None):
    """Describe only reviewed original bytes, without any scanner result or alert expectation."""

    if error:
        return Canonical(
            {
                "schema_version": 1,
                "profile": "owned-response-capture.v1",
                "outcome": "refused",
                "error": error,
            }
        )

    address, port, _, _, case = Destination(url)
    headers, body = ReviewedResponse(case)

    return Canonical(
        {
            "schema_version": 1,
            "profile": "owned-response-capture.v1",
            "outcome": "captured",
            "catalog_sha256": "fb57a1e31904e9904ef5501a6dc7721c9263e12ab55672405c5a70fb2c3798d7",
            "case_id": case,
            "url": url,
            "address": address,
            "port": port,
            "request": BytePart(RequestBytes(url)),
            "response_headers": BytePart(headers),
            "response_body": BytePart(body),
            "response": {
                "size_bytes": len(headers + body),
                "sha256": hashlib.sha256(headers + body).hexdigest(),
            },
        }
    )


def Result(raw=None, stderr=b"", error=None):
    """Preserve real typed original fragments and terminal state for an offline executor double."""

    if raw is None:
        raw = Record(error=error)

    chunks = (raw[:11], raw[11:37], raw[37:])
    events = [ExecutionEvent(0, ExecutionEventKind.STARTED)]

    for chunk in chunks:
        if chunk:
            events.append(ExecutionEvent(len(events), ExecutionEventKind.STDOUT, chunk))

    if stderr:
        events.append(ExecutionEvent(len(events), ExecutionEventKind.STDERR, stderr))

    events.append(
        ExecutionEvent(
            len(events), ExecutionEventKind.COMPLETED, termination=ExecutionTermination.PROCESS_EXIT
        )
    )

    return LocalExecutionResult(
        AdapterExecution(
            ExecutionState.FAILED if error else ExecutionState.SUCCEEDED, 2 if error else 0, 0.01
        ),
        ExecutionTermination.PROCESS_EXIT,
        raw,
        stderr,
        tuple(events),
    )


def Setup(
    tmp_path, monkeypatch, *, raw=None, error=None, stderr=b"", clock=None, monotonic=None, url=URL
):
    """Wire the real policy/job/evidence owners around a deterministic execution boundary."""

    authority = [Authority(url)]
    args = {"clock": clock or (lambda: AT)}

    if monotonic is not None:
        args["monotonic"] = monotonic

    provider = OwnedResponseCaptureProvider(
        tmp_path, url, lambda: authority[0], approve_workflow=True, **args
    )

    async def Execute(self, request, *, context_provider, on_event, cancellation, **kwargs):
        """Use the actual closed-parent fresh context and original typed event callbacks."""

        context_provider()
        result = Result(Record(url, error) if raw is None else raw, stderr, error)

        for event in result.events:
            on_event(event)

        return result

    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)
    job = ScanJob(
        JobSpec(
            "acquire",
            "workspace",
            authority[0].context.scope.Reference(),
            authority[0].owner_reference,
            PROVIDER_ID,
            30,
        ),
        provider,
        evidence_store=provider.store,
        max_events=32,
    )

    return provider, job, authority


def Run(runner, job):
    """Exercise real job lifecycle and terminal snapshot, with no process/socket."""

    async def Wait():
        """Start and reap the original owning job."""

        job.Start()

        return await job.Wait()

    return runner.run(Wait())


def test_OriginalFragmentsReceiptLastAndRelocatedReplay(
    tmp_path, monkeypatch, runner, custody_diagnostics
):
    """Actual fragment boundaries and original IDs survive source/runtime removal and relocation."""

    provider, job, _ = Setup(tmp_path, monkeypatch)
    snapshot = Run(runner, job)

    if snapshot.state is not JobState.COMPLETED:
        PrintCustodyDiagnostics(custody_diagnostics)

    assert snapshot.state is JobState.COMPLETED, "Closed acquisition must complete"
    capture = provider.capture
    assert capture is not None and len(capture.records) == 7, (
        "All original roles must be acknowledged"
    )
    receipt = json.loads(provider.store.Read(capture.records[-1].reference))
    assert [row["data_hex"] for row in receipt["events"]] == [
        event.data.hex() for event in capture.outcome.events
    ], "Original fragments must not be rechunked"
    assert capture.stage.exists() and not (capture.stage / "work").exists(), (
        "Retain stage, clean work"
    )
    reconciled = ReconcileOwnedResponse(capture.stage, provider.store, snapshot)
    assert len(reconciled.stored_ids) == len(reconciled.acknowledged_ids) == 7, (
        "Verify each original ID"
    )
    assert ReconcileOwnedResponse(capture.stage, provider.store).acknowledged_ids == (), (
        "Storage verification alone cannot acknowledge original attachments"
    )
    moved = tmp_path / "relocated"
    moved.mkdir()
    (tmp_path / "evidence").rename(moved / "evidence")
    replay = ReplayOwnedResponseCapture(
        OwnedResponseEvidenceStore(moved / "evidence"), capture.receipt_id
    )
    assert replay.record_json == Record() and len(replay.original_ids) == 6, (
        "Replay only original facts"
    )


def test_PortableCustodyDiagnosticsRetainOnlySafeFailureLocations(
    tmp_path, monkeypatch, runner, custody_diagnostics
):
    """A hidden storage error is located without echoing its arbitrary message or source data."""

    provider, job, _ = Setup(tmp_path, monkeypatch)
    private = "PRIVATE rejected diagnostics"

    def Refuse(*args, **kwargs):
        """Simulate one original store failure without any publication acknowledgement."""

        raise EvidenceStorageError(private)

    monkeypatch.setattr(provider.store, "Put", Refuse)
    snapshot = Run(runner, job)
    assert snapshot.state is JobState.FAILED and not snapshot.artifacts, (
        "Diagnostic observation cannot change incomplete original custody"
    )
    assert len(custody_diagnostics) == 2 and custody_diagnostics[0][:2] == (
        "capture-evidence",
        "JobError",
    ) and custody_diagnostics[1][:2] == (
        "capture-evidence",
        "EvidenceStorageError",
    ), "The safe diagnostic must identify the original failed phase and exception kind"
    assert private not in repr(custody_diagnostics) and all(
        type(name) is str and type(line) is int
        for name, line in custody_diagnostics[0][2]
    ), "Only static source function names and line numbers may survive diagnostic observation"


def test_PortableCustodyDiagnosticStdoutRetainsCompleteMasksWithoutPrivateValues(capsys):
    """The actual captured-stdout line preserves all masks without assertion repr abbreviation."""

    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    private = "PRIVATE path/message/bytes/hash must not appear"
    checks = (
        ("byte-cap-exceeded", False),
        ("path-before/fd-open", tuple((key, key != "st_ctime_ns") for key in fields)),
        ("fd-open/fd-after", tuple((key, True) for key in fields)),
        ("unapproved", private),
    )
    PrintCustodyDiagnostics(
        [("stage-header", "ValueError", (("Append", 606), ("ReadPrivate", 210)), checks)]
    )
    output = capsys.readouterr()
    expected = (
        'OWNED_CUSTODY {"phase":"stage-header","type":"ValueError",'
        '"location":"Append:606/ReadPrivate:210","order":"DISMC","cap":false,'
        '"path_fd":"11110","fd_fd":"11111","fd_path":"?????"}\n'
    )
    assert output.out == expected and not output.err, (
        "Captured stdout must retain every compact mask and unobserved marker without truncation"
    )
    assert output.out.isascii() and len(output.out) < 512 and private not in output.out, (
        "The bounded ASCII diagnostic cannot publish arbitrary source values or error messages"
    )


@pytest.mark.parametrize(
    "phase",
    ("prepare", "check-prepared", "execute", "prestage-control", "prestage-admission",
     "publish-capture", "run"),
)
def test_PortableDiagnosticsObserveFirstOriginalFailureBeforeOrDuringCustody(
    tmp_path, monkeypatch, runner, custody_diagnostics, capsys, phase
):
    """The broad owner catch must retain the first actual boundary before staging begins."""

    import fuzzy1337.owned_response_capture as parent

    private = b"PRIVATE source/exception diagnostic"
    provider, job, _ = Setup(
        tmp_path, monkeypatch, raw=private if phase == "prestage-admission" else None
    )

    def Refuse(*args, **kwargs):
        """Raise the original private error without allowing diagnostic message publication."""

        raise ValueError(private.decode())

    if phase == "prepare":
        monkeypatch.setattr(parent, "PrepareOwnedResponseInvocation", Refuse)

    elif phase == "check-prepared":
        monkeypatch.setattr(parent.PolicyEngine, "Validate", Refuse)

    elif phase == "execute":
        async def Execute(*args, **kwargs):
            """Fail the actual awaited owner boundary without an invented terminal result."""

            raise ValueError(private.decode())

        monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)

    elif phase == "prestage-control":
        original = Result

        def ContradictoryResult(*args, **kwargs):
            """Supply individually typed facts that contradict the actual exit termination."""

            result = original(*args, **kwargs)

            return replace(
                result, execution=AdapterExecution(ExecutionState.TIMED_OUT, None, 0.01)
            )

        monkeypatch.setattr(sys.modules[__name__], "Result", ContradictoryResult)

    elif phase == "publish-capture":
        monkeypatch.setattr(OwnedResponseStage, "WriteExclusive", Refuse)

    elif phase == "run":
        provider._monotonic = lambda: float("nan")

    snapshot = Run(runner, job)
    assert snapshot.state is JobState.FAILED and custody_diagnostics[0][0] == phase, (
        "The original first failing phase must remain visible through the owning provider catch"
    )
    PrintCustodyDiagnostics(custody_diagnostics)
    output = capsys.readouterr()
    value = json.loads(output.out.removeprefix("OWNED_CUSTODY "))
    expected_kind = "OwnedResponseRecordError" if phase == "prestage-admission" else "ValueError"
    assert value["phase"] == phase and value["type"] == expected_kind and value["location"], (
        "Each actual failed boundary must retain its fixed phase, original kind and source location"
    )
    assert private.decode() not in output.out and len(output.out) < 512 and not output.err, (
        "First-failure observation cannot echo private values, paths or exception messages"
    )


@pytest.mark.parametrize("field", ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))
def test_PortableCustodyDiagnosticsIdentifyExactPhysicalFieldWithoutValues(
    tmp_path, monkeypatch, custody_diagnostics, field
):
    """Locate each original cross-view mismatch without exporting any observed metadata value."""

    import fuzzy1337.owned_response_custody as custody

    tmp_path.chmod(0o700)
    stage = OwnedResponseStage(
        tmp_path, {"workspace_id": "workspace", "owner_reference": "operator:execution"}
    )
    original = custody.ArtifactHandleInfo

    def Changed(descriptor):
        """Inject one mismatching opened-handle field while preserving the original path view."""

        info = original(descriptor)
        fields = {
            key: getattr(info, key)
            for key in (
                "st_dev", "st_ino", "st_uid", "st_nlink", "st_size", "st_mtime_ns",
                "st_ctime_ns", "st_mode",
            )
        }
        fields[field] += 1

        return SimpleNamespace(**fields)

    monkeypatch.setattr(custody, "ArtifactHandleInfo", Changed)

    with pytest.raises(ValueError):
        stage.Append({"kind": "intent"})

    checks = dict(custody_diagnostics[0][3])
    assert checks["byte-cap-exceeded"] is False and dict(checks["path-before/fd-open"]) == {
        key: key != field
        for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    }, "The diagnostic must identify only the original unequal physical field"
    assert all(equal for _, equal in checks["fd-open/fd-after"]), (
        "Two stable original handle views must remain distinct from the mismatching path view"
    )


@pytest.mark.parametrize("field", ("workspace", "environment", "resources", "authorization"))
def test_SameInvocationCannotSubstituteFullRequest(tmp_path, monkeypatch, runner, field):
    """Fixed request validation covers fields outside the canonical policy invocation digest."""

    provider, job, _ = Setup(tmp_path, monkeypatch)

    async def Execute(self, request, *, context_provider, **kwargs):
        """Attack one full-request field while leaving the approved invocation unchanged."""

        altered = {
            "workspace": "other",
            "environment": {},
            "resources": ExecutionResources(1, 1, 0.5),
            "authorization": replace(request.authorization, authorization_id="authorization:other"),
        }
        object.__setattr__(request, field, altered[field])
        context_provider()
        raise AssertionError("Changed actual request must never reach execution")

    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)
    snapshot = Run(runner, job)
    assert snapshot.state is JobState.FAILED and not snapshot.artifacts, (
        "Whole request must fail before Put"
    )


@pytest.mark.parametrize(
    "error", ("input", "connection", "timeout", "protocol", "response-policy", "body-policy")
)
def test_ClosedRefusalPreservesOnlySafeOriginalRecord(tmp_path, monkeypatch, runner, error):
    """All six admitted worker errors retain truthful safe streams without response originals."""

    provider, job, _ = Setup(tmp_path, monkeypatch, error=error)
    snapshot = Run(runner, job)
    assert snapshot.state is JobState.FAILED, "Closed refusal is not a successful acquisition"
    assert len(snapshot.artifacts) == 3, "Refusal retains only safe streams and actual receipt"
    replay = ReplayOwnedResponseCapture(provider.store, provider.capture.receipt_id)
    assert json.loads(replay.record_json)["error"] == error, "Replay preserves original refusal"


@pytest.mark.parametrize("stderr", (b"", b"X"))
def test_UnadmittedOutputHasControlOnlyNoBytesOrContentHash(tmp_path, monkeypatch, runner, stderr):
    """Rejected response bytes and diagnostics never cross the canonical retention boundary."""

    secret = b"PRIVATE rejected response"
    provider, job, _ = Setup(tmp_path, monkeypatch, raw=secret, stderr=stderr)
    snapshot = Run(runner, job)
    assert snapshot.state is JobState.FAILED and len(snapshot.artifacts) == 1, (
        "Only safe control retained"
    )
    raw = provider.store.Read(snapshot.artifacts[0].evidence.reference)
    source = ReadPrivate(provider.capture.stage / "admitted.json", 3145728)
    assert (
        secret not in raw + source
        and hashlib.sha256(secret).hexdigest().encode() not in raw + source
    ), "Rejected original bytes and hashes cannot enter receipt or stage"
    assert provider.capture.outcome is None, "Unsafe raw outcome cannot escape as retained capture"
    assert json.loads(raw)["custody"] == "control-only", (
        "Control facts do not imply original stream custody"
    )
    with pytest.raises(ValueError):
        ReplayOwnedResponseCapture(provider.store, provider.capture.receipt_id)


@pytest.mark.parametrize("failure", ("after-attachment", "unreturned-put"))
def test_PartialPutAndRealAttachmentRemainDistinct(tmp_path, monkeypatch, runner, failure):
    """Actual stored objects do not manufacture acknowledgements or trigger publication retry."""

    provider, job, _ = Setup(tmp_path, monkeypatch)

    if failure == "after-attachment":
        original = JobContext.CaptureEvidence

        def Capture(self, raw, role, media, provenance):
            """Fail after the existing owner really attached one original artifact."""

            artifact = original(self, raw, role, media, provenance)

            if role == "owned-response-request":
                raise RuntimeError("PRIVATE callback failure")

            return artifact

        monkeypatch.setattr(JobContext, "CaptureEvidence", Capture)

    else:
        original = provider.store.Put

        def Put(*args):
            """Fail without returning an original ID after actual immutable storage publication."""

            original(*args)
            raise EvidenceStorageError("PRIVATE lost acknowledgement")

        monkeypatch.setattr(provider.store, "Put", Put)

    snapshot = Run(runner, job)
    assert snapshot.state is JobState.FAILED and provider.capture.receipt_id is None, (
        "Custody stays incomplete"
    )
    result = ReconcileOwnedResponse(provider.capture.stage, provider.store, snapshot)
    count = 3 if failure == "after-attachment" else 0
    assert len(result.acknowledged_ids) == count, (
        "Only actual original artifacts acknowledge attachment"
    )
    assert len(result.stored_ids) == (3 if count else 1), (
        "Storage and original acknowledgement differ"
    )
    assert "PRIVATE" not in str(snapshot.failure), "No rejected diagnostics escape into job failure"


def test_CurrentOwnerPolicyAndWorkflowApprovalRefuseBeforeLaunch(tmp_path, monkeypatch, runner):
    """Recorded consent attester remains independent while executing approval can be revoked."""

    provider, job, authority = Setup(tmp_path, monkeypatch)
    authority[0] = replace(authority[0], workflow_approved=False)
    snapshot = Run(runner, job)
    assert snapshot.state is JobState.FAILED and provider.prepared is None, (
        "Approval is independently required"
    )


@pytest.mark.parametrize("changed", ("owner", "policy", "scope", "approval"))
def test_AuthorityChangeAfterOriginalCapturePreservesCustody(
    tmp_path, monkeypatch, runner, changed
):
    """Original admitted evidence survives final current authority refusal without Save."""

    provider, job, authority = Setup(tmp_path, monkeypatch)
    original = GovernedLocalExecutor.Execute

    async def Execute(self, request, **kwargs):
        """Change current authority only after the actual original process return."""

        result = await original(self, request, **kwargs)
        old = authority[0]

        if changed == "owner":
            authority[0] = replace(old, owner_reference="operator:other")

        elif changed == "approval":
            authority[0] = replace(old, workflow_approved=False)

        elif changed == "policy":
            authority[0] = replace(
                old, context=replace(old.context, policy=replace(old.context.policy, revision=1))
            )

        else:
            authority[0] = replace(
                old, context=replace(old.context, scope=replace(old.context.scope, revision=1))
            )

        return result

    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)
    snapshot = Run(runner, job)
    assert snapshot.state is JobState.FAILED and len(snapshot.artifacts) == 7, (
        "Retain original custody on denial"
    )


def test_OuterCancellationAwaitsOriginalOwnerAndPublishesOnlyControl(tmp_path, monkeypatch, runner):
    """Caller cancellation bridges to and reaps the original executor without an orphan task."""

    provider, job, _ = Setup(tmp_path, monkeypatch)
    ready = asyncio.Event()
    cleanup = []

    async def Execute(self, request, *, context_provider, on_event, cancellation, **kwargs):
        """Finish the actual cancelled result only after its owned cleanup marker."""

        context_provider()
        on_event(ExecutionEvent(0, ExecutionEventKind.STARTED))
        ready.set()
        await cancellation.wait()
        cleanup.append(True)
        return LocalExecutionResult(
            AdapterExecution(ExecutionState.CANCELLED, None, 0.01),
            ExecutionTermination.CANCELLATION,
            b"",
            b"",
            (
                ExecutionEvent(0, ExecutionEventKind.STARTED),
                ExecutionEvent(
                    1, ExecutionEventKind.COMPLETED, termination=ExecutionTermination.CANCELLATION
                ),
            ),
        )

    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)

    async def Cancel():
        """Use the original public job cancellation operation."""

        job.Start()
        await ready.wait()
        await job.CancelAndWait("operator:execution", grace_seconds=0.001)
        return job.Snapshot()

    snapshot = runner.run(Cancel())
    assert snapshot.state is JobState.CANCELLED and cleanup == [True], "Await actual owned cleanup"
    assert len(snapshot.artifacts) == 1, "Only safe cancellation control survives"


@pytest.mark.parametrize("kind", ("startup", "execution", "custody"))
def test_FakeClockLateBudgetsNeverBecomeSuccess(tmp_path, monkeypatch, runner, kind):
    """Measured late returns fail without intentional sleeps or repeating whole gates."""

    elapsed = [0.0]
    provider, job, _ = Setup(tmp_path, monkeypatch, monotonic=lambda: elapsed[0])
    original = GovernedLocalExecutor.Execute

    async def Execute(self, request, **kwargs):
        """Advance only the injected clock at the selected finite boundary."""

        if kind == "startup":
            elapsed[0] = 3

        result = await original(self, request, **kwargs)

        if kind == "execution":
            elapsed[0] = 17

        return result

    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)

    if kind == "custody":
        original_put = provider.store.Put

        def Put(*args):
            """Simulate elapsed fsync without a real blocking test."""

            result = original_put(*args)
            elapsed[0] += 2
            return result

        monkeypatch.setattr(provider.store, "Put", Put)

    snapshot = Run(runner, job)
    assert snapshot.state is JobState.FAILED, "Late phase cannot produce successful job"


def test_ReplayRejectsChangedOriginalManifestRoleAndWire(tmp_path, monkeypatch, runner):
    """Content equality never replaces exact original role/provenance association."""

    provider, job, _ = Setup(tmp_path, monkeypatch)
    Run(runner, job)
    capture = provider.capture
    raw = provider.store.Read(capture.records[-1].reference)
    receipt = json.loads(raw)
    receipt["evidence_ids"]["headers"] = receipt["evidence_ids"]["body"]
    altered = provider.store.Put(
        Canonical(receipt),
        "owned-response-receipt",
        "application/json",
        capture.records[-1].provenance,
    )
    with pytest.raises(ValueError):
        ReplayOwnedResponseCapture(provider.store, altered.evidence_id)


@pytest.mark.parametrize("raw", (b"{}\n", b'{"x":1,"x":2}', b'{"x":NaN}', b"[]", b"{"))
def test_StageControlParserRejectsNoncanonicalOrUnsafeJson(raw):
    """Pure bounded control admission has no last-key-wins or nonfinite fallback."""

    with pytest.raises(ValueError):
        ParseCanonical(raw, 8192)


@pytest.mark.parametrize("address", ("127.0.0.1", "[::1]"))
@pytest.mark.parametrize("case", ("missing", "fixed", "body-decoy"))
def test_AllClosedCasesAndLiteralFamiliesUseSameParentOwners(
    tmp_path, monkeypatch, runner, address, case
):
    """Cover both literal families and all exact original catalog cases."""

    url = f"http://{address}:32123/zap-passive/{case}"
    provider, job, _ = Setup(tmp_path, monkeypatch, url=url)
    snapshot = Run(runner, job)
    assert snapshot.state is JobState.COMPLETED, "Every exact catalog case must admit"
    replay = ReplayOwnedResponseCapture(provider.store, provider.capture.receipt_id)
    assert replay.record_json == Record(url), "Replay preserves the exact original selected URL"


@pytest.mark.parametrize(
    "mutation", ("none", "copy", "policy", "owner", "budget", "stage", "request", "context")
)
def test_PersistenceGuardUsesSameOriginalCaptureAuthorityTaskAndFinalBudget(
    tmp_path, monkeypatch, runner, mutation
):
    """Validate original post-cleanup proofs without allocating a fresh budget."""

    elapsed = [0.0]
    provider, _, authority = Setup(tmp_path, monkeypatch, monotonic=lambda: elapsed[0])
    calls = []

    class Composition:
        """Exercise only persistence guards inside the same actual owning provider task; no Save."""

        async def Run(self, context):
            """Validate exact original capture at both synthetic persistence boundaries."""

            await provider.Run(context)
            capture = provider.capture
            provider.ValidatePersistence(context, capture)
            calls.append("before")

            if mutation == "copy":
                capture = replace(capture)

            elif mutation == "policy":
                old = authority[0]
                authority[0] = replace(
                    old,
                    context=replace(old.context, policy=replace(old.context.policy, revision=1)),
                )

            elif mutation == "owner":
                authority[0] = replace(authority[0], owner_reference="operator:other")

            elif mutation == "budget":
                elapsed[0] = 3

            elif mutation == "stage":
                (capture.stage / "admitted.json").write_bytes(b"{}")

            elif mutation == "request":
                object.__setattr__(capture.request, "resources", ExecutionResources(1, 1, 0.5))

            elif mutation == "context":
                context = JobContext(job)

            provider.ValidatePersistence(context, capture)
            calls.append("after")

    job = ScanJob(
        JobSpec(
            "compose",
            "workspace",
            authority[0].context.scope.Reference(),
            "operator:execution",
            PROVIDER_ID,
            30,
        ),
        Composition(),
        evidence_store=provider.store,
        max_events=32,
    )
    snapshot = Run(runner, job)
    assert snapshot.state is (JobState.COMPLETED if mutation == "none" else JobState.FAILED), (
        "Only original capture, current authority and remaining budget may cross persistence guards"
    )
    assert calls == (["before", "after"] if mutation == "none" else ["before"]), (
        "Denial must stop the following boundary without pretending rollback"
    )
    with pytest.raises(JobError):
        provider.ValidatePersistence(provider._context, provider.capture)


@pytest.mark.parametrize("changed", ("stdout-join", "sequence", "kind", "termination", "state"))
def test_ActualEventControlSubstitutionNeverCreatesOriginalReceipt(changed):
    """Untrusted typed dataclass mutation cannot substitute control or stream association."""

    from fuzzy1337.owned_response_custody import ValidateControlResult

    result = Result()

    if changed == "stdout-join":
        object.__setattr__(result, "stdout", b"other")

    elif changed == "sequence":
        object.__setattr__(result.events[1], "sequence", 100)

    elif changed == "kind":
        object.__setattr__(result.events[1], "kind", "stdout")

    elif changed == "termination":
        object.__setattr__(result.events[-1], "termination", ExecutionTermination.TIMEOUT)

    else:
        object.__setattr__(result.execution, "duration_seconds", float("nan"))

    with pytest.raises(ValueError):
        ValidateControlResult(result)


@pytest.mark.parametrize(
    "changed", ("admitted", "log-replaced", "log-bytes", "directory", "oversize-frame", "too-many")
)
def test_StageRefusesReplacementCorruptionAndIncrementalBounds(tmp_path, changed):
    """Refuse staging tampering without truncating or repairing an original file."""

    tmp_path.chmod(0o700)
    stage = OwnedResponseStage(
        tmp_path, {"workspace_id": "workspace", "owner_reference": "operator:execution"}
    )

    if changed == "admitted":
        (tmp_path / "admitted.json").write_bytes(b"{}")

    elif changed == "log-replaced":
        raw = (tmp_path / "publication.log").read_bytes()
        (tmp_path / "publication.log").rename(tmp_path / "old-log")
        (tmp_path / "publication.log").write_bytes(raw)
        (tmp_path / "publication.log").chmod(0o600)

    elif changed == "log-bytes":
        with (tmp_path / "publication.log").open("ab") as output:
            output.write(b"X")

    elif changed == "directory":
        stage.identity = (0, 0, 0, 0, 0)

    elif changed == "too-many":
        stage.frames = 16

    frame = {"kind": "intent", "role": "stdout", "candidate_id": "sha256:" + "0" * 64}

    if changed == "oversize-frame":
        frame["candidate_id"] = "X" * 8192

    with pytest.raises(ValueError):
        stage.Append(frame)


@pytest.mark.parametrize("mutation", ("partial", "bad-frame", "reordered", "early-finished"))
def test_ReconciliationRefusesPartialOrReorderedImmutableLog(
    tmp_path, monkeypatch, runner, mutation
):
    """Read-only recovery cannot repair a partial log or infer missing original acknowledgements."""

    provider, job, _ = Setup(tmp_path, monkeypatch)
    Run(runner, job)
    stage = provider.capture.stage
    path = stage / "publication.log"
    raw = path.read_bytes()

    if mutation == "partial":
        raw = raw[:-1]

    elif mutation == "bad-frame":
        raw = b"\xff\xff\xff\xff" + raw[4:]

    else:
        size = int.from_bytes(raw[:4], "big")
        header = raw[: 4 + size]
        frame = (
            {"kind": "finished", "custody": "acknowledged"}
            if mutation == "early-finished"
            else {"kind": "intent", "role": "stderr", "candidate_id": "sha256:" + "0" * 64}
        )
        encoded = Canonical(frame)
        raw = header + len(encoded).to_bytes(4, "big") + encoded

    path.write_bytes(raw)
    with pytest.raises(ValueError):
        ReconcileOwnedResponse(stage, provider.store, job.Snapshot())
    assert path.read_bytes() == raw, "Recovery must not mutate or repair the original corrupted log"


@pytest.mark.parametrize(
    "field", ("schema_version", "custody", "request", "events", "refusal", "provenance")
)
def test_OfflineReplayRejectsAlteredCanonicalReceipt(tmp_path, monkeypatch, runner, field):
    """Canonical storage alone cannot turn a substituted receipt into original acquisition facts."""

    provider, job, _ = Setup(tmp_path, monkeypatch)
    Run(runner, job)
    original = provider.capture.records[-1]
    document = json.loads(provider.store.Read(original.reference))
    provenance = original.provenance

    if field == "schema_version":
        document[field] = 2

    elif field == "custody":
        document[field] = "control-only"

    elif field == "request":
        document[field]["environment"]["PATH"] = "injected"

    elif field == "events":
        document[field][1]["data_hex"] = "00"

    elif field == "refusal":
        document[field] = "protocol"

    else:
        provenance = replace(provenance, workspace_id="other")

    altered = provider.store.Put(
        Canonical(document), "owned-response-receipt", "application/json", provenance
    )
    with pytest.raises(ValueError):
        ReplayOwnedResponseCapture(provider.store, altered.evidence_id)


@pytest.mark.parametrize("value", (float("nan"), float("inf"), -1, True))
def test_FiniteMonotonicClockCannotBypassSharedBudget(tmp_path, monkeypatch, value):
    """Invalid injected time cannot silently disable a deadline comparison."""

    provider, _, _ = Setup(tmp_path, monkeypatch, monotonic=lambda: value)
    with pytest.raises(ValueError):
        provider.Tick()


def test_RegressingMonotonicClockRefusesInsteadOfRenewingBudget(tmp_path, monkeypatch):
    """A backwards current budget clock cannot provide additional forward time."""

    value = [2.0]
    provider, _, _ = Setup(tmp_path, monkeypatch, monotonic=lambda: value[0])
    assert provider.Tick() == 2, "Observe original monotonic origin"
    value[0] = 1
    with pytest.raises(ValueError):
        provider.Tick()


def test_UnsupportedParentPlatformRefusesBeforeWorkOrLaunch(tmp_path, monkeypatch, runner):
    """Unit fake POSIX support never weakens the production explicit platform refusal."""

    import fuzzy1337.owned_response_capture as parent

    provider, job, _ = Setup(tmp_path, monkeypatch)
    monkeypatch.setattr(parent, "SupportedPlatform", lambda: False)
    snapshot = Run(runner, job)
    assert snapshot.state is JobState.FAILED and provider.prepared is None, "No unsupported launch"
    assert not snapshot.artifacts, "Do not fabricate execution originals"


def test_ForcedCallerCancellationReapsSameExecutorTask(tmp_path, monkeypatch, runner):
    """A direct caller task cancellation still bridges and awaits the one original owner."""

    provider, _, authority = Setup(tmp_path, monkeypatch)
    ready = asyncio.Event()
    cleanup = []
    owned = []

    async def Execute(self, request, *, context_provider, on_event, cancellation, **kwargs):
        """Wait for the real parent cancellation bridge before marking cleanup complete."""

        context_provider()
        on_event(ExecutionEvent(0, ExecutionEventKind.STARTED))
        ready.set()
        await cancellation.wait()
        cleanup.append("confirmed")
        return LocalExecutionResult(
            AdapterExecution(ExecutionState.CANCELLED, None, 0.01),
            ExecutionTermination.CANCELLATION,
            b"",
            b"",
            (
                ExecutionEvent(0, ExecutionEventKind.STARTED),
                ExecutionEvent(
                    1, ExecutionEventKind.COMPLETED, termination=ExecutionTermination.CANCELLATION
                ),
            ),
        )

    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)

    class Composition:
        """Cancel the exact caller task without changing any generic job or executor API."""

        async def Run(self, context):
            """Wait for actual executor startup, then cancel and reap the original caller."""

            task = asyncio.create_task(provider.Run(context))
            owned.append(task)
            await ready.wait()
            task.cancel()
            await task

    job = ScanJob(
        JobSpec(
            "force",
            "workspace",
            authority[0].context.scope.Reference(),
            "operator:execution",
            PROVIDER_ID,
            30,
        ),
        Composition(),
        evidence_store=provider.store,
        max_events=32,
    )
    snapshot = Run(runner, job)
    assert snapshot.state is JobState.CANCELLED and cleanup == ["confirmed"], (
        "Owned cleanup precedes terminal"
    )
    assert owned[0].done() and len(snapshot.artifacts) == 1, (
        "No abandoned task or raw partial output"
    )


def test_ControlParserRejectsUnpairedUnicodeWithoutDiagnosticEcho():
    """Canonical escaping cannot admit a malformed Unicode source-control string."""

    with pytest.raises(ValueError):
        ParseCanonical(b'{"x":"\\ud800"}', 8192)


CANCELLED_OWNER_PROGRAM = """
import asyncio
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, SOURCE_PATH_TOKEN)
import fuzzy1337.owned_response_capture as parent
from fuzzy1337.executors.contracts import ExecutionEvent, ExecutionEventKind

async def CancelledOwner(self, request, *, on_event, **kwargs):
    on_event(ExecutionEvent(0, ExecutionEventKind.STARTED))
    raise asyncio.CancelledError

async def Exercise(root):
    provider = parent.OwnedResponseCaptureProvider(
        root, "http://127.0.0.1:32123/zap-passive/missing", lambda: None,
        approve_workflow=True)
    provider.CheckPrepared = lambda *args: None
    parent.GovernedLocalExecutor.Execute = CancelledOwner
    context = SimpleNamespace(Cancellation=asyncio.Event(), Heartbeat=lambda: None,
                              CheckCancellation=lambda: None)
    prepared = SimpleNamespace(request=object(), grant=object(), operation=root)
    provider.Prepare = lambda context: prepared
    (root / "work").mkdir()
    try:
        await provider.Run(context)
    except asyncio.CancelledError:
        print(json.dumps({"owner_cancelled": provider._owner_cancelled,
            "cleanup_confirmed": provider._cleanup_confirmed,
            "capture_absent": provider.capture is None,
            "work_retained": (root / "work").exists(),
            "stage_absent": not (root / "admitted.json").exists()}))
    else:
        raise AssertionError("Cancelled owner cannot manufacture a result")

with tempfile.TemporaryDirectory() as root:
    asyncio.run(Exercise(Path(root).resolve()))
"""


def test_TerminalCancelledExecuteTaskCannotBusyLoopOrInventCleanup():
    """An external OS deadline catches the old loop even when asyncio timers cannot run."""

    import subprocess
    from pathlib import Path

    program = CANCELLED_OWNER_PROGRAM.replace(
        "SOURCE_PATH_TOKEN", repr(str(Path(__file__).resolve().parents[2] / "src"))
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", program], capture_output=True, timeout=4, check=False
    )
    assert completed.returncode == 0 and not completed.stderr, (
        "Terminal child cancellation must promptly propagate without a fabricated result"
    )
    assert json.loads(completed.stdout) == {
        "owner_cancelled": True,
        "cleanup_confirmed": False,
        "capture_absent": True,
        "work_retained": True,
        "stage_absent": True,
    }, "Child cancellation cannot assert original result, cleanup proof or capture custody"


@pytest.mark.parametrize(
    "termination,state,expected",
    (
        (ExecutionTermination.TIMEOUT, ExecutionState.TIMED_OUT, "timeout"),
        (ExecutionTermination.OUTPUT_LIMIT, ExecutionState.CANCELLED, "output_limit"),
        (ExecutionTermination.CANCELLATION, ExecutionState.CANCELLED, None),
    ),
)
def test_ActualExecutorTerminalReasonSurvivesSafeControlCustody(
    tmp_path, monkeypatch, runner, termination, state, expected
):
    """An inner owner deadline/output limit cannot be replaced by generic provider refusal."""

    provider, job, _ = Setup(tmp_path, monkeypatch)
    partial = b"PRIVATE incomplete original"
    result = LocalExecutionResult(
        AdapterExecution(state, None, 0.01),
        termination,
        partial,
        b"",
        (
            ExecutionEvent(0, ExecutionEventKind.STARTED),
            ExecutionEvent(1, ExecutionEventKind.STDOUT, partial),
            ExecutionEvent(2, ExecutionEventKind.COMPLETED, termination=termination),
        ),
    )

    async def Execute(self, request, *, context_provider, on_event, **kwargs):
        """Return the actual typed original outcome before the parent outer timeout expires."""

        context_provider()
        for event in result.events:
            on_event(event)
        return result

    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)
    snapshot = Run(runner, job)
    assert not provider._timed_out, "Classify actual inner result without relying on outer deadline"
    assert snapshot.state is (JobState.CANCELLED if expected is None else JobState.FAILED), (
        "Keep original owner termination precedence after safe custody"
    )
    assert expected is None or snapshot.failure.code.value == expected, (
        "Retain exact original timeout or output-limit failure code"
    )
    assert len(snapshot.artifacts) == 1, "Only safe control receipt can survive incomplete output"
    raw = provider.store.Read(snapshot.artifacts[0].evidence.reference)
    assert partial not in raw and hashlib.sha256(partial).hexdigest().encode() not in raw, (
        "Actual owner classification cannot authorize retaining rejected source bytes or hashes"
    )
    receipt = json.loads(raw)
    assert (
        receipt["execution"]["state"] == state.value and receipt["termination"] == termination.value
    ), "Safe receipt preserves the actual original execution state and termination"


@pytest.mark.parametrize(
    "termination,state,exit_code",
    (
        (ExecutionTermination.TIMEOUT, ExecutionState.SUCCEEDED, 0),
        (ExecutionTermination.OUTPUT_LIMIT, ExecutionState.SUCCEEDED, 0),
        (ExecutionTermination.CANCELLATION, ExecutionState.SUCCEEDED, 0),
        (ExecutionTermination.PROCESS_EXIT, ExecutionState.TIMED_OUT, None),
        (ExecutionTermination.PROCESS_EXIT, ExecutionState.CANCELLED, None),
        (ExecutionTermination.TIMEOUT, ExecutionState.FAILED, 2),
        (ExecutionTermination.OUTPUT_LIMIT, ExecutionState.FAILED, 2),
        (ExecutionTermination.CANCELLATION, ExecutionState.FAILED, 2),
        (ExecutionTermination.TIMEOUT, ExecutionState.CANCELLED, None),
        (ExecutionTermination.CANCELLATION, ExecutionState.TIMED_OUT, None),
        (ExecutionTermination.OUTPUT_LIMIT, ExecutionState.TIMED_OUT, None),
    ),
)
def test_ContradictoryTypedTerminalPairsRefuseBeforeAnyStaging(
    tmp_path, monkeypatch, runner, termination, state, exit_code
):
    """Individually valid typed fields cannot manufacture a contradictory original owner result."""

    provider, job, _ = Setup(tmp_path, monkeypatch)
    result = LocalExecutionResult(
        AdapterExecution(state, exit_code, 0.01),
        termination,
        b"",
        b"",
        (
            ExecutionEvent(0, ExecutionEventKind.STARTED),
            ExecutionEvent(1, ExecutionEventKind.COMPLETED, termination=termination),
        ),
    )

    async def Execute(self, request, *, context_provider, on_event, **kwargs):
        """Return a typed contradiction without a process or source content."""

        context_provider()
        for event in result.events:
            on_event(event)
        return result

    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)
    snapshot = Run(runner, job)
    assert snapshot.state is JobState.FAILED and not snapshot.artifacts, (
        "Contradictory original controls must fail before any canonical evidence"
    )
    assert (
        provider.capture is None and not (provider.prepared.operation / "admitted.json").exists()
    ), "Do not stage or manufacture custody from contradictory original controls"
