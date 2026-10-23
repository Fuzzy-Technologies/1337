# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic private-control, ownership-refusal and interrupted-handoff boundaries."""

from __future__ import annotations

import asyncio
import hashlib
import os
import sys
from collections.abc import Iterator
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest

from fuzzy1337.executors import descendant_supervisor as supervisor
from fuzzy1337.executors import local
from fuzzy1337.executors import owned_process as owned
from fuzzy1337.executors.contracts import LocalExecutionRequest
from fuzzy1337.executors.local import LocalExecutionError, LocalExecutor
from fuzzy1337.policy import GovernedLocalExecutor, PolicyDenialReason, PolicyDeniedError
from fuzzy1337.scope import AuthorizationState, ScopeAuthorization
from tests.contract.test_local_executor import Request
from tests.unit.test_security_policy import AT, Grant, Inputs

DIGEST = "a" * 64


@pytest.fixture(scope="module")
def owned_runner() -> Iterator[asyncio.Runner]:
    """Create the owned event loop before the unit network guard on every platform."""

    with asyncio.Runner() as runner:
        runner.get_loop()
        yield runner


@pytest.fixture
def control_kernel(tmp_path, monkeypatch):
    """Model private control portably; real Linux ownership remains separate acceptance."""

    selected = SimpleNamespace(**vars(os))
    asynchronous = SimpleNamespace(**vars(asyncio))
    seals = {}
    counter = []

    def Memfd(name, flags):
        """Provide an ordinary pytest-owned file only for sealed-control protocol/error tests."""

        counter.append(name)
        descriptor = os.open(tmp_path / f"private-control-{len(counter)}",
                             os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        seals[descriptor] = 0

        return descriptor

    def Fcntl(descriptor, operation, value=0):
        """Track requested seals without pretending this deterministic double is a kernel proof."""

        if operation == owned.LINUX_F_ADD_SEALS:
            seals[descriptor] = value

            return 0

        assert operation == owned.LINUX_F_GET_SEALS, "Unexpected private-file operation."

        return seals[descriptor]

    def Loop():
        """Deliver already-published private readiness bytes without platform pipe selectors."""

        running = asyncio.get_running_loop()
        readers = {}

        def Add(descriptor, callback):
            """Schedule one synthetic readable event after the fake helper has published READY."""

            readers[descriptor] = running.call_soon(callback)

        def Remove(descriptor):
            """Cancel a pending synthetic notification before closing its exact descriptor."""

            handle = readers.pop(descriptor, None)

            if handle is not None:
                handle.cancel()

        return SimpleNamespace(create_future=running.create_future, add_reader=Add,
                               remove_reader=Remove)

    selected.memfd_create = Memfd
    selected.MFD_CLOEXEC = 1
    selected.MFD_ALLOW_SEALING = 2
    asynchronous.get_running_loop = Loop
    monkeypatch.setattr(owned, "os", selected)
    monkeypatch.setattr(owned, "sys", SimpleNamespace(platform="linux", executable=sys.executable))
    monkeypatch.setattr(owned, "asyncio", asynchronous)
    monkeypatch.setattr(owned, "RequireLinuxOwnership", lambda: None)
    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(fcntl=Fcntl))

    return selected


def Receipt(**changes):
    """Describe a fixed private receipt without source, environment or public stream data."""

    return {"schema_version": 1, "configuration_sha256": DIGEST, "cleanup": "confirmed",
        "worker_returncode": 0, "reaped_processes": 1, "failure": None, **changes}


def Reader(record, *, wrapper_status=0):
    """Use actual private pipe bytes and a fixed already-exited supervisor observation."""

    read_fd, write_fd = os.pipe()

    try:
        os.write(write_fd, record if isinstance(record, bytes) else owned.CanonicalControl(record))

    finally:
        os.close(write_fd)

    return owned.OwnedExecution(SimpleNamespace(returncode=wrapper_status), read_fd, DIGEST)


@pytest.mark.parametrize("status", [0, 17, 125, -9, -15])
def test_ReceiptPreservesActualSignedWorkerStatusAndClosesItsDescriptor(status):
    """Wrapper exit encoding cannot replace a negative original worker status with128+signal."""

    proof = Reader(Receipt(worker_returncode=status), wrapper_status=owned.WrapperExit(status))
    descriptor = proof.receipt_fd
    assert proof.Verify() == status and proof.Verify() == status, "Original worker status changed."

    with pytest.raises(OSError):
        os.fstat(descriptor)


@pytest.mark.parametrize("mutation", [
    {"schema_version": True}, {"schema_version": 2}, {"configuration_sha256": "b" * 64},
    {"cleanup": "failed"}, {"failure": "ownership"}, {"failure": "invented"},
    {"worker_returncode": True}, {"worker_returncode": None}, {"worker_returncode": -65},
    {"worker_returncode": 256}, {"reaped_processes": True}, {"reaped_processes": 0},
    {"reaped_processes": 129}, {"extra": "PRIVATE_CONTROL_MARKER"},
])
def test_ReceiptCannotConvertMalformedOrUnknownCleanupIntoCompletion(mutation):
    """Every original completion requires an exact typed, configuration-bound cleanup receipt."""

    proof = Reader(Receipt(**mutation))

    with pytest.raises(LocalExecutionError) as error:
        proof.Verify()

    assert "PRIVATE_CONTROL_MARKER" not in str(error.value), "Private control contents escaped."
    assert proof.receipt_fd == -1, "Failed verification leaked its private descriptor."


@pytest.mark.parametrize("raw", [b"", b"{}\n", b"{}", b"[]\n", b"\xff", b"x" * 513,
    b'{"schema_version":1,"schema_version":1}\n'])
def test_ReceiptRejectsAbsentNoncanonicalDuplicateAndOversizedControl(raw):
    """Missing or ambiguous control bytes cannot establish cleanup or expose source diagnostics."""

    proof = Reader(raw)

    with pytest.raises(LocalExecutionError):
        proof.Verify()


def test_WrapperExitMismatchCannotBecomeVerifiedOriginalCompletion():
    """A correct-looking receipt cannot override a contradictory observed supervisor exit."""

    with pytest.raises(LocalExecutionError):
        Reader(Receipt(), wrapper_status=125).Verify()


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_UnsupportedPlatformRefusesBeforeAnySupervisorOrWorkerLaunch(
    tmp_path, monkeypatch, owned_runner, platform,
):
    """Linux opt-in cannot accidentally fall through to the existing weaker platform owner."""

    monkeypatch.setattr(local, "sys", SimpleNamespace(platform=platform))

    def Refuse(*args, **kwargs):
        """Fail if unsupported ownership reaches either subprocess entry point."""

        pytest.fail("Unsupported descendant ownership launched a process.")

    monkeypatch.setattr(LocalExecutor, "StartProcess", Refuse)
    monkeypatch.setattr(owned, "StartOwnedExecution", Refuse)

    with pytest.raises(LocalExecutionError, match="Linux"):
        owned_runner.run(LocalExecutor(tmp_path).Execute(Request(tmp_path, "pass"),
                                                        own_descendants=True))


def test_MissingOwnKernelInterfaceRefusesBeforePayloadOrSupervisorLaunch(
    tmp_path, monkeypatch, owned_runner,
):
    """A Linux platform string alone cannot establish the required direct-child interface."""

    accesses = []

    def Refuse(path, flags):
        """Observe only the current process's exact kernel path, without reading child IDs."""

        accesses.append(path)

        raise FileNotFoundError(2, "PRIVATE_KERNEL_MARKER")

    monkeypatch.setattr(owned, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(local, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(owned, "os", SimpleNamespace(getpid=lambda: 123, memfd_create=True,
        open=Refuse, O_RDONLY=0, O_CLOEXEC=1))

    with pytest.raises(LocalExecutionError, match="interface is unavailable") as error:
        owned_runner.run(LocalExecutor(tmp_path).Execute(Request(tmp_path, "pass"),
                                                        own_descendants=True))

    assert accesses == ["/proc/123/task/123/children"], (
        "Ownership preflight enumerated another PID."
    )
    assert "PRIVATE_KERNEL_MARKER" not in str(error.value), "Kernel diagnostics escaped."


@pytest.mark.parametrize("value", [1, "true", None])
def test_OwnershipSelectionRequiresAnExplicitBoolean(tmp_path, owned_runner, value):
    """Coercible metadata cannot silently select a different process-ownership boundary."""

    with pytest.raises(LocalExecutionError):
        owned_runner.run(LocalExecutor(tmp_path).Execute(Request(tmp_path, "pass"),
                                                        own_descendants=value))


@pytest.mark.parametrize("mode", ["available", "platform", "primitive"])
def test_KernelAvailabilityRequiresLinuxPrimitivesAndClosesOnlyItsOwnOpenedDescriptor(
    monkeypatch, mode,
):
    """Availability is an own-file open/close proof, never a read of workbench job identities."""

    actions = []
    selected = SimpleNamespace(getpid=lambda: 321, open=lambda path, flags:
        actions.append((path, flags)) or 42, close=lambda descriptor: actions.append(descriptor),
        O_RDONLY=0, O_CLOEXEC=1)

    if mode != "primitive":
        selected.memfd_create = True

    monkeypatch.setattr(owned, "sys", SimpleNamespace(
        platform="darwin" if mode == "platform" else "linux"))
    monkeypatch.setattr(owned, "os", selected)

    if mode == "available":
        owned.RequireLinuxOwnership()
        assert actions == [("/proc/321/task/321/children", 1), 42], (
            "Capability preflight accessed another process or leaked its own descriptor."
        )

    else:
        with pytest.raises(LocalExecutionError, match="primitives"):
            owned.RequireLinuxOwnership()

        assert actions == [], "Unsupported platform/primitives touched a kernel process file."


@pytest.mark.parametrize("mode", [
    "configuration-size", "configuration-write", "seal", "launch", "readiness", "gate-write",
])
def test_BoundedSetupFailuresNeverAcknowledgeAWorkerOrLeakRawDiagnostics(
    tmp_path, monkeypatch, owned_runner, control_kernel, mode,
):
    """Finite config, seal and launch failures remain errors before the approved worker starts."""

    processes = []
    original_write = owned.os.write

    async def Spawn(*arguments, **kwargs):
        """Model only an acquired helper or an explicit original process-creation failure."""

        if mode == "launch":
            raise OSError(5, "PRIVATE_SETUP_MARKER")

        process = FakeSupervisor(arguments, write=original_write,
                                 ready=b"0" if mode == "readiness" else b"1")
        processes.append(process)

        return process

    def Write(descriptor, raw):
        """Inject a short write only at the selected finite private configuration or start gate."""

        if mode == "configuration-write" and raw != b"1" or mode == "gate-write" and raw == b"1":
            return 0

        return original_write(descriptor, raw)

    monkeypatch.setattr(owned.asyncio, "create_subprocess_exec", Spawn)
    monkeypatch.setattr(owned.os, "write", Write)

    if mode == "seal":
        monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(fcntl=lambda *args: 0))

    with pytest.raises(LocalExecutionError) as error:
        owned_runner.run(owned.StartOwnedExecution(("approved-worker",), tmp_path,
            {"A": "x" * 65536} if mode == "configuration-size" else {}, {}))

    assert "PRIVATE_SETUP_MARKER" not in str(error.value), "Raw source diagnostics escaped."
    assert all(not process.started and process.returncode == 125 for process in processes), (
        "An unsuccessful bounded setup reached or lost the approved worker."
    )


class FakeSupervisor:
    """Model only private handoff/receipt I/O; real process cleanup requires independent CI."""

    def __init__(self, arguments, *, corrupt=False, write=None, ready=b"1"):
        """Duplicate the same private descriptors a real spawned helper would inherit."""

        self.receipt_fd = os.dup(int(arguments[5]))
        self.gate_fd = os.dup(int(arguments[7]))
        self.digest = arguments[6]
        self.returncode = None
        self.started = False
        self.corrupt = corrupt
        self.waits = 0
        self.terminated = False
        ready_fd = os.dup(int(arguments[8]))

        try:
            (os.write if write is None else write)(ready_fd, ready)

        finally:
            os.close(ready_fd)

    def Terminate(self):
        """Model a stop request against the explicitly acquired supervisor handle."""

        self.terminated = True

    terminate = Terminate

    async def Wait(self):
        """Publish a controlled receipt only after observing the original private start gate."""

        self.waits += 1

        if self.returncode is not None:
            return self.returncode

        self.started = os.read(self.gate_fd, 2) == b"1"
        status = -9 if self.started and self.terminated else 0
        record = Receipt(configuration_sha256=self.digest,
            worker_returncode=status if self.started else None,
            reaped_processes=1 if self.started else 0,
            failure=None if self.started else "parent-lost",
            cleanup="failed" if self.corrupt else "confirmed")
        os.write(self.receipt_fd, owned.CanonicalControl(record))
        os.close(self.receipt_fd)
        os.close(self.gate_fd)
        self.returncode = owned.WrapperExit(status) if self.started else 125

        return self.returncode

    wait = Wait


@pytest.mark.parametrize("mode", [
    "normal", "gate-failure", "ack-lost", "creation-cancel", "bad-cleanup",
])
def test_InterruptedHandoffClosesPrivateDescriptorsAndNeverStartsTheApprovedWorker(
    tmp_path, monkeypatch, owned_runner, control_kernel, mode,
):
    """After-create gate failure and creation cancellation retain ownership until helper exit."""

    monkeypatch.setattr(owned, "RequireLinuxOwnership", lambda: None)
    captured = {}
    entered = asyncio.Event()
    release = asyncio.Event()

    async def Spawn(*arguments, **kwargs):
        """Inspect synthetic sealed control, then model an actual acquired helper handle."""

        configuration_fd = int(arguments[4])
        captured["original_fds"] = tuple(kwargs["pass_fds"])
        captured["payload"] = supervisor.ReadConfiguration(configuration_fd, arguments[6])
        captured["helper_environment"] = kwargs["env"]
        captured["process"] = FakeSupervisor(arguments, corrupt=mode == "bad-cleanup",
                                              write=original_write)
        entered.set()

        if mode == "creation-cancel":
            await release.wait()

        return captured["process"]

    original_write = os.write

    def Write(descriptor, raw):
        """Fail only the parent start handoff; other private control bytes stay unchanged."""

        if mode in ("gate-failure", "bad-cleanup") and raw == b"1":
            raise OSError(5, "PRIVATE_HANDOFF_MARKER")

        if mode == "ack-lost" and raw == b"1":
            original_write(descriptor, raw)

            raise OSError(5, "PRIVATE_HANDOFF_MARKER")

        return original_write(descriptor, raw)

    monkeypatch.setattr(owned.asyncio, "create_subprocess_exec", Spawn)
    monkeypatch.setattr(owned.os, "write", Write)

    async def Run():
        """Cancel only after helper creation started, before the parent receives its handle."""

        operation = asyncio.create_task(owned.StartOwnedExecution(("approved-worker", "literal"),
            tmp_path, {"OWNED_VALUE": "original", "LD_PRELOAD": "synthetic-worker-only"},
            {"LANG": "C"}))

        if mode == "creation-cancel":
            await entered.wait()
            operation.cancel()
            release.set()

            with pytest.raises(asyncio.CancelledError):
                await operation

        elif mode != "normal":
            with pytest.raises(LocalExecutionError) as error:
                await operation

            assert "PRIVATE_HANDOFF_MARKER" not in str(error.value), "Raw handoff error escaped."

        else:
            handle = await operation
            assert await handle.Wait() == 0, "The private normal receipt did not verify."

    owned_runner.run(Run())
    process = captured["process"]
    assert process.waits and process.returncode is not None, "Failed handoff lost its helper."
    assert process.started is (mode in ("normal", "ack-lost")), (
        "Private handoff did not preserve whether its acknowledgement reached the helper."
    )

    if mode in ("gate-failure", "ack-lost", "bad-cleanup"):
        assert process.terminated, "Failed post-create handoff did not stop its known helper."
    argv, environment, _ = captured["payload"]
    assert argv == ("approved-worker", "literal") and environment == {
        "OWNED_VALUE": "original", "LD_PRELOAD": "synthetic-worker-only",
    }, "Private payload changed original argv/environment semantics."
    assert captured["helper_environment"] == {"LANG": "C"}, (
        "Worker environment overrides influenced the trusted supervisor loader."
    )

    for descriptor in captured["original_fds"]:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize("raw", [b"", b"0", b"11", b"1"])
def test_ReadinessUsesASeparateExactByteAndCannotConsumeTheCleanupReceipt(
    owned_runner, control_kernel, raw,
):
    """An invalid or interrupted readiness handoff leaves original receipt framing intact."""

    proof = Reader(Receipt())
    proof.ready_fd, write_fd = os.pipe()
    os.write(write_fd, raw)
    os.close(write_fd)

    if raw == b"1":
        owned_runner.run(proof.AwaitReady())

    else:
        with pytest.raises(LocalExecutionError, match="readiness"):
            owned_runner.run(proof.AwaitReady())

    assert proof.ready_fd == -1, "Readiness descriptor remained live."
    assert proof.Verify() == 0, "Readiness consumed or corrupted the cleanup receipt."


@pytest.mark.parametrize("mode", ["cancel", "timeout"])
def test_UnfinishedReadinessClosesOnlyItsOwnDescriptor(
    monkeypatch, owned_runner, control_kernel, mode,
):
    """Cancellation or a bounded readiness deadline cannot consume a later cleanup receipt."""

    proof = Reader(Receipt())
    proof.ready_fd, write_fd = os.pipe()
    monkeypatch.setattr(owned, "OWNED_PARENT_GRACE_SECONDS", 0.01)
    running_loop = owned.asyncio.get_running_loop

    def NotReady():
        """Retain an unreadable private pipe rather than scheduling a synthetic read event."""

        selected = running_loop()
        selected.add_reader = lambda descriptor, callback: None

        return selected

    monkeypatch.setattr(owned.asyncio, "get_running_loop", NotReady)

    async def Run():
        """Interrupt only the fixed readiness wait, with its writer deliberately still open."""

        operation = asyncio.create_task(proof.AwaitReady())

        if mode == "cancel":
            await asyncio.sleep(0)
            operation.cancel()

            with pytest.raises(asyncio.CancelledError):
                await operation

        else:
            with pytest.raises(LocalExecutionError, match="deadline"):
                await operation

    try:
        owned_runner.run(Run())
        assert proof.ready_fd == -1 and proof.Verify() == 0, "Readiness changed final proof."

    finally:
        os.close(write_fd)
        proof.Close()


@pytest.mark.parametrize("mode", ["revoked", "asynchronous", "nonempty"])
def test_CurrentLaunchAuthorityIsRecheckedAfterHelperReadyBeforeAnyPayloadAck(
    tmp_path, monkeypatch, owned_runner, control_kernel, mode,
):
    """Helper startup cannot retain authority that expires while its process is being acquired."""

    monkeypatch.setattr(owned, "RequireLinuxOwnership", lambda: None)
    monkeypatch.setattr(local, "sys", SimpleNamespace(platform="linux"))
    captured = {}
    checks = []

    async def Spawn(*arguments, **kwargs):
        """Model time/authority changing during the awaited installed-helper startup."""

        captured["process"] = FakeSupervisor(arguments)

        return captured["process"]

    async def Asynchronous():
        """Represent an invalid awaitable policy result that must never be awaited."""

        pytest.fail("An asynchronous final authority check was executed.")

    def Check(request):
        """Allow the initial check and refuse only after actual helper readiness."""

        checks.append(request)

        if len(checks) == 2:
            assert captured["process"].returncode is None, "Final check occurred after exit."

            if mode == "revoked":
                raise PermissionError("AUTHORITY_REVOKED_AFTER_HELPER_READY")

            return Asynchronous() if mode == "asynchronous" else "not-None"

        return None

    monkeypatch.setattr(owned.asyncio, "create_subprocess_exec", Spawn)

    with pytest.raises(PermissionError if mode == "revoked" else LocalExecutionError) as error:
        owned_runner.run(LocalExecutor(tmp_path).Execute(Request(tmp_path, "pass"),
            own_descendants=True, pre_launch=Check))

    assert len(checks) == 2 and checks[0] is checks[1], "Fresh authority check lost original input."
    assert not captured["process"].started and captured["process"].returncode == 125, (
        "A denied fresh launch check still acknowledged the approved payload."
    )

    if mode == "revoked":
        assert str(error.value) == "AUTHORITY_REVOKED_AFTER_HELPER_READY", (
            "Verified unstarted cleanup replaced the original authority denial."
        )


@pytest.mark.parametrize("change", ["scope", "expiry"])
def test_GovernedOwnedLaunchCannotReuseScopeOrClockFromBeforeHelperStartup(
    tmp_path, monkeypatch, owned_runner, control_kernel, change,
):
    """Real policy revalidates the unchanged grant/request against current authority after READY."""

    invocation, capability, context = Inputs()
    grant = Grant(invocation, capability, context)
    request = LocalExecutionRequest(invocation, capability, grant.authorization)
    current = {"context": context, "at": AT}
    captured = {}
    observed = []

    async def Spawn(*arguments, **kwargs):
        """Change only current authority during awaited helper startup, before publishing READY."""

        if change == "scope":
            current["context"] = replace(context, scope=replace(context.scope,
                authorization=ScopeAuthorization(AuthorizationState.REVOKED)))

        else:
            current["at"] = AT + timedelta(days=1)

        captured["process"] = FakeSupervisor(arguments)

        return captured["process"]

    monkeypatch.setattr(owned.asyncio, "create_subprocess_exec", Spawn)
    monkeypatch.setattr(local, "sys", SimpleNamespace(platform="linux"))

    with pytest.raises(PolicyDeniedError) as denied:
        owned_runner.run(GovernedLocalExecutor(tmp_path, clock=lambda: current["at"]).Execute(
            request, grant=grant, context_provider=lambda: current["context"],
            on_event=observed.append, own_descendants=True))

    assert denied.value.reason == (PolicyDenialReason.SCOPE_DENIED if change == "scope"
                                   else PolicyDenialReason.GRANT_EXPIRED), (
        "Fresh helper-ready denial lost the original policy reason."
    )
    assert not captured["process"].started and captured["process"].returncode == 125, (
        "A revoked or expired grant still reached the approved worker."
    )
    assert observed == [], "A refused helper-ready launch emitted misleading worker events."


@pytest.mark.skipif(sys.platform != "linux", reason="Linux sealed-memfd protocol")
def test_UnsealedConfigurationCannotReachAnApprovedWorker():
    """Required kernel seals are checked rather than inferred from Python constant availability."""

    descriptor = os.memfd_create("owned-test-config", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)

    try:
        raw = owned.CanonicalControl({"schema_version": 1, "argv": ["approved-worker"],
                                      "environment": {}, "parent_pid": os.getpid()})
        os.write(descriptor, raw)
        os.lseek(descriptor, 0, os.SEEK_SET)

        with pytest.raises(supervisor.OwnershipFailure, match="setup"):
            supervisor.ReadConfiguration(descriptor, hashlib.sha256(raw).hexdigest())

    finally:
        os.close(descriptor)


def test_AdoptedCleanupSignalsOnlyFreshUnreapedChildrenInEachWave(monkeypatch):
    """A PID cannot be reaped/reused between kernel child selection and its signal wave."""

    owner = supervisor.DescendantOwner()
    actions = []
    waves = iter(((101,), (202,), ()))
    current = [()]

    def Reap():
        """Complete the prior wave before simulating newly adopted detached descendants."""

        actions.append("reap")

        return len(actions) > 5

    def Children():
        """Expose only the current kernel-owned selection; no global process table is consulted."""

        current[0] = next(waves)
        actions.append("children")

        return current[0]

    def Kill(process_id, selected):
        """Reject unrelated PIDs or an intervening reap that could permit identifier reuse."""

        assert actions[-1] == "children" and process_id in current[0], (
            "Unsafe PID signal selection."
        )
        assert selected == 9, "Cleanup selected an unexpected signal."
        actions.append("kill")

    monkeypatch.setattr(owner, "Reap", Reap)
    monkeypatch.setattr(owner, "Children", Children)
    monkeypatch.setattr(supervisor, "os", SimpleNamespace(kill=Kill))
    monkeypatch.setattr(supervisor, "signal", SimpleNamespace(SIGKILL=9))
    owner.Cleanup()
    assert actions == ["reap", "children", "kill", "reap", "children", "kill", "reap",
                       "children"], (
        "Adopted descendants were not handled as independently selected owned waves."
    )
