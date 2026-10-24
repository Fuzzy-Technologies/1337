# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic closed-wire, source-build and mocked ownership boundary tests only."""

from __future__ import annotations

import asyncio
import importlib.util
import io
import re
import struct
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/zap_inert"


def Load(name):
    """Load a fixed test helper without invoking its runtime entrypoint."""

    spec = importlib.util.spec_from_file_location("unit_inert_" + name, FIXTURE / (name + ".py"))
    assert spec is not None and spec.loader is not None, ("Closed inert contract invariant failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    return module


CONTRACT = Load("contract")
BUILD = Load("build")


@pytest.mark.parametrize("mode", CONTRACT.MODES)
def test_ClosedRequestRoundTripsExactBytes(mode):
    """Encode only the fixed network-endian fields and zero padding."""

    envelope = CONTRACT.Envelope(mode, 32123, 32124, bytes(range(16)), bytes(range(32)))
    raw = envelope.Encode()
    assert len(raw) == 64 and raw[9:12] == bytes(3), ("Closed inert contract invariant failed")
    assert raw[12:16] == bytes.fromhex("7d7b7d7c"), ("Closed inert contract invariant failed")
    assert CONTRACT.Decode(raw) == envelope, ("Closed inert contract invariant failed")
    assert envelope.Ack() == b"1337ZAK1" + bytes(range(16)) + bytes(range(32)), (
        "Closed inert contract invariant failed"
    )
    assert CONTRACT.READY.size == 96 and CONTRACT.ACK.size == 56, (
        "Closed inert contract invariant failed"
    )


@pytest.mark.parametrize("offset,value", ((0, 0), (8, 5), (9, 1), (10, 1), (11, 1), (12, 0)))
def test_RequestRefusesAlternateVersionPaddingModeAndPorts(offset, value):
    """A closed request has no extension or alternate padding interpretation."""

    raw = bytearray(CONTRACT.Envelope("normal", 32123, 32124, bytes(16), bytes(32)).Encode())
    raw[offset] = value

    with pytest.raises(ValueError):
        CONTRACT.Decode(bytes(raw))


@pytest.mark.parametrize("suffix", (b"", b"extra"))
def test_RequestRefusesTruncationAndTrailingBytes(suffix):
    """Exactly 64 original bytes are required."""

    with pytest.raises(ValueError):
        CONTRACT.Decode(bytes(63) + suffix)


def test_ReadyDeclarationsMustMatchOriginalBindingAndExactQuota():
    """Claimed fields cannot change nonce, binding or closed limits."""

    envelope = CONTRACT.Envelope("normal", 32123, 32124, bytes(16), bytes(32))
    original = (b"1337ZRD1", bytes(16), bytes(32), 7, 9, 4096, 16384, 1024)
    assert CONTRACT.ParseReady(CONTRACT.READY.pack(*original), envelope) == original[3:], (
        "Closed inert contract invariant failed"
    )

    for index in range(len(original)):
        changed = list(original)
        changed[index] = b"X" * len(changed[index]) if isinstance(changed[index], bytes) else 0

        with pytest.raises(ValueError):
            CONTRACT.ParseReady(CONTRACT.READY.pack(*changed), envelope)


def test_ArgumentsAreClosedAndContainNoPermissiveFlags():
    """Only four typed own handles and the fixed fixture enter the helper template."""

    args = CONTRACT.BwrapArguments("/private/bin/bwrap", (3, 4, 5, 6))
    assert args[-3:] == ("--", "/inert", "/request.bin"), ("Closed inert contract invariant failed")
    assert args.count("--bind-fd") == 1 and args.count("--ro-bind-fd") == 3, (
        "Closed inert contract invariant failed"
    )
    assert not any("try" in value or value in {"--unshare-all", "--share-net",
        "--not-a-security-boundary"} for value in args), ("Closed inert contract invariant failed")
    assert "--disable-userns" in args and "--remount-ro" in args, (
        "Closed inert contract invariant failed"
    )

    for invalid in ((3, 3, 4, 5), (0, 3, 4, 5), (True, 3, 4, 5), (3, 4, 5)):
        with pytest.raises(ValueError):
            CONTRACT.BwrapArguments("/private/bin/bwrap", invalid)


def Elf(kind=1):
    """Construct fixed ELF metadata without compiling or running anything."""

    raw = bytearray(120)
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", raw, 16, 2, 62, 1)
    struct.pack_into("<Q", raw, 32, 64)
    struct.pack_into("<HH", raw, 54, 56, 1)
    struct.pack_into("<I", raw, 64, kind)

    return raw


def test_StaticElfAdmissionRejectsInterpreterDynamicAndWrongArchitecture():
    """ELF admission is deterministic metadata inspection, never fixture execution."""

    BUILD.ValidateElf(bytes(Elf()))

    for raw in (Elf(2), Elf(3), bytes(63), b"bad" * 80):
        with pytest.raises(ValueError):
            BUILD.ValidateElf(bytes(raw))

    raw = Elf()
    struct.pack_into("<H", raw, 18, 183)

    with pytest.raises(ValueError):
        BUILD.ValidateElf(bytes(raw))


@pytest.mark.parametrize("name,kind", (("/escape", tarfile.REGTYPE),
    ("bubblewrap-0.13.0/../escape", tarfile.REGTYPE),
    ("bubblewrap-0.13.0/link", tarfile.SYMTYPE),
    ("bubblewrap-0.13.0/link", tarfile.LNKTYPE), ("other/file", tarfile.REGTYPE)))
def test_SourceArchiveRejectsEscapesAndLinks(name, kind):
    """Pinned source extraction still refuses unsafe inventory mechanics."""

    member = tarfile.TarInfo(name)
    member.type = kind

    with pytest.raises(ValueError):
        BUILD.ValidateMembers([member])


def test_TerminalCancelledExecutionIsRefusedWithoutBusyLoop():
    """The original terminal task cannot be mistaken for repeated caller cancellation."""

    if sys.platform != "linux":
        pytest.skip("Linux-specific owner import; pure closed contract tests remain portable")

    owner = Load("owner")

    async def Scenario():
        """Settle one mocked terminal cancellation without launching an executor."""

        task = asyncio.create_task(asyncio.sleep(0))
        task.cancel()

        with pytest.raises(ValueError, match="cleanup result is unknown"):
            await asyncio.wait_for(owner.Settle(task, asyncio.Event()), 0.2)

    asyncio.run(Scenario())


def test_ReceiveReadyClosesEveryReceivedDescriptorOnTruncation(monkeypatch):
    """Malformed control cannot leak its original received descriptors."""

    if sys.platform != "linux":
        pytest.skip("Linux-specific SCM_RIGHTS owner import")

    owner = Load("owner")
    closed = []
    monkeypatch.setattr(owner, "os", SimpleNamespace(close=closed.append))
    channel = SimpleNamespace(recvmsg=lambda *_: (b"bad", [(owner.socket.SOL_SOCKET,
        owner.socket.SCM_RIGHTS, struct.pack("=ii", 17, 18))], owner.socket.MSG_CTRUNC, None))

    with pytest.raises(ValueError, match="ancillary"):
        owner.ReceiveReady(channel, None)

    assert closed == [17, 18], ("Closed inert contract invariant failed")


def test_OnlyUserNamespaceDenialAdmitsConfiguredLimitEnospc():
    """Source keeps valid userns quota denial separate from other operation errors."""

    raw = (FIXTURE / "inert.c").read_text()
    assert "user_error == ENOSPC" in raw, ("Closed inert contract invariant failed")
    start, end = raw.index("static int PermissionDenied"), raw.index("static void Lockdown")
    assert "ENOSPC" not in raw[start:end] and "EINVAL" not in raw[start:end], (
        "Closed inert contract invariant failed"
    )


@pytest.mark.parametrize("case", ("valid", "unsupported", "dead", "owner", "cloexec"))
def test_DirectPeerIdentityHasNoNumericReopenFallback(monkeypatch, case):
    """Mock the exact kernel socket seam and require refusal to close every acquired FD."""

    if sys.platform != "linux":
        pytest.skip("Linux-specific direct peer pidfd contract")

    owner = Load("owner")
    envelope = CONTRACT.Envelope("normal", 32123, 32124, bytes(16), bytes(32))
    ready = CONTRACT.READY.pack(b"1337ZRD1", bytes(16), bytes(32), 7, 9, 4096, 16384, 1024)
    closed = []
    calls = []
    original_os = owner.os
    fake_os = SimpleNamespace(close=closed.append, getuid=lambda: 1001, getgid=lambda: 1001,
        fstat=lambda _: SimpleNamespace(st_mode=0o40700, st_uid=1001, st_dev=7, st_ino=9),
        O_RDONLY=original_os.O_RDONLY, O_ACCMODE=original_os.O_ACCMODE,
        O_PATH=original_os.O_PATH)
    monkeypatch.setattr(owner, "os", fake_os)

    def Flags(descriptor, operation):
        """Return only the specific expected readonly/CLOEXEC descriptor facts."""

        if operation == 3:
            return 0

        return 0 if case == "cloexec" and descriptor == 20 else 1

    monkeypatch.setattr(owner, "fcntl", SimpleNamespace(fcntl=Flags, F_GETFL=3,
        F_GETFD=1, FD_CLOEXEC=1))

    def Liveness(descriptor):
        """Observe the original returned kernel handle without a process lookup."""

        calls.append(("alive", descriptor))

        if case == "dead":
            raise ValueError("original peer exited")

    monkeypatch.setattr(owner, "Alive", Liveness)

    def SocketOption(level, option, length):
        """Supply only the original direct socket identity and credential locator."""

        calls.append((level, option, length))

        if option == 77:
            if case == "unsupported":
                raise OSError("unsupported kernel peer pidfd")

            return struct.pack("=i", 20)

        return struct.pack("=iii", 4321, 333 if case == "owner" else 1001, 1001)

    def Peek(*_):
        """Model no trailing data without touching a real socket."""

        raise BlockingIOError

    channel = SimpleNamespace(recvmsg=lambda *_: (ready, [(owner.socket.SOL_SOCKET,
        owner.socket.SCM_RIGHTS, struct.pack("=i", 17))], 0, None), recv=Peek,
        getsockopt=SocketOption, gettimeout=lambda: 1, setblocking=lambda _: None,
        settimeout=lambda _: None)

    if case == "valid":
        directory, pidfd, locator, _ = owner.ReceiveReady(channel, envelope)
        assert (directory, pidfd, locator) == (17, 20, 4321), (
            "Direct original descriptors and labelled locator changed")
        assert not closed and (owner.socket.SOL_SOCKET, 77, 4) in calls, (
            "Valid direct kernel identity must stay owned until later custody")

    else:
        with pytest.raises((ValueError, OSError)):
            owner.ReceiveReady(channel, envelope)

        assert closed == ([17] if case == "unsupported" else [17, 20]), (
            "Every original acquired descriptor must close on identity refusal")



def test_RepeatedCallerCancellationSettlesOneOriginalTask():
    """Repeated cancellation does not multiply cleanup tasks or spin on a terminal child."""

    if sys.platform != "linux":
        pytest.skip("Linux-specific owner import")

    owner = Load("owner")

    async def Scenario():
        """Use deterministic event ordering with no process, filesystem or namespace operation."""

        finish = asyncio.Event()
        cancellation = asyncio.Event()

        async def Original():
            """Return the one original result only when the deterministic owner permits it."""

            await finish.wait()

            return "actual original result"

        original = asyncio.create_task(Original())
        settlement = asyncio.create_task(owner.Settle(original, cancellation))
        await asyncio.sleep(0)
        settlement.cancel()
        await asyncio.sleep(0)
        settlement.cancel()
        await asyncio.sleep(0)
        finish.set()
        actual = await asyncio.wait_for(settlement, 0.2)
        assert actual == "actual original result" and cancellation.is_set(), (
            "Repeated caller cancellation lost or replaced the actual original result")
        assert original.done() and not original.cancelled(), (
            "The original task must settle without direct cancellation")

    asyncio.run(Scenario())


@pytest.mark.parametrize("changed", (None, "source_archive_sha256", "fixture_flags",
    "source_commit", "fixture_source_sha256", "fixture_sha256", "bwrap_sha256", "host_uid"))
def test_BuildAdmissionBindsActualPinnedSourceAndStaticMaterial(monkeypatch, changed):
    """Mock material reads while retaining the real pure ELF validator and source digest."""

    if sys.platform != "linux":
        pytest.skip("Linux-specific owner import")

    owner = Load("owner")
    provenance = {"source_archive_sha256": CONTRACT.BWRAP_SHA256,
        "source_archive_bytes": CONTRACT.BWRAP_SIZE,
        "source_commit": "719a4fd474d44b26906bcf2b1b0fb6eddd8d56d0",
        "fixture_source_sha256": owner.hashlib.sha256(
            (FIXTURE / "inert.c").read_bytes()).hexdigest(),
        "fixture_flags": ["-static", "-std=c11", "-O2", "-D_GNU_SOURCE"],
        "fixture_sha256": "fixture-original", "bwrap_sha256": "bwrap-original",
        "host_uid": owner.os.getuid()}

    if changed is not None:
        provenance[changed] = "changed"

    class MaterialRoot:
        """Provide only fixed mocked material bytes, without an executable or syscall."""

        def __truediv__(self, leaf):
            """Return a closed fake manifest or static fixture path."""

            assert leaf in {"inert", "provenance.json"}, "Unexpected material role was inspected"

            return SimpleNamespace(read_bytes=lambda: bytes(Elf()))

    monkeypatch.setattr(owner, "Material", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(owner, "BoundedRead", lambda *_: owner.Canonical(provenance))
    materials = {"fixture": {"sha256": "fixture-original"},
        "bwrap": {"sha256": "bwrap-original"}}

    if changed is None:
        assert owner.VerifyBuild(MaterialRoot(), materials) == provenance, (
            "The original pinned source and static fixture admission changed")

    else:
        with pytest.raises(ValueError, match="provenance differs"):
            owner.VerifyBuild(MaterialRoot(), materials)


def test_PartialTestPublicationPreservesAdmittedWritesWithoutRetryOrControl(monkeypatch):
    """Inject one write failure without real file operations or invented receipt success."""

    if sys.platform != "linux":
        pytest.skip("Linux-specific owner import")

    owner = Load("owner")
    writes = []
    opened = []
    closed = []

    class StagePath:
        """Name only original closed staging roles in a mocked private operation."""

        def __truediv__(self, role):
            """Return the literal role to the mocked exclusive-open seam."""

            if role == "admitted-evidence":
                return self

            return role

        def Mkdir(self, **kwargs):
            """Require a fresh private stage without touching a filesystem."""

            assert kwargs == {"mode": 0o700}, "Test staging must be private and exclusive"

        mkdir = Mkdir

    def Open(role, *_args):
        """Allocate only one mocked descriptor per original role."""

        opened.append(role)

        return len(opened)

    def Write(descriptor, raw):
        """Fail exactly once on the second original without a retry."""

        writes.append((descriptor, raw))

        if descriptor == 2:
            raise OSError("fixed injected original write failure")

        return len(raw)

    original_os = owner.os
    monkeypatch.setattr(owner, "os", SimpleNamespace(open=Open, write=Write,
        close=closed.append, fsync=lambda _: None, O_WRONLY=original_os.O_WRONLY,
        O_CREAT=original_os.O_CREAT, O_EXCL=original_os.O_EXCL,
        O_NOFOLLOW=original_os.O_NOFOLLOW, O_CLOEXEC=original_os.O_CLOEXEC))
    execution = SimpleNamespace(stdout=b"original-out", stderr=b"original-error",
        termination=SimpleNamespace(value="cancellation"), execution=SimpleNamespace(
            state=SimpleNamespace(value="cancelled"), exit_code=-15))
    outcome = owner.Outcome(execution, {}, CONTRACT.REPORT_BYTES, CONTRACT.SETUP_BYTES, True, None)

    with pytest.raises(OSError, match="fixed injected"):
        owner.SaveTestEvidence(StagePath(), outcome)

    assert opened == ["stdout.bin", "stderr.bin"] and closed == [1, 2], (
        "Partial publication must preserve the first original and close every active write FD")
    assert len(writes) == 2 and "actual.json" not in opened, (
        "Uncertain publication cannot retry originals or publish a synthetic terminal control")


@pytest.mark.parametrize("changed", (None, "capability", "namespace", "quota", "root",
    "material", "alias", "late", "absolute-alias", "consumed-fd3", "target-symlink",
    "target-foreign", "missing-control"))
def test_KnownPeerInspectionUsesOriginalFdAndRejectsChangedFacts(monkeypatch, changed):
    """Exercise allowed and refused kernel observations entirely through fixed syscall doubles."""

    if sys.platform != "linux":
        pytest.skip("Linux-specific known-peer kernel observation contract")

    owner = Load("owner")
    original_os = owner.os
    closed = []
    liveness = []
    info = SimpleNamespace(st_dev=7, st_ino=9, st_mode=0o40700, st_uid=1001,
        st_nlink=2, st_size=0, st_mtime_ns=10, st_ctime_ns=11)
    identity = owner.Identity(info)
    materials = {role: {"identity": identity} for role in ("fixture", "request")}

    class KernelPath:
        """Represent only a fixed known peer locator without accessing procfs."""

        def __init__(self, value):
            """Store a deterministic literal path for mocked observation dispatch."""

            self.value = value

        def __truediv__(self, leaf):
            """Join only source-selected known-peer observation names."""

            return KernelPath(self.value + "/" + str(leaf))

        def __str__(self):
            """Expose a deterministic fake path spelling to the syscall doubles."""

            return self.value

    def Read(path, _maximum):
        """Supply bounded original kernel status, mappings, mounts and request bytes."""

        name = str(path)

        if name.endswith("/status"):
            fields = {key: "0" for key in owner.PEER_CAP_FIELDS}
            fields.update(NoNewPrivs="1", Threads="1")

            if changed == "capability":
                fields["CapEff"] = "1"

            return "\n".join(key + ": " + value for key, value in fields.items()).encode()

        if name.endswith(("/uid_map", "/gid_map")):
            return b"0 1001 1\n"

        if name.endswith("/mountinfo"):
            rows = []

            for leaf in ("/", "/work", "/inert", "/request.bin", "/control.sock"):
                flags = "rw,nodev,nosuid,noexec" if leaf == "/work" else "ro"

                if changed == "root" and leaf == "/":
                    flags = "rw"

                rows.append(f"1 0 0:7 / {leaf} {flags} - tmpfs tmpfs rw")

            return "\n".join(rows).encode()

        assert name.endswith("/request.bin"), "Inspection used an unexpected kernel path"

        return b"original fixed request"

    def Readlink(path):
        """Return only distinct namespace identities, fixed aliases and the control socket."""

        name = str(path)

        if "/ns/" in name:
            prefix = "host" if name.startswith("/proc/self") or changed == "namespace" else "peer"

            return prefix + ":[1]"

        if name.endswith("/fd/4"):
            if changed == "missing-control":
                raise FileNotFoundError(2, "private diagnostic message", "/private/PID/control")

            return "socket:[99]"

        alias = name.split("/root/", 1)[1]

        return "/wrong" if changed == "alias" else owner.ALIASES[alias]

    def Stat(path, **kwargs):
        """Keep report absence separate from ordinary known mounted identities."""

        if kwargs and path in {"home", "tmp", "session", "report", "shm"}:
            assert kwargs == {"dir_fd": 17, "follow_symlinks": False}, (
                "Alias target must stay anchored to the original quota without following links")

            if changed == "target-symlink":
                return SimpleNamespace(**{**vars(info), "st_mode": 0o120777})

            if changed == "target-foreign":
                return SimpleNamespace(**{**vars(info), "st_dev": 99})

            return info

        if kwargs:
            if changed == "late":
                return info

            raise FileNotFoundError

        if str(path).endswith("/fd/3"):
            raise FileNotFoundError(2, "consumed descriptor is already absent")

        if changed == "absolute-alias" and str(path).startswith("/proc/4321/root/") and (
            str(path).split("/root/", 1)[1] in owner.ALIASES
        ):
            raise FileNotFoundError(2, "absolute alias looked up in inspector root", "/work/home")

        if changed == "material" and str(path).endswith("/inert"):
            return SimpleNamespace(**{**vars(info), "st_ino": 77})

        return info

    def Open(path, flags, **kwargs):
        """Require the actual report-absence check to use original-dir nofollow openat."""

        assert path == "report" and kwargs == {"dir_fd": 17}, (
            "Late absence inspection must stay relative to the original quota descriptor")
        assert flags & original_os.O_NOFOLLOW and flags & original_os.O_DIRECTORY, (
            "Late absence inspection must refuse directory symlinks")

        return 30

    class Entries:
        """Expose only the closed final-stage inherited descriptor inventory."""

        def __enter__(self):
            """Return fixed entries without scanning a real process."""

            names = ("0", "1", "2", "3", "4") if changed == "consumed-fd3" else (
                "0", "1", "2", "4")

            return iter(SimpleNamespace(name=name) for name in names)

        def __exit__(self, *_):
            """Finish the mocked fixed descriptor inventory."""

            return False

    monkeypatch.setattr(owner, "Path", KernelPath)
    monkeypatch.setattr(owner, "Alive", liveness.append)
    monkeypatch.setattr(owner, "BoundedRead", Read)
    monkeypatch.setattr(owner, "os", SimpleNamespace(getuid=lambda: 1001,
        getgid=lambda: 1001, readlink=Readlink, stat=Stat, lstat=Stat, fstat=lambda _: info,
        fstatvfs=lambda _: SimpleNamespace(f_frsize=4096, f_blocks=16384,
            f_files=1000 if changed == "quota" else 1024), scandir=lambda _: Entries(),
        open=Open, close=closed.append, O_RDONLY=original_os.O_RDONLY,
        O_DIRECTORY=original_os.O_DIRECTORY, O_NOFOLLOW=original_os.O_NOFOLLOW,
        O_CLOEXEC=original_os.O_CLOEXEC))
    arguments = (4321, 20, 17, (7, 9, 4096, 16384, 1024), b"original fixed request", materials)

    if changed in {None, "absolute-alias", "consumed-fd3"}:
        actual = owner.VerifyPeer(*arguments)
        assert actual["mount_count"] == 5 and liveness == [20, 20] and closed == [30], (
            "Accepted peer facts need both original pidfd guards and closed nofollow inspection")

    else:
        with pytest.raises((ValueError, FileNotFoundError)) as caught:
            owner.VerifyPeer(*arguments)

        if changed == "missing-control":
            observed = {}
            owner.RecordFirstFailure(observed, "peer-verify", caught.value)
            first = observed["first_failure"]
            assert first["phase"] == "peer-verify" and first["errno"] == 2 and any(
                item["function"] == "VerifyPeer" for item in first["locations"]
            ), "Original missing control must retain a bounded real source location and errno"

        assert liveness[0] == 20 and closed == ([30] if changed == "late" else []), (
            "Refused observations must not leak a short-lived custody descriptor")


def test_FinalReadyDeadlineIncludesReceiveInspectionAndFreshAuthority(monkeypatch):
    """Accept at4.8s then inspect through5.3s must refuse ACK despite spare outer budget."""

    if sys.platform != "linux":
        pytest.skip("Linux-specific closed owner import")

    owner = Load("owner")
    sent = []
    checks = []
    envelope = CONTRACT.Envelope("normal", 32123, 32124, bytes(16), bytes(32))
    monkeypatch.setattr(owner, "time", SimpleNamespace(monotonic=lambda: 5.3))
    monkeypatch.setattr(owner, "Alive", checks.append)
    channel = SimpleNamespace(sendall=sent.append)

    with pytest.raises(ValueError, match="deadline"):
        owner.Acknowledge(channel, envelope, 20, asyncio.Event(), lambda: None, 0.0, 5.0)

    assert sent == [], "An expired original final READY window must never send ACK"


def Oracle():
    """Import only genuine assertion predicates, without entering any runtime owner."""

    path = ROOT / "tests/integration/test_zap_inert_isolation.py"
    spec = importlib.util.spec_from_file_location("unit_inert_assertions", path)
    assert spec is not None and spec.loader is not None, "Fixed assertion module is unavailable"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def OracleOutcome(case):
    """Construct one fixed predicate input; these mocked facts are never genuine evidence."""

    observed = {"host_sink_contacts": 0, "final_ready_verified": True,
        "original_peer_exited_after_cleanup": True, "ack_sent": case != "deny",
        "intentional_authority_revocation": case == "deny",
        "current_authority_refused": case == "deny",
        "cooperative_cancel_requested": case in {"cancel", "deny", "missing"},
        "direct_peer_sigkill_requested": case == "kill",
        "direct_peer_exit_observed": case == "kill",
        "live_private_listener_host_refused": True,
        "work_complete_observed": case in {"normal", "bytes", "inodes"},
        "normal_release_requested": case in {"normal", "bytes", "inodes"}}
    denials = b"".join(b"DENIED " + name + b" 1\n" for name in (b"quota-remount",
        b"new-tmpfs", b"new-userns", b"new-mountns", b"new-netns", b"root-write", b"input-write"))
    stdout = denials + b"NETWORK host-refused private-connected\nLATE original-identity\n"
    termination, state, exit_code = "process_exit", "succeeded", 0
    complete, report, failure = True, CONTRACT.REPORT_BYTES, None

    if case in {"timeout", "cancel", "kill"}:
        stdout += b"OWNED_CHILD 2\n"
        termination, state, exit_code = {"timeout": ("timeout", "timed_out", -15),
            "cancel": ("cancellation", "cancelled", -15), "kill": ("process_exit", "failed", 137)
        }[case]

    if case in {"deny", "missing"}:
        termination, state, exit_code = "cancellation", "cancelled", -15
        complete, report = False, None
        failure = "ValueError" if case == "deny" else "missing-late-report"
        stdout = b"" if case == "deny" else b"ACK_WITHOUT_REPORT\n"

    if case in {"normal", "bytes", "inodes"}:
        stdout += b"WORK_COMPLETE\n"

    if case == "bytes":
        stdout += b"QUOTA bytes 65536 ENOSPC\n"

    if case == "inodes":
        stdout += b"QUOTA inodes 1000 ENOSPC\n"

    execution = SimpleNamespace(termination=SimpleNamespace(value=termination), stdout=stdout,
        execution=SimpleNamespace(state=SimpleNamespace(value=state), exit_code=exit_code))

    return SimpleNamespace(execution=execution, observations=observed, report=report,
        setup=CONTRACT.SETUP_BYTES, complete=complete, failure=failure, cleanup_confirmed=True)


@pytest.mark.parametrize("case", ("normal", "bytes", "inodes", "timeout", "cancel", "kill",
    "deny", "missing"))
def test_AssertionPredicatesAcceptOnlyCompleteFixedMockFacts(case):
    """Check deterministic assertion plumbing; this is not successful runtime acceptance."""

    Oracle().AssertOutcome(case, SimpleNamespace(CONTRACT=CONTRACT), OracleOutcome(case))


@pytest.mark.parametrize("case", ("cancel", "kill", "missing", "deny", "wrong-quota",
    "wrong-kill-exit"))
def test_AssertionPredicatesRejectIndependentCounterexamples(case):
    """Reject timeout-for-cancel, unrelated denial and missing-marker oracle substitutions."""

    selected = "bytes" if case == "wrong-quota" else "kill" if case == "wrong-kill-exit" else case
    outcome = OracleOutcome(selected)

    if case in {"cancel", "kill"}:
        outcome.execution.termination.value = "timeout"
        outcome.execution.execution.state.value = "timed_out"

    if case == "missing":
        outcome.execution.stdout = b""

    if case == "deny":
        outcome.observations["final_ready_verified"] = False
        outcome.observations["current_authority_refused"] = False

    if case == "wrong-quota":
        outcome.execution.stdout = outcome.execution.stdout.replace(b"QUOTA bytes", b"QUOTA inodes")

    if case == "wrong-kill-exit":
        outcome.execution.execution.exit_code = 1

    with pytest.raises(AssertionError):
        Oracle().AssertOutcome(selected, SimpleNamespace(CONTRACT=CONTRACT), outcome)


def ActualCancelledResult():
    """Build one genuine result type for mocked task plumbing without executing a process."""

    from fuzzy1337.adapters import AdapterExecution, ExecutionState
    from fuzzy1337.executors.contracts import (
        ExecutionEvent,
        ExecutionEventKind,
        ExecutionTermination,
        LocalExecutionResult,
    )

    identity = (7, 9, 0o100600, 0, 1, len(CONTRACT.REPORT_BYTES), 10, 11)
    stdout = b"LATE " + b" ".join(str(value).encode() for value in identity) + b"\n"

    return LocalExecutionResult(AdapterExecution(ExecutionState.CANCELLED, -15, 1),
        ExecutionTermination.CANCELLATION, stdout, b"", (
            ExecutionEvent(0, ExecutionEventKind.COMPLETED,
                termination=ExecutionTermination.CANCELLATION),))


def CustodyDoubles(monkeypatch, owner, cleaned, clock):
    """Replace every custody/syscall seam with fixed original-object observations."""

    reads, saves, closed = [], [], []

    def Read(directory, role, expected):
        """Forbid first read before the actual original task confirms cleanup."""

        assert cleaned.is_set() and directory == 17, (
            "Original report was read before confirmed owned cleanup or through another FD")
        reads.append((role, expected))

        return CONTRACT.SETUP_BYTES if role == "setup" else CONTRACT.REPORT_BYTES

    def Save(operation, outcome):
        """Record one original admitted publication after confirmed cleanup or unknown control."""

        assert outcome.execution is None or cleaned.is_set(), (
            "A fake terminal result was published before original cleanup")
        saves.append((operation, outcome.execution, outcome.report))

    class Poll:
        """Expose only the direct original pidfd's mocked terminal readiness."""

        def Register(self, descriptor, _flags):
            """Require the retained original direct peer identity."""

            assert descriptor == 20, "A numeric or replacement peer identity was used"

        register = Register

        def Poll(self, timeout):
            """Return known original exit only after the owned cleanup event."""

            assert timeout == 0, "Custody inspection must not renew the cleanup deadline"

            return [(20, 1)] if cleaned.is_set() else []

        poll = Poll

    class Sink:
        """Provide a fixed empty owned sink without touching a real socket."""

        def Accept(self):
            """Return no accepted contact at the current final observation."""

            raise BlockingIOError

        accept = Accept

    monkeypatch.setattr(owner, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(owner, "select", SimpleNamespace(poll=Poll, POLLIN=1,
        POLLHUP=16, POLLERR=8, POLLNVAL=32))
    monkeypatch.setattr(owner, "os", SimpleNamespace(close=closed.append, getuid=lambda: 1001))
    monkeypatch.setattr(owner, "ReadOriginal", Read)
    monkeypatch.setattr(owner, "SaveTestEvidence", Save)

    return reads, saves, closed, Sink()


def test_AfterAckCallerCancellationWaitsOriginalCleanupBeforeFirstLateRead(monkeypatch):
    """Cancel an actual awaited custody coroutine twice while the one original task is held."""

    if sys.platform != "linux":
        pytest.skip("Linux-specific custody owner import")

    owner = Load("owner")

    async def Scenario():
        """Hold owned cleanup after ACK, then permit the actual original result and first read."""

        cleaned = asyncio.Event()
        cancellation = asyncio.Event()
        reads, saves, closed, sink = CustodyDoubles(monkeypatch, owner, cleaned, [0.0])
        result = ActualCancelledResult()

        async def Original():
            """Represent the same original Execute task with already-written late output."""

            await cleaned.wait()

            return result

        original = asyncio.create_task(Original())
        finishing = asyncio.create_task(owner.FinishOwned(original, cancellation,
            "original-operation", 17, 20, {"ack_sent": True}, None, 0.0, bytearray(), sink))
        await asyncio.sleep(0)
        finishing.cancel()
        await asyncio.sleep(0)
        finishing.cancel()
        await asyncio.sleep(0)
        assert cancellation.is_set() and reads == [] and not original.cancelled(), (
            "Caller cancellation must request original cleanup without an early read or new task")
        cleaned.set()
        outcome = await asyncio.wait_for(finishing, 0.5)
        assert outcome.execution is result and outcome.failure == "caller-cancelled", (
            "First caller cancellation and the actual original result must both survive")
        assert outcome.cleanup_confirmed and outcome.report == CONTRACT.REPORT_BYTES, (
            "Already-written original late output was lost after actual cleanup")
        assert [role for role, _ in reads] == ["setup", "report"] and len(saves) == 1, (
            "Original custody must happen once and only after cleanup")
        assert closed == [17, 20], "Verified custody must close both original retained handles"

    asyncio.run(Scenario())


@pytest.mark.parametrize("case", ("late-budget", "pending", "terminal-cancelled", "late-publish"))
def test_CustodyBudgetOrUnknownCleanupRetainsExactOriginalRecovery(monkeypatch, case):
    """Late or unknown results cannot close originals or synthesize successful custody."""

    if sys.platform != "linux":
        pytest.skip("Linux-specific custody owner import")

    owner = Load("owner")

    async def Scenario():
        """Exercise original task/FD handoff with deterministic events and fixed clocks."""

        cleaned = asyncio.Event()
        cancellation = asyncio.Event()
        initial = 29.0 if case == "late-budget" else 21.0 if case == "pending" else 0.0
        clock = [initial]
        reads, saves, closed, sink = CustodyDoubles(monkeypatch, owner, cleaned, clock)
        result = ActualCancelledResult()

        async def Original():
            """Return the only original actual result after its cleanup is permitted."""

            await cleaned.wait()

            return result

        original = asyncio.create_task(Original())

        if case in {"late-budget", "late-publish"}:
            cleaned.set()
            await original

        if case == "terminal-cancelled":
            original.cancel()

            try:
                await original

            except asyncio.CancelledError:
                pass

        if case == "late-publish":
            save = owner.SaveTestEvidence

            def LateSave(operation, outcome):
                """Simulate measured-late fsync without a retry or another read."""

                save(operation, outcome)
                clock[0] = 29.0

            monkeypatch.setattr(owner, "SaveTestEvidence", LateSave)

        outcome = await owner.FinishOwned(original, cancellation, "original-operation",
            17, 20, {"ack_sent": True}, "first-stop", 0.0, bytearray(b"observed prefix"), sink)
        assert outcome.failure == "first-stop" and not outcome.complete, (
            "Later custody failure must preserve the first failure and cannot claim success")
        assert (outcome._retained_directory, outcome._retained_pidfd) == (17, 20) and (
            outcome._retained_task is original and closed == []
        ), "Unknown or late custody must retain exact original handles and task"

        if case in {"pending", "terminal-cancelled"}:
            assert outcome.execution is None and not outcome.cleanup_confirmed and reads == [], (
                "Unconfirmed cleanup cannot invent a terminal result or first-read original output")

            with pytest.raises(ValueError, match="cannot be silently dropped"):
                outcome.CloseRecovery()

            assert closed == [], "Unknown original ownership was silently closed"

        if case == "pending":
            cleaned.set()
            await original
            outcome.ConfirmSettledRecovery()
            outcome.CloseRecovery()
            assert outcome.execution is result and closed == [17, 20] and not outcome.complete, (
                "Confirmed settlement may dispose originals without inventing expired custody")

        if case in {"late-budget", "late-publish"}:
            assert reads == ([] if case == "late-budget" else [
                ("setup", None), ("report", (7, 9, 0o100600, 1001, 1,
                    len(CONTRACT.REPORT_BYTES), 10, 11))
            ]), "Expired custody must not first-read or replace the original report"
            assert len(saves) == (0 if case == "late-budget" else 1), (
                "Original absolute publication budget must not be renewed or retried")
            outcome.CloseRecovery()

    asyncio.run(Scenario())


@pytest.mark.parametrize("case", ("normal", "bytes", "inodes", "timeout", "cancel", "kill",
    "deny", "missing"))
def test_UnknownExecutionNeverSatisfiesAnyGenuinePredicate(case):
    """Explicit unknown cleanup must fail before any terminal-result dereference."""

    outcome = OracleOutcome(case)
    outcome.execution = None
    outcome.cleanup_confirmed = False

    with pytest.raises(AssertionError, match="explicitly unknown"):
        Oracle().AssertOutcome(case, SimpleNamespace(CONTRACT=CONTRACT), outcome)


def test_ReceiveAckRejectsKernelErrorBeforeAnyAncillaryWalk():
    """Static C contract checks are inspection only; they do not execute the fixture."""

    raw = (FIXTURE / "inert.c").read_text()
    section = raw[raw.index("static ssize_t ReceiveAckPart"):raw.index("static void Ready")]
    assert section.index("Require(length >= 0)") < section.index("CMSG_FIRSTHDR"), (
        "A failed recvmsg must never expose uninitialized ancillary metadata to parsing")
    assert "ReceiveAckPart(channel, ack, sizeof(ack)) == 56" in raw and (
        "ReceiveAckPart(channel, &eof, 1) == 0" in raw
    ), "Closed ACK requires exact bytes and EOF through the same ancillary-rejecting parser"


def test_UnknownCleanupPublicationHasNoInventedTerminalOrCompleteStreams(monkeypatch):
    """Inspect actual unknown-control serialization through mocked exclusive file writes."""

    if sys.platform != "linux":
        pytest.skip("Linux-specific owner import")

    owner = Load("owner")
    opened, written, closed = [], {}, []

    class Stage:
        """Name only the fixed admitted test stage and literal record roles."""

        def __truediv__(self, role):
            """Return this stage or one literal original-record name."""

            return self if role == "admitted-evidence" else role

        def Mkdir(self, **kwargs):
            """Require the same private original stage without creating a real directory."""

            assert kwargs == {"mode": 0o700}, "Unknown-control staging must remain private"

        mkdir = Mkdir

    def Open(role, *_):
        """Record one exclusive descriptor per selected original/control role."""

        opened.append(role if isinstance(role, str) else "stage")

        return len(opened)

    def Write(descriptor, raw):
        """Retain exactly the bytes passed to each original mocked write."""

        written[opened[descriptor - 1]] = raw

        return len(raw)

    original_os = owner.os
    flags = {name: getattr(original_os, name) for name in (
        "O_WRONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_CLOEXEC", "O_RDONLY", "O_DIRECTORY")}
    monkeypatch.setattr(owner, "os", SimpleNamespace(**flags, open=Open, write=Write,
        close=closed.append, fsync=lambda _: None))
    outcome = owner.Outcome(None, {"ack_sent": True}, None, None, False, "owned-cleanup-unknown")
    outcome.observed_stdout_prefix = b"actual observed prefix"
    owner.SaveTestEvidence(Stage(), outcome)
    control = owner.json.loads(written["actual.json"])
    assert control["state"] == "unknown" and control["termination"] is None and (
        control["exit_code"] is None and not control["cleanup_confirmed"]
        and not control["custody_complete"]
    ), "Unknown cleanup cannot invent an actual terminal or successful custody"
    assert set(written) == {"observed-stdout-prefix.bin", "actual.json"} and (
        written["observed-stdout-prefix.bin"] == b"actual observed prefix" and closed == [1, 2, 3]
    ), "A partial observed prefix cannot be labelled a complete original terminal stream"


@pytest.mark.parametrize("events,valid", (([(20, 1)], True), ([(20, 17)], True),
    ([(20, 8)], False), ([(20, 32)], False), ([(99, 1)], False), ([(20, 16)], False),
    ([(20, 9)], False), ([(20, 33)], False), ([(20, 5)], False), ([], False),
    ([(20, 1), (20, 1)], False), ([(20, True)], False)))
@pytest.mark.parametrize("path", ("finish", "recovery"))
def test_OriginalPeerExitRequiresReadableIdentityWithoutErrorFlags(
    monkeypatch, events, valid, path,
):
    """Invalid readiness cannot confirm cleanup or allow either original-read/disposal path."""

    if sys.platform != "linux":
        pytest.skip("Linux-specific direct peer readiness semantics")

    owner = Load("owner")

    async def Scenario():
        """Provide only mocked original poll facts around one actually settled fake task."""

        cleaned = asyncio.Event()
        cleaned.set()
        reads, _saves, closed, sink = CustodyDoubles(monkeypatch, owner, cleaned, [0.0])

        class Readiness:
            """Return one fixed kernel-ready result without touching an OS descriptor."""

            def Register(self, descriptor, flags):
                """Accept source-selected exit observation flags for the original descriptor."""

                assert descriptor == 20 and flags in (1, 57), (
                    "A foreign descriptor or unrelated readiness mask was registered")

            register = Register

            def Poll(self, timeout):
                """Return the selected original or refused fixed readiness observation."""

                assert timeout == 0, "Peer exit observation must not renew an expired budget"

                return events

            poll = Poll

        monkeypatch.setattr(owner, "select", SimpleNamespace(poll=Readiness,
            POLLIN=1, POLLHUP=16, POLLERR=8, POLLNVAL=32))
        result = ActualCancelledResult()
        original = asyncio.create_task(asyncio.sleep(0, result=result))
        await original

        if path == "finish":
            outcome = await owner.FinishOwned(original, asyncio.Event(), "original-operation",
                17, 20, {"ack_sent": True}, None, 0.0, bytearray(), sink)

            if valid:
                assert outcome.cleanup_confirmed and outcome.complete and len(reads) == 2, (
                    "Original readable exit must preserve normal post-cleanup custody")
                assert closed == [17, 20], "Verified original handles were not closed after custody"

            else:
                assert not outcome.cleanup_confirmed and not outcome.complete and reads == [], (
                    "Error, stale or foreign readiness allowed first original report reads")
                assert (outcome._retained_directory, outcome._retained_pidfd) == (17, 20), (
                    "Unconfirmed original exit must preserve both recovery descriptors")

                with pytest.raises(ValueError, match="cannot be silently dropped"):
                    outcome.CloseRecovery()

                assert closed == [], "Unconfirmed recovery ownership was silently discarded"

        else:
            outcome = owner.Outcome(None, {"ack_sent": True}, None, None, False, "unknown")
            outcome._retained_directory = 17
            outcome._retained_pidfd = 20
            outcome._retained_task = original

            if valid:
                outcome.ConfirmSettledRecovery()
                assert outcome.cleanup_confirmed and outcome.execution is result, (
                    "Original readable exit must permit confirmation of the same settled task")
                outcome.CloseRecovery()
                assert closed == [17, 20] and reads == [], (
                    "Recovery disposal cannot invent a late first read or lose original handles")

            else:
                with pytest.raises(ValueError):
                    outcome.ConfirmSettledRecovery()

                assert not outcome.cleanup_confirmed and outcome.execution is None, (
                    "Invalid original readiness manufactured confirmed recovery")

                with pytest.raises(ValueError, match="cannot be silently dropped"):
                    outcome.CloseRecovery()

                assert reads == [] and closed == [], (
                    "Invalid readiness must retain original ownership without late report access")

    asyncio.run(Scenario())


def test_WorkflowRunnerContextStaysInGenuineStepEnvironment():
    """Prevent unsupported runner expressions in job env while binding both genuine test steps."""

    workflow = yaml.safe_load((ROOT / ".github/workflows/zap-inert-acceptance.yml").read_text())
    context_reference = re.compile(r"\brunner\s*(?:\.|\[)")
    test_steps = []

    for job in workflow["jobs"].values():
        assert all(context_reference.search(str(value)) is None
            for value in job.get("env", {}).values()), (
            "GitHub runner context is unavailable in jobs.<job>.env")

        for step in job.get("steps", []):
            if "tests/integration/test_zap_inert_isolation.py" in step.get("run", ""):
                test_steps.append(step)

    assert len(test_steps) == 2, "Both serial and parallel genuine proof steps require material"

    for step in test_steps:
        assert step.get("env", {}).get("FUZZY1337_ZAP_INERT_MATERIAL") == (
            "${{ runner.temp }}/zap-inert-build/runtime"
        ), "Genuine test material must use runner context only in the supported step env"


def LicenseMembers():
    """Return a synthetic ordinary COPYING plus the only two allowed relative license links."""

    root = tarfile.TarInfo("bubblewrap-0.13.0")
    root.type = tarfile.DIRTYPE
    copying = tarfile.TarInfo("bubblewrap-0.13.0/COPYING")
    copying.size = len(b"synthetic upstream license notice\n")
    members = [root, copying]

    for name in ("COPYING.LIB", "LICENSE"):
        link = tarfile.TarInfo("bubblewrap-0.13.0/" + name)
        link.type = tarfile.SYMTYPE
        link.linkname = "COPYING"
        members.append(link)

    return members


def test_PinnedLicenseSymlinksKeepOrdinaryTargetAndOriginalNoticeBytes():
    """Admit exact synthetic metadata and resolve its unchanged notice in memory only."""

    members = LicenseMembers()
    BUILD.ValidateMembers(members)
    storage = io.BytesIO()
    notice = b"synthetic upstream license notice\n"

    with tarfile.open(fileobj=storage, mode="w") as archive:
        for member in members:
            archive.addfile(member, io.BytesIO(notice) if member.isfile() else None)

    storage.seek(0)

    with tarfile.open(fileobj=storage, mode="r:") as archive:
        BUILD.ValidateMembers(archive.getmembers())

        for name in ("COPYING", "COPYING.LIB", "LICENSE"):
            stream = archive.extractfile("bubblewrap-0.13.0/" + name)
            assert stream is not None and stream.read() == notice, (
                "Admitted license aliases must preserve the exact ordinary synthetic notice")


@pytest.mark.parametrize("case", ("escape", "absolute", "dot-target", "transitive", "self",
    "foreign", "hardlink", "nonzero-link", "missing-target", "directory-target", "linked-target",
    "duplicate", "duplicate-root", "dot-alias", "slash-alias", "backslash-alias", "parent-alias",
    "negative-size", "byte-cap", "count-cap", "sparse-target"))
def test_ClosedLicenseAdmissionRejectsForeignOrAliasedMetadata(case):
    """Keep the two license exceptions closed against links, chains, aliases and size bypasses."""

    members = LicenseMembers()
    link = members[-1]
    targets = {"escape": "../COPYING", "absolute": "/COPYING", "dot-target": "./COPYING",
        "transitive": "COPYING.LIB", "self": "LICENSE"}

    if case in targets:
        link.linkname = targets[case]

    elif case == "foreign":
        link.name = "bubblewrap-0.13.0/other"

    elif case == "hardlink":
        link.type = tarfile.LNKTYPE

    elif case == "nonzero-link":
        link.size = 1

    elif case == "missing-target":
        del members[1]

    elif case == "directory-target":
        members[1].type = tarfile.DIRTYPE
        members[1].size = 0

    elif case == "linked-target":
        members[1].type = tarfile.SYMTYPE
        members[1].size = 0
        members[1].linkname = "LICENSE"

    elif case == "duplicate":
        members.append(link)

    elif case == "duplicate-root":
        duplicate = tarfile.TarInfo("bubblewrap-0.13.0/")
        duplicate.type = tarfile.DIRTYPE
        members.append(duplicate)

    elif case == "dot-alias":
        link.name = "bubblewrap-0.13.0/./LICENSE"

    elif case == "slash-alias":
        link.name = "bubblewrap-0.13.0//LICENSE"

    elif case == "backslash-alias":
        link.name = "bubblewrap-0.13.0/dir\\LICENSE"

    elif case == "parent-alias":
        members.append(tarfile.TarInfo("bubblewrap-0.13.0/LICENSE/child"))

    elif case == "negative-size":
        members[1].size = -1

    elif case == "byte-cap":
        members[1].size = 8 * 1024 * 1024 + 1

    elif case == "count-cap":
        members.extend(tarfile.TarInfo(f"bubblewrap-0.13.0/file-{index}") for index in range(253))

    elif case == "sparse-target":
        members[1].sparse = []

    with pytest.raises(ValueError):
        BUILD.ValidateMembers(members)


@pytest.mark.parametrize("case", ("valid", "bad-target", "count-cap", "bounded-preview"))
def test_ArchiveDiagnosticPrecedesAdmissionAndPreservesFirstRefusal(monkeypatch, case):
    """Retain bounded metadata in memory before an actual pure admission decision."""

    members = LicenseMembers()

    if case == "bad-target":
        members[-1].linkname = "../COPYING"

    elif case == "count-cap":
        members.extend(tarfile.TarInfo(f"bubblewrap-0.13.0/file-{index}") for index in range(253))

    elif case == "bounded-preview":
        members = [tarfile.TarInfo("bubblewrap-0.13.0/" + "\x01" * 1024) for _ in range(256)]

    writes = []
    original = BUILD.ValidateMembers

    class ProvisioningReport:
        """Capture only diagnostic JSON without creating a file or running a helper."""

        def WriteBytes(self, raw):
            """Retain one bounded standards-compliant metadata checkpoint."""

            assert len(raw) <= 512 * 1024, "Provisioning diagnostics exceeded their fixed bound"
            writes.append(BUILD.json.loads(raw))

            return len(raw)

        write_bytes = WriteBytes

    def Validate(original_members):
        """Require the original inventory checkpoint before the pure validator may decide."""

        assert len(writes) == 1 and writes[0]["admission"] == "pending", (
            "Archive admission started before original inventory was retained")
        assert writes[0]["member_count"] == len(original_members), (
            "The diagnostic inventory must describe the original selected archive metadata")
        original(original_members)

    monkeypatch.setattr(BUILD, "ValidateMembers", Validate)

    if case == "valid":
        BUILD.AdmitMembers(members, ProvisioningReport())
        assert writes[-1]["admission"] == "admitted" and writes[-1]["first_rejection"] is None, (
            "An admitted synthetic inventory acquired an invented rejection")

    else:
        with pytest.raises(ValueError):
            BUILD.AdmitMembers(members, ProvisioningReport())

        assert writes[-1]["admission"] == "refused" and writes[-1]["first_rejection"], (
            "A refused inventory lost its first explicit admission reason")

    assert len(writes) == 2 and len(writes[-1]["members"]) <= 256, (
        "Only one pre-admission and one final bounded diagnostic may be written")
    assert writes[-1]["inventory_truncated"] == (case == "count-cap"), (
        "Inventory truncation must remain explicit rather than hiding excluded metadata")


def test_ProvisioningInventoryUploadKeepsExplicitPublicMetadataAllowlist():
    """Upload the bounded admission JSON without exposing the dependency tree or control sockets."""

    workflow = yaml.safe_load((ROOT / ".github/workflows/zap-inert-acceptance.yml").read_text())
    steps = workflow["jobs"]["closed-inert"]["steps"]
    upload = next(step for step in steps
        if step.get("uses", "").startswith("actions/upload-artifact@"))
    selected = {line.strip() for line in upload["with"]["path"].splitlines()
        if "/zap-inert-build/" in line}
    prefix = "${{ runner.temp }}/zap-inert-build/"
    assert selected == {prefix + "runtime/provenance.json", prefix + BUILD.INVENTORY_REPORT_NAME}, (
        "Dependency diagnostics must select only the explicit public metadata files")


def test_FirstReadyFailureMetadataPreservesOriginalLocationWithoutSensitiveData(monkeypatch):
    """Retain original control-only exception facts without inspecting paths or new files."""

    if sys.platform != "linux":
        pytest.skip("Linux-specific owner import")

    owner = Load("owner")
    observed = {}
    sensitive = ("/private/customer/PID77777", "sha256:" + "a" * 64, "source-bytes-secret")

    def Fail(*_):
        """Raise the fixed original failure through a real whitelisted source frame."""

        raise FileNotFoundError(2, sensitive[2], sensitive[0] + sensitive[1])

    def NoNewPath(*_):
        """Reject diagnostic attempts to perform another path lookup."""

        raise AssertionError("Failure diagnostics must not read or resolve a path")

    monkeypatch.setattr(owner, "os", SimpleNamespace())
    monkeypatch.setattr(owner, "Path", NoNewPath)

    try:
        owner.BoundedRead(SimpleNamespace(open=Fail), 64)

    except FileNotFoundError as error:
        owner.RecordFirstFailure(observed, "peer-verify", error)

    first = observed["first_failure"]
    encoded = owner.json.dumps(first)
    assert first["phase"] == "peer-verify" and first["error_type"] == "FileNotFoundError" and (
        first["errno"] == 2 and 1 <= len(first["locations"]) <= 4
    ), "The original bounded error phase, class and errno must survive unchanged"
    assert all(item["function"] == "BoundedRead" and 0 < item["line"] <= 1000000
        for item in first["locations"]), "Only whitelisted original source frames may be retained"
    assert len(encoded) <= 1024 and not any(value in encoded for value in sensitive), (
        "Diagnostics must exclude original messages, paths, PIDs, bytes and hashes")
    owner.RecordFirstFailure(observed, "ready-receive", PermissionError(13, "later private error"))
    assert observed["first_failure"] is first, "Later failure overwrote original metadata"


def test_FirstReadyFailureMetadataRefusesUnknownLabelsAndErrno():
    """Unknown classes, phases and errno values cannot become arbitrary diagnostic strings."""

    if sys.platform != "linux":
        pytest.skip("Linux-specific owner import")

    owner = Load("owner")

    class PrivateError(OSError):
        """Represent an unapproved exception type without exposing its custom name."""

    observed = {}
    owner.RecordFirstFailure(observed, "/private/PID111/hash-secret", PrivateError(
        123456, "private message bytes", "/private/customer/path"))
    first = observed["first_failure"]
    assert first == {"phase": "other", "error_type": "other", "errno": None,
        "locations": [], "frames_limited": False}, (
        "Unapproved metadata must reduce to fixed neutral labels without sensitive values")
