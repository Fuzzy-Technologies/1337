# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure exact-native argument and adapter contracts; no tool, process or target is invoked."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.executors import InvocationDigest
from fuzzy1337.raw_cli import RawNmapAdapter, RawNmapSelection, SelectRawNmap

TCP = ("--unprivileged", "-n", "-Pn", "-sT", "-p", "443,80", "--host-timeout", "15s",
       "-oX", "-", "127.0.0.1")


def ForbiddenRead(reference):
    """Prove pure selection and preparation never read evidence or contact an external owner."""

    raise AssertionError("Pure native selection unexpectedly read original evidence")


@pytest.mark.parametrize("service, ipv6", [
    (False, False), (True, False), (False, True), (True, True)])
def test_NativeProfilesRetainExactTokensAndExistingCapabilities(tmp_path, service, ipv6):
    """Both reviewed profiles retain original ordering and derive only one literal destination."""

    native = TCP[:-1] + (("-sV", "--version-light") if service else ()) + (
        ("-6", "::1") if ipv6 else (TCP[-1],))
    selection = SelectRawNmap(native)
    assert selection.arguments == native and selection.ports == (80, 443), (
        "Original native tokens must remain exact while the derived port set stays deterministic")
    assert selection.address == ("::1" if ipv6 else "127.0.0.1"), (
        "The independently derived literal address must match the sole native target")
    capability = "network.service-discovery" if service else "network.tcp-connect"
    assert selection.capability == capability and selection.timeout_seconds == 15, (
        "Native flags must select only their existing capability and finite timeout")
    request = selection.Request()
    assert request.impact is ImpactLevel.STANDARD and request.target_reference == (
        selection.Target.Reference()), "Scope subject must be the original literal target"
    executable = str(tmp_path / "trusted tool")
    adapter = RawNmapAdapter(ForbiddenRead, selection, executable, "7.992")
    invocation = adapter.PrepareInvocation(request)
    assert invocation.argv == (executable, *native) and invocation.provider_version == "7.992", (
        "Preparation must retain actual native argument order and the observed provider version")
    assert invocation.request == request and invocation.timeout_seconds == 15, (
        "Exact native execution must retain its independently derived request and finite bound")


def test_OptionReorderingChangesTheAuthorizedDigestWithoutChangingTheTarget(tmp_path):
    """Equal parsed meaning must not let a differently ordered command inherit confirmation."""

    first = SelectRawNmap(TCP)
    second = SelectRawNmap(("-p", "443,80", "--unprivileged", "-Pn", "-sT", "-n",
        "-oX", "-", "127.0.0.1", "--host-timeout", "15s"))
    executable = str(tmp_path / "nmap")
    invocation = RawNmapAdapter(ForbiddenRead, first, executable).PrepareInvocation(first.Request())
    reordered = RawNmapAdapter(ForbiddenRead, second, executable).PrepareInvocation(
        second.Request())
    assert first.Request() == second.Request() and invocation.argv != reordered.argv, (
        "The same finite request must preserve both distinct original argument orders")
    assert InvocationDigest(invocation) != InvocationDigest(reordered), (
        "Exact execution authorization must change when any actual native argument order changes")


@pytest.mark.parametrize("arguments", [
    (), ("nmap -sT 127.0.0.1",), TCP + ("--script", "default"), TCP + ("-sS",),
    TCP + ("-O",), TCP + ("-sU",), TCP + ("-A",), TCP + ("--datadir", "/tmp"),
    TCP + ("-iL", "targets"), TCP + ("--resume", "prior"), TCP + ("-oN", "output"),
    TCP + ("-n",), TCP + ("127.0.0.2",), TCP[:-1] + ("localhost",),
    TCP[:-1] + ("127.0.0.0/24",), TCP[:-1] + ("0.0.0.0",),
    TCP[:-1] + ("224.0.0.1",), TCP[:-1] + ("127.000.0.1",), TCP[:-1] + ("::1",),
    TCP + ("-6",), TCP + ("-sV",), TCP + ("--version-light",),
    TCP[:4] + ("-p", "80,80") + TCP[6:],
    TCP[:4] + ("-p", "0") + TCP[6:], TCP[:4] + ("-p", "65536") + TCP[6:],
    TCP[:4] + ("-p", "080") + TCP[6:], TCP[:4] + ("-p", "1-1024") + TCP[6:],
    TCP[:4] + ("-p", "http") + TCP[6:], TCP[:4] + ("-p", ",80") + TCP[6:],
    TCP[:6] + ("--host-timeout", "0s") + TCP[8:],
    TCP[:6] + ("--host-timeout", "3601s") + TCP[8:],
    TCP[:6] + ("--host-timeout", "1m") + TCP[8:],
    TCP[:6] + ("--host-timeout", "01s") + TCP[8:],
    TCP[:8] + ("-oX", "report.xml") + TCP[10:], TCP[1:],
    TCP[:-1] + ("127.0.0.1\n",), TCP[:-1] + ("127.0.0.1\x00",),
    TCP[:-1] + ("fe80::1%lo", "-6"), TCP + ("--host-timeout",),
    ("x" * 8193,), ("-n",) * 33,
], ids=lambda value: "invalid-" + str(len(value)))
def test_UnmodeledFlagsTargetsAndAmbiguousValuesRefuseBeforeAnyOwner(arguments):
    """Unsupported flags or token expansion cannot obtain a derived scope or process recipe."""

    with pytest.raises(ValueError):
        SelectRawNmap(arguments)


@pytest.mark.parametrize("arguments", ["nmap --unprivileged", b"nmap", (True,), (None,), ["-n"]])
def test_SelectionRequiresExplicitTypedTokensRatherThanShellText(arguments):
    """Shell text, ambiguous token types and unvalidated dataclass construction remain refused."""

    with pytest.raises(ValueError):
        if isinstance(arguments, list):
            RawNmapSelection(arguments)

        else:
            SelectRawNmap(arguments)


def test_FrozenSelectionAndAdapterRefuseRequestSubstitution(tmp_path):
    """No later request or mutable field can broaden the original capability inputs."""

    selection = SelectRawNmap(TCP)

    with pytest.raises(FrozenInstanceError):
        selection.arguments = TCP + ("-A",)

    adapter = RawNmapAdapter(ForbiddenRead, selection, str(tmp_path / "nmap"))

    with pytest.raises(ValueError, match="original native arguments"):
        adapter.PrepareInvocation(replace(selection.Request(), parameters={}))

    with pytest.raises(ValueError, match="absolute trusted executable"):
        RawNmapAdapter(ForbiddenRead, selection, "nmap")

    with pytest.raises(ValueError, match="typed selection"):
        RawNmapAdapter(ForbiddenRead, TCP, str(tmp_path / "nmap"))
