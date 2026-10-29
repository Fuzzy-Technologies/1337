# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline guard refusal/restoration doubles; no actual network, process, job or store work."""

from __future__ import annotations

import asyncio
import socket
import sys
from types import SimpleNamespace

import pytest

from fuzzy1337.model import LocalModelStore
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.contract import owned_content_response_sdk_offline_guard as guard
from tests.contract.owned_content_response_sdk_offline_guard import DetachedGuard, OfflineGuard


@pytest.mark.parametrize("enabled", [False, None, 1, "yes"])
def test_ExactOptInPrecedesGuardInstallation(enabled):
    """Truthiness must not enroll or change the process's existing boundary owners."""

    original = socket.socket

    with pytest.raises(PermissionError):
        with OfflineGuard(enabled=enabled):
            raise AssertionError("Default denial failed")

    assert socket.socket is original, (
        "Leaving the offline guard must restore the original socket constructor."
    )


@pytest.mark.parametrize("failure", [None, "lost-ack", "cancelled"])
def test_AnalysisRetainsOriginalSaveObjectsAndRestoresForbiddenAliases(failure, monkeypatch):
    """Only explicit doubles may run; cancellation and missing returns stay distinguishable."""

    proposal = SimpleNamespace(ToDict=lambda: {"revision": 4})
    returned = SimpleNamespace(ToDict=lambda: {"revision": 4})

    def Save(store, state, *, expected_revision):
        """Return the original synthetic object without performing a real persistence action."""

        assert state is proposal and expected_revision == 3, (
            "The observed model Save must receive the original proposal object and exact CAS "
            "revision."
        )

        if failure == "lost-ack":
            raise OSError("synthetic unavailable acknowledgement")

        return returned

    monkeypatch.setattr(LocalModelStore, "Save", Save)
    original_socket = socket.socket
    record = None

    try:
        with OfflineGuard(enabled=True) as record:
            with pytest.raises(AssertionError, match="socket.socket"):
                socket.socket()

            assert LocalModelStore.Save(None, proposal, expected_revision=3) is returned, (
                "The guarded Save must preserve the original returned object without manufacturing "
                "an ACK."
            )

            if failure == "cancelled":
                raise asyncio.CancelledError

    except OSError:
        assert failure == "lost-ack", (
            "Only the explicitly selected lost-ACK fixture may raise the injected persistence "
            "failure."
        )

    except asyncio.CancelledError:
        assert failure == "cancelled", (
            "Only the explicitly selected cancellation fixture may propagate the injected "
            "cancellation."
        )

    assert socket.socket is original_socket and LocalModelStore.Save is Save, (
        "Guard cleanup must restore both the original socket constructor and model Save callback."
    )
    detached = DetachedGuard(record)
    assert detached["calls"]["socket.socket"] == 1, (
        "The detached guard record must retain the one actual intercepted socket constructor call."
    )
    assert len(detached["saves"]) == 1 and detached["saves"][0]["proposal"] == {"revision": 4}, (
        "The guard must retain one original Save proposal with its exact proposed revision."
    )
    assert detached["saves"][0]["returned"] == (
        None if failure == "lost-ack" else {"revision": 4}), (
        "The Save trace must distinguish a missing acknowledgement from the actual returned "
        "revision."
    )
    assert detached["saves"][0]["exception_type"] == (
        "OSError" if failure == "lost-ack" else None), (
        "The Save trace must retain the original injected exception type only for lost ACK."
    )


@pytest.mark.parametrize("boundary", ["model", "workspace", "scope"])
def test_HistoricalReplayRefusesWritesAndCurrentScopeBeforeEffects(boundary, monkeypatch):
    """The original boundary doubles remain uncalled when historical verification tries I/O."""

    called = []

    def Unexpected(*args, **kwargs):
        """Record any original write/authority attempt; a valid guard must prevent this."""

        called.append(True)

    owner, name = {"model": (LocalModelStore, "Save"), "workspace": (LocalWorkspaceStore, "Save"),
        "scope": (LocalScopeStore, "Open")}[boundary]
    monkeypatch.setattr(owner, name, Unexpected)

    with OfflineGuard(historical=True, enabled=True) as record:
        with pytest.raises(AssertionError):
            getattr(owner, name)(None)

    assert called == [] and getattr(owner, name) is Unexpected, (
        "Denied offline operations must not call the original owner callback or replace its "
        "binding."
    )
    assert sum(record["calls"].values()) == 1 and record["saves"] == [], (
        "A denied offline operation must retain one attempted call and no Save trace."
    )


@pytest.mark.parametrize("event", ["socket.__new__", "socket.connect", "socket.gethostbyname",
    "socket.gethostbyaddr", "socket.getnameinfo"])
def test_CachedNativeAliasAuditPrecedesMockedSocketEffects(event):
    """Emit actual audit protocol events without creating a socket, resolving DNS or connecting."""

    effects = []

    def CachedNativeAlias():
        """Model the documented native audit boundary before any socket side effect."""

        arguments = {"socket.__new__": (None, 2, 1, 0),
            "socket.connect": (None, ("127.0.0.1", 0)),
            "socket.gethostbyname": ("unit.invalid",), "socket.gethostbyaddr": ("127.0.0.1",),
            "socket.getnameinfo": (("127.0.0.1", 0), 0)}[event]
        sys.audit(event, *arguments)
        effects.append(True)

    with OfflineGuard(enabled=True) as record:
        with pytest.raises(AssertionError, match="audited socket"):
            CachedNativeAlias()

    assert effects == [] and record["calls"]["socket.audit"] == 1, (
        "The socket audit guard must record and block the operation before any injected side "
        "effect."
    )
    CachedNativeAlias()
    assert effects == [True] and guard._audit_owner is None, (
        "Retained hook must be inert after exit")


def test_ExistingSocketInventoryRefusesBeforePatchingAnyOwner(monkeypatch):
    """Synthetic socket inventory proves failure before SDK/seam mutation, without a real socket."""

    token = object()
    monkeypatch.setattr(guard, "_SOCKET_TYPE", type(token))
    monkeypatch.setattr(guard.gc, "get_objects", lambda: [token])
    original = socket.socket

    with pytest.raises(PermissionError, match="existing sockets"):
        with OfflineGuard(enabled=True):
            raise AssertionError("Socket inventory must deny first")

    assert socket.socket is original and guard._audit_owner is None, (
        "Failed guard setup must restore the original socket constructor and release audit "
        "ownership."
    )


@pytest.mark.parametrize("method", ["connect", "connect_ex", "sendall"])
def test_OriginalPythonSocketMethodsRefuseBeforeOriginalEffect(method):
    """Call patched original methods with a dummy self, never constructing a socket."""

    original = getattr(guard._SOCKET_CLASS, method)

    with OfflineGuard(enabled=True):
        with pytest.raises(AssertionError, match=method):
            getattr(guard._SOCKET_CLASS, method)(None, b"synthetic")

    assert getattr(guard._SOCKET_CLASS, method) is original, (
        "Guard teardown must restore every original socket-class method."
    )


def test_AuditDeliveryFailureDeniesBeforeAnySeamPatch(monkeypatch):
    """Suppressed audit delivery cannot silently turn a denied constructor into an allowed one."""

    monkeypatch.setattr(guard.sys, "audit", lambda *args: None)
    original = socket.socket

    with pytest.raises(RuntimeError, match="delivery is unavailable"):
        with OfflineGuard(enabled=True):
            raise AssertionError("Audit delivery must be verified before entry")

    assert socket.socket is original and guard._audit_owner is None, (
        "Repeated guard use must restore the original socket constructor and release audit "
        "ownership."
    )


def test_NestedGuardRefusesWithoutReplacingOriginalActiveOwner():
    """One process registry owner cannot be silently replaced by another operation."""

    with OfflineGuard(enabled=True) as record:
        with pytest.raises(RuntimeError, match="cannot overlap"):
            with OfflineGuard(enabled=True):
                raise AssertionError("Nested guard must refuse")

        assert guard._audit_owner is record, (
            "The active offline guard must retain its original audit record as the sole audit "
            "owner."
        )

    assert guard._audit_owner is None, (
        "Guard exit must release audit ownership even when the operation fails."
    )
