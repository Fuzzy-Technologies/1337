# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Opt-in Python tripwires and original Save observations for the fixed reviewed SDK path.

Audit refusal/telemetry is scoped to deterministic tests, not a sandbox for adversarial code.
See https://docs.python.org/3.12/library/sys.html#sys.addaudithook for the process-hook contract.
"""

from __future__ import annotations

import asyncio
import gc
import importlib
import multiprocessing
import os
import socket
import subprocess
import sys
import threading
from contextlib import ExitStack, contextmanager
from unittest.mock import patch

_SOCKET_TYPE = socket.SocketType
_SOCKET_CLASS = socket.socket
_audit_installed = False
_audit_owner = None


def SocketAudit(event, args):
    """Keep one deliberate process hook inert outside an explicitly active guard context."""

    if _audit_owner is not None:
        if event == "fuzzy1337.offline_guard.probe":
            _audit_owner["audit_probe_seen"] = True

        elif event.startswith("socket."):
            _audit_owner["calls"]["socket.audit"] += 1
            raise AssertionError("Offline SDK operation attempted audited socket work")


@contextmanager
def SocketGate(record):
    """Refuse pre-existing sockets and audited constructor/connect/DNS aliases before effects.

    The interpreter cannot remove an audit hook. Registration is once per helper module;
    its active owner is always cleared on exit and the retained hook is then inert.
    """

    global _audit_installed, _audit_owner

    if _audit_owner is not None:
        raise RuntimeError("Offline SDK socket guards cannot overlap")

    if any(isinstance(value, _SOCKET_TYPE) for value in gc.get_objects()):
        raise PermissionError("Offline SDK guard requires a process without existing sockets")

    if not _audit_installed:
        sys.addaudithook(SocketAudit)
        _audit_installed = True

    record["calls"]["socket.audit"] = 0
    record["audit_probe_seen"] = False
    _audit_owner = record

    try:
        sys.audit("fuzzy1337.offline_guard.probe")

        if record["audit_probe_seen"] is not True:
            raise RuntimeError("Offline SDK audit hook delivery is unavailable")

        yield

    finally:
        _audit_owner = None


@contextmanager
def OfflineGuard(*, historical: bool = False, enabled: bool = False):
    """Block external work, observing original analysis Saves or denying historical writes.

    Args:
        historical: Exact boolean selecting replay-only Save/current-scope refusal.
        enabled: Separate exact test-driver opt-in; false refuses before product imports.

    Yields:
        Per-seam forbidden-call counters and original analysis Save argument/return objects.
        The caller retains them after restoration and independently verifies the original state.
    """

    if enabled is not True or type(historical) is not bool:
        raise PermissionError("Offline SDK tripwires require exact explicit operation selection")

    from fuzzy1337.evidence import LocalEvidenceStore
    from fuzzy1337.executors import LocalExecutor
    from fuzzy1337.model import LocalModelStore
    from fuzzy1337.owned_response_custody import OwnedResponseStage
    from fuzzy1337.policy import GovernedLocalExecutor, PolicyEngine
    from fuzzy1337.scope import LocalScopeStore
    from fuzzy1337.workspace import LocalWorkspaceStore

    acquisition = importlib.import_module("fuzzy1337.owned_response_workflow")
    parent = importlib.import_module("fuzzy1337.owned_response_capture")
    workflow = importlib.import_module("fuzzy1337.native_response_header_workflow")
    headers = importlib.import_module("fuzzy1337.native_response_headers")
    originals = {"model": LocalModelStore.Save, "workspace": LocalWorkspaceStore.Save}
    record = {"calls": {}, "saves": []}
    blocked, patched = set(), set()

    with SocketGate(record), ExitStack() as stack:
        def Block(owner, name):
            """Replace one actual seam, counting every attempted call before refusing it."""

            if not hasattr(owner, name) or (id(owner), name) in patched:
                return

            original = getattr(owner, name)
            blocked.add(id(original))
            patched.add((id(owner), name))
            label = owner.__name__ + "." + name
            record["calls"][label] = 0

            def Forbidden(*args, **kwargs):
                """Refuse without executing an original external or replay-write seam."""

                record["calls"][label] += 1
                raise AssertionError("Offline SDK operation attempted " + label)

            stack.enter_context(patch.object(owner, name, Forbidden))

        inventory = [(_SOCKET_CLASS, ("connect", "connect_ex", "send", "sendall", "sendto",
            "sendmsg", "sendfile")), (socket, ("socket", "SocketType", "create_connection",
                "getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr",
                "getnameinfo", "getfqdn")),
            (subprocess, ("Popen", "run", "call", "check_call", "check_output")),
            (asyncio, ("create_subprocess_exec", "create_subprocess_shell")),
            (os, ("system", "fork", "forkpty", "posix_spawn", "posix_spawnp", "startfile")),
            (threading.Thread, ("start",)), (multiprocessing.Process, ("start",)),
            (LocalExecutor, ("Execute",)), (GovernedLocalExecutor, ("Execute",)),
            (PolicyEngine, ("Plan", "Authorize")),
            (LocalEvidenceStore, ("Put", "PublishStoredBytes")),
            (OwnedResponseStage, ("__init__", "Append")),
            (parent.OwnedResponseCaptureProvider, ("__init__",)),
            (parent, ("PrepareOwnedResponseInvocation", "PrepareResponseInvocation")),
            (acquisition, ("RunOwnedResponseCapture", "PlanOwnedResponseCapture",
                "RunOwnedContentResponseCapture", "PlanOwnedContentResponseCapture"))]

        if historical:
            inventory.extend([(LocalModelStore, ("Save",)), (LocalWorkspaceStore, ("Save",)),
                (LocalScopeStore, ("Open",))])

        for owner, names in inventory:
            for name in names:
                Block(owner, name)

        for module in (workflow, headers, acquisition, parent):
            for name, value in tuple(vars(module).items()):
                if id(value) in blocked:
                    Block(module, name)

        def Save(owner, store, proposal, expected_revision, options):
            """Delegate unchanged original arguments and retain actual returns or uncertainty."""

            row = {"owner": owner, "expected_revision": expected_revision, "proposal": proposal,
                "returned": None, "exception_type": None}
            record["saves"].append(row)

            try:
                returned = originals[owner](store, proposal, **options)
                row["returned"] = returned

                return returned

            except BaseException as error:
                row["exception_type"] = type(error).__name__

                raise

        def ModelSave(store, proposal, *, expected_revision):
            """Observe only the actual explicit model CAS keyword and original proposal."""

            return Save("model", store, proposal, expected_revision,
                {"expected_revision": expected_revision})

        def WorkspaceSave(store, proposal):
            """Observe only the actual proposal revision, leaving increment to the store."""

            return Save("workspace", store, proposal, proposal.revision, {})

        if not historical:
            stack.enter_context(patch.object(LocalModelStore, "Save", ModelSave))
            stack.enter_context(patch.object(LocalWorkspaceStore, "Save", WorkspaceSave))

        yield record


def DetachedGuard(record: dict) -> dict:
    """Detach observed original documents after all patched owners have been restored.

    Args:
        record: Original yielded guard counters and retained Save objects, not expected values.

    Returns:
        JSON-compatible observations; caller still checks all forbidden counters equal zero.
    """

    return {"calls": dict(record["calls"]), "audit_probe_seen": record["audit_probe_seen"],
        "saves": [{**row,
        "proposal": row["proposal"].ToDict(), "returned": None if row["returned"] is None else
            row["returned"].ToDict()} for row in record["saves"]]}
