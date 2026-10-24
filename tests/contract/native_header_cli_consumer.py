# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Fixed installed entry-point runner with real setup/triage and offline side-effect tripwires."""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import importlib.metadata
import json
import multiprocessing
import os
import runpy
import socket
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

SOURCE_MODULES = ("__main__.py", "cli.py", "command_registry.py", "shell.py",
    "response_commands.py", "scan_commands.py", "native_crawl_commands.py",
    "adapters/native_crawl.py", "native_crawl_worker.py", "native_crawl.py",
    "native_crawl_workflow.py", "adapters/owned_response_capture.py", "owned_response_capture.py",
    "owned_response_capture_worker.py", "owned_response_custody.py", "owned_response_workflow.py",
    "native_response_headers.py", "native_response_header_workflow.py", "report_commands.py")
WORKSPACE = "native-header-cli-pipeline"
SCOPE = "native-pipeline"
OWNER = "operator:native-header-cli"
ATTESTER = "attester:separate-owned-pipeline"


def Canonical(value: object) -> bytes:
    """Encode finite actual owner facts without NaN or implicit source attribution."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")


def Identity() -> dict:
    """Observe every enrolled command/crawl/header module from the real installed wheel."""

    import fuzzy1337

    result = {"distribution_version": importlib.metadata.version("1337"), "installed_sources": {}}

    for name in SOURCE_MODULES:
        if name != "__main__.py":
            module = importlib.import_module("fuzzy1337." + name[:-3].replace("/", "."))
            path = Path(module.__file__).resolve()

        else:
            path = Path(fuzzy1337.__file__).resolve().parent / name

        assert path.stat().st_size <= 1024 * 1024, "Fixed installed source exceeds its ceiling"
        result["installed_sources"][name] = {"path": str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    return result


def Setup(config: dict) -> dict:
    """Create actual empty canonical owners and one explicit four-URL/IP consent scope."""

    from fuzzy1337.model import LocalModelStore
    from fuzzy1337.scan_commands import CreateWorkspace
    from fuzzy1337.scope import (
        AuthorizationState,
        LocalScopeStore,
        ScopeAuthorization,
        ScopeSnapshot,
        Target,
        TargetKind,
    )
    from fuzzy1337.workspace import LocalWorkspaceStore

    root = Path(config["workspace"])
    CreateWorkspace(root, WORKSPACE, "Owned native CLI pipeline")
    now = datetime.now(timezone.utc)
    consent = ScopeAuthorization(AuthorizationState.GRANTED, ATTESTER,
        "consent:explicit-owned-native-pipeline", (now - timedelta(minutes=1)).isoformat(),
        (now + timedelta(minutes=20)).isoformat())
    selected = tuple(Target(TargetKind.URL, url) for url in config["selected_urls"])
    targets = (*selected, Target(TargetKind.IP, "127.0.0.1"))
    scope = LocalScopeStore(root).Create(ScopeSnapshot(SCOPE, WORKSPACE, consent,
        targets=targets, allow=targets))

    return {"workspace": LocalWorkspaceStore(root).Open().ToDict(),
        "model": LocalModelStore(root).Open().ToDict(), "scope": scope.ToDict(),
        "installed_identity": Identity()}


def Triage(config: dict) -> dict:
    """Perform one actual attributed canonical Finding disposition, retaining its real ACK."""

    from fuzzy1337.findings import FindingStatus, TransitionFinding
    from fuzzy1337.model import LocalModelStore, ModelProvenance

    store = LocalModelStore(Path(config["workspace"]))
    before = store.Open()
    provenance = ModelProvenance("operator.native-header-cli", "triage:explicit-cli-pipeline",
        datetime.now(timezone.utc).isoformat(), "scope:" + SCOPE, "operator:controlled-triage", "1")
    proposal, _ = TransitionFinding(before, config["finding_reference"], FindingStatus.CONFIRMED,
        provenance, "Independent operator confirmed the original missing header")
    acknowledged = store.Save(proposal, expected_revision=before.revision)

    return {"prior_revision": before.revision, "acknowledged": acknowledged.ToDict(),
        "installed_identity": Identity()}


def OfflineEntry(metrics_path: Path, arguments: list[str]) -> int:
    """Run the real installed module entry point; observe Saves and forbid new acquisition."""

    from fuzzy1337 import native_crawl_workflow, owned_response_capture, owned_response_workflow
    from fuzzy1337.evidence import LocalEvidenceStore
    from fuzzy1337.executors import LocalExecutor
    from fuzzy1337.model import LocalModelStore
    from fuzzy1337.owned_response_capture import OwnedResponseCaptureProvider
    from fuzzy1337.owned_response_custody import OwnedResponseStage
    from fuzzy1337.policy import GovernedLocalExecutor, PolicyEngine
    from fuzzy1337.workspace import LocalWorkspaceStore

    metrics = {"schema_version": 1, "product_argv": arguments, "installed_identity": Identity(),
        "store_reads": [], "saves": [], "forbidden_calls": 0, "entry_exit_code": None}

    def Forbidden(*_args, **_kwargs):
        """Fail immediately on a real forbidden call, without substituting a success result."""

        metrics["forbidden_calls"] += 1

        raise AssertionError("Offline installed CLI attempted forbidden acquisition or publication")

    def ObserveStore(store_type, kind):
        """Delegate actual owner reads/Saves unchanged and retain actual returned revisions."""

        original_open, original_save = store_type.Open, store_type.Save

        def Open(store, *args, **kwargs):
            """Record a real Open before delegating its unchanged result or failure."""

            metrics["store_reads"].append(kind)

            return original_open(store, *args, **kwargs)

        def Save(store, proposed, *args, **kwargs):
            """Record the actual acknowledged Save, with no retries or synthetic ACK metadata."""

            record = {"kind": kind, "acknowledgement_returned": False}
            metrics["saves"].append(record)
            result = original_save(store, proposed, *args, **kwargs)
            record.update(acknowledgement_returned=True, revision=result.revision)

            return result

        store_type.Open, store_type.Save = Open, Save

    ObserveStore(LocalModelStore, "model")
    ObserveStore(LocalWorkspaceStore, "workspace")

    for owner, names in ((socket, ("socket", "create_connection", "getaddrinfo")),
        (subprocess, ("Popen", "run", "call", "check_call", "check_output")),
        (asyncio, ("create_subprocess_exec", "create_subprocess_shell")),
        (os, ("system", "fork", "forkpty", "posix_spawn", "posix_spawnp", "startfile")),
        (threading.Thread, ("start",)), (multiprocessing.Process, ("start",)),
        (LocalExecutor, ("Execute",)), (GovernedLocalExecutor, ("Execute",)),
        (PolicyEngine, ("Plan", "Authorize")),
        (LocalEvidenceStore, ("Put", "PublishStoredBytes")),
        (OwnedResponseStage, ("__init__", "Append")),
        (OwnedResponseCaptureProvider, ("__init__",)),
        (owned_response_capture, ("PrepareOwnedResponseInvocation",)),
        (owned_response_workflow, ("RunOwnedResponseCapture", "PlanOwnedResponseCapture",
            "PrepareOwnedResponseInvocation")),
        (native_crawl_workflow, ("RunNativeCrawl", "PlanNativeCrawl"))):
        for name in names:
            if hasattr(owner, name):
                setattr(owner, name, Forbidden)

    sys.argv = ["1337", *arguments]

    try:
        runpy.run_module("fuzzy1337", run_name="__main__")

    except SystemExit as terminal:
        assert type(terminal.code) is int, "Installed entry point must return a concrete exit code"
        metrics["entry_exit_code"] = terminal.code

        return terminal.code

    finally:
        metrics_path.write_bytes(Canonical(metrics))

    raise AssertionError("Installed entry point returned without its actual terminal status")


def Main() -> int:
    """Dispatch only fixed identity/setup/triage or the real offline installed product entry."""

    arguments = sys.argv[1:]

    if arguments == ["identity"]:
        output = Identity()

    elif len(arguments) == 2 and arguments[0] in ("setup", "triage"):
        raw = Path(arguments[1]).read_bytes()
        assert len(raw) <= 8192, "Fixed pipeline setup/triage input exceeds its bound"
        output = Setup(json.loads(raw)) if arguments[0] == "setup" else Triage(json.loads(raw))

    elif len(arguments) >= 4 and arguments[0] == "offline" and arguments[2] == "--":
        return OfflineEntry(Path(arguments[1]), arguments[3:])

    else:
        raise ValueError("Unsupported fixed native-header CLI consumer operation")

    sys.stdout.buffer.write(Canonical(output))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
