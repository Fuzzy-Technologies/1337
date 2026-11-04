# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed-wheel-only SDK consumer for independent owned-response product acceptance."""

from __future__ import annotations

import asyncio
import json
import socket
import sys
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.executors import LocalExecutor
from fuzzy1337.findings import Finding, FindingStatus
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.nucleiscan import ReadNucleiPolicy
from fuzzy1337.owned_response_workflow import (
    PlanOwnedResponseCapture,
    ReplayOwnedResponse,
    RunOwnedResponseCapture,
)
from fuzzy1337.policy import PolicyEngine
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

OWNER = "actor:owned-response-product"
WORKSPACE = "owned-response-product"


def Detached(value):
    """Return actual owner contracts as data without constructing expected product output."""

    return json.loads(SerializeContract(value))


def Inspect(root: Path) -> dict:
    """Reopen canonical originals using actual recorded IDs, never replacement publications."""

    workspace = LocalWorkspaceStore(root).Open()
    store = LocalEvidenceStore(root / "evidence")
    originals = {}

    for identity in workspace.evidence_record_references:
        record = store.Get(identity)
        originals[identity] = {"manifest": record.ToDict(),
            "data_hex": store.Read(record.reference).hex()}

    return {"workspace": workspace.ToDict(), "model": LocalModelStore(root).Open().ToDict(),
        "originals": originals}


def Setup(config: dict) -> dict:
    """Seed explicit consent plus unrelated synthetic native model/triage and original evidence."""

    root = Path(config["workspace"])
    workspace_store = LocalWorkspaceStore(root)
    workspace_store.Create(WorkspaceConfiguration("Owned response product oracle"), WORKSPACE)
    model_store = LocalModelStore(root)
    model = model_store.Create()
    now = datetime.now(timezone.utc)
    expired = config.get("negative") == "expired"
    consent = ScopeAuthorization(AuthorizationState.REVOKED if config.get("negative") == (
        "revoked") else AuthorizationState.GRANTED, "attester:independent-source-consent",
        "consent:owned-response-source", (now - timedelta(minutes=2)).isoformat(),
        (now - timedelta(seconds=1) if expired else now + timedelta(minutes=30)).isoformat())
    targets = (Target(TargetKind.URL, config["url"]), Target(TargetKind.IP, "127.0.0.1"))
    LocalScopeStore(root).Create(ScopeSnapshot("owned-source", WORKSPACE,
        authorization=consent, targets=targets, allow=targets))
    store = LocalEvidenceStore(root / "evidence")
    provenance = EvidenceProvenance(WORKSPACE, "scope:unrelated-native-fixture", "native.trivy",
        "1", "0.75.0", now.isoformat(), now.isoformat())
    original = store.Put(b"unrelated synthetic native source; no engine execution\n",
        "unrelated-native-source", "application/octet-stream", provenance)
    attribution = ModelProvenance("native.trivy", "job:unrelated-native-fixture", now.isoformat(),
        "scope:unrelated-native-fixture", "artifact:unrelated-native-fixture", "0.75.0",
        (original.reference,))
    asset = SecurityObject(ObjectIdentity(WORKSPACE, ObjectKind.ASSET, "native-image:unrelated"),
        {"source": "native.trivy", "fixture": "unrelated existing native state"}, (attribution,))
    finding = Finding(asset.Reference(), "owned.native-fixture", "package:unrelated",
        "Unrelated synthetic existing finding", (attribution,))
    proposed, _ = model.Apply(objects=(asset, finding.ToObject(WORKSPACE)))
    saved = model_store.Save(proposed, expected_revision=model.revision)
    triaged = replace(finding, status=FindingStatus.CONFIRMED,
        status_reason="Existing independent operator triage must survive response acquisition")
    proposed, _ = saved.Apply(objects=(triaged.ToObject(WORKSPACE),))
    saved = model_store.Save(proposed, expected_revision=saved.revision)
    workspace = workspace_store.Open()
    workspace_store.Save(replace(workspace,
        object_references=tuple(item.Reference() for item in saved.objects),
        job_references=("job:unrelated-native-fixture",), evidence_references=(original.reference,),
        evidence_record_references=(original.evidence_id,)))
    result = Inspect(root)
    result["scope_file"] = str(LocalScopeStore(root).Paths("owned-source", initialize=False)[1])

    return result


def OriginalExecution(request, result) -> dict:
    """Detach exact actual executor values while returning the original object to its owner."""

    return {"request": Detached(request), "execution": Detached(result.execution),
        "termination": result.termination.value, "stdout_hex": result.stdout.hex(),
        "stderr_hex": result.stderr.hex(), "events": [{"sequence": event.sequence,
            "kind": event.kind.value, "data_hex": event.data.hex(),
            "termination": None if event.termination is None else event.termination.value}
            for event in result.events]}


def Capture(config: dict) -> dict:
    """Invoke the installed SDK and observe its genuine executor without substituting a result."""

    root = Path(config["workspace"])
    policy = Path(config["policy"])
    executions = []
    owner_reads = 0
    original_execute = LocalExecutor.Execute

    def CurrentOwner():
        """Change only trusted current attribution after the initial original actor selection."""

        nonlocal owner_reads
        owner_reads += 1

        return "actor:changed-before-launch" if config.get("negative") == (
            "owner-change") and owner_reads > 1 else OWNER

    async def Observe(executor, request, **options):
        """Delegate actual installed worker execution and retain its original return unchanged."""

        result = await original_execute(executor, request, **options)
        executions.append(OriginalExecution(request, result))

        return result

    LocalExecutor.Execute = Observe

    try:
        summary = asyncio.run(RunOwnedResponseCapture(root, "owned-source", config["url"], OWNER,
            lambda: ReadNucleiPolicy(policy),
            approve_safe_response_capture=config.get("approve", True),
            current_owner_provider=CurrentOwner))
        result = {"summary": summary.ToDict(), "exception_type": None}

    except (PermissionError, ValueError) as error:
        result = {"summary": None, "exception_type": type(error).__name__}

    finally:
        LocalExecutor.Execute = original_execute

    result.update(state=Inspect(root), executions=executions, owner_reads=owner_reads)

    return result


def Cancellation(config: dict) -> dict:
    """Cancel the installed SDK only after the owned listener records its actual selected GET."""

    root = Path(config["workspace"])
    ready = Path(config["request_ready"])
    executions = []
    original_execute = LocalExecutor.Execute

    async def Observe(executor, request, **options):
        """Retain the genuine original terminal result after actual local process cleanup."""

        result = await original_execute(executor, request, **options)
        executions.append(OriginalExecution(request, result))

        return result

    async def Run():
        """Own one public SDK task and await its terminal summary after caller cancellation."""

        task = asyncio.create_task(RunOwnedResponseCapture(root, "owned-source", config["url"],
            OWNER, lambda: ReadNucleiPolicy(Path(config["policy"])),
            approve_safe_response_capture=True))
        deadline = time.monotonic() + 3

        try:
            while not ready.exists():
                if task.done():
                    raise AssertionError("Installed SDK ended before the selected GET was observed")

                if time.monotonic() >= deadline:
                    raise AssertionError("Owned listener did not observe the selected GET in time")

                await asyncio.sleep(0.01)

            task.cancel()
            summary = await asyncio.wait_for(asyncio.shield(task), timeout=3)

            return summary, task.done()

        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    LocalExecutor.Execute = Observe

    try:
        summary, settled = asyncio.run(Run())

    finally:
        LocalExecutor.Execute = original_execute

    store = LocalEvidenceStore(root / "evidence")
    attached = {}

    for identity in summary.ToDict()["original_role_ids"].values():
        record = store.Get(identity)
        attached[identity] = {"manifest": record.ToDict(),
            "data_hex": store.Read(record.reference).hex()}

    return {"summary": summary.ToDict(), "state": Inspect(root), "executions": executions,
        "sdk_task_settled": settled, "attached": attached}


def Replay(config: dict) -> dict:
    """Exercise installed pure replay with forbidden network, execution, grants and persistence."""

    def Forbidden(*_args, **_kwargs):
        """Reject any online work, current authorization or canonical write during replay."""

        raise AssertionError("Offline replay attempted online work or canonical persistence")

    socket.create_connection = Forbidden
    socket.socket.connect = Forbidden
    LocalExecutor.Execute = Forbidden
    PolicyEngine.Plan = Forbidden
    PolicyEngine.Authorize = Forbidden
    LocalModelStore.Save = Forbidden
    LocalWorkspaceStore.Save = Forbidden
    LocalEvidenceStore.Put = Forbidden
    root = Path(config["workspace"])

    try:
        summary = ReplayOwnedResponse(root, config["receipt"])

    except (ValueError, OSError, RuntimeError) as error:
        return {"summary": None, "exception_type": type(error).__name__}

    return {"summary": summary.ToDict(), "exception_type": None, "state": Inspect(root)}


def Main() -> int:
    """Dispatch only this test consumer's fixed setup/inspect/plan/capture/replay operations."""

    mode, configuration = sys.argv[1:]
    config = json.loads(Path(configuration).read_bytes())
    root = Path(config["workspace"])

    if mode == "setup":
        result = Setup(config)

    elif mode == "inspect":
        result = Inspect(root)

    elif mode == "plan":
        plan = PlanOwnedResponseCapture(root, "owned-source", config["url"], OWNER,
            lambda: ReadNucleiPolicy(Path(config["policy"])))
        result = {"summary": plan.ToDict(), "state": Inspect(root)}

    elif mode == "capture":
        result = Capture(config)

    elif mode == "replay":
        result = Replay(config)

    elif mode == "cancel":
        result = Cancellation(config)

    else:
        raise ValueError("Unsupported owned product test operation")

    module = sys.modules[RunOwnedResponseCapture.__module__]
    result["runtime_module"] = str(Path(module.__file__).resolve())
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
