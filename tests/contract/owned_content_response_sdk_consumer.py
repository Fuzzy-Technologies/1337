# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Opt-in installed SDK handoffs only; no setup, launcher, acceptance oracle or CLI enrollment.

Capture never starts analysis. Analysis and historical replay each require their own explicit
selection. Observations preserve actual SDK values; they do not manufacture ACKs or source IDs.
Every operation requires a fresh observation directory, including source and header replays.
"""

from __future__ import annotations

import json
from pathlib import Path

CONTENT_PROFILE = "owned-content-response-capture.v1"
MAX_OBSERVATION_BYTES = 16 * 1024 * 1024


def ReserveObservation(directory: Path, operation: str) -> None:
    """Reserve one fresh attempt owner before any SDK, executor or store effects.

    Args:
        directory: New absolute owned observation directory; any existing owner is refused.
        operation: Fixed independently selected operation name.
    """

    assert isinstance(directory, Path) and directory.is_absolute(), "Observation owner is explicit"
    assert operation in ("capture", "analyze", "replay"), "Observation operation must remain fixed"
    directory.mkdir(parents=True, exist_ok=False)
    reservation = {"schema_version": 1, "operation": operation}

    with (directory / "attempt.json").open("x", encoding="ascii") as output:
        output.write(json.dumps(reservation, sort_keys=True, separators=(",", ":")))


def Observation(directory: Path, operation: str, value: dict) -> None:
    """Retain actual safe observations even when an SDK operation raises unexpectedly.

    Args:
        directory: Original fresh reserved attempt owner, separate from product workspace.
        operation: Fixed consumer operation name.
        value: Actual detached SDK result and original executor facts, never expected output.
    """

    assert isinstance(directory, Path) and directory.is_absolute(), "Observation owner is explicit"
    assert operation in ("capture", "analyze", "replay"), "Observation operation must remain fixed"
    assert json.loads((directory / "attempt.json").read_bytes()) == {
        "schema_version": 1, "operation": operation}, "Original reservation must match operation"
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")
    assert len(raw) <= MAX_OBSERVATION_BYTES, "Original SDK observation exceeds its retention bound"

    with (directory / (operation + ".json")).open("xb") as output:
        output.write(raw)


def Selection(config: dict, fields: set[str]) -> Path:
    """Require the entire explicit consumer selection without hidden defaults or workspace reads.

    Args:
        config: Explicit caller-selected operation inputs.
        fields: Entire fixed member set for that one operation.

    Returns:
        Selected absolute workspace; existence and ownership remain actual SDK decisions.
    """

    assert type(config) is dict and set(config) == fields, "Consumer selection must remain closed"
    assert all(type(config[key]) is str and config[key] for key in fields if key not in (
        "approve_safe_content_response_capture", "retain_response", "approve_passive_header_check",
        "expected_model_revision", "expected_workspace_revision")), "Explicit text is required"
    root = Path(config["workspace"])
    assert root.is_absolute(), "Consumer workspace selection must be absolute"

    if "policy" in fields:
        assert Path(config["policy"]).is_absolute(), "Current policy must be explicitly selected"

    for key in ("approve_safe_content_response_capture", "retain_response",
        "approve_passive_header_check"):
        if key in fields:
            assert type(config[key]) is bool, "Approval and retention values require exact bool"

    for key in ("expected_model_revision", "expected_workspace_revision"):
        if key in fields:
            assert type(config[key]) is int and config[key] >= 0, "CAS bases require exact integers"

    return root


def OriginalExecution(request, result) -> dict:
    """Detach original executor bytes/events after their owner consumed the unchanged result.

    Args:
        request: Original governed local request object.
        result: Original LocalExecutionResult; never replaced or reconstructed.

    Returns:
        Exact detached original invocation, execution, stream and event values.
    """

    from fuzzy1337.adapters import SerializeContract

    return {"request": json.loads(SerializeContract(request)),
        "execution": json.loads(SerializeContract(result.execution)),
        "termination": result.termination.value, "stdout_hex": result.stdout.hex(),
        "stderr_hex": result.stderr.hex(), "events": [{"sequence": item.sequence,
            "kind": item.kind.value, "data_hex": item.data.hex(), "termination": (
                None if item.termination is None else item.termination.value)}
            for item in result.events]}


async def Capture(config: dict, observations: Path, *, enabled: bool = False,
    current_owner_provider=None) -> dict:
    """Delegate one SAFE-plus-retention acquisition, retaining truthful failure observations.

    Args:
        config: Closed explicit workspace/scope/URL/actor/policy and separate boolean selections.
        observations: Fresh independent attempt directory; reuse refuses before SDK effects.
        enabled: Exact independent execution opt-in; default denial performs no SDK work.
        current_owner_provider: Optional actually trusted actor reader passed unchanged to SDK.

    Returns:
        Actual SDK summary; failed/partial/refused states never trigger interpretation.
    """

    if enabled is not True:
        raise PermissionError("Installed SDK capture needs explicit execution opt-in")

    root = Selection(config, {"workspace", "scope_id", "url", "owner_reference", "policy",
        "approve_safe_content_response_capture", "retain_response"})
    ReserveObservation(observations, "capture")
    from fuzzy1337.executors import LocalExecutor
    from fuzzy1337.model import LocalModelStore
    from fuzzy1337.nucleiscan import ReadNucleiPolicy
    from fuzzy1337.owned_response_workflow import RunOwnedContentResponseCapture
    from fuzzy1337.workspace import LocalWorkspaceStore

    original_execute = LocalExecutor.Execute
    original_model_save, original_workspace_save = LocalModelStore.Save, LocalWorkspaceStore.Save
    originals = []
    saves = []
    document = None
    exception_type = None

    async def Observe(executor, request, **options):
        """Return the same original result, without inspecting or changing its control flow."""

        result = await original_execute(executor, request, **options)
        originals.append((request, result))

        return result

    def Save(owner, original, store, state, expected_revision, options):
        """Retain actual call/return objects without changing the original store operation."""

        record = {"owner": owner, "expected_revision": expected_revision, "proposal": state,
            "returned": None, "exception_type": None}
        saves.append(record)

        try:
            result = original(store, state, **options)
            record["returned"] = result

            return result

        except BaseException as error:
            record["exception_type"] = type(error).__name__

            raise

    def ModelSave(store, state, *, expected_revision):
        """Observe the original explicit model CAS keyword without substituting a proposal."""

        return Save("model", original_model_save, store, state, expected_revision,
            {"expected_revision": expected_revision})

    def WorkspaceSave(store, state):
        """Observe the original workspace proposal revision; its owner increments on commit."""

        return Save("workspace", original_workspace_save, store, state, state.revision, {})

    LocalExecutor.Execute = Observe
    LocalModelStore.Save, LocalWorkspaceStore.Save = ModelSave, WorkspaceSave

    try:
        summary = await RunOwnedContentResponseCapture(root, config["scope_id"], config["url"],
            config["owner_reference"], lambda: ReadNucleiPolicy(Path(config["policy"])),
            approve_safe_content_response_capture=config["approve_safe_content_response_capture"],
            retain_response=config["retain_response"],
            current_owner_provider=current_owner_provider)
        document = summary.ToDict()

        return document

    except BaseException as error:
        exception_type = type(error).__name__

        raise

    finally:
        LocalExecutor.Execute = original_execute
        LocalModelStore.Save = original_model_save
        LocalWorkspaceStore.Save = original_workspace_save
        detached = [{**row, "proposal": row["proposal"].ToDict(), "returned": (
            None if row["returned"] is None else row["returned"].ToDict())} for row in saves]
        Observation(observations, "capture", {"summary": document, "exception_type": exception_type,
            "executions": [OriginalExecution(request, result) for request, result in originals],
            "store_saves": detached})


def Analyze(config: dict, observations: Path, *, enabled: bool = False,
    current_owner_provider=None) -> dict:
    """Select content-family v2 interpretation with separate PASSIVE approval and explicit CAS.

    Args:
        config: Explicit source receipt/URL, current scope/actor/policy, analysis and CAS inputs.
        observations: Fresh independent attempt directory, never a previous operation owner.
        enabled: Separate execution opt-in, never inherited from acquisition.
        current_owner_provider: Optional trusted actor reader passed unchanged.

    Returns:
        Actual completed/denied/failed/partial SDK result, without any fabricated persistence ACK.
    """

    if enabled is not True:
        raise PermissionError("Installed SDK analysis needs independent execution opt-in")

    root = Selection(config, {"workspace", "scope_id", "url", "owner_reference", "policy",
        "original_receipt_id", "analysis_reference", "expected_model_revision",
        "expected_workspace_revision", "approve_passive_header_check"})
    ReserveObservation(observations, "analyze")
    from fuzzy1337.native_response_header_workflow import ApplyOwnedResponseHeaderCheck
    from fuzzy1337.nucleiscan import ReadNucleiPolicy
    from fuzzy1337.scope import Target, TargetKind

    target = Target(TargetKind.URL, config["url"])
    assert target.value == config["url"], "Analysis cannot normalize a selected original source URL"
    document = None
    exception_type = None

    try:
        summary = ApplyOwnedResponseHeaderCheck(root, config["scope_id"],
            config["original_receipt_id"], target, config["owner_reference"],
            lambda: ReadNucleiPolicy(Path(config["policy"])),
            analysis_reference=config["analysis_reference"],
            expected_model_revision=config["expected_model_revision"],
            expected_workspace_revision=config["expected_workspace_revision"],
            approve_passive_header_check=config["approve_passive_header_check"],
            current_owner_provider=current_owner_provider, source_profile=CONTENT_PROFILE)
        document = summary.ToDict()
        assert document["profile"] == "owned-response-header-absence.v2" and document[
            "source_profile"] == CONTENT_PROFILE, "Actual analysis must retain explicit content v2"

        return document

    except BaseException as error:
        exception_type = type(error).__name__

        raise

    finally:
        Observation(observations, "analyze", {"summary": document,
            "exception_type": exception_type})


def Replay(config: dict, observations: Path, *, enabled: bool = False) -> dict:
    """Dispatch only the explicitly selected content source or historical header-v2 replay.

    Args:
        config: Explicit workspace, kind (source/header) and original immutable reference.
        observations: Fresh attempt directory, including for source versus header replay.
        enabled: Separate explicit replay opt-in; no current policy or source runtime input.

    Returns:
        Actual historical SDK summary; no repair, reacquisition or family fallback is attempted.
    """

    if enabled is not True:
        raise PermissionError("Installed SDK replay needs explicit operation opt-in")

    root = Selection(config, {"workspace", "kind", "reference"})
    assert config["kind"] in ("source", "header"), "Replay family must be explicitly selected"
    ReserveObservation(observations, "replay")
    from fuzzy1337.native_response_header_workflow import ReplayOwnedResponseHeaderCheck
    from fuzzy1337.owned_response_workflow import ReplayOwnedContentResponse

    document = None
    exception_type = None

    try:
        summary = (ReplayOwnedContentResponse(root, config["reference"]) if config["kind"] == (
            "source") else ReplayOwnedResponseHeaderCheck(root, config["reference"]))
        document = summary.ToDict()

        if config["kind"] == "header":
            assert document["profile"] == "owned-response-header-absence.v2" and document[
                "source_profile"] == CONTENT_PROFILE, "Historical replay must retain content v2"

        return document

    except BaseException as error:
        exception_type = type(error).__name__

        raise

    finally:
        Observation(observations, "replay", {"summary": document, "exception_type": exception_type})
