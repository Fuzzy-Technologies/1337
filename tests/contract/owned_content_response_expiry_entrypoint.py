# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Fixed isolated post-model-ACK clock fixture; no replacement SDK, store or acceptance verdict.

The controlled receiver clock advances only after the unchanged original Save observer records
an actual model return. It does not measure elapsed wall time or authenticate an operator.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

OLD_ENTRYPOINT = "owned_content_response_sdk_entrypoint.py"
OLD_ENTRYPOINT_SHA256 = "9f8bd64c8cd0cc3502ff20e5650eb1687bfa2b3296075bb7dee03a3a81076452"
OLD_GUARD = "owned_content_response_sdk_offline_guard.py"
OLD_GUARD_SHA256 = "578d17fc0a61af306b1ca4f650768a1023bac1df5853951cebe823c7fd4367ae"
OPERATION = "analyze-expiry-offline"
PROFILE = "owned-content-response-capture.v1"
MAX_BYTES = 16 * 1024 * 1024
MAX_READS = 512
FIELDS = {"workspace", "scope_id", "url", "owner_reference", "policy", "original_receipt_id",
    "analysis_reference", "expected_model_revision", "expected_workspace_revision",
    "approve_passive_header_check"}


class ModelAckClock:
    """Supply one exact thirty-second exclusive boundary after an original model return."""

    def __init__(self, issued: datetime, seconds: int, record: dict) -> None:
        """Bind a fresh observer and aware UTC anchor without a product or store call.

        Args:
            issued: Exact aware UTC receiver time selected for this controlled fixture.
            seconds: Exact integer 30, independently checked against the actual policy.
            record: Fresh unchanged OfflineGuard observation, initially without any Save.

        Raises:
            ValueError: The window, UTC anchor or original observer is not the fixed fresh fixture.
        """

        if type(issued) is not datetime or issued.utcoffset() != timedelta(0) or (
            type(seconds) is not int or seconds != 30 or record.get("saves") != []
            or record.get("audit_probe_seen") is not True
        ):
            raise ValueError("Expiry fixture requires UTC, exact 30 seconds and a fresh observer")

        self.issued, self.expires = issued, issued + timedelta(seconds=seconds)
        self.record, self.readings = record, []

    def __call__(self) -> datetime:
        """Read only original in-memory Save observations; never patch, sleep, read or write stores.

        Returns:
            The fixed initial time before ACK, or its exact exclusive expiry after real return.

        Raises:
            ValueError: The bounded trace or exact original model ACK/revision is unavailable.
        """

        if len(self.readings) >= MAX_READS:
            raise ValueError("Expiry fixture clock trace exceeds its fixed bound")

        rows = self.record["saves"]
        acknowledged = False
        revision = None

        if rows:
            if len(rows) != 1 or rows[0]["owner"] != "model" or (
                rows[0]["exception_type"] is not None or rows[0]["returned"] is None
                or rows[0]["returned"] != rows[0]["proposal"]
                or type(rows[0]["expected_revision"]) is not int
            ):
                raise ValueError("Clock trigger requires exactly one unchanged original model ACK")

            revision = rows[0]["returned"].revision

            if type(revision) is not int or revision != rows[0]["expected_revision"] + 1:
                raise ValueError("Clock trigger requires the actual returned model revision")

            acknowledged = True

        now = self.expires if acknowledged else self.issued
        self.readings.append({"value": now.isoformat(), "model_ack_observed": acknowledged,
            "returned_model_revision": revision})

        return now

    def Snapshot(self) -> dict:
        """Detach bounded fixture observations without claiming elapsed real time.

        Returns:
            The immutable window and actual callback readings used by the original SDK call.
        """

        return {"issued_at": self.issued.isoformat(), "expires_at": self.expires.isoformat(),
            "duration_seconds": 30, "trigger": "original-model-save-return",
            "elapsed_wall_clock_claimed": False, "readings": list(self.readings)}


def Selection(config: dict, observations: Path) -> Path:
    """Require explicit current bases and independent True approval before any SDK activity.

    Args:
        config: Entire fixed content-family analysis selection; no clock/dispatcher knobs.
        observations: Fresh absolute owner separate from the explicit product workspace.

    Returns:
        The original selected workspace boundary, without normalization of its URL or policy.

    Raises:
        ValueError: Inputs, independent approval or canonical owner separation are invalid.
    """

    if type(config) is not dict or set(config) != FIELDS or any(
        type(config[key]) is not str or not config[key] for key in FIELDS - {
            "expected_model_revision", "expected_workspace_revision",
            "approve_passive_header_check"}
    ) or config["approve_passive_header_check"] is not True or any(
        type(config[key]) is not int or config[key] < 0 for key in (
            "expected_model_revision", "expected_workspace_revision")
    ):
        raise ValueError("Expiry analysis requires exact independent inputs and True opt-in")

    root = Path(config["workspace"])
    policy = Path(config["policy"])

    if any(not path.is_absolute() or ".." in path.parts for path in (
        root, policy, observations)) or root.resolve().is_relative_to(observations.resolve()) or (
            observations.resolve().is_relative_to(root.resolve())):
        raise ValueError("Expiry observation and workspace owners must remain separate")

    return root


def ReadAuthority(root: Path, scope_id: str, policy_path: Path) -> tuple[dict, object]:
    """Read actual scope and typed policy; these reads create no approval or authority grant.

    Args:
        root: Explicit existing workspace selected by the caller.
        scope_id: Original registered source scope identifier.
        policy_path: Explicit independent analysis policy path.

    Returns:
        Actual scope document and original typed policy for the initial fixture prerequisite.
    """

    from fuzzy1337.nucleiscan import ReadNucleiPolicy
    from fuzzy1337.scope import LocalScopeStore

    return LocalScopeStore(root).Open(scope_id).ToDict(), ReadNucleiPolicy(policy_path)


def ReadPolicy(path: Path) -> tuple[object, dict]:
    """Read the original typed policy and its serialized document without changing either.

    Args:
        path: Fixed explicit selected current analysis policy file.

    Returns:
        Original typed policy and detached observed document for exact hash reconciliation.
    """

    from fuzzy1337.adapters import SerializeContract
    from fuzzy1337.nucleiscan import ReadNucleiPolicy

    policy = ReadNucleiPolicy(path)

    return policy, json.loads(SerializeContract(policy))


def Apply(config: dict, policy: Callable[[], object], owner: Callable[[], str],
    clock: Callable[[], datetime]) -> dict:
    """Call only the installed public content-family API with the supplied trusted readers.

    Args:
        config: Original explicit selection with separate approval and current revision bases.
        policy: Fresh original typed policy reader, not a synthetic grant.
        owner: Fixture trusted synchronous actor reader; no authentication is asserted.
        clock: Controlled aware receiver clock keyed to actual original model ACK observation.

    Returns:
        Actual SDK summary, without replacement persistence, retry or rollback.

    Raises:
        ValueError: Original URL spelling or public API preconfiguration is invalid.
    """

    from fuzzy1337.native_response_header_workflow import ApplyOwnedResponseHeaderCheck
    from fuzzy1337.scope import Target, TargetKind

    target = Target(TargetKind.URL, config["url"])

    if target.value != config["url"]:
        raise ValueError("Expiry analysis cannot normalize the selected original URL")

    return ApplyOwnedResponseHeaderCheck(Path(config["workspace"]), config["scope_id"],
        config["original_receipt_id"], target, config["owner_reference"], policy,
        analysis_reference=config["analysis_reference"],
        expected_model_revision=config["expected_model_revision"],
        expected_workspace_revision=config["expected_workspace_revision"],
        approve_passive_header_check=config["approve_passive_header_check"],
        current_owner_provider=owner, clock=clock, source_profile=PROFILE).ToDict()


def Analyze(config: dict, observations: Path, guard: Any, *, enabled: bool = False) -> dict:
    """Observe one installed analysis under unchanged tripwires and a source-owned clock fixture.

    Args:
        config: Closed original analysis selection, with current bases and independent approval.
        observations: Fresh absolute independent owner for original observations.
        guard: Exactly loaded pinned existing OfflineGuard, never caller-selected in Main.
        enabled: Separate exact operation opt-in; false refuses before reads or product imports.

    Returns:
        Actual summary and original detached observer/reader/clock facts; no acceptance verdict.

    Raises:
        PermissionError: The independent fixture execution opt-in is not exactly True.
        ValueError: Original policy/consent cannot admit the exact fixed thirty-second window.
        OSError: An original input or fresh observation cannot be read or retained.
    """

    if enabled is not True:
        raise PermissionError("Expiry analysis requires explicit fixture execution opt-in")

    root = Selection(config, observations)
    observations.mkdir(parents=True, exist_ok=False)
    summary, exception_type, record, clock = None, None, None, None
    owners, policies = [], []

    def Owner() -> str:
        """Observe only the explicitly selected trusted actor.

        Returns:
            The selected fixture actor, without an authentication assertion.
        """

        if len(owners) >= MAX_READS:
            raise ValueError("Expiry owner trace exceeds its fixed bound")

        owners.append(config["owner_reference"])

        return config["owner_reference"]

    def Policy() -> object:
        """Refresh the actual selected policy without replacement or derived approval.

        Returns:
            The unchanged original typed policy read from the selected file.
        """

        if len(policies) >= MAX_READS:
            raise ValueError("Expiry policy trace exceeds its fixed bound")

        actual, document = ReadPolicy(Path(config["policy"]))
        policies.append(document)

        return actual

    try:
        with guard.OfflineGuard(historical=False, enabled=True) as record:
            scope, policy = ReadAuthority(root, config["scope_id"], Path(config["policy"]))
            t0 = datetime.now(timezone.utc)
            consent = scope["authorization"]

            if type(policy.max_authorization_seconds) is not int or (
                policy.max_authorization_seconds != 30
                or datetime.fromisoformat(consent["valid_from"]) > t0
                or datetime.fromisoformat(consent["valid_until"]) <= t0 + timedelta(seconds=30)
            ):
                raise ValueError("Original scope and policy must admit the exact 30-second window")

            clock = ModelAckClock(t0, policy.max_authorization_seconds, record)
            summary = Apply(config, Policy, Owner, clock)

    except BaseException as error:
        exception_type = type(error).__name__

        raise

    finally:
        control = {"guard": None if record is None else guard.DetachedGuard(record),
            "clock": None if clock is None else clock.Snapshot(), "owner_values": owners,
            "policy_documents": policies}
        document = {"summary": summary, "exception_type": exception_type, "control": control}
        raw = json.dumps(document, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("ascii")

        if len(raw) > MAX_BYTES:
            raise ValueError("Original expiry observation exceeds its fixed retention bound")

        with (observations / "expiry-analysis.json").open("xb") as stream:
            stream.write(raw)

    return document


def LoadFixed() -> tuple[ModuleType, object, dict]:
    """Load only the exact accepted identity/input helper and its exact existing offline guard.

    Returns:
        Original fixed helper namespace, original guard and exact executed helper path/hash facts.

    Raises:
        ValueError: The accepted source hash or bounded fixed helper record differs.
        OSError: A fixed original helper cannot be read.
    """

    directory = Path(__file__).resolve().parent
    path = directory / OLD_ENTRYPOINT

    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)

    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != OLD_ENTRYPOINT_SHA256:
        raise ValueError("The accepted fixed entrypoint source must remain byte-identical")

    original = ModuleType("owned_content_expiry_original_entrypoint")
    original.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), original.__dict__)
    sources, guard_raw = original.GuardSource()

    if sources[OLD_GUARD]["sha256"] != OLD_GUARD_SHA256:
        raise ValueError("The accepted offline guard source must remain byte-identical")

    sources[OLD_ENTRYPOINT] = {"path": str(path), "sha256": OLD_ENTRYPOINT_SHA256}
    current = Path(__file__).resolve()
    sources[current.name] = {"path": str(current),
        "sha256": hashlib.sha256(original.BoundedRead(current, 1024 * 1024)).hexdigest()}

    return original, original.LoadGuard(guard_raw), sources


def Main(arguments: list[str] | None = None) -> int:
    """Dispatch only one explicit isolated expiry operation; no alternate helper or command.

    Args:
        arguments: Exactly the fixed operation, absolute input and separate --execute opt-in.

    Returns:
        Zero after retaining an original actual SDK result, without interpreting it as success.

    Raises:
        ValueError: The exact fixed operation, explicit paths or separate opt-in is missing.
    """

    args = sys.argv[1:] if arguments is None else arguments

    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or (
        len(args) != 3 or args[0] != OPERATION or args[2] != "--execute"
    ):
        raise ValueError("Expiry child requires the exact fixed -I -B opted-in operation")

    original, guard, sources = LoadFixed()
    config = original.ReadInput(Path(args[1]))
    identity = original.Identity()
    result = Analyze(config["selection"], Path(config["observations"]), guard, enabled=True)
    output = {"operation": OPERATION, "installed_identity": identity,
        "consumer_sources": sources, **result}
    raw = json.dumps(output, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")

    if len(raw) > MAX_BYTES:
        raise ValueError("Original expiry stdout exceeds its fixed bound")

    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
