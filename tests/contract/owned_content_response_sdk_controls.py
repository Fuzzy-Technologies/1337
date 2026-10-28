# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Fixed setup/inspection controls and separate typed policy fixtures, never grant or capture."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import ModuleType

SETUP_SOURCE = "owned_content_response_sdk_setup.py"
SEED_SOURCE = "owned_response_product_runner.py"
MAX_SOURCE_BYTES = 1024 * 1024
MAX_OBSERVATION_BYTES = 16 * 1024 * 1024


def Policies() -> dict:
    """Construct separate explicit typed policy fixtures without any grant or workflow approval.

    Returns:
        SAFE content-source permission and independent PASSIVE header permission, each with
        empty privileges. Neither supplies retain_response or either operation's approval.
    """

    from fuzzy1337.adapters import ImpactLevel
    from fuzzy1337.policy import CapabilityPermission, ImpactPolicy

    return {"acquisition": ImpactPolicy("owned-content-sdk-safe", maximum_impact=ImpactLevel.SAFE,
        permissions=(CapabilityPermission("http.owned-content-response-capture",
            "native.loopback-content-response", ImpactLevel.SAFE),), max_authorization_seconds=30),
        "analysis": ImpactPolicy("owned-content-sdk-passive", maximum_impact=ImpactLevel.PASSIVE,
            permissions=(CapabilityPermission("http.owned-response-header-check",
                "native.response-passive", ImpactLevel.PASSIVE),), max_authorization_seconds=30)}


def LoadFixed(name: str) -> tuple[ModuleType, dict]:
    """Execute only a fixed bounded local reviewed helper and report the same original bytes.

    Args:
        name: Setup or original seed filename from the closed source-owned list.

    Returns:
        Fixed helper namespace and exact observed path/hash for caller checkpoint reconciliation.
    """

    if name not in (SETUP_SOURCE, SEED_SOURCE):
        raise ValueError("Unsupported fixed SDK control source")

    path = Path(__file__).resolve().with_name(name)

    with path.open("rb") as stream:
        raw = stream.read(MAX_SOURCE_BYTES + 1)

    if len(raw) > MAX_SOURCE_BYTES:
        raise ValueError("Fixed SDK control source exceeds its byte bound")

    module = ModuleType("owned_content_fixed_control")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)

    return module, {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}


def Dispatch(operation: str, selection: dict, observations: Path, *, enabled: bool = False) -> dict:
    """Run exactly one fresh setup or read-only inspection with exclusive original observations.

    Args:
        operation: Setup, fresh-setup or inspect; no acquisition or general command dispatch.
        selection: Explicit approved setup selection, or only an absolute inspection workspace.
        observations: Fresh absolute operation directory, canonically separate from workspace.
        enabled: Exact independent operation opt-in; false performs no helper/store activity.

    Returns:
        Actual original setup/inspection values, helper binding and explicit typed policy paths
        for setup only. Partial failures retain observed values and are reraised without repair.
    """

    if enabled is not True:
        raise PermissionError("SDK controls require separate explicit operation opt-in")

    if operation not in ("setup", "fresh-setup", "inspect") or (
        not isinstance(observations, Path) or not observations.is_absolute()
    ):
        raise ValueError("Fixed SDK control operation and fresh observation owner are required")

    if type(selection) is not dict or type(selection.get("workspace")) is not str:
        raise ValueError("SDK controls require an explicitly selected absolute workspace")

    workspace = Path(selection["workspace"])

    if not workspace.is_absolute() or ".." in workspace.parts or ".." in observations.parts or (
        observations.is_relative_to(workspace) or workspace.is_relative_to(observations)
    ):
        raise ValueError("Observation owner and product workspace must be separate absolute paths")

    canonical_workspace = workspace.resolve()
    canonical_observations = observations.resolve()

    if canonical_observations.is_relative_to(canonical_workspace) or (
        canonical_workspace.is_relative_to(canonical_observations)
    ):
        raise ValueError("Observation and workspace aliases must remain canonically separate")

    if operation == "inspect" and (type(selection) is not dict or set(selection) != {"workspace"}
        or type(selection["workspace"]) is not str or not Path(selection["workspace"]).is_absolute()
    ):
        raise ValueError("Inspection selects only its explicit absolute existing workspace")

    observations.mkdir(parents=True, exist_ok=False)

    with (observations / "attempt.json").open("x", encoding="ascii") as output:
        output.write(json.dumps({"schema_version": 1, "operation": operation}, sort_keys=True))

    result = None
    exception_type = None

    try:
        if operation in ("setup", "fresh-setup"):
            helper, source = LoadFixed(SETUP_SOURCE)
            actual = (helper.Setup(selection, enabled=True) if operation == "setup" else
                helper.FreshSetup(selection, enabled=True))
            result = ({"original_setup": actual} if operation == "setup" else actual)
            result.update(helper_source=source, policies={})
            from fuzzy1337.adapters import SerializeContract

            policies = Policies()

            if operation == "fresh-setup":
                identity = actual["state"]["workspace"]["workspace_id"]
                policies = {role: replace(policy, policy_id=identity + "-" + role)
                    for role, policy in policies.items()}
                policies["analysis-denied"] = replace(policies["analysis"],
                    policy_id=identity + "-analysis-denied", permissions=())

            for role, policy in policies.items():
                raw = SerializeContract(policy).encode("ascii")
                path = observations / (role + "-policy.json")

                with path.open("xb") as output:
                    output.write(raw)

                result["policies"][role] = {"path": str(path), "sha256":
                    hashlib.sha256(raw).hexdigest()}

                if operation == "fresh-setup":
                    result["policies"][role]["document"] = json.loads(raw)

        else:
            helper, source = LoadFixed(SEED_SOURCE)
            actual = helper.Inspect(Path(selection["workspace"]))
            result = {"original_inspection": actual, "helper_source": source}

        return result

    except BaseException as error:
        exception_type = type(error).__name__

        raise

    finally:
        raw = json.dumps({"result": result, "exception_type": exception_type}, sort_keys=True,
            separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")

        if len(raw) > MAX_OBSERVATION_BYTES:
            raise ValueError("Original SDK control observation exceeds its byte bound")

        with (observations / (operation + ".json")).open("xb") as output:
            output.write(raw)
