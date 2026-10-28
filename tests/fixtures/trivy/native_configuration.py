# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Test-only fixed native config process custody, without product configuration authority."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ImpactLevel, SerializeContract
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    ExecutionResources,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutionResult,
    LocalExecutor,
)

PROVIDER_VERSION = "0.75.0"
CONFIG_TIMEOUT_SECONDS = 30
VERSION_TIMEOUT_SECONDS = 10
MAX_CONFIG_STDOUT_BYTES = 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_VERSION_STDOUT_BYTES = 16 * 1024


def OriginalArguments(
    executable: Path, cache: Path, inputs: Path, scanner: str, operation: str,
) -> tuple[str, ...]:
    """Build only VERSION or the fixed embedded Dockerfile/Kubernetes compatibility argv.

    The caller owns a pinned executable and freshly staged closed owned specimen.
    This test helper grants no product capability and accepts no extra flags.
    """

    if scanner not in {"dockerfile", "kubernetes"} or operation not in {"version", "config"}:
        raise ValueError("unsupported closed native configuration compatibility selection")

    if any(not isinstance(path, Path) or not path.is_absolute()
           for path in (executable, cache, inputs)):
        raise ValueError("native compatibility selections must be explicit absolute paths")

    prefix = (str(executable), "--cache-dir", str(cache), "--config=")

    if operation == "version":
        return (*prefix, "--version", "--format", "json")

    return (*prefix, "--debug", "config", "--cache-backend", "memory",
        "--misconfig-scanners", scanner, "--include-non-failures", "--format", "json",
        "--exit-code", "0", "--ignorefile=", "--skip-check-update", "--skip-version-check",
        "--disable-telemetry", "--timeout", str(CONFIG_TIMEOUT_SECONDS) + "s", str(inputs))


def FreshEnvironment(root: Path) -> dict[str, str]:
    """Create separate empty owned process roots, refusing reuse or nonabsolute selections."""

    if not isinstance(root, Path) or not root.is_absolute():
        raise ValueError("native compatibility environment root must be absolute")

    root.mkdir(mode=0o700)
    paths = {}

    for name in ("home", "config", "cache", "tmp", "cwd"):
        path = root / name
        path.mkdir(mode=0o700)
        paths[name] = str(path)

    return {"HOME": paths["home"], "XDG_CONFIG_HOME": paths["config"],
        "XDG_CACHE_HOME": paths["cache"], "TMPDIR": paths["tmp"],
        "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


async def CaptureOriginal(
    root: Path, executable: Path, cache: Path, inputs: Path, scanner: str, operation: str,
    environment_root: Path, evidence: Path,
) -> LocalExecutionResult:
    """Retain actual bounded streams and cleanup truth under a test-only caller decision.

    This deliberately uses no image grant or native configuration product authority.
    The existing Linux descendant owner controls this one fixed test process. Available
    original events survive exceptional failure; no missing result is labeled successful.
    """

    arguments = OriginalArguments(executable, cache, inputs, scanner, operation)
    environment = FreshEnvironment(environment_root)
    cwd = environment_root / "cwd"
    workspace = cwd.relative_to(root).as_posix()
    request = AdapterRequest("compatibility.configuration", "test:owned-native-config-specimen",
                             ImpactLevel.SAFE, {"operation": operation, "scanner": scanner})
    invocation = AdapterInvocation("compatibility.trivy-config", request, arguments,
        VERSION_TIMEOUT_SECONDS if operation == "version" else CONFIG_TIMEOUT_SECONDS,
        None if operation == "version" else PROVIDER_VERSION)
    authorization = ExecutionAuthorization("test-only:closed-native-config-compatibility",
        "test-only:owned-fixtures", "test-only:compatibility-not-product-permission",
        InvocationDigest(invocation))
    original_request = LocalExecutionRequest(invocation,
        CapabilityDescriptor(request.capability, invocation.adapter_id, ImpactLevel.SAFE),
        authorization, workspace=workspace, environment=environment,
        resources=ExecutionResources(max_stdout_bytes=(MAX_VERSION_STDOUT_BYTES
            if operation == "version" else MAX_CONFIG_STDOUT_BYTES),
            max_stderr_bytes=MAX_STDERR_BYTES, terminate_grace_seconds=1.0))
    evidence.mkdir(parents=True, exist_ok=True)
    events = []
    result = None
    failure = None

    try:
        result = await LocalExecutor(root).Execute(original_request, on_event=events.append,
                                                   own_descendants=True)

        return result

    except BaseException as error:
        failure = type(error).__name__
        raise

    finally:
        stdout = result.stdout if result is not None else b"".join(
            event.data for event in events if event.kind.value == "stdout")
        stderr = result.stderr if result is not None else b"".join(
            event.data for event in events if event.kind.value == "stderr")
        (evidence / (operation + ".stdout")).write_bytes(stdout)
        (evidence / (operation + ".stderr")).write_bytes(stderr)
        receipt = {"schema_version": 1, "classification": "test-only-native-compatibility",
            "product_authorization": False, "request": json.loads(SerializeContract(
                original_request)), "original_failure": failure,
            "execution": json.loads(SerializeContract(result.execution))
                if result is not None else None,
            "termination": result.termination.value if result is not None else None,
            "streams": {name: {"size_bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()}
                for name, raw in (("stdout", stdout), ("stderr", stderr))},
            "events": [{"sequence": event.sequence, "kind": event.kind.value,
                "size_bytes": len(event.data), "sha256": hashlib.sha256(event.data).hexdigest(),
                "termination": event.termination.value if event.termination else None}
                for event in events]}
        (evidence / (operation + ".receipt.json")).write_text(
            json.dumps(receipt, sort_keys=True, indent=2, allow_nan=False) + "\n",
            encoding="utf-8")
