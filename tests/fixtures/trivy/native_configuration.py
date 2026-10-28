# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Test-only fixed native config process custody, without product configuration authority."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ImpactLevel, SerializeContract
from fuzzy1337.adapters.trivy import ParseJson
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
OWNED_SPECIMENS = {
    "dockerfile.root-user": ("dockerfile/unsafe/Dockerfile", "Dockerfile", "dockerfile"),
    "dockerfile.non-root-user": ("dockerfile/safe/Dockerfile", "Dockerfile", "dockerfile"),
    "kubernetes.privileged-container": ("kubernetes/unsafe.yaml", "unsafe.yaml", "kubernetes"),
    "kubernetes.non-privileged-container": ("kubernetes/safe.yaml", "safe.yaml", "kubernetes"),
    "kubernetes.second-document": ("kubernetes/multi.yaml", "multi.yaml", "kubernetes"),
}


def RequireOwnedSpecimen(case: dict) -> None:
    """Refuse any catalog path/type expansion before reading or staging the owned specimen."""

    selected = OWNED_SPECIMENS.get(case.get("caseId"))
    inputs = case.get("inputs")

    if selected is None or type(inputs) is not list or len(inputs) != 1 or (
        type(inputs[0]) is not dict
    ) or (inputs[0].get("fixture"), inputs[0].get("logicalPath"), case.get("scanner")) != selected:
        raise ValueError("native compatibility accepts only the five original owned specimens")


def VerifyEmbeddedChecks(stderr: bytes) -> dict[str, int]:
    """Require positive original embedded loader diagnostics without disk/data/reader overrides."""

    text = stderr.decode("utf-8")
    blocked = ("Checks from disk are loaded", "Checks from readers are loaded",
               "Overriding filesystem for checks")

    if any(message in text for message in blocked):
        raise ValueError("native configuration used an unselected check/data source")

    counts = {}

    for kind in ("libraries", "checks"):
        matches = re.findall(r"Embedded " + kind + r" are loaded[^\n]*\bcount=([1-9][0-9]*)\b",
                             text)

        if not matches:
            raise ValueError("native embedded loader did not establish positive " + kind)

        counts[kind] = int(matches[-1])

    return counts


def VerifyNativeInterpretation(raw: bytes, case: dict) -> dict:
    """Check independent selected native rows and exact file processing, without total/clean claims.

    All native rows remain in raw evidence. Expected values come only from the separately
    authored source oracle; source locations are compared only where it establishes them.
    """

    payload = ParseJson(raw, max_bytes=MAX_CONFIG_STDOUT_BYTES)

    if type(payload.get("SchemaVersion")) is not int or payload["SchemaVersion"] != 2:
        raise ValueError("native config output requires the pinned schema-two envelope")

    results = payload.get("Results")

    if type(results) is not list or len(results) != len(case["inputs"]):
        raise ValueError("native config output omitted or expanded selected file processing")

    observed = {}

    for result in results:
        if type(result) is not dict or type(result.get("Target")) is not str:
            raise ValueError("native config result lacks its selected file identity")

        target = result["Target"]

        if target in observed:
            raise ValueError("native config output duplicated a selected file")

        observed[target] = result

    selected = {}

    for item in case["inputs"]:
        result = observed.get(item["logicalPath"])

        if result is None or result.get("Class") != "config" or result.get("Type") != (
            item["resultType"]
        ) or type(result.get("Misconfigurations")) is not list:
            raise ValueError("native config did not positively process the exact selected type")

        rows = result["Misconfigurations"]
        matched = []

        for expected in case["requiredChecks"]:
            candidates = [row for row in rows if type(row) is dict
                          and row.get("ID") == expected["id"]
                          and row.get("Status") == expected["status"]]

            if len(candidates) != 1:
                raise ValueError("native output lacks one independently expected check/status")

            candidate = candidates[0]

            if "severity" in expected and candidate.get("Severity") != expected["severity"]:
                raise ValueError("native check severity differs from its pinned source")

            for expected_name, native_name in (("nativeStartLine", "StartLine"),
                                                ("nativeEndLine", "EndLine")):
                if expected_name in expected:
                    cause = candidate.get("CauseMetadata")

                    if type(cause) is not dict or type(cause.get(native_name)) is not int or (
                        cause[native_name] != expected[expected_name]
                    ):
                        raise ValueError("native cause location differs from its original source")

            matched.append({"id": expected["id"], "status": expected["status"]})

        selected[item["logicalPath"]] = matched

    return {"selected_native_checks": selected, "native_product_acceptance": False,
            "scan_completeness": "not-assessed"}


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
    environment_before = {name: sorted(path.name for path in (environment_root / name).iterdir())
                          for name in ("home", "config", "cache", "tmp", "cwd")}
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
            "environment_before": environment_before,
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
