# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Run one installed native check and export bounded original bytes without host mounts."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import importlib
import importlib.metadata
import json
import math
import os
import re
import shutil
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

CHECK_ID = "native.prometheus-exposition"
CAPABILITY = "web.prometheus-exposition-check"
PATHS = ("/metrics", "/rest/admin/application-version", "/")
MAX_FILES = 128
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_ENCODED_BYTES = 12 * 1024 * 1024
MEDIA_TYPES = {"application/json", "application/octet-stream", "application/zip", "text/plain"}
REQUEST_BASIS = "approved-worker-invocation-and-successful-record"
MODULES = ("adapters.prometheus_exposition", "adapters.native_web", "native_web_worker",
           "native_web", "scan_commands")


def StrictJson(raw: bytes) -> object:
    """Reject ambiguous/nonfinite JSON at the standalone export boundary."""

    def Object(pairs):
        """Keep each source key unique at every nesting depth."""

        result = {}

        for key, value in pairs:
            if key in result:
                raise ValueError("Native bundle JSON repeats a key")

            result[key] = value

        return result

    def Constant(value):
        """Reject nonstandard numeric constants."""

        raise ValueError("Native bundle JSON contains a nonfinite constant")

    def Float(value):
        """Reject numeric overflow before it can enter retained acquisition metadata."""

        converted = float(value)

        if not math.isfinite(converted):
            raise ValueError("Native bundle JSON number is nonfinite")

        return converted

    return json.loads(raw.decode("utf-8"), object_pairs_hook=Object,
                      parse_constant=Constant, parse_float=Float)


def SafePath(value: str) -> PurePosixPath:
    """Accept only bounded ordinary relative artifact paths, never aliases or device paths."""

    if type(value) is not str or not value or len(value) > 512 or any(
        ord(character) < 32 or ord(character) == 127 or character in "\\:" for character in value
    ) or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("Native bundle requires safe relative paths")

    path = PurePosixPath(value)

    if path.is_absolute():
        raise ValueError("Native bundle cannot use absolute paths")

    return path


def ExportBundle(root: Path, outcome: dict) -> str:
    """Encode a finite owned workspace after execution; no host files enter this bundle."""

    files = []
    total = 0

    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Native bundle cannot export symbolic links")

        if path.is_dir():
            continue

        if not path.is_file():
            raise ValueError("Native bundle can export only regular files")

        relative = path.relative_to(root).as_posix()
        SafePath(relative)

        with path.open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)

        total += len(raw)

        if len(raw) > MAX_FILE_BYTES or total > MAX_BUNDLE_BYTES or len(files) >= MAX_FILES:
            raise ValueError("Native bundle exceeded its finite original-byte/file budget")

        media = "application/json" if path.suffix == ".json" else (
            "application/zip" if path.suffix == ".whl" else "application/octet-stream"
        )
        files.append({"path": relative, "media_type": media, "size_bytes": len(raw),
                      "sha256": hashlib.sha256(raw).hexdigest(),
                      "data_base64": base64.b64encode(raw).decode("ascii")})

    return json.dumps({"schema_version": 1, "outcome": outcome, "files": files},
                      sort_keys=True, allow_nan=False)


def ImportBundle(raw: bytes, output: Path) -> dict:
    """Validate the complete finite bundle before writing any original artifact bytes."""

    if len(raw) > MAX_ENCODED_BYTES:
        raise ValueError("Native bundle exceeded its encoded byte budget")

    bundle = StrictJson(raw)

    if not isinstance(bundle, dict) or set(bundle) != {"schema_version", "outcome", "files"} or (
        type(bundle["schema_version"]) is not int or bundle["schema_version"] != 1
        or not isinstance(bundle["outcome"], dict) or not isinstance(bundle["files"], list)
        or not 1 <= len(bundle["files"]) <= MAX_FILES
    ):
        raise ValueError("Native bundle shape or file count is invalid")

    decoded = {}
    total = 0

    for record in bundle["files"]:
        if not isinstance(record, dict) or set(record) != {
            "path", "media_type", "size_bytes", "sha256", "data_base64",
        }:
            raise ValueError("Native bundle file metadata is invalid")

        relative = SafePath(record["path"])

        if relative in decoded or type(record["media_type"]) is not str or (
            record["media_type"] not in MEDIA_TYPES
        ) or (
            type(record["size_bytes"]) is not int or not 0 <= record["size_bytes"] <= MAX_FILE_BYTES
            or type(record["sha256"]) is not str
            or re.fullmatch("[a-f0-9]{64}", record["sha256"]) is None
            or type(record["data_base64"]) is not str
            or len(record["data_base64"]) > (MAX_FILE_BYTES + 2) // 3 * 4
        ):
            raise ValueError("Native bundle file identity, media type, or size is invalid")

        data = base64.b64decode(record["data_base64"], validate=True)
        total += len(data)

        if total > MAX_BUNDLE_BYTES or len(data) != record["size_bytes"] or (
            hashlib.sha256(data).hexdigest() != record["sha256"]
        ):
            raise ValueError("Native bundle bytes differ from their declared bounded identity")

        decoded[relative] = data

    for relative in decoded:
        if any(parent in decoded for parent in relative.parents):
            raise ValueError("Native bundle files cannot alias directory parents")

    for relative, data in decoded.items():
        destination = output.joinpath(*relative.parts)

        for component in (output, *destination.relative_to(output).parents):
            candidate = component if component.is_absolute() else output / component

            if candidate.is_symlink():
                raise ValueError("Native bundle destination cannot traverse symbolic links")

        if destination.exists() or destination.is_symlink():
            raise ValueError("Native bundle cannot overwrite existing files")

        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)

    return bundle


def WriteJson(path: Path, value: object) -> None:
    """Retain deterministic standards-compliant acquisition metadata."""

    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def Provision() -> None:
    """Prove clean installed-wheel imports and freeze image-local source/binary identities."""

    import fuzzy1337
    from fuzzy1337.adapters.native_web import NativeWebCheckFor

    package = Path(fuzzy1337.__file__).parent
    revision = os.environ.get("BENCHMARK_SOURCE_REVISION", "")
    check = NativeWebCheckFor(CHECK_ID)

    if not sys.flags.isolated or not str(package).startswith("/opt/benchmark-runtime/") or (
        "site-packages" not in package.parts or re.fullmatch("[a-f0-9]{40}", revision) is None
        or check.capability != CAPABILITY or type(check.max_body_bytes) is not int
        or not 4096 <= check.max_body_bytes <= 1048576
    ):
        raise ValueError("Native runner requires the pinned detector in a clean installed wheel")

    wheels = list(Path("/opt/benchmark-wheel").glob("*.whl"))

    if len(wheels) != 1:
        raise ValueError("Native runner requires exactly one current-source wheel")

    modules = {}

    for name in MODULES:
        module = importlib.import_module("fuzzy1337." + name)
        path = Path(module.__file__)

        if not path.is_relative_to(package):
            raise ValueError("Native module escaped the installed package")

        modules[name] = hashlib.sha256(path.read_bytes()).hexdigest()

    wheel = wheels[0]
    WriteJson(Path("/opt/benchmark-provisioning.json"), {
        "source_revision": revision, "package_path": str(package),
        "distribution_version": importlib.metadata.version("1337"),
        "python_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "effective_body_bytes": check.max_body_bytes,
        "module_sha256": modules, "wheel": {"filename": wheel.name,
            "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "size_bytes": wheel.stat().st_size},
    })


def RunActual(root: Path, path: str) -> dict:
    """Exercise real installed product planning/execution and reopen its actual saved evidence."""

    from fuzzy1337.adapters import ImpactLevel, SerializeContract
    from fuzzy1337.evidence import LocalEvidenceStore
    from fuzzy1337.executors import InvocationDigest
    from fuzzy1337.findings import Findings
    from fuzzy1337.jobs import JobState
    from fuzzy1337.model import LocalModelStore
    from fuzzy1337.native_web import NativeWebScanLimits, PlanNativeWebScan, RunNativeWebScan
    from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, PolicyConfirmation
    from fuzzy1337.scan_commands import CreateWorkspace
    from fuzzy1337.scope import (
        AuthorizationState,
        LocalScopeStore,
        ScopeAuthorization,
        ScopeSnapshot,
        Target,
        TargetKind,
    )

    if path not in PATHS:
        raise ValueError("Native runner accepts only the three finite exact paths")

    root.mkdir(parents=True)
    shutil.copyfile("/opt/benchmark-provisioning.json", root / "provisioning.json")
    provisioning = StrictJson((root / "provisioning.json").read_bytes())
    wheel = Path("/opt/benchmark-wheel") / provisioning["wheel"]["filename"]
    shutil.copyfile(wheel, root / wheel.name)
    workspace = root / "workspace"
    CreateWorkspace(workspace, "external-native", "Owned pinned Juice Shop native comparison")
    target = Target(TargetKind.URL, "http://127.0.0.1:3000" + path)
    address = Target(TargetKind.IP, "127.0.0.1")
    now = datetime.now(UTC)
    owner = "operator:owned-external-native"
    LocalScopeStore(workspace).Create(ScopeSnapshot("local", "external-native", ScopeAuthorization(
        AuthorizationState.GRANTED, owner, "consent:owned-external-native",
        (now - timedelta(minutes=1)).isoformat(), (now + timedelta(minutes=5)).isoformat(),
    ), targets=(target, address), allow=(target, address)))

    def Policy():
        """Permit only the explicit native capability under exact-plan STANDARD confirmation."""

        return ImpactPolicy("owned-external-native", maximum_impact=ImpactLevel.STANDARD,
            permissions=(CapabilityPermission(
                CAPABILITY, "native.web-check", ImpactLevel.STANDARD),))

    limits = NativeWebScanLimits(request_timeout_seconds=3, timeout_seconds=10)
    plan = PlanNativeWebScan(workspace, "local", target, owner, Policy,
                            check_id=CHECK_ID, limits=limits)
    WriteJson(root / "plan.json", plan.ToDict())
    started = time.monotonic()
    summary = asyncio.run(RunNativeWebScan(workspace, "local", target, owner, Policy,
        check_id=CHECK_ID, limits=limits,
        confirmation=PolicyConfirmation(plan.policy_plan.intent_sha256,
                                        "approval:owned-external-native")))
    duration = time.monotonic() - started
    WriteJson(root / "summary.json", summary.ToDict())
    store = LocalEvidenceStore(workspace / "evidence")

    for artifact in summary.snapshot.artifacts:
        record = artifact.evidence

        if store.Get(record.evidence_id) != record or (
            record.provenance.invocation_sha256 != InvocationDigest(plan.invocation)
            or record.provenance.tool_version != plan.invocation.provider_version
        ):
            raise ValueError("Native worker acquisition identity differs from the actual plan")

        (root / ("worker-" + record.reference.role + ".json")).write_bytes(
            store.Read(record.reference))

    findings = Findings(LocalModelStore(workspace).Open())
    (root / "findings.raw.json").write_text(SerializeContract(findings))
    WriteJson(root / "findings.json", [{"rule_id": finding.check_id,
        "path": urlsplit(finding.location_key).path} for finding in findings])
    WriteJson(root / "invocation.json", {
        "argv": list(plan.invocation.argv), "scanner_id": plan.invocation.adapter_id,
        "scanner_version": plan.invocation.provider_version,
        "scanner_sha256": provisioning["python_sha256"],
        "rule_sha256": provisioning["module_sha256"]["adapters.prometheus_exposition"],
        "product_revision": provisioning["source_revision"],
        "effective_budget": {"request_timeout_seconds": limits.request_timeout_seconds,
            "operation_timeout_seconds": limits.timeout_seconds, "max_requests": 1,
            "max_response_bytes": provisioning["effective_body_bytes"], "rate_limit": 1},
    })
    return {"status": "completed" if summary.snapshot.state is JobState.COMPLETED else "crashed",
            "exit_code": summary.ExitCode(), "duration_seconds": duration,
            "target_url": target.value}


def Main(arguments: list[str] | None = None) -> int:
    """Provision the image or execute one finite accepted case and export original bytes."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provision", action="store_true")
    parser.add_argument("--path", choices=PATHS)
    options = parser.parse_args(arguments)

    if options.provision:
        Provision()

        return 0

    if options.path is None:
        parser.error("--path is required for native execution")

    root = Path("/tmp/native-benchmark")

    try:
        outcome = RunActual(root, options.path)

    except Exception as error:
        root.mkdir(parents=True, exist_ok=True)
        WriteJson(root / "failure.json", {"exception_type": type(error).__name__})
        outcome = {"status": "crashed", "exit_code": 4, "duration_seconds": None,
                   "target_url": "http://127.0.0.1:3000" + options.path}

    print(ExportBundle(root, outcome))

    return outcome["exit_code"]


if __name__ == "__main__":
    raise SystemExit(Main())
