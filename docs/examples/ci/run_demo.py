# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Run the installed local-demo entry path and retain independently checked CI evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def Read(path: Path) -> dict:
    """Read one retained JSON object; malformed outcomes fail the CI recipe."""

    value = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path.name}")

    return value


def Write(path: Path, value: dict) -> None:
    """Publish one new diagnostic without replacing earlier run evidence."""

    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def Run(parent: Path, name: str, arguments: list[str], expected: int) -> dict:
    """Execute the isolated installed CLI, retaining streams and actual process status."""

    completed = subprocess.run(
        [sys.executable, "-I", "-m", "fuzzy1337", *arguments],
        capture_output=True, text=True, timeout=90, check=False,
    )
    Write(parent / f"{name}-process.json", {
        "schema_version": 1, "arguments": arguments,
        "exit_status": completed.returncode,
        "stdout": completed.stdout, "stderr": completed.stderr,
    })
    outcome = json.loads(completed.stdout)

    if not isinstance(outcome, dict) or outcome.get("schema_version") != 1:
        raise ValueError(f"{name}: expected one schema-version-one outcome")

    Write(parent / f"{name}.json", outcome)

    if completed.returncode != expected:
        raise ValueError(f"{name}: expected exit {expected}, got {completed.returncode}")

    return outcome



def Inspect(parent: Path, name: str, arguments: list[str]) -> str:
    """Retain installed CLI version/diagnostics as text without inventing a JSON interface."""

    completed = subprocess.run(
        [sys.executable, "-I", "-m", "fuzzy1337", *arguments],
        capture_output=True, text=True, timeout=30, check=False,
    )
    Write(parent / f"{name}-process.json", {
        "schema_version": 1, "arguments": arguments,
        "exit_status": completed.returncode,
        "stdout": completed.stdout, "stderr": completed.stderr,
    })

    if completed.returncode != 0:
        raise ValueError(f"{name}: installed CLI inspection returned {completed.returncode}")

    return completed.stdout.strip()


def Digests(root: Path) -> dict[str, str]:
    """Capture retained file digests for the no-clobber comparison."""

    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


def Verify(parent: Path, outcome: dict, reopened: dict, exported: dict) -> dict:
    """Verify counts, original raw digests, stopped-target receipt and offline snapshot parity."""

    root = parent / "demo"
    expected = {"host": 1, "port": 1, "service": 1, "endpoint": 3, "finding": 0}

    if outcome.get("state") != "completed" or outcome.get("target_teardown_completed") is not True:
        raise ValueError("Demo did not complete with confirmed target teardown")

    if reopened.get("model_revision") != 3 or reopened.get("verified_evidence_records") != 3:
        raise ValueError("Independent reopen did not verify revision three and three acquisitions")

    if any(reopened.get("object_counts", {}).get(key) != count for key, count in expected.items()):
        raise ValueError("Reopened discovery object counts differ from the bounded recipe")

    index = Read(root / "evidence-index.json")

    if index.get("verified_acquisitions") != 3 or len(index.get("records", [])) != 3:
        raise ValueError("Evidence index does not retain three verified acquisitions")

    for item in index["records"]:
        material = (root / item["material_path"]).resolve()

        if not material.is_relative_to(root.resolve()):
            raise ValueError("Indexed evidence path escapes the retained demo")

        raw = material.read_bytes()
        reference = item["record"]["reference"]

        if (len(raw) != reference["size_bytes"]
                or hashlib.sha256(raw).hexdigest() != reference["sha256"]):
            raise ValueError("Original evidence bytes do not match the retained index")

    target = Read(root / "target.json")

    if target.get("teardown_completed") is not True or [
        (request["path"], request["status"]) for request in target["requests"]
    ] != [("/", 200), ("/health", 204), ("/redirect", 302)]:
        raise ValueError("Target receipt differs from the exact approved request plan")

    if not exported.get("output_published") or exported.get("model_revision") != 3:
        raise ValueError("Fresh offline export was not acknowledged")

    if (parent / "reopened-model.json").read_bytes() != (root / "reports/model.json").read_bytes():
        raise ValueError("Offline export differs from the demo's saved JSON snapshot")

    if Read(parent / "reopened-model.json").get("scan_completeness") != "not-assessed":
        raise ValueError("The report lost its explicit completeness limitation")

    return {"schema_version": 1, "state": "completed", "model_revision": 3,
            "verified_evidence_records": 3, "object_counts": expected,
            "snapshot_sha256": exported["snapshot_sha256"],
            "scan_completeness": "not-assessed", "target_teardown_completed": True}


def Main() -> int:
    """Require predeclared CI approval, execute one fresh bundle and retain actual failures."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="Existing empty physical artifact parent")
    args = parser.parse_args()
    parent = args.output.resolve(strict=True)

    if not parent.is_dir() or any(parent.iterdir()):
        parser.error("output must be an existing empty directory")

    root = parent / "demo"

    try:
        version = Inspect(parent, "version", ["--version"])
        Inspect(parent, "doctor", ["doctor"])
        Write(parent / "runtime.json", {
            "schema_version": 1, "package_version": version,
            "python_version": sys.version, "python_executable": sys.executable,
        })
        plan = Run(parent, "plan", ["demo", "local", str(root), "--json"], 3)

        if plan.get("failure") != "approval_required" or root.exists():
            raise ValueError("Missing approval did not refuse before target/root creation")

        if os.environ.get("F1337_APPROVED_LOCAL_DEMO") != "1":
            Write(parent / "ci-result.json", {
                "schema_version": 1, "state": "denied", "exit_status": 3,
                "failure": "predeclared_local_demo_approval_required",
            })
            return 3

        outcome = Run(parent, "approved", [
            "demo", "local", str(root), "--approve-safe-http", "--json"], 0)
        reopened = Run(parent, "reopen", [
            "workspace", "open", str(root / "workspace"), "--json"], 0)
        exported = Run(parent, "export", [
            "report", "export", str(root / "workspace"), "--format", "json",
            "--output", str(parent / "reopened-model.json"), "--json"], 0)
        result = Verify(parent, outcome, reopened, exported)
        before = Digests(root)
        refused = Run(parent, "no-clobber", [
            "demo", "local", str(root), "--approve-safe-http", "--json"], 2)

        if refused.get("phase") != "configuration" or Digests(root) != before:
            raise ValueError("Existing-root refusal changed retained material")

        result["exit_status"] = 0
        result["no_clobber_verified"] = True
        Write(parent / "ci-result.json", result)
        return 0
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        Write(parent / "ci-result.json", {
            "schema_version": 1, "state": "failed", "exit_status": 4,
            "failure": type(error).__name__, "detail": str(error),
        })
        return 4


if __name__ == "__main__":
    raise SystemExit(Main())
