# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit one-GET diagnostic on a fresh pinned target, separate from scanner evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from .external_native_runner import StrictJson

pytestmark = pytest.mark.serial
MAX_BODY_BYTES = 262144


def CaptureDiagnostic(lab, directory: Path) -> dict:
    """Preserve this new bounded response as raw bytes without attributing it to a prior scan."""

    script = lab.repository_root / "tests/functional/external_metrics_probe.js"
    directory.mkdir(parents=True, exist_ok=True)
    result = lab.Compose("exec", "-T", lab.target.Service, "/nodejs/bin/node", "-e",
                         script.read_text(), timeout_seconds=3)
    (directory / "probe-response.json").write_text(result.stdout)
    payload = StrictJson(result.stdout.encode("utf-8"))

    if not isinstance(payload, dict) or set(payload) != {
        "status", "headers", "body_base64", "body_bytes", "error",
    } or type(payload["body_bytes"]) is not int or (
        not 0 <= payload["body_bytes"] <= MAX_BODY_BYTES
        or type(payload["body_base64"]) is not str
        or len(payload["body_base64"]) > (MAX_BODY_BYTES + 2) // 3 * 4
    ):
        raise ValueError("Metrics diagnostic response violates its finite byte contract")

    body = base64.b64decode(payload["body_base64"], validate=True)

    if len(body) != payload["body_bytes"]:
        raise ValueError("Metrics diagnostic original body length disagrees")

    (directory / "response.body.bin").write_bytes(body)
    receipt = {"purpose": "independent-fresh-target-metrics-diagnostic",
        "original_scan_response": False, "method": "GET",
        "url": "http://127.0.0.1:3000/metrics", "max_body_bytes": MAX_BODY_BYTES,
        "child_deadline_seconds": 2.25, "docker_exec_deadline_seconds": 3,
        "redirects": False, "retries": 0, "status": payload["status"],
        "headers": payload["headers"], "error": payload["error"],
        "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
        "driver_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
        "target_provenance": lab.provenance, "returncode": result.returncode,
        "timed_out": result.timed_out, "duration_seconds": result.duration_seconds}
    (directory / "diagnostic-receipt.json").write_text(json.dumps(receipt, indent=2))
    lab.RequireSuccess(result, "One independently attributed owned metrics diagnostic")

    return receipt


def test_OneFreshTargetMetricsDiagnostic(request):
    """Acquire only one new exact metrics response when the explicit diagnostic is enabled."""

    selection = os.environ.get("FUZZY1337_EXTERNAL_METRICS_DIAGNOSTIC")

    if selection in {None, ""}:
        pytest.skip("Separate metrics diagnostic is UNRUN without explicit selection")

    if selection != "juice-shop" or os.environ.get("FUZZY1337_EXTERNAL_TARGETS") != "juice-shop":
        pytest.fail("Metrics diagnostic requires the explicitly selected pinned Juice Shop pack")

    lab = request.getfixturevalue("external_target_lab")
    directory = lab.repository_root / "functional-evidence/external-native-benchmark/diagnostic"
    directory = directory / ("run-" + uuid4().hex[:12])
    receipt = CaptureDiagnostic(lab, directory)
    assert receipt["status"] == 200 and receipt["error"] == "", (
        "The independent diagnostic must complete its one authorized HTTP request."
    )
