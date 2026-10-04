# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise real localhost micro-target responses through oracle report consumers."""

from __future__ import annotations

import importlib.util
import json
import threading
import time
from collections.abc import Iterator
from dataclasses import replace
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

from fuzzy1337.functional_metrics import (
    BuildReport,
    RenderHtml,
    RenderMarkdown,
    RunStatus,
    ScoreRun,
    SerializeReport,
)
from tests.functional.scenarios import WEB_MICRO_TARGET_CONTRACT
from tests.functional.web_micro_metrics import WEB_MICRO_ORACLE, NormalizeWebMicroRun


@pytest.fixture
def micro_target_url() -> Iterator[str]:
    """Own an ephemeral localhost instance of the actual repository HTTP target."""

    source = Path(__file__).resolve().parents[2] / "labs/targets/web-micro/server.py"
    spec = importlib.util.spec_from_file_location("metrics_micro_target", source)
    assert spec is not None and spec.loader is not None, "The first-party handler must be loadable."
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    with ThreadingHTTPServer(("127.0.0.1", 0), module.MicroTargetRequestHandler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            yield f"http://127.0.0.1:{server.server_port}"

        finally:
            server.shutdown()
            thread.join(timeout=2)
            assert not thread.is_alive(), "The fixture must join its owned HTTP target thread."


def test_ActualMicroTargetProducerFeedsMetricsAndAllGeneratedViews(micro_target_url, tmp_path):
    """Prove the actual producer, metadata mapper, scorer, and machine/human report path."""

    started = time.monotonic()
    observations = {}

    for marker in ("command-execution", "file-inclusion", "ssrf", "upload"):
        with urlopen(f"{micro_target_url}/canary/{marker}", timeout=2) as response:
            observations[f"canary.{marker}"] = {
                "status": response.status, "body": json.load(response)
            }

    with pytest.raises(HTTPError) as missing:
        urlopen(f"{micro_target_url}/missing", timeout=2)

    with missing.value as response:
        observations["unknown-route"] = {"status": response.code, "body": json.load(response)}

    stdout = json.dumps(observations, sort_keys=True)
    run = NormalizeWebMicroRun(
        stdout, "", ("localhost-contract-probe",), 0, time.monotonic() - started,
    )
    report = BuildReport((WEB_MICRO_ORACLE,), (run,))
    (tmp_path / "report.json").write_text(SerializeReport(report), encoding="utf-8")
    (tmp_path / "matrix.md").write_text(RenderMarkdown(report), encoding="utf-8")
    (tmp_path / "matrix.html").write_text(RenderHtml(report), encoding="utf-8")
    payload = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    metrics = payload["runs"][0]["metrics"]

    assert tuple(item.identifier for item in WEB_MICRO_ORACLE.checks[:-1]) == (
        WEB_MICRO_TARGET_CONTRACT.expected_findings
    ), "Report truth must reuse existing scenario metadata rather than duplicate findings."
    assert (metrics["tp"], metrics["fp"], metrics["fn"], metrics["tn"]) == (4, 0, 0, 1), (
        "Actual positive markers and the missing-route control must satisfy the finite oracle."
    )
    assert metrics["evidence_completeness"] == 1, "Every probe evidence role must be retained."
    assert payload["runs"][0]["run"]["evidence"][0]["content"] == stdout, (
        "The exact producer stdout must survive report generation and JSON consumption."
    )
    assert len(payload["matrix"]["rows"]) == 5, (
        "The matrix must cover all declared check capabilities."
    )
    assert "web-micro@1" in (tmp_path / "matrix.md").read_text(), (
        "Human views must retain actual target pack/version provenance."
    )
    assert "<table>" in (tmp_path / "matrix.html").read_text(), (
        "HTML output must be consumable without an external renderer."
    )


def test_MicroTargetRegressionRecordsMissesFalseAlarmsAndFailureTruth():
    """Exercise missing markers, invented routes, partial runs, and qualitative scoring."""

    observations = {
        "canary.upload": {"status": 200, "body": {"simulation": "wrong-marker"}},
        "unknown-route": {"status": 200, "body": {}},
    }
    run = NormalizeWebMicroRun(json.dumps(observations), "", ("probe",), 0, 0)
    metrics = ScoreRun(WEB_MICRO_ORACLE, run)

    assert (metrics["tp"], metrics["fp"], metrics["fn"], metrics["tn"]) == (0, 1, 4, 0), (
        "Missing canary markers and an invented success route must become FN and FP."
    )
    assert ScoreRun(replace(WEB_MICRO_ORACLE, complete=False), run)["accuracy"] is None, (
        "The same observations cannot claim accuracy without a complete oracle."
    )

    for returncode, timed_out, status in (
        (1, False, RunStatus.CRASHED), (124, True, RunStatus.TIMED_OUT)
    ):
        failed = NormalizeWebMicroRun(
            "partial invalid JSON", "error", ("probe",), returncode, 1, timed_out
        )

        assert failed.status is status, "A failed probe must preserve its actual terminal state."
        assert ScoreRun(WEB_MICRO_ORACLE, failed)["tn"] is None, (
            "A failed probe must not turn unexamined negatives into success."
        )
