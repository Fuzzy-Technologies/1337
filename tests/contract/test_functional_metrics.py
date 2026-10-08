# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Contract checks for oracle scoring, raw evidence, and shared report projections."""

from __future__ import annotations

import json
from dataclasses import replace
from html.parser import HTMLParser

import pytest

from fuzzy1337.functional_metrics import (
    FUNCTIONAL_REPORT_VERSION,
    BuildReport,
    FunctionalRun,
    OracleCheck,
    Ratio,
    RawEvidence,
    RenderHtml,
    RenderMarkdown,
    RunStatus,
    ScenarioOracle,
    ScoreRun,
    SerializeReport,
)


def Oracle() -> ScenarioOracle:
    """Declare finite positives, negatives, and an explicit non-applicable check."""

    return ScenarioOracle(
        identifier="synthetic.mixed",
        target_pack="synthetic",
        target_version="1",
        provenance="first-party:synthetic",
        complete=True,
        checks=(
            OracleCheck("positive.hit", "web.canary", True),
            OracleCheck("positive.miss", "web.canary", True),
            OracleCheck("negative.alarm", "web.negative", False),
            OracleCheck("negative.quiet", "web.negative", False),
            OracleCheck("unavailable.check", "web.unavailable", None, applicable=False),
        ),
    )


def Run() -> FunctionalRun:
    """Preserve duplicate raw observations while counting unique object identities."""

    return FunctionalRun(
        scenario_id="synthetic.mixed",
        scanner_id="contract.probe",
        release_id="0.1.8",
        status=RunStatus.COMPLETED,
        duration_seconds=0.125,
        detected_checks=("positive.hit", "positive.hit", "negative.alarm", "unknown.alarm"),
        discovered_objects=("route.root", "route.root", "route.canary"),
        evidence=(
            RawEvidence("stdout", "text/plain", "exact stdout\n\x00"),
            RawEvidence("stderr", "text/plain", ""),
            RawEvidence("invocation", "application/json", '["probe", "synthetic"]'),
        ),
    )


def test_FiniteOracleCountsAndRatiosPreserveUnexpectedAndDuplicateDetections():
    """Calculate every confusion outcome and explain unexpected closed-world findings."""

    metrics = ScoreRun(Oracle(), Run())

    assert (metrics["tp"], metrics["fp"], metrics["fn"], metrics["tn"]) == (1, 1, 1, 1), (
        "Confusion counts must score exactly the finite declared check population."
    )
    assert metrics["recall_tpr"] == 0.5, "Recall must use the declared positive population."
    assert metrics["false_positive_rate"] == 0.5, "FPR must equal FP / (FP + TN)."
    assert metrics["precision"] == 0.5, "Precision must use the fixed oracle population."
    assert metrics["accuracy"] == 0.5, "Accuracy must use the fixed oracle population."
    assert metrics["unexpected_detections"] == ["unknown.alarm"], (
        "Unexpected findings must remain individually explainable."
    )
    assert metrics["discovered_object_count"] == 2, "Duplicate discoveries must not inflate counts."
    assert metrics["detected_check_count"] == 3, "Duplicate findings must not inflate counts."
    assert metrics["duration_seconds"] == 0.125, "Measured duration must be preserved."
    assert metrics["evidence_completeness"] == 1, "Empty stderr is valid preserved evidence."

    expanded = replace(Run(), detected_checks=Run().detected_checks + ("another.alarm",))
    expanded_metrics = ScoreRun(Oracle(), expanded)

    assert expanded_metrics["unexpected_detection_count"] == 2, (
        "Additional outside-oracle detections must remain separately measurable."
    )
    assert all(expanded_metrics[key] == metrics[key] for key in (
        "tp", "fp", "fn", "tn", "recall_tpr", "false_positive_rate", "precision", "accuracy"
    )), "Outside-oracle observations must never change the finite denominator across releases."


@pytest.mark.parametrize("status", [RunStatus.CRASHED, RunStatus.TIMED_OUT])
def test_FailedRunsWithholdAccuracyAndPreservePartialEvidence(status):
    """Never turn an interrupted assessment into apparent true negatives or healthy accuracy."""

    run = replace(Run(), status=status, evidence=Run().evidence[:1])
    metrics = ScoreRun(Oracle(), run)
    report = BuildReport((Oracle(),), (run,))

    assert not metrics["accuracy_available"], "Incomplete runs cannot claim accuracy."
    assert metrics["accuracy_reason"] == "incomplete-run", "Failure cause must remain explicit."
    assert all(metrics[key] is None for key in ("tp", "fp", "fn", "tn", "recall_tpr")), (
        "An interrupted scanner must not be scored as a completed assessment."
    )
    assert metrics["crashes"] == int(status is RunStatus.CRASHED), "Crashes must remain measurable."
    assert metrics["timeouts"] == int(status is RunStatus.TIMED_OUT), (
        "Timeouts must remain measurable."
    )
    assert metrics["evidence_completeness"] == 1 / 3, (
        "Evidence completeness must use required roles."
    )
    assert metrics["missing_evidence"] == ["invocation", "stderr"], (
        "Missing evidence roles must remain individually explainable."
    )
    assert status.value in RenderMarkdown(report), (
        "Human views must preserve failed terminal state."
    )


def test_QualitativeTargetsAndEmptyPopulationsNeverFabricateAbsoluteAccuracy():
    """Represent incomplete truth and zero denominators with explicit nullable values."""

    qualitative = replace(
        Oracle(), complete=False, checks=(OracleCheck("positive.hit", "web.canary", None),)
    )
    qualitative_metrics = ScoreRun(qualitative, Run())
    empty = replace(Oracle(), checks=(), required_evidence=())
    empty_metrics = ScoreRun(empty, replace(Run(), detected_checks=(), discovered_objects=()))

    assert qualitative_metrics["tp"] is None, "Incomplete app oracles cannot supply TP counts."
    assert qualitative_metrics["accuracy_reason"] == "incomplete-oracle", (
        "Qualitative target state must distinguish incomplete truth from a failed run."
    )
    assert empty_metrics["tp"] is None and not empty_metrics["accuracy_available"], (
        "An empty oracle cannot supply a meaningful accuracy population."
    )
    assert empty_metrics["accuracy_reason"] == "empty-oracle", (
        "An empty complete oracle must explain why accuracy is withheld."
    )
    assert all(empty_metrics[key] is None for key in (
        "recall_tpr", "false_positive_rate", "precision", "accuracy", "evidence_completeness"
    )), "Undefined denominators must serialize as null."
    report = BuildReport((empty,), (replace(Run(), detected_checks=()),))
    assert "NaN" not in SerializeReport(report), (
        "Reports must contain standards-compliant JSON numbers."
    )
    assert "unknown" in RenderMarkdown(BuildReport((qualitative,), (Run(),))), (
        "Human qualitative views must keep unknown expectations explicit."
    )


class TableParser(HTMLParser):
    """Inspect emitted tags without allowing raw result text to become executable HTML."""

    def __init__(self) -> None:
        """Initialize the HTML tag inventory."""

        super().__init__()
        self.tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Capture tags imposed by the renderer rather than by supplied metadata."""

        self.tags.append(tag)


def test_SharedMatrixProjectionsRetainComparisonsMissingRunsAndEscapedText():
    """Generate all matrix views from identical metadata with safe comparative columns."""

    oracle = replace(Oracle(), target_version='<img src=x onerror="alert(1)"> | `unsafe`')
    current = replace(Run(), release_id="[click](javascript:alert(1))")
    competitor = replace(Run(), scanner_id="comparison.probe", detected_checks=())
    missing = replace(Oracle(), identifier="synthetic.not-run", target_pack="future-pack")
    report = BuildReport((missing, oracle), (current, competitor))
    reordered = BuildReport((oracle, missing), (competitor, current))
    payload = json.loads(SerializeReport(report))
    markdown = RenderMarkdown(report)
    html = RenderHtml(report)
    parser = TableParser()
    parser.feed(html)

    assert FUNCTIONAL_REPORT_VERSION == payload["schema_version"] == 1, (
        "Machine consumers must receive the declared schema version."
    )
    assert SerializeReport(report) == SerializeReport(reordered), (
        "Run and scenario input order must not affect deterministic report output."
    )
    assert payload["runs"][1]["run"]["evidence"][0]["content"] == "exact stdout\n\x00", (
        "JSON evidence must preserve raw content and duplicates without normalization."
    )
    assert len(payload["matrix"]["columns"]) == 3, "Each comparison and missing run needs a column."
    assert payload["matrix"]["columns"][2]["scanner_id"] is None, (
        "Absent assessments must remain not run rather than not detected."
    )
    assert {row["capability"] for row in payload["matrix"]["rows"]} == {
        "web.canary", "web.negative", "web.unavailable"
    }, "Capabilities must come directly from check metadata."
    assert "not-run" in markdown and "not-applicable" in markdown, (
        "Applicability and missing assessment states must remain distinguishable."
    )
    assert "detected=False" in markdown and "detected=True" in markdown, (
        "Human cells must retain individual missed and detected expectations."
    )
    assert "img" not in parser.tags and "script" not in parser.tags, (
        "Supplied text must never become executable HTML."
    )
    assert "\\[click\\]" in markdown and "&#124;" in markdown, (
        "Markdown markup and column separators in metadata must be escaped."
    )
    assert len({len(line) for line in markdown.splitlines()}) == 1, (
        "All generated Markdown table rows must align to identical source widths."
    )


def test_NonApplicableDetectionIsExplicitAndUnknownCapabilityIntersectionStaysAbsent():
    """Expose impossible detections and keep undeclared matrix intersections non-applicable."""

    run = replace(Run(), detected_checks=("unavailable.check",))
    another = replace(
        Oracle(), identifier="synthetic.other", checks=(OracleCheck("only.other", "other", True),)
    )
    report = BuildReport((Oracle(), another), (run,))
    payload = json.loads(SerializeReport(report))

    assert ScoreRun(Oracle(), run)["unexpected_detections"] == ["unavailable.check"], (
        "Detecting a non-applicable check must remain an explicit outside-oracle anomaly."
    )
    assert "unexpected-detection" in RenderMarkdown(report), (
        "Human views must not hide a detection behind a non-applicable state."
    )
    assert payload["matrix"]["rows"][0]["cells"][0]["applicable"] is False, (
        "A capability absent from scenario metadata must remain explicitly non-applicable."
    )


@pytest.mark.parametrize(
    ("factory", "message"),
    [
        (lambda: OracleCheck("Bad", "web.canary", True), "identifier"),
        (lambda: OracleCheck("check", "web.canary", 1), "boolean"),
        (lambda: OracleCheck("check", "web.canary", True, applicable=False), "non-applicable"),
        (lambda: replace(Oracle(), complete="yes"), "completeness"),
        (lambda: replace(Oracle(), checks=(OracleCheck("unknown", "web", None),)), "expectation"),
        (lambda: replace(Oracle(), checks=Oracle().checks * 2), "unique"),
        (lambda: replace(Run(), duration_seconds=-1), "duration"),
        (lambda: replace(Run(), duration_seconds=float("nan")), "duration"),
        (lambda: replace(Run(), duration_seconds=float("inf")), "duration"),
        (lambda: replace(Run(), duration_seconds=True), "duration"),
        (lambda: replace(Run(), status="completed"), "terminal"),
        (lambda: replace(Run(), evidence=Run().evidence * 2), "unique"),
        (lambda: RawEvidence("stdout", "text/plain", b"bytes"), "content"),
        (lambda: replace(Oracle(), target_version="1\nforged"), "single-line"),
        (lambda: replace(Run(), release_id="1\rforged"), "single-line"),
        (lambda: Ratio(-1, 1), "nonnegative"),
        (lambda: Ratio(1, True), "nonnegative"),
        (lambda: ScoreRun(Oracle(), replace(Run(), scenario_id="other")), "match"),
        (lambda: BuildReport((Oracle(), Oracle()), ()), "unique"),
        (lambda: BuildReport((Oracle(),), (Run(), Run())), "unique"),
        (lambda: BuildReport((), (Run(),)), "declared"),
        (lambda: SerializeReport({"invalid": float("nan")}), "JSON"),
    ],
)
def test_InvalidFunctionalContractsFailClosed(factory, message):
    """Reject invalid truth, run identity, terminal states, and serialization."""

    with pytest.raises(ValueError, match=message):
        factory()
