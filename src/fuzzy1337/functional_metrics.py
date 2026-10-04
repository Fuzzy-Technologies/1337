# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Score finite functional oracles and derive explainable capability reports."""

from __future__ import annotations

import html
import json
import math
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from enum import StrEnum

from fuzzy1337.adapters.contracts import RequireIdentifier, RequireText, UniqueIdentifiers

FUNCTIONAL_REPORT_VERSION = 1


class RunStatus(StrEnum):
    """Terminal assessment states that preserve crash and timeout truth."""

    COMPLETED = "completed"
    CRASHED = "crashed"
    TIMED_OUT = "timed-out"


@dataclass(frozen=True, slots=True)
class OracleCheck:
    """Declare one finite check; unknown expectations require an incomplete oracle.

    Attributes:
        identifier: Exact finding/check key matched against normalized detections.
        capability: Matrix row key; several checks may exercise the same capability.
        expected: Positive, negative, or unknown expected detection.
        applicable: Whether this check applies to the declared scenario.
    """

    identifier: str
    capability: str
    expected: bool | None
    applicable: bool = True

    def __post_init__(self) -> None:
        """Reject ambiguous check identity, applicability, or expectation."""

        RequireIdentifier(self.identifier, "check identifier")
        RequireIdentifier(self.capability, "capability")

        if type(self.applicable) is not bool or (
            self.expected is not None and type(self.expected) is not bool
        ):
            raise ValueError("check applicability and expectation must be boolean or null")

        if not self.applicable and self.expected is not None:
            raise ValueError("non-applicable checks cannot declare an expectation")


@dataclass(frozen=True, slots=True)
class ScenarioOracle:
    """Versioned target metadata and finite expectations for one assessment.

    Attributes:
        identifier: Stable scenario identity.
        target_pack: Stable first-party or pinned external target pack identity.
        target_version: Exact target version or digest.
        provenance: Origin of the target and oracle, retained in JSON.
        checks: Finite declared positive, negative, and applicability metadata.
        complete: Whether this oracle exhaustively describes applicable expected checks.
        required_evidence: Roles required for evidence completeness measurement.
    """

    identifier: str
    target_pack: str
    target_version: str
    provenance: str
    checks: tuple[OracleCheck, ...]
    complete: bool
    required_evidence: tuple[str, ...] = ("stdout", "stderr", "invocation")

    def __post_init__(self) -> None:
        """Freeze metadata and prevent incomplete truth from claiming accuracy."""

        RequireIdentifier(self.identifier, "scenario identifier")
        RequireIdentifier(self.target_pack, "target pack")
        RequireText(self.target_version, "target version")
        RequireText(self.provenance, "provenance")
        checks = tuple(self.checks)
        UniqueIdentifiers(tuple(check.identifier for check in checks), "check identifiers")
        evidence = UniqueIdentifiers(self.required_evidence, "required evidence")

        if type(self.complete) is not bool:
            raise ValueError("oracle completeness must be boolean")

        if self.complete and any(check.applicable and check.expected is None for check in checks):
            raise ValueError("complete oracles require every applicable expectation")

        object.__setattr__(self, "checks", checks)
        object.__setattr__(self, "required_evidence", evidence)


@dataclass(frozen=True, slots=True)
class RawEvidence:
    """Preserve exact textual assessment output under a declared evidence role.

    Attributes:
        role: Unique role such as stdout, stderr, or invocation.
        media_type: MIME type describing the preserved content.
        content: Exact text, including empty stderr or partial failed output.
    """

    role: str
    media_type: str
    content: str

    def __post_init__(self) -> None:
        """Validate role and media type without modifying raw output."""

        RequireIdentifier(self.role, "evidence role")
        RequireText(self.media_type, "media type")

        if not isinstance(self.content, str):
            raise ValueError("raw evidence content must be text")


@dataclass(frozen=True, slots=True)
class FunctionalRun:
    """Keep scanner/release identity, normalized detections, and raw evidence distinct.

    Attributes:
        scenario_id: ScenarioOracle identifier assessed by this run.
        scanner_id: Assessment producer; independent of target oracle identity.
        release_id: Scanner/product release or explicitly identified contract-probe version.
        status: Completed, crashed, or timed-out assessment state.
        duration_seconds: Measured finite nonnegative elapsed assessment duration.
        detected_checks: Normalized check identifiers; raw duplicates remain preserved.
        discovered_objects: Normalized object identifiers, counted by unique identity.
        evidence: Exact textual assessment outputs and invocation metadata.
    """

    scenario_id: str
    scanner_id: str
    release_id: str
    status: RunStatus
    duration_seconds: float
    detected_checks: tuple[str, ...] = ()
    discovered_objects: tuple[str, ...] = ()
    evidence: tuple[RawEvidence, ...] = ()

    def __post_init__(self) -> None:
        """Reject invalid terminal state or duration and freeze supplied sequences."""

        RequireIdentifier(self.scenario_id, "scenario identifier")
        RequireIdentifier(self.scanner_id, "scanner identifier")
        RequireText(self.release_id, "release identifier")

        if not isinstance(self.status, RunStatus):
            raise ValueError("run status must be a terminal RunStatus")

        if (
            isinstance(self.duration_seconds, bool)
            or not isinstance(self.duration_seconds, (int, float))
            or not math.isfinite(self.duration_seconds)
            or self.duration_seconds < 0
        ):
            raise ValueError("duration must be finite and nonnegative")

        for field_name in ("detected_checks", "discovered_objects"):
            values = tuple(getattr(self, field_name))

            for value in values:
                RequireIdentifier(value, field_name)

            object.__setattr__(self, field_name, values)

        evidence = tuple(self.evidence)
        UniqueIdentifiers(tuple(record.role for record in evidence), "evidence roles")
        object.__setattr__(self, "evidence", evidence)


def Ratio(numerator: int, denominator: int) -> float | None:
    """Return a defined ratio or null when its finite denominator is zero.

    Args:
        numerator: Nonnegative count above the fraction line.
        denominator: Nonnegative count below the fraction line.

    Returns:
        Floating-point ratio or None for an undefined denominator.

    Raises:
        ValueError: Either count is not a nonnegative integer.
    """

    if any(type(value) is not int or value < 0 for value in (numerator, denominator)):
        raise ValueError("ratio counts must be nonnegative integers")

    return numerator / denominator if denominator else None


def ScoreRun(oracle: ScenarioOracle, run: FunctionalRun) -> dict[str, object]:
    """Score exact known answers while preserving failed/qualitative run truth.

    Args:
        oracle: Finite scenario truth and required evidence roles.
        run: Assessment observations, terminal state, and raw evidence.

    Returns:
        Counts, nullable accuracy ratios, runtime state, and evidence completeness.

    Raises:
        ValueError: The run belongs to a different scenario.
    """

    if oracle.identifier != run.scenario_id:
        raise ValueError("run scenario does not match the oracle")

    detected = set(run.detected_checks)
    positives = {check.identifier for check in oracle.checks if check.applicable and check.expected}
    negatives = {
        check.identifier for check in oracle.checks if check.applicable and check.expected is False
    }
    declared = {check.identifier for check in oracle.checks if check.applicable}
    unexpected = detected - declared
    missing_evidence = sorted(set(oracle.required_evidence) - {item.role for item in run.evidence})
    eligible = oracle.complete and run.status is RunStatus.COMPLETED and bool(declared)
    tp = len(positives & detected)
    fp = len(negatives & detected)
    fn = len(positives - detected)
    tn = len(negatives - detected)

    return {
        "accuracy_available": eligible,
        "accuracy_reason": (
            "complete-oracle" if eligible
            else "incomplete-run" if run.status is not RunStatus.COMPLETED
            else "incomplete-oracle" if not oracle.complete else "empty-oracle"
        ),
        "tp": tp if eligible else None,
        "fp": fp if eligible else None,
        "fn": fn if eligible else None,
        "tn": tn if eligible else None,
        "recall_tpr": Ratio(tp, tp + fn) if eligible else None,
        "false_positive_rate": Ratio(fp, fp + tn) if eligible else None,
        "precision": Ratio(tp, tp + fp) if eligible else None,
        "accuracy": Ratio(tp + tn, tp + fp + fn + tn) if eligible else None,
        "unexpected_detections": sorted(unexpected),
        "unexpected_detection_count": len(unexpected),
        "detected_check_count": len(detected),
        "discovered_object_count": len(set(run.discovered_objects)),
        "duration_seconds": run.duration_seconds,
        "crashes": int(run.status is RunStatus.CRASHED),
        "timeouts": int(run.status is RunStatus.TIMED_OUT),
        "evidence_expected": len(oracle.required_evidence),
        "evidence_present": len(oracle.required_evidence) - len(missing_evidence),
        "evidence_completeness": Ratio(
            len(oracle.required_evidence) - len(missing_evidence), len(oracle.required_evidence)
        ),
        "missing_evidence": missing_evidence,
    }


def BuildReport(
    scenarios: Sequence[ScenarioOracle], runs: Sequence[FunctionalRun]
) -> dict[str, object]:
    """Build versioned run evidence and capability matrix from one oracle source.

    Args:
        scenarios: Unique scenario metadata, including target pack/version.
        runs: At most one run per scenario, scanner, and release.

    Returns:
        Deterministic JSON-compatible report with raw runs and matrix projections.

    Raises:
        ValueError: A scenario is duplicated, a run is duplicated, or a run is undeclared.
    """

    UniqueIdentifiers(tuple(item.identifier for item in scenarios), "scenario identifiers")
    oracles = {item.identifier: item for item in scenarios}
    grouped: dict[str, list[FunctionalRun]] = {key: [] for key in oracles}
    seen: set[tuple[str, str, str]] = set()

    for assessment in runs:
        identity = (assessment.scenario_id, assessment.scanner_id, assessment.release_id)

        if identity in seen:
            raise ValueError("scenario/scanner/release runs must be unique")

        if assessment.scenario_id not in oracles:
            raise ValueError("run scenario must be declared")

        seen.add(identity)
        grouped[assessment.scenario_id].append(assessment)

    capabilities = sorted({check.capability for item in scenarios for check in item.checks})
    columns: list[dict[str, object]] = []
    cells_by_capability: dict[str, list[dict[str, object]]] = {key: [] for key in capabilities}
    scored_runs: list[dict[str, object]] = []

    for scenario_id, oracle in sorted(oracles.items()):
        scenario_runs = sorted(
            grouped[scenario_id], key=lambda item: (item.scanner_id, item.release_id)
        )
        column_runs: Sequence[FunctionalRun | None] = scenario_runs or (None,)

        for run in column_runs:
            columns.append({
                "scenario_id": scenario_id,
                "target_pack": oracle.target_pack,
                "target_version": oracle.target_version,
                "scanner_id": run.scanner_id if run else None,
                "release_id": run.release_id if run else None,
            })

            if run is not None:
                scored_runs.append({"run": asdict(run), "metrics": ScoreRun(oracle, run)})

            for capability in capabilities:
                checks = [item for item in oracle.checks if item.capability == capability]
                detected = set(run.detected_checks) if run else set()
                applicable = any(item.applicable for item in checks)
                state = "not-run" if applicable else "not-applicable"

                if run is not None and applicable:
                    state = run.status.value if run.status is not RunStatus.COMPLETED else (
                        "detected" if any(item.identifier in detected for item in checks)
                        else "not-detected"
                    )

                if run is not None and not applicable and any(
                    item.identifier in detected for item in checks
                ):
                    state = "unexpected-detection"

                cells_by_capability[capability].append({
                    "applicable": applicable,
                    "state": state,
                    "checks": [
                        {
                            "identifier": item.identifier,
                            "expected": item.expected,
                            "detected": item.identifier in detected if run else None,
                            "applicable": item.applicable,
                        }
                        for item in sorted(checks, key=lambda item: item.identifier)
                    ],
                })

    return {
        "schema_version": FUNCTIONAL_REPORT_VERSION,
        "scenarios": [asdict(item) for _, item in sorted(oracles.items())],
        "runs": scored_runs,
        "matrix": {
            "columns": columns,
            "rows": [
                {"capability": key, "cells": cells_by_capability[key]} for key in capabilities
            ],
        },
    }


def SerializeReport(report: dict[str, object]) -> str:
    """Serialize report data with stable keys and standards-compliant numbers.

    Args:
        report: Data produced by BuildReport.

    Returns:
        Indented JSON with a trailing newline.

    Raises:
        ValueError: Report data contains non-finite numbers.
    """

    return json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"


def MatrixRows(report: dict[str, object]) -> list[list[str]]:
    """Project generated report cells into a shared human-readable table.

    Args:
        report: Data produced by BuildReport.

    Returns:
        Table header and rows preserving individual expected/detected check states.
    """

    matrix = report["matrix"]
    assert isinstance(matrix, dict), "matrix must be produced by BuildReport"
    headers = ["Capability"]

    for column in matrix["columns"]:
        scanner = column["scanner_id"] or "not-run"
        release = column["release_id"] or "none"
        headers.append(
            f"{column['target_pack']}@{column['target_version']} / "
            f"{column['scenario_id']} / {scanner}@{release}"
        )

    rows = [headers]

    for row in matrix["rows"]:
        values = [row["capability"]]

        for cell in row["cells"]:
            checks = [item for item in cell["checks"] if item["applicable"]]
            expected = ", ".join(
                f"{item['identifier']}: expected="
                f"{'unknown' if item['expected'] is None else item['expected']}, "
                f"detected={'not-run' if item['detected'] is None else item['detected']}"
                for item in checks
            ) or "none"
            values.append(f"{cell['state']}; {expected}")

        rows.append(values)

    return rows


def RenderMarkdown(report: dict[str, object]) -> str:
    """Render a source-aligned Markdown matrix without interpreting supplied HTML.

    Args:
        report: Data produced by BuildReport.

    Returns:
        Capability table with escaped text and aligned source columns.
    """

    rows = []

    for row in MatrixRows(report):
        escaped = []

        for value in row:
            value = html.escape(value).replace("|", "&#124;").replace("\\", "\\\\")

            for character in "`*_[]()!~":
                value = value.replace(character, "\\" + character)

            escaped.append(value)

        rows.append(escaped)

    widths = [max(3, *(len(row[index]) for row in rows)) for index in range(len(rows[0]))]
    rows.insert(1, ["-" * width for width in widths])

    return "\n".join(
        "| " + " | ".join(
            value.ljust(width) for value, width in zip(row, widths, strict=True)
        ) + " |"
        for row in rows
    ) + "\n"


def RenderHtml(report: dict[str, object]) -> str:
    """Render an escaped HTML matrix that never embeds executable raw evidence.

    Args:
        report: Data produced by BuildReport.

    Returns:
        Standalone UTF-8 HTML document containing the capability table.
    """

    rows = MatrixRows(report)
    header = "".join(f"<th scope=\"col\">{html.escape(value)}</th>" for value in rows[0])
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(value)}</td>" for value in row) + "</tr>"
        for row in rows[1:]
    )

    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<title>Functional capability matrix</title></head><body>"
        f"<table><caption>Functional capability matrix</caption><thead><tr>{header}</tr>"
        f"</thead><tbody>{body}</tbody></table></body></html>\n"
    )
