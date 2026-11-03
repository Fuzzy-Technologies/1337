# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal explicit same-basis product comparison through two unchanged original path analyses."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from io import StringIO
from pathlib import Path
from typing import TextIO, cast

from fuzzy1337.evidence import EvidenceError, RequireEvidenceDigest
from fuzzy1337.model import CanonicalModelJson, LocalModelStore
from fuzzy1337.path_analysis import PathAnalysisLimits
from fuzzy1337.path_comparison import (
    COMPARISON_PROFILE,
    MAX_COMPARISON_JSON_BYTES,
    MAX_ORIGINAL_OUTCOME_BYTES,
    ComparePathOutcomes,
    RenderPathComparisonHtml,
)
from fuzzy1337.reachability import (
    Integer,
    ReachabilityLimits,
    ReachabilityModelVersion,
    Reference,
    Text,
    Time,
)
from fuzzy1337.runtime_commands import RuntimeArgumentParser, RuntimeFailure, RuntimePath
from fuzzy1337.workspace import LocalWorkspaceStore

__all__: tuple[str, ...] = ()
_COMMON_FIELDS = ("expected-revision", "expected-snapshot-sha256", "source", "target", "context",
                  "scope-reference", "as-of", "max-age-seconds", "max-depth", "max-paths",
                  "max-work", "max-frontier", "max-cut-work")
_INTEGER_FIELDS = frozenset({"expected-revision", "max-age-seconds", "max-depth", "max-paths",
                             "max-work", "max-frontier", "max-cut-work"})
_REPEAT_FLAGS = frozenset({"--transition", "--before-assessment", "--after-assessment"})


def PathComparisonParser() -> argparse.ArgumentParser:
    """Declare common exact owner selections and two explicit original assessment sets.

    Returns:
        Parser refusing abbreviations and requiring explicit assessed/unassessed sides.
    """

    parser = RuntimeArgumentParser(prog="1337 paths compare", add_help=False, allow_abbrev=False)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--html", action="store_true")

    for name in _COMMON_FIELDS:
        parser.add_argument("--" + name, required=True,
                            type=int if name in _INTEGER_FIELDS else str)

    parser.add_argument("--transition", required=True, action="append")
    parser.add_argument("--focus-transition", required=True)

    for side in ("before", "after"):
        assessments = parser.add_mutually_exclusive_group(required=True)
        assessments.add_argument("--" + side + "-assessment", action="append")
        assessments.add_argument("--" + side + "-no-assessments", action="store_true")

    return parser


def UniqueComparisonScalars(arguments: Sequence[str]) -> None:
    """Refuse ambiguous scalar repetition before parser, workspace or original evidence reads.

    Args:
        arguments: Explicit comparison arguments; only three selected reference flags repeat.
    """

    seen: set[str] = set()

    for value in arguments:
        name = value.split("=", 1)[0]

        if name.startswith("--") and name not in _REPEAT_FLAGS:
            if name in seen:
                raise RuntimeFailure("configuration", 2)

            seen.add(name)


class BoundedPathCapture(StringIO):
    """Refuse an oversized original outcome before retaining another caller-stream chunk."""

    def __init__(self) -> None:
        """Own an empty one-MiB UTF-8 capture; no partial result escapes a failed side."""

        super().__init__()
        self.received_bytes = 0

    def Write(self, value: str) -> int:
        """Bound each write before the backing StringIO retains its characters.

        Args:
            value: Original owning command text, including its terminal newline.

        Returns:
            Number of characters retained, following the TextIO callback contract.
        """

        size = len(value.encode("utf-8"))

        if self.received_bytes + size > MAX_ORIGINAL_OUTCOME_BYTES:
            raise RuntimeFailure("output-limit")

        self.received_bytes += size

        return super().write(value)

    write = Write


def AnalyzeSide(arguments: Sequence[str], side: str) -> dict[str, object]:
    """Call the unchanged original owning handler once and retain only completed machine output.

    Args:
        arguments: Implementation-generated ordinary analyze arguments, never arbitrary forwarding.
        side: Fixed before/after diagnostic label owned by this implementation.

    Returns:
        Detached original completed outcome within the unchanged one-MiB owning ceiling.
    """

    from fuzzy1337.path_commands import RunPathCommands

    with BoundedPathCapture() as captured:
        status = RunPathCommands(arguments, captured, json_output=True)
        raw = captured.getvalue()

    if status != 0:
        raise RuntimeFailure(side + "-analysis", status if status in (2, 4, 130) else 4)

    document = json.loads(raw)

    if not isinstance(document, dict) or document.get("status") != "completed":
        raise RuntimeFailure(side + "-analysis")

    return cast(dict[str, object], document)


def AnalyzeArguments(options: argparse.Namespace, side: str) -> list[str]:
    """Generate one finite ordinary owner request without accepting forwarded argument syntax.

    Args:
        options: Fully preflighted local comparison namespace.
        side: Fixed before or after side selecting its explicit original manifest set.

    Returns:
        Exact analyze action and complete common owner fields plus one assessment selection.
    """

    arguments = ["analyze", str(options.workspace)]

    for name in _COMMON_FIELDS:
        arguments.extend(("--" + name, str(getattr(options, name.replace("-", "_")))))

    for reference in options.transition:
        arguments.extend(("--transition", reference))

    assessments = getattr(options, side + "_assessment")

    if assessments:
        for identity in assessments:
            arguments.extend(("--assessment", identity))

    else:
        arguments.append("--no-assessments")

    return arguments


def RunPathComparisonCommands(
    arguments: Sequence[str], output: TextIO, *, json_output: bool = False,
) -> int:
    """Compare two original same-basis path states without evidence, model or authority changes.

    Args:
        arguments: Common original analyze selections, explicit side manifests and one focus.
        output: Caller-owned terminal destination; no artifact file is created implicitly.
        json_output: Emit the additive Internal paired outcome, mutually exclusive with HTML.

    Returns:
        Zero for a completed bounded pair, two for configuration, four for basis/proof/profile/
        output refusal, or 130 for interruption. Neither failed side yields a partial pair.
    """

    if list(arguments) in (["--help"], ["-h"]):
        PathComparisonParser().print_help(file=output)

        return 0

    outcome: dict[str, object] = {"schema_version": 1, "profile_version": 1,
        "profile": COMPARISON_PROFILE, "command": "paths.compare", "status": "failed",
        "failure": None, "exit_code": 4, "before": None, "after": None,
        "core_mutation": "none", "evidence_mutation": "none", "authority": "none"}
    status = 4
    phase = "configuration"
    html = None

    try:
        UniqueComparisonScalars(arguments)
        options = PathComparisonParser().parse_args(arguments)

        if options.html and json_output:
            raise RuntimeFailure("configuration", 2)

        Integer(options.expected_revision, 0, 2**63 - 1)
        RequireEvidenceDigest(options.expected_snapshot_sha256)
        source, target = Reference(options.source, "object"), Reference(options.target, "object")
        selected = tuple(Reference(value, "relation") for value in options.transition)
        focus = Reference(options.focus_transition, "relation")

        if source == target or not 1 <= len(selected) <= 128 or len(set(selected)) != len(
            selected,
        ) or focus not in selected:
            raise RuntimeFailure("selection", 2)

        for side in ("before", "after"):
            identities = tuple(Reference(value, "sha256")
                               for value in (getattr(options, side + "_assessment") or ()))

            if len(identities) > 32 or len(set(identities)) != len(identities):
                raise RuntimeFailure("configuration", 2)

        Text(options.context)
        Text(options.scope_reference)
        Time(options.as_of)
        Integer(options.max_age_seconds, 0, 604800)
        ReachabilityLimits(options.max_depth, options.max_paths, options.max_work,
                           options.max_frontier)
        PathAnalysisLimits(options.max_cut_work)
        root = RuntimePath(options.workspace)
        phase = "basis"
        workspace = LocalWorkspaceStore(root).Open()
        model = LocalModelStore(root).Open()
        expected = ReachabilityModelVersion(1, workspace.workspace_id, options.expected_revision,
                                           options.expected_snapshot_sha256)

        if ReachabilityModelVersion.FromModel(model) != expected:
            raise RuntimeFailure("basis")

        phase = "before-analysis"
        before = AnalyzeSide(AnalyzeArguments(options, "before"), "before")
        phase = "after-analysis"
        after = AnalyzeSide(AnalyzeArguments(options, "after"), "after")
        phase = "comparison-profile"
        candidate = ComparePathOutcomes(before, after, model, focus_transition=focus)

        if options.html:
            phase = "output-limit"
            html = RenderPathComparisonHtml(candidate, model)

        if LocalWorkspaceStore(root).Open() != workspace or LocalModelStore(root).Open() != model:
            raise RuntimeFailure("basis-changed")

        outcome = candidate
        status = 0

    except RuntimeFailure as error:
        outcome["failure"] = error.category
        status = error.status

    except KeyboardInterrupt:
        outcome["failure"] = "interrupted"
        status = 130

    except (EvidenceError, OSError, ValueError, TypeError, KeyError, AttributeError,
            OverflowError, RecursionError):
        outcome["failure"] = phase
        status = 2 if phase == "configuration" else 4

    outcome["exit_code"] = status

    if status == 0 and html is not None:
        output.write(html)

    elif json_output:
        raw = CanonicalModelJson(outcome) + b"\n"

        if len(raw) > MAX_COMPARISON_JSON_BYTES:
            raise RuntimeFailure("output-limit")

        output.write(raw.decode("utf-8"))

    else:
        output.write("Selected-path state comparison " + str(outcome["status"]) +
                     " (exit " + str(status) + ").\n")

        if status == 0:
            output.write("Observed focus state change.\n" if outcome["observed_state_change"] else
                         "No observed transition-state change.\n")
            output.write("Caller-selected roles only; causality and remediation efficacy "
                         "are unassessed.\n")

        else:
            output.write("failure: " + str(outcome["failure"]) + "\n")

    output.flush()

    return status
