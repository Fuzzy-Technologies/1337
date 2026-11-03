# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal same-basis comparison of original selected-path outcomes and static presentation."""

from __future__ import annotations

import base64
import json
from html import escape
from typing import Any, cast

from fuzzy1337.model import CanonicalModelJson, ModelState
from fuzzy1337.path_rendering import (
    MAX_RENDER_NODES,
    MAX_RENDER_TRANSITIONS,
    Download,
    GraphSvg,
)
from fuzzy1337.reachability import ReachabilityModelVersion

__all__: tuple[str, ...] = ()
COMPARISON_PROFILE = "same-basis-selected-path-comparison"
MAX_COMPARISON_JSON_BYTES = 3 * 1024 * 1024
MAX_COMPARISON_HTML_BYTES = 8 * 1024 * 1024
MAX_ORIGINAL_OUTCOME_BYTES = 1024 * 1024
_STATES = frozenset({"CONFIRMED", "LIKELY", "POTENTIAL", "BLOCKED", "UNKNOWN"})


def ComparePathOutcomes(
    before: dict[str, object], after: dict[str, object], model: ModelState, *,
    focus_transition: str,
) -> dict[str, object]:
    """Compare exact completed owner outcomes without manufacturing an alternative graph.

    Args:
        before: Original completed outcome returned by the owning analyze command.
        after: Independently returned completed outcome over the same selected basis and query.
        model: Exact immutable common owner-read saved model, not a replacement graph DTO.
        focus_transition: Existing selected relation allowed to differ in its observed state label.

    Returns:
        Detached Internal comparison containing both unchanged original outcomes. Zero changed
        states is valid; no confidence, causality, chronological or efficacy claim is derived.

    Raises:
        ValueError: Completed outcomes disagree on basis/query, exceed finite bounds, or change
            another transition. This Internal consumer grants no serialized-graph admission API.
    """

    version = ReachabilityModelVersion.FromModel(model)
    expected = {"schema_version": version.schema_version, "workspace_id": version.workspace_id,
                "revision": version.revision, "snapshot_sha256": version.snapshot_sha256}
    relations = {item.Reference(): item for item in model.relations}
    selected = []

    for original in (before, after):
        if original.get("status") != "completed" or original.get("command") != "paths.analyze" or (
            original.get("schema_version") != 1 or original.get("exit_code") != 0
            or original.get("model_version") != expected
            or len(CanonicalModelJson(original)) + 1 > MAX_ORIGINAL_OUTCOME_BYTES
        ):
            raise ValueError("comparison requires bounded completed original owner outcomes")

        analysis = cast(dict[str, Any], original["analysis"])
        transitions = analysis["transitions"]
        search = analysis["search"]
        indexed = {item["relation_reference"]: item for item in transitions}
        nodes = {search["source_reference"], search["target_reference"]}

        if not 1 <= len(transitions) <= MAX_RENDER_TRANSITIONS or len(indexed) != len(transitions):
            raise ValueError("comparison exceeds selected transition profile")

        for reference, transition in indexed.items():
            relation = relations.get(reference)

            if relation is None or transition["state"] not in _STATES or (
                relation.source_reference != transition["source_reference"]
                or relation.target_reference != transition["target_reference"]
            ):
                raise ValueError("comparison has inconsistent original transition identity")

            nodes.update((transition["source_reference"], transition["target_reference"]))

        if len(nodes) > MAX_RENDER_NODES or focus_transition not in indexed:
            raise ValueError("comparison exceeds selected node or focus profile")

        selected.append((analysis, indexed))

    for name in ("context_reference", "scope_reference", "as_of", "max_age_seconds"):
        if before[name] != after[name]:
            raise ValueError("comparison requires the same explicit context and clock")

    left, right = selected[0][0], selected[1][0]

    if any(left["search"][name] != right["search"][name] for name in (
        "source_reference", "target_reference", "limits",
    )) or left["cuts"]["max_cut_work"] != right["cuts"]["max_cut_work"] or (
        selected[0][1].keys() != selected[1][1].keys()
    ):
        raise ValueError("comparison requires the same selected query and bounds")

    changes = []

    for reference in sorted(selected[0][1]):
        before_state = selected[0][1][reference]["state"]
        after_state = selected[1][1][reference]["state"]

        if before_state != after_state:
            if reference != focus_transition:
                raise ValueError("comparison state change exceeds the selected focus")

            changes.append({"relation_reference": reference, "before_state": before_state,
                            "after_state": after_state})

    result: dict[str, object] = {
        "schema_version": 1, "profile_version": 1, "profile": COMPARISON_PROFILE,
        "command": "paths.compare", "status": "completed", "failure": None, "exit_code": 0,
        "core_mutation": "none", "evidence_mutation": "none", "authority": "none",
        "model_version": expected, "focus_transition": focus_transition,
        "observed_state_change": bool(changes), "state_changes": changes,
        "before": before, "after": after,
    }
    raw = CanonicalModelJson(result)

    if len(raw) + 1 > MAX_COMPARISON_JSON_BYTES:
        raise ValueError("comparison exceeds its complete JSON budget")

    return cast(dict[str, object], json.loads(raw))


def RenderPathComparisonHtml(comparison: dict[str, object], model: ModelState) -> str:
    """Render isolated static original SVG images and separately escaped original proof panels.

    Args:
        comparison: Exact completed same-basis comparison produced by the Internal consumer.
        model: Same owner-read immutable common model used for both original analyses.

    Returns:
        Standalone no-JavaScript HTML with exact comparison JSON and both original SVG downloads.
        UNKNOWN and independent search/cut completeness remain explicit per original outcome.

    Raises:
        ValueError: Comparison identity, graph or complete artifact violates the finite profile.
    """

    before = cast(dict[str, object], comparison["before"])
    after = cast(dict[str, object], comparison["after"])
    rebuilt = ComparePathOutcomes(before, after, model,
                                  focus_transition=cast(str, comparison["focus_transition"]))

    if rebuilt != comparison:
        raise ValueError("presentation requires an unchanged original comparison")

    raw = CanonicalModelJson(comparison) + b"\n"
    parts = []
    downloads = [Download(raw, "application/json", "path-comparison.json",
                          "Download exact comparison JSON")]

    for label, original in (("Before", before), ("After", after)):
        document = cast(dict[str, Any], original)
        svg, _ = GraphSvg(document, model)
        encoded = base64.b64encode(svg.encode("utf-8")).decode("ascii")
        analysis = document["analysis"]
        search, cuts = analysis["search"], analysis["cuts"]
        focus_state = next(transition["state"] for transition in analysis["transitions"]
                           if transition["relation_reference"] == comparison["focus_transition"])
        proof = json.dumps(original, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2)
        parts.append('<section class="phase"><h2>' + label
            + '</h2><p class="focus-state"><strong>Focus state: ' + escape(focus_state)
            + '</strong></p><p>Returned candidate paths: '
            + str(len(search["paths"])) + '; enumeration complete: '
            + str(search["complete"]).lower() + '; cut checks complete: '
            + str(cuts["complete"]).lower() + '.</p><img alt="' + label
            + ' original selected graph" src="data:image/svg+xml;base64,' + encoded + '">'
            + '<details open><summary>' + label + ' original proof, UNKNOWN and bounds</summary>'
            + '<pre>' + escape(proof)
            + '</pre></details></section>')
        downloads.append(Download(svg.encode("utf-8"), "image/svg+xml",
                                  label.lower() + "-path.svg", "Download " + label + " SVG"))

    state_text = "Observed focus state change" if comparison["observed_state_change"] else (
        "No observed transition-state change")
    csp = ("default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'none'; "
           "base-uri 'none'; form-action 'none'; frame-src 'none'; object-src 'none'")
    html = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="' + escape(csp, quote=True) + '">'
        '<title>1337 selected-path state comparison</title><style>'
        'body{font:16px system-ui,sans-serif;margin:24px;line-height:1.5;color:#14233b}'
        '.phases{display:flex;flex-wrap:wrap;gap:20px}.phase{flex:1;min-width:280px;'
        'max-width:100%;border:1px solid #a7b5c7;padding:12px;overflow:hidden}'
        'img{display:block;width:100%;height:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere;'
        'max-height:480px;overflow:auto}a.download{display:inline-block;margin:8px}'
        '</style></head><body><h1>Selected-path state comparison</h1><p>' + state_text
        + '. Before/after are caller-selected roles. Chronology, one changed control, causality, '
        'physical access, global completeness, risk and remediation efficacy are unassessed.</p>'
        '<p>Focus: <code>' + escape(str(comparison["focus_transition"])) + '</code></p>'
        '<p>UNKNOWN remains a possible selected candidate. Search and independent cut bounds '
        'remain separate; counts are not mitigation benefit.</p><div class="phases">'
        + "".join(parts) + '</div><p>' + "".join(downloads)
        + '</p><details><summary>Exact paired machine outcome</summary><pre id="comparison-json">'
        + escape(raw.decode("utf-8")) + '</pre></details></body></html>\n')

    if len(html.encode("utf-8")) > MAX_COMPARISON_HTML_BYTES:
        raise ValueError("comparison exceeds its complete HTML budget")

    return html
