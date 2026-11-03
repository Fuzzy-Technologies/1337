# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal offline presentation of the owning command's verified selected-path outcome."""

from __future__ import annotations

import base64
import hashlib
from collections import deque
from html import escape
from typing import Any, cast

from fuzzy1337.model import CanonicalModelJson, ModelState

__all__: tuple[str, ...] = ()

MAX_HTML_BYTES = 4 * 1024 * 1024
MAX_RENDER_NODES = 64
MAX_RENDER_TRANSITIONS = 128

SCRIPT = '''"use strict";
const graph = document.getElementById("path-graph");
const initial = graph.getAttribute("viewBox").split(" ").map(Number);
let view = initial.slice();
let drag = null;
function Apply() {
    graph.setAttribute("viewBox", view.join(" "));
}
function Zoom(factor) {
    const width = Math.min(initial[2] * 4,
            Math.max(Math.min(initial[2] / 4, 600), view[2] * factor));
    const bounds = graph.getBoundingClientRect();
    const height = width * bounds.height / bounds.width;
    view = [view[0] + (view[2] - width) / 2, view[1] + (view[3] - height) / 2,
            width, height];
    Apply();
}
document.getElementById("zoom-in").addEventListener("click", () => Zoom(0.8));
document.getElementById("zoom-out").addEventListener("click", () => Zoom(1.25));
document.getElementById("reset-view").addEventListener("click", () => {
    view = initial.slice();
    Apply();
});
graph.addEventListener("wheel", event => {
    event.preventDefault();
    Zoom(event.deltaY < 0 ? 0.8 : 1.25);
}, {passive: false});
graph.addEventListener("pointerdown", event => {
    if (event.target.closest("a")) return;
    drag = [event.clientX, event.clientY, view[0], view[1]];
    graph.setPointerCapture(event.pointerId);
});
graph.addEventListener("pointermove", event => {
    if (!drag) return;
    const bounds = graph.getBoundingClientRect();
    view[0] = drag[2] - (event.clientX - drag[0]) * view[2] / bounds.width;
    view[1] = drag[3] - (event.clientY - drag[1]) * view[3] / bounds.height;
    Apply();
});
graph.addEventListener("pointerup", () => { drag = null; });
graph.addEventListener("pointercancel", () => { drag = null; });
document.querySelectorAll("a.inspect").forEach(link => {
    link.addEventListener("click", () => {
        const detail = document.getElementById(link.getAttribute("href").slice(1));
        detail.open = true;
    });
});
'''

SVG_STYLE = '''text{font:13px system-ui,sans-serif;fill:#14233b}
.node rect{fill:#f1f5fb;stroke:#334e70;stroke-width:2}
.node.cut rect{stroke-width:5}.edge path{fill:none;stroke-width:3}
.edge text{paint-order:stroke;stroke:#fff;stroke-width:5px;stroke-linejoin:round}
.CONFIRMED path{stroke:#176b46}.LIKELY path{stroke:#2456a4;stroke-dasharray:14 5}
.POTENTIAL path{stroke:#875a16;stroke-dasharray:10 4 2 4}
.BLOCKED path{stroke:#a51d35;stroke-dasharray:4 4}
.UNKNOWN path{stroke:#555;stroke-dasharray:1 6}
a:focus rect,a:focus path{stroke:#7a22c8;stroke-width:6}
'''

STYLE = '''body{font:16px system-ui,sans-serif;color:#14233b;background:#f7f9fc;
margin:0 auto;max-width:1180px;padding:24px;line-height:1.5}
h1,h2,h3{line-height:1.2}a{color:#2456a4}button,a.download{font:inherit;padding:8px 12px;
margin:4px;border:1px solid #63738a;border-radius:6px;background:white;color:#14233b}
.panel,details{background:white;border:1px solid #c8d2df;border-radius:8px;padding:14px;
margin:12px 0}#path-graph{display:block;width:100%;height:520px;touch-action:none;
border:1px solid #a7b5c7;background:white;cursor:grab}
summary{cursor:pointer;font-weight:600}pre,code{overflow-wrap:anywhere;white-space:pre-wrap;
font-size:13px}pre{max-height:440px;overflow:auto}li{margin:6px 0}
.legend{display:flex;flex-wrap:wrap;gap:12px;padding:0;list-style:none}
.legend span{border-bottom:3px solid;padding:4px}.legend .unknown{border-style:dotted}
.legend .likely,.legend .blocked{border-style:dashed}.legend .potential{border-style:double}
:target{outline:3px solid #7a22c8}noscript{display:block;padding:12px;background:#fff4cd}
'''


def Anchor(reference: str) -> str:
    """Make a fixed local identifier without embedding caller-controlled attribute syntax.

    Args:
        reference: Original model reference retained separately in the visible explanation.

    Returns:
        ASCII presentation anchor; it creates no new model identity.
    """

    return "detail-" + hashlib.sha256(reference.encode("utf-8")).hexdigest()


def Download(raw: bytes, media_type: str, filename: str, label: str) -> str:
    """Build a local download for bytes already owned by this same standalone artifact.

    Args:
        raw: Exact canonical JSON or rendered static SVG bytes.
        media_type: Fixed first-party media type, never supplied by a source declaration.
        filename: Fixed plain basename without an input-derived path.
        label: Fixed visible English description.

    Returns:
        Escaped anchor containing a base64 data URI and no external resource reference.
    """

    encoded = base64.b64encode(raw).decode("ascii")

    return (f'<a class="download" download="{escape(filename, quote=True)}" '
            f'href="data:{escape(media_type, quote=True)};base64,{encoded}">{escape(label)}</a>')


def Layout(references: tuple[str, ...], transitions: list[dict[str, Any]],
           source: str) -> tuple[dict[str, tuple[int, int]], int, int]:
    """Place every selected original node using bounded deterministic breadth-first ranks.

    Args:
        references: Sorted original selected endpoints, with no omitted source or target.
        transitions: Original directed selected transitions, including blocked and unknown ones.
        source: Exact explicit query source; rank is presentation only, never reachability.

    Returns:
        Original-reference coordinates and finite SVG width/height, preserving cycles and islands.
    """

    successors: dict[str, list[str]] = {reference: [] for reference in references}

    for transition in transitions:
        successors[transition["source_reference"]].append(transition["target_reference"])

    ranks = {source: 0}
    pending = deque((source,))

    while pending:
        current = pending.popleft()

        for following in sorted(successors[current]):
            if following not in ranks:
                ranks[following] = ranks[current] + 1
                pending.append(following)

    final_rank = max(ranks.values()) + 1
    rows: dict[int, int] = {}
    positions = {}

    for reference in references:
        rank = ranks.get(reference, final_rank)
        row = rows.get(rank, 0)
        positions[reference] = (320 + rank * 260, 120 + row * 140)
        rows[rank] = row + 1

    # Keep cubic control points, self-loops and complete state labels inside the static export.
    # The rightmost vertical curve extends 200 pixels; its state label is centered at +180.
    width = max(point[0] for point in positions.values()) + 300
    height = max(point[1] for point in positions.values()) + 100

    return positions, width, height


def EdgeGeometry(source: tuple[int, int], target: tuple[int, int]) -> tuple[str, int, int]:
    """Separate forward, reverse, vertical and self transitions without changing their direction.

    Args:
        source: Original source node's presentation coordinates.
        target: Original target node's presentation coordinates.

    Returns:
        Cubic SVG path and its deterministic state-label position.
    """

    x1, y1 = source
    x2, y2 = target

    if source == target:
        return (f'M {x1 - 45} {y1 - 30} C {x1 - 100} {y1 - 95}, '
                f'{x1 + 100} {y1 - 95}, {x1 + 45} {y1 - 30}', x1, y1 - 64)

    if x1 == x2:
        side = 1 if y2 > y1 else -1
        start, finish = x1 + side * 100, x2 + side * 100

        return (f'M {start} {y1} C {start + side * 100} {y1}, '
                f'{finish + side * 100} {y2}, {finish} {y2}',
                x1 + side * 180, (y1 + y2) // 2)

    direction = 1 if x2 > x1 else -1
    start, finish = x1 + direction * 100, x2 - direction * 100
    offset = -50 * direction

    return (f'M {start} {y1} C {start + direction * 65} {y1 + offset}, '
            f'{finish - direction * 65} {y2 + offset}, {finish} {y2}',
            (start + finish) // 2, (y1 + y2) // 2 + offset)


def GraphSvg(document: dict[str, Any], model: ModelState) -> tuple[str, str]:
    """Render only the owning outcome's selected graph and original typed-node explanations.

    Args:
        document: Completed command outcome after original proof admission and final basis reread.
        model: Same exact immutable owner-read model used by the analysis.

    Returns:
        Static standalone SVG and accessible node/edge explanation HTML with original attribution.

    Raises:
        ValueError: Graph exceeds the finite presentation profile or has inconsistent owner refs.
    """

    analysis = document["analysis"]
    transitions = analysis["transitions"]
    search = analysis["search"]
    references = {search["source_reference"], search["target_reference"]}

    for transition in transitions:
        references.update((transition["source_reference"], transition["target_reference"]))

    if len(references) > MAX_RENDER_NODES or len(transitions) > MAX_RENDER_TRANSITIONS:
        raise ValueError("selected graph exceeds offline presentation profile")

    kinds = {item.Reference(): item.identity.kind.value for item in model.objects}

    if not references <= kinds.keys():
        raise ValueError("selected graph has foreign model endpoints")

    positions, width, height = Layout(tuple(sorted(references)), transitions,
                                      search["source_reference"])
    cuts = {item["reference"] for item in analysis["cuts"]["verified"]}
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" id="path-graph" '
           f'viewBox="0 0 {width} {height}" role="group" aria-labelledby="graph-title graph-desc">',
           '<title id="graph-title">Selected original transition graph</title>',
           '<desc id="graph-desc">Directed selected transitions. Full state words and line '
           'patterns distinguish attestations. CUT means a verified structural cut in this '
           'selected nonblocked graph. Each object and edge links to its original '
           'explanation.</desc>',
           '<style>' + SVG_STYLE + '</style>',
           '<defs><marker id="arrow" markerWidth="9" markerHeight="9" refX="8" refY="4.5" '
           'orient="auto" markerUnits="userSpaceOnUse"><path d="M0 0 L9 4.5 L0 9" '
           'fill="#334e70"/></marker></defs>']
    details = []

    for transition in transitions:
        reference = transition["relation_reference"]
        state = transition["state"]

        if state not in {"CONFIRMED", "LIKELY", "POTENTIAL", "BLOCKED", "UNKNOWN"}:
            raise ValueError("selected transition has an unsupported state")

        path, label_x, label_y = EdgeGeometry(positions[transition["source_reference"]],
                                            positions[transition["target_reference"]])
        label = state + (" · CUT" if reference in cuts else "")
        svg.append(f'<a class="edge inspect {state}" href="#{Anchor(reference)}" '
            f'aria-label="{escape(label + " " + reference, quote=True)}">'
            f'<path d="{path}" marker-end="url(#arrow)"/>'
            f'<text x="{label_x}" y="{label_y}" '
            f'text-anchor="middle" textLength="{len(label) * 8}" '
            f'lengthAdjust="spacingAndGlyphs">{escape(label)}</text></a>')
        details.append(f'<details id="{Anchor(reference)}" open><summary>'
            f'{escape(label + " " + reference)}</summary><pre>'
            f'{escape(CanonicalModelJson(transition).decode("utf-8"))}</pre></details>')

    for reference in sorted(references):
        x, y = positions[reference]
        role = "SOURCE" if reference == search["source_reference"] else (
            "TARGET" if reference == search["target_reference"] else "")
        label = str(kinds[reference]) + (" · " + role if role else "")
        cut = reference in cuts
        suffix = " · CUT" if cut else ""
        svg.append(f'<a class="node inspect{" cut" if cut else ""}" '
            f'href="#{Anchor(reference)}" '
            f'aria-label="{escape(label + " " + reference, quote=True)}">'
            f'<rect x="{x - 100}" y="{y - 30}" width="200" height="60" rx="9"/>'
            f'<text x="{x}" y="{y - 6}" text-anchor="middle" '
            f'textLength="{len(label + suffix) * 7}" lengthAdjust="spacingAndGlyphs">'
            f'{escape(label + suffix)}</text>'
            f'<text x="{x}" y="{y + 16}" text-anchor="middle" textLength="140" '
            f'lengthAdjust="spacingAndGlyphs">'
            f'{escape(reference[:19] + "…")}</text></a>')
        details.append(f'<details id="{Anchor(reference)}" open><summary>{escape(label + suffix)}'
            f'</summary><p><code>{escape(reference)}</code></p><p>'
            'Object kind and reference come from the exact saved model. Attributes, raw evidence '
            'and inferred attack semantics are not rendered.</p></details>')

    svg.append('</svg>')

    return "".join(svg), "".join(details)


def RenderPathHtml(outcome: dict[str, object], model: ModelState) -> str:
    """Present one completed original path outcome without any I/O or inference.

    Args:
        outcome: Exact successful bounded schema-one command outcome, not a replacement analysis.
        model: Same complete immutable owner-read saved model that produced the verified outcome.

    Returns:
        Deterministic self-contained UTF-8 HTML with exact JSON and standalone SVG downloads.

    Raises:
        ValueError: Outcome is not completed or the graph/artifact exceeds presentation bounds.
    """

    if outcome.get("status") != "completed" or not isinstance(outcome.get("analysis"), dict):
        raise ValueError("offline presentation requires a completed owning analysis")

    document = cast(dict[str, Any], outcome)
    svg, details = GraphSvg(document, model)
    analysis = document["analysis"]
    raw = CanonicalModelJson(outcome) + b"\n"
    embedded = raw.decode("utf-8").replace("&", "\\u0026").replace("<", "\\u003c").replace(
        ">", "\\u003e").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode("ascii")
    csp = ("default-src 'none'; script-src 'sha256-" + script_hash + "'; "
           "style-src 'unsafe-inline'; "
           "base-uri 'none'; form-action 'none'; frame-src 'none'; object-src 'none'")
    summary = {key: value for key, value in document.items() if key != "analysis"}
    html = '<!doctype html><html lang="en"><head><meta charset="utf-8">' + (
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{escape(csp, quote=True)}">'
        '<title>1337 selected-path analysis</title><style>' + STYLE + '</style></head><body>'
        '<h1>Selected-path analysis</h1><p>Original hop attestations and structural cuts only. '
        'Physical access, global completeness and remediation efficacy remain unassessed.</p>'
        '<section class="panel"><h2>Analysis bounds</h2><p>Returned candidate paths: '
        f'{len(analysis["search"]["paths"])}; enumeration complete: '
        f'{str(analysis["search"]["complete"]).lower()}; verified structural cuts: '
        f'{len(analysis["cuts"]["verified"])}; cut checks complete: '
        f'{str(analysis["cuts"]["complete"]).lower()}.</p>'
        '<p>UNKNOWN transitions remain possible selected candidates; this does not establish '
        'access. Search and independent cut checks have separate completeness and budgets.</p>'
        '<ul class="legend" aria-label="Transition state legend">'
        '<li><span>CONFIRMED</span></li><li><span class="likely">LIKELY</span></li>'
        '<li><span class="potential">POTENTIAL</span></li>'
        '<li><span class="blocked">BLOCKED</span></li>'
        '<li><span class="unknown">UNKNOWN</span></li></ul></section>'
        '<div aria-label="Graph view controls"><button id="zoom-in" type="button">Zoom in</button>'
        '<button id="zoom-out" type="button">Zoom out</button>'
        '<button id="reset-view" type="button">Reset view</button></div>'
        '<p>Drag the graph background to pan; scroll or use buttons to zoom. Select a node or '
        'edge to inspect original references and attribution below. All explanations are also '
        'available as ordinary expandable text.</p><noscript>Interactive controls are disabled. '
        'The original static graph, explanations and downloads remain available.</noscript>' + svg +
        '<p>' + Download(raw, "application/json", "path-analysis.json", "Download exact JSON") +
        Download(svg.encode(), "image/svg+xml", "path-analysis.svg", "Download static SVG") + '</p>'
        '<h2>Original selected nodes and transitions</h2>' + details +
        '<details open><summary>Paths, independent cuts, coverage and original reasons</summary>'
        '<pre>' + escape(CanonicalModelJson(analysis).decode("utf-8")) + '</pre></details>'
        '<details><summary>Exact saved basis and attribution</summary><pre>' +
        escape(CanonicalModelJson(summary).decode("utf-8")) + '</pre></details>'
        '<script id="analysis-json" type="application/json">' + embedded + '</script>'
        '<script id="path-controls">' + SCRIPT + '</script></body></html>\n')

    if len(html.encode("utf-8")) > MAX_HTML_BYTES:
        raise ValueError("offline artifact exceeds presentation byte limit")

    return html
