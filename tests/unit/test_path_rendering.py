# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure presentation tests use detached DTOs without claiming original source verification."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from html import unescape

import pytest

from fuzzy1337 import path_rendering as rendering
from fuzzy1337.model import (
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Relation,
    RelationKind,
    SecurityObject,
)
from tests.integration.test_path_rendering_browser import ScriptCoverage


def Presentation(count=5):
    """Construct a tiny detached view fixture, never a replacement for source-owner acceptance."""

    provenance = ModelProvenance("owned.graph", "run:unit", "2026-11-03T00:00:00Z",
                                "scope:owned", "target:owned")
    objects = tuple(SecurityObject(ObjectIdentity("owned", ObjectKind.ASSET, "node:" + str(index)),
                    provenance=(provenance,)) for index in range(count))
    references = tuple(item.Reference() for item in objects)
    states = ("UNKNOWN", "POTENTIAL", "LIKELY", "CONFIRMED", "BLOCKED")
    transitions = [{"source_reference": references[index],
        "target_reference": references[(index + 1) % len(objects)],
        "relation_reference": "relation:" + f"{index:064x}", "state": states[index % len(states)],
        "reasons": ["original-reason"], "claims": []} for index in range(count)]
    document = {"status": "completed", "schema_version": 1, "analysis": {
        "transitions": transitions, "search": {"source_reference": references[0],
            "target_reference": references[-1], "paths": [], "complete": False},
        "cuts": {"verified": [{"kind": "node", "reference": references[1]},
            {"kind": "relation", "reference": transitions[2]["relation_reference"]}],
            "complete": True}}}

    return document, ModelState("owned", objects=objects)


def test_DeterministicSvgRetainsStatesOriginalRefsAndScriptHash():
    """Presentation preserves exact DTO values while its fixed script has an explicit CSP pin."""

    document, model = Presentation()
    html = rendering.RenderPathHtml(document, model)
    assert html == rendering.RenderPathHtml(document, model), "Presentation is not deterministic"
    embedded = re.search(r'<script id="analysis-json" type="application/json">(.*?)</script>',
                         html, re.DOTALL).group(1)
    assert json.loads(embedded) == document, "Embedded JSON changed original explanation values"

    for transition in document["analysis"]["transitions"]:
        assert transition["state"] in html and transition["relation_reference"] in html, (
            "A selected transition's original state/reference disappeared"
        )

    expected_hash = base64.b64encode(hashlib.sha256(rendering.SCRIPT.encode()).digest()).decode()
    assert "sha256-" + expected_hash in html and "default-src &#x27;none&#x27;" in html, (
        "Offline controls lost the exact fixed script or deny-network CSP"
    )
    assert "· CUT" in html and "enumeration complete: false" in html and (
        "cut checks complete: true" in html
    ), "Presentation merged structural cuts, independent completeness or source uncertainty"
    raw = re.search(r'download="path-analysis.json" href="data:application/json;base64,([^"]+)"',
                    html).group(1)
    assert base64.b64decode(raw) == rendering.CanonicalModelJson(document) + b"\n", (
        "JSON download is not the original exact canonical command outcome"
    )
    svg_raw = re.search(r'download="path-analysis.svg" href="data:image/svg\+xml;base64,([^"]+)"',
                        html).group(1)
    assert base64.b64decode(svg_raw).decode() == rendering.GraphSvg(document, model)[0], (
        "Static SVG download uses a separately maintained graph"
    )


@pytest.mark.parametrize("value", ["</script><script>alert(1)</script>",
    '<img src="https://invalid.example/remote" onerror="alert(1)">',
    '" onfocus="alert(1) & <tag>', "\u2028\u2029"])
def test_ContextAndReasonMarkupNeverBecomesExecutable(value):
    """Source text cannot close JSON script, create attributes or add remote resources."""

    document, model = Presentation()
    document["context_reference"] = value
    document["analysis"]["transitions"][0]["reasons"] = [value]
    html = rendering.RenderPathHtml(document, model)
    assert len(re.findall(r"<script\b", html)) == 2 and "<img" not in html, (
        "Source-controlled explanation added executable markup"
    )
    embedded = re.search(r'<script id="analysis-json" type="application/json">(.*?)</script>',
                         html, re.DOTALL).group(1)
    assert "<" not in embedded and "\u2028" not in embedded and "\u2029" not in embedded, (
        "JSON script context retained a terminator or raw line separator"
    )
    assert json.loads(embedded) == document and (
        json.dumps(value, ensure_ascii=False) in unescape(html)
    ), (
        "Safe rendering altered or suppressed original explanation text"
    )


@pytest.mark.parametrize("mutation", ["failed", "missing", "foreign", "state", "nodes", "edges",
                                      "bytes"])
def test_InvalidOrOversizedPresentationRefusesBeforeReturningArtifact(monkeypatch, mutation):
    """No malformed owner DTO or exceeded finite profile produces partial successful HTML."""

    document, model = Presentation()

    if mutation == "failed":
        document["status"] = "failed"

    elif mutation == "missing":
        document["analysis"] = None

    elif mutation == "foreign":
        model = ModelState("owned")

    elif mutation == "state":
        document["analysis"]["transitions"][0]["state"] = 'UNKNOWN" onclick="alert(1)'

    else:
        field = {"nodes": "MAX_RENDER_NODES", "edges": "MAX_RENDER_TRANSITIONS",
                 "bytes": "MAX_HTML_BYTES"}[mutation]
        monkeypatch.setattr(rendering, field, 1)

    with pytest.raises(ValueError):
        rendering.RenderPathHtml(document, model)


def test_LayoutKeepsCyclicSelfAndDisconnectedOriginalReferencesFinite():
    """Deterministic presentation rank never labels unreachable or blocked nodes as access."""

    transitions = [{"source_reference": "a", "target_reference": "a"},
                   {"source_reference": "a", "target_reference": "b"},
                   {"source_reference": "b", "target_reference": "a"}]
    positions, width, height = rendering.Layout(("a", "b", "c"), transitions, "a")
    assert set(positions) == {"a", "b", "c"} and positions["a"][0] < positions["b"][0] < (
        positions["c"][0]
    ) and width > 0 and height > 0, "Presentation lost a cyclic/disconnected original endpoint"


@pytest.mark.parametrize("source,target", [((120, 80), (380, 80)),
    ((120, 80), (120, 220)), ((120, 80), (120, 80))])
def test_OppositeAndSelfTransitionsHaveFiniteDistinctCurves(source, target):
    """Every actual directed case retains a geometry instead of hiding its reverse transition."""

    forward = rendering.EdgeGeometry(source, target)
    reverse = rendering.EdgeGeometry(target, source)
    assert len(forward) == 3 and all(isinstance(item, int) for item in forward[1:]), (
        "Directed geometry lost finite deterministic label coordinates"
    )

    if source != target:
        assert forward[0] != reverse[0] and forward[1:] != reverse[1:], (
            "Opposite transitions share the same visible state label/curve"
        )

    else:
        assert forward[2] >= 16, "A first-row self-loop label is clipped above the SVG viewport"


@pytest.mark.parametrize("count", [64, 65])
def test_ActualNodePresentationCeilingIsInclusiveAndNeverPartitions(count):
    """All 64 selected endpoints render; a 65th cannot silently disappear into a partial graph."""

    document, model = Presentation(count)

    if count > 64:
        with pytest.raises(ValueError, match="profile"):
            rendering.RenderPathHtml(document, model)

    else:
        html = rendering.RenderPathHtml(document, model)
        assert len(re.findall(r'class="node inspect', html)) == count, (
            "The supported node ceiling omitted an original selected endpoint"
        )


@pytest.mark.parametrize("count", [128, 129])
def test_ActualTransitionCeilingRetainsAllOriginalDirectedEdges(count):
    """Unique canonical edges at the inclusive ceiling render; exceeding it refuses the artifact."""

    document, model = Presentation(64)
    objects = model.objects
    selected = [(source, target) for source in objects for target in objects if source != target]
    transitions = []

    for source, target in selected[:count]:
        relation = Relation(RelationKind.RELATED_TO, source.Reference(), target.Reference(),
                            provenance=source.provenance)
        transitions.append({"source_reference": source.Reference(),
            "target_reference": target.Reference(), "relation_reference": relation.Reference(),
            "state": "UNKNOWN", "reasons": ["unassessed"], "claims": []})

    document["analysis"]["transitions"] = transitions

    if count > 128:
        with pytest.raises(ValueError, match="profile"):
            rendering.RenderPathHtml(document, model)

    else:
        html = rendering.RenderPathHtml(document, model)
        assert len(re.findall(r'class="edge inspect', html)) == count, (
            "The supported transition ceiling omitted original directed transitions"
        )


def test_V8BlockAccountingHonorsUnexecutedInnerBranchAndExecutedNestedRange():
    """Handwritten V8-style ranges detect missed branches despite an executed enclosing function."""

    functions = [{"ranges": [{"startOffset": 0, "endOffset": 10, "count": 1},
        {"startOffset": 2, "endOffset": 8, "count": 0},
        {"startOffset": 4, "endOffset": 6, "count": 1}]}]
    assert ScriptCoverage(functions, 10) == 0.6, (
        "Coverage arithmetic hid unexecuted inner blocks behind an executed parent"
    )
    assert rendering.SCRIPT.isascii(), "UTF-16 coverage offsets no longer equal script characters"
