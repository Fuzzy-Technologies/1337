# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure paired-presentation checks; synthetic DTOs do not establish original source admission."""

from __future__ import annotations

import base64
import builtins
import json
import re
import socket
from copy import deepcopy
from html import unescape

import pytest

from fuzzy1337 import path_comparison as comparison
from fuzzy1337.model import (
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Relation,
    RelationKind,
    SecurityObject,
)
from fuzzy1337.path_rendering import GraphSvg
from fuzzy1337.reachability import ReachabilityModelVersion


def Presentation(count=3, edges=None):
    """Construct bounded presentation-only originals over genuine canonical object identities."""

    provenance = ModelProvenance("owned.graph", "run:unit", "2026-11-03T00:00:00Z",
                                "scope:owned", "target:owned")
    objects = tuple(SecurityObject(ObjectIdentity("owned", ObjectKind.ASSET, "node:" + str(index)),
                    provenance=(provenance,)) for index in range(count))
    coordinates = [(index, index + 1) for index in range(count - 1)] if edges is None else edges
    relations = tuple(Relation(RelationKind.RELATED_TO, objects[left].Reference(),
                               objects[right].Reference(), provenance=(provenance,))
                      for left, right in coordinates)
    model = ModelState("owned", objects=objects, relations=relations)
    version = ReachabilityModelVersion.FromModel(model)
    outcome = {"schema_version": 1, "command": "paths.analyze", "status": "completed",
        "failure": None, "exit_code": 0, "context_reference": "owned:comparison",
        "scope_reference": "scope:owned", "as_of": "2026-11-03T00:00:00+00:00",
        "max_age_seconds": 3600, "assessment_manifest_ids": [],
        "model_version": {"schema_version": version.schema_version,
            "workspace_id": version.workspace_id, "revision": version.revision,
            "snapshot_sha256": version.snapshot_sha256},
        "analysis": {"transitions": [{"relation_reference": relation.Reference(),
            "source_reference": relation.source_reference,
            "target_reference": relation.target_reference, "state": "UNKNOWN", "claims": [],
            "reasons": ["unassessed"]} for relation in relations],
            "search": {"source_reference": objects[0].Reference(),
                "target_reference": objects[-1].Reference(), "paths": [], "complete": False,
                "limits": {"max_depth": 16, "max_paths": 64, "max_work": 4096,
                           "max_frontier": 1024}},
            "cuts": {"verified": [], "complete": True, "max_cut_work": 100000}}}

    return outcome, model, relations[0].Reference()


def Pair():
    """Create a literal single-focus state difference, retaining separate source facts."""

    before, model, focus = Presentation()
    after = deepcopy(before)
    after["analysis"]["transitions"][0]["state"] = "BLOCKED"
    after["assessment_manifest_ids"] = ["sha256:" + "a" * 64]

    return comparison.ComparePathOutcomes(before, after, model, focus_transition=focus), model


def test_PureDetachedPairAndStaticArtifactRetainEveryOriginalWithoutIo(monkeypatch):
    """Pure comparison/presentation retains original UNKNOWN and independent completeness."""

    before, model, focus = Presentation()
    after = deepcopy(before)
    after["analysis"]["transitions"][0]["state"] = "BLOCKED"

    def Refuse(*args, **kwargs):
        """Trip unadvertised storage/network activity inside pure comparison and rendering."""

        raise AssertionError("Pure path comparison attempted I/O.")

    monkeypatch.setattr(builtins, "open", Refuse)
    monkeypatch.setattr(socket, "socket", Refuse)
    result = comparison.ComparePathOutcomes(before, after, model, focus_transition=focus)
    html = comparison.RenderPathComparisonHtml(result, model)
    assert result["before"] == before and result["after"] == after, "Original outcomes changed."
    assert result["state_changes"] == [{"relation_reference": focus, "before_state": "UNKNOWN",
                                        "after_state": "BLOCKED"}], "Focus labels were composed."
    before["analysis"]["transitions"][0]["state"] = "CONFIRMED"
    assert result["before"]["analysis"]["transitions"][0]["state"] == "UNKNOWN", (
        "Returned comparison still aliases its mutable caller input."
    )
    assert "enumeration complete: false" in html and "cut checks complete: true" in html and (
        "UNKNOWN" in html and "remediation efficacy are unassessed" in html
    ), "Static presentation lost uncertainty, separate completeness or its claim boundary."
    assert "<script" not in html and "<iframe" not in html and html.count("<img ") == 2, (
        "Static comparison introduced script/frames or omitted an isolated graph."
    )
    raw = re.search(r'download="path-comparison.json" href="data:application/json;base64,([^"]+)"',
                    html).group(1)
    assert base64.b64decode(raw) == comparison.CanonicalModelJson(result) + b"\n", (
        "Paired download differs from its exact machine outcome."
    )

    for label, original in (("before", result["before"]), ("after", result["after"])):
        encoded = re.search('download="' + label + r'-path.svg" href="data:image/svg\+xml;'
                            r'base64,([^"]+)"', html).group(1)
        assert base64.b64decode(encoded).decode() == GraphSvg(original, model)[0], (
            "Static SVG download is not the original graph producer output."
        )


@pytest.mark.parametrize("case", ["status", "command", "schema", "exit", "pin", "bytes",
    "empty", "duplicate", "foreign", "endpoint", "state", "focus", "nodes", "edges",
    "context", "scope", "clock", "age", "source", "target", "limits", "cuts", "selection",
    "unrelated"])
def test_CompletedBasisSelectionAndOneFocusProfileCannotBeBypassed(case):
    """Presentation admission refuses malformed, mismatched or over-budget synthetic owner DTOs."""

    if case == "nodes":
        before, model, focus = Presentation(65)

    elif case == "edges":
        before, model, focus = Presentation(12, [(left, right) for left in range(12)
                                                 for right in range(12)][:129])

    else:
        before, model, focus = Presentation()

    after = deepcopy(before)
    fields = {"status": "status", "command": "command", "schema": "schema_version",
              "exit": "exit_code", "pin": "model_version"}

    if case in fields:
        after[fields[case]] = "invalid"

    elif case == "bytes":
        after["oversized"] = "x" * (1024 * 1024)

    elif case == "empty":
        after["analysis"]["transitions"] = []

    elif case == "duplicate":
        after["analysis"]["transitions"].append(after["analysis"]["transitions"][0])

    elif case in ("foreign", "endpoint", "state"):
        field = {"foreign": "relation_reference", "endpoint": "source_reference",
                 "state": "state"}[case]
        after["analysis"]["transitions"][0][field] = "invalid"

    elif case == "focus":
        focus = "relation:" + "0" * 64

    elif case in ("context", "scope", "clock", "age"):
        field = {"context": "context_reference", "scope": "scope_reference", "clock": "as_of",
                 "age": "max_age_seconds"}[case]
        after[field] = "different"

    elif case in ("source", "target", "limits"):
        field = case + "_reference" if case != "limits" else case
        after["analysis"]["search"][field] = "different"

    elif case == "cuts":
        after["analysis"]["cuts"]["max_cut_work"] = 1

    elif case == "selection":
        after["analysis"]["transitions"].pop()

    elif case == "unrelated":
        after["analysis"]["transitions"][1]["state"] = "BLOCKED"

    with pytest.raises(ValueError):
        comparison.ComparePathOutcomes(before, after, model, focus_transition=focus)


@pytest.mark.parametrize("hostile", ['</script><script>alert(1)</script>',
    '<img src="https://example.invalid/" onerror="alert(1)">', '" & <tag>', "\u2028\u2029"])
def test_StaticProofTextDoesNotCreateMarkupOrExternalResources(hostile):
    """Original source strings stay exact text in proof panels and machine downloads."""

    before, model, focus = Presentation()
    before["context_reference"] = hostile
    after = deepcopy(before)
    result = comparison.ComparePathOutcomes(before, after, model, focus_transition=focus)
    html = comparison.RenderPathComparisonHtml(result, model)
    assert "<script" not in html and html.count("<img ") == 2 and (
        'src="https://' not in html and json.dumps(hostile, ensure_ascii=False) in unescape(html)
    ), "Source text created executable markup, a resource, or lost its exact original value."
    assert "No observed transition-state change" in html, "Zero differences became a state change."


def test_WholeJsonAndHtmlCeilingsRefuseInsteadOfReturningPartialArtifact(monkeypatch):
    """Defensive pair-size and actual escaped HTML growth each fail the complete operation."""

    result, model = Pair()
    monkeypatch.setattr(comparison, "MAX_COMPARISON_JSON_BYTES", 10)

    with pytest.raises(ValueError, match="complete JSON budget"):
        comparison.ComparePathOutcomes(result["before"], result["after"], model,
                                       focus_transition=result["focus_transition"])

    monkeypatch.undo()
    before, model, focus = Presentation()
    before["long_escaped_original"] = "&" * 800000
    after = deepcopy(before)
    large = comparison.ComparePathOutcomes(before, after, model, focus_transition=focus)

    with pytest.raises(ValueError, match="complete HTML budget"):
        comparison.RenderPathComparisonHtml(large, model)

    result["observed_state_change"] = False

    with pytest.raises(ValueError, match="unchanged original comparison"):
        comparison.RenderPathComparisonHtml(result, model)


@pytest.mark.parametrize("state", ["CONFIRMED", "LIKELY", "POTENTIAL", "BLOCKED", "UNKNOWN"])
@pytest.mark.parametrize("focus_index", [0, 1])
def test_ReadableFocusStateAndIndentedProofRetainExactOriginalValues(state, focus_index):
    """Readable state words come from each original focus, including unchanged UNKNOWN."""

    before, model, _ = Presentation()
    focus = before["analysis"]["transitions"][focus_index]["relation_reference"]
    before["analysis"]["transitions"][focus_index]["state"] = state
    result = comparison.ComparePathOutcomes(before, deepcopy(before), model, focus_transition=focus)
    originalBytes = comparison.CanonicalModelJson(result)
    html = comparison.RenderPathComparisonHtml(result, model)
    labels = re.findall(r'<p class="focus-state"><strong>Focus state: ([A-Z]+)</strong></p>', html)
    assert labels == [state, state], "Focus state came from a change summary or another edge."

    for side, label in (("before", "Before"), ("after", "After")):
        rendered = re.search('<details open><summary>' + label
            + r' original proof, UNKNOWN and bounds</summary><pre>(.*?)</pre>', html, re.DOTALL)
        assert rendered is not None, "Readable original proof panel disappeared."
        proof = unescape(rendered.group(1))
        assert json.loads(proof) == result[side] and '\n  "analysis": {' in proof, (
            "Pretty printing changed original proof values or lost two-space indentation."
        )

    raw = re.search(r'download="path-comparison.json" href="data:application/json;base64,([^"]+)"',
                    html).group(1)
    assert base64.b64decode(raw) == originalBytes + b"\n" and comparison.CanonicalModelJson(
        result,
    ) == originalBytes, "Readable presentation changed canonical machine output or exact download."


def test_ReadableChangedFocusLabelsRemainIndependentBeforeAndAfterFacts():
    """A changed pair prints each original state directly instead of a combined summary label."""

    result, model = Pair()
    html = comparison.RenderPathComparisonHtml(result, model)
    assert re.findall(r'Focus state: ([A-Z]+)</strong>', html) == ["UNKNOWN", "BLOCKED"], (
        "Readable changed-focus presentation merged or replaced its original side states."
    )
