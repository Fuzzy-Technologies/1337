# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline HTML consumes the actual saved model and original source-owner path explanations."""

from __future__ import annotations

import base64
import json
import re
import shutil
import xml.etree.ElementTree as etree
from io import StringIO

import pytest

from fuzzy1337 import path_commands as commands
from fuzzy1337 import path_rendering as rendering
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    Relation,
    RelationKind,
    SecurityObject,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration
from tests.contract.reachability_fixture import Fixture
from tests.integration.test_path_command_workflow import Selected
from tests.path_command_helpers import Arguments, Files, Run, SmallArguments, SmallGraph, Value


def Html(arguments):
    """Call the actual HTML product handler without bypassing any model/proof admission."""

    output = StringIO()
    status = commands.RunPathCommands([*arguments, "--html"], output)

    return status, output.getvalue()


def Embedded(html):
    """Decode only the inert original JSON outcome from the self-contained product artifact."""

    selected = re.search(r'<script id="analysis-json" type="application/json">(.*?)</script>',
                         html, re.DOTALL)
    assert selected is not None, "Successful HTML omitted its original exact machine outcome"

    return json.loads(selected.group(1))


@pytest.mark.parametrize("phase", ["initial", "potential", "likely", "confirmed", "remediation",
                                  "conflicting-barrier"])
def test_ActualOriginalSixPhaseOutputMatchesJsonAndSurvivesRelocation(tmp_path, phase):
    """Rendering changes no original state, evidence reference, model basis or saved owner bytes."""

    fixture = Fixture.Create(tmp_path / "workspace")
    records = fixture.Phase(phase)
    arguments = Selected(fixture, records)
    before = Files(fixture.root)
    status, original = Run(arguments)
    htmlStatus, html = Html(arguments)
    assert status == htmlStatus == 0 and Embedded(html) == original, (
        "HTML is not a presentation of the actual original selected graph explanation"
    )
    assert "synthetic-private-source-value" not in html and "_seal" not in html, (
        "HTML copied raw witnesses, observation attributes or private verification seals"
    )

    for transition in original["analysis"]["transitions"]:
        assert transition["relation_reference"] in html and transition["state"] in html, (
            "Rendered graph omitted original selected transition provenance/state"
        )

    moved = tmp_path / "moved workspace"
    shutil.move(fixture.root, moved)
    fixture.root = moved
    relocatedStatus, relocated = Html(Selected(fixture, records))
    assert relocatedStatus == 0 and relocated == html and Files(moved) == before, (
        "Standalone selected-graph HTML changed after relocation or mutated original stores"
    )


def test_UnknownCandidatesAndIndependentTruncationRemainVisible(tmp_path):
    """An unassessed depth-truncated enumeration still exposes the independent cut result."""

    context = SmallGraph(tmp_path)
    arguments = Value(SmallArguments(context), "--max-depth", "1")
    status, html = Html(arguments)
    result = Embedded(html)
    assert status == 0 and all(item["state"] == "UNKNOWN"
        for item in result["analysis"]["transitions"]), "Unassessed transitions became confirmed"
    assert "enumeration complete: false" in html and "cut checks complete: true" in html, (
        "HTML combined incomplete enumeration with independently verified structural cuts"
    )


def test_ActualOppositeAttestationsAndSelfLoopKeepIndependentVisibleGeometry(tmp_path):
    """A genuine original BLOCKED edge and CONFIRMED reverse retain distinct inspectable states."""

    fixture = Fixture.Create(tmp_path / "workspace")
    records = fixture.Phase("remediation")
    status, html = Html(Selected(fixture, records))
    assert status == 0, "Original opposite-edge fixture failed owning proof admission"
    svg = re.search(r'(<svg\b.*?</svg>)', html, re.DOTALL).group(1)
    root = etree.fromstring(svg)
    namespace = {"svg": "http://www.w3.org/2000/svg"}
    links = {item.attrib["href"]: item for item in root.findall("svg:a", namespace)}
    forwardRef = fixture.relations["portal-identity"].Reference()
    reverseRef = fixture.relations["identity-portal-cycle"].Reference()
    forward = links["#" + rendering.Anchor(forwardRef)]
    reverse = links["#" + rendering.Anchor(reverseRef)]
    assert "BLOCKED" in forward.attrib["class"] and "CONFIRMED" in reverse.attrib["class"], (
        "Original opposite-edge states were combined or promoted"
    )
    assert forward.find("svg:path", namespace).attrib["d"] != reverse.find(
        "svg:path", namespace).attrib["d"] and forward.find("svg:text", namespace).attrib != (
        reverse.find("svg:text", namespace).attrib
    ), "Opposite original transitions hide each other's visible curve/state label"
    selfRef = fixture.relations["detour-self-cycle"].Reference()
    assert "#" + rendering.Anchor(selfRef) in links, "Original selected self-loop disappeared"


@pytest.mark.parametrize("disconnected", [False, True])
def test_ActualSameRankCurvesAndAllLabelsFitHtmlAndDownloadedStaticSvg(tmp_path, disconnected):
    """Original same-rank edges, reverse curves and self-loops fit the static artifact."""

    root = tmp_path / "owned geometry workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned graph geometry"), "geometry")
    store = LocalModelStore(root)
    initial = store.Create()
    provenance = ModelProvenance("owned.geometry", "run:geometry", "2026-10-14T00:00:00Z",
                                "scope:owned", "target:owned")
    kinds = {"a": ObjectKind.DOMAIN, "b": ObjectKind.SERVICE, "c": ObjectKind.ENDPOINT}

    if disconnected:
        kinds.update({"d": ObjectKind.TECHNOLOGY, "e": ObjectKind.HOST})

    keys = {"a": "geometry.invalid", "e": "127.0.0.1"}
    objects = {alias: SecurityObject(ObjectIdentity(initial.workspace_id, kind,
        keys.get(alias, "owned-geometry:" + alias)), provenance=(provenance,))
        for alias, kind in kinds.items()}
    coordinates = (("a", "b"), ("a", "c"), ("b", "c"), ("c", "b"), ("b", "a"),
                   ("a", "a"), ("b", "b"), ("c", "c"))

    if disconnected:
        coordinates += (("d", "e"), ("e", "d"))

    relations = tuple(Relation(RelationKind.RELATED_TO, objects[source].Reference(),
        objects[target].Reference(), provenance=(provenance,)) for source, target in coordinates)
    changed, _ = initial.Apply(objects=tuple(objects.values()), relations=relations)
    model = store.Save(changed, expected_revision=initial.revision)
    arguments = Arguments(root, model, objects["a"].Reference(), objects["c"].Reference(),
                          tuple(item.Reference() for item in relations))
    before = Files(root)
    status, ordinary = Run(arguments)
    htmlStatus, html = Html(arguments)
    assert status == htmlStatus == 0 and Embedded(html) == ordinary, (
        "Geometry presentation changed the original graph analysis or machine-readable outcome"
    )
    svg = re.search(r'(<svg\b.*?</svg>)', html, re.DOTALL).group(1)
    selected = re.search(r'download="path-analysis.svg" href="data:image/svg\+xml;base64,([^"]+)"',
                         html).group(1)
    downloaded = base64.b64decode(selected).decode("utf-8")
    assert downloaded == svg, "Downloaded static graph is not the same rendered original graph"
    namespace = {"svg": "http://www.w3.org/2000/svg"}

    for artifact in (svg, downloaded):
        document = etree.fromstring(artifact)
        left, top, width, height = map(float, document.attrib["viewBox"].split())
        assert left == top == 0, "Static graph changed its declared finite canvas origin"
        assert len(document.findall("svg:a/svg:path", namespace)) == len(relations), (
            "Geometry bounds fix silently omitted an original transition"
        )

        for path in document.findall("svg:a/svg:path", namespace):
            points = [float(value) for value in re.findall(r'-?\d+(?:\.\d+)?', path.attrib["d"])]
            assert all(0 <= value <= width for value in points[::2]) and all(
                0 <= value <= height for value in points[1::2]
            ), "An original transition's cubic control hull is outside the static canvas"

        for text in document.findall("svg:a/svg:text", namespace):
            x, y = float(text.attrib["x"]), float(text.attrib["y"])
            halfWidth = float(text.attrib["textLength"]) / 2
            assert 0 <= x - halfWidth <= x + halfWidth <= width and (
                0 <= y - 16 <= y + 16 <= height
            ), "An original state or typed-node label is clipped outside the static canvas"

        for rectangle in document.findall("svg:a/svg:rect", namespace):
            x, y = float(rectangle.attrib["x"]), float(rectangle.attrib["y"])
            assert 0 <= x < x + float(rectangle.attrib["width"]) <= width and (
                0 <= y < y + float(rectangle.attrib["height"]) <= height
            ), "An original selected node is clipped outside the static canvas"

    assert Files(root) == before, "Geometry rendering changed the authoritative saved model"


@pytest.mark.parametrize("failure", ["basis", "proof", "limit", "mode"])
def test_ActualRefusalNeverEmitsPartialHtmlOrChangesSavedOwner(tmp_path, monkeypatch, failure):
    """Original proof/model guards and presentation limits fail closed through the product."""

    fixture = Fixture.Create(tmp_path / "workspace")
    records = fixture.Phase("confirmed")
    arguments = Selected(fixture, records)

    if failure == "basis":
        arguments = Value(arguments, "--expected-snapshot-sha256", "a" * 64)

    elif failure == "proof":
        selected = fixture.root / "evidence/blobs/sha256" / records[0].reference.sha256
        selected.write_bytes(b"corrupt owned original")

    elif failure == "limit":
        monkeypatch.setattr(rendering, "MAX_HTML_BYTES", 1)

    before = Files(fixture.root)

    if failure == "mode":
        output = StringIO()
        status = commands.RunPathCommands([*arguments, "--html"], output, json_output=True)
        html = output.getvalue()

    else:
        status, html = Html(arguments)

    assert status == (2 if failure == "mode" else 4) and "<!doctype" not in html, (
        "Failed original admission or presentation produced partial successful HTML"
    )
    assert Files(fixture.root) == before, "Read-only presentation changed original stored owners"
