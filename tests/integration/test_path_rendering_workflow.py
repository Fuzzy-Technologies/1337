# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline HTML consumes the actual saved model and original source-owner path explanations."""

from __future__ import annotations

import json
import re
import shutil
import xml.etree.ElementTree as etree
from io import StringIO

import pytest

from fuzzy1337 import path_commands as commands
from fuzzy1337 import path_rendering as rendering
from tests.contract.reachability_fixture import Fixture
from tests.integration.test_path_command_workflow import Selected
from tests.path_command_helpers import Files, Run, SmallArguments, SmallGraph, Value


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
    html_status, html = Html(arguments)
    assert status == html_status == 0 and Embedded(html) == original, (
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
    relocated_status, relocated = Html(Selected(fixture, records))
    assert relocated_status == 0 and relocated == html and Files(moved) == before, (
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
    forward_ref = fixture.relations["portal-identity"].Reference()
    reverse_ref = fixture.relations["identity-portal-cycle"].Reference()
    forward = links["#" + rendering.Anchor(forward_ref)]
    reverse = links["#" + rendering.Anchor(reverse_ref)]
    assert "BLOCKED" in forward.attrib["class"] and "CONFIRMED" in reverse.attrib["class"], (
        "Original opposite-edge states were combined or promoted"
    )
    assert forward.find("svg:path", namespace).attrib["d"] != reverse.find(
        "svg:path", namespace).attrib["d"] and forward.find("svg:text", namespace).attrib != (
        reverse.find("svg:text", namespace).attrib
    ), "Opposite original transitions hide each other's visible curve/state label"
    self_ref = fixture.relations["detour-self-cycle"].Reference()
    assert "#" + rendering.Anchor(self_ref) in links, "Original selected self-loop disappeared"


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
