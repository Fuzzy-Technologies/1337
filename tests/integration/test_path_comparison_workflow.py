# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual original pair admission, final owner bases and portable read-only comparison failures."""

from __future__ import annotations

import base64
import json
import re
import shutil
import socket
import subprocess
from dataclasses import replace
from io import StringIO

import pytest

from fuzzy1337 import path_comparison_commands as commands
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from fuzzy1337.path_commands import RunPathCommands
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.contract.reachability_fixture import Fixture
from tests.contract.test_path_comparison_contract import OriginalArguments, PairArguments
from tests.path_command_helpers import Files, Run, Value


def Setup(tmp_path):
    """Acquire independent original before/after assertions over one actual saved model."""

    fixture = Fixture.Create(tmp_path / "workspace")
    before, after = fixture.Phase("confirmed"), fixture.Phase("remediation")

    return fixture, before, after


def Refuse(*args, **kwargs):
    """Trip any persistence, process or network operation during the paired read-only query."""

    raise AssertionError("Read-only pair attempted owner writes, network or process execution.")


def Html(arguments):
    """Invoke the common product route with explicit paired static presentation."""

    output = StringIO()
    status = RunPathCommands([*arguments, "--html"], output)

    return status, output.getvalue()


def test_ActualStaticPairKeepsOriginalProofAndReopensAfterRelocation(tmp_path, monkeypatch):
    """Both original owner analyses and exact paired artifacts survive relocation without writes."""

    fixture, before, after = Setup(tmp_path)
    arguments = PairArguments(fixture, before, after)
    _, original_before = Run(OriginalArguments(fixture, before))
    _, original_after = Run(OriginalArguments(fixture, after))
    retained = Files(fixture.root)
    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    monkeypatch.setattr(LocalWorkspaceStore, "Save", Refuse)
    monkeypatch.setattr(LocalEvidenceStore, "Put", Refuse)
    monkeypatch.setattr(socket, "socket", Refuse)
    monkeypatch.setattr(subprocess, "Popen", Refuse)
    status, paired = Run(arguments)
    html_status, html = Html(arguments)
    assert status == html_status == 0 and paired["before"] == original_before and paired[
        "after"
    ] == original_after, "Actual comparison substituted a supplied or reconstructed graph."
    download = re.search(r'download="path-comparison.json" href="data:application/json;'
                         r'base64,([^"]+)"', html).group(1)
    assert json.loads(base64.b64decode(download)) == paired and "<script" not in html, (
        "Static artifact changed original paired output or added a script."
    )
    assert "synthetic-private-source-value" not in html and "_seal" not in html, (
        "Comparison copied private raw witnesses or internal verification seals."
    )
    moved = tmp_path / "relocated"
    shutil.move(fixture.root, moved)
    fixture.root = moved
    moved_status, moved_pair = Run(PairArguments(fixture, before, after))
    moved_html_status, moved_html = Html(PairArguments(fixture, before, after))
    assert moved_status == moved_html_status == 0 and moved_pair == paired and moved_html == html, (
        "Relocation changed exact original pairing, IDs or static artifacts."
    )
    assert Files(moved) == retained, "Paired query wrote saved owner or original evidence bytes."


@pytest.mark.parametrize("side", ["before", "after"])
def test_CorruptOriginalSideRefusesWholePairWithoutPartialHtmlOrJson(tmp_path, side):
    """A second-side failure cannot preserve a successful first-only paired artifact."""

    fixture, before, after = Setup(tmp_path)
    record = before[0] if side == "before" else after[0]
    blob = fixture.root / "evidence" / record.reference.locator
    blob.write_bytes(b"x" * record.reference.size_bytes)
    retained = Files(fixture.root)
    status, result = Run(PairArguments(fixture, before, after))
    html_status, html = Html(PairArguments(fixture, before, after))
    assert status == html_status == 4 and result["failure"] == side + "-analysis" and (
        result["before"] is None and result["after"] is None and "<!doctype" not in html
    ), "A corrupt source side escaped as partial or successful comparison."
    assert Files(fixture.root) == retained, "Failed pair repaired or changed original source bytes."


@pytest.mark.parametrize("when", ["between", "after", "workspace"])
def test_RealOwnerBasisDriftBetweenOrAfterAnalysesRefusesPair(tmp_path, monkeypatch, when):
    """Actual saved model/workspace changes cannot inherit either original side's success."""

    fixture, before, after = Setup(tmp_path)
    original = commands.AnalyzeSide

    def Analyze(arguments, side):
        """Change a real owning store after an independently completed original side."""

        result = original(arguments, side)

        if (when == "between" and side == "before") or (when != "between" and side == "after"):
            if when == "workspace":
                owner = LocalWorkspaceStore(fixture.root)
                state = owner.Open()
                owner.Save(replace(state, configuration=replace(state.configuration,
                                                               display_name="Changed owner")))

            else:
                store = LocalModelStore(fixture.root)
                state = store.Open()
                store.Save(replace(state, revision=state.revision + 1),
                           expected_revision=state.revision)

        return result

    monkeypatch.setattr(commands, "AnalyzeSide", Analyze)
    status, result = Run(PairArguments(fixture, before, after))
    assert status == 4 and result["before"] is None and result["after"] is None, (
        "Changed saved bases inherited a completed paired result."
    )
    assert result["failure"] == ("after-analysis" if when == "between" else "basis-changed"), (
        "Basis refusal occurred outside the independently verified owner/final-reread contract."
    )


@pytest.mark.parametrize("side,failure,status", [("before", KeyboardInterrupt, 130),
    ("after", KeyboardInterrupt, 130), ("after", OSError, 4)])
def test_EnteredSideExceptionsNeverReturnPartialPair(tmp_path, monkeypatch, side, failure, status):
    """Interruptions and unexpected read failures keep both nested original outcomes unavailable."""

    fixture, before, after = Setup(tmp_path)
    original = commands.AnalyzeSide

    def Analyze(arguments, selected_side):
        """Interrupt only the explicitly selected owner boundary with untrusted exception text."""

        if selected_side == side:
            raise failure("untrusted-path-value")

        return original(arguments, selected_side)

    monkeypatch.setattr(commands, "AnalyzeSide", Analyze)
    code, result = Run(PairArguments(fixture, before, after))
    assert code == status and result["before"] is None and result["after"] is None and (
        "untrusted-path-value" not in json.dumps(result)
    ), "An exceptional side leaked paths or exposed a successful partial pair."


def test_StalePinAndZeroChangeHumanOutputHaveHonestSeparateMeanings(tmp_path):
    """A stale pin fails; repeated original selection completes without a state change."""

    fixture, before, after = Setup(tmp_path)
    status, refused = Run(Value(PairArguments(fixture, before, after),
                                "--expected-snapshot-sha256", "0" * 64))
    assert status == 4 and refused["failure"] == "basis", "A stale model pin was silently updated."
    output = StringIO()
    status = RunPathCommands(PairArguments(fixture, before, before), output)
    assert status == 0 and "No observed transition-state change" in output.getvalue(), (
        "Equal original states were called remediation or unsupported failure."
    )
    output = StringIO()
    status = RunPathCommands(PairArguments(fixture, before, after), output)
    assert status == 0 and "Observed focus state change" in output.getvalue() and (
        "causality and remediation efficacy are unassessed" in output.getvalue()
    ), "Human comparison converted a focus label change into efficacy."
