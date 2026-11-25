# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed SDK publication must match the actual saved-state reader."""

import json
import subprocess
import sys

import pytest


CONSUMER = r"""
import json
import sys
from dataclasses import dataclass, field, fields, make_dataclass
from pathlib import Path

from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.lenses import LensQuery, ResolveLens
from fuzzy1337.model import (
    LocalModelStore, ModelProvenance, ModelState, ObjectIdentity, ObjectKind, SecurityObject,
)
from fuzzy1337.reporting import ReportSnapshot
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

@dataclass(frozen=True)
class TaggedText(str):
    note: str = "tag"

@dataclass(frozen=True)
class TaggedNumber(float):
    note: str = "tag"

class PlainText(str):
    pass

class PlainNumber(float):
    pass

class ConsumerState(ModelState):
    pass

root = Path(sys.argv[1]) / "owned-workspace"
case = sys.argv[2]
extra = case == "unsupported-wire"
LocalWorkspaceStore(root).Create(WorkspaceConfiguration("External saved consumer"), "fixture")
store = LocalModelStore(root)
store.Create()
path = root / "state/model/model.json"
before = path.read_bytes()
wid = TaggedText("fixture") if case in ("concrete-text", "fallback-text") else "fixture"
wid = PlainText(wid) if case == "plain-text" else wid
seconds = TaggedNumber(0.125) if case == "concrete-duration" else 0.125
seconds = PlainNumber(seconds) if case == "plain-duration" else seconds
provenance = ModelProvenance(
    "fixture", "run:saved", "2026-11-25T12:00:00+00:00",
    "scope:fixture", "target:" + "a" * 64,
    execution=AdapterExecution(ExecutionState.FAILED, 7, seconds),
)
attributes = (
    {"retained": TaggedText("value")} if case == "readable-attribute" else {"saved": [1, 2]}
)
original = SecurityObject(
    ObjectIdentity("fixture", ObjectKind.HOST, "127.0.0.1"), attributes, (provenance,),
)
additions = [("unversioned", list[str], field(default_factory=list))] if extra else []
subclass = make_dataclass(
    "ConsumerHost", additions, bases=(SecurityObject,), frozen=True, slots=True,
)
values = {item.name: getattr(original, item.name) for item in fields(original)}
if extra:
    values["unversioned"] = ["retained"]
host = subclass(**values) if case in ("unsupported-wire", "compatible-subclass") else original
proposal, _ = ModelState(wid).Apply(objects=(host,))
if case == "fallback-text":
    proposal = ConsumerState(
        proposal.workspace_id, proposal.revision, proposal.objects,
        proposal.relations, proposal.observations,
    )
saveError = None
openError = None
committed = None
count = None
viewCount = None
reportCount = None
same = None
attribute = None
try:
    committed = store.Save(proposal, expected_revision=0)
except ValueError:
    saveError = "ValueError"
try:
    reopened = store.Open()
    count = len(reopened.objects)
    view = ResolveLens("dfir").Project(reopened, LensQuery(object_kinds=(ObjectKind.HOST,)))
    viewCount = len(view["object_references"])
    reportCount = ReportSnapshot(reopened).ToDict()["summary"]["objects"]
    same = reopened == committed if committed is not None else None
    if case == "readable-attribute":
        attribute = dict(reopened.objects[0].attributes["retained"])
except ValueError:
    openError = "ValueError"
print(json.dumps({
    "save_error": saveError, "open_error": openError,
    "unchanged": before == path.read_bytes(),
    "writer_lock": (root / "state/model/.write-lock").exists(),
    "objects": count, "view_objects": viewCount, "report_objects": reportCount,
    "returned_matches_reader": same, "retained_attribute": attribute,
    "wire_workspace_id": json.loads(path.read_bytes())["workspace_id"],
}, sort_keys=True))
"""


@pytest.mark.parametrize("case,refused", [
    ("unsupported-wire", True), ("compatible-subclass", False),
    ("concrete-text", True), ("concrete-duration", True), ("fallback-text", True),
    ("plain-text", False), ("plain-duration", False), ("readable-attribute", False),
])
def test_InstalledSdkSaveReturnsOnlyReadableWireAndPreservesPriorState(tmp_path, case, refused):
    """Use installed SDK classes and final bytes, including concrete scalar regressions."""

    result = subprocess.run(
        [sys.executable, "-I", "-c", CONSUMER, str(tmp_path), case],
        cwd=tmp_path, capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode == 0 and not result.stderr, (
        "The bounded external saved-state consumer must complete without a traceback"
    )
    facts = json.loads(result.stdout)
    expectedCount = 0 if refused else 1
    assert facts == {
        "save_error": "ValueError" if refused else None, "open_error": None,
        "unchanged": refused, "writer_lock": False,
        "objects": expectedCount, "view_objects": expectedCount, "report_objects": expectedCount,
        "returned_matches_reader": None if refused else True,
        "retained_attribute": {"note": "value"} if case == "readable-attribute" else None,
        "wire_workspace_id": "fixture",
    }, f"Save and the actual saved-state readers disagreed about the persisted wire: {facts}"
