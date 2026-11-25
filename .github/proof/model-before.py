"""Reproduce the original local SDK state corruption in new, temporary, operator-owned workspaces."""
from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import fuzzy1337
from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.model import LocalModelStore, ModelProvenance, ModelState, ObjectIdentity, ObjectKind, SecurityObject
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

assert Path(fuzzy1337.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
CONSUMER = "\nimport json\nimport sys\nfrom dataclasses import field, fields, make_dataclass\nfrom pathlib import Path\n\nfrom fuzzy1337.lenses import LensQuery, ResolveLens\nfrom fuzzy1337.model import (\n    LocalModelStore, ModelProvenance, ModelState, ObjectIdentity, ObjectKind, SecurityObject,\n)\nfrom fuzzy1337.reporting import ReportSnapshot\nfrom fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration\n\nroot = Path(sys.argv[1]) / \"owned-workspace\"\nextra = sys.argv[2] == \"extra\"\nLocalWorkspaceStore(root).Create(WorkspaceConfiguration(\"External saved consumer\"), \"fixture\")\nstore = LocalModelStore(root)\nstore.Create()\npath = root / \"state/model/model.json\"\nbefore = path.read_bytes()\nprovenance = ModelProvenance(\n    \"fixture\", \"run:saved\", \"2026-11-25T12:00:00+00:00\",\n    \"scope:fixture\", \"target:\" + \"a\" * 64,\n)\noriginal = SecurityObject(\n    ObjectIdentity(\"fixture\", ObjectKind.HOST, \"127.0.0.1\"),\n    {\"saved\": [1, 2]}, (provenance,),\n)\nadditions = [(\"unversioned\", list[str], field(default_factory=list))] if extra else []\nsubclass = make_dataclass(\n    \"ConsumerHost\", additions, bases=(SecurityObject,), frozen=True, slots=True,\n)\nvalues = {item.name: getattr(original, item.name) for item in fields(original)}\nif extra:\n    values[\"unversioned\"] = [\"retained\"]\nhost = subclass(**values)\nproposal, _ = ModelState(\"fixture\").Apply(objects=(host,))\nsaveError = None\nopenError = None\ncount = None\nviewCount = None\nreportCount = None\ntry:\n    store.Save(proposal, expected_revision=0)\nexcept ValueError:\n    saveError = \"ValueError\"\ntry:\n    reopened = store.Open()\n    count = len(reopened.objects)\n    view = ResolveLens(\"dfir\").Project(reopened, LensQuery(object_kinds=(ObjectKind.HOST,)))\n    viewCount = len(view[\"object_references\"])\n    reportCount = ReportSnapshot(reopened).ToDict()[\"summary\"][\"objects\"]\nexcept ValueError:\n    openError = \"ValueError\"\nprint(json.dumps({\n    \"save_error\": saveError, \"open_error\": openError,\n    \"unchanged\": before == path.read_bytes(),\n    \"writer_lock\": (root / \"state/model/.write-lock\").exists(),\n    \"objects\": count, \"view_objects\": viewCount, \"report_objects\": reportCount,\n}, sort_keys=True))"
for variant in ("extra", "compatible"):
    with TemporaryDirectory() as work:
        result = subprocess.run([sys.executable, "-I", "-c", CONSUMER, work, variant], cwd=work,
                                check=True, capture_output=True, timeout=15)
        facts = json.loads(result.stdout)
        assert not result.stderr and facts["save_error"] is None and facts["writer_lock"] is False
        assert facts["open_error"] == ("ValueError" if variant == "extra" else None), facts
        assert not facts["unchanged"], facts
        if variant == "compatible":
            assert facts["objects"] == facts["view_objects"] == facts["report_objects"] == 1
        print("ORIGINAL_STORED_MODEL", variant, json.dumps(facts, sort_keys=True))

@dataclass(frozen=True)
class TaggedText(str):
    note: str = "tag"

@dataclass(frozen=True)
class TaggedNumber(float):
    note: str = "tag"

class ConsumerState(ModelState):
    pass

for case in ("concrete-text", "concrete-duration", "fallback-text"):
    with TemporaryDirectory() as directory:
        root = Path(directory) / "owned"
        LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned scalar boundary"), "fixture")
        store = LocalModelStore(root)
        store.Create()
        before = (root / "state/model/model.json").read_bytes()
        wid = TaggedText("fixture") if case.endswith("text") else "fixture"
        seconds = TaggedNumber(0.125) if case == "concrete-duration" else 0.125
        provenance = ModelProvenance("fixture", "run:saved", "2026-11-25T12:00:00Z", "scope:fixture",
                                     "target:owned", execution=AdapterExecution(ExecutionState.FAILED, 7, seconds))
        entity = SecurityObject(ObjectIdentity("fixture", ObjectKind.ASSET, "saved:owned"), {}, (provenance,))
        proposal, _ = ModelState(wid).Apply(objects=(entity,))
        if case == "fallback-text":
            proposal = ConsumerState(proposal.workspace_id, proposal.revision, proposal.objects,
                                     proposal.relations, proposal.observations)
        facts = {"case": case, "save": None, "open": None}
        try:
            store.Save(proposal, expected_revision=0)
        except Exception as error:
            facts["save"] = type(error).__name__
        try:
            store.Open()
        except Exception as error:
            facts["open"] = type(error).__name__
        raw = (root / "state/model/model.json").read_bytes()
        facts["changed_original"] = raw != before
        facts["wire_workspace_id"] = json.loads(raw)["workspace_id"]
        facts["writer_lock"] = (root / "state/model/.write-lock").exists()
        print("ORIGINAL_STORED_SCALAR", json.dumps(facts, sort_keys=True))
        assert facts["save"] is None and facts["open"] == "ValueError" and facts["changed_original"], facts
        assert facts["writer_lock"] is False
