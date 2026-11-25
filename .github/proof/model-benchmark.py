"""Compare the original and corrected Save on an identical normal 256-object proposed snapshot."""
import hashlib
import json
from pathlib import Path
import statistics
import sys
import time
from tempfile import TemporaryDirectory
import fuzzy1337
from fuzzy1337.model import LocalModelStore, ModelProvenance, ModelState, ObjectIdentity, ObjectKind, SecurityObject
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

assert Path(fuzzy1337.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
receipt_file = Path(sys.argv[1])
tag = sys.argv[2]
assert tag in ("before","after")
source = ModelProvenance("fixture", "run:saved", "2026-11-25T12:00:00Z", "scope:fixture", "target:owned")
objects = tuple(SecurityObject(ObjectIdentity("fixture", ObjectKind.ASSET, "asset:" + str(i)),
                               {"label": str(i)}, (source,)) for i in range(256))
proposal, delta = ModelState("fixture").Apply(objects=objects)
assert len(proposal.objects) == 256 and len(proposal.observations) == 256 and proposal.revision == 1
rows = []
for i in range(6):
    with TemporaryDirectory() as work:
        root = Path(work) / "owned"
        LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Performance fixture"), "fixture")
        store = LocalModelStore(root)
        store.Create()
        cpu, wall = time.process_time_ns(), time.perf_counter_ns()
        committed = store.Save(proposal, expected_revision=0)
        wall_time, cpu_time = time.perf_counter_ns() - wall, time.process_time_ns() - cpu
        assert store.Open() == committed == proposal
        payload = (root / "state/model/model.json").read_bytes()
        rows.append({"wall_ms": wall_time/1e6, "cpu_ms": cpu_time/1e6, "sha256": hashlib.sha256(payload).hexdigest(),
                     "bytes": len(payload)})
with receipt_file.open("a", encoding="utf-8") as f:
    f.write(json.dumps({"tag":tag, "rows":rows[1:]}, sort_keys=True) + "\n")
