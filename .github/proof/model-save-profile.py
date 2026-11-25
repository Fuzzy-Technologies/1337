# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0
"""Profile public SDK Save once, beside one unprofiled identical 236573-byte save.

Run with the noneditable wheel's Python: python -I model-save-profile.py OUTPUT
"""
import cProfile
import hashlib
import json
from pathlib import Path
import pstats
import sys
from tempfile import TemporaryDirectory
import time

from fuzzy1337 import model
from fuzzy1337.model import (
    LocalModelStore, ModelProvenance, ModelState, ObjectIdentity, ObjectKind, SecurityObject,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

output = Path(sys.argv[1]).resolve()
output.mkdir(parents=True, exist_ok=False)
module = Path(model.__file__).resolve()
assert module.is_relative_to(Path(sys.prefix).resolve()), "Use a noneditable installed wheel"
raw = module.read_bytes()
blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
assert blob == "23b2d6f352a2cdbbd9028bb69b171f4c85f5a86f", "Model source differs from #539"
source = ModelProvenance(
    "fixture", "run:saved", "2026-11-25T12:00:00Z", "scope:fixture", "target:owned",
)
objects = tuple(SecurityObject(
    ObjectIdentity("fixture", ObjectKind.ASSET, "asset:" + str(index)),
    {"label": str(index)}, (source,),
) for index in range(256))
proposal, _ = ModelState("fixture").Apply(objects=objects)
assert (len(proposal.objects), len(proposal.observations), proposal.revision) == (256, 256, 1)
rows = []
profile = cProfile.Profile()

for label in ("plain", "profiled"):
    with TemporaryDirectory(prefix="owned-", dir=output) as work:
        root = Path(work) / "owned"
        LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Performance fixture"), "fixture")
        store = LocalModelStore(root)
        store.Create()
        cpu, wall = time.process_time_ns(), time.perf_counter_ns()

        if label == "profiled":
            committed = profile.runcall(store.Save, proposal, expected_revision=0)

        else:
            committed = store.Save(proposal, expected_revision=0)

        elapsedWall, elapsedCpu = time.perf_counter_ns() - wall, time.process_time_ns() - cpu
        assert store.Open() == committed == proposal, "Save/Open differ from the proposed snapshot"
        payload = (root / "state/model/model.json").read_bytes()
        assert len(payload) == 236573, "Benchmark payload differs from the original workload"
        assert payload == model.CanonicalModelJson(proposal.ToDict()) + b"\n", "Wire bytes differ"
        rows.append({"label": label, "wall_ms": elapsedWall / 1e6, "cpu_ms": elapsedCpu / 1e6,
                     "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})

assert rows[0]["sha256"] == rows[1]["sha256"], "Paired saves published different bytes"
profile.dump_stats(output / "save.pstats")
stats = pstats.Stats(profile).sort_stats("cumulative")
selected = []
names = {"Save", "PrepareModelState", "DecodeModelState", "FromDict", "__post_init__",
         "Reference", "ModelReference", "CanonicalModelJson", "JsonValue", "FreezeJson",
         "RequireStoredReference", "ValidatePaths", "WorkspaceFields", "UniqueWorkspaceObject"}

for (filename, line, function), (primitive, total, own, cumulative, callers) in stats.stats.items():
    if function not in names and not function.startswith("Validate"):
        continue

    selected.append({"file": filename, "line": line, "function": function,
                     "primitive_calls": primitive, "calls": total,
                     "own_seconds": own, "cumulative_seconds": cumulative,
                     "callers": [{"file": key[0], "line": key[1], "function": key[2],
                                  "stats": list(value) if isinstance(value, tuple) else value}
                                 for key, value in sorted(callers.items())]})

selected.sort(key=lambda item: item["cumulative_seconds"], reverse=True)
result = {"model_blob": blob, "python": sys.version, "rows": rows, "profile": selected,
          "note": "One pair only; profiling adds overhead. Nested cumulative times overlap."}
(output / "profile.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"model_blob": blob, "rows": rows, "profile": [
    {key: value for key, value in item.items() if key != "callers"} for item in selected
]}, indent=2))
stats.print_stats(25)
