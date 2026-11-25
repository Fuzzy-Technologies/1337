# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0
"""Pair two installed wheels on the original 236573-byte SDK Save fixture.

Run: python p67-pair.py BEFORE_PYTHON AFTER_PYTHON OUTPUT
Only Python children and owned temporary saved workspaces are used.
"""
import cProfile
import hashlib
import json
from pathlib import Path
import pstats
import statistics
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

PINS = {"before": "23b2d6f352a2cdbbd9028bb69b171f4c85f5a86f",
        "after": "81847ac121a3aa55a69e12e1e902a1e755eae24f"}
WIRE = "06041ea4379737dc835ba6fb4f8d9f824b22bfb74e483ae390216de243494632"


def Sample(tag, output, profiled=False):
    """Time one full public Save; keep construction, Create and post-save Open outside clocks."""

    from fuzzy1337 import model
    from fuzzy1337.model import (
        LocalModelStore, ModelProvenance, ModelState, ObjectIdentity, ObjectKind, SecurityObject,
    )
    from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

    path = Path(model.__file__).resolve()
    assert path.is_relative_to(Path(sys.prefix).resolve()), "Use the noneditable installed wheel"
    sourceBytes = path.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(sourceBytes)).encode() + b"\0" + sourceBytes).hexdigest()
    assert blob == PINS[tag], "Installed model source differs from the reviewed variant"
    source = ModelProvenance("fixture", "run:saved", "2026-11-25T12:00:00Z",
                             "scope:fixture", "target:owned")
    objects = tuple(SecurityObject(ObjectIdentity("fixture", ObjectKind.ASSET, "asset:" + str(i)),
                                    {"label": str(i)}, (source,)) for i in range(256))
    proposal, _ = ModelState("fixture").Apply(objects=objects)
    assert (len(proposal.objects), len(proposal.observations), proposal.revision) == (256, 256, 1)
    profile = cProfile.Profile()

    with TemporaryDirectory(prefix="owned-", dir=output) as work:
        root = Path(work) / "owned"
        LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Performance fixture"), "fixture")
        store = LocalModelStore(root)
        store.Create()
        cpu, wall = time.process_time_ns(), time.perf_counter_ns()
        committed = (profile.runcall(store.Save, proposal, expected_revision=0) if profiled
                     else store.Save(proposal, expected_revision=0))
        elapsedWall, elapsedCpu = time.perf_counter_ns() - wall, time.process_time_ns() - cpu
        assert store.Open() == committed == proposal, "Saved/reopened snapshot differs"
        payload = (root / "state/model/model.json").read_bytes()
        assert len(payload) == 236573 and hashlib.sha256(payload).hexdigest() == WIRE
        assert payload == model.CanonicalModelJson(proposal.ToDict()) + b"\n", "Wire bytes differ"

    result = {"tag": tag, "model_blob": blob, "python": sys.version, "bytes": 236573,
              "sha256": WIRE, "wall_ms": elapsedWall / 1e6, "cpu_ms": elapsedCpu / 1e6}

    if profiled:
        profile.dump_stats(output / (tag + ".pstats"))
        result["profile"] = [{"file": key[0], "line": key[1], "function": key[2],
                              "calls": value[1], "own_seconds": value[2],
                              "cumulative_seconds": value[3]}
                             for key, value in pstats.Stats(profile).stats.items()
                             if key[2] in {"Reference", "ModelReference", "CanonicalModelJson",
                                           "FromDict", "DecodeModelState", "Save"}]

    return result


def Main():
    """Alternate eleven fresh Save pairs, discard the first pair, then profile each wheel once."""

    if sys.argv[1] == "--sample":
        print(json.dumps(Sample(sys.argv[2], Path(sys.argv[3]), len(sys.argv) == 5)))
        return

    before, after, output = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]).resolve()
    output.mkdir(parents=True, exist_ok=False)
    interpreters = {"before": before, "after": after}
    rows = []

    def Run(tag, profiled=False):
        """Run only the chosen installed-wheel Python; child timing excludes process startup."""

        command = [str(interpreters[tag]), "-I", str(Path(__file__).resolve()),
                   "--sample", tag, str(output)]

        if profiled:
            command.append("--profile")

        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
        assert not result.stderr, "Unexpected child diagnostic"
        return json.loads(result.stdout)

    for pair in range(11):
        for tag in (("before", "after") if pair % 2 == 0 else ("after", "before")):
            rows.append(dict(Run(tag), pair=pair, measured=pair != 0))

    assert len({row["python"] for row in rows}) == 1, "Compare the same Python runtime"
    summaries = {tag: {metric: statistics.median(row[metric] for row in rows
                         if row["tag"] == tag and row["measured"])
                       for metric in ("wall_ms", "cpu_ms")} for tag in PINS}
    result = {"source_pins": PINS, "bytes": 236573, "sha256": WIRE, "timed_pairs": 10,
              "rows": rows, "medians": summaries, "profiles": [Run(tag, True) for tag in PINS]}
    (output / "paired.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key != "rows"}, indent=2))


if __name__ == "__main__":
    Main()
