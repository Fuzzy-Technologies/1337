#!/usr/bin/env python3
"""Verify the complete unit-local cleanup without running workflows or product acquisition."""

import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

BASE = "36e2409dbf93b187462febf9c14813db40e4f7b0"
TREE = "e29916b43a989eaff463430eaa30520da0fa309b"
GATE = "b9f642abda5c8f945bdb32f059d8ab336e95f004"
NAMING = "1748583602d6eec3e9bb2b2cf417bc2e91038865"
BASELINE = "contracts/python-naming-baseline.json"
MAPS = {
    "tests/unit/test_ci_local_image_product.py": {
        "oracle_path": "oraclePath", "xml_cases": "xmlCases"},
    "tests/unit/test_release_finalize.py": {
        "original_tags": "originalTags", "selected_root": "selectedRoot"},
}


def Git(*arguments):
    return subprocess.run(["git", "--no-replace-objects", *arguments], check=True,
                          capture_output=True, timeout=30).stdout


class Reverse(ast.NodeTransformer):
    def __init__(self, names):
        self.names = names
        self.seen = Counter()

    def visit_Name(self, node):
        if node.id in self.names:
            self.seen[node.id] += 1
            node.id = self.names[node.id]
        return node


def Main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate-directory", type=Path, required=True)
    options = parser.parse_args()
    directory = options.gate_directory.resolve()
    for name, expected in (("passive_test_gate.py", GATE), ("python_naming.py", NAMING)):
        payload = (directory / name).read_bytes()
        assert hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload).hexdigest() == (
            expected
        ), "Reviewed selector/helper blob differs"
    changed = Git("diff", "--no-ext-diff", "--no-textconv", "--ignore-submodules=none",
                  "--no-renames", "--name-status", BASE, TREE).decode().splitlines()
    assert set(changed) == {"M\t" + path for path in (*MAPS, BASELINE)}, "Unexpected changed path"
    summary = {}
    for path, names in MAPS.items():
        before, after = (Git("show", ref + ":" + path) for ref in (BASE, TREE))
        original, candidate = (ast.parse(value, type_comments=True) for value in (before, after))
        assert not any(getattr(node, "id", None) == "pytest_plugins"
                       or getattr(node, "attr", None) == "pytest_plugins"
                       or (isinstance(node, ast.Constant) and node.value == "pytest_plugins")
                       for source in (original, candidate) for node in ast.walk(source)), (
            "Selected source declares shared pytest plugins"
        )
        for replacement in names.values():
            assert re.search(rb"\b" + replacement.encode() + rb"\b", before) is None, (
                "Replacement collides with an original binding"
            )
        reverse = Reverse({new: old for old, new in names.items()})
        restored = reverse.visit(candidate)
        assert ast.dump(original, include_attributes=False) == ast.dump(
            restored, include_attributes=False), "A non-Name AST field or behavior changed"
        restored_bytes = after
        for old, new in names.items():
            restored_bytes = re.sub(rb"\b" + new.encode() + rb"\b", old.encode(), restored_bytes)
        assert restored_bytes == before and set(reverse.seen) == set(names.values()), (
            "Reverse substitution did not restore every exact original byte"
        )
        summary[path] = {"replacements": names, "name_nodes": dict(reverse.seen)}
    before, after = (Git("show", ref + ":" + BASELINE) for ref in (BASE, TREE))
    old, new = (Counter(tuple(row) for row in json.loads(value)) for value in (before, after))
    removed = old - new
    assert sum(removed.values()) == 4 and not new - old and all(
        path in MAPS and kind == "local" and name in MAPS[path]
        for path, kind, scope, name in removed), "Baseline changed outside the four local rows"
    assert Counter({row: count for row, count in old.items()
                    if row[0].startswith("tests/unit/") and row[1] == "local"}) == (
        removed
    ) and not any(row[0].startswith("tests/unit/") and row[1] == "local" for row in new), (
        "Remaining unit local debt was not completely eliminated"
    )
    omitted = Counter()
    lines = []
    for line in before.splitlines(keepends=True):
        text = line.strip().removesuffix(b",")
        if text.startswith(b"[") and text != b"[":
            row = tuple(json.loads(text))
            if removed[row] > omitted[row]:
                omitted[row] += 1
                continue
        lines.append(line)
    assert omitted == removed and b"".join(lines) == after, "Unrelated baseline bytes changed"
    sys.path.insert(0, str(directory))
    import passive_test_gate as gate
    decisions = []

    def Trace(frame, event, value):
        if frame.f_code.co_filename == gate.__file__ and event == "return" and value is False:
            node = frame.f_locals.get("node")
            decisions.append({"function": frame.f_code.co_name, "line": frame.f_lineno,
                              "consumer": frame.f_locals.get("consumer"),
                              "node_line": getattr(node, "lineno", None),
                              "node": ast.dump(node)[:1000] if isinstance(node, ast.AST) else None})
        return Trace

    previous = sys.gettrace()
    sys.settrace(Trace)
    try:
        leaf = gate.LeafTests(tuple(MAPS), TREE)
    finally:
        sys.settrace(previous)
    print(json.dumps({"base": BASE, "tree": TREE, "modules": summary,
                      "baseline_before": old.total(), "baseline_after": new.total(),
                      "removed": list(removed.elements()), "unit_local_remaining": 0,
                      "plugins_absent": True, "tracked_consumers_leaf": leaf,
                      "consumer_diagnostics": decisions,
                      "assessment": "structural-only-not-event-admission-or-runtime-acceptance"},
                     indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
