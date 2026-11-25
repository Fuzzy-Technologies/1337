#!/usr/bin/env python3
"""Measure a reconstructed leaf subset; keep actual #537 as a shared/full-only control."""

import argparse
import ast
from collections import Counter
from contextlib import contextmanager
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from xml.etree import ElementTree

HISTORICAL = "79912c8467a23f8b806078f5f0738e01eb76d205"
BASE = "84d1101b3de10da09f89881f523a032cd909d696"
SECOND = "b63d113396ff9daa9e7d27dce1512a5306f980d6"
HISTORICAL_TREE = "d799aab5e060546ec022180c4a5f60763671d3f4"
POSITIVE_TREE = "8222fe58b28e90ab123399e73a0769f1685cf209"
LEAF_HEAD = "f23e67750127a74dc05910a820b88456ce9be92e"
LEAF_BASE = "4240f4d94f9d3dfa6bacbf9768e358c2033a2c75"
RUNTIME = "tests/unit/test_runtime_commands.py"
BASELINE = "contracts/python-naming-baseline.json"
CHECKS = ("tests/unit/test_python_style.py", "tests/unit/test_source_documentation_headers.py",
          "tests/unit/test_python_naming.py", "tests/unit/test_passive_test_gate.py",
          "tests/unit/test_passive_integration.py")
ZIP_SHA256 = "450fb3faece7630008c8ff359c36c4d46b49fba60af766e75aff8312bd4d13c7"


def Git(*arguments):
    return subprocess.run(["git", "--no-replace-objects", *arguments], check=True,
                          capture_output=True, timeout=30).stdout


def Checkout(root, *, head=None, base, tree=None, parent_count=None):
    os.chdir(root)
    actual = Git("rev-parse", "HEAD").decode().strip()
    assert re.fullmatch(r"[0-9a-f]{40}", actual) and (head is None or actual == head), "Wrong HEAD"
    assert Git("rev-parse", "HEAD^1").decode().strip() == base, "Wrong original first parent"
    if tree is not None:
        assert Git("rev-parse", "HEAD^{tree}").decode().strip() == tree, "Wrong immutable tree"
    if parent_count is not None:
        assert len(Git("rev-list", "--parents", "-n", "1", "HEAD").split()) == parent_count + 1, (
            "Unexpected parent count"
        )
    return actual


def Cases(path):
    result = Counter()
    for case in ElementTree.parse(path).getroot().iter("testcase"):
        owner = case.attrib["classname"].replace("\\", ".").replace("/", ".")
        parts = owner[owner.index("tests.unit."):].removeprefix("tests.unit.").split(".")
        node = "tests/unit/" + parts[0] + ".py::" + "::".join([*parts[1:], case.attrib["name"]])
        result[node] += 1
    assert result and set(result.values()) == {1}, "JUnit identities are empty or duplicated"
    return result


@contextmanager
def Event(path, base, head, *, base_ref="develop", event="pull_request"):
    keys = ("GITHUB_EVENT_NAME", "GITHUB_BASE_REF", "GITHUB_HEAD_REF", "GITHUB_EVENT_PATH")
    original = {key: os.environ.get(key) for key in keys}
    previous = path.read_bytes() if path.exists() else None
    branch = "feature/passive-batch-retrospective-proof"
    path.write_text(json.dumps({"pull_request": {"draft": False,
                    "base": {"sha": base, "ref": base_ref},
                    "head": {"sha": head, "ref": branch}}}), encoding="utf-8")
    os.environ.update(dict(zip(keys, (event, base_ref, branch, str(path)), strict=True)))
    try:
        yield
    finally:
        if previous is None:
            path.unlink()
        else:
            path.write_bytes(previous)
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def Inspect(gate, output, label, base, head, *, changes=None, **event):
    decisions = []

    def Trace(frame, kind, value):
        if frame.f_code.co_filename == gate.__file__ and (
            (kind == "return" and value is False) or kind == "exception"
        ):
            context = frame.f_locals
            node = context.get("node")
            decisions.append({"function": frame.f_code.co_name, "line": frame.f_lineno,
                              "event": kind, "consumer": context.get("consumer"),
                              "path": str(context.get("path", "")),
                              "node_line": getattr(node, "lineno", None),
                              "node": ast.dump(node)[:1200] if isinstance(node, ast.AST) else None,
                              "exception": str(value[1])[:500] if kind == "exception" else None})
        return Trace

    with Event(output / "event-fixture.json", base, head, **event):
        if changes is None:
            actual, changes = gate.ChangedFiles(base)
            assert actual == head, "ChangedFiles returned a different source identity"
        previous = sys.gettrace()
        sys.settrace(Trace)
        try:
            selection, reason = gate.TestOnlySelection(base, head, changes)
        finally:
            sys.settrace(previous)
    result = {"base": base, "head": head, "reason": reason, "selection": list(selection),
              "changes": changes, "decisions": decisions[-10:],
              "event": {"synthetic": True, "name": event.get("event", "pull_request"),
                        "base_ref": event.get("base_ref", "develop")}}
    (output / (label + ".json")).write_text(
        json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"control": label, **result}), flush=True)
    return result


def VerifyWheel(root):
    distribution = metadata.distribution("1337")
    assert not json.loads(distribution.read_text("direct_url.json") or "{}").get(
        "dir_info", {}).get("editable"), "Editable install is forbidden"
    expected = {name for name in Git("ls-tree", "-r", "--name-only", "HEAD",
                                    "--", "src/fuzzy1337").decode().splitlines()
                if name.endswith(".py")}
    installed = {str(item): item for item in distribution.files or ()
                 if str(item).startswith("fuzzy1337/") and str(item).endswith(".py")}
    assert set(installed) == {name.removeprefix("src/") for name in expected}, (
        "Installed wheel Python inventory differs from source"
    )
    for name in sorted(expected):
        path = Path(distribution.locate_file(installed[name.removeprefix("src/")])).resolve()
        assert not path.is_relative_to(root / "src"), "Runtime came from source instead of wheel"
        assert path.read_bytes() == Git("show", "HEAD:" + name), name
    return len(expected)


def Main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--historical-root", type=Path, required=True)
    parser.add_argument("--positive-root", type=Path, required=True)
    parser.add_argument("--leaf-root", type=Path)
    parser.add_argument("--candidate-tools", type=Path, required=True)
    parser.add_argument("--gate-blob", required=True)
    parser.add_argument("--naming-blob", required=True)
    parser.add_argument("--baseline-xml", type=Path, required=True)
    parser.add_argument("--baseline-xml-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    historical, positive, tools, output, baseline = (value.resolve() for value in (
        options.historical_root, options.positive_root, options.candidate_tools,
        options.output, options.baseline_xml))
    assert historical != positive and not any(tools.is_relative_to(root) or output.is_relative_to(
        root) for root in (historical, positive)), "Use distinct checkouts and RUNNER_TEMP"
    output.mkdir(parents=True, exist_ok=True)
    assert hashlib.sha256(baseline.read_bytes()).hexdigest() == options.baseline_xml_sha256, (
        "Original extracted XML digest differs"
    )
    for filename, expected in (("passive_test_gate.py", options.gate_blob),
                               ("python_naming.py", options.naming_blob)):
        payload = (tools / filename).read_bytes()
        assert hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload).hexdigest() == (
            expected
        ), filename
    Checkout(historical, head=HISTORICAL, base=BASE, tree=HISTORICAL_TREE, parent_count=2)
    assert Git("rev-parse", "HEAD^2").decode().strip() == SECOND, "Wrong second parent"
    runtime_count = VerifyWheel(historical)
    sys.path.insert(0, str(tools))
    import passive_test_gate as gate
    import fuzzy1337
    import fuzzy1337.test_runner
    package = Path(metadata.distribution("1337").locate_file("fuzzy1337")).resolve()
    assert all(Path(module.__file__).resolve().is_relative_to(package)
               for module in (fuzzy1337, fuzzy1337.test_runner)), "Unverified imported runtime"
    assert tuple(gate.TEST_ONLY_CHECKS) == CHECKS, "Mandatory selection changed"
    controls = {}
    controls["actual-537"] = Inspect(gate, output, "actual-537", BASE, HISTORICAL)
    assert not controls["actual-537"]["selection"] and controls["actual-537"]["reason"] == (
        "shared-or-dynamic-test-module"
    ), "Actual #537 must stay full: its selected module has real external imports"
    controls["master"] = Inspect(gate, output, "master", BASE, HISTORICAL, base_ref="master")
    controls["unknown-event"] = Inspect(gate, output, "unknown-event", BASE, HISTORICAL,
                                       event="merge_group")
    controls["actual-product-multi"] = Inspect(gate, output, "actual-product-multi", SECOND,
                                             HISTORICAL)
    assert any(item["path"].startswith("src/") for item in controls["actual-product-multi"][
        "changes"]), "Second-parent control contains no actual product change"
    unknown = (*controls["actual-537"]["changes"],
               {**controls["actual-537"]["changes"][0], "path": "unclassified-input"})
    controls["unknown-path-fixture"] = Inspect(gate, output, "unknown-path-fixture", BASE,
                                               HISTORICAL, changes=unknown)
    assert all(not controls[key]["selection"] for key in controls), "A full control narrowed"
    if options.leaf_root is not None:
        Checkout(options.leaf_root.resolve(), head=LEAF_HEAD, base=LEAF_BASE, parent_count=1)
        controls["actual-455-selector-only"] = Inspect(
            gate, output, "actual-455-selector-only", LEAF_BASE, LEAF_HEAD)
        controls["actual-455-selector-only"]["executed"] = False
        controls["actual-455-selector-only"]["missing-modern-ownership-files"] = [
            path for path in CHECKS if not Path(path).is_file()]
    positive_head = Checkout(positive, base=BASE, tree=POSITIVE_TREE, parent_count=1)
    assert VerifyWheel(positive) == runtime_count, "Positive source changed installed runtime"
    assert Git("show", "HEAD:" + RUNTIME) == Git("show", HISTORICAL + ":" + RUNTIME), (
        "Reconstructed runtime test differs from the accepted #537 file"
    )
    removed = Counter(tuple(row) for row in json.loads(Git("show", BASE + ":" + BASELINE)))
    current = Counter(tuple(row) for row in json.loads(Git("show", "HEAD:" + BASELINE)))
    assert removed - current == Counter((RUNTIME, "local",
        "top.test_EveryOriginalReadViewRequiresOnePhysicalLink", name)
        for name in ("handle_calls", "path_calls")) and not current - removed, (
        "Reconstruction did not remove exactly the two accepted local baseline rows"
    )
    controls["reconstructed-positive"] = Inspect(gate, output, "reconstructed-positive", BASE,
                                                positive_head)
    selected = controls["reconstructed-positive"]
    selection = (RUNTIME, *CHECKS)
    assert selected["selection"] == list(selection) and selected["reason"] == (
        "verified-leaf-unit-changes"
    ) and {item["path"] for item in selected["changes"]} == {RUNTIME, BASELINE}, (
        "Refusing execution: reconstructed exact subset is not eligible"
    )
    with (output / "positive-naming.log").open("w", encoding="utf-8") as log:
        subprocess.run([sys.executable, str(positive / "tools/python_naming.py")], check=True,
                       stdout=log, stderr=subprocess.STDOUT, timeout=300)
    with Event(output / "event-fixture.json", BASE, positive_head):
        started = time.monotonic()
        with (output / "candidate-gate.log").open("w", encoding="utf-8") as log:
            subprocess.run([sys.executable, str(tools / "passive_test_gate.py"),
                            "--base", BASE, "--suite-timeout", "900"], check=True,
                           stdout=log, stderr=subprocess.STDOUT, timeout=900)
        elapsed = time.monotonic() - started
    receipt = json.loads((positive / "coverage/passive-acceptance.json").read_text(encoding="utf-8"))
    assert receipt["scope"] == "test-only" and receipt["base"] == BASE and receipt["head"] == (
        positive_head
    ) and receipt["selection"] == list(selection), "Gate receipt selected another source or scope"
    assert receipt["modules"] == {} and receipt["global_module_gate"] == "not-claimed" and (
        set(receipt["partitions"]) == {"units"}
    ), "Gate claimed production coverage or executed supplemental boundaries"
    actual = Counter()
    for path in sorted((positive / "coverage").glob("passive-units-*.xml")):
        actual.update(Cases(path))
        assert not any(case.find(kind) is not None
                       for case in ElementTree.parse(path).getroot().iter("testcase")
                       for kind in ("failure", "error", "skipped")), "A selected case did not pass"
    expected = Counter({node: count for node, count in Cases(baseline).items()
                        if node.split("::", 1)[0] in selection})
    assert actual == expected and all(any(node.startswith(path + "::") for node in actual)
                                     for path in selection), "Original exact cases differ"
    result = {"reconstructed": True, "label": "reconstructed-single-file-subset-of-537",
              "source": positive_head, "base": BASE, "tree": POSITIVE_TREE,
              "accepted-test-origin": HISTORICAL, "runtime-source": HISTORICAL,
              "gate_blob": options.gate_blob, "naming_blob": options.naming_blob,
              "installed_python_files": runtime_count, "baseline_artifact": 15052005768,
              "baseline_zip_sha256": ZIP_SHA256, "baseline_xml_sha256": options.baseline_xml_sha256,
              "controls": controls, "gate": receipt, "wall_seconds": elapsed,
              "original_full_pytest_seconds": {"units": 143.18, "boundaries": 41.00},
              "cases_by_file": dict(Counter(node.split("::", 1)[0] for node in actual)),
              "nodeids": sorted(actual), "actual-537-full-suite-executed": False}
    (output / "historical-p65-benchmark.json").write_text(
        json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"reconstructed": True, "source": positive_head, "passed": len(actual),
                      "wall_seconds": elapsed, "receipt": str(output / "historical-p65-benchmark.json")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
