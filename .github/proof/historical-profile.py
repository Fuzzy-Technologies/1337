#!/usr/bin/env python3
"""Run one P65 gate against immutable historical #537; never run a fallback suite."""

import argparse
from collections import Counter
from contextlib import contextmanager
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from xml.etree import ElementTree

HEAD = "79912c8467a23f8b806078f5f0738e01eb76d205"
BASE = "84d1101b3de10da09f89881f523a032cd909d696"
SECOND = "b63d113396ff9daa9e7d27dce1512a5306f980d6"
TREE = "d799aab5e060546ec022180c4a5f60763671d3f4"
BRANCH = "feature/passive-batch-private-test-names"
FILES = ("tests/unit/test_owned_response_parent.py", "tests/unit/test_runtime_commands.py")
CHECKS = ("tests/unit/test_python_style.py", "tests/unit/test_source_documentation_headers.py",
          "tests/unit/test_python_naming.py", "tests/unit/test_passive_test_gate.py",
          "tests/unit/test_passive_integration.py")
ZIP_SHA256 = "450fb3faece7630008c8ff359c36c4d46b49fba60af766e75aff8312bd4d13c7"


def Git(*arguments):
    return subprocess.run(["git", "--no-replace-objects", *arguments], check=True,
                          capture_output=True, timeout=30).stdout


def BlobId(payload):
    return hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload).hexdigest()


def Cases(path):
    result = Counter()
    for case in ElementTree.parse(path).getroot().iter("testcase"):
        owner = case.attrib["classname"].replace("\\", ".").replace("/", ".")
        owner = owner[owner.index("tests.unit."):]
        parts = owner.removeprefix("tests.unit.").split(".")
        node = "tests/unit/" + parts[0] + ".py::" + "::".join([*parts[1:], case.attrib["name"]])
        result[node] += 1
    assert result and set(result.values()) == {1}, "JUnit identities are empty or duplicated"
    return result


@contextmanager
def Event(path, *, base=BASE, base_ref="develop", event="pull_request"):
    keys = ("GITHUB_EVENT_NAME", "GITHUB_BASE_REF", "GITHUB_HEAD_REF", "GITHUB_EVENT_PATH")
    original = {key: os.environ.get(key) for key in keys}
    previous = path.read_bytes() if path.exists() else None
    path.write_text(json.dumps({"pull_request": {"draft": False,
                    "base": {"sha": base, "ref": base_ref},
                    "head": {"sha": HEAD, "ref": BRANCH}}}), encoding="utf-8")
    os.environ.update(dict(zip(keys, (event, base_ref, BRANCH, str(path)), strict=True)))
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


def Main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--candidate-tools", type=Path, required=True)
    parser.add_argument("--gate-blob", required=True)
    parser.add_argument("--naming-blob", required=True)
    parser.add_argument("--baseline-xml", type=Path, required=True)
    parser.add_argument("--baseline-xml-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    root, tools, output = (value.resolve() for value in
                           (options.source_root, options.candidate_tools, options.output))
    assert not tools.is_relative_to(root) and not output.is_relative_to(root), "Use RUNNER_TEMP"
    output.mkdir(parents=True, exist_ok=True)
    baseline = options.baseline_xml.resolve()
    assert hashlib.sha256(baseline.read_bytes()).hexdigest() == options.baseline_xml_sha256, (
        "Original extracted XML digest differs"
    )
    os.chdir(root)
    for expression, expected in (("HEAD", HEAD), ("HEAD^1", BASE),
                                 ("HEAD^2", SECOND), ("HEAD^{tree}", TREE)):
        assert Git("rev-parse", expression).decode().strip() == expected, expression
    for filename, expected in (("passive_test_gate.py", options.gate_blob),
                               ("python_naming.py", options.naming_blob)):
        assert BlobId((tools / filename).read_bytes()) == expected, filename
    distribution = metadata.distribution("1337")
    direct = json.loads(distribution.read_text("direct_url.json") or "{}")
    assert not direct.get("dir_info", {}).get("editable"), "Editable install is forbidden"
    expected = {name for name in Git("ls-tree", "-r", "--name-only", HEAD,
                                    "--", "src/fuzzy1337").decode().splitlines()
                if name.endswith(".py")}
    installed = {str(item): item for item in distribution.files or ()
                 if str(item).startswith("fuzzy1337/") and str(item).endswith(".py")}
    assert set(installed) == {name.removeprefix("src/") for name in expected}, (
        "Installed wheel Python inventory differs from historical source"
    )
    for name in sorted(expected):
        file = Path(distribution.locate_file(installed[name.removeprefix("src/")])).resolve()
        assert not file.is_relative_to(root), "Runtime came from the source checkout"
        assert file.read_bytes() == Git("show", HEAD + ":" + name), name
    sys.path.insert(0, str(tools))
    import passive_test_gate as gate
    import fuzzy1337
    import fuzzy1337.test_runner
    for module in (fuzzy1337, fuzzy1337.test_runner):
        file = Path(module.__file__).resolve()
        assert file.is_relative_to(Path(distribution.locate_file("fuzzy1337")).resolve()), (
            "Imported runtime is outside the verified installed wheel"
        )
    assert tuple(gate.TEST_ONLY_CHECKS) == CHECKS, "Mandatory ownership selection changed"
    with (output / "historical-naming.log").open("w", encoding="utf-8") as log:
        subprocess.run([sys.executable, str(root / "tools/python_naming.py")], check=True,
                       stdout=log, stderr=subprocess.STDOUT, timeout=300)
    event_path = output / "historical-event-fixture.json"
    controls = {}
    with Event(event_path):
        head, changes = gate.ChangedFiles(BASE)
        assert head == HEAD and {item["path"] for item in changes} == {
            *FILES, "contracts/python-naming-baseline.json"
        }, "Historical complete diff differs"
        selection, reason = gate.TestOnlySelection(BASE, head, changes)
        assert selection == (*FILES, *CHECKS) and (
            reason == "verified-leaf-unit-changes"
        ), "Refusing execution: historical diff did not select the intended quick profile"
        controls["historical"] = reason
        for label, settings in (("master", {"base_ref": "master"}),
                                ("unknown-event", {"event": "merge_group"})):
            with Event(event_path, **settings):
                selected, why = gate.TestOnlySelection(BASE, HEAD, changes)
                assert not selected, label + " incorrectly narrowed"
                controls[label] = why
        with Event(event_path, base=SECOND):
            broad_head, broad = gate.ChangedFiles(SECOND)
            assert broad_head == HEAD and any(item["path"].startswith("src/") for item in broad), (
                "Second-parent control does not contain actual product changes"
            )
            selected, why = gate.TestOnlySelection(SECOND, HEAD, broad)
            assert not selected, "Actual product/multi-feature diff incorrectly narrowed"
            controls["actual-second-parent-product-diff"] = why
        unknown = (*changes, {**changes[0], "path": "unclassified-input"})
        selected, why = gate.TestOnlySelection(BASE, HEAD, unknown)
        assert not selected, "Unknown-path negative fixture incorrectly narrowed"
        controls["unknown-path-fixture"] = why
    with Event(event_path):
        assert gate.TestOnlySelection(BASE, HEAD, changes)[0] == selection, "Route changed"
        started = time.monotonic()
        with (output / "candidate-gate.log").open("w", encoding="utf-8") as log:
            subprocess.run([sys.executable, str(tools / "passive_test_gate.py"),
                            "--base", BASE, "--suite-timeout", "900"], check=True,
                           stdout=log, stderr=subprocess.STDOUT, timeout=900)
        elapsed = time.monotonic() - started
    receipt = json.loads((root / "coverage/passive-acceptance.json").read_text(encoding="utf-8"))
    assert receipt["scope"] == "test-only" and receipt["base"] == BASE and receipt["head"] == HEAD, (
        "Candidate gate receipt does not bind the historical quick route"
    )
    assert receipt["selection"] == list(selection) and receipt["modules"] == {} and (
        receipt["global_module_gate"] == "not-claimed" and set(receipt["partitions"]) == {"units"}
    ), "Candidate gate changed scope or executed supplemental boundaries"
    actual = Counter()
    for path in sorted((root / "coverage").glob("passive-units-*.xml")):
        actual.update(Cases(path))
        assert not any(case.find(kind) is not None
                       for case in ElementTree.parse(path).getroot().iter("testcase")
                       for kind in ("failure", "error", "skipped")), "A selected case did not pass"
    expected_cases = Counter({node: count for node, count in Cases(baseline).items()
                              if node.split("::", 1)[0] in selection})
    assert actual == expected_cases and all(any(node.startswith(path + "::") for node in actual)
                                           for path in selection), "Original exact cases differ"
    result = {"source": HEAD, "base": BASE, "tree": TREE, "gate_blob": options.gate_blob,
              "naming_blob": options.naming_blob, "installed_python_files": len(expected),
              "baseline_artifact": 15052005768, "baseline_zip_sha256": ZIP_SHA256,
              "baseline_xml_sha256": options.baseline_xml_sha256, "controls": controls,
              "event": "historical-fixture-not-live-admission", "gate": receipt,
              "wall_seconds": elapsed, "original_pytest_seconds": {"units": 143.18, "boundaries": 41.00},
              "cases_by_file": dict(Counter(node.split("::", 1)[0] for node in actual)),
              "nodeids": sorted(actual)}
    (output / "historical-p65-benchmark.json").write_text(
        json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"passed": len(actual), "wall_seconds": elapsed,
                      "receipt": str(output / "historical-p65-benchmark.json")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
