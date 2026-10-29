# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Read-only final six-case original-evidence acceptance gate; never starts a target or scanner."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from pathlib import Path
from xml.etree import ElementTree

TRACKS = ("whole1337", "external-nuclei")
CASES = ("metrics.exposed", "metrics.json-control", "metrics.html-control")
PATHS = {"metrics.exposed": "/metrics", "metrics.json-control": "/rest/admin/application-version",
         "metrics.html-control": "/"}
TARGET_SOURCE = "5658473cf8814459bf89000ce373b20ed0b4eb37"
TARGET_INDEX = "sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b"
TARGET_PLATFORM = "sha256:7f7539921b046863f2fc48b84061f957e50b3aa4652ae0a62014a2fc25654d0b"
TEMPLATE_SHA256 = "dff3e6ea0821ba769cf63575ad685b8c1def939ed24f790f42d2fde924d55c74"


def Require(condition: bool, message: str) -> None:
    """Refuse missing original proof without repairing data or creating an execution claim."""

    if not condition:
        raise ValueError(message)


def Read(root: Path, relative: str, maximum: int = 2 * 1024 * 1024) -> bytes:
    """Read complete bounded ordinary evidence without allowing linked paths or traversal."""

    path = Path(relative)
    Require(not path.is_absolute() and ".." not in path.parts, "Invalid original evidence path")
    selected = root / path

    for component in (root, *(root.joinpath(*path.parts[:index])
                              for index in range(1, len(path.parts) + 1))):
        Require(not component.is_symlink(), "Original evidence path is linked")

    metadata = selected.stat()
    Require(selected.is_file() and metadata.st_nlink == 1 and metadata.st_size <= maximum,
            "Original evidence is missing, aliased or oversized")
    raw = selected.read_bytes()
    Require(len(raw) == metadata.st_size, "Original evidence changed during gate reading")

    return raw


def Decode(raw: bytes):
    """Decode original JSON with unique keys and finite numeric values."""

    def Object(pairs):
        """Preserve unique source keys rather than silently accepting overwritten facts."""

        result = {}

        for key, value in pairs:
            Require(key not in result, "Original evidence repeats a JSON key")
            result[key] = value

        return result

    def Constant(value):
        """Reject nonfinite constants without reflecting original provider text."""

        raise ValueError("Original evidence contains a nonfinite JSON number")

    def Float(value):
        """Refuse numeric syntax that overflows the finite host number range."""

        number = float(value)
        Require(math.isfinite(number), "Original evidence contains a nonfinite JSON number")

        return number

    return json.loads(raw, object_pairs_hook=Object, parse_constant=Constant, parse_float=Float)


def Json(root: Path, relative: str):
    """Decode one already bounded original JSON artifact."""

    return Decode(Read(root, relative))


def Verify(repository: Path, head: str, tree: str) -> dict:
    """Require six current-head passes and original image/target/provider facts."""

    Require(all(re.fullmatch("[a-f0-9]{40}", item) is not None for item in (head, tree)),
            "Comparison gate requires exact checked-out source and tree identities")
    junit = ElementTree.fromstring(Read(repository, "functional-evidence/nuclei-comparison.xml"))
    cases, suites = list(junit.iter("testcase")), list(junit.iter("testsuite"))
    expected = {f"test_GenuineNucleiApplicationComparison[{case}-{track}]"
                for case in CASES for track in TRACKS}
    Require(len(suites) == 1 and len(cases) == 6 and {
        item.get("name") for item in cases} == expected and all(
        item.get("classname") == "tests.functional.test_external_nuclei_benchmark" for item in cases
    ) and all(suites[0].get(key) == value for key, value in (
        ("tests", "6"), ("failures", "0"), ("errors", "0"), ("skipped", "0"))) and not any(
        list(junit.iter(kind)) for kind in ("failure", "error", "skipped")
    ), "Require exactly six original application passes without skip/error/failure")
    runs = list((repository / "functional-evidence/external-nuclei-prerequisites").glob("run-*"))
    Require(0 < len(runs) <= 16, "Comparison evidence owners are missing or ambiguous")
    accepted = []

    for root in runs:
        relative = (root / "host.json").relative_to(repository).as_posix()
        host = Json(repository, relative)

        if host.get("kind") == "finite-nuclei-application-comparison":
            accepted.append((root, host))

    Require(len(accepted) == 1, "Require exactly one original six-case comparison owner")
    root, host = accepted[0]
    Require(host["status"] == "completed-comparison" and host["source_revision"] == head
        and host["source_tree"] == tree and host["governed_no_home_compatibility"] == "established",
        "Comparison host/source or genuine initialization did not complete")
    context = Json(root, "context-inventory.json")
    Require(context["revision"] == head and context["tree"] == tree,
            "Original committed source inventory differs from the selected revision")
    image = Json(root, "governed-prerequisite/image-provisioning.json")
    Require(image["source_revision"] == head and image["installed"]["installed"][
        "source_revision"] == head and Read(root, "runner.iid", 80).decode().strip() == (
        host["image_id"]), "Original image/current installed source identities differ")
    Require(Json(root, "governed-prerequisite/prerequisites.json")[
        "governed_no_home_compatibility"] == "established", "Genuine no-HOME proof is absent")
    report = Json(root, "comparison.json")
    rows = report["observations"]
    Require(report["schema_version"] == 2 and len(rows) == 6 and {
        (item["case_id"], item["scanner_track"]) for item in rows
    } == {(case, track) for case in CASES for track in TRACKS},
        "Original comparison must contain exactly the six selected finite observations")
    instances = set()

    for row in rows:
        execution = row["execution"]
        positive = row["case_id"] == "metrics.exposed"
        Require(row["schema_version"] == 2 and row["status"] == (
            "completed" if positive else "unproven") and type(execution["exit_code"]) is int
            and execution["exit_code"] == 0 and execution["request_count"] == 1
            and execution["scanner_version"] == "3.4.10"
            and execution["scanner_sha256"] == image["material"]["executable"]["sha256"]
            and execution["rule_sha256"] == TEMPLATE_SHA256
            and execution["product_revision"] == (
                head if row["scanner_track"] == "whole1337" else None)
            and execution["source_revision"] == TARGET_SOURCE
            and execution["image_index_digest"] == TARGET_INDEX
            and execution["platform_digest"] == TARGET_PLATFORM
            and execution["target_url"] == "http://127.0.0.1:3000" + PATHS[row["case_id"]]
            and execution["network_internal"] is True
            and type(execution["published_ports"]) is int and execution["published_ports"] == 0
            and 0 <= execution["duration_seconds"] <= 3
            and execution["effective_budget"] == {"request_timeout_seconds": 3,
                "operation_timeout_seconds": 3, "max_requests": 1,
                "max_response_bytes": 1048576, "rate_limit": 1}
            and len(execution["findings"]) == int(positive),
            "Original case must retain genuine bounded matching or unproven empty invocation facts")
        Require(re.fullmatch("[a-f0-9]{64}", execution["target_instance"]) is not None,
                "Every application case must identify its exact fresh target instance")
        instances.add(execution["target_instance"])
        evidence = {}

        for record in execution["evidence"]:
            raw = Read(root, record["path"])
            Require(record["role"] not in evidence and len(raw) == record["size_bytes"]
                and hashlib.sha256(raw).hexdigest() == record["sha256"],
                "Original comparison evidence hash/size/role differs")
            evidence[record["role"]] = raw

        Require(Decode(evidence["invocation"])["argv"] == execution["argv"] and (
            Decode(evidence["findings"]) == execution["findings"]
            and bool(evidence["stdout"].strip()) is positive
            and Decode(evidence["attempt-provenance"])[
                "independent_server_contact_count"] is None
        ), "Original provider bytes cannot be replaced by a normalized completion claim")

    Require(len(instances) == 6 and report["whole_application_accuracy"] is None,
            "Comparison must use six distinct fresh targets and no whole-application score")

    for track in TRACKS:
        Require(report["finite_completed_case_counts"][track] == {
            "tp": 1, "fp": 0, "fn": 0, "tn": 0, "unscored": 2, "coverage_gaps": 0},
            "Empty Nuclei output must receive no TN/FN credit or completed-response denominator")

    Require(host["cleanup"] and all((item.get("container_absent") is True) if (
        "container_absent" in item) else item.get("absent") is True for item in host["cleanup"]),
        "Independent original runner/tag cleanup is missing or unconfirmed")

    return {"executed_cases": 6, "fresh_targets": 6, "nuclei_tp": 2, "unproven": 4}


def Main(arguments=None) -> int:
    """Read originals for the exact CLI-supplied source identity; no runtime helper is imported."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True)
    parser.add_argument("--identity", required=True)
    options = parser.parse_args(arguments)
    identity = options.identity.splitlines()
    Require(len(identity) == 2 and identity[0] == options.head,
            "Comparison must bind the exact checked-out workflow head")
    print(json.dumps(Verify(Path.cwd(), options.head, identity[1]), sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
