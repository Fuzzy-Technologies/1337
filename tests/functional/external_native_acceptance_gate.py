# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify original finite native application acceptance without running a scanner or target."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import math
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree

CASES = {"metrics.exposed": "/metrics", "metrics.json-control": "/rest/admin/application-version",
         "metrics.html-control": "/"}
MODULES = ("adapters.prometheus_exposition", "adapters.native_web", "native_web_worker",
           "native_web", "scan_commands")
ROLES = {"stdout", "stderr", "invocation", "findings", "target-provenance", "requests",
         "attempt-provenance", "installed-wheel", "installed-source"}
TARGET_SOURCE = "5658473cf8814459bf89000ce373b20ed0b4eb37"
TARGET_INDEX = "sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b"
TARGET_PLATFORMS = {
    "linux/amd64": "sha256:7f7539921b046863f2fc48b84061f957e50b3aa4652ae0a62014a2fc25654d0b",
    "linux/arm64": "sha256:f2b4f8284af700c0e8a31d5c2b7f0cc84a027ec410f99d26fb763fba7a7f469b",
}
BUDGET = {"request_timeout_seconds": 3, "operation_timeout_seconds": 10, "max_requests": 1,
          "max_response_bytes": 262144, "rate_limit": 1}
ROOT = "functional-evidence/external-native-benchmark"


def Require(condition: bool, message: str) -> None:
    """Refuse incomplete or contradictory originals without repairing their claimed outcome."""

    if not condition:
        raise ValueError(message)


def SafePath(relative: str) -> PurePosixPath:
    """Admit only ordinary bounded relative names, including when read on Windows."""

    Require(type(relative) is str and 0 < len(relative) <= 512 and not any(
        ord(character) < 32 or ord(character) == 127 or character in "\\:"
        for character in relative), "Invalid original native evidence path")
    path = PurePosixPath(relative)
    Require(not path.is_absolute() and all(part not in {"", ".", ".."}
        for part in relative.split("/")), "Invalid original native evidence path")

    return path


def Read(root: Path, relative: str, maximum: int = 2 * 1024 * 1024) -> bytes:
    """Read complete regular unaliased originals within the selected evidence owner."""

    parts = SafePath(relative).parts

    for component in (root, *(root.joinpath(*parts[:index])
                              for index in range(1, len(parts) + 1))):
        Require(not component.is_symlink(), "Original native evidence path is linked")

    selected = root.joinpath(*parts)
    metadata = selected.stat()
    Require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
        and metadata.st_size <= maximum, "Original native evidence is aliased or oversized")

    with selected.open("rb") as stream:
        raw = stream.read(maximum + 1)

    Require(len(raw) == metadata.st_size and len(raw) <= maximum,
            "Original native evidence changed during reading")

    return raw


def Decode(raw: bytes):
    """Reject ambiguous JSON and nonfinite numbers at every original metadata boundary."""

    def Object(pairs):
        """Keep each original key unique rather than accepting an overwritten claim."""

        result = {}

        for key, value in pairs:
            Require(key not in result, "Original native evidence repeats a JSON key")
            result[key] = value

        return result

    def Constant(value):
        """Refuse nonstandard numeric constants without reflecting source content."""

        raise ValueError("Original native evidence contains a nonfinite number")

    def Float(value):
        """Refuse otherwise valid JSON numbers that overflow the finite host number range."""

        number = float(value)
        Require(math.isfinite(number), "Original native evidence contains a nonfinite number")

        return number

    return json.loads(raw, object_pairs_hook=Object, parse_constant=Constant, parse_float=Float)


def Json(root: Path, relative: str):
    """Decode one bounded original JSON document."""

    return Decode(Read(root, relative))


def Digest(raw: bytes) -> str:
    """Identify exact bytes rather than a normalized interpretation of their contents."""

    return hashlib.sha256(raw).hexdigest()


def VerifyJunit(repository: Path) -> None:
    """Require exactly the three actual native cases without skips, duplicate names or errors."""

    raw = Read(repository, ROOT + "/pytest.xml")
    Require(b"<!" not in raw, "Native JUnit cannot declare external or expanded XML content")
    document = ElementTree.fromstring(raw)
    cases, suites = list(document.iter("testcase")), list(document.iter("testsuite"))
    expected = {"test_InstalledNativeScannerMatchesRealApplicationCases[" + case + "]"
                for case in CASES}
    Require(len(suites) == 1 and len(cases) == 3 and {
        item.get("name") for item in cases} == expected and all(item.get("classname")
        == "tests.functional.test_external_native_benchmark" for item in cases)
        and all(suites[0].get(key) == value for key, value in (
            ("tests", "3"), ("failures", "0"), ("errors", "0"), ("skipped", "0")))
        and not any(list(document.iter(kind)) for kind in ("failure", "error", "skipped")),
        "Require exactly three original native application passes without skip/error/failure")


def VerifyBundle(root: Path, case_id: str, execution: dict, required: set[str]) -> None:
    """Join every exported file to original attached Docker bytes, without extracting anything."""

    stdout = Read(root, case_id + "/docker.stdout", 12 * 1024 * 1024)
    stderr = Read(root, case_id + "/docker.stderr")
    attached = Json(root, case_id + "/docker-exit.json")
    argv = attached["argv"]
    Require(type(attached["returncode"]) is int and attached["returncode"] == 0
        and attached["timed_out"] is False
        and type(attached["duration_seconds"]) in (int, float)
        and 0 <= attached["duration_seconds"] <= 40
        and attached["stdout_sha256"] == Digest(stdout)
        and attached["stderr_sha256"] == Digest(stderr) and len(argv) == 4
        and argv[:3] == ["docker", "start", "--attach"]
        and re.fullmatch("[a-f0-9]{64}", argv[3]) is not None,
        "Original Docker attachment did not complete with its exact native bytes")
    bundle = Decode(stdout)
    outcome, files = bundle["outcome"], bundle["files"]
    Require(type(bundle["schema_version"]) is int and bundle["schema_version"] == 1
        and set(bundle) == {"schema_version", "outcome", "files"}
        and type(outcome["exit_code"]) is int
        and outcome == {"status": "completed", "exit_code": 0,
            "duration_seconds": execution["duration_seconds"],
            "target_url": execution["target_url"]}
        and type(files) is list and 1 <= len(files) <= 128,
        "Original native bundle outcome or file count differs from its completed case")
    seen, total, projected = set(), 0, []

    for record in files:
        Require(set(record) == {"path", "media_type", "size_bytes", "sha256", "data_base64"}
            and record["media_type"] in {"application/json", "application/octet-stream",
                "application/zip", "text/plain"}, "Original bundle file has unknown metadata")
        relative = SafePath(record["path"]).as_posix()
        Require(relative not in seen and type(record["size_bytes"]) is int
            and 0 <= record["size_bytes"] <= 2 * 1024 * 1024,
            "Original bundle file identity is repeated or oversized")
        seen.add(relative)
        raw = base64.b64decode(record["data_base64"], validate=True)
        total += len(raw)
        Require(total <= 8 * 1024 * 1024 and len(raw) == record["size_bytes"]
            and Digest(raw) == record["sha256"]
            and Read(root, case_id + "/scanner/" + relative) == raw,
            "Exported original native bytes differ from Docker attachment")
        projected.append({key: value for key, value in record.items() if key != "data_base64"})

    Require(required <= seen and Json(root, case_id + "/bundle-manifest.json") == {
        "schema_version": 1, "outcome": outcome, "files": projected},
        "Retained native bundle manifest differs from original attachment")


def VerifyInstalled(repository: Path, evidence: dict[str, bytes], head: str) -> dict:
    """Bind the original installed wheel and selected module bytes to the current checkout."""

    source = Decode(evidence["installed-source"])
    wheel = source["wheel"]
    modules = source["module_sha256"]
    Require(source["source_revision"] == head and set(modules) == set(MODULES)
        and source["runner_sha256"] == Digest(Read(repository,
            "tests/functional/external_native_runner.py"))
        and re.fullmatch("[a-f0-9]{64}", source["python_sha256"]) is not None
        and source["effective_body_bytes"] == 262144
        and re.fullmatch(r"/opt/benchmark-runtime/lib/python3\.(?:13|14)/site-packages/fuzzy1337",
                           source["package_path"]) is not None
        and re.fullmatch(r"1337-[A-Za-z0-9_.+-]+\.whl", wheel["filename"]) is not None
        and type(wheel["size_bytes"]) is int and wheel["size_bytes"] == len(evidence[
            "installed-wheel"]) and wheel["sha256"] == Digest(evidence["installed-wheel"]),
        "Installed native source, runner or wheel differs from the selected checkout")

    with zipfile.ZipFile(io.BytesIO(evidence["installed-wheel"])) as archive:
        names = archive.namelist()
        Require(len(names) <= 2048 and len(names) == len(set(names)),
                "Installed native wheel has ambiguous or excessive members")

        for name in MODULES:
            member = "fuzzy1337/" + name.replace(".", "/") + ".py"
            current = Read(repository, "src/" + member)
            info = archive.getinfo(member)
            Require(info.file_size == len(current) and not info.flag_bits & 1
                and modules[name] == Digest(current),
                "Installed native module receipt differs from current source bytes")

            with archive.open(info) as stream:
                installed = stream.read(len(current) + 1)

            Require(installed == current,
                    "Installed native wheel member differs from current source bytes")

    return source


def VerifyCase(repository: Path, root: Path, row: dict, head: str, reset_hash: str) -> str:
    """Require the original response, Finding, attempt and source for one finite case."""

    case_id, execution = row["case_id"], row["execution"]
    positive = case_id == "metrics.exposed"
    url = "http://127.0.0.1:3000" + CASES[case_id]
    Require(type(row["schema_version"]) is int and row["schema_version"] == 1
        and row["status"] == "completed"
        and row["scanner_track"] == "native-engine"
        and row["pack_id"] == "external.juice-shop.prometheus.v1"
        and type(execution["exit_code"]) is int and execution["exit_code"] == 0
        and type(execution["request_count"]) is int and execution["request_count"] == 1
        and execution["product_revision"] == head and execution["source_revision"] == TARGET_SOURCE
        and execution["image_index_digest"] == TARGET_INDEX
        and execution["platform_digest"] in TARGET_PLATFORMS.values()
        and execution["reset_contract_sha256"] == reset_hash and execution["target_url"] == url
        and execution["network_internal"] is True and type(execution["published_ports"]) is int
        and execution["published_ports"] == 0 and execution["effective_budget"] == BUDGET
        and all(type(value) in (int, float) for value in execution["effective_budget"].values())
        and type(execution["duration_seconds"]) in (int, float)
        and 0 <= execution["duration_seconds"] <= 10
        and re.fullmatch("[a-f0-9]{64}", execution["target_instance"]) is not None
        and execution["scanner_id"] == "native.web-check" and execution["scanner_version"] == "1"
        and execution["argv"] == ["/opt/benchmark-runtime/bin/python", "-I", "-m",
            "fuzzy1337.native_web_worker", url, "3.0", "native.prometheus-exposition"],
        "Original native case changed its source, target, invocation or effective limits")
    records = execution["evidence"]
    Require(type(records) is list and len(records) == len(ROLES) and {
        record["role"] for record in records} == ROLES,
        "Original native case must retain exactly its nine distinct evidence roles")
    evidence = {}

    for record in records:
        Require(record["path"].startswith(case_id + "/"),
                "Original native role belongs to a different case")
        raw = Read(root, record["path"])
        Require(type(record["size_bytes"]) is int and len(raw) == record["size_bytes"]
            and Digest(raw) == record["sha256"], "Original native role hash or size differs")
        evidence[record["role"]] = raw

    source = VerifyInstalled(repository, evidence, head)
    expected_paths = {"stdout": "scanner/worker-stdout.json",
        "stderr": "scanner/worker-stderr.json",
        "invocation": "scanner/invocation.json", "findings": "scanner/findings.json",
        "target-provenance": "target-provenance.json", "requests": "approved-attempts.json",
        "attempt-provenance": "attempt-provenance.json",
        "installed-source": "scanner/provisioning.json",
        "installed-wheel": "scanner/" + source["wheel"]["filename"]}
    Require(all(record["path"] == case_id + "/" + expected_paths[record["role"]]
                for record in records), "Original native evidence roles changed their owning paths")
    Require(execution["scanner_sha256"] == source["python_sha256"] and execution["rule_sha256"]
        == source["module_sha256"]["adapters.prometheus_exposition"],
        "Original native executable or rule identity differs from its installed source")
    invocation = Decode(evidence["invocation"])
    Require(all(invocation.get(key) == execution[key] for key in ("argv", "scanner_id",
        "scanner_version", "scanner_sha256", "rule_sha256", "product_revision",
        "effective_budget")),
        "Original native invocation differs from report metadata")
    provenance = Decode(evidence["target-provenance"])
    Require(all(provenance.get(key) == execution[key] for key in ("source_revision",
        "image_index_digest", "platform_digest", "target_url", "target_instance",
        "reset_contract_sha256", "network_internal", "published_ports"))
        and Decode(evidence["requests"]) == [{"method": "GET", "url": url}],
        "Original native case or request attribution differs from the supplied report")
    worker = Decode(evidence["stdout"])
    Require(evidence["stderr"] == b"" and set(worker) == {"schema_version", "check_id",
        "profile_version", "url", "address", "port", "scheme", "status", "media_type",
        "body_bytes", "body_sha256", "matched"}
        and type(worker["schema_version"]) is int and worker["schema_version"] == 1
        and worker["check_id"] == "native.prometheus-exposition"
        and worker["profile_version"] == "1"
        and worker["url"] == url and worker["address"] == "127.0.0.1" and worker["port"] == 3000
        and worker["scheme"] == "http" and type(worker["status"]) is int and worker["status"] == 200
        and worker["matched"] is positive and type(worker["body_bytes"]) is int
        and 0 < worker["body_bytes"] <= 262144
        and re.fullmatch("[a-f0-9]{64}", worker["body_sha256"]) is not None
        and (worker["media_type"] == "text/plain" if positive else worker["media_type"] == "other"),
        "Original native worker did not assess the exact complete finite response")
    findings = ([{"rule_id": "native.prometheus-exposition", "path": CASES[case_id]}]
                if positive else [])
    Require(execution["findings"] == findings and Decode(evidence["findings"]) == findings,
            "Original native Findings disagree with the independent finite case truth")
    attempt = Decode(evidence["attempt-provenance"])
    Require(attempt["basis"] == "approved-worker-invocation-and-successful-record"
        and type(attempt["approved_attempt_count"]) is int
        and attempt["approved_attempt_count"] == 1
        and "independent_server_contact_count" in attempt
        and attempt["independent_server_contact_count"] is None
        and attempt["scanner_source_revision"] == head
        and re.fullmatch("sha256:[a-f0-9]{64}", attempt["scanner_image_id"]) is not None,
        "Original native attempt attribution fabricated contacts or changed installed source")

    if not positive:
        control = attempt["fixture_http_probes"][-1]
        body = control["body"].encode("utf-8")
        Require(control["host"] == "127.0.0.1" and control["port"] == 3000
            and control["path"] == CASES[case_id] and control["status"] == 200
            and control["error"] == "" and control["timed_out"] is False
            and Digest(body) == worker["body_sha256"] and len(body) == worker["body_bytes"]
            and (Decode(body) == {"version": "20.2.0"} if case_id == "metrics.json-control"
                 else "OWASP Juice Shop" in control["body"]),
            "Native negative case lacks its separate genuine JSON or HTML response control")

    VerifyBundle(root, case_id, execution, {value.removeprefix("scanner/")
        for value in expected_paths.values() if value.startswith("scanner/")})

    return execution["target_instance"]


def Verify(repository: Path, head: str, tree: str) -> dict:
    """Require the exact current-head three-case result and its retained original byte joins."""

    Require(all(type(item) is str and re.fullmatch("[a-f0-9]{40}", item) is not None
                for item in (head, tree)), "Native gate requires exact source and tree identities")
    VerifyJunit(repository)
    target = Json(repository, "labs/external/juice-shop.v1.json")
    pack = Json(repository, "labs/external/benchmark/juice-shop-cases.v1.json")
    Require(target["version"] == "20.2.0" and target["source_revision"] == TARGET_SOURCE
        and target["index_digest"] == TARGET_INDEX
        and target["platform_digests"] == TARGET_PLATFORMS
        and pack["pack_id"] == "external.juice-shop.prometheus.v1"
        and pack["source_revision"] == TARGET_SOURCE and pack["whole_application_oracle_complete"]
        is False and pack["requested_budget"] == BUDGET and len(pack["cases"]) == 3
        and all(item["applicability"] == "applicable"
                and item["capability"] == "web.prometheus-exposition-check"
                for item in pack["cases"])
        and {(item["id"], item["path"], item["expected"]) for item in pack["cases"]}
        == {(case, path, case == "metrics.exposed") for case, path in CASES.items()},
        "Selected native app fixture or independent finite case truth changed")
    native = [item for item in pack["scanner_tracks"] if item["id"] == "native-engine"]
    Require(len(native) == 1 and native[0]["implementation"] == "available"
        and native[0]["scanner_id"] == "native.web-check"
        and native[0]["rule_ids"] == ["native.prometheus-exposition"],
        "Selected native mapping lacks its accepted exact detector")
    reset_hash = Digest(json.dumps({"target": target, "compose_sha256": Digest(Read(repository,
        "labs/external/compose.yaml"))}, sort_keys=True).encode())
    parent = repository / ROOT
    Require(not parent.is_symlink(), "Native evidence owner is linked")
    runs = []

    for candidate in parent.iterdir():
        if candidate.name.startswith("run-"):
            Require(len(runs) == 0 and not candidate.is_symlink() and candidate.is_dir()
                and re.fullmatch("run-[a-f0-9]{12}", candidate.name) is not None,
                "Require exactly one unlinked original native execution owner")
            runs.append(candidate)

    Require(len(runs) == 1, "Require exactly one original native execution owner")
    root = runs[0]
    report = Json(root, "report.json")
    rows = report["observations"]
    Require(type(report["schema_version"]) is int and report["schema_version"] == 1
        and report["pack_id"] == pack["pack_id"]
        and type(rows) is list and len(rows) == 3 and {row["case_id"] for row in rows} == set(CASES)
        and report["whole_application_accuracy"] is None,
        "Native acceptance must contain exactly three finite cases and no whole-app score")
    instances = {VerifyCase(repository, root, row, head, reset_hash) for row in rows}
    Require(len(instances) == 3 and report["finite_completed_case_counts"]["native-engine"]
        == {"tp": 1, "fp": 0, "fn": 0, "tn": 2, "unscored": 0, "coverage_gaps": 0},
        "Native cases must use three distinct fresh targets and exact finite TP1/TN2")
    cells = report["cells"]
    tracks = {"native-engine", "whole1337", "external-nuclei"}
    Require(type(cells) is list and len(cells) == 9 and {
        (cell["case_id"], cell["scanner_track"]) for cell in cells
        } == {(case, track) for case in CASES for track in tracks}
        and set(report["finite_completed_case_counts"]) == tracks
        and report["pairwise_conditions"] == [],
        "Native report cannot invent or omit application comparison cells")

    for cell in cells:
        native = cell["scanner_track"] == "native-engine"
        expected = cell["case_id"] == "metrics.exposed"
        Require(cell["expected"] is expected and cell["applicability"] == "applicable"
            and cell["status"] == ("completed" if native else "not-run")
            and cell["score"] == (("tp" if expected else "tn") if native else None)
            and cell["unadjudicated_findings"] == [] and cell["budget_deviation"] is False,
            "Native report cell disagrees with its finite observations or unrun tracks")

    for track, counts in report["finite_completed_case_counts"].items():
        Require(all(type(value) is int for value in counts.values()) and (
            track == "native-engine" or counts == {"tp": 0, "fp": 0, "fn": 0,
                "tn": 0, "unscored": 3, "coverage_gaps": 0}),
            "Native-only acceptance cannot credit unexecuted comparison tracks")

    return {"executed_cases": 3, "fresh_targets": 3, "native_tp": 1, "native_tn": 2,
            "whole_application_accuracy": None, "source_revision": head, "source_tree": tree}


def Main(arguments=None) -> int:
    """Read retained originals for the checked-out identity without starting any process."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True)
    parser.add_argument("--identity", required=True)
    options = parser.parse_args(arguments)
    identity = options.identity.splitlines()
    Require(len(identity) == 2 and identity[0] == options.head,
            "Native gate must bind the exact checked-out workflow head")
    print(json.dumps(Verify(Path.cwd(), options.head, identity[1]), sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
