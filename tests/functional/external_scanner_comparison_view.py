# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Join the verified native and Nuclei Juice Shop evidence from one exact CI source."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .external_benchmark import BuildComparison
from .external_native_acceptance_gate import ROOT as NATIVE_ROOT
from .external_native_acceptance_gate import Verify as VerifyNative
from .external_nuclei_comparison_gate import Decode, Read, Require
from .external_nuclei_comparison_gate import Verify as VerifyNuclei

_MODES = {"native-engine": ("1337Scope", "native"), "whole1337": ("Nuclei", "governed"),
          "external-nuclei": ("Nuclei", "standalone")}
_TARGET_KEYS = ("source_revision", "image_index_digest", "platform_digest", "reset_contract_sha256")
_SCANNER_KEYS = ("scanner_id", "scanner_version", "scanner_sha256", "rule_sha256",
                 "product_revision", "effective_budget")
_NUCLEI_KEYS = ("scanner_version", "scanner_sha256", "rule_sha256")


def JoinVerifiedReports(pack: dict, reports: tuple[dict, dict], head: str) -> dict:
    """Align verified tracks on one pinned basis and preserve each native or provider outcome."""

    byCase = {case["id"]: {} for case in pack["cases"]}
    tracks = {}
    instances = set()
    basis = None

    for report in reports:
        cells = {(cell["case_id"], cell["scanner_track"]): cell for cell in report["cells"]}

        for observation in report["observations"]:
            caseId, track = observation["case_id"], observation["scanner_track"]
            execution = observation["execution"]
            target = {key: execution[key] for key in _TARGET_KEYS}
            scanner = {key: execution[key] for key in _SCANNER_KEYS}
            instance = execution["target_instance"]
            expectedRevision = None if track == "external-nuclei" else head

            if basis is None:
                basis = target

            Require(target == basis and instance not in instances,
                    "Comparison requires the same target/reset basis and distinct instances")
            Require(scanner["product_revision"] == expectedRevision,
                    "Comparison requires the selected product source for both product tracks")
            Require(tracks.setdefault(track, scanner) == scanner and track not in byCase[caseId],
                    "Comparison requires one stable scanner identity and one result per case/track")
            instances.add(instance)
            cell = cells[caseId, track]
            byCase[caseId][track] = {"status": cell["status"], "score": cell["score"],
                                    "target_instance": instance}

    Require(all(case.keys() == _MODES.keys() for case in byCase.values()),
            "Comparison requires an original observation for every selected case and track")
    Require(all(tracks["whole1337"][key] == tracks["external-nuclei"][key] for key in _NUCLEI_KEYS),
            "Nuclei orchestration comparison requires the same binary, version and template")
    nativeBudget = tracks["native-engine"]["effective_budget"]

    return {"pack_id": pack["pack_id"], "target": basis,
        "tracks": {track: {**tracks[track], "engine": engine, "mode": mode,
                           "scanner_sha256_basis": "installed-python" if mode == "native"
                           else "nuclei-executable"} for track, (engine, mode) in _MODES.items()},
        "cases": [{"case_id": case["id"], "path": case["path"], "expected": case["expected"],
                   "tracks": byCase[case["id"]]} for case in pack["cases"]],
        "equal_effective_budgets": all(item["effective_budget"] == nativeBudget
                                      for item in tracks.values()),
        "whole_application_accuracy": None}


def ReportPath(repository: Path, parent: str, name: str) -> str:
    """Identify the single saved report selected by the corresponding original gate."""

    reports = list((repository / parent).glob("run-*/" + name))
    Require(len(reports) == 1, "Comparison requires exactly one saved report per evidence owner")

    return reports[0].relative_to(repository).as_posix()


def VerifyAndCompare(repository: Path, head: str, tree: str) -> dict:
    """Recheck both original gates and derive the view from their bound report observations."""

    paths = (ReportPath(repository, NATIVE_ROOT, "report.json"), ReportPath(
        repository, "functional-evidence/external-nuclei-prerequisites", "comparison.json"))
    raw = tuple(Read(repository, path) for path in paths)
    VerifyNative(repository, head, tree)
    VerifyNuclei(repository, head, tree)
    pack = Decode(Read(repository, "labs/external/benchmark/juice-shop-cases.v1.json"))
    target = Decode(Read(repository, "labs/external/juice-shop.v1.json"))
    native, nuclei = (BuildComparison(pack, target, Decode(data)["observations"],
        (repository / path).parent) for path, data in zip(paths, raw, strict=True))
    Require(tuple(Read(repository, path) for path in paths) == raw,
            "A source report changed during original evidence verification")
    return {"kind": "pinned-external-scanner-comparison", "source_revision": head,
        "source_tree": tree, "source_report_sha256": {"native": hashlib.sha256(raw[0]).hexdigest(),
            "nuclei": hashlib.sha256(raw[1]).hexdigest()},
        **JoinVerifiedReports(pack, (native, nuclei), head)}


def Main(arguments: list[str] | None = None) -> int:
    """Write the finite view for an exact source checkout with extracted CI evidence."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True,
                        help="exact source checkout with the artifact under functional-evidence/")
    parser.add_argument("--head", required=True)
    parser.add_argument("--tree", required=True)
    options = parser.parse_args(arguments)
    view = VerifyAndCompare(options.repository, options.head, options.tree)
    print(json.dumps(view, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
