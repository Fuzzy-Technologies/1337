# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Validate finite external comparison records without starting or impersonating a scanner."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
from itertools import combinations
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

CONTRACT_DIRECTORY = Path(__file__).resolve().parents[2] / "labs/external/benchmark"
REQUIRED_ROLES = frozenset({
    "stdout", "stderr", "invocation", "findings", "target-provenance", "requests",
})
EXECUTED_STATUSES = frozenset({"completed", "crashed", "timed-out"})
ISOLATED_IPV4_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))


def DecodeJson(raw: bytes) -> object:
    """Decode any structured role while rejecting duplicate keys and nonfinite constants."""

    def Object(pairs):
        """Reject ambiguous metadata instead of silently retaining the final value."""

        result = {}

        for key, value in pairs:
            if key in result:
                raise ValueError("External benchmark JSON repeats a key")

            result[key] = value

        return result

    def Constant(value):
        """Reject nonstandard JSON numeric constants."""

        raise ValueError("External benchmark JSON contains a nonfinite constant")

    def Float(value):
        """Reject finite JSON syntax whose conversion overflows the host numeric range."""

        converted = float(value)

        if not math.isfinite(converted):
            raise ValueError("External benchmark JSON number is nonfinite")

        return converted

    return json.loads(raw.decode("utf-8"), object_pairs_hook=Object,
                      parse_constant=Constant, parse_float=Float)


def ReadJson(path: Path) -> dict:
    """Read one strict local contract object with the same decoder as acquired evidence."""

    result = DecodeJson(path.read_bytes())

    if not isinstance(result, dict):
        raise ValueError("External benchmark contract must be an object")

    return result


def LoadPack() -> tuple[dict, dict]:
    """Load the independent finite oracle and bind it to the existing immutable target."""

    schema = ReadJson(CONTRACT_DIRECTORY / "case-pack.schema.json")
    pack = ReadJson(CONTRACT_DIRECTORY / "juice-shop-cases.v1.json")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(pack)
    target = ReadJson(CONTRACT_DIRECTORY.parent / pack["target_manifest"])

    if pack["source_revision"] != target["source_revision"]:
        raise ValueError("Benchmark oracle source revision differs from the pinned target")

    for group in ("sources", "cases", "scanner_tracks", "deferred_inventory"):
        ids = [item["id"] for item in pack[group]]

        if len(set(ids)) != len(ids):
            raise ValueError("Benchmark identities must be unique within each group")

    sources = {item["id"] for item in pack["sources"]}

    for case in (*pack["cases"], *pack["deferred_inventory"]):
        if not set(case["source_ids"]) <= sources:
            raise ValueError("Every case source reference must exist independently")

    for track in pack["scanner_tracks"]:
        artifact = track["artifact"]

        if artifact is not None:
            VerifiedEvidence({"evidence": [{"role": "rule", **artifact}]}, CONTRACT_DIRECTORY)

    return pack, target


def VerifiedEvidence(execution: dict, evidence_root: Path) -> dict[str, bytes]:
    """Verify bounded local artifact bytes; metadata alone cannot establish execution."""

    evidence = {}

    for record in execution["evidence"]:
        relative = Path(record["path"])

        if relative.anchor or any(part in {".", ".."} for part in relative.parts):
            raise ValueError("Benchmark evidence must remain beneath its evidence directory")

        path = evidence_root / relative

        for component in (evidence_root, *(
            evidence_root.joinpath(*relative.parts[:index])
            for index in range(1, len(relative.parts) + 1)
        )):
            if component.is_symlink():
                raise ValueError("Benchmark evidence cannot traverse symbolic links")

        if record["role"] in evidence or not path.is_file():
            raise ValueError("Benchmark evidence roles must identify distinct existing files")

        with path.open("rb") as stream:
            raw = stream.read(record["size_bytes"] + 1)

        if len(raw) != record["size_bytes"] or hashlib.sha256(raw).hexdigest() != record["sha256"]:
            raise ValueError("Benchmark evidence bytes differ from the acquisition record")

        evidence[record["role"]] = raw

    return evidence


def ValidateObservation(pack: dict, target: dict, observation: dict, evidence_root: Path) -> None:
    """Reject invented completion, widened targets, mismatched inputs, or unsupported scoring."""

    schema = ReadJson(CONTRACT_DIRECTORY / "result.schema.json")
    json.dumps(observation, allow_nan=False)
    resource = Resource.from_contents(ReadJson(CONTRACT_DIRECTORY / "case-pack.schema.json"))
    registry = Registry().with_resource("case-pack.schema.json", resource)
    Draft202012Validator(schema, registry=registry).validate(observation)
    cases = {item["id"]: item for item in pack["cases"]}
    tracks = {item["id"]: item for item in pack["scanner_tracks"]}

    if observation["pack_id"] != pack["pack_id"] or observation["case_id"] not in cases:
        raise ValueError("Observation must address an exact declared pack and case")

    case = cases[observation["case_id"]]
    track = tracks[observation["scanner_track"]]
    status = observation["status"]

    if status in {"manual", "not-applicable"} and status != case["applicability"]:
        raise ValueError("A scanner coverage gap cannot change application applicability")

    if status not in EXECUTED_STATUSES:
        return

    execution = observation["execution"]
    parsed = urlsplit(execution["target_url"])

    try:
        address = ipaddress.ip_address(parsed.hostname or "")

    except ValueError as error:
        raise ValueError("Benchmark target must use an isolated literal address") from error

    isolated = address.is_loopback or any(
        address.version == network.version and address in network
        for network in ISOLATED_IPV4_NETWORKS
    )

    if not isolated or address.is_link_local or (
        address.is_multicast or address.is_unspecified or parsed.scheme != "http"
        or parsed.username is not None or parsed.password is not None
        or parsed.path != case["path"] or parsed.query or parsed.fragment
        or parsed.port != target["http_port"]
    ):
        raise ValueError("Benchmark execution changed the exact isolated case URL")

    if execution["source_revision"] != pack["source_revision"] or (
        execution["image_index_digest"] != target["index_digest"]
        or execution["platform_digest"] not in target["platform_digests"].values()
        or execution["scanner_id"] != track["scanner_id"]
        or (observation["scanner_track"] != "external-nuclei"
            and execution["product_revision"] is None)
        or (observation["scanner_track"] == "external-nuclei"
            and execution["product_revision"] is not None)
    ):
        raise ValueError("Executed scanner and target provenance must match the selected inputs")

    evidence = VerifiedEvidence(execution, evidence_root)

    if status == "completed":
        if track["implementation"] != "available" or case["applicability"] != "applicable":
            raise ValueError("Planned detectors and manual cases cannot establish completion")

        if track["artifact"] is not None and (
            execution["rule_sha256"] != track["artifact"]["sha256"]
        ):
            raise ValueError("Executed rule differs from the independently pinned artifact")

        operation_budget = execution["effective_budget"]["operation_timeout_seconds"]

        if execution["exit_code"] != 0 or execution["request_count"] != 1 or (
            execution["duration_seconds"] > operation_budget
            or not REQUIRED_ROLES <= evidence.keys()
        ):
            raise ValueError("Completed comparison requires bounded execution and evidence")

        invocation = DecodeJson(evidence["invocation"])

        if not isinstance(invocation, dict):
            raise ValueError("Acquired invocation must be an object")

        for key in ("argv", "scanner_id", "scanner_version", "scanner_sha256", "rule_sha256",
                    "product_revision", "effective_budget"):
            if invocation.get(key) != execution[key]:
                raise ValueError("Acquired invocation differs from supplied scanner metadata")

        if DecodeJson(evidence["findings"]) != execution["findings"]:
            raise ValueError("Normalized findings differ from their retained acquisition")

        provenance = DecodeJson(evidence["target-provenance"])

        if not isinstance(provenance, dict):
            raise ValueError("Acquired target provenance must be an object")

        for key in ("source_revision", "image_index_digest", "platform_digest", "target_url",
                    "target_instance", "reset_contract_sha256", "network_internal",
                    "published_ports"):
            if provenance.get(key) != execution[key]:
                raise ValueError("Acquired target provenance differs from comparison metadata")

        requests = DecodeJson(evidence["requests"])

        if requests != [{"method": "GET", "url": execution["target_url"]}]:
            raise ValueError("A completed case requires the exact single unauthenticated GET")


def BuildComparison(pack: dict, target: dict, observations: list[dict],
                    evidence_root: Path) -> dict:
    """Count only finite adjudicated completed cases and keep all missing work visible."""

    by_identity = {}

    for observation in observations:
        ValidateObservation(pack, target, observation, evidence_root)
        identity = (observation["case_id"], observation["scanner_track"])

        if identity in by_identity:
            raise ValueError("A case/scanner comparison may contain only one observation")

        by_identity[identity] = observation

    cells = []
    counts = {}

    for track in pack["scanner_tracks"]:
        totals = dict.fromkeys(("tp", "fp", "fn", "tn", "unscored", "coverage_gaps"), 0)

        for case in pack["cases"]:
            observation = by_identity.get((case["id"], track["id"]))
            status = observation["status"] if observation else (
                case["applicability"] if case["applicability"] != "applicable" else "not-run"
            )
            execution = observation["execution"] if observation else None
            mapped = []
            unadjudicated = []

            for finding in execution["findings"] if execution else ():
                destination = mapped if finding["path"] == case["path"] and (
                    finding["rule_id"] in track["rule_ids"]
                ) else unadjudicated
                destination.append(finding)

            score = None

            if status == "completed" and case["expected"] is not None:
                score = ("tp" if mapped else "fn") if case["expected"] else (
                    "fp" if mapped else "tn"
                )
                totals[score] += 1

            else:
                totals["unscored"] += 1

            if case["applicability"] == "applicable" and (
                status == "unsupported" or track["implementation"] != "available"
            ):
                totals["coverage_gaps"] += 1

            reason = observation["reason"] if observation else "No execution supplied"
            cells.append({"case_id": case["id"], "scanner_track": track["id"],
                          "applicability": case["applicability"], "expected": case["expected"],
                          "status": status, "score": score,
                          "reason": reason,
                          "unadjudicated_findings": unadjudicated,
                          "budget_deviation": bool(execution and execution["effective_budget"]
                                                   != pack["requested_budget"])})

        counts[track["id"]] = totals

    pairs = []

    for case in pack["cases"]:
        completed = [item for item in observations
                     if item["case_id"] == case["id"] and item["status"] == "completed"]

        for left, right in combinations(completed, 2):
            first, second = left["execution"], right["execution"]
            reasons = []

            if first["effective_budget"] != second["effective_budget"]:
                reasons.append("effective-budgets-differ")

            if first["reset_contract_sha256"] != second["reset_contract_sha256"]:
                reasons.append("reset-contracts-differ")

            if first["target_instance"] == second["target_instance"]:
                reasons.append("target-instance-reused-across-scanners")

            pairs.append({"case_id": case["id"],
                          "scanner_tracks": [left["scanner_track"], right["scanner_track"]],
                          "equal_budget_and_reset": not reasons, "differences": reasons})

    return {"schema_version": 1, "pack_id": pack["pack_id"], "cells": cells,
            "finite_completed_case_counts": counts, "whole_application_accuracy": None,
            "pairwise_conditions": pairs, "observations": observations}
