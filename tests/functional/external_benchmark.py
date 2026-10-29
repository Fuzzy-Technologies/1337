# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Validate finite external comparison records without starting or impersonating a scanner."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from itertools import combinations
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

CONTRACT_DIRECTORY = Path(__file__).resolve().parents[2] / "labs/external/benchmark"
REQUIRED_ROLES = frozenset({
    "stdout", "stderr", "invocation", "findings", "target-provenance", "requests",
})
EXECUTED_STATUSES = frozenset({"completed", "unproven", "failed", "crashed", "timed-out",
                               "cancelled"})
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
NUCLEI_RULE_PREFIXES = {"whole1337": "nuclei.", "external-nuclei": ""}
NUCLEI_ATTEMPT_BASIS = "approved-single-configured-nuclei-invocation"
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


def VerifiedEvidence(execution: dict, evidence_root: Path, *,
                     maximum: int = MAX_EVIDENCE_BYTES) -> dict[str, bytes]:
    """Verify bounded local artifact bytes; metadata alone cannot establish execution."""

    evidence = {}

    for record in execution["evidence"]:
        relative = Path(record["path"])

        if relative.anchor or any(part in {".", ".."} for part in relative.parts):
            raise ValueError("Benchmark evidence must remain beneath its evidence directory")

        size = record["size_bytes"]

        if type(size) is not int or not 0 <= size <= maximum:
            raise ValueError("Benchmark evidence exceeds the 2 MiB per-file ceiling")

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


def ProjectNucleiMatches(raw: bytes, scanner_track: str) -> list[dict]:
    """Project explicit raw match identities without invoking product normalization or a scanner."""

    if len(raw) > MAX_EVIDENCE_BYTES:
        raise ValueError("Benchmark Nuclei stdout exceeds the 2 MiB per-file ceiling")

    findings = []

    for line in raw.splitlines():
        record = DecodeJson(line)

        if not isinstance(record, dict) or record.get("type") != "http" or (
            not isinstance(record.get("template-id"), str) or not record["template-id"]
            or not isinstance(record.get("matched-at"), str) or not record["matched-at"]
            or ("matcher-status" in record and record["matcher-status"] is not True)
        ):
            raise ValueError("Benchmark Nuclei output requires explicit HTTP match identities")

        parsed = urlsplit(record["matched-at"])

        if parsed.scheme != "http" or not parsed.netloc:
            raise ValueError("Benchmark Nuclei match requires an explicit HTTP URL")

        findings.append({"rule_id": NUCLEI_RULE_PREFIXES[scanner_track] + record["template-id"],
                         "path": parsed.path, "target_url": record["matched-at"]})

    return findings


def PartitionFindings(observation: dict, case: dict, track: dict) -> tuple[list, list]:
    """Keep unknown identities visible and require exact v2 input binding before adjudication."""

    execution = observation["execution"]
    mapped, unadjudicated = [], []

    for finding in execution["findings"] if execution else ():
        exact_input = observation["schema_version"] == 1 or (
            finding["target_url"] == execution["target_url"]
        )
        destination = mapped if exact_input and finding["path"] == case["path"] and (
            finding["rule_id"] in track["rule_ids"]
        ) else unadjudicated
        destination.append(finding)

    return mapped, unadjudicated


def ValidateHostAttempt(observation: dict, target: dict, case: dict, evidence_root: Path) -> None:
    """Require original source-bound start/capture/cleanup facts for failed null-provider rows."""

    if observation["schema_version"] != 2 or observation["status"] not in {
        "failed", "crashed", "timed-out", "cancelled",
    }:
        raise ValueError("Only failed v2 attempts may omit unavailable provider execution facts")

    attempt = observation["host_attempt"]
    evidence = {}

    for record in attempt["evidence"]:
        if record["role"] in evidence:
            raise ValueError("Host attempt repeats an original evidence role")

        maximum = 12 * 1024 * 1024 if record["role"] == "host-start-stdout" else MAX_EVIDENCE_BYTES
        evidence.update(VerifiedEvidence({"evidence": [record]}, evidence_root, maximum=maximum))

    required = {"host-attempt", "host-start-stdout", "host-start-stderr", "host-cleanup",
                "target-provenance", "source-provenance", "host-start-command"}

    if not required <= evidence.keys() or attempt["case_id"] != observation["case_id"] or (
        attempt["scanner_track"] != observation["scanner_track"]
        or attempt["start_attempted"] is not True
    ):
        raise ValueError("Failed host attempt lost its exact original case/track/start facts")

    original = DecodeJson(evidence["host-attempt"])
    command = DecodeJson(evidence["host-start-command"])
    cleanup = DecodeJson(evidence["host-cleanup"])
    source = DecodeJson(evidence["source-provenance"])
    provenance = DecodeJson(evidence["target-provenance"])

    if any(not isinstance(value, dict) for value in (
        original, command, cleanup, source, provenance
    )):
        raise ValueError("Original host attempt evidence requires explicit structured records")

    if type(original.get("start_attempted")) is not bool:
        raise ValueError("Original host attempt requires an exact recorded start boolean")

    required_command = {"exit_code", "cleanup_confirmed", "streams_complete", "timed_out",
                        "launch_error", "capture_error", "interrupted", "duration_seconds"}

    if not required_command <= command.keys() or any(type(command[key]) is not bool for key in (
        "cleanup_confirmed", "streams_complete", "timed_out"
    )) or (command["exit_code"] is not None and type(command["exit_code"]) is not int):
        raise ValueError("Failed host attempt requires its original explicit capture lifecycle")

    for role in ("stdout", "stderr"):
        raw = evidence["host-start-" + role]

        if command.get(role) != {"size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}:
            raise ValueError("Failed host raw bytes differ from original command custody")

    if any(original.get(key) != attempt[key] for key in (
        "source_revision", "case_id", "scanner_track", "target_instance", "start_attempted",
    )) or source.get("revision") != attempt["source_revision"] or (
        original.get("source_tree") != source.get("tree")
        or provenance.get("target_instance") != attempt["target_instance"]
        or provenance.get("target_url") != "http://127.0.0.1:" + str(
            target["http_port"]) + case["path"]
        or provenance.get("source_revision") != target["source_revision"]
        or provenance.get("image_index_digest") != target["index_digest"]
        or provenance.get("platform_digest") not in target["platform_digests"].values()
        or provenance.get("network_internal") is not True
        or type(provenance.get("published_ports")) is not int
        or provenance.get("published_ports") != 0
        or command.get("argv") != original.get("start_argv")
        or not isinstance(command.get("argv"), list)
        or len(command["argv"]) != 9
        or command["argv"][:4] != ["/usr/bin/docker", "--host",
                                    "unix:///var/run/docker.sock", "--config"]
        or re.fullmatch("[a-f0-9]{40}", str(original.get("source_tree"))) is None
        or re.fullmatch("[a-f0-9]{64}", str(original.get("runner_container_id"))) is None
        or command["argv"][-4:] != ["container", "start", "--attach",
                                    original.get("runner_container_id")]
        or "container_absent" not in cleanup or "target_absent" not in cleanup
        or any(cleanup[key] is not None and type(cleanup[key]) is not bool
               for key in ("container_absent", "target_absent"))
    ):
        raise ValueError("Failed host attempt lost its source/target/capture/cleanup binding")


def ValidateObservation(pack: dict, target: dict, observation: dict, evidence_root: Path) -> None:
    """Reject invented completion, widened targets, mismatched inputs, or unsupported scoring."""

    version = observation.get("schema_version")
    schema = ReadJson(CONTRACT_DIRECTORY / (
        "result.v2.schema.json" if version == 2 else "result.schema.json"
    ))
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

    if execution is None:
        ValidateHostAttempt(observation, target, case, evidence_root)

        return

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

    if status in {"completed", "unproven"}:
        if track["implementation"] != "available" or case["applicability"] != "applicable":
            raise ValueError("Planned detectors and manual cases cannot establish completion")

        if track["artifact"] is not None and (
            execution["rule_sha256"] != track["artifact"]["sha256"]
        ):
            raise ValueError("Executed rule differs from the independently pinned artifact")

        operation_budget = execution["effective_budget"]["operation_timeout_seconds"]

        if type(execution["exit_code"]) is not int or execution["exit_code"] != 0 or (
            execution["request_count"] != 1 or
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

        if version == 2:
            if "attempt-provenance" not in evidence:
                raise ValueError("Nuclei observations require explicit attempt provenance")

            attempt = DecodeJson(evidence["attempt-provenance"])

            if not isinstance(attempt, dict) or attempt.get("basis") != NUCLEI_ATTEMPT_BASIS or (
                type(attempt.get("approved_attempt_count")) is not int
                or attempt["approved_attempt_count"] != 1
                or "independent_server_contact_count" not in attempt
                or attempt["independent_server_contact_count"] is not None
            ):
                raise ValueError("Nuclei invocation does not establish independent server contacts")

            projected = ProjectNucleiMatches(evidence["stdout"], observation["scanner_track"])

            if projected != execution["findings"]:
                raise ValueError("Nuclei findings differ from explicit raw match identities")

            mapped, _ = PartitionFindings(observation, case, track)

            if (status == "completed") != bool(mapped):
                raise ValueError(
                    "Nuclei completion requires a mapped match; absence stays unproven"
                )


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
            mapped, unadjudicated = (
                PartitionFindings(observation, case, track) if observation else ([], [])
            )

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

    version = 2 if any(item["schema_version"] == 2 for item in observations) else 1

    return {"schema_version": version, "pack_id": pack["pack_id"], "cells": cells,
            "finite_completed_case_counts": counts, "whole_application_accuracy": None,
            "pairwise_conditions": pairs, "observations": observations}
