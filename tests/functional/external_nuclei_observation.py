# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Strict original application bundle binding and additive finite v2 observation assembly."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .external_native_runner import ImportBundle, StrictJson
from .external_nuclei_application import CaseSelection
from .external_nuclei_runner import (
    CONFIG_SHA256,
    TEMPLATE_SHA256,
    VERSION,
    AttemptProvenance,
    EffectiveBudget,
    ExactUrl,
    ProjectStandaloneMatches,
    StandaloneArguments,
)

SCAN = Path("/tmp/nuclei-application/scan")


def Json(root: Path, relative: str):
    """Decode an already bounded imported original without replacing or canonicalizing its bytes."""

    return StrictJson((root / relative).read_bytes())


def BindApplicationBundle(raw: bytes, output: Path, manifest_raw: bytes, revision: str,
                          track: str, path: str, target_instance: str, owner: str) -> dict:
    """Require one original producer to agree with its exact inspected-image prerequisite.

    The shared transport validates all file counts, byte/hash bounds and paths before writing.
    No producer invocation is rewritten, and standalone JSONL never goes through a product model.
    Whole-product custody is independently reopened through its actual model/evidence owners.
    """

    bundle = ImportBundle(raw, output)
    manifest = StrictJson(manifest_raw)
    selected = CaseSelection(track, path, target_instance, owner)

    if (output / "image-provisioning.json").read_bytes() != manifest_raw or (
        Json(output, "case-selection.json") != selected
        or manifest["source_revision"] != revision
        or Json(output, "outcome.json") != bundle["outcome"]
    ):
        raise ValueError("Nuclei application bundle differs from its original image/case binding")

    outcome = bundle["outcome"]

    if outcome["target_url"] != ExactUrl(path):
        raise ValueError("Nuclei application outcome changed its exact target input")

    invocation = Json(output, "scan/invocation.json")
    origin = manifest["installed"]["installed"]
    expected_argv = StandaloneArguments(Path(manifest["material"]["executable"]["path"]), path,
        SCAN / "prometheus-exposition.yaml", SCAN / "operator-config.yaml")
    fields = {"scanner_id": "nuclei" if track == "external-nuclei" else "native.nuclei",
        "scanner_version": VERSION, "scanner_sha256": manifest["material"]["executable"]["sha256"],
        "rule_sha256": TEMPLATE_SHA256, "product_revision": None if (
            track == "external-nuclei") else revision, "effective_budget": EffectiveBudget()}

    if invocation["argv"] != list(expected_argv) or any(
        invocation.get(name) != value for name, value in fields.items()
    ) or invocation["provider_timeout_seconds"] != 3:
        raise ValueError("Nuclei original invocation differs from the frozen comparison profile")

    if hashlib.sha256((output / "scan/prometheus-exposition.yaml").read_bytes()).hexdigest() != (
        TEMPLATE_SHA256
    ) or hashlib.sha256((output / "scan/operator-config.yaml").read_bytes()).hexdigest() != (
        CONFIG_SHA256
    ):
        raise ValueError("Nuclei copied original template/configuration bytes differ")

    expected_profile = json.loads(json.dumps(manifest["material"]["profile"]))
    expected_profile["templates"][0]["path"] = str(SCAN / "prometheus-exposition.yaml")
    expected_profile["configuration_path"] = str(SCAN / "operator-config.yaml")

    if Json(output, "scan/profile.json") != expected_profile or Json(
        output, "scan/attempt-provenance.json"
    ) != AttemptProvenance(path) or Json(output, "scan/requests.json") != (
        AttemptProvenance(path)["configured_requests"]
    ):
        raise ValueError("Nuclei original profile or configured-attempt facts differ")

    findings = Json(output, "scan/findings.json")

    if findings != outcome["findings"]:
        raise ValueError("Nuclei original findings differ from their enclosing producer outcome")

    if track == "external-nuclei":
        expected_environment = {"HOME": str(SCAN / "runtime-home"),
            "XDG_CONFIG_HOME": str(SCAN / "runtime-home/config"),
            "XDG_CACHE_HOME": str(SCAN / "runtime-home/cache"),
            "TMPDIR": str(SCAN / "runtime-home/tmp")}
        process = Json(output, "scan/process.json")

        if invocation["environment"] != expected_environment or Json(
            output, "scan/authorization.json"
        ) != selected["authorization"] or outcome["exit_code"] != process["exit_code"] or (
            outcome["duration_seconds"] != process["duration_seconds"]
        ):
            raise ValueError("Nuclei standalone original authority/environment/lifecycle differ")

        if outcome["status"] in {"completed", "unproven"} and (
            process["streams_complete"] is not True or process["timed_out"] is not False
            or any(process[key] is not None for key in ("capture_exhausted", "launch_error",
                "capture_error", "interrupted", "cleanup_error"))
        ):
            raise ValueError("Nuclei standalone success lacks complete original process ownership")

    else:
        from fuzzy1337.adapters import SerializeContract
        from fuzzy1337.evidence import LocalEvidenceStore
        from fuzzy1337.findings import Findings
        from fuzzy1337.model import LocalModelStore

        inventory = Json(output, "scan/installed-inventory.json")
        expected_inventory = {**origin, "whole1337_runtime_sha256": manifest["support_sha256"][
            "external_nuclei_runtime.py"]}
        state = LocalModelStore(output / "scan/workspace").Open()
        records = Json(output, "scan/acquisitions.json")
        evidence = LocalEvidenceStore(output / "scan/workspace/evidence")
        actual = tuple(evidence.Get(item["evidence_id"]) for item in records)
        streams = {item.reference.role: evidence.Read(item.reference) for item in actual}

        if inventory != expected_inventory or Json(output, "scan/model.json") != state.ToDict() or (
            len(actual) != 2 or set(streams) != {"stdout", "stderr"}
            or json.loads(SerializeContract(actual)) != records
            or streams["stdout"] != (output / "scan/stdout.raw").read_bytes()
            or streams["stderr"] != (output / "scan/stderr.raw").read_bytes()
            or Json(output, "scan/fixture-authorization.json") != selected["authorization"]
            or Json(output, "scan/findings.raw.json") != json.loads(
                SerializeContract(Findings(state)))
            or hashlib.sha256((output / "scan/installed.whl").read_bytes()).hexdigest()
                != origin["wheel"]["sha256"]
        ):
            raise ValueError("Whole1337 imported saved state or original paired custody differs")

        plan = Json(output, "scan/plan.json")

        expected_digest = hashlib.sha256(SerializeContract(plan["invocation"]).encode()).hexdigest()
        execution = actual[0].provenance.execution

        if plan["invocation"]["argv"] != invocation["argv"] or any(
            item.provenance.invocation_sha256 != expected_digest for item in actual
        ) or actual[0].provenance != actual[1].provenance or (
            execution is None or outcome["duration_seconds"] != execution.duration_seconds
            or outcome["exit_code"] != execution.exit_code
        ):
            raise ValueError("Whole1337 original plan differs from its retained invocation")

    if outcome["status"] in {"completed", "unproven"}:
        projected = ProjectStandaloneMatches((output / "scan/stdout.raw").read_bytes())

        if track == "whole1337":
            projected = [{**item, "rule_id": "nuclei." + item["rule_id"]} for item in projected]

        if type(outcome["exit_code"]) is not int or outcome["exit_code"] != 0 or (
            projected != findings
        ):
            raise ValueError("Nuclei success must retain exact genuine raw matching identities")

    return bundle


def Observation(pack: dict, target: dict, case: dict, track: str, root: Path,
                scanner: Path, provenance: Path, outcome: dict) -> dict:
    """Assemble v2 from originals, retaining unknown contacts and failed exits."""

    invocation = Json(scanner, "scan/invocation.json")
    target_facts = StrictJson(provenance.read_bytes())
    execution = {key: invocation[key] for key in ("scanner_id", "scanner_version", "scanner_sha256",
        "rule_sha256", "product_revision", "argv", "effective_budget")}
    execution.update({key: target_facts[key] for key in ("source_revision", "image_index_digest",
        "platform_digest", "target_url", "target_instance", "reset_contract_sha256",
        "network_internal", "published_ports")})
    execution.update(exit_code=outcome["exit_code"], duration_seconds=outcome["duration_seconds"],
        request_count=1, findings=Json(scanner, "scan/findings.json"), evidence=[])
    roles = [(role, scanner / "scan" / name) for role, name in (
        ("stdout", "stdout.raw"), ("stderr", "stderr.raw"), ("invocation", "invocation.json"),
        ("findings", "findings.json"), ("requests", "requests.json"),
        ("attempt-provenance", "attempt-provenance.json"))]
    roles.extend((("target-provenance", provenance),
                  ("image-provisioning", scanner / "image-provisioning.json"),
                  ("case-selection", scanner / "case-selection.json")))

    for role, path in roles:
        raw = path.read_bytes()
        execution["evidence"].append({"role": role, "path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)})

    return {"schema_version": 2, "pack_id": pack["pack_id"], "case_id": case["id"],
            "scanner_track": track, "status": outcome["status"], "reason": outcome["reason"],
            "execution": execution}
