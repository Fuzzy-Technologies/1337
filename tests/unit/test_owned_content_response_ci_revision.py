# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Synthetic stale-CAS evidence attacks; no SDK, target, build or installed runtime executes."""

from __future__ import annotations

import copy
import hashlib
import json
from urllib.parse import urlsplit

import pytest

from tests.contract import owned_content_response_ci_revision_evidence as evidence
from tests.contract.owned_content_response_oracle import RequestBytes
from tests.contract.owned_content_response_sdk_oracle import Canonical
from tests.unit.test_owned_content_response_header_v2_oracle import Fixture as HeaderFixture
from tests.unit.test_owned_content_response_header_v2_oracle import Saves
from tests.unit.test_owned_content_response_product_runner import Installation, Process, SourceFacts
from tests.unit.test_owned_content_response_sdk_pipeline import Guard


def Fixture(tmp_path):
    """Build marked synthetic originals with real fixture hashes and detached original CAS bases."""

    acquired, _, _, _, options = HeaderFixture()
    before = copy.deepcopy(acquired)
    before["model"]["revision"] -= 1
    before["workspace"]["revision"] -= 1
    before["model"]["objects"] = before["model"]["objects"][1:]
    before["model"]["observations"] = []
    before["workspace"]["object_references"] = before["workspace"]["object_references"][1:]

    for key in ("scope_references", "job_references", "evidence_record_references",
        "evidence_references"):
        before["workspace"][key] = []

    before["originals"] = {}
    source = acquired["model"]["observations"][0]["attributes"]
    capture = {"schema_version": 1, "workflow": "owned-content-response-capture",
        "source_id": "native.loopback-content-response", "state": "completed",
        "acquisition_outcome": "captured", "custody_status": "complete", "stage_retained": True,
        "original_job_id": source["original_job_id"], "original_receipt_id": options["receipt_id"],
        "original_role_ids": source["original_role_ids"], "source_facts": source,
        "model_revision": acquired["model"]["revision"],
        "workspace_revision": acquired["workspace"]["revision"],
        "model_persistence_status": "acknowledged", "workspace_persistence_status": "acknowledged",
        "job": {"spec": {"job_id": source["original_job_id"], "workspace_id": "unit-only",
            "scope_reference": "scope:unit-only"}, "state": "completed", "failure": None,
            "cancellation_requested": False}}
    setup = {"state": before, "scope": options["authority"]["scope"], "policies": {
        "analysis": {"path": "/mock-only/passive-policy.json",
            "document": options["authority"]["policy"]}}}
    summary = {"state": "failed", "failure": "revision-conflict", "condition_observed": None,
        "assessment_reference": None, "finding_reference": None,
        "model_commit": "not-attempted", "workspace_commit": "not-attempted",
        "model_revision": acquired["model"]["revision"],
        "workspace_revision": acquired["workspace"]["revision"]}
    selected = {"workspace": "/mock-only/pipeline/workspace", "url": options["url"],
        "scope_id": "unit-only", "owner_reference": options["authority"]["owner_reference"],
        "policy": setup["policies"]["analysis"]["path"],
        "original_receipt_id": options["receipt_id"], "analysis_reference": options["analysis"],
        "expected_model_revision": acquired["model"]["revision"] - 1,
        "expected_workspace_revision": acquired["workspace"]["revision"],
        "approve_passive_header_check": True, "authority_scenario": "positive"}
    plan = {"selection": {"scenario": "stale-model-revision", "case": "missing",
        "url": options["url"]}, "expected_state": "failed", "expected_findings": 0,
        "workspace_id": "unit-only", "scope_id": "unit-only",
        "owner_reference": selected["owner_reference"], "analysis_reference": options["analysis"]}
    guard = {"authority_scenario": "positive", "owner_reads": 0, "guard": Guard()}
    helpers = {name: {"path": "/mock-only/tests/contract/" + name, "sha256": "a" * 64}
        for name in (evidence.ACTOR_HELPER, "owned_content_response_sdk_consumer.py",
            "owned_content_response_sdk_controls.py", "owned_content_response_sdk_setup.py",
            "owned_response_product_runner.py", "owned_content_response_sdk_offline_guard.py")}
    helpers[evidence.ACTOR_HELPER]["sha256"] = evidence.ACTOR_HELPER_SHA256
    documents = {"pipeline-result.json": {"state": "checked-revision-conflict",
        "expected_findings": 0, "runtime_acceptance": "passed", "source_delivery": "normal-eof"},
        "pipeline-plan.json": plan, "stage-04-input.json": {"selection": selected},
        "pipeline-helper-sources.json": helpers,
        "sdk-capture-original.json": {"summary": copy.deepcopy(capture), "exception_type": None,
            "store_saves": Saves(before, acquired)},
        "sdk-analyze-offline-consumer.json": {"summary": copy.deepcopy(summary),
            "exception_type": None}, "sdk-analyze-offline-guard.json": copy.deepcopy(guard)}
    installation, identity = Installation()
    identity.update(python="/owned/environment/bin/python", prefix="/owned/environment")

    for index, (operation, actual) in enumerate(zip(evidence.OPERATIONS, (
        setup, capture, {"original_inspection": acquired}, summary,
        {"original_inspection": copy.deepcopy(acquired)}), strict=True), start=3):
        required = {evidence.ACTOR_HELPER, "owned_content_response_sdk_consumer.py"}
        required.update(("owned_content_response_sdk_controls.py",
            "owned_content_response_sdk_setup.py", "owned_response_product_runner.py") if (
                operation in ("fresh-setup", "inspect")) else (
                    "owned_content_response_sdk_offline_guard.py",) if operation.endswith(
                        "-offline") else ())
        child = {"operation": operation, "summary": copy.deepcopy(actual),
            "installed_identity": copy.deepcopy(identity),
            "consumer_sources": {name: copy.deepcopy(helpers[name]) for name in required}}

        if operation == "analyze-offline":
            child.update(copy.deepcopy(guard))

        prefix = f"process-{index:03d}-sdk-{operation}"
        argv = [identity["python"], "-I", "-B", helpers[evidence.ACTOR_HELPER]["path"],
            operation, f"/mock-only/pipeline/stage-{index - 2:02d}-input.json", "--execute"]
        terminal = Process(Canonical(child), options["url"], 0)
        terminal.update(argv=argv, cwd="/mock-only/pipeline", timeout_seconds=35,
            installation={"identity": {**copy.deepcopy(installation), "installed_sources": (
                copy.deepcopy(identity["installed_sources"]))}, "manifest_sha256": "b" * 64})
        terminal["installation"]["manifest_sha256"] = hashlib.sha256(json.dumps(
            terminal["installation"]["identity"], sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()
        documents[prefix + "/stdout.bin"] = child
        documents[prefix + "/process.json"] = terminal
        documents[prefix + "/invocation.json"] = {"schema_version": 1, "argv": argv,
            "cwd": terminal["cwd"], "timeout_seconds": 35, "stdin": "closed-devnull",
            "state": "not-launched", "returncode": None, "terminal_return_observed": False,
            "installation": copy.deepcopy(terminal["installation"])}

    _, _, main, sentinel, _ = SourceFacts()
    parsed = urlsplit(options["url"])
    main["origin"] = f"http://127.0.0.1:{parsed.port}"
    main["accepted_endpoints"]["0"]["local_port"] = parsed.port
    main["contacts"][0].update(request_hex=RequestBytes(options["url"]).hex(),
        received_bytes=len(RequestBytes(options["url"])))
    documents.update({"main-source-final.json": main, "sentinel-source-final.json": sentinel})
    junit = tmp_path / "revision.xml"
    junit.write_text('<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
        f'<testcase classname="{evidence.CASE_CLASS}" name="{evidence.CASE_NAME}"/>'
        '</testsuite></testsuites>')
    retained = tmp_path / "retained"
    case = retained / "run-mock-only/stale-model-revision"
    path = case.parent / "installation/wheel-identity.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(Canonical(installation))
    path.with_name("source-checkpoint.json").write_bytes(Canonical({key: installation[key]
        for key in ("schema_version", "source_commit", "source_tree", "source_modules_sha256")}))

    return junit, retained, case, documents


@pytest.mark.parametrize("mutation", [None, "wrong-case", "wrong-class", "skip", "hidden-skip",
    "extra-case", "duplicate-result", "bool-count", "wrong-scenario", "wrong-source-case",
    "bool-plan-count", "approval-denied", "missing-permission", "denied-scope", "owner-basis",
    "not-stale", "stale-workspace", "negative-basis", "bool-basis", "receipt",
    "capture-lost-ack", "capture-incomplete", "source-bytes", "child-summary", "wrong-failure",
    "clean-negative", "condition", "assessment", "finding", "exception", "model-ack",
    "workspace-ack", "wrong-revision", "actor-read", "bool-actor-read", "save", "guard-call",
    "child-guard", "changed-state", "helper-hash", "child-helper", "installed-source",
    "terminal-digest", "manifest-digest", "source-checkpoint", "timeout", "argv", "later-stage",
    "replay", "sentinel-contact"])
def test_StaleCasRequiresExactOriginalBasisWithoutAdmissionInterpretationOrWrites(
    tmp_path, mutation,
):
    """Self-consistent synthetic records cannot substitute another failure or invent admission."""

    junit, retained, case, documents = Fixture(tmp_path)
    plan = documents["pipeline-plan.json"]
    selected = documents["stage-04-input.json"]["selection"]
    setup = documents["process-003-sdk-fresh-setup/stdout.bin"]["summary"]
    capture = documents["sdk-capture-original.json"]
    guard = documents["sdk-analyze-offline-guard.json"]
    child = documents["process-006-sdk-analyze-offline/stdout.bin"]
    consumer = documents["sdk-analyze-offline-consumer.json"]
    summary = consumer["summary"]

    if mutation in ("wrong-case", "wrong-class", "skip", "hidden-skip", "extra-case"):
        old, new = {"wrong-case": (evidence.CASE_NAME, "unrelated_case"),
            "wrong-class": (evidence.CASE_CLASS, "unrelated.class"),
            "skip": ('skipped="0"', 'skipped="1"'),
            "hidden-skip": ('/>', '><skipped/></testcase>'),
            "extra-case": ('</testsuite>', '<testcase/></testsuite>')}[mutation]
        junit.write_text(junit.read_text().replace(old, new))

    elif mutation == "duplicate-result":
        path = retained / "run-duplicate/stale-model-revision/pipeline-result.json"
        path.parent.mkdir(parents=True)
        path.write_bytes(Canonical(documents["pipeline-result.json"]))

    elif mutation == "bool-count":
        documents["pipeline-result.json"]["expected_findings"] = False

    elif mutation in ("wrong-scenario", "wrong-source-case"):
        plan["selection"]["scenario" if mutation == "wrong-scenario" else "case"] = "positive"

    elif mutation == "bool-plan-count":
        plan["expected_findings"] = False

    elif mutation == "approval-denied":
        selected["approve_passive_header_check"] = False

    elif mutation == "missing-permission":
        setup["policies"]["analysis"]["document"]["permissions"] = []

    elif mutation == "denied-scope":
        setup["scope"]["authorization"]["state"] = "denied"

    elif mutation == "owner-basis":
        selected["owner_reference"] = "actor:foreign"

    elif mutation in ("not-stale", "stale-workspace", "negative-basis", "bool-basis"):
        field = "expected_workspace_revision" if mutation == "stale-workspace" else (
            "expected_model_revision")
        selected[field] = {"not-stale": 4, "stale-workspace": 1,
            "negative-basis": -1, "bool-basis": True}[mutation]

    elif mutation == "receipt":
        selected["original_receipt_id"] = "sha256:" + "0" * 64

    elif mutation == "capture-lost-ack":
        capture["store_saves"][0]["returned"] = None

    elif mutation == "capture-incomplete":
        capture["summary"]["custody_status"] = "incomplete"
        documents["process-004-sdk-capture/stdout.bin"]["summary"] = copy.deepcopy(
            capture["summary"])

    elif mutation == "source-bytes":
        state = documents["process-005-sdk-inspect/stdout.bin"]["summary"]["original_inspection"]
        identity = capture["summary"]["original_role_ids"]["owned-response-headers"]
        state["originals"][identity]["data_hex"] = b"substituted".hex()

    elif mutation == "child-summary":
        child["summary"]["failure"] = "authorization"

    elif mutation in ("wrong-failure", "clean-negative", "condition", "assessment", "finding",
        "exception", "model-ack", "workspace-ack", "wrong-revision"):
        if mutation == "wrong-failure":
            summary.update(state="denied", failure="authorization")

        elif mutation == "clean-negative":
            summary.update(state="completed", failure=None, condition_observed=False)

        elif mutation in ("condition", "assessment", "finding"):
            key = "condition_observed" if mutation == "condition" else mutation + "_reference"
            summary[key] = False if mutation == "condition" else "unexpected:interpretation"

        elif mutation == "exception":
            consumer["exception_type"] = "UnexpectedError"

        elif mutation in ("model-ack", "workspace-ack"):
            summary[mutation.removesuffix("-ack") + "_commit"] = "acknowledged"

        else:
            summary["model_revision"] = 3

        child["summary"] = copy.deepcopy(summary)

    elif mutation in ("actor-read", "bool-actor-read"):
        guard["owner_reads"] = child["owner_reads"] = 1 if mutation == "actor-read" else False

    elif mutation == "save":
        guard["guard"]["saves"] = child["guard"]["saves"] = [{"owner": "model"}]

    elif mutation == "guard-call":
        guard["guard"]["calls"]["LocalEvidenceStore.Put"] = 1
        child["guard"] = copy.deepcopy(guard["guard"])

    elif mutation == "child-guard":
        child["guard"]["audit_probe_seen"] = False

    elif mutation == "changed-state":
        documents["process-007-sdk-inspect/stdout.bin"]["summary"]["original_inspection"][
            "model"]["revision"] += 1

    elif mutation == "helper-hash":
        documents["pipeline-helper-sources.json"][evidence.ACTOR_HELPER]["sha256"] = "0" * 64

    elif mutation == "child-helper":
        child["consumer_sources"][evidence.ACTOR_HELPER]["path"] = "/mock-only/another-helper.py"

    elif mutation == "installed-source":
        child["installed_identity"]["installed_sources"]["native_response_header_workflow.py"][
            "sha256"] = "0" * 64

    elif mutation == "manifest-digest":
        documents["process-006-sdk-analyze-offline/process.json"]["installation"][
            "manifest_sha256"] = "0" * 64

    elif mutation == "source-checkpoint":
        path = case.parent / "installation/source-checkpoint.json"
        checkpoint = json.loads(path.read_bytes())
        checkpoint["source_tree"] = "0" * 40
        path.write_bytes(Canonical(checkpoint))

    elif mutation == "timeout":
        documents["process-006-sdk-analyze-offline/process.json"]["state"] = "timeout"

    elif mutation == "argv":
        documents["process-006-sdk-analyze-offline/process.json"]["argv"].remove("-I")

    elif mutation == "later-stage":
        documents["physical-relocation.json"] = {"original_root_absent": True}

    elif mutation == "replay":
        documents["process-008-sdk-replay-offline/process.json"] = {"returncode": 0}

    elif mutation == "sentinel-contact":
        documents["sentinel-source-final.json"]["counters"]["contacts"] = 1

    for name, value in list(documents.items()):
        if name.endswith("/stdout.bin"):
            terminal = documents[name.removesuffix("stdout.bin") + "process.json"]
            raw = Canonical(value)
            terminal["stdout"].update(observed_size_bytes=len(raw), retained_size_bytes=len(raw),
                observed_sha256=hashlib.sha256(raw).hexdigest())

    if mutation == "terminal-digest":
        documents["process-006-sdk-analyze-offline/process.json"]["stdout"][
            "observed_sha256"] = "0" * 64

    for name, value in documents.items():
        path = case / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(Canonical(value))

        if name.endswith("/stdout.bin"):
            path.with_name("stderr.bin").write_bytes(b"")

    if mutation is None:
        assert evidence.RequireOutcome(junit, retained) == documents["pipeline-result.json"], (
            "Only this exact synthetic pre-admission CAS conflict may satisfy the evidence gate")
        assert evidence.Main([str(junit), str(retained)]) == 0, (
            "The standalone original-evidence checker must enforce the same stale-CAS contract")

    else:
        with pytest.raises((AssertionError, ValueError)):
            evidence.RequireOutcome(junit, retained)


def test_StaleModelEntrypointRequiresBothOriginalPaths():
    """No implicit original evidence location may be selected by the read-only checker."""

    with pytest.raises(ValueError, match="Expected original stale-model"):
        evidence.Main([])
