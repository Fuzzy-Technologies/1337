# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent actual installed acquisition SDK/CLI, canonical originals and relocated replay."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from tests.integration.test_owned_response_worker_execution import (
    CATALOG_SHA256,
    Canonical,
    CatalogCase,
    ExpectedRequest,
    OwnedResponseListener,
)
from tests.integration.test_owned_response_worker_execution import (
    installed_worker as installed_worker,
)

RUNNER = Path(__file__).resolve().parents[1] / "contract/owned_response_product_runner.py"
OWNER = "actor:owned-response-product"
WORKSPACE = "owned-response-product"
ROLES = {"stdout": "application/json", "stderr": "application/octet-stream",
    "owned-response-request": "application/octet-stream",
    "owned-response-headers": "application/octet-stream",
    "owned-response-body": "text/html; charset=utf-8",
    "owned-response-wire": "application/octet-stream", "owned-response-receipt": "application/json"}


@pytest.fixture(autouse=True)
def supported_product_runtime():
    """Refuse missing required Linux capability instead of disguising it as positive acceptance."""

    if sys.platform != "linux":
        if os.environ.get("FUZZY1337_RUN_OWNED_RESPONSE_PRODUCT_ACCEPTANCE") == "1":
            pytest.fail("Required product acceptance needs the supported Linux acquisition parent")

        pytest.skip("Unsupported acquisition parent; this skip is not positive acceptance")


class HeldResponseListener(OwnedResponseListener):
    """Observe one actual GET then send nothing while the SDK owns worker cancellation."""

    def __init__(self, readiness: Path) -> None:
        """Bind only this test's listener and record no readiness until the full request arrives.

        Args:
            readiness: Owned control marker read by the isolated installed SDK consumer.
        """

        self.readiness = readiness
        self.peer_closed = False
        self.hold_expired = False
        super().__init__(b"")

    def Serve(self) -> None:
        """Keep one connection open until actual peer EOF, with a finite emergency hold."""

        while not self.stopping.is_set():
            try:
                connection, _ = self.listener.accept()

            except socket.timeout:
                continue

            except OSError:
                return

            self.accepted += 1
            request = bytearray()

            with connection:
                connection.settimeout(3)

                try:
                    while b"\r\n\r\n" not in request and len(request) <= 1024:
                        chunk = connection.recv(1025 - len(request))

                        if not chunk:
                            return

                        request.extend(chunk)

                    self.requests.append(bytes(request))
                    self.readiness.write_bytes(b"actual-selected-get")
                    self.peer_closed = connection.recv(1) == b""

                except (OSError, TimeoutError):
                    self.hold_expired = True


def Sha(value) -> str:
    """Identify independent primitive JSON expectations without production identity builders."""

    return hashlib.sha256(Canonical(value)).hexdigest()


def Files(root: Path) -> dict:
    """Snapshot only this owned workspace's bytes and mutation times to detect replay writes."""

    return {path.relative_to(root).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in root.rglob("*") if path.is_file()}


def Policy(allowed: bool = True) -> dict:
    """Write the explicit existing SAFE acquisition policy grammar independently."""

    return {"policy_id": "owned-response-product", "revision": 0, "maximum_impact": "SAFE",
        "permissions": [{"capability_id": "http.synthetic-response-capture",
            "adapter_id": "native.loopback-response", "maximum_impact": "SAFE",
            "granted_privileges": []}] if allowed else [], "max_authorization_seconds": 300}


def CaptureRuntime(installed: Path, root: Path) -> Path:
    """Install the same actual wheel separately so original runtime inputs can be removed."""

    wheel, = tuple((installed.parents[2] / "wheel").glob("*.whl"))
    created = subprocess.run((sys.executable, "-m", "venv", str(root)),
        capture_output=True, timeout=30, check=False)
    assert created.returncode == 0, "Capture interpreter creation failed: " + repr(created.stderr)
    python = root / "bin/python"
    result = subprocess.run((str(python), "-I", "-B", "-m", "pip", "--isolated", "install",
        "--no-index", "--no-deps", "--no-compile", "--disable-pip-version-check", str(wheel)),
        capture_output=True, timeout=30, check=False)
    assert result.returncode == 0, (
        "Offline capture-wheel installation failed: " + repr(result.stderr)
    )

    return python


def Consumer(python: Path, directory: Path, mode: str, config: dict) -> dict:
    """Execute only the owned fixed SDK consumer under isolated installed Python."""

    path = directory / (mode + "-config.json")
    path.write_bytes(Canonical(config))
    result = subprocess.run((str(python), "-I", "-B", str(RUNNER), mode, str(path)),
        cwd=directory, capture_output=True, timeout=35, check=False)
    assert result.returncode == 0 and result.stderr == b"", (
        "Installed SDK consumer failed: " + repr(result.stderr)
    )

    return json.loads(result.stdout)


def Cli(python: Path, directory: Path, arguments: tuple[str, ...]):
    """Run the actual installed CLI entry point, with no injected source import path."""

    return subprocess.run((str(python), "-I", "-B", "-m", "fuzzy1337", "--json", "response",
        *arguments), cwd=directory, capture_output=True, timeout=35, check=False)


def ExpectedWorker(listener, case: dict) -> dict:
    """Build expected worker bytes from the frozen independent wire and handwritten request only."""

    request = ExpectedRequest(listener, case["case_id"])

    return {"schema_version": 1, "profile": "owned-response-capture.v1", "outcome": "captured",
        "catalog_sha256": CATALOG_SHA256, "case_id": case["case_id"],
        "url": listener.origin + case["path"], "address": "127.0.0.1", "port": listener.port,
        "request": {"base64": base64.b64encode(request).decode(), "size_bytes": len(request),
            "sha256": hashlib.sha256(request).hexdigest()},
        "response_headers": {key: case["header_section"][key]
            for key in ("base64", "size_bytes", "sha256")},
        "response_body": {key: case["body"][key] for key in ("base64", "size_bytes", "sha256")},
        "response": {key: case["response"][key] for key in ("size_bytes", "sha256")}}


def CheckCapture(summary, state, prior, listener, case, python, root, observed=None) -> dict:
    """Authenticate original seven-role custody and one real canonical transition per capture."""

    assert summary["state"] == "completed" and summary["acquisition_outcome"] == "captured", (
        "Actual installed acquisition and both canonical acknowledgements must complete"
    )
    assert summary["model_persistence_status"] == summary["workspace_persistence_status"] == (
        "acknowledged") and summary["stage_retained"] is True, (
        "Successful composition must report actual acknowledgement and honestly retained staging"
    )
    assert state["model"]["revision"] == prior["model"]["revision"] + 1 and (
        state["workspace"]["revision"] == prior["workspace"]["revision"] + 1
        and summary["model_revision"] == state["model"]["revision"]
        and summary["workspace_revision"] == state["workspace"]["revision"]
    ), "Each actual capture must acknowledge exactly one model and one workspace revision"
    ids = summary["original_role_ids"]
    assert set(ids) == set(ROLES) and len(set(ids.values())) == 7, (
        "Success must retain seven distinct original manifest IDs and no HAR/assessment role"
    )
    assert ids["owned-response-receipt"] == summary["original_receipt_id"], (
        "The summary must retain the actual original receipt manifest ID"
    )
    originals = {role: state["originals"][identity] for role, identity in ids.items()}
    content = {role: bytes.fromhex(item["data_hex"]) for role, item in originals.items()}
    worker = ExpectedWorker(listener, case)
    expected = {"stdout": Canonical(worker), "stderr": b"",
        "owned-response-request": ExpectedRequest(listener, case["case_id"]),
        "owned-response-headers": base64.b64decode(case["header_section"]["base64"]),
        "owned-response-body": base64.b64decode(case["body"]["base64"]),
        "owned-response-wire": base64.b64decode(case["response"]["base64"])}
    assert all(content[role] == raw for role, raw in expected.items()), (
        "Original stream and wire evidence must exactly match the independently frozen bytes"
    )
    receipt = json.loads(content["owned-response-receipt"])
    assert Canonical(receipt) == content["owned-response-receipt"] and receipt["custody"] == (
        "complete") and receipt["refusal"] is None, (
        "Success requires canonical complete original custody"
    )
    assert receipt["evidence_ids"] == {"stdout": ids["stdout"], "stderr": ids["stderr"],
        "request": ids["owned-response-request"], "headers": ids["owned-response-headers"],
        "body": ids["owned-response-body"], "response": ids["owned-response-wire"]}, (
        "The noncircular receipt must preserve every actual original role-specific manifest ID"
    )
    target_reference = "target:" + Sha({"kind": "url", "value": worker["url"]})
    invocation = {"adapter_id": "native.loopback-response", "request": {
        "capability": "http.synthetic-response-capture", "target_reference": target_reference,
        "impact": "SAFE", "parameters": {"url": worker["url"]}, "credential_references": []},
        "argv": [str(python), "-I", "-B", "-m",
            "fuzzy1337.owned_response_capture_worker", worker["url"]],
        "timeout_seconds": 10, "provider_version": "1"}
    request = receipt["request"]
    assert request["invocation"] == invocation and request["resources"] == {
        "max_stdout_bytes": 8192, "max_stderr_bytes": 1, "terminate_grace_seconds": 0.5}, (
        "Receipt must bind the exact installed isolated recipe and original stream/cleanup limits"
    )
    assert re.fullmatch(r"owned-response-[0-9a-f]{32}/work", request["workspace"]) and (
        set(request["environment"]) == {"LANG", "LC_ALL", "PATH", "COMSPEC", "PATHEXT",
            "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
        and request["environment"]["LANG"] == request["environment"]["LC_ALL"] == "C"
        and all(request["environment"][key] == "" for key in
            ("PATH", "COMSPEC", "PATHEXT", "SYSTEMROOT", "WINDIR"))
        and request["environment"]["TEMP"] == request["environment"]["TMP"] == (
            str(root / request["workspace"]))
    ), "Original actual request must bind the complete exact private effective environment"
    assert request["authorization"]["invocation_sha256"] == Sha(invocation) and (
        request["authorization"]["scope_reference"] == "scope:owned-source"
        and request["authorization"]["policy_reference"] == "policy:owned-response-product"
        and request["authorization"]["granted_privileges"] == []
    ), "The original actual request must retain independent current acquisition authorization"
    events = receipt["events"]
    assert [event["sequence"] for event in events] == list(range(len(events))) and (
        events[0]["kind"] == "started" and events[-1]["kind"] == "completed"
        and events[-1]["termination"] == receipt["termination"] == "process_exit"
        and receipt["execution"]["state"] == "succeeded"
        and receipt["execution"]["exit_code"] == 0
    ), "Complete original lifecycle and terminal state must agree without invented success"

    for stream in ("stdout", "stderr"):
        joined = b"".join(bytes.fromhex(event["data_hex"]) for event in events
            if event["kind"] == stream)
        assert joined == content[stream], "Receipt fragments must equal the original stream"

    provenance = originals["stdout"]["manifest"]["provenance"]
    assert provenance == {"workspace_id": WORKSPACE, "scope_reference": "scope:owned-source",
        "source_id": "native.loopback-response", "source_version": "1", "tool_version": "1",
        "started_at": receipt["started_at"], "finished_at": receipt["finished_at"],
        "invocation_sha256": Sha(invocation), "execution": receipt["execution"]}, (
        "Original manifests must retain full execution and collection provenance"
    )

    for role, original in originals.items():
        manifest = original["manifest"]
        raw = content[role]
        digest = hashlib.sha256(raw).hexdigest()
        assert ids[role] == "sha256:" + Sha(manifest) and manifest["provenance"] == provenance and (
            manifest["reference"] == {"role": role, "locator": "blobs/sha256/" + digest,
                "sha256": digest, "size_bytes": len(raw), "media_type": ROLES[role]}
        ), "Reopened actual original ID, full five-field reference and provenance must agree"

    artifact_ids = {item["evidence"]["evidence_id"] for item in summary["job"]["artifacts"]}
    assert artifact_ids == set(ids.values()) and summary["original_job_id"] in (
        state["workspace"]["job_references"]), "Actual job attachments must retain all original IDs"
    assert set(ids.values()) <= set(state["workspace"]["evidence_record_references"]), (
        "Workspace must retain original IDs independently of shared content hashes"
    )

    if observed is not None:
        assert observed["request"] == request and (
            observed["execution"] == receipt["execution"] and
            observed["events"] == events and observed["termination"] == receipt["termination"]
            and observed["stdout_hex"] == content["stdout"].hex()
            and observed["stderr_hex"] == content["stderr"].hex()
        ), "SDK receipt must preserve the observed original executor result and fragments"

    return {"receipt": receipt, "content": content, "ids": ids, "worker": worker}


@pytest.mark.parametrize("case_id", ["missing", "fixed", "body-decoy"])
def test_InstalledSdkAndCliPreserveOriginalCaptureAssociationsAndRelocatedOfflineReplay(
    installed_worker, tmp_path, case_id,
):
    """Each frozen original crosses SDK and CLI, then replays after source inputs disappear."""

    case = CatalogCase(case_id)
    python = CaptureRuntime(installed_worker, tmp_path / "original-runtime")
    listener = OwnedResponseListener(base64.b64decode(case["response"]["base64"]))
    root = tmp_path / "workspace"
    policy = tmp_path / "selected-policy.json"
    policy.write_bytes(Canonical(Policy()))
    config = {"workspace": str(root), "policy": str(policy), "url": listener.origin + case["path"]}

    try:
        initial = Consumer(python, tmp_path, "setup", config)
        assert Path(initial["runtime_module"]).is_relative_to(python.parents[1]), (
            "SDK must import the actual clean installed wheel, never checkout/editable code"
        )
        before_plan = Files(root)
        plan = Consumer(python, tmp_path, "plan", config)
        assert plan["summary"]["state"] == "planned" and (
            plan["summary"]["execution_authorized"] is False
        ), (
            "Planning must expose only descriptive intent without an execution grant"
        )
        assert listener.accepted == 0 and Files(root) == before_plan, (
            "Actual installed planning must make zero contacts and no canonical or private writes"
        )
        sdk = Consumer(python, tmp_path, "capture", config)
        assert sdk["exception_type"] is None and len(sdk["executions"]) == 1, (
            "One approved SDK attempt must execute exactly one actual original worker"
        )
        first = CheckCapture(sdk["summary"], sdk["state"], initial, listener, case, python, root,
            sdk["executions"][0])
        command = ("capture", str(root), "--target", config["url"], "--scope", "owned-source",
            "--owner", OWNER, "--policy", str(policy), "--approve-safe-response-capture")
        cli = Cli(python, tmp_path, command)
        assert cli.returncode == 0 and cli.stderr == b"", "Installed capture CLI must complete"
        cli_summary = json.loads(cli.stdout)
        final = Consumer(python, tmp_path, "inspect", config)
        second = CheckCapture(cli_summary, final, sdk["state"], listener, case, python, root)

    finally:
        listener.Close()

    assert listener.accepted == 2 and listener.requests == (
        [ExpectedRequest(listener, case_id)] * 2
    ), (
        "SDK and CLI must each issue one exact selected GET without retry or follow-up"
    )
    assert not set(first["ids"].values()) & set(second["ids"].values()), (
        "Distinct real captures must preserve distinct original manifests even for identical bytes"
    )
    initial_objects = {Sha(item["identity"]): item for item in initial["model"]["objects"]}
    final_objects = {Sha(item["identity"]): item for item in final["model"]["objects"]}
    assert all(final_objects[key] == value for key, value in initial_objects.items()), (
        "Acquisition must preserve unrelated native assets and confirmed finding triage exactly"
    )
    assert {key: final["originals"][key] for key in initial["originals"]} == initial["originals"], (
        "Unrelated original evidence IDs, bytes and full provenance must survive both captures"
    )
    added = [item for key, item in final_objects.items() if key not in initial_objects]
    assert len(added) == 1 and added[0]["identity"] == {"workspace_id": WORKSPACE,
        "kind": "endpoint", "key": config["url"]} and (
        added[0]["attributes"] == {"url": config["url"]}
    ), (
        "Acquisition may add only its source Endpoint, without security assessment or Findings"
    )
    assert final["model"]["relations"] == initial["model"]["relations"] == [], (
        "Source acquisition must create no relation or alter unrelated model topology"
    )
    assert Counter(item["identity"]["kind"] for item in initial_objects.values()) == {
        "asset": 1, "finding": 1} and any(item["attributes"].get("status") == "confirmed"
        for item in initial_objects.values()), (
        "Preservation requires an actual unrelated native asset and already confirmed Finding"
    )
    endpoint = added[0]
    endpoint_reference = "object:" + Sha({"namespace": "object", "identity": endpoint["identity"]})
    assert endpoint["reference"] == endpoint_reference, (
        "Both captures must share the same canonical source Endpoint identity"
    )
    initial_observations = initial["model"]["observations"]
    added_observations = [item for item in final["model"]["observations"]
        if item not in initial_observations]
    assert all(item in final["model"]["observations"] for item in initial_observations) and (
        Counter(item["kind"] for item in added_observations) == {
            "object-update": 2, "owned-response-source": 2}
    ), "Both immutable source observations and their owner updates must preserve original history"
    source_facts = [item for item in added_observations if item["kind"] == "owned-response-source"]

    expected_attributions = []

    for summary, captured in ((sdk["summary"], first), (cli_summary, second)):
        facts = [item for item in source_facts if item["attributes"]["original_receipt_id"] == (
            summary["original_receipt_id"])]
        expected_facts = {"profile": "owned-response-capture.v1", "catalog_sha256": CATALOG_SHA256,
            "case_id": case_id, "original_job_id": summary["original_job_id"],
            "original_receipt_id": summary["original_receipt_id"],
            "original_role_ids": captured["ids"],
            "request_sha256": captured["worker"]["request"]["sha256"],
            "response_sha256": case["response"]["sha256"],
            "header_size_bytes": case["header_section"]["size_bytes"],
            "body_size_bytes": case["body"]["size_bytes"]}
        assert len(facts) == 1 and facts[0]["attributes"] == expected_facts, (
            "Each original job, receipt and role association must remain an immutable source fact"
        )
        expected_attribution = {"source_id": "native.loopback-response",
            "run_reference": summary["original_job_id"],
            "observed_at": captured["receipt"]["finished_at"],
            "scope_reference": "scope:owned-source",
            "target_reference": captured["receipt"]["request"]["invocation"]["request"][
                "target_reference"], "provider_version": "1",
            "evidence_references": sorted((final["originals"][identity]["manifest"]["reference"]
                for identity in captured["ids"].values()), key=Canonical),
            "execution": captured["receipt"]["execution"]}
        expected_attributions.append(expected_attribution)
        assert facts[0]["subject_reference"] == endpoint_reference and (
            facts[0]["provenance"] == expected_attribution
            and summary["source_facts"] == expected_facts
        ), "Each source fact must bind its original endpoint, complete evidence and execution"
        updates = [item for item in added_observations if item["kind"] == "object-update"
            and item["provenance"] == expected_attribution]
        assert len(updates) == 1 and updates[0]["subject_reference"] == endpoint_reference and (
            updates[0]["attributes"] == {"url": config["url"]}
        ), "Each capture must retain exactly its own source Endpoint update attribution"

    assert sorted(endpoint["provenance"], key=Canonical) == sorted(
        expected_attributions, key=Canonical
    ), "The shared Endpoint must retain both exact original capture attributions"

    operations = tuple(root.glob("owned-response-*"))
    assert len(operations) == 2 and all((path / "admitted.json").is_file() and (
        path / "publication.log").is_file() for path in operations), (
        "Initial SDK staging is deliberately retained; success cannot claim complete stage cleanup"
    )
    policy.unlink()
    Path(initial["scope_file"]).unlink()
    shutil.rmtree(python.parents[1])
    moved = tmp_path / "moved-workspace"
    shutil.move(str(root), moved)
    assert not root.exists() and not python.exists() and not policy.exists(), (
        "Offline replay must lose the original target, runtime path and current policy inputs"
    )
    before_replay = Files(moved)

    for summary in (sdk["summary"], cli_summary):
        replay_config = {"workspace": str(moved), "receipt": summary["original_receipt_id"]}
        replay = Consumer(installed_worker, tmp_path, "replay", replay_config)
        command = Cli(installed_worker, tmp_path, ("replay", str(moved), "--receipt",
            summary["original_receipt_id"]))
        assert replay["exception_type"] is None and (
            command.returncode == 0 and command.stderr == b""
        ), (
            "Installed SDK and CLI must verify originals after historical inputs are removed"
        )
        for actual in (replay["summary"], json.loads(command.stdout)):
            assert actual["state"] == "verified" and all(actual[key] == summary[key] for key in (
                "original_job_id", "original_receipt_id", "original_role_ids", "source_facts")), (
                "Replay must return original IDs and immutable source association"
            )

        assert Files(moved) == before_replay and (
            replay["state"]["originals"] == final["originals"]
        ), (
            "Offline replay must write nothing and preserve every actual original manifest and byte"
        )

    body_record = final["originals"][first["ids"]["owned-response-body"]]
    blob = moved / "evidence" / body_record["manifest"]["reference"]["locator"]
    raw = blob.read_bytes()
    blob.write_bytes(bytes((raw[0] ^ 1,)) + raw[1:])
    tampered = Files(moved)
    replay_config = {"workspace": str(moved), "receipt": sdk["summary"]["original_receipt_id"]}
    rejected = Consumer(installed_worker, tmp_path, "replay", replay_config)
    command = Cli(installed_worker, tmp_path, ("replay", str(moved), "--receipt",
        sdk["summary"]["original_receipt_id"]))
    assert rejected["summary"] is None and rejected["exception_type"] is not None and (
        command.returncode != 0 and Files(moved) == tampered
    ), "Tampered original bytes must refuse both replay interfaces without repair or writes"


@pytest.mark.parametrize("negative", [
    "approval", "permission", "revoked", "expired", "owner-change",
])
def test_InstalledCurrentAuthorityRefusalsMakeNoSelectedRequest(
    installed_worker, tmp_path, negative,
):
    """Independent approval, fresh permission/consent and original current actor remain required."""

    case = CatalogCase("missing")
    listener = OwnedResponseListener(base64.b64decode(case["response"]["base64"]))
    root = tmp_path / "workspace"
    policy = tmp_path / "selected-policy.json"
    policy.write_bytes(Canonical(Policy(negative != "permission")))
    config = {"workspace": str(root), "policy": str(policy), "url": listener.origin + case["path"],
        "negative": negative, "approve": negative != "approval"}

    try:
        initial = Consumer(installed_worker, tmp_path, "setup", config)
        refused = Consumer(installed_worker, tmp_path, "capture", config)

        if negative == "approval":
            command = Cli(installed_worker, tmp_path, (
                "capture", str(root), "--target", config["url"],
                "--scope", "owned-source", "--owner", OWNER, "--policy", str(policy)))
            assert command.returncode != 0, "Installed CLI must require explicit SAFE approval"

    finally:
        listener.Close()

    assert listener.accepted == 0 and listener.requests == [], (
        "Denied original authority must refuse before any selected GET or follow-up"
    )
    assert refused["exception_type"] is not None or refused["summary"]["state"] == "failed", (
        "Authority denial must remain an explicit failure, never successful zero-response capture"
    )
    assert refused["state"]["model"] == initial["model"] and (
        refused["state"]["originals"] == initial["originals"]
    ), "Denied acquisition must preserve unrelated native model, triage and original evidence"

    if negative == "owner-change":
        assert refused["owner_reads"] >= 2, "Current actor must refresh after SDK selection"


def test_InstalledSdkCallerCancellationAwaitsActualWorkerAndSocketCleanup(
    installed_worker, tmp_path,
):
    """Cancel after the actual GET and retain original terminal control."""

    case = CatalogCase("missing")
    listener = HeldResponseListener(tmp_path / "selected-request-ready")
    root = tmp_path / "workspace"
    policy = tmp_path / "selected-policy.json"
    policy.write_bytes(Canonical(Policy()))
    config = {"workspace": str(root), "policy": str(policy), "url": listener.origin + case["path"],
        "request_ready": str(listener.readiness)}

    try:
        initial = Consumer(installed_worker, tmp_path, "setup", config)
        cancelled = Consumer(installed_worker, tmp_path, "cancel", config)
        (tmp_path / "original-cancellation-result.json").write_bytes(Canonical(cancelled))

    finally:
        listener.Close()

    assert listener.accepted == 1 and listener.requests == [ExpectedRequest(listener, "missing")], (
        "Caller cancellation must occur after exactly one actual selected GET without retry"
    )
    assert listener.peer_closed and not listener.hold_expired, (
        "The actual worker must close its owned socket before the listener's emergency deadline"
    )
    summary = cancelled["summary"]
    assert cancelled["sdk_task_settled"] and summary["state"] == "cancelled" and (
        summary["acquisition_outcome"] == "unknown" and summary["custody_status"] == "incomplete"
        and summary["source_facts"] is None and summary["stage_retained"] is True
        and summary["model_persistence_status"] == "not-attempted"
        and summary["workspace_persistence_status"] == "not-attempted"
    ), "Caller cancellation must await cleanup and report its truthful incomplete outcome"
    assert cancelled["state"] == {key: initial[key] for key in (
        "workspace", "model", "originals"
    )}, (
        "Cancellation must preserve canonical model, triage, workspace and original refs"
    )
    assert len(cancelled["executions"]) == 1, (
        "The SDK must await exactly one actual original executor terminal result"
    )
    actual = cancelled["executions"][0]
    assert actual["execution"]["state"] == "cancelled" and (
        actual["termination"] == "cancellation" and
        actual["stdout_hex"] == actual["stderr_hex"] == ""
        and actual["events"][-1]["kind"] == "completed"
        and actual["events"][-1]["termination"] == "cancellation"
    ), "The actual worker must finish cancellation without rejected output or false success"
    ids = summary["original_role_ids"]
    assert ids == {"owned-response-receipt": summary["original_receipt_id"]} and (
        set(cancelled["attached"]) == set(ids.values())
    ), "Only the control receipt may be acknowledged; no response or stream role is admitted"
    original = cancelled["attached"][summary["original_receipt_id"]]
    raw = bytes.fromhex(original["data_hex"])
    receipt = json.loads(raw)
    assert raw == Canonical(receipt) and receipt["custody"] == "control-only" and (
        receipt["request"] == actual["request"] and receipt["execution"] == actual["execution"]
        and receipt["termination"] == actual["termination"]
        and receipt["refusal"] == "record-unadmitted"
        and receipt["evidence_ids"] == dict.fromkeys(
            ("stdout", "stderr", "request", "headers", "body", "response"))
        and receipt["events"] == [{"sequence": event["sequence"], "kind": event["kind"],
            "termination": event["termination"],
            "data_size_bytes": len(bytes.fromhex(event["data_hex"]))} for event in actual["events"]]
    ), "Cancellation custody must retain exact control sizes without rejected bytes or hashes"
