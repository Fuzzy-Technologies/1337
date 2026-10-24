# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual installed crawl SDK/CLI and separate native Git consumption of independent live links."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from fuzzy1337.functional_metrics import (
    BuildReport,
    FunctionalRun,
    OracleCheck,
    RawEvidence,
    RenderHtml,
    RenderMarkdown,
    RunStatus,
    ScenarioOracle,
    SerializeReport,
)
from tests.native_crawl_acceptance_helpers import (
    AssertNativeRecord,
    AssertZeroNativeContact,
    CanonicalNative,
    NativeAcceptanceGraph,
    NativeConfig,
    NativeConsumer,
    NativeEnvironment,
    NativeGet,
    NativeHeldCancellation,
    NativeInstallation,
    NativeProcess,
)
from tests.native_crawl_acceptance_helpers import installed_native_crawl as installed_native_crawl
from tests.native_crawl_acceptance_helpers import native_acceptance_run as native_acceptance_run
from tests.native_crawl_acceptance_helpers import native_case_evidence as native_case_evidence
from tests.native_crawl_graph_helpers import CrawlGraphOracle


def PersistNativeAcceptance(directory: Path, output: dict, target) -> None:
    """Retain actual outputs, contact facts and failed work without fabricating an assessed
    result."""

    directory.mkdir(parents=True, exist_ok=True)
    (directory / "consumer.json").write_bytes(CanonicalNative(output))
    (directory / "original-target-contacts.json").write_bytes(CanonicalNative({
        "contacts": [item.ToDict() for item in target.state.Observe()],
        "counters": target.state.Counters(), "errors": list(target.state.Errors()),
        "sentinel_origin": target.sentinel_origin,
        "sentinel_contacts": [item.ToDict() for item in target.sentinel_state.Observe()],
        "sentinel_counters": target.sentinel_state.Counters(),
        "sentinel_errors": list(target.sentinel_state.Errors())}))


def AssertNativeContactWaves(contacts: tuple, waves: list[list[str]]) -> None:
    """Compare actual wave membership while preserving independently observed within-wave
    arrivals."""

    paths = [item.target for item in contacts]
    expected = [path for wave in waves for path in wave]
    assert len(paths) == len(set(paths)) and set(paths) == set(expected), (
        "Actual unique contacts must equal the finite handwritten reachable selection."
    )
    offset = 0

    for wave in waves:
        assert set(paths[offset:offset + len(wave)]) == set(wave), (
            "Actual contacts must respect depth waves; concurrency need not preserve arrival order."
        )
        offset += len(wave)


def AssertOriginalNativeCustody(output: dict, contacts: tuple, *, variant: str) -> None:
    """Join original actual executor streams, three-role custody and handwritten response
    assertions."""

    summary = output["summary"]
    identities = summary["original_record_ids"]
    assert len(identities) == len(set(identities)) and set(identities) == set(
        summary["acknowledged_record_ids"]), "Every original retained record needs its actual ACK."
    assert summary["custody_status"] == "complete", "Incomplete original custody must fail."
    originals = output["state"]["originals"]
    controls = [json.loads(bytes.fromhex(originals[identity]["data_hex"]))
                for identity in identities
                if originals[identity]["manifest"]["reference"]["role"] == "native-crawl-control"]
    assert len(controls) == len(output["executions"]), (
        "Every actual original execution needs its separately named control receipt."
    )
    by_source = {json.loads(execution["request"]["invocation"]["argv"][-1])["source_url"]:
                 execution for execution in output["executions"]}

    for control in controls:
        document = json.loads(control["request"]["invocation"]["argv"][-1])
        execution = by_source[document["source_url"]]
        argv = execution["request"]["invocation"]["argv"]
        assert argv == [output["installed_python"], "-I", "-m",
            "fuzzy1337.native_crawl_worker", CanonicalNative(document).decode("ascii")], (
                "Actual original execution must use only the fixed isolated packaged worker argv."
            )
        stdout = bytes.fromhex(execution["stdout_hex"])
        stderr = bytes.fromhex(execution["stderr_hex"])
        assert control["request"] == execution["request"] and (
            control["execution"] == execution["execution"]
            and control["termination"] == execution["termination"]
            and control["stdout_size_bytes"] == len(stdout)
            and control["stderr_size_bytes"] == len(stderr)
        ), "Control metadata must bind the actual original request/termination/stream sizes."
        assert bytes.fromhex(originals[control["original_stdout_id"]]["data_hex"]) == stdout and (
            bytes.fromhex(originals[control["original_stderr_id"]]["data_hex"]) == stderr == b""
        ), "Original stored streams must equal the genuine executor's unchanged returned bytes."
        record = json.loads(stdout)
        assert CanonicalNative(record) == stdout, "Original worker stdout must remain byte-exact."

        if record["outcome"] != "refused":
            contact = next(item for item in contacts if item.target == urlsplit(
                document["source_url"]).path)
            AssertNativeRecord(record, document, contact, variant=variant)

    assert len(identities) == 3 * len(controls), (
        "The crawl may retain stdout/stderr/control only, without fabricated HTTP-body evidence."
    )
    for identity in identities:
        original = originals[identity]
        raw = bytes.fromhex(original["data_hex"])
        reference = original["manifest"]["reference"]
        assert reference["sha256"] == hashlib.sha256(raw).hexdigest() and (
            reference["size_bytes"] == len(raw)
        ), "Reopened original immutable evidence must preserve its actual content identity."


def AssertNativeSaves(output: dict, expected_urls: list[str]) -> None:
    """Require actual ordered CAS acknowledgements and durable structural request projection."""

    summary = output["summary"]
    assert summary["completed_urls"] == expected_urls and (
        [item["source_url"] for item in summary["model_saves"]] == expected_urls
    ), "Acknowledged source/model transitions must follow independently declared breadth/URL order."
    saves = output["actual_model_saves"]
    assert len(saves) == len(expected_urls) and all(item["exact_acknowledgement"] and (
        item["expected_revision"] == item["prior_revision"]
        and item["acknowledged_revision"] == item["proposed_revision"] == item["prior_revision"] + 1
    ) for item in saves), "Each ordered Save must acknowledge its exact CAS basis."
    assert all(item["persistence"] == "acknowledged" for item in summary["model_saves"]) and (
        summary["workspace_persistence_status"] == "acknowledged"
    ), "Observed or unknown persistence cannot replace acknowledged completion."
    responses = [item for item in output["state"]["model"]["observations"]
                 if item["kind"] == "web.owned-crawl-response"]
    assert {item["attributes"]["source"]["url"] for item in responses} == set(expected_urls), (
        "Actual durable response observations must contain every fetched source."
    )
    assert output["state"]["requests"] and not output["state"]["findings"], (
        "Crawl must project actual structural requests while making no vulnerability claim."
    )
    projected = {template["request_reference"]: template for endpoint in output["state"]["requests"]
                 for template in endpoint["templates"]}
    projected_urls = {template["endpoint"]["origin"] + template["endpoint"]["path_template"]
                      for template in projected.values()}
    assert projected_urls == set(expected_urls), (
        "Actual structural request projection must preserve the reachable source collection only."
    )
    for response in responses:
        attributes = response["attributes"]
        expected_references = {attributes["source_request_reference"], *(entry["request_reference"]
            for entry in attributes["frontier"]["entries"])}
        assert expected_references.issubset(projected), (
            "Every actual source/candidate request must survive in complete reopened collections."
        )

    assert any(entity["attributes"].get("independent_existing_attribute") ==
        "preserve-existing-structural-state" for entity in output["state"]["model"]["objects"]), (
            "Actual source projection must preserve unrelated existing Endpoint attributes."
        )
    assert any(template["body_kind"] == "json" for template in projected.values()), (
        "A preexisting structural request variant must survive anonymous GET collection merging."
    )
    assert output["capability"]["adapter_id"] == "native.crawl" and (
        output["capability"]["capabilities"] == ["http.owned-loopback-crawl"]
    ), "Capability metadata must come from the actual installed consumer descriptor."


@pytest.mark.integration
def test_ActualSdkChangesFetchesAtSameSeedAndPreservesOrderedOriginalState(
    installed_native_crawl, tmp_path, native_case_evidence,
) -> None:
    """Changing only target bytes changes actual traversal, with measured inverted sibling
    overlap."""

    oracle = CrawlGraphOracle()

    with NativeAcceptanceGraph(native_case_evidence) as target:
        original_seed = target.graph.Url("/entry")

        for variant in ("positive", "fixed", "decoy", "redirect"):
            assert target.state.WaitIdle(), "Mutation requires all original owners idle."
            target.state.SetVariant(variant)

            if variant == "positive":
                target.state.InvertSiblingCompletion()

            directory = tmp_path / variant
            config = NativeConfig(target, directory / "workspace")
            setup = NativeConsumer(installed_native_crawl, directory, "setup", config,
                evidence=native_case_evidence)
            assert setup["crawl_attester"] != setup["selected_owner"], (
                "Crawl attestation must differ from execution attribution."
            )
            before = len(target.state.Observe())
            output = NativeConsumer(installed_native_crawl, directory, "crawl", config,
                evidence=native_case_evidence)
            assert target.state.WaitIdle(), "The actual SDK left original target owners active."
            contacts = target.state.Observe()[before:]
            PersistNativeAcceptance(directory / "evidence", output, target)
            expected_paths = [path for wave in oracle["variants"][variant]["expected_waves"]
                              for path in wave]
            AssertNativeContactWaves(contacts, oracle["variants"][variant]["expected_waves"])
            assert config["seed_url"] == original_seed, "Every variant must use the same seed URL."
            summary = output["summary"]
            assert output["exception_type"] is None and summary is not None, (
                "Actual SDK startup/authority failure cannot be scored as a successful clean run."
            )
            AssertOriginalNativeCustody(output, contacts, variant=variant)

            if variant == "redirect":
                assert summary["state"] == "failed" and (
                    summary["completed_urls"] == [original_seed]
                ), (
                    "Redirect refusal must preserve the acknowledged seed."
                )
                assert "/redirect-destination" not in [item.target for item in contacts], (
                    "The actual crawler must never follow an admitted response's redirect."
                )

            else:
                assert summary["state"] == "completed", "Required real crawl work did not complete."
                AssertNativeSaves(output, [target.graph.origin + path for path in expected_paths])

            if variant == "positive":
                by_path = {item.target: item for item in contacts}
                assert target.state.Counters()["maximum_active_handlers"] >= 2 and max(
                    by_path["/branch-a"].active_at_start,
                    by_path["/branch-b"].active_at_start,
                ) >= 2 and (
                    by_path["/branch-b"].completion_sequence <
                    by_path["/branch-a"].completion_sequence
                ), "Actual two-handler overlap and B-before-A completion must both be measured."

            reopened = NativeConsumer(installed_native_crawl, directory, "inspect", config,
                evidence=native_case_evidence)
            assert reopened["state"] == output["state"], (
                "Canonical model, complete request collections and originals must durably reopen."
            )
            assert not target.state.Errors(), "Target failures invalidate acceptance."


@pytest.mark.integration
@pytest.mark.parametrize("negative", ["unregistered", "ip-denied", "excluded", "revoked",
    "policy-denied", "owner-after-plan", "owner-grant-launch", "approval-missing"])
def test_ActualSdkFreshDenialMakesZeroOriginalContact(
    installed_native_crawl, tmp_path, negative, native_case_evidence,
):
    """Current registration/scope/consent/policy/actor/approval denial precedes every real
    request."""

    with NativeAcceptanceGraph(native_case_evidence) as target:
        config = NativeConfig(target, tmp_path / "workspace", negative=negative,
                              approve=negative != "approval-missing")
        setup = NativeConsumer(installed_native_crawl, tmp_path, "setup", config,
            evidence=native_case_evidence)
        output = NativeConsumer(installed_native_crawl, tmp_path, "crawl", config,
            evidence=native_case_evidence)
        PersistNativeAcceptance(tmp_path / "evidence", output, target)
        AssertZeroNativeContact(target)
        assert output["executions"] == [] and output["actual_model_saves"] == [], (
            "Fresh denied work must launch no actual worker and perform no model Save."
        )
        assert output["exception_type"] is not None or output["summary"]["state"] == "failed", (
            "Denied work must remain explicit failure rather than completed zero-Finding success."
        )
        assert output["state"] == setup["state"], "Denial must preserve canonical state."


@pytest.mark.integration
@pytest.mark.parametrize("negative", ["owner-before-save", "lost-model-ack"])
def test_ActualSdkRetainsOriginalAcquisitionAndTruthfulUnacknowledgedModelState(
    installed_native_crawl, tmp_path, negative, native_case_evidence,
):
    """Actual original worker success cannot override fresh owner denial or a real lost Save ACK."""

    with NativeAcceptanceGraph(native_case_evidence) as target:
        target.state.SetVariant("fixed")
        config = NativeConfig(target, tmp_path / "workspace", negative=negative)
        setup = NativeConsumer(installed_native_crawl, tmp_path, "setup", config,
            evidence=native_case_evidence)
        output = NativeConsumer(installed_native_crawl, tmp_path, "crawl", config,
            evidence=native_case_evidence)
        assert target.state.WaitIdle(), "Failed SDK work must settle original owners."
        PersistNativeAcceptance(tmp_path / "evidence", output, target)
        assert output["summary"]["state"] == "failed" and output["executions"], (
            "Persistence denial or lost ACK must fail after real acquisition."
        )
        AssertOriginalNativeCustody(output, target.state.Observe(), variant="fixed")
        assert output["summary"]["completed_urls"] == [], (
            "Completion cannot count an unacknowledged Save/event transition."
        )

        if negative == "owner-before-save":
            assert not output["actual_model_saves"] and output["state"]["model"] == (
                setup["state"]["model"]), "Trusted reader drift must deny before actual model Save."

        else:
            assert len(output["actual_model_saves"]) == 1 and (
                output["state"]["model"]["revision"] ==
                setup["state"]["model"]["revision"] + 1
            ) and output["summary"]["model_saves"][0]["persistence"] == "observed-committed", (
                "Committed lost ACK state must remain visible without retry."
            )


@pytest.mark.integration
def test_DiscoveredTargetsRequireSeparateGitConfirmationAndPersistFiniteFindings(
    installed_native_crawl, tmp_path, native_case_evidence,
) -> None:
    """Score actual saved Git TP1/TN3, preserve operator triage and keep Endpoint owners
    separate."""

    oracle = CrawlGraphOracle()
    scenarios, runs = [], []

    with NativeAcceptanceGraph(native_case_evidence) as target:
        config = NativeConfig(target, tmp_path / "workspace")
        NativeConsumer(installed_native_crawl, tmp_path, "setup", config,
            evidence=native_case_evidence)
        positive = NativeConsumer(installed_native_crawl, tmp_path, "crawl", config,
            evidence=native_case_evidence)
        assert positive["summary"]["state"] == "completed", (
            "Separate Git acceptance requires actual successful positive graph discovery first."
        )
        assert target.state.WaitIdle(), "Original graph owners must settle before byte mutation."
        target.state.SetVariant("redirect")
        redirect = NativeConsumer(installed_native_crawl, tmp_path, "crawl", config,
            evidence=native_case_evidence)
        assert redirect["summary"]["state"] == "failed", (
            "The explicit redirect crawl variant must remain refused/unassessed."
        )
        discovered = {item["attributes"]["candidate_url"] for item in
            redirect["state"]["model"]["observations"] if item["kind"] == "web.owned-crawl-link"}

        for case in oracle["git_handoff"]["cases"]:
            url = target.graph.origin + case["path"]
            assert url in discovered, "Git selection needs actual discovery provenance."
            before = target.state.Counters()["contacts"]
            denied = NativeConsumer(installed_native_crawl, tmp_path, "git",
                                   {**config, "git_url": url, "confirm": False},
                evidence=native_case_evidence)
            assert denied["summary"]["state"] == "failed" and (
                target.state.Counters()["contacts"] == before
            ), "Crawl approval must not confirm a STANDARD Git plan."
            output = NativeConsumer(installed_native_crawl, tmp_path, "git",
                                    {**config, "git_url": url},
                evidence=native_case_evidence)
            assert target.state.WaitIdle(), "The actual Git check must settle its original request."
            current = [item for item in output["state"]["findings"]
                       if item["location_key"] == url
                       and item["check_id"] == "native.git-head-exposure"]
            summary = output["summary"]
            completed = summary["state"] == "completed"
            status = RunStatus.COMPLETED if completed else RunStatus.CRASHED
            scenarios.append(ScenarioOracle(case["id"], oracle["target_pack"],
                oracle["target_version"], oracle["provenance"],
                (OracleCheck(case["id"], case["capability"], case["expected_match"]),), True))
            prior_ids = set(denied["state"]["originals"])
            raw = [RawEvidence("invocation", "application/json",
                               CanonicalNative(output["plan"]["invocation"]).decode())]

            for identity, original in output["state"]["originals"].items():
                if identity not in prior_ids:
                    reference = original["manifest"]["reference"]
                    raw.append(RawEvidence(reference["role"], reference["media_type"],
                                           bytes.fromhex(original["data_hex"]).decode()))

            runs.append(FunctionalRun(case["id"], output["plan"]["invocation"]["adapter_id"],
                output["provider_version"], status,
                summary["duration_seconds"], (case["id"],) if current else (), evidence=tuple(raw)))
            report = BuildReport(tuple(scenarios), tuple(runs))
            output_directory = tmp_path / "git-evidence" / case["id"]
            PersistNativeAcceptance(output_directory, output, target)
            (tmp_path / "git-matrix.json").write_text(SerializeReport(report), encoding="utf-8")
            native_case_evidence.Write("git-matrix.json", SerializeReport(report).encode("utf-8"))
            native_case_evidence.Write("git-matrix.md", RenderMarkdown(report).encode("utf-8"))
            native_case_evidence.Write("git-matrix.html", RenderHtml(report).encode("utf-8"))
            (tmp_path / "git-matrix.md").write_text(RenderMarkdown(report), encoding="utf-8")
            (tmp_path / "git-matrix.html").write_text(RenderHtml(report), encoding="utf-8")
            assert completed, "Failed/unexecuted real Git work must never count as a true negative."
            assert len(current) == int(case["expected_match"]), (
                "Actual persisted Git Findings differ from independently handwritten finite truth."
            )
            assert [item.target for item in target.state.Observe()[before:]] == [case["path"]], (
                "The existing checker must make one exact GET with zero redirect followups."
            )
            assert output["plan"]["impact"] == "STANDARD" and output["plan"][
                "confirmation_required"] is True and output["summary"]["capabilities"], (
                "Actual consumer metadata must retain separate STANDARD permission/confirmation."
            )

            if case["expected_match"]:
                structural = {item["endpoint_reference"] for item in output["state"]["requests"]}
                assert current[0]["subject_reference"] not in structural, (
                    "Legacy Git and structural crawl Endpoints must stay distinct."
                )
                triaged = NativeConsumer(installed_native_crawl, tmp_path, "triage", config,
                    evidence=native_case_evidence)
                rerun = NativeConsumer(installed_native_crawl, tmp_path, "git",
                                      {**config, "git_url": url},
                    evidence=native_case_evidence)
                assert rerun["summary"]["state"] == "completed" and any(
                    finding["reference"] == current[0]["reference"]
                    and finding["status"] == "confirmed"
                    and finding["status_reason"] == triaged["state"]["findings"][0]["status_reason"]
                    for finding in rerun["state"]["findings"]
                ), "Rerun must preserve actual Finding identity and operator triage."
                assert target.state.WaitIdle(), "Actual triage rerun must settle its original GET."

        metrics = [item["metrics"] for item in report["runs"]]
        assert {key: sum(item[key] for item in metrics) for key in ("tp", "tn", "fp", "fn")} == (
            oracle["git_handoff"]["expected_metrics"]
        ), "The genuine persisted finite matrix must score exactly TP1/TN3/FP0/FN0."
        reopened = NativeConsumer(installed_native_crawl, tmp_path, "inspect", config,
            evidence=native_case_evidence)
        assert len(reopened["state"]["findings"]) == 1 and reopened["state"]["findings"][0][
            "status"] == "confirmed", "Finding and triage must survive reopen."
        assert not target.state.Errors(), "Target failures invalidate Git acceptance."


def NativeCli(python: Path, directory: Path, arguments: list[str], *, evidence):
    """Run the actual installed entry point with isolated owned state and original byte streams."""

    return NativeProcess(evidence, "cli",
        (str(python), "-I", "-B", "-m", "fuzzy1337", "--json", *arguments),
        cwd=directory, environment=NativeEnvironment(directory / "cli-state"), timeout=45,
        installation=NativeInstallation(python))


@pytest.mark.integration
def test_InstalledCliPlansApprovesTraversesAndReopensTruthfulRefusedWork(
    installed_native_crawl, tmp_path, native_case_evidence,
) -> None:
    """Use actual scan crawl/json commands; default selected attribution claims no external
    reader."""

    oracle = CrawlGraphOracle()

    with NativeAcceptanceGraph(native_case_evidence) as target:
        for variant in ("positive", "fixed", "decoy", "redirect"):
            assert target.state.WaitIdle(), "CLI mutation requires idle original owners."
            target.state.SetVariant(variant)
            directory = tmp_path / ("cli-" + variant)
            config = NativeConfig(target, directory / "workspace")
            NativeConsumer(installed_native_crawl, directory, "setup", config,
                evidence=native_case_evidence)
            policy = directory / "policy.json"
            policy.write_bytes(CanonicalNative({
                "policy_id": "independent-native-crawl", "revision": 0,
                "maximum_impact": "SAFE", "permissions": [{"capability_id":
                    "http.owned-loopback-crawl", "adapter_id": "native.crawl",
                    "maximum_impact": "SAFE", "granted_privileges": []}],
                "max_authorization_seconds": 300}))
            arguments = ["scan", "crawl", config["workspace"], "--seed", config["seed_url"]]

            for selected in config["selected_urls"]:
                arguments.extend(("--selected", selected))

            arguments.extend(("--scope", "crawl", "--owner", "actor:independent-crawl-operator",
                              "--policy", str(policy)))
            before = target.state.Counters()["contacts"]
            planned = NativeCli(installed_native_crawl, directory, [*arguments, "--plan"],
                evidence=native_case_evidence)
            denied = NativeCli(installed_native_crawl, directory, arguments,
                evidence=native_case_evidence)
            assert planned.returncode == 0 and json.loads(planned.stdout)["profile"] == (
                oracle["profile"]), "Installed CLI must expose read-only crawl planning."
            assert denied.returncode == 3 and json.loads(denied.stdout)["state"] == "failed" and (
                target.state.Counters()["contacts"] == before
            ), "Installed CLI planning/missing approval must cause zero original contact."
            result = NativeCli(installed_native_crawl, directory,
                               [*arguments, "--approve-safe-crawl"],
                evidence=native_case_evidence)
            assert target.state.WaitIdle(), "CLI must settle every original owner."
            summary = json.loads(result.stdout)
            expected_completed = oracle["variants"][variant]["expected_completed"]
            assert result.returncode == (0 if expected_completed else 4) and summary["state"] == (
                "completed" if expected_completed else "failed"
            ), "Actual installed CLI must expose truthful completed versus refused work."
            contacts = target.state.Observe()[before:]
            AssertNativeContactWaves(contacts, oracle["variants"][variant]["expected_waves"])
            reopened = NativeCli(installed_native_crawl, directory,
                                 ["workspace", "open", config["workspace"]],
                evidence=native_case_evidence)
            assert reopened.returncode == 0 and json.loads(reopened.stdout)[
                "verified_evidence_records"] >= 3 * len(contacts), (
                    "CLI reopen must verify original worker/control records."
                )
            for name, process in (("plan", planned), ("denied", denied), ("run", result),
                                  ("reopen", reopened)):
                (directory / (name + ".stdout")).write_bytes(process.stdout)
                (directory / (name + ".stderr")).write_bytes(process.stderr)
                assert process.stderr == b"", "CLI stderr must remain empty."

            PersistNativeAcceptance(directory / "evidence", {"summary": summary}, target)
            assert not target.state.Errors(), "Target mechanism failure invalidates CLI acceptance."


@pytest.mark.integration
def test_ActualSdkRelocatedOriginalsReopenOfflineAfterOriginalRootRemoval(
    installed_native_crawl, tmp_path, native_case_evidence,
) -> None:
    """Relocate actual canonical originals and verify them without HTTP or writes."""

    with NativeAcceptanceGraph(native_case_evidence) as target:
        original_root = tmp_path / "original-workspace"
        config = NativeConfig(target, original_root)
        NativeConsumer(installed_native_crawl, tmp_path, "setup", config, native_case_evidence)
        output = NativeConsumer(installed_native_crawl, tmp_path, "crawl", config,
                                native_case_evidence)
        assert output["summary"]["state"] == "completed" and target.state.WaitIdle(), (
            "Relocation requires actual completed acquisition and settled original target owners."
        )
        prior_contacts = target.state.Counters()["contacts"]
        relocated_root = tmp_path / "relocated-workspace"
        shutil.copytree(original_root, relocated_root)
        shutil.rmtree(original_root)
        relocated = NativeConsumer(installed_native_crawl, tmp_path, "inspect-offline",
            {**config, "workspace": str(relocated_root)}, native_case_evidence)
        native_case_evidence.Json("relocation.json", {
            "original_root_removed": not original_root.exists(),
            "relocated_root": str(relocated_root), "original_contacts": prior_contacts,
            "contacts_after_offline_reopen": target.state.Counters()["contacts"],
            "same_canonical_originals": relocated["state"] == output["state"]})
        assert not original_root.exists() and relocated["state"] == output["state"] and (
            target.state.Counters()["contacts"] == prior_contacts
        ), "Relocated originals must reopen unchanged with zero new contacts."


@pytest.mark.integration
def test_ActualSdkCallerCancellationSettlesOriginalWorkerAndSocket(
    installed_native_crawl, tmp_path, native_case_evidence,
) -> None:
    """Cancel after real GET readiness; require peer EOF and incomplete custody."""

    readiness = tmp_path / "actual-get-ready"

    with NativeHeldCancellation(native_case_evidence, readiness) as listener:
        url = listener.origin + "/native-crawl-held"
        config = {"workspace": str(tmp_path / "workspace"), "seed_url": url,
                  "selected_urls": [url], "request_ready": str(readiness)}
        setup = NativeConsumer(installed_native_crawl, tmp_path, "setup", config,
                               native_case_evidence)
        output = NativeConsumer(installed_native_crawl, tmp_path, "cancel", config,
                                native_case_evidence)
        summary = output["summary"]
        assert summary["state"] == "cancelled" and output["sdk_task_settled"] is True and (
            output["caller_cancel_requests"] >= 1 and output["executions"]
        ), "Actual caller cancellation must settle the same SDK task and original execution."
        assert summary["custody_status"] == "incomplete" and summary["completed_urls"] == [] and (
            output["actual_model_saves"] == [] and
            output["state"]["model"] == setup["state"]["model"]
        ), "Cancelled work must stay incomplete with no model Save or completed-page fiction."
        assert any(item["termination"] == "cancellation" for item in output["executions"]), (
            "At least one actual original executor result must attest the requested cancellation."
        )
        originals = output["state"]["originals"]
        controls = [json.loads(bytes.fromhex(originals[identity]["data_hex"]))
            for identity in summary["original_record_ids"]
            if originals[identity]["manifest"]["reference"]["role"] == "native-crawl-control"]
        assert controls and controls[0]["termination"] == "cancellation" and all(
            control["original_job_id"] == summary["original_job_id"] for control in controls
        ), "Original cancelled control evidence must bind the same job without fabricated success."

    assert listener.accepted == 1 and listener.requests == [NativeGet(listener.origin,
        "/native-crawl-held")] and listener.peer_closed and not listener.hold_expired and (
            not listener.thread.is_alive()
        ), "The cancelled worker must reach actual peer EOF and the listener must join."
