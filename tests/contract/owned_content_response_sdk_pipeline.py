# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite content capture/header-v2 sequence using existing consumers and independent oracles.

Plan/Run use explicit handoffs; RunInstalled separately opts into the existing installed-process
and owned-target evidence owners. Mocked handoffs never establish runtime acceptance. Fresh
setup is distinct from the old fixed-identity SDK seed and never renews original consent.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from tests.contract.owned_content_response_header_v2_oracle import (
    AssertContentHeaderV2,
    AssertHistoricalContentHeaderReplay,
)
from tests.contract.owned_content_response_sdk_oracle import AssertContentParts, Canonical
from tests.contract.owned_content_response_sdk_state_oracle import AssertSdkSaveTransition

EXPECTATIONS = {"missing": 1, "fixed": 0, "body-decoy": 1}
SCENARIOS = ("positive", "approval-denied", "policy-denied", "owner-drift")
REVISION_SCENARIO = "stale-model-revision"
FIELDS = {"fixture_id", "workspace", "relocated_workspace", "observations", "url", "case",
    "scenario", "consent_valid_from", "consent_valid_until"}


def Plan(selection: dict) -> dict:
    """Freeze one fresh finite attempt and its Finding/authority expectations before any handoff.

    Args:
        selection: Entire explicit fixture identity, paths, literal IPv4 URL, source case,
            authority scenario and aware consent times. No clock or filesystem is consulted.

    Returns:
        Closed independent inputs and derived fixture identities; no product IDs or ACKs.
        Window shape is not current freshness: reviewed setup and unchanged product authority
        still must check real time. Historical consent is never renewed by this plan.
    """

    if type(selection) is not dict or set(selection) != FIELDS or any(
        type(value) is not str or not value for value in selection.values()
    ):
        raise ValueError("Pipeline selection requires every explicit text input")

    if not 8 <= len(selection["fixture_id"]) <= 64 or re.fullmatch(
        r"[a-z0-9]+(?:-[a-z0-9]+)*", selection["fixture_id"]) is None or (
        selection["case"] not in EXPECTATIONS or selection["scenario"] not in (
            *SCENARIOS, REVISION_SCENARIO)
    ):
        raise ValueError("Pipeline identity, case and authority scenario must be predeclared")

    roots = [Path(selection[key]) for key in (
        "workspace", "relocated_workspace", "observations")]

    if any(not root.is_absolute() or ".." in root.parts for root in roots) or any(
        left.is_relative_to(right) or right.is_relative_to(left)
        for index, left in enumerate(roots) for right in roots[index + 1:]
    ):
        raise ValueError("Pipeline owners must be explicit separate absolute roots")

    parsed = urlsplit(selection["url"])

    if parsed.hostname != "127.0.0.1" or parsed.port is None or not (
        1024 <= parsed.port <= 65535) or selection["url"] != (
            f"http://127.0.0.1:{parsed.port}/research/content"):
        raise ValueError("First integrated path selects only its literal IPv4 owned content URL")

    start, end = [datetime.fromisoformat(selection[key]) for key in (
        "consent_valid_from", "consent_valid_until")]

    if any(value.tzinfo is None or value.utcoffset() is None for value in (start, end)) or not (
        0 < (end - start).total_seconds() <= 900
    ):
        raise ValueError("Fresh fixture consent requires an aware positive window of at most 900s")

    identity = "owned-content-header-" + selection["fixture_id"]

    return {"schema_version": 1, "selection": dict(selection), "workspace_id": identity,
        "scope_id": identity, "owner_reference": "actor:" + identity,
        "attester_reference": "attester:" + identity, "consent_reference": "consent:" + identity,
        "analysis_reference": "analysis:" + identity,
        "expected_state": "failed" if selection["scenario"] == REVISION_SCENARIO else (
            "completed" if selection["scenario"] == "positive" else "denied"),
        "expected_findings": EXPECTATIONS[selection["case"]] if selection["scenario"] == (
            "positive") else 0}


def AssertOffline(record: dict, *, historical: bool) -> None:
    """Require observed tripwire delivery and zero forbidden effects, never infer missing zeros."""

    assert set(record) == {"calls", "audit_probe_seen", "saves"} and (
        record["audit_probe_seen"] is True), "Original offline guard telemetry is required"
    required = {"socket.audit", "socket.socket", "subprocess.Popen", "LocalExecutor.Execute",
        "GovernedLocalExecutor.Execute", "PolicyEngine.Authorize", "LocalEvidenceStore.Put",
        "LocalEvidenceStore.PublishStoredBytes", "OwnedResponseStage.__init__"}

    if historical:
        required.update(("LocalModelStore.Save", "LocalWorkspaceStore.Save",
            "LocalScopeStore.Open"))

    assert type(record["calls"]) is dict and required <= set(record["calls"]) and all(
        type(value) is int and value == 0 for value in record["calls"].values()), (
            "Any forbidden offline call, including a swallowed refusal, fails the sequence")
    assert type(record["saves"]) is list, "Original Save observations must remain explicit"

    if historical:
        assert record["saves"] == [], "Historical replay must not attempt any Save"


def Run(plan: dict, handoff, *, enabled: bool = False) -> dict:
    """Drive one fixed setup/capture/analysis/relocation/header-replay sequence without retries.

    Args:
        plan: Exact independent Plan result, frozen before fresh setup.
        handoff: Fixed installed consumer transport for named operations. Each call receives
            an explicit selection and distinct observation owner and returns actual detached
            observations. Fresh setup and physical relocation remain separately reviewed owners.
        enabled: Independent exact sequence opt-in; false performs no reads or handoffs.

    Returns:
        Checked historical identities or checked authority refusal. Original installation,
        process and target cleanup evidence remain required for genuine acceptance.
    """

    if enabled is not True:
        raise PermissionError("Integrated SDK sequence requires explicit execution opt-in")

    if type(plan) is not dict or Canonical(Plan(plan["selection"])) != Canonical(plan):
        raise ValueError("Pipeline plan changed after independent expectations were frozen")

    selected = plan["selection"]
    root, relocated = selected["workspace"], selected["relocated_workspace"]
    observations = Path(selected["observations"])
    paths = [Path(root), Path(relocated), observations]
    canonical = [path.resolve() for path in paths]

    if any(path.exists() or path.is_symlink() for path in paths[:2]) or any(
        left.is_relative_to(right) or right.is_relative_to(left)
        for index, left in enumerate(canonical) for right in canonical[index + 1:]
    ):
        raise ValueError("Fresh pipeline roots must be absent and canonically separate")

    step = 0

    def Call(operation: str, inputs: dict) -> dict:
        """Pass one explicit finite operation to a fresh, separately named observation owner."""

        nonlocal step
        step += 1

        return handoff(operation, inputs, observations / f"{step:02d}-{operation}")

    setup = Call("fresh-setup", {key: selected[key] for key in (
        "fixture_id", "workspace", "url", "consent_valid_from", "consent_valid_until")})
    before = setup["state"]
    scope = setup["scope"]
    assert before["workspace"]["workspace_id"] == before["model"]["workspace_id"] == (
        plan["workspace_id"]), "Fresh setup cannot reuse a historical workspace identity"
    assert scope["scope_id"] == plan["scope_id"] and scope["workspace_id"] == (
        plan["workspace_id"]), "Fresh scope must belong to this independently selected fixture"
    consent = scope["authorization"]
    assert consent == {"state": "granted", "authority_reference": plan["attester_reference"],
        "record_reference": plan["consent_reference"],
        "valid_from": selected["consent_valid_from"],
        "valid_until": selected["consent_valid_until"]}, "Original fresh consent must be exact"
    capture = Call("capture", {"workspace": root, "url": selected["url"],
        "scope_id": plan["scope_id"], "owner_reference": plan["owner_reference"],
        "policy": setup["policies"]["acquisition"]["path"],
        "approve_safe_content_response_capture": True, "retain_response": True})
    acquired = Call("inspect", {"workspace": root})["state"]
    summary = capture["summary"]
    AssertSdkSaveTransition(before, acquired, summary, capture["store_saves"],
        url=selected["url"], workspace_id=plan["workspace_id"],
        scope_reference="scope:" + plan["scope_id"])
    receipt = summary["original_receipt_id"]
    AssertContentParts(selected["case"], selected["url"], receipt, acquired["originals"],
        summary["source_facts"], job_id=summary["original_job_id"])
    analysis_policy = setup["policies"]["analysis-denied" if selected["scenario"] == (
        "policy-denied") else "analysis"]
    model_revision = acquired["model"]["revision"]

    if selected["scenario"] == REVISION_SCENARIO:
        assert type(model_revision) is int and model_revision > 0, (
            "A stale CAS selection requires an observed positive acquired model revision")
        model_revision -= 1

    analysis = Call("analyze-offline", {"workspace": root, "url": selected["url"],
        "scope_id": plan["scope_id"], "owner_reference": plan["owner_reference"],
        "policy": analysis_policy["path"], "original_receipt_id": receipt,
        "analysis_reference": plan["analysis_reference"],
        "expected_model_revision": model_revision,
        "expected_workspace_revision": acquired["workspace"]["revision"],
        "approve_passive_header_check": selected["scenario"] != "approval-denied",
        "authority_scenario": "positive" if selected["scenario"] == REVISION_SCENARIO else (
            selected["scenario"])})
    AssertOffline(analysis["guard"], historical=False)
    interpreted = Call("inspect", {"workspace": root})["state"]
    actual = analysis["summary"]

    if selected["scenario"] == REVISION_SCENARIO:
        assert actual["state"] == "failed" and actual["failure"] == "revision-conflict", (
            "The unchanged installed SDK must refuse the explicitly stale original model basis")
        assert all(actual[key] is None for key in (
            "condition_observed", "assessment_reference", "finding_reference")), (
                "A pre-admission revision conflict must remain unassessed without a Finding")
        assert all(actual[owner + "_commit"] == "not-attempted" and type(actual[
            owner + "_revision"]) is int and actual[owner + "_revision"] == acquired[owner][
                "revision"] for owner in ("model", "workspace")), (
                    "A pre-admission revision conflict cannot invent a Save acknowledgement")
        assert type(analysis["owner_reads"]) is int and analysis["owner_reads"] == 0 and (
            analysis["authority_scenario"] == "positive"), (
                "Revision checking precedes fresh analysis admission and actor reads")
        assert analysis["guard"]["saves"] == [] and Canonical(acquired) == Canonical(interpreted), (
            "The original-basis conflict must preserve acquired state without any analysis Save")

        return {"state": "checked-revision-conflict", "expected_findings": 0}

    if plan["expected_state"] == "denied":
        assert actual["state"] == "denied" and actual["failure"] == "authorization"
        assert all(actual[key] is None for key in (
            "condition_observed", "assessment_reference", "finding_reference"))
        assert analysis["guard"]["saves"] == [] and Canonical(acquired) == Canonical(interpreted)

        return {"state": "checked-authority-refusal", "expected_findings": 0}

    identities = AssertContentHeaderV2(acquired, interpreted, actual,
        analysis["guard"]["saves"], case=selected["case"], url=selected["url"],
        receipt_id=receipt, analysis=plan["analysis_reference"], authority={"scope": scope,
            "policy": setup["policies"]["analysis"]["document"],
            "owner_reference": plan["owner_reference"], "owner_attribution": "trusted-reader"})
    assert int(identities["finding_reference"] is not None) == plan["expected_findings"], (
        "Persisted Finding truth must equal the expectation declared before capture")
    moved = Call("relocate", {"workspace": root, "relocated_workspace": relocated})
    assert moved == {"original_root_absent": True, "relocated_root_present": True}, (
        "Relocation must physically remove the original root before historical verification")
    assert not Path(root).exists() and not Path(root).is_symlink() and Path(relocated).is_dir(), (
        "Returned relocation claims cannot substitute for the physical selected roots")
    relocated_before = Call("inspect", {"workspace": relocated})["state"]
    assert Canonical(interpreted) == Canonical(relocated_before), "Relocation cannot repair state"
    replay = Call("replay-offline", {"workspace": relocated, "kind": "header",
        "reference": identities["assessment_reference"]})
    AssertOffline(replay["guard"], historical=True)
    relocated_after = Call("inspect", {"workspace": relocated})["state"]
    AssertHistoricalContentHeaderReplay(relocated_before, relocated_after, replay["summary"],
        identities)

    return {"state": "checked-header-replay", "expected_findings": plan["expected_findings"],
        "identities": identities}


def RunInstalled(installed, directory: Path, evidence, *, fixture_id: str, case: str,
    scenario: str, enabled: bool = False) -> dict:
    """Execute this one finite sequence with existing installed-process and owned-target owners.

    Args:
        installed: Unchanged actual Build result from owned_content_response_worker_launcher.
        directory: New absolute test-owned root, separate from retained original evidence.
        evidence: Original NativeCaseEvidence owner; all subprocess and source finals are retained.
        fixture_id: New independently selected identity, never a historical or mock fixture.
        case: Independently served missing/fixed/body-decoy variant.
        scenario: Explicit positive or authority-refusal scenario; no implicit retries.
        enabled: Exact independent genuine runtime opt-in; false performs no imports or work.

    Returns:
        Genuine acceptance only after installed/process/source, Save, header and replay checks.
        An unavailable prerequisite or failed actual stage raises with original evidence retained.
    """

    if enabled is not True:
        raise PermissionError("Installed integrated SDK execution requires explicit runtime opt-in")

    from fuzzy1337.executors.owned_process import RequireLinuxOwnership
    from tests.contract.owned_content_response_product_runner import (
        AssertContentInstallation,
        AssertContentSourceFacts,
        AssertOriginalTerminalProcess,
    )
    from tests.contract.owned_content_response_target import OwnedContentResponseTarget
    from tests.contract.owned_content_response_worker_launcher import (
        REPOSITORY,
        ChildEvidence,
        RetainSourceFinal,
    )
    from tests.native_crawl_acceptance_helpers import (
        CanonicalNative,
        NativeEnvironment,
        NativeInstallation,
        NativeProcess,
    )

    RequireLinuxOwnership()
    assert directory.is_absolute() and NativeInstallation(installed.python) == (
        installed.installation), "The selected original installed identity must remain unchanged"
    directory.mkdir(parents=True, exist_ok=False)
    environment = NativeEnvironment(directory / "owned-state")
    source_status = NativeProcess(evidence, "pipeline-source-status",
        ("git", "status", "--porcelain"), cwd=REPOSITORY, environment=environment, timeout=5)
    checkpoint = NativeProcess(evidence, "pipeline-checkpoint",
        ("git", "rev-parse", "HEAD", "HEAD^{tree}"), cwd=REPOSITORY,
        environment=environment, timeout=5)
    assert source_status.returncode == checkpoint.returncode == 0 and (
        source_status.stdout == b"" and checkpoint.stdout.decode("ascii").split() == [
            installed.commit, installed.tree]), "Runtime requires the exact clean installed tree"
    from tests.contract import owned_content_response_sdk_entrypoint as entrypoint

    names = ("owned_content_response_sdk_entrypoint.py", "owned_content_response_sdk_consumer.py",
        "owned_content_response_sdk_controls.py", "owned_content_response_sdk_setup.py",
        "owned_response_product_runner.py", "owned_content_response_sdk_offline_guard.py")
    sources = {}

    for name in names:
        path = Path(__file__).resolve().with_name(name)
        sources[name] = {"path": str(path), "sha256": hashlib.sha256(
            entrypoint.BoundedRead(path, entrypoint.MAX_SOURCE_BYTES)).hexdigest()}

    evidence.Json("pipeline-helper-sources.json", sources)
    main, sentinel = (ChildEvidence(evidence, name) for name in ("main", "sentinel"))
    calls = 0

    def Handoff(operation, selection, observations):
        """Use only the fixed installed entrypoint, or one physical same-parent relocation."""

        nonlocal calls
        calls += 1
        envelope = {"selection": selection, "observations": str(observations)}
        evidence.Json(f"stage-{calls:02d}-input.json", envelope)

        if operation == "relocate":
            observations.mkdir(parents=True, exist_ok=False)
            original, destination = Path(selection["workspace"]), Path(
                selection["relocated_workspace"])
            original.rename(destination)
            actual = {"original_root_absent": not original.exists() and not original.is_symlink(),
                "relocated_root_present": destination.is_dir()}
            evidence.Json("physical-relocation.json", actual)

            return actual

        assert operation in ("fresh-setup", "capture", "inspect", "analyze-offline",
            "replay-offline"), "There is no arbitrary installed command dispatch"
        input_path = directory / f"stage-{calls:02d}-input.json"

        with input_path.open("xb") as output:
            output.write(CanonicalNative(envelope))

        argv = (str(installed.python), "-I", "-B", sources[names[0]]["path"], operation,
            str(input_path), "--execute")
        assert NativeInstallation(installed.python) == installed.installation
        retained_names = (("offline-guard.json", "guard"),
            ("consumer/" + operation.removesuffix("-offline") + ".json", "consumer")) if (
                operation.endswith("-offline")) else ((operation + ".json", "original"),)

        try:
            process = NativeProcess(evidence, "sdk-" + operation, argv, cwd=directory,
                environment=environment, timeout=35, maximum=1024 * 1024,
                installation=installed.installation)

        finally:
            for name, role in retained_names:
                path = observations / name
                label = "sdk-" + operation + "-" + role
                evidence.Json(label + "-retention.json", {"observation_present": path.is_file()})

                if path.is_file():
                    evidence.Write(label + ".json", entrypoint.BoundedRead(path, 16 * 1024 * 1024))

        prefix = evidence.local / f"process-{evidence.sequence:03d}-sdk-{operation}"
        invocation = json.loads((prefix / "invocation.json").read_bytes())
        terminal = json.loads((prefix / "process.json").read_bytes())
        assert invocation == {"schema_version": 1, "argv": list(argv), "cwd": str(directory),
            "timeout_seconds": 35, "stdin": "closed-devnull", "state": "not-launched",
            "returncode": None, "terminal_return_observed": False,
            "installation": installed.installation}, "Original prelaunch selection must reconcile"
        AssertOriginalTerminalProcess(terminal, process.stdout, process.stderr, argv=argv)
        assert process.returncode == 0 and process.stderr == b"" and terminal["cwd"] == (
            str(directory)) and terminal["timeout_seconds"] == 35 and terminal[
                "installation"] == installed.installation, "Actual SDK child failed"
        observed = json.loads(process.stdout)
        assert CanonicalNative(observed) == process.stdout and observed["operation"] == operation
        AssertContentInstallation(installed.installation["identity"],
            observed["installed_identity"], commit=installed.commit, tree=installed.tree)
        assert observed["installed_identity"]["python"] == str(installed.python) and observed[
            "installed_identity"]["prefix"] == str(installed.python.parents[1].resolve())
        required = set(names[:2]) | (set(names[2:5]) if operation in (
            "fresh-setup", "inspect") else {names[5]} if operation.endswith("-offline") else set())
        assert observed["consumer_sources"] == {name: sources[name] for name in required}, (
            "Each actual child must bind its exact reviewed helper sources")

        if operation == "capture":
            retained = json.loads(entrypoint.BoundedRead(observations / "capture.json",
                16 * 1024 * 1024))
            assert retained["exception_type"] is None and Canonical(retained["summary"]) == (
                Canonical(observed["summary"])), "Original capture observation must reconcile"
            return retained

        if operation == "inspect":
            return {"state": observed["summary"]["original_inspection"]}

        if operation.endswith("-offline"):
            retained = json.loads(entrypoint.BoundedRead(observations / "offline-guard.json",
                16 * 1024 * 1024))
            assert all(retained[key] == observed[key] for key in (
                "guard", "owner_reads", "authority_scenario")), "Original guard facts differ"
            return {"summary": observed["summary"], "guard": observed["guard"],
                "owner_reads": observed["owner_reads"],
                "authority_scenario": observed["authority_scenario"]}

        return observed["summary"]

    try:
        with OwnedContentResponseTarget(main, address="127.0.0.1", case=case) as source:
            with OwnedContentResponseTarget(sentinel, address="127.0.0.1", case="missing") as other:
                now = datetime.now(timezone.utc)
                plan = Plan({"fixture_id": fixture_id, "workspace": str(directory / "workspace"),
                    "relocated_workspace": str(directory / "relocated"),
                    "observations": str(directory / "observations"),
                    "url": source.graph.Url("/research/content"), "case": case,
                    "scenario": scenario,
                    "consent_valid_from": now.isoformat(),
                    "consent_valid_until": (now + timedelta(seconds=300)).isoformat()})
                evidence.Json("pipeline-plan.json", plan)
                sentinel_origin = other.graph.origin
                result = Run(plan, Handoff, enabled=True)

    finally:
        finals = RetainSourceFinal(evidence, {"main": main, "sentinel": sentinel})

    delivery = AssertContentSourceFacts(case, plan["selection"]["url"], finals["main"],
        finals["sentinel"], sentinel_origin=sentinel_origin)
    result.update(runtime_acceptance="passed", source_delivery=delivery)
    evidence.Json("pipeline-result.json", result)

    return result
