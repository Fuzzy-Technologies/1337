# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""One opted-in installed post-model-ACK expiry sequence, separate from the seven accepted cases.

Import and inert handoff checks perform no source, SDK, build or target execution. Genuine
execution requires the separate RunInstalled opt-in and original installed/process evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from tests.contract.owned_content_response_ci_expiry_evidence import (
    EXPIRY_HELPER,
    EXPIRY_HELPER_SHA256,
    OLD_PINS,
    OPERATION,
    PIPELINE,
    PIPELINE_SHA256,
    SCENARIO,
    AssertControls,
    AssertPartialExpiry,
)
from tests.contract.owned_content_response_sdk_oracle import AssertContentParts, Canonical
from tests.contract.owned_content_response_sdk_state_oracle import AssertSdkSaveTransition

FIELDS = {"fixture_id", "workspace", "observations", "url", "consent_valid_from",
    "consent_valid_until"}
CHECKER = "owned_content_response_ci_expiry_evidence.py"


def Plan(selection: dict) -> dict:
    """Freeze only the new expiry fixture identity and finite original inputs, without I/O.

    Args:
        selection: Exact fresh identity, separate absolute owners, literal source URL and consent.

    Returns:
        One fixed partial-expiry plan with independent actor/attester and analysis identities.

    Raises:
        ValueError: Inputs are missing, ambiguous, outside the closed fixture or unbounded.
    """

    if type(selection) is not dict or set(selection) != FIELDS or any(
        type(value) is not str or not value for value in selection.values()
    ):
        raise ValueError("Expiry plan requires every explicit text input")

    if not 8 <= len(selection["fixture_id"]) <= 64 or re.fullmatch(
        r"[a-z0-9]+(?:-[a-z0-9]+)*", selection["fixture_id"]) is None:
        raise ValueError("Expiry fixture requires one new bounded identity")

    root, observations = (Path(selection[key]) for key in ("workspace", "observations"))

    if any(not path.is_absolute() or ".." in path.parts for path in (root, observations)) or (
        root.is_relative_to(observations) or observations.is_relative_to(root)
    ):
        raise ValueError("Expiry fixture owners must be separate explicit absolute paths")

    parsed = urlsplit(selection["url"])

    if parsed.hostname != "127.0.0.1" or parsed.port is None or not (
        1024 <= parsed.port <= 65535) or selection["url"] != (
            f"http://127.0.0.1:{parsed.port}/research/content"):
        raise ValueError("Expiry plan selects only its original literal IPv4 owned source")

    start, end = (datetime.fromisoformat(selection[key]) for key in (
        "consent_valid_from", "consent_valid_until"))

    if any(time.tzinfo is None or time.utcoffset() is None for time in (start, end)) or not (
        30 < (end - start).total_seconds() <= 900
    ):
        raise ValueError("Expiry fixture consent needs an aware bounded window longer than 30s")

    identity = "owned-content-header-" + selection["fixture_id"]

    return {"schema_version": 1, "selection": dict(selection), "scenario": SCENARIO,
        "workspace_id": identity, "scope_id": identity, "owner_reference": "actor:" + identity,
        "attester_reference": "attester:" + identity, "consent_reference": "consent:" + identity,
        "analysis_reference": "analysis:" + identity, "expected_state": "partial",
        "expected_findings": 1}


def Run(plan: dict, handoff: Callable[[str, dict, Path], dict], *,
    enabled: bool = False) -> dict:
    """Drive only fresh setup/capture/inspect/expiry/inspect, without retry or workspace repair.

    Args:
        plan: Original exact Plan result, fixed before any state or execution handoff.
        handoff: Fixed finite transport used by RunInstalled; inert tests supply marked doubles.
        enabled: Separate exact sequence opt-in, default false before any filesystem activity.

    Returns:
        Checked partial identities, without genuine runtime acceptance until outer evidence joins.

    Raises:
        PermissionError: The separate sequence execution opt-in is absent.
        ValueError: The frozen plan or independent fresh owner boundaries differ.
        AssertionError: Original acquisition, partial-state or control observations fail their
            oracle.
    """

    if enabled is not True:
        raise PermissionError("Expiry sequence requires explicit operation opt-in")

    if type(plan) is not dict or Canonical(Plan(plan["selection"])) != Canonical(plan):
        raise ValueError("Expiry plan changed after its independent selection")

    selected = plan["selection"]
    root, observations = Path(selected["workspace"]), Path(selected["observations"])

    if root.exists() or root.is_symlink() or observations.exists() or observations.is_symlink() or (
        root.resolve().is_relative_to(observations.resolve()) or
        observations.resolve().is_relative_to(root.resolve())
    ):
        raise ValueError("Expiry sequence requires new canonically separate owners")

    step = 0

    def Call(operation: str, inputs: dict) -> dict:
        """Name each original child and observation owner exactly once.

        Args:
            operation: One fixed stage from this five-child sequence.
            inputs: Original independently selected operation fields.

        Returns:
            Actual detached original child observations, or marked inert test doubles.
        """

        nonlocal step
        step += 1

        return handoff(operation, inputs, observations / f"{step:02d}-{operation}")

    setup = Call("fresh-setup", {key: selected[key] for key in (
        "fixture_id", "workspace", "url", "consent_valid_from", "consent_valid_until")})
    assert setup["scope"]["scope_id"] == setup["scope"]["workspace_id"] == plan["workspace_id"], (
        "Original expiry invariant differs: setup['scope']['scope_id'] == "
        "setup['scope']['workspace_id'] == plan['workspace_id']"
    )
    assert setup["scope"]["authorization"] == {"state": "granted",
        "authority_reference": plan["attester_reference"], "record_reference": plan[
            "consent_reference"], "valid_from": selected["consent_valid_from"],
        "valid_until": selected["consent_valid_until"]}, (
        "Original expiry invariant differs: setup['scope']['authorization'] == {'state': "
        "'granted', 'authority_reference': plan['attester_reference'], 'record_re..."
    )
    capture = Call("capture", {"workspace": str(root), "url": selected["url"],
        "scope_id": plan["scope_id"], "owner_reference": plan["owner_reference"],
        "policy": setup["policies"]["acquisition"]["path"],
        "approve_safe_content_response_capture": True, "retain_response": True})
    acquired = Call("inspect", {"workspace": str(root)})["state"]
    assert capture["exception_type"] is None, (
        "Original expiry invariant differs: capture['exception_type'] is None"
    )
    original = capture["summary"]
    AssertSdkSaveTransition(setup["state"], acquired, original, capture["store_saves"],
        url=selected["url"], workspace_id=plan["workspace_id"],
        scope_reference="scope:" + plan["scope_id"])
    AssertContentParts("missing", selected["url"], original["original_receipt_id"],
        acquired["originals"], original["source_facts"], job_id=original["original_job_id"])
    expiry = Call(OPERATION, {"workspace": str(root), "url": selected["url"],
        "scope_id": plan["scope_id"], "owner_reference": plan["owner_reference"],
        "policy": setup["policies"]["analysis"]["path"],
        "original_receipt_id": original["original_receipt_id"],
        "analysis_reference": plan["analysis_reference"],
        "expected_model_revision": acquired["model"]["revision"],
        "expected_workspace_revision": acquired["workspace"]["revision"],
        "approve_passive_header_check": True})
    after = Call("inspect", {"workspace": str(root)})["state"]
    assert expiry["exception_type"] is None, (
        "Original expiry invariant differs: expiry['exception_type'] is None"
    )
    authority = {"scope": setup["scope"], "policy": setup["policies"]["analysis"]["document"],
        "owner_reference": plan["owner_reference"], "owner_attribution": "trusted-reader",
        "analysis_reference": plan["analysis_reference"]}
    identities = AssertPartialExpiry(acquired, after, expiry["summary"],
        expiry["control"]["guard"]["saves"], case="missing", url=selected["url"],
        receipt_id=original["original_receipt_id"], analysis=plan["analysis_reference"],
        authority=authority)
    AssertControls(expiry["control"], acquired, after, authority)

    return {"state": "checked-post-model-ack-expiry-partial", "expected_findings": 1,
        "identities": identities}


def RunInstalled(installed: Any, directory: Path, evidence: Any, *, fixture_id: str,
    enabled: bool = False) -> dict:
    """Execute only the new fixed expiry sequence with the existing installed/source owners.

    Args:
        installed: Unchanged actual Build result from owned_content_response_worker_launcher.
        directory: New absolute test-owned root, separate from retained original evidence.
        evidence: Original NativeCaseEvidence owner; all subprocess and source finals are retained.
        fixture_id: New independently selected identity, never a historical or mock fixture.
        enabled: Exact independent genuine runtime opt-in; false performs no imports or work.

    Returns:
        Narrow partial-expiry acceptance only after original installed/process/source/ACK checks.
        An unavailable prerequisite or failed actual stage raises with original evidence retained.

    Raises:
        PermissionError: The separate genuine fixture execution opt-in is absent.
        AssertionError: An installation, original process, source or narrow state check fails.
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

    names = (*OLD_PINS, EXPIRY_HELPER, PIPELINE, CHECKER)
    sources = {}

    for name in names:
        path = Path(__file__).resolve().with_name(name)
        sources[name] = {"path": str(path), "sha256": hashlib.sha256(
            entrypoint.BoundedRead(path, entrypoint.MAX_SOURCE_BYTES)).hexdigest()}

    assert all(sources[name]["sha256"] == digest for name, digest in OLD_PINS.items()), (
        "Original expiry invariant differs: all((sources[name]['sha256'] == digest for name, "
        'digest in OLD_PINS.items()))'
    )
    assert sources[EXPIRY_HELPER]["sha256"] == EXPIRY_HELPER_SHA256 and (
        sources[PIPELINE]["sha256"] == PIPELINE_SHA256), "Reviewed new fixed sources changed"
    evidence.Json("pipeline-helper-sources.json", sources)
    main, sentinel = (ChildEvidence(evidence, name) for name in ("main", "sentinel"))
    calls = 0

    def Handoff(operation: str, selection: dict, observations: Path) -> dict:
        """Invoke one fixed child and retain its original terminal/observation facts.

        Args:
            operation: One exact operation from this fixed five-child sequence.
            selection: Original explicit stage inputs, never shell or helper selectors.
            observations: Fresh absolute independent original observation owner.

        Returns:
            Original detached child output after installation/process/source reconciliation.
        """

        nonlocal calls
        calls += 1
        envelope = {"selection": selection, "observations": str(observations)}
        evidence.Json(f"stage-{calls:02d}-input.json", envelope)

        assert operation in ("fresh-setup", "capture", "inspect", OPERATION), (
            "Original expiry invariant differs: operation in ('fresh-setup', 'capture', "
            "'inspect', OPERATION)"
        )
        helper = EXPIRY_HELPER if operation == OPERATION else (
            "owned_content_response_sdk_entrypoint.py")
        input_path = directory / f"stage-{calls:02d}-input.json"

        with input_path.open("xb") as output:
            output.write(CanonicalNative(envelope))

        argv = (str(installed.python), "-I", "-B", sources[helper]["path"], operation,
            str(input_path), "--execute")
        assert NativeInstallation(installed.python) == installed.installation, (
            'Original expiry invariant differs: NativeInstallation(installed.python) == '
            'installed.installation'
        )
        retained_names = (("expiry-analysis.json", "original"),) if operation == OPERATION else (
            (operation + ".json", "original"),)

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
        assert CanonicalNative(observed) == process.stdout and observed["operation"] == operation, (
            'Original expiry invariant differs: CanonicalNative(observed) == process.stdout '
            "and observed['operation'] == operation"
        )
        AssertContentInstallation(installed.installation["identity"],
            observed["installed_identity"], commit=installed.commit, tree=installed.tree)
        assert observed["installed_identity"]["python"] == str(installed.python) and observed[
            "installed_identity"]["prefix"] == str(installed.python.parents[1].resolve()), (
            "Original expiry invariant differs: observed['installed_identity']['python'] == "
            "str(installed.python) and observed['installed_identity']['prefix'] == str..."
        )
        required = {"owned_content_response_sdk_entrypoint.py", EXPIRY_HELPER,
            "owned_content_response_sdk_offline_guard.py"} if operation == OPERATION else {
                "owned_content_response_sdk_entrypoint.py",
                "owned_content_response_sdk_consumer.py"}

        if operation in ("fresh-setup", "inspect"):
            required.update(("owned_content_response_sdk_controls.py",
                "owned_content_response_sdk_setup.py", "owned_response_product_runner.py"))

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

        if operation == OPERATION:
            retained = json.loads(entrypoint.BoundedRead(observations / "expiry-analysis.json",
                16 * 1024 * 1024))
            assert all(Canonical(retained[key]) == Canonical(observed[key]) for key in (
                "summary", "control", "exception_type")), "Original expiry observations differ"

            return retained

        return observed["summary"]

    try:
        with OwnedContentResponseTarget(main, address="127.0.0.1", case="missing") as source:
            with OwnedContentResponseTarget(sentinel, address="127.0.0.1", case="missing") as other:
                now = datetime.now(timezone.utc)
                plan = Plan({"fixture_id": fixture_id, "workspace": str(directory / "workspace"),
                    "observations": str(directory / "observations"),
                    "url": source.graph.Url("/research/content"),
                    "consent_valid_from": now.isoformat(),
                    "consent_valid_until": (now + timedelta(seconds=300)).isoformat()})
                evidence.Json("pipeline-plan.json", plan)
                sentinel_origin = other.graph.origin
                result = Run(plan, Handoff, enabled=True)

    finally:
        finals = RetainSourceFinal(evidence, {"main": main, "sentinel": sentinel})

    delivery = AssertContentSourceFacts("missing", plan["selection"]["url"], finals["main"],
        finals["sentinel"], sentinel_origin=sentinel_origin)
    result.update(runtime_acceptance="passed", source_delivery=delivery)
    evidence.Json("pipeline-result.json", result)

    return result
