# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Check one original stale-model CAS conflict before fresh analysis admission, without reruns."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from xml.etree import ElementTree

from tests.contract.owned_content_response_ci_actor_evidence import (
    ACTOR_HELPER,
    ACTOR_HELPER_SHA256,
    PERMISSION,
)
from tests.contract.owned_content_response_ci_denial_evidence import ReadJson
from tests.contract.owned_content_response_product_runner import (
    AssertContentInstallation,
    AssertContentSourceFacts,
    AssertOriginalTerminalProcess,
)
from tests.contract.owned_content_response_sdk_entrypoint import BoundedRead
from tests.contract.owned_content_response_sdk_oracle import AssertContentParts, Canonical
from tests.contract.owned_content_response_sdk_pipeline import AssertOffline
from tests.contract.owned_content_response_sdk_state_oracle import AssertSdkSaveTransition

CASE_NAME = "test_InstalledFreshStaleModelRevisionContentHeaderPipelinePreservesAcquiredState"
CASE_CLASS = "tests.functional.test_owned_content_response_sdk_pipeline"
OPERATIONS = ("fresh-setup", "capture", "inspect", "analyze-offline", "inspect")


def RequireChildren(case: Path, helpers: dict) -> list[dict]:
    """Join five original SDK children to the selected installation and complete terminal streams.

    The unchanged functional owner also checks build, source checkpoint and original prelaunch
    records. This read-only gate independently binds each retained SDK child and its fixed argv.
    """

    installation = ReadJson(case.parent / "installation/wheel-identity.json")
    checkpoint = ReadJson(case.parent / "installation/source-checkpoint.json")

    if checkpoint != {key: installation[key] for key in (
        "schema_version", "source_commit", "source_tree", "source_modules_sha256")}:
        raise ValueError("The original source checkpoint must bind the selected wheel inventory")

    children = []
    original_installation = None

    for index, operation in enumerate(OPERATIONS, start=3):
        paths = list(case.glob(f"process-{index:03d}-sdk-{operation}"))

        if len(paths) != 1:
            raise ValueError("Each original SDK operation must be retained exactly once")

        root = paths[0]
        child = ReadJson(root / "stdout.bin")
        terminal = ReadJson(root / "process.json")
        invocation = ReadJson(root / "invocation.json")
        identity = child["installed_identity"]
        AssertContentInstallation(installation, identity,
            commit=installation["source_commit"], tree=installation["source_tree"])
        cwd = terminal["cwd"]
        argv = (identity["python"], "-I", "-B", helpers[ACTOR_HELPER]["path"], operation,
            str(Path(cwd) / f"stage-{index - 2:02d}-input.json"), "--execute")
        AssertOriginalTerminalProcess(terminal, BoundedRead(root / "stdout.bin", 2 * 1024 * 1024),
            BoundedRead(root / "stderr.bin", 1024 * 1024), argv=argv)
        installed = terminal["installation"]
        manifest = json.dumps(installed["identity"], sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("ascii")

        if installed["manifest_sha256"] != hashlib.sha256(manifest).hexdigest() or (
            original_installation is not None and installed != original_installation):
            raise ValueError("Original children must retain the same actual installation manifest")

        original_installation = installed

        if terminal["returncode"] != 0 or (root / "stderr.bin").stat().st_size != 0 or (
            terminal["timeout_seconds"] != 35 or invocation != {"schema_version": 1,
                "argv": list(argv), "cwd": cwd, "timeout_seconds": 35,
                "stdin": "closed-devnull", "state": "not-launched", "returncode": None,
                "terminal_return_observed": False, "installation": installed}
        ) or child["operation"] != operation:
            raise ValueError("Original SDK terminal and prelaunch selection must reconcile")

        sources = child["consumer_sources"]
        required = {ACTOR_HELPER, "owned_content_response_sdk_consumer.py"}
        required.update(("owned_content_response_sdk_controls.py",
            "owned_content_response_sdk_setup.py", "owned_response_product_runner.py") if (
                operation in ("fresh-setup", "inspect")) else (
                    "owned_content_response_sdk_offline_guard.py",) if operation.endswith(
                        "-offline") else ())

        if sources != {name: helpers[name] for name in required} or any(
            installed["identity"][key] != value
            for key, value in installation.items()
        ) or installed["identity"]["installed_sources"] != identity[
            "installed_sources"]:
            raise ValueError("All original children must bind the same reviewed installed sources")

        children.append(child)

    if len(list(case.glob("process-*-sdk-*"))) != len(OPERATIONS):
        raise ValueError("No retry or later SDK operation may accompany the stale CAS case")

    return children


def RequireOutcome(junit: Path, retained: Path) -> dict:
    """Require original capture ACKs and one explicit stale-basis conflict with no interpretation.

    Granted scope, selected PASSIVE policy and True opt-in remain inputs. Zero actor reads
    establish that fresh analysis admission was never reached, not that permission was checked.
    """

    document = ElementTree.fromstring(BoundedRead(junit, 1024 * 1024))
    suites, cases = list(document.iter("testsuite")), list(document.iter("testcase"))

    if len(suites) != 1 or any(suites[0].get(key) != value for key, value in (
        ("tests", "1"), ("failures", "0"), ("errors", "0"), ("skipped", "0"))) or (
        len(cases) != 1 or cases[0].get("name") != CASE_NAME or cases[0].get(
            "classname") != CASE_CLASS or any(list(document.iter(kind)) for kind in (
                "failure", "error", "skipped"))
    ):
        raise ValueError("One original stale-model case must pass without failures or skips")

    results = list(retained.glob("run-*/stale-model-revision/pipeline-result.json"))

    if len(results) != 1:
        raise ValueError("One original stale-model revision result is required")

    case = results[0].parent
    result = ReadJson(results[0])

    if result != {"state": "checked-revision-conflict", "expected_findings": 0,
        "runtime_acceptance": "passed", "source_delivery": "normal-eof"} or type(
            result.get("expected_findings")) is not int:
        raise ValueError("A stale CAS conflict is unassessed, never a completed negative scan")

    plan = ReadJson(case / "pipeline-plan.json")
    selected = ReadJson(case / "stage-04-input.json")["selection"]
    helpers = ReadJson(case / "pipeline-helper-sources.json")

    if helpers[ACTOR_HELPER]["sha256"] != ACTOR_HELPER_SHA256:
        raise ValueError("The unchanged reviewed installed entrypoint must own this CAS selection")

    setup_child, capture_child, acquired_child, child, after_child = RequireChildren(case, helpers)
    setup, acquired, after = setup_child["summary"], acquired_child["summary"][
        "original_inspection"], after_child["summary"]["original_inspection"]
    policy = setup["policies"]["analysis"]

    if plan["selection"]["scenario"] != "stale-model-revision" or plan["selection"]["case"] != (
        "missing") or plan["expected_state"] != "failed" or type(plan["expected_findings"]) is not (
            int) or plan["expected_findings"] != 0 or selected["authority_scenario"] != "positive":
        raise ValueError("Only the explicit missing-header stale-model CAS selection is admitted")

    if selected["approve_passive_header_check"] is not True or selected["policy"] != policy[
        "path"] or policy["document"]["maximum_impact"] != "PASSIVE" or policy["document"][
            "permissions"] != [PERMISSION] or setup["scope"]["authorization"]["state"] != (
                "granted") or any(selected[key] != plan[key] for key in (
                    "owner_reference", "scope_id", "analysis_reference")) or selected["url"] != (
                        plan["selection"]["url"]):
        raise ValueError("Current authority inputs remain independently selected, not checked")

    capture = ReadJson(case / "sdk-capture-original.json")

    if capture["exception_type"] is not None or Canonical(capture["summary"]) != Canonical(
        capture_child["summary"]):
        raise ValueError("Actual capture and retained original Save observations must agree")

    original = capture["summary"]
    AssertSdkSaveTransition(setup["state"], acquired, original, capture["store_saves"],
        url=selected["url"], workspace_id=plan["workspace_id"],
        scope_reference="scope:" + plan["scope_id"])
    AssertContentParts("missing", selected["url"], original["original_receipt_id"],
        acquired["originals"], original["source_facts"], job_id=original["original_job_id"])

    if selected["original_receipt_id"] != original["original_receipt_id"] or any(
        type(value) is not int for value in (acquired["model"]["revision"],
            acquired["workspace"]["revision"], selected["expected_model_revision"],
            selected["expected_workspace_revision"])) or acquired["model"]["revision"] <= 0 or (
                selected["expected_model_revision"] != acquired["model"]["revision"] - 1
                or selected["expected_workspace_revision"] != acquired["workspace"]["revision"]):
        raise ValueError("Only the actual acquired model basis minus one may cause this conflict")

    consumer = ReadJson(case / "sdk-analyze-offline-consumer.json")
    summary = consumer["summary"]

    if consumer["exception_type"] is not None or Canonical(child["summary"]) != Canonical(
        summary) or summary["state"] != "failed" or summary["failure"] != "revision-conflict" or (
            any(summary[key] is not None for key in (
                "condition_observed", "assessment_reference", "finding_reference"))):
        raise ValueError("Actual pre-admission CAS failure cannot create interpretation identities")

    for owner in ("model", "workspace"):
        if summary[owner + "_commit"] != "not-attempted" or type(summary[owner + "_revision"]
        ) is not int or summary[owner + "_revision"] != acquired[owner]["revision"]:
            raise ValueError("The CAS conflict cannot fabricate a Save or changed revision")

    guard = ReadJson(case / "sdk-analyze-offline-guard.json")
    AssertOffline(guard["guard"], historical=False)

    if any(record["authority_scenario"] != "positive" or type(record["owner_reads"]) is not int
        or record["owner_reads"] != 0 for record in (guard, child)) or Canonical(child["guard"]
        ) != Canonical(guard["guard"]) or guard["guard"]["saves"] != [] or Canonical(acquired
        ) != Canonical(after) or (case / "physical-relocation.json").exists():
        raise ValueError("CAS failure must precede admission and preserve all acquired owner state")

    main, sentinel = [ReadJson(case / (name + "-source-final.json")) for name in (
        "main", "sentinel")]

    if AssertContentSourceFacts("missing", selected["url"], main, sentinel,
        sentinel_origin=sentinel["origin"]) != "normal-eof":
        raise ValueError("The sole original capture and zero-contact sentinel must actually settle")

    return result


def Main(arguments: list[str] | None = None) -> int:
    """Check only explicitly supplied original paths for this one finite stale-CAS identity."""

    selected = sys.argv[1:] if arguments is None else arguments

    if len(selected) != 2:
        raise ValueError("Expected original stale-model JUnit and evidence paths")

    RequireOutcome(Path(selected[0]), Path(selected[1]))
    print("Required genuine stale-model conflict: 1 passed, 0 skipped; admission not reached")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
