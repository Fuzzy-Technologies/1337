# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Required genuine installed CI command over the existing pinned inert native-image oracle."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

import pytest

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.functional.test_native_image_product import (
    ORACLE,
    OWNER,
    SCAN_TIMEOUT,
    Canonical,
    CheckModel,
    CheckPair,
    OwnedSelection,
    Policy,
    RegisterScope,
)
from tests.functional.test_native_image_product import product_runtime as product_runtime
from tests.integration.test_trivy_native import native_runtime as native_runtime

EVIDENCE = Path("functional-evidence/native-image-ci")
SEVERITIES = ("unknown", "informational", "low", "medium", "high", "critical")
LATE_POLICY_REFUSAL = '''# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Inject one explicit policy revocation after genuine installed CLI report publication."""

import json
import sys
from pathlib import Path

import fuzzy1337.ci_commands as commands
from fuzzy1337.cli import Main

original_publish = commands.PublishReport
policy_path = Path(sys.argv[1])


def Publish(destination, payload):
    """Preserve actual report bytes, then revoke only the selected owned native permission."""

    original_publish(destination, payload)

    if destination.suffix == ".xml":
        policy = json.loads(policy_path.read_bytes())
        policy["permissions"] = []
        policy_path.write_text(json.dumps(policy), encoding="utf-8")


commands.PublishReport = Publish
raise SystemExit(Main(sys.argv[2:]))
'''


def Arguments(root, selection, policy, parent, limit):
    """Select the genuine existing profile and all labels explicitly, without severity ranking."""

    severities = [argument for value in SEVERITIES for argument in ("--severity", value)]

    return ["ci", "scan", str(root), "--profile", "native-trivy", "--archive", selection.archive,
        "--executable", str(selection.executable), "--cache-directory", selection.cache_directory,
        "--policy", str(policy), "--scope", "local", "--owner", OWNER,
        "--read-consent-reference", selection.read_consent.record_ref, "--approve-safe-image",
        *severities, "--status", "open", "--max-matches", str(limit),
        "--timeout", str(SCAN_TIMEOUT),
        "--acknowledge-unassessed-completeness", "--report-json", str(parent / "ci.json"),
        "--report-sarif", str(parent / "ci.sarif"),
        "--report-junit", str(parent / "ci.xml"), "--json"]


def Console(arguments, evidence, label, *, late_policy=None):
    """Run the installed isolated entry point with an optional final-policy fault injection."""

    prefix = [sys.executable, "-I", "-m", "fuzzy1337"] if late_policy is None else (
        [sys.executable, "-I", "-c", LATE_POLICY_REFUSAL, str(late_policy)])
    result = subprocess.run([*prefix, *arguments], capture_output=True,
                            timeout=SCAN_TIMEOUT + 85, check=False, shell=False)
    (evidence / (label + ".stdout")).write_bytes(result.stdout)
    (evidence / (label + ".stderr")).write_bytes(result.stderr)
    outcome = json.loads(result.stdout)
    assert result.returncode == outcome["exit_code"], (
        "The installed process exit must equal the actual machine outcome"
    )

    return result.returncode, outcome


def CheckArtifacts(root, parent, outcome, case, target, runtime, evidence):
    """Independently inspect original native pair, saved candidate facts and actual report files."""

    _, _, provisioning, network = runtime
    store = LocalEvidenceStore(root / "evidence")
    records = tuple(store.Get(identifier)
                    for identifier in outcome["scan"]["retained_evidence_ids"])
    assert len(records) == 6, "The assembled installed native CI command must own exactly six roles"
    replay, _, _ = CheckPair(root, records, case, target, provisioning)
    saved, _ = CheckModel(root, case, records)
    findings = saved.Objects(ObjectKind.FINDING)
    expected_refs = sorted(item.Reference() for item in findings)
    matched = sorted(item.Reference() for item in findings if item.attributes["status"] == "open"
                     and item.attributes["severity"] in SEVERITIES)
    criterion = outcome["criterion"]
    assert criterion["selected_findings"] == expected_refs and (
        criterion["matched_findings"] == matched and criterion["matched_count"] == len(matched)
    ), "Independent saved-field conjunction must equal only the current original native detections"
    assert criterion["run_reference"] == replay.provenance.run_reference, (
        "The CI predicate must preserve its exact original native SCAN receipt attribution"
    )
    exported = json.loads((parent / "ci.json").read_bytes())
    sarif = json.loads((parent / "ci.sarif").read_bytes())
    junit = ElementTree.parse(parent / "ci.xml").getroot()
    properties = {item.attrib["name"]: item.attrib["value"]
                  for item in junit.findall("properties/property")}
    snapshot = hashlib.sha256(Canonical(saved.ToDict())).hexdigest()
    assert exported["model"] == saved.ToDict() and snapshot == exported["snapshot_sha256"] == (
        outcome["snapshot_sha256"]
    ) == properties["snapshot_sha256"] == (
        sarif["runs"][0]["properties"]["canonicalSnapshotSha256"]
    ), "Actual native JSON, SARIF and JUnit must pin the same independently hashed saved snapshot"
    assert len(sarif["runs"][0]["results"]) == len(junit.findall("testcase")) == len(findings), (
        "Every actual format retains the complete saved native finding interpretations"
    )
    assert properties["scan_completeness"] == outcome["scan_completeness"] == "not-assessed", (
        "Native criterion satisfaction cannot assert complete scanner discovery"
    )

    for name, filename in (("json", "ci.json"), ("sarif", "ci.sarif"), ("junit", "ci.xml")):
        raw = (parent / filename).read_bytes()
        report = outcome["reports"][name]
        assert report["status"] == "completed" and report["output_published"] is True and (
            report["report_sha256"] == hashlib.sha256(raw).hexdigest()
            and report["size_bytes"] == len(raw)
        ), "Each artifact outcome must describe independently reopened actually published bytes"
        (evidence / filename).write_bytes(raw)

    shutil.copytree(root / "evidence", evidence / "evidence", dirs_exist_ok=True)
    (evidence / "expected.json").write_bytes(Canonical({"case": case,
        "provisioning": provisioning, "network_namespace": network,
        "matched_count": len(matched), "scan_completeness": "not-assessed"}))

    return len(matched)


@pytest.mark.parametrize("case", ORACLE["cases"], ids=[item["case_id"] for item in ORACLE["cases"]])
def test_GenuineInstalledCiPreservesPredicateArtifactsAndNoOptinRefusal(
    tmp_path, product_runtime, case,
):
    """Real pinned archive cases prove violating/satisfied criteria and no-optin refusal."""

    root = tmp_path / "owned-native-ci"
    selection = OwnedSelection(root, case, product_runtime)
    target = RegisterScope(root, case)
    policy = tmp_path / "native-policy.json"
    policy.write_text(SerializeContract(Policy()), encoding="utf-8")
    evidence = EVIDENCE / case["case_id"]
    evidence.mkdir(parents=True, exist_ok=True)
    limit = 0 if case["expected_selected_advisory_match"] else 1024
    arguments = Arguments(root, selection, policy, tmp_path, limit)
    before_workspace, before_model = LocalWorkspaceStore(root).Open(), LocalModelStore(root).Open()
    denied = [item for item in arguments if item != "--approve-safe-image"]
    status, outcome = Console(denied, evidence, "no-optin")
    assert status == 3 and outcome["scan"] is None and (
        outcome["criterion"]["status"] == "indeterminate"
    ), "Independent recorded read consent and policy cannot replace native workflow approval"
    assert LocalWorkspaceStore(root).Open() == before_workspace and (
        LocalModelStore(root).Open() == before_model
        and not (root / "native-image-claims").exists()
        and not any(item["output_published"] for item in outcome["reports"].values())
    ), "No-optin refusal must leave canonical state, claims and report publications unchanged"
    selection.executable.chmod(0o700)
    status, outcome = Console(arguments, evidence, "ci-run")
    assert outcome["scan"]["state"] == "completed" and not outcome["scan"]["custody_uncertain"], (
        "Genuine CI execution requires the actual completed certain-custody native workflow"
    )
    matches = CheckArtifacts(root, tmp_path, outcome, case, target, product_runtime, evidence)
    assert status == (1 if matches > limit else 0), (
        "The installed CLI exit must equal the independently counted explicit native predicate"
    )
    assert status == (1 if case["expected_selected_advisory_match"] else 0), (
        "The selected vulnerable case exceeds zero; the fixed case permits at most 1024 matches"
    )


def test_GenuineCiLatePolicyRefusalRetainsActualPublishedArtifacts(tmp_path, product_runtime):
    """Genuine execution with an explicit final-policy fault preserves publication truth."""

    case = ORACLE["cases"][0]
    root = tmp_path / "owned-native-ci-late-refusal"
    selection = OwnedSelection(root, case, product_runtime)
    target = RegisterScope(root, case)
    selection.executable.chmod(0o700)
    policy = tmp_path / "native-policy.json"
    policy.write_text(SerializeContract(Policy()), encoding="utf-8")
    evidence = EVIDENCE / "late-policy-refusal"
    evidence.mkdir(parents=True, exist_ok=True)
    status, outcome = Console(Arguments(root, selection, policy, tmp_path, 1024), evidence,
                              "late-refusal", late_policy=policy)
    assert status == 3 and outcome["scan"]["state"] == "completed" and (
        outcome["criterion"]["status"] == "satisfied"
    ), "Late policy refusal cannot become zero or erase already established scan/predicate facts"
    CheckArtifacts(root, tmp_path, outcome, case, target, product_runtime, evidence)
