# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite genuine installed content/header-v2 and authority controls on owned literal loopback."""

from __future__ import annotations

import os
import sys
from uuid import uuid4

import pytest

from fuzzy1337.executors.owned_process import RequireLinuxOwnership
from tests.contract.native_response_header_evidence import AdmitHeaderPlatform
from tests.contract.owned_content_response_sdk_pipeline import RunInstalled
from tests.contract.owned_content_response_worker_launcher import REPOSITORY, Build
from tests.native_crawl_acceptance_helpers import (
    NativeCaseEvidence,
    NativeEnvironment,
    NativeProcess,
)

pytestmark = [pytest.mark.integration, pytest.mark.serial]


@pytest.fixture(scope="module")
def installed_content_header_pipeline(tmp_path_factory):
    """Check advertised Linux ownership, then reuse the exact clean offline wheel build owner."""

    AdmitHeaderPlatform(sys.platform,
        os.environ.get("FUZZY1337_RUN_OWNED_CONTENT_HEADER_ACCEPTANCE"))
    RequireLinuxOwnership()
    root = tmp_path_factory.mktemp("installed-content-header")
    retained = REPOSITORY / "functional-evidence/owned-content-sdk" / ("run-" + uuid4().hex)
    evidence = NativeCaseEvidence(root / "build-evidence", retained / "installation")
    checkpoint = NativeProcess(evidence, "selected-checkpoint",
        ("git", "rev-parse", "HEAD", "HEAD^{tree}"), cwd=REPOSITORY,
        environment=NativeEnvironment(root / "selection-state"), timeout=5)
    assert checkpoint.returncode == 0, "The source checkpoint must be observed before build"
    commit, tree = checkpoint.stdout.decode("ascii").split()
    installed = Build(REPOSITORY, root / "installation", evidence,
        commit=commit, tree=tree, enabled=True)

    return installed, retained


def test_InstalledFreshContentHeaderPipelineRetainsAcknowledgedFindingAndRelocatedReplay(
    installed_content_header_pipeline, tmp_path,
):
    """A newly authorized missing-header source yields one actual durable replayable Finding."""

    installed, retained = installed_content_header_pipeline
    evidence = NativeCaseEvidence(tmp_path / "original-evidence", retained / "missing-positive")
    evidence.Json("case.json", {"schema_version": 1,
        "identity": "content-sdk:ipv4:missing:positive:relocated-header-replay",
        "expected_findings": 1, "runtime_acceptance": "unassessed-until-original-checks"})
    result = RunInstalled(installed, tmp_path / "pipeline", evidence,
        fixture_id="missing-" + uuid4().hex, case="missing", scenario="positive", enabled=True)
    assert result["runtime_acceptance"] == "passed" and result["state"] == (
        "checked-header-replay"), "A failed or unexecuted stage cannot satisfy genuine acceptance"
    assert result["expected_findings"] == 1 and result["identities"]["finding_reference"]


def test_InstalledFreshFixedContentHeaderPipelineRetainsNegativeAssessmentAndRelocatedReplay(
    installed_content_header_pipeline, tmp_path,
):
    """A new actual fixed-header source yields a durable negative assessment without a Finding."""

    installed, retained = installed_content_header_pipeline
    evidence = NativeCaseEvidence(tmp_path / "original-evidence", retained / "fixed-positive")
    evidence.Json("case.json", {"schema_version": 1,
        "identity": "content-sdk:ipv4:fixed:positive:relocated-header-replay",
        "expected_findings": 0, "runtime_acceptance": "unassessed-until-original-checks"})
    result = RunInstalled(installed, tmp_path / "pipeline", evidence,
        fixture_id="fixed-" + uuid4().hex, case="fixed", scenario="positive", enabled=True)
    assert result["runtime_acceptance"] == "passed" and result["state"] == (
        "checked-header-replay"), "A failed fixed-source stage cannot establish negative acceptance"
    assert result["expected_findings"] == 0 and result["identities"]["finding_reference"] is None, (
        "An actual fixed header must not create a Finding")
    assert result["identities"]["condition_observed"] is False, (
        "The persisted negative assessment must derive from the original fixed header")


def test_InstalledFreshPolicyDeniedContentHeaderPipelinePreservesAcquiredStateWithoutAssessment(
    installed_content_header_pipeline, tmp_path,
):
    """Valid SAFE capture does not grant offline analysis permission or permit an analysis Save."""

    installed, retained = installed_content_header_pipeline
    evidence = NativeCaseEvidence(tmp_path / "original-evidence", retained / "policy-denied")
    evidence.Json("case.json", {"schema_version": 1,
        "identity": "content-sdk:ipv4:missing:policy-denied:no-analysis-save",
        "expected_findings": 0, "assessment": "unassessed",
        "runtime_acceptance": "unassessed-until-original-checks"})
    result = RunInstalled(installed, tmp_path / "pipeline", evidence,
        fixture_id="policy-" + uuid4().hex, case="missing", scenario="policy-denied", enabled=True)
    assert result == {"state": "checked-authority-refusal", "expected_findings": 0,
        "runtime_acceptance": "passed", "source_delivery": "normal-eof"}, (
            "Denied analysis must remain unassessed without writing an assessment or Finding")


def test_InstalledFreshActorDriftContentHeaderPipelinePreservesAcquiredStateWithoutAssessment(
    installed_content_header_pipeline, tmp_path,
):
    """The controlled trusted actor reader must be revalidated despite valid policy and approval."""

    installed, retained = installed_content_header_pipeline
    evidence = NativeCaseEvidence(tmp_path / "original-evidence", retained / "actor-denied")
    evidence.Json("case.json", {"schema_version": 1,
        "identity": "content-sdk:ipv4:missing:owner-drift:no-analysis-save",
        "expected_findings": 0, "assessment": "unassessed",
        "runtime_acceptance": "unassessed-until-original-checks"})
    result = RunInstalled(installed, tmp_path / "pipeline", evidence,
        fixture_id="actor-" + uuid4().hex, case="missing", scenario="owner-drift", enabled=True)
    assert result == {"state": "checked-authority-refusal", "expected_findings": 0,
        "runtime_acceptance": "passed", "source_delivery": "normal-eof"}, (
            "Actor mismatch must remain unassessed without modifying acquired owner state")


def test_InstalledFreshBodyDecoyContentHeaderPipelineRetainsFindingAndRelocatedReplay(
    installed_content_header_pipeline, tmp_path,
):
    """Header-like body text cannot suppress the Finding from an absent actual HTTP field."""

    installed, retained = installed_content_header_pipeline
    evidence = NativeCaseEvidence(tmp_path / "original-evidence", retained / "body-decoy-positive")
    evidence.Json("case.json", {"schema_version": 1,
        "identity": "content-sdk:ipv4:body-decoy:positive:relocated-header-replay",
        "expected_findings": 1, "runtime_acceptance": "unassessed-until-original-checks"})
    result = RunInstalled(installed, tmp_path / "pipeline", evidence,
        fixture_id="body-decoy-" + uuid4().hex, case="body-decoy", scenario="positive",
        enabled=True)
    assert result["runtime_acceptance"] == "passed" and result["state"] == (
        "checked-header-replay"), "The actual body-decoy sequence must finish relocated replay"
    assert result["expected_findings"] == 1 and result["identities"]["finding_reference"], (
        "Text in the original body must not replace a real HTTP response header")
    assert result["identities"]["condition_observed"] is True, (
        "The persisted positive assessment must derive from original HTTP header names")


def test_InstalledFreshApprovalDeniedContentHeaderPipelinePreservesAcquiredStateWithoutAssessment(
    installed_content_header_pipeline, tmp_path,
):
    """Granted capture and PASSIVE permission cannot replace separate explicit analysis approval."""

    installed, retained = installed_content_header_pipeline
    evidence = NativeCaseEvidence(tmp_path / "original-evidence", retained / "approval-denied")
    evidence.Json("case.json", {"schema_version": 1,
        "identity": "content-sdk:ipv4:missing:approval-denied:no-analysis-save",
        "expected_findings": 0, "assessment": "unassessed",
        "runtime_acceptance": "unassessed-until-original-checks"})
    result = RunInstalled(installed, tmp_path / "pipeline", evidence,
        fixture_id="approval-" + uuid4().hex, case="missing", scenario="approval-denied",
        enabled=True)
    assert result == {"state": "checked-authority-refusal", "expected_findings": 0,
        "runtime_acceptance": "passed", "source_delivery": "normal-eof"}, (
            "Explicitly unapproved analysis must preserve acquired state without interpretation")


def test_InstalledFreshStaleModelRevisionContentHeaderPipelinePreservesAcquiredState(
    installed_content_header_pipeline, tmp_path,
):
    """An explicit stale model basis fails before fresh analysis admission or either Save."""

    installed, retained = installed_content_header_pipeline
    evidence = NativeCaseEvidence(tmp_path / "original-evidence", retained / "stale-model-revision")
    evidence.Json("case.json", {"schema_version": 1,
        "identity": "content-sdk:ipv4:missing:stale-model-revision:no-analysis-save",
        "expected_findings": 0, "assessment": "unassessed",
        "runtime_acceptance": "unassessed-until-original-checks"})
    result = RunInstalled(installed, tmp_path / "pipeline", evidence,
        fixture_id="revision-" + uuid4().hex, case="missing", scenario="stale-model-revision",
        enabled=True)
    assert result == {"state": "checked-revision-conflict", "expected_findings": 0,
        "runtime_acceptance": "passed", "source_delivery": "normal-eof"}, (
            "Stale CAS must preserve acquired state without reaching fresh analysis admission")
