# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Check ordered SQL assessment using independently governed owned SQLite samples."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.adapters.native_web import (
    NATIVE_SQL_BOOLEAN_SAMPLE_CAPABILITY,
    NATIVE_SQL_BOOLEAN_SAMPLE_CHECK_ID,
    NATIVE_WEB_PROVIDER_ID,
)
from fuzzy1337.evidence import EvidenceError
from fuzzy1337.findings import Findings
from fuzzy1337.jobs import JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_web import NativeWebScanLimits, PlanNativeWebScan, RunNativeWebScan
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, PolicyConfirmation
from fuzzy1337.scan_commands import CreateWorkspace
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.sql_boolean_assessment import (
    AssessSqlBooleanEvidence,
    ClassifySqlBooleanDigests,
    SqlBooleanOutcome,
)
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.web_vulnerability_helpers import Oracle, OwnedWebVulnerabilityTarget

WORKSPACE_ID = "owned-sql-assessment"
OWNER = "operator:owned-sql-assessment"
POLICY = ImpactPolicy("owned-sql-assessment", maximum_impact=ImpactLevel.STANDARD,
    permissions=(CapabilityPermission(NATIVE_SQL_BOOLEAN_SAMPLE_CAPABILITY, NATIVE_WEB_PROVIDER_ID,
                                      ImpactLevel.STANDARD),))


def SamplePolicy() -> ImpactPolicy:
    """Return the current explicit permission for only the separately approved sample profile."""

    return POLICY


@pytest.mark.parametrize(("digests", "expected"), [
    ((), SqlBooleanOutcome.PARTIAL),
    (("base", "base", "false"), SqlBooleanOutcome.PARTIAL),
    (("base", "base", "false", "changed"), SqlBooleanOutcome.UNSTABLE_BASELINE),
    (("base", "same", "same", "base"), SqlBooleanOutcome.NO_DIFFERENTIAL),
    (("base", "base", "false", "base"), SqlBooleanOutcome.DIFFERENTIAL_CANDIDATE),
    (("base", "true", "false", "base"), SqlBooleanOutcome.INCONCLUSIVE),
])
def test_OnlyTheFiniteStableDigestPatternSupportsACandidate(digests, expected):
    """Keep missing, unstable and inconclusive evidence separate from absence or a candidate."""

    assert ClassifySqlBooleanDigests(digests) is expected, (
        "The ordered digest classification drifted."
    )


@pytest.mark.parametrize(("mode", "control", "expected"), [
    ("vulnerable", "complete", SqlBooleanOutcome.DIFFERENTIAL_CANDIDATE),
    ("fixed", "complete", SqlBooleanOutcome.NO_DIFFERENTIAL),
    ("fixed", "denied", SqlBooleanOutcome.PARTIAL),
    ("fixed", "wrong-role", None),
])
def test_AssessOnlyTheCurrentOwnedSqlJobPrefix(tmp_path, mode, control, expected):
    """Verify original acquisitions and model observations without contacting the target again."""

    root = tmp_path / "workspace"
    CreateWorkspace(root, WORKSPACE_ID, "Owned SQL assessment tests")
    workspaceStore = LocalWorkspaceStore(root)
    before = workspaceStore.Open()
    cases = {case["sample"]: case for case in Oracle()["sql_boolean_cases"] if case["mode"] == mode}

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        targets = tuple(Target(TargetKind.URL, service.base_url + cases[role]["route"])
                        for role in ("baseline", "true", "false", "baseline"))
        allowed = (*targets[:3], Target(TargetKind.IP, "127.0.0.1"))
        now = datetime.now(UTC)
        LocalScopeStore(root).Create(ScopeSnapshot("local", WORKSPACE_ID, ScopeAuthorization(
            AuthorizationState.GRANTED, OWNER, "consent:owned-sql-assessment",
            (now - timedelta(minutes=1)).isoformat(), (now + timedelta(minutes=10)).isoformat(),
        ), targets=allowed, allow=allowed))

        def Plan(target, *, limits=NativeWebScanLimits()):
            """Plan exactly one approved-by-operator owned SQL sample coordinate."""

            return PlanNativeWebScan(root, "local", target, OWNER, SamplePolicy,
                                    check_id=NATIVE_SQL_BOOLEAN_SAMPLE_CHECK_ID, limits=limits)

        plans = tuple(Plan(target) for target in targets)
        assert AssessSqlBooleanEvidence(root, before, plans, ()) is SqlBooleanOutcome.PARTIAL, (
            "Missing execution cannot become an assessed result."
        )
        runs = []

        for index in range(len(plans)):
            selected = 2 if control == "wrong-role" and index == 1 else index
            target, plan = targets[selected], plans[selected]
            denied = control == "denied" and index == 1
            confirmation = None if denied else PolicyConfirmation(
                plan.policy_plan.intent_sha256, f"approval:owned-sql-assessment-{index}")
            run = asyncio.run(RunNativeWebScan(root, "local", target, OWNER, SamplePolicy,
                check_id=NATIVE_SQL_BOOLEAN_SAMPLE_CHECK_ID, confirmation=confirmation))
            runs.append(run)

            if denied:
                assert run.snapshot.state is JobState.FAILED, (
                    "Missing approval must fail the probe."
                )

                break

        targetFacts = service.Observe()
        assert len(targetFacts["queries"]) == (1 if control == "denied" else 4), (
            "Only separately confirmed probes may reach actual SQLite."
        )

        if control == "wrong-role":
            with pytest.raises(ValueError, match="differs from its native invocation"):
                AssessSqlBooleanEvidence(root, before, plans, tuple(runs))

            assert service.Observe() == targetFacts, "A role mismatch cannot contact the target."

            return

        assert AssessSqlBooleanEvidence(root, before, plans, tuple(runs)) is expected, (
            "The verified pattern must reflect the actual SQLite control outcome."
        )
        assert service.Observe() == targetFacts, "Offline assessment contacted the target."
        assert not Findings(LocalModelStore(root).Open()), (
            "Digest evidence cannot create a Finding."
        )

        if control == "denied":
            return

        records = tuple(tuple(artifact.evidence for artifact in item.snapshot.artifacts)
                        for item in runs)
        assert records[0][0].reference == records[-1][0].reference, (
            "Repeated equal stdout should share its immutable content address."
        )
        assert records[0][0].evidence_id != records[-1][0].evidence_id, (
            "A repeated baseline needs a separate acquisition."
        )

        with pytest.raises(ValueError, match="four exact probe plans"):
            AssessSqlBooleanEvidence(root, before, plans[:3], tuple(runs))

        with pytest.raises(ValueError, match="planned role"):
            AssessSqlBooleanEvidence(root, before, (plans[0], plans[2], plans[1], plans[3]),
                                     tuple(runs))

        invalidPlan = replace(plans[0], policy_plan=replace(plans[0].policy_plan,
                              invocation_sha256="0" * 64))

        with pytest.raises(ValueError, match="exact confirmed native sample plans"):
            AssessSqlBooleanEvidence(root, before, (invalidPlan, *plans[1:]), tuple(runs))

        changedPlan = Plan(targets[-1], limits=NativeWebScanLimits(request_timeout_seconds=4.0))

        with pytest.raises(ValueError, match="one coordinate"):
            AssessSqlBooleanEvidence(root, before, (*plans[:3], changedPlan), tuple(runs))

        with pytest.raises(ValueError, match="exact ordered current job suffix"):
            AssessSqlBooleanEvidence(root, before, plans, tuple(reversed(runs)))

        with pytest.raises(ValueError, match="at most four current sample receipts"):
            AssessSqlBooleanEvidence(root, before, plans, (*runs, runs[0]))

        with pytest.raises(ValueError, match="exact ordered current job suffix"):
            AssessSqlBooleanEvidence(root, workspaceStore.Open(), plans, tuple(runs))

        wrongOwner = replace(runs[-1], snapshot=replace(runs[-1].snapshot,
            spec=replace(runs[-1].snapshot.spec, owner_reference="operator:other")))

        with pytest.raises(ValueError, match="planned owner"):
            AssessSqlBooleanEvidence(root, before, plans, (*runs[:3], wrongOwner))

        badEvents = replace(runs[-1], events=runs[-1].events[:-1])

        with pytest.raises(ValueError, match="truthful terminal"):
            AssessSqlBooleanEvidence(root, before, plans, (*runs[:3], badEvents))

        reused = replace(before, evidence_record_references=(records[-1][0].evidence_id,))

        with pytest.raises(ValueError, match="stale, reused or misattributed"):
            AssessSqlBooleanEvidence(root, reused, plans, tuple(runs))

        if mode == "fixed":
            modelStore = LocalModelStore(root)
            saved = modelStore.Open()
            modified = tuple(replace(item, attributes={**item.attributes, "body_sha256": "0" * 64})
                if item.provenance.run_reference == runs[-1].snapshot.spec.job_id else item
                for item in saved.observations)
            modelStore.Save(replace(saved, observations=modified, revision=saved.revision + 1),
                            expected_revision=saved.revision)

            with pytest.raises(ValueError, match="saved observation differs"):
                AssessSqlBooleanEvidence(root, before, plans, tuple(runs))

        else:
            rawBlob = root / "evidence" / records[-1][0].reference.locator
            rawBlob.write_bytes(b"corrupt")

            with pytest.raises(EvidenceError):
                AssessSqlBooleanEvidence(root, before, plans, tuple(runs))

        assert service.Observe() == targetFacts, "Refused evidence also cannot contact the target."
