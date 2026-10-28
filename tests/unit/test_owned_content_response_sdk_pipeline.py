# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Mocked finite SDK pipeline control flow; no setup, target, SDK, store or runtime acceptance."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from tests.contract import owned_content_response_sdk_pipeline as pipeline


def Selection(tmp_path, *, case="missing", scenario="positive"):
    """Declare independent synthetic future fixture inputs without creating a product owner."""

    return {"fixture_id": "mock-run-0001", "workspace": str(tmp_path / "original"),
        "relocated_workspace": str(tmp_path / "relocated"),
        "observations": str(tmp_path / "observations"),
        "url": "http://127.0.0.1:15432/research/content", "case": case, "scenario": scenario,
        "consent_valid_from": "2030-01-01T00:00:00+00:00",
        "consent_valid_until": "2030-01-01T00:05:00+00:00"}


def Guard(*, historical=False):
    """Return explicitly mocked tripwire facts; these are never real offline observations."""

    calls = {key: 0 for key in ("socket.audit", "socket.socket", "subprocess.Popen",
        "LocalExecutor.Execute", "GovernedLocalExecutor.Execute", "PolicyEngine.Authorize",
        "LocalEvidenceStore.Put", "LocalEvidenceStore.PublishStoredBytes",
        "OwnedResponseStage.__init__")}

    if historical:
        calls.update({key: 0 for key in (
            "LocalModelStore.Save", "LocalWorkspaceStore.Save", "LocalScopeStore.Open")})

    return {"calls": calls, "audit_probe_seen": True, "saves": []}


class MockSequence:
    """Provide marked mock handoffs and oracle spies without touching any runtime seam."""

    def __init__(self, plan, monkeypatch):
        """Own detached synthetic values and replace only pure assertions for wiring checks."""

        self.plan = plan
        self.calls = []
        self.oracles = []
        self.before = {"workspace": {"workspace_id": plan["workspace_id"], "revision": 1},
            "model": {"workspace_id": plan["workspace_id"], "revision": 2}, "originals": {}}
        self.acquired = deepcopy(self.before)
        self.acquired["workspace"]["revision"] = 2
        self.acquired["model"]["revision"] = 3
        self.interpreted = deepcopy(self.acquired)
        self.summary = {"original_receipt_id": "receipt:mock-only",
            "original_job_id": "job:mock-only", "source_facts": {"mock_only": True}}
        self.identities = {"original_receipt_id": "receipt:mock-only",
            "analysis_reference": plan["analysis_reference"],
            "assessment_reference": "assessment:mock-only", "condition_observed": True,
            "finding_reference": "finding:mock-only" if plan["expected_findings"] else None}
        self.analysis = {"summary": {"state": plan["expected_state"], "failure": "authorization",
            "condition_observed": None, "assessment_reference": None, "finding_reference": None},
            "guard": Guard()}
        self.replay = {"summary": {"mock_replay": True}, "guard": Guard(historical=True)}
        self.relocated = {"original_root_absent": True, "relocated_root_present": True}
        self.scope = {"scope_id": plan["scope_id"], "workspace_id": plan["workspace_id"],
            "authorization": {"state": "granted", "authority_reference": plan[
                "attester_reference"], "record_reference": plan["consent_reference"],
                "valid_from": plan["selection"]["consent_valid_from"],
                "valid_until": plan["selection"]["consent_valid_until"]}}
        self.policies = {role: {"path": f"/mock-only/{role}.json", "document": {
            "mock_policy": role}} for role in ("acquisition", "analysis")}

        def CaptureOracle(*args, **kwargs):
            """Observe unmodified SDK-save input wiring; no acquisition is asserted here."""

            assert args == (self.before, self.acquired, self.summary, [])
            assert kwargs["workspace_id"] == plan["workspace_id"]
            self.oracles.append("capture")

        def PartsOracle(*args, **kwargs):
            """Observe selected original receipt/case wiring without manufacturing any parts."""

            assert args == (plan["selection"]["case"], plan["selection"]["url"],
                "receipt:mock-only", {}, self.summary["source_facts"])
            assert kwargs == {"job_id": "job:mock-only"}
            self.oracles.append("parts")

        def HeaderOracle(*args, **kwargs):
            """Observe original state/guard Save wiring and independently selected authority."""

            assert args == (self.acquired, self.interpreted, self.analysis["summary"], [])
            assert kwargs["analysis"] == plan["analysis_reference"] and (
                kwargs["authority"]["scope"] is self.scope)
            assert kwargs["authority"]["owner_attribution"] == "trusted-reader"
            self.oracles.append("header")

            return self.identities

        def ReplayOracle(*args):
            """Observe the same persisted identities and relocated snapshots, never replay."""

            assert args == (self.interpreted, self.interpreted,
                self.replay["summary"], self.identities)
            self.oracles.append("replay")

        monkeypatch.setattr(pipeline, "AssertSdkSaveTransition", CaptureOracle)
        monkeypatch.setattr(pipeline, "AssertContentParts", PartsOracle)
        monkeypatch.setattr(pipeline, "AssertContentHeaderV2", HeaderOracle)
        monkeypatch.setattr(pipeline, "AssertHistoricalContentHeaderReplay", ReplayOracle)

    def Handoff(self, operation, selection, observations):
        """Return marked mock documents; relocation creates only an empty filesystem sentinel."""

        self.calls.append((operation, deepcopy(selection), observations))

        if operation == "fresh-setup":
            return {"state": self.before, "scope": self.scope, "policies": self.policies}

        if operation == "capture":
            return {"summary": self.summary, "store_saves": []}

        if operation == "inspect":
            return {"state": self.acquired if len(self.calls) == 3 else self.interpreted}

        if operation == "analyze-offline":
            return self.analysis

        if operation == "relocate":
            Path(selection["relocated_workspace"]).mkdir()

            return self.relocated

        assert operation == "replay-offline", "The coordinator has no general command dispatch"

        return self.replay


@pytest.mark.parametrize("case,expected", [("missing", 1), ("fixed", 0), ("body-decoy", 1)])
def test_MockedSequenceKeepsIndependentFindingTruthAndRelocatedHeaderReplay(
    tmp_path, monkeypatch, case, expected,
):
    """One fixed operation order preserves actual selections and fresh observation ownership."""

    plan = pipeline.Plan(Selection(tmp_path, case=case))
    mock = MockSequence(plan, monkeypatch)
    result = pipeline.Run(plan, mock.Handoff, enabled=True)
    assert result["state"] == "checked-header-replay" and result["expected_findings"] == expected
    assert mock.oracles == ["capture", "parts", "header", "replay"]
    assert [item[0] for item in mock.calls] == ["fresh-setup", "capture", "inspect",
        "analyze-offline", "inspect", "relocate", "inspect", "replay-offline", "inspect"]
    owners = [item[2] for item in mock.calls]
    assert len(set(owners)) == len(owners) and all(owner.parent == tmp_path / "observations"
        for owner in owners), "Every operation has a fresh independent observation owner"
    capture, analyze, replay = [mock.calls[index][1] for index in (1, 3, 7)]
    assert capture["approve_safe_content_response_capture"] is True and capture[
        "retain_response"] is True and analyze["approve_passive_header_check"] is True
    assert analyze["original_receipt_id"] == mock.summary["original_receipt_id"]
    assert analyze["expected_model_revision"] == 3 and analyze["expected_workspace_revision"] == 2
    assert replay == {"workspace": str(tmp_path / "relocated"), "kind": "header",
        "reference": mock.identities["assessment_reference"]}


@pytest.mark.parametrize("scenario", pipeline.SCENARIOS[1:])
def test_MockedAuthorityRefusalLeavesOriginalsUnchangedAndStopsBeforeRelocation(
    tmp_path, monkeypatch, scenario,
):
    """Each independently declared authority failure requires no assessment, Save or replay."""

    plan = pipeline.Plan(Selection(tmp_path, scenario=scenario))
    mock = MockSequence(plan, monkeypatch)
    assert pipeline.Run(plan, mock.Handoff, enabled=True) == {
        "state": "checked-authority-refusal", "expected_findings": 0}
    assert mock.oracles == ["capture", "parts"] and len(mock.calls) == 5
    selected = mock.calls[3][1]
    assert selected["authority_scenario"] == scenario and selected[
        "approve_passive_header_check"] is (scenario != "approval-denied")


@pytest.mark.parametrize("mutation", ["consent", "offline-call", "missing-tripwire",
    "lost-probe", "wrong-finding", "old-root-remains", "relocation-claim",
    "relocation-repairs", "replay-write"])
def test_MockedFailuresStopWithoutRetryOrLaterStages(tmp_path, monkeypatch, mutation):
    """Wrong authority, swallowed offline attempts and incomplete relocation cannot advance."""

    plan = pipeline.Plan(Selection(tmp_path))
    mock = MockSequence(plan, monkeypatch)
    maximum_calls = 5

    if mutation == "consent":
        mock.scope["authorization"]["record_reference"] = "consent:historical"
        maximum_calls = 1

    elif mutation == "offline-call":
        mock.analysis["guard"]["calls"]["socket.audit"] = 1

    elif mutation == "missing-tripwire":
        del mock.analysis["guard"]["calls"]["LocalEvidenceStore.Put"]

    elif mutation == "lost-probe":
        mock.analysis["guard"]["audit_probe_seen"] = False

    elif mutation == "wrong-finding":
        mock.identities["finding_reference"] = None

    elif mutation == "old-root-remains":
        mock.relocated["original_root_absent"] = False
        maximum_calls = 6

    elif mutation == "relocation-claim":
        def Claimed(operation, selection, observations):
            """Preserve an old empty directory despite mocked relocation success metadata."""

            value = mock.Handoff(operation, selection, observations)

            if operation == "relocate":
                Path(selection["workspace"]).mkdir()

            return value

        maximum_calls = 6

    elif mutation == "relocation-repairs":
        mock.interpreted["originals"]["unexpected"] = "repair"

        def Relocated(operation, selection, observations):
            """Return changed relocated documents from an explicitly mocked reader."""

            value = mock.Handoff(operation, selection, observations)

            if len(mock.calls) == 7:
                return {"state": mock.acquired}

            return value

        maximum_calls = 7

    else:
        mock.replay["guard"]["saves"].append({"mock_forbidden_write": True})
        maximum_calls = 8

    selected_handoff = mock.Handoff

    if mutation == "relocation-repairs":
        selected_handoff = Relocated

    elif mutation == "relocation-claim":
        selected_handoff = Claimed

    with pytest.raises(AssertionError):
        pipeline.Run(plan, selected_handoff, enabled=True)

    assert len(mock.calls) <= maximum_calls, "No failing operation may trigger a retry"


@pytest.mark.parametrize("enabled", [False, None, 1, "yes"])
def test_SequenceDefaultDenialPrecedesPlanReadsAndHandoffs(enabled):
    """A truthy flag cannot opt into acquisition, analysis or even fresh fixture setup."""

    with pytest.raises(PermissionError):
        pipeline.Run(None, None, enabled=enabled)


@pytest.mark.parametrize("mutation", ["extra", "identity", "relative", "overlap", "external",
    "query", "case", "scenario", "naive", "backward", "long-window"])
def test_PlanRejectsAmbiguousTargetsIdentitiesAndConsentWindowsBeforeEffects(tmp_path, mutation):
    """Malformed declarations never rely on product-returned truth or implicit clock renewal."""

    selection = Selection(tmp_path)

    if mutation == "extra":
        selection["implicit_approval"] = "yes"

    else:
        key, value = {"identity": ("fixture_id", "old"),
            "relative": ("workspace", "relative/product"),
            "overlap": ("observations", str(tmp_path / "original" / "observations")),
            "external": ("url", "http://example.com:15432/research/content"),
            "query": ("url", selection["url"] + "?case=missing"), "case": ("case", "catalog"),
            "scenario": ("scenario", "auto"), "naive": (
                "consent_valid_from", "2030-01-01T00:00:00"),
            "backward": ("consent_valid_until", "2029-12-31T23:59:59+00:00"),
            "long-window": ("consent_valid_until", "2030-01-01T01:00:00+00:00")}[mutation]
        selection[key] = value

    with pytest.raises(ValueError):
        pipeline.Plan(selection)


def test_ChangedFrozenExpectationRefusesBeforeAnyHandoff(tmp_path):
    """The selected source truth cannot be changed after the pipeline plan was frozen."""

    plan = pipeline.Plan(Selection(tmp_path))
    plan["expected_findings"] = 0

    with pytest.raises(ValueError):
        pipeline.Run(plan, None, enabled=True)


@pytest.mark.parametrize("existing", ["workspace", "relocated_workspace"])
def test_ExistingProductRootsRefuseBeforeFreshSetup(tmp_path, existing):
    """An existing owner cannot supply historical state or receive an implicit replacement."""

    selection = Selection(tmp_path)
    Path(selection[existing]).mkdir()

    with pytest.raises(ValueError):
        pipeline.Run(pipeline.Plan(selection), None, enabled=True)


def test_CanonicalObservationAliasRefusesBeforeFreshSetup(tmp_path):
    """A lexical sibling alias cannot let observations enter the original product owner."""

    selection = Selection(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    selection["observations"] = str(alias / "original" / "observations")

    with pytest.raises(ValueError):
        pipeline.Run(pipeline.Plan(selection), None, enabled=True)
