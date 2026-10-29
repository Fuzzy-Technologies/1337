# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure policy and mocked setup/inspection control contracts; no real SDK stores or execution."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.nucleiscan import ReadNucleiPolicy
from tests.contract import owned_content_response_sdk_controls as controls


def test_TypedPoliciesKeepSafeAcquisitionAndPassiveAnalysisPermissionsIndependent():
    """Policy fixtures contain neither implicit workflow approval nor byte retention selection."""

    policies = controls.Policies()
    safe, passive = policies["acquisition"], policies["analysis"]
    assert safe.maximum_impact is ImpactLevel.SAFE and passive.maximum_impact is (
        ImpactLevel.PASSIVE), (
        "Acquisition and analysis must retain separate SAFE and PASSIVE impact levels."
    )
    assert [(item.capability_id, item.adapter_id) for item in safe.permissions] == [(
        "http.owned-content-response-capture", "native.loopback-content-response")], (
        "SAFE acquisition policy must grant only the explicit content capture capability and "
        "provider."
    )
    assert [(item.capability_id, item.adapter_id) for item in passive.permissions] == [(
        "http.owned-response-header-check", "native.response-passive")], (
        "PASSIVE analysis policy must grant only the fixed original-header check capability and "
        "provider."
    )
    assert all(not item.granted_privileges for policy in policies.values()
        for item in policy.permissions), "No credential or execution privilege is fabricated"


def test_SetupControlPreservesSeedAndWritesExclusiveTypedPolicyFixtures(tmp_path, monkeypatch):
    """Only controlled seed values are observed; policy JSON round-trips through the real parser."""

    actual = {"mock_original_native_state": "unmodified"}
    calls = []

    def Setup(selection, *, enabled):
        """Observe only a mocked setup handoff, never create a product workspace."""

        calls.append((selection, enabled))

        return actual

    def Load(name):
        """Observe the fixed approved setup source selection, without loading an actual helper."""

        assert name == controls.SETUP_SOURCE, "Setup may load only the fixed reviewed setup helper"

        return SimpleNamespace(Setup=Setup), {"mock_source_sha256": "a" * 64}

    monkeypatch.setattr(controls, "LoadFixed", Load)
    selection = {"workspace": str(tmp_path / "workspace"), "url": (
        "http://127.0.0.1:15432/research/content"),
        "owner_reference": "actor:owned-response-product"}
    observed = controls.Dispatch("setup", selection, tmp_path / "observations", enabled=True)
    assert observed["original_setup"] is actual and calls == [(selection, True)], (
        "Original setup values are not replaced with inferred ACKs or IDs")

    for role, policy in controls.Policies().items():
        path = tmp_path / "observations" / (role + "-policy.json")
        assert ReadNucleiPolicy(path) == policy, "The explicit fixture must remain typed and exact"
        data = json.loads(path.read_bytes())
        assert not {"retain_response", "approve_safe_content_response_capture",
            "approve_passive_header_check"}.intersection(data), "Policy is not workflow approval"

    with pytest.raises(FileExistsError):
        controls.Dispatch("setup", selection, tmp_path / "observations", enabled=True)

    assert len(calls) == 1, "A used observation owner refuses before another seed operation"


@pytest.mark.parametrize("failure", [False, True])
def test_InspectionCallsOnlyOriginalReadOwnerAndPreservesFailure(tmp_path, monkeypatch, failure):
    """Read-only product inspection never seeds state, writes policy or suppresses owner errors."""

    calls = []
    actual = {"mock_original_evidence": "unchanged"}

    def Inspect(root):
        """Record one mocked canonical reader, without constructing stores or acquiring sources."""

        calls.append(root)

        if failure:
            raise RuntimeError("original mock reader failure")

        return actual

    def Unexpected():
        """Refuse any policy fixture generation during read-only product inspection."""

        raise AssertionError("Inspection must not create policy fixtures")

    monkeypatch.setattr(controls, "Policies", Unexpected)
    monkeypatch.setattr(controls, "LoadFixed", lambda name: (SimpleNamespace(Inspect=Inspect),
        {"mock_fixed_seed": name}))
    selection = {"workspace": str(tmp_path / "workspace")}
    observations = tmp_path / "inspection"

    if failure:
        with pytest.raises(RuntimeError):
            controls.Dispatch("inspect", selection, observations, enabled=True)

    else:
        assert controls.Dispatch("inspect", selection, observations, enabled=True)[
            "original_inspection"] is actual, "The actual reader values remain unchanged"

    assert calls == [tmp_path / "workspace"] and not (tmp_path / "workspace").exists(), (
        "Only the mocked product reader executes")
    record = json.loads((observations / "inspect.json").read_bytes())
    assert record["exception_type"] == ("RuntimeError" if failure else None), "Failure is retained"


@pytest.mark.parametrize("enabled", [False, None, 1, "yes"])
def test_ControlDefaultDenialPrecedesAnyHelperOrStoreAccess(enabled):
    """Explicit identity, approval and retained state cannot be inferred from truthiness."""

    with pytest.raises(PermissionError):
        controls.Dispatch("setup", None, None, enabled=enabled)


@pytest.mark.parametrize("overlap", ["same", "inside", "parent"])
def test_ObservationOwnerCannotMutateTheInspectedProductWorkspace(tmp_path, overlap):
    """Independent observation writes must not enter or enclose the selected product workspace."""

    workspace = tmp_path / "workspace"
    owner = {"same": workspace, "inside": workspace / "observations", "parent": tmp_path}[overlap]

    with pytest.raises(ValueError):
        controls.Dispatch("inspect", {"workspace": str(workspace)}, owner, enabled=True)

    assert not workspace.exists(), "Invalid owner relationships refuse before product mutations"


@pytest.mark.parametrize("alias", ["observation-into-workspace", "workspace-inside-observation",
    "equal-canonical-roots", "disjoint"])
def test_CanonicalAliasSeparationPrecedesEffectsAndPreservesOriginalSelection(
    alias, tmp_path, monkeypatch,
):
    """Canonical overlap refuses before writes/readers; disjoint aliases keep original SDK paths."""

    workspace = tmp_path / "selected-workspace-alias"
    observations = tmp_path / "selected-observation-alias" / "fresh"
    physical_workspace = tmp_path / "physical-product"
    physical_observations = tmp_path / "physical-evidence"

    if alias == "observation-into-workspace":
        physical_observations = physical_workspace / "fresh"

    elif alias == "workspace-inside-observation":
        physical_workspace = physical_observations / "product"

    elif alias == "equal-canonical-roots":
        physical_observations = physical_workspace

    original_resolve = Path.resolve
    calls = []

    def Resolve(path, *args, **kwargs):
        """Model resolved aliases without constructing any symlink or actual product workspace."""

        if path == workspace:
            return physical_workspace

        if path == observations:
            return physical_observations

        return original_resolve(path, *args, **kwargs)

    def Inspect(root):
        """Observe a mocked read handoff without actual stores or workspace mutations."""

        calls.append(root)

        return {"mock_original_inspection": True}

    monkeypatch.setattr(Path, "resolve", Resolve)
    monkeypatch.setattr(controls, "LoadFixed", lambda _name: (SimpleNamespace(Inspect=Inspect),
        {"mock_original_source": True}))

    if alias == "disjoint":
        controls.Dispatch("inspect", {"workspace": str(workspace)}, observations, enabled=True)
        assert calls == [workspace], "Separation checks preserve the selected SDK path"

    else:
        with pytest.raises(ValueError):
            controls.Dispatch("inspect", {"workspace": str(workspace)}, observations, enabled=True)

        assert calls == [] and not observations.exists(), (
            "Alias overlap must refuse before observation mkdir or product reader effects")


def test_FreshSetupControlKeepsFixtureAuthorityAndDeniedPolicyIndependent(tmp_path, monkeypatch):
    """Fresh control calls only the distinct mocked seed and emits actual typed policy variants."""

    identity = "owned-content-header-fresh-control-0001"
    actual = {"state": {"workspace": {"workspace_id": identity}},
        "scope": {"mock_new_consent": True}}
    calls = []

    def FreshSetup(selection, *, enabled):
        """Observe the distinct fresh fixture call without creating any product stores."""

        calls.append((selection, enabled))

        return actual

    def Unexpected(*args, **kwargs):
        """Refuse any attempt to reuse the old fixed-identity setup for this operation."""

        raise AssertionError("Fresh setup cannot dispatch to historical identity setup")

    monkeypatch.setattr(controls, "LoadFixed", lambda name: (SimpleNamespace(
        FreshSetup=FreshSetup, Setup=Unexpected), {"mock_source": name}))
    selection = {"workspace": str(tmp_path / "workspace"), "fixture_id": "fresh-control-0001"}
    result = controls.Dispatch("fresh-setup", selection, tmp_path / "observations", enabled=True)
    assert calls == [(selection, True)] and result["scope"] is actual["scope"], (
        "Fresh setup must receive the selected configuration once and return its actual scope "
        "object."
    )
    policies = result["policies"]
    assert set(policies) == {"acquisition", "analysis", "analysis-denied"}, (
        "Setup must retain distinct acquisition, allowed-analysis and denied-analysis policy "
        "documents."
    )

    for role, observed in policies.items():
        path = tmp_path / "observations" / (role + "-policy.json")
        parsed = ReadNucleiPolicy(path)
        assert parsed.policy_id == identity + "-" + role, (
            "Each persisted policy must retain its own selected identity and role suffix."
        )
        assert json.loads(path.read_bytes()) == observed["document"], (
            "The persisted policy bytes must equal the independently observed original document."
        )

    assert policies["analysis"]["document"]["permissions"], (
        "Allowed analysis policy must retain an explicit permission rather than an empty grant "
        "set."
    )
    assert policies["analysis-denied"]["document"]["permissions"] == [], (
        "Denial is a separate typed fixture, not a permission patched during analysis")
