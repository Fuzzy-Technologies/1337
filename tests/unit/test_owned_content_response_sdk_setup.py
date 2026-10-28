# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Mocked fresh setup seam contracts; no workspace/model/evidence/scope store or SDK execution."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from tests.contract import owned_content_response_sdk_setup as setup


@pytest.mark.parametrize("enabled", [False, None, 1, "yes"])
def test_SetupOptInRefusesBeforeAnySelectionOrOriginalSeedRead(enabled, monkeypatch):
    """Truthiness cannot create a workspace, load the original seed or enroll acquisition."""

    def Unexpected():
        """Detect any fixed helper load before the independent setup opt-in."""

        raise AssertionError("No seed load is authorized")

    monkeypatch.setattr(setup, "LoadSeed", Unexpected)

    with pytest.raises(PermissionError):
        setup.Setup(None, enabled=enabled)


def test_SetupPreservesActualOriginalNativeEvidenceAndConfirmedTriage(tmp_path, monkeypatch):
    """The mocked seed result stays untouched; no replacement IDs, ACK or triage are invented."""

    root = tmp_path / "fresh"
    actual = {"model": {"mock_native_triage": "CONFIRMED"},
        "originals": {"mock_original_id": {"mock_original_bytes": "unmodified"}},
        "scope_file": "mock_original_scope_path"}
    source = {"path": "mock_fixed_reviewed_seed", "sha256": "a" * 64}
    calls = []

    def Seed(config):
        """Record only the original seed handoff, without constructing any real store."""

        assert not root.exists(), "The original Create must own the fresh atomic root creation"
        calls.append(config)

        return actual

    original = SimpleNamespace(OWNER=setup.OWNER, WORKSPACE=setup.WORKSPACE, Setup=Seed)
    monkeypatch.setattr(setup, "LoadSeed", lambda: (original, source))
    config = {"workspace": str(root), "url": "http://127.0.0.1:15432/research/content",
        "owner_reference": setup.OWNER}
    observed = setup.Setup(config, enabled=True)
    assert observed["original_setup"] is actual and observed["seed_source"] is source, (
        "Actual original seed/inspection and source facts remain unchanged")
    assert calls == [{"workspace": str(root), "url": config["url"]}], "No negative/default override"
    assert observed["selection"]["ip"] == "127.0.0.1" and observed["selection"][
        "owner_reference"] != observed["selection"]["attester_reference"], (
            "The selected IPv4 source and independent attester must remain explicit")
    assert observed["selection"]["owner_reference"] == setup.OWNER and observed["selection"][
        "scope_id"] == "owned-source", "Later SDK calls must consume the original fixed selection"


@pytest.mark.parametrize("mutation", ["existing", "relative", "owner", "attester", "ipv6",
    "dns", "leading-zero-port", "query"])
def test_SetupInvalidOrMismatchedSelectionRefusesBeforeOriginalSeed(
    mutation, tmp_path, monkeypatch,
):
    """The IPv4 seed cannot silently register another family or overwrite original native state."""

    root = tmp_path / "workspace"
    config = {"workspace": str(root), "url": "http://127.0.0.1:15432/research/content",
        "owner_reference": setup.OWNER}

    if mutation == "existing":
        root.mkdir()
        (root / "original-native-marker").write_bytes(b"original")

    elif mutation == "relative":
        config["workspace"] = "relative/workspace"

    elif mutation in ("owner", "attester"):
        config["owner_reference"] = "actor:other" if mutation == "owner" else setup.ATTESTER

    else:
        config["url"] = {"ipv6": "http://[::1]:15432/research/content",
            "dns": "http://localhost:15432/research/content",
            "leading-zero-port": "http://127.0.0.1:015432/research/content",
            "query": "http://127.0.0.1:15432/research/content?"}[mutation]

    def Unexpected():
        """Fail if invalid selection reaches a helper load or any potential store activity."""

        raise AssertionError("Invalid setup must refuse before original seed")

    monkeypatch.setattr(setup, "LoadSeed", Unexpected)

    with pytest.raises((ValueError, FileExistsError)):
        setup.Setup(config, enabled=True)

    if mutation == "existing":
        assert (root / "original-native-marker").read_bytes() == b"original", "No original erasure"


def test_FixedSeedSourceHashDescribesTheExactBytesExecuted(tmp_path, monkeypatch):
    """The only source load is the reviewed sibling, never a config-selected script or fallback."""

    current = tmp_path / "owned_content_response_sdk_setup.py"
    current.write_bytes(b"# synthetic setup wrapper")
    sibling = current.with_name("owned_response_product_runner.py")
    raw = b"OWNER = 'mock-fixed-owner'\nWORKSPACE = 'mock-fixed-workspace'\n"
    sibling.write_bytes(raw)
    monkeypatch.setattr(setup, "__file__", str(current))
    loaded, source = setup.LoadSeed()
    assert loaded.OWNER == "mock-fixed-owner" and loaded.WORKSPACE == "mock-fixed-workspace", (
        "Only the fixed sibling's original bytes execute")
    assert source == {"path": str(sibling), "sha256": hashlib.sha256(raw).hexdigest()}, (
        "The caller can independently bind exactly executed reviewed seed source bytes")


def FreshConfig(tmp_path):
    """Select a new synthetic fixture and original fixed time window; perform no setup."""

    return {"fixture_id": "fresh-run-0001", "workspace": str(tmp_path / "new-owner"),
        "url": "http://127.0.0.1:15432/research/content",
        "consent_valid_from": "2030-01-01T00:00:00+00:00",
        "consent_valid_until": "2030-01-01T00:05:00+00:00"}


@pytest.mark.parametrize("mutation", [None, "expired", "future", "naive", "long-window",
    "historical", "unit-fixture", "relative", "foreign", "noncanonical-time"])
def test_NewFixtureSelectionRequiresItsOriginalCurrentlyValidAuthority(tmp_path, mutation):
    """Pure input checks never renew a delayed consent window or reuse old fixture identities."""

    config = FreshConfig(tmp_path)
    now = datetime(2030, 1, 1, 0, 1, tzinfo=timezone.utc)

    if mutation is None:
        selected = setup.FreshSelection(config, now)
        assert selected["workspace_id"] == selected["scope_id"] == (
            "owned-content-header-fresh-run-0001")
        assert len(set(selected.values())) == 4, "Only workspace/scope intentionally share identity"
        assert selected["owner_reference"] != selected["attester_reference"]

        return

    if mutation in ("expired", "future", "naive"):
        now = {"expired": datetime(2030, 1, 1, 0, 5, tzinfo=timezone.utc),
            "future": datetime(2029, 12, 31, 23, 59, tzinfo=timezone.utc),
            "naive": datetime(2030, 1, 1, 0, 1)}[mutation]

    else:
        key, value = {"long-window": ("consent_valid_until", "2030-01-01T00:20:00+00:00"),
            "historical": ("fixture_id", setup.WORKSPACE),
            "unit-fixture": ("fixture_id", "mock-run-0001"),
            "relative": ("workspace", "relative/owner"),
            "foreign": ("url", "http://localhost:15432/research/content"),
            "noncanonical-time": ("consent_valid_from", "2030-01-01T00:00:00Z")}[mutation]
        config[key] = value

    with pytest.raises((PermissionError, ValueError)):
        setup.FreshSelection(config, now)


@pytest.mark.parametrize("enabled", [False, None, 1, "yes"])
def test_NewSetupDefaultDenialPrecedesClockAndStorage(enabled):
    """An old setup opt-in or truthy value cannot authorize the distinct fresh fixture owner."""

    def Unexpected():
        """Detect any attempted time read before exact independent setup approval."""

        raise AssertionError("Default denial precedes even fixture clock reads")

    with pytest.raises(PermissionError):
        setup.FreshSetup(None, enabled=enabled, current_time_provider=Unexpected)


def test_NewSetupUsesDistinctConsentAndPreservesNativeTriageWithoutStoreIo(tmp_path, monkeypatch):
    """Real immutable contracts flow through mocked storage methods; no SDK or store I/O runs."""

    from fuzzy1337 import evidence, model, scope, workspace
    from fuzzy1337.adapters import EvidenceReference

    config = FreshConfig(tmp_path)
    identity = "owned-content-header-" + config["fixture_id"]
    states = {}
    calls = []

    def CreateWorkspace(store, configuration, workspace_id):
        """Retain a typed synthetic workspace only in memory, without a directory creation."""

        assert workspace_id == identity and not store.root.exists()
        states["workspace"] = workspace.WorkspaceState(workspace_id, configuration)

        return states["workspace"]

    def CreateScope(store, snapshot):
        """Retain the exact newly declared scope and independent consent in memory."""

        states["scope"] = snapshot

        return snapshot

    def Put(store, raw, role, media, provenance):
        """Return a typed synthetic original record without publishing any bytes."""

        calls.append("Put")
        digest = hashlib.sha256(raw).hexdigest()

        return evidence.EvidenceRecord(EvidenceReference(role, "blobs/sha256/" + digest,
            digest, media, len(raw)), provenance)

    def SaveModel(store, proposed, *, expected_revision):
        """Observe the original CAS proposal without acknowledging a real storage operation."""

        assert expected_revision == states.get("model", model.ModelState(identity)).revision
        assert proposed.workspace_id == identity and proposed.revision == expected_revision + 1
        states["model"] = proposed
        calls.append("model-Save")

        return proposed

    def SaveWorkspace(store, proposed):
        """Observe fresh native associations without mutating any canonical owner on disk."""

        states["workspace"] = replace(proposed, revision=proposed.revision + 1)
        calls.append("workspace-Save")

        return states["workspace"]

    monkeypatch.setattr(workspace.LocalWorkspaceStore, "Create", CreateWorkspace)
    monkeypatch.setattr(workspace.LocalWorkspaceStore, "Open", lambda store: states["workspace"])
    monkeypatch.setattr(workspace.LocalWorkspaceStore, "Save", SaveWorkspace)
    monkeypatch.setattr(model.LocalModelStore, "Create", lambda store: model.ModelState(identity))
    monkeypatch.setattr(model.LocalModelStore, "Save", SaveModel)
    monkeypatch.setattr(scope.LocalScopeStore, "Create", CreateScope)
    monkeypatch.setattr(scope.LocalScopeStore, "Open", lambda store, scope_id: states["scope"])
    monkeypatch.setattr(evidence.LocalEvidenceStore, "Put", Put)
    inspection = {"mock_original_inspection": True}
    monkeypatch.setattr(setup, "LoadSeed", lambda: (
        SimpleNamespace(Inspect=lambda root: inspection), {"mock_fixed_reader_hash": "a" * 64}))
    result = setup.FreshSetup(config, enabled=True,
        current_time_provider=lambda: datetime(2030, 1, 1, 0, 1, tzinfo=timezone.utc))
    assert result["state"] is inspection and calls == [
        "Put", "model-Save", "model-Save", "workspace-Save"]
    assert not (tmp_path / "new-owner").exists(), "Mocked methods performed no storage I/O"
    assert result["scope"]["authorization"] == {"state": "granted",
        "authority_reference": "attester:" + identity, "record_reference": "consent:" + identity,
        "valid_from": config["consent_valid_from"], "valid_until": config["consent_valid_until"]}
    finding = next(row for row in states["model"].objects if row.identity.kind.value == "finding")
    assert finding.attributes["status"] == "confirmed" and finding.attributes["status_reason"]
    assert states["workspace"].job_references == ("job:unrelated-" + identity,)


def test_NewFixtureCannotUseRepeatedIdentifierSeparators(tmp_path):
    """Reject malformed derived scope/policy identities before constructing a store owner."""

    config = FreshConfig(tmp_path)
    config["fixture_id"] = "fresh--invalid"

    with pytest.raises(ValueError):
        setup.FreshSelection(config, datetime(2030, 1, 1, 0, 1, tzinfo=timezone.utc))
