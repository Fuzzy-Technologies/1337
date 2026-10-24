# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Mocked fresh setup seam contracts; no workspace/model/evidence/scope store or SDK execution."""

from __future__ import annotations

import hashlib
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
