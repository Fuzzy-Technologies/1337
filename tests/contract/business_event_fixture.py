# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Produce original owner scenarios independently of business profiles."""

from __future__ import annotations

from fuzzy1337.business_events import ApplyBusinessEvent, ReadBusinessEventDefinition
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.model import CanonicalModelJson, LocalModelStore
from fuzzy1337.reachability import ReachabilityModelVersion
from tests.contract.reachability_fixture import Fixture


def DefinitionFields(fixture, critical=("billing", "key"), **changes):
    """Build literal normative owner declarations without deriving expected path or impact states.

    Args:
        fixture: Existing independent symbolic graph producer.
        critical: Explicit symbolic ordinary Asset membership, not inferred graph destinations.
        changes: Deliberate original-source field overrides.

    Returns:
        Detached strict profile-one JSON envelope.
    """

    return {"profile_version": 1, "workspace_id": fixture.model.workspace_id,
        "definition_key": "billing-service-disruption", "definition_version": "2026.1",
        "owner_reference": "owner:synthetic-billing", "title": "Billing service disruption",
        "unacceptable_outcome": "Owner-declared loss of billing service availability",
        "declared_at": "2026-10-13T00:00:00Z",
        "critical_asset_references": [fixture.objects[alias].Reference() for alias in critical],
        **changes}


def Acquire(fixture, fields=None, *, raw=None, role="business-event-definition",
            media_type="application/json", **provenance_changes):
    """Retain original definition bytes through the actual existing evidence owner.

    Args:
        fixture: Existing isolated owned model/evidence workspace.
        fields: Explicit declaration JSON; defaults to two handwritten critical Assets.
        raw: Optional exact hostile source bytes, bypassing fixture canonical serialization.
        role: Deliberate original evidence-role override.
        media_type: Deliberate original media-type override.
        provenance_changes: Deliberate original acquisition attribution overrides.

    Returns:
        Existing owner's original immutable evidence manifest.
    """

    if raw is None:
        raw = CanonicalModelJson(DefinitionFields(fixture) if fields is None else fields)

    fields = {"workspace_id": fixture.model.workspace_id,
        "scope_reference": fixture.graph["scope_reference"], "source_id": "synthetic-outcome-owner",
        "source_version": "1", "tool_version": "owner-definition-1",
        "started_at": "2026-10-13T00:00:00Z", "finished_at": "2026-10-13T00:00:00Z",
        **provenance_changes}

    return LocalEvidenceStore(fixture.root / "evidence").Put(raw, role, media_type,
                                                           EvidenceProvenance(**fields))


def Read(fixture, record):
    """Invoke the actual source reader with an independently persisted exact model pin.

    Args:
        fixture: Exact current reopened owning graph/model fixture.
        record: Original definition manifest.

    Returns:
        Production owning-read definition output.
    """

    return ReadBusinessEventDefinition(fixture.model, record, workspace_root=fixture.root,
        expected_model_version=ReachabilityModelVersion(**fixture.Version()),
        scope_reference=fixture.graph["scope_reference"])


def Persist(fixture, record):
    """Apply, CAS-save and reopen a declaration using the existing public model owner.

    Args:
        fixture: Existing current persisted technical model, updated only after successful save.
        record: Original definition manifest.

    Returns:
        Fresh owning-read output against the reopened augmented model.
    """

    definition = Read(fixture, record)
    changed, _ = ApplyBusinessEvent(definition, fixture.model)
    store = LocalModelStore(fixture.root)
    store.Save(changed, expected_revision=fixture.model.revision)
    fixture.model = store.Open()

    return Read(fixture, record)


def Create(root, **fields):
    """Create real independent technical state and acquire a versioned owner-definition source.

    Args:
        root: Explicit isolated synthetic test workspace.
        fields: Deliberate declaration-field overrides before acquisition.

    Returns:
        Independent graph fixture and immutable original source record.
    """

    fixture = Fixture.Create(root)
    record = Acquire(fixture, DefinitionFields(fixture, **fields))

    return fixture, record
