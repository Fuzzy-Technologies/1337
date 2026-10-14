# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise the bounded original owner-definition grammar and all attribution joins."""

from __future__ import annotations

from dataclasses import replace

import pytest

from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.business_events import (
    ApplyBusinessEvent,
    DefinitionEvidenceStore,
    ReadBusinessEventDefinition,
)
from fuzzy1337.evidence import EvidenceError
from fuzzy1337.model import LocalModelStore
from fuzzy1337.reachability import ReachabilityModelVersion
from tests.contract.business_event_fixture import Acquire, Create, DefinitionFields, Read


@pytest.mark.parametrize("changes", [
    {"profile_version": True}, {"profile_version": 2}, {"workspace_id": "foreign"},
    {"definition_key": "foreign/key"}, {"definition_key": "é"}, {"definition_key": "x" * 129},
    {"definition_version": ""}, {"owner_reference": ""}, {"title": ""},
    {"unacceptable_outcome": "x" * 4097}, {"declared_at": "2026-10-13T00:00:01Z"},
    {"declared_at": "2026-10-13"}, {"critical_asset_references": []},
    {"critical_asset_references": "object:" + "a" * 64},
    {"critical_asset_references": ["object:" + "a" * 64]}, {"unknown": "ignored"},
])
def test_ExactOriginalDefinitionGrammarFailsClosed(tmp_path, changes):
    """Malformed versions, fields, time and memberships never become model declarations."""

    fixture, _ = Create(tmp_path / "workspace")
    record = Acquire(fixture, DefinitionFields(fixture, **changes))
    before = fixture.model

    with pytest.raises(ValueError):
        Read(fixture, record)

    assert LocalModelStore(fixture.root).Open() == before, "Invalid definition mutated the model"


@pytest.mark.parametrize("raw", [b"{}", b"[]", b"null", b"false", b"{", b"\xff",
    b'{"profile_version":1,"profile_version":1}', b'{"profile_version":NaN}',
    b"[" * 2000 + b"]" * 2000, b" " * (65536 + 1)], ids=[
        "empty-object", "array", "null", "boolean", "malformed-json", "invalid-utf8",
        "duplicate-field", "nonfinite", "excessive-depth", "source-byte-limit",
    ])
def test_OriginalSourceRejectsDuplicatesConstantsEncodingNestingAndOversize(tmp_path, raw):
    """Parser denial preserves the strict source grammar and bounded original evidence read."""

    fixture, _ = Create(tmp_path / "workspace")

    with pytest.raises(ValueError):
        Read(fixture, Acquire(fixture, raw=raw))


@pytest.mark.parametrize("provenance", [
    {"workspace_id": "foreign"}, {"scope_reference": "scope:foreign"}, {"source_version": "2"},
    {"invocation_sha256": "a" * 64},
    {"execution": AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.1)},
])
def test_OriginalAcquisitionAttributionCannotBecomeAnotherOwnerScenario(tmp_path, provenance):
    """Execution receipts and foreign or unsupported attribution are not definitions."""

    fixture, _ = Create(tmp_path / "workspace")

    with pytest.raises(ValueError):
        Read(fixture, Acquire(fixture, **provenance))


@pytest.mark.parametrize("source", [{"role": "stdout"}, {"media_type": "text/plain"}])
def test_OriginalEvidenceRoleAndMediaTypeMustMatchTheProfile(tmp_path, source):
    """Arbitrary original bytes cannot acquire definition authority through content similarity."""

    fixture, _ = Create(tmp_path / "workspace")

    with pytest.raises(ValueError):
        Read(fixture, Acquire(fixture, **source))


def test_DuplicateCriticalMembersAndControlOrForeignObjectsAreRejected(tmp_path):
    """Explicit memberships validate ordinary Assets in the exact owning model."""

    fixture, _ = Create(tmp_path / "workspace")

    for critical in (("billing", "billing"), ("key-control",)):
        with pytest.raises(ValueError):
            Read(fixture, Acquire(fixture, DefinitionFields(fixture, critical=critical)))

    foreign = replace(fixture.objects["billing"].identity, workspace_id="foreign").Reference()

    with pytest.raises(ValueError):
        Read(fixture, Acquire(fixture, DefinitionFields(fixture,
            critical_asset_references=[foreign])))


def test_AlteredSuppliedManifestAndDeletedOriginalRecordsCannotBeReplayed(tmp_path):
    """Record equality and the real original manifest are required even when its blob survives."""

    fixture, record = Create(tmp_path / "workspace")
    altered = replace(record, provenance=replace(record.provenance, source_id="another-owner"))

    with pytest.raises(EvidenceError):
        Read(fixture, altered)

    object.__setattr__(altered, "evidence_id", record.evidence_id)

    with pytest.raises(ValueError):
        Read(fixture, altered)

    path = fixture.root / "evidence" / "records" / (record.evidence_id[7:] + ".json")
    path.unlink()

    with pytest.raises(EvidenceError):
        Read(fixture, record)


def test_ActualParsedManifestSizeIsCheckedBeforeOriginalBlobAllocation(tmp_path):
    """A small forged caller reference cannot conceal the actual oversized owning manifest."""

    fixture, _ = Create(tmp_path / "workspace")
    large = Acquire(fixture, raw=b" " * 65537)
    supplied = replace(large, reference=replace(large.reference, size_bytes=1))
    object.__setattr__(supplied, "evidence_id", large.evidence_id)

    with pytest.raises(ValueError, match="source byte bound"):
        Read(fixture, supplied)

    store = DefinitionEvidenceStore(fixture.root / "evidence")
    forged = replace(large.reference, size_bytes=1)
    object.__setattr__(forged, "size_bytes", True)

    for reference in (None, replace(large.reference, size_bytes=0), forged):
        with pytest.raises(ValueError):
            store.Read(reference)


def test_ExactlyBoundedWhitespaceAndRawIntegrityRemainOwnedByTheEvidenceStore(tmp_path):
    """Inclusive 64 KiB grammar is accepted; corrupt original bytes are never imported."""

    fixture, record = Create(tmp_path / "workspace")
    store = DefinitionEvidenceStore(fixture.root / "evidence")
    raw = store.Read(record.reference)
    exact = Acquire(fixture, raw=raw + b" " * (65536 - len(raw)))
    assert Read(fixture, exact).critical_asset_references, "Inclusive source-byte bound was denied"
    blob = fixture.root / "evidence" / record.reference.locator
    blob.write_bytes(b"corrupt original definition")

    with pytest.raises(EvidenceError):
        Read(fixture, record)


def test_CompleteModelPinAndOriginalAttributionGuardTypedCopies(tmp_path):
    """Typed outputs cannot be rebound to another owner, source field, membership or basis."""

    fixture, record = Create(tmp_path / "workspace")
    definition = Read(fixture, record)

    for changes in ({"owner_reference": "owner:foreign"}, {"unacceptable_outcome": "Forged"},
        {"critical_asset_references": (fixture.objects["isolated"].Reference(),)},
        {"record": replace(record, provenance=replace(record.provenance, source_id="foreign"))},
        {"_seal": object()}, {"definition_reference": "business-event:" + "a" * 64}):
        with pytest.raises(ValueError):
            ApplyBusinessEvent(replace(definition, **changes), fixture.model)

    changed, _ = fixture.model.Apply(objects=(replace(fixture.objects["billing"],
                                                     attributes={"owner_change": True}),))

    with pytest.raises(ValueError):
        ApplyBusinessEvent(definition, changed)

    LocalModelStore(fixture.root).Save(changed, expected_revision=fixture.model.revision)

    with pytest.raises(ValueError):
        Read(fixture, record)


def test_UntypedInputsAndWrongSelectedPinsAreRejected(tmp_path):
    """Public runtime boundaries refuse ad-hoc source records and basis coercion."""

    fixture, record = Create(tmp_path / "workspace")
    version = ReachabilityModelVersion.FromModel(fixture.model)

    for model, source, pin in ((fixture.model, None, version), (fixture.model, record, None),
        (None, record, version),
        (fixture.model, record, replace(version, snapshot_sha256="a" * 64))):
        with pytest.raises(ValueError):
            ReadBusinessEventDefinition(model, source, workspace_root=fixture.root,
                expected_model_version=pin, scope_reference=fixture.graph["scope_reference"])

    with pytest.raises(ValueError):
        ApplyBusinessEvent(None, fixture.model)
