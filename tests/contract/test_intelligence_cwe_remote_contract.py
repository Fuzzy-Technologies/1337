# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Freeze remote-CWE request and custody identities without borrowing local import authority."""

from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, fields, replace

import pytest

from fuzzy1337 import intelligence_cwe_remote as remote
from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord
from fuzzy1337.intel_references import CanonicalReferenceJson
from fuzzy1337.intelligence_cwe_acquisition import CweLocalRequest, CweLocalSource
from fuzzy1337.workspace import EvidenceReference


def test_RemoteRequestHasNoPayloadUrlHeaderCallbackOrImplicitSelection():
    """The new typed family exposes only fixed source, explicit IDs and finite limits."""

    assert [field.name for field in fields(remote.CweHttpsRequest)] == [
        "source", "requested_ids", "max_bytes", "timeout_seconds",
    ], "Remote request admitted another source or executable delivery surface"
    source = remote.CweHttpsSource("5.0", "a" * 64)
    request = remote.CweHttpsRequest(source, ("CWE-79",))

    with pytest.raises(FrozenInstanceError):
        request.max_bytes = 1

    with pytest.raises(ValueError):
        remote.CweHttpsRequest(CweLocalSource("5.0", "a" * 64), ("CWE-79",))

    with pytest.raises(ValueError):
        CweLocalRequest(source, b"owned", ("CWE-79",))


def test_ExactProfileRolesAndIndependentAcknowledgementsStayDistinct():
    """A successful remote artifact cannot impersonate a local source or legacy snapshot."""

    assert remote.IMPORTER_ID == "cwe-https-selected-acquisition", "Importer identity changed"
    assert remote.IMPORTER_VERSION == "1", "Importer version changed"
    assert remote.TRANSPORT_PROFILE == "cwe-https-zip-identity-v1", "Transport profile changed"
    assert {remote.RAW_ROLE, remote.PARTIAL_ROLE, remote.ENVELOPE_ROLE, remote.RECEIPT_ROLE} == {
        "cwe-https-zip-source", "cwe-https-zip-partial", "cwe-https-selected-envelope",
        "cwe-https-selected-acquisition",
    }, "Source custody roles collapsed or changed"
    assert {value.value for value in remote.CweHttpsAcknowledgement} == {
        "not-attempted", "unknown", "confirmed",
    }, "Uncertain publication was conflated with absence or success"
    assert remote.MAX_ZIP_BYTES == 4194304 and remote.MAX_ENVELOPE_BYTES == 2097152, (
        "Profile silently raised original or normalized bounds"
    )
    assert remote.MAX_RECEIPT_BYTES == 65536, "Receipt bound changed"
    assert remote.MAX_NOTICE_BYTES == 16384 and remote.MAX_SOURCE_BYTES == 32768, (
        "Notice/source subdocument bounds changed"
    )


def test_SourceCanonicalIdentityRetainsUnknownLegalAndAuthenticationFacts():
    """Byte identity and fixed full notices never become publisher or legal guarantees."""

    source = remote.CweHttpsSource("4.21", "a" * 64)
    data = source.ToDict()
    assert data["legal_rights"] == data["publisher_authentication"] == (
        data["notice_applicability"]
    ) == "not-assessed", "Unassessed source assurance became a claim"
    assert CanonicalReferenceJson(data) == CanonicalReferenceJson(
        remote.DecodeSource(data).ToDict(),
    ), "Complete fixed source identity changed"


def Envelope():
    """Build source-bound synthetic original custody without filesystem or network work."""

    from fuzzy1337.intelligence_cwe_selection import ParseCweSelection
    from tests.integration.test_intelligence_cwe_remote_persistence import Payload, Request

    request = Request()
    payload = Payload()
    digest = hashlib.sha256(payload).hexdigest()
    raw = EvidenceRecord(EvidenceReference(remote.RAW_ROLE, f"blobs/sha256/{digest}",
        digest, "application/zip", len(payload)),
        EvidenceProvenance("owned", "scope:owned", remote.IMPORTER_ID, "1", None,
                           "2026-11-02T13:00:00Z", "2026-11-02T13:00:01Z"))
    selection = ParseCweSelection(payload, request.requested_ids, catalog_version="5.0")

    return remote.CweHttpsSelection(request.source, raw, selection, 4194304, 15)


@pytest.mark.parametrize("change", [{"source": None}, {"raw": None}, {"selection": None}])
def test_EnvelopeRefusesUntypedOriginalSourceOrSelectedContent(change):
    """Detached mutable or absent objects cannot impersonate exact original custody DTOs."""

    with pytest.raises(ValueError):
        replace(Envelope(), **change)


@pytest.mark.parametrize("field,value", [("role", "cwe-local-zip-source"),
    ("media_type", "text/csv")])
def test_OriginalRemoteRawRoleAndMediaAreMandatory(field, value):
    """Content hashes cannot cross original/local/partial or format domains."""

    envelope = Envelope()

    with pytest.raises(ValueError):
        replace(envelope, raw=replace(envelope.raw,
            reference=replace(envelope.raw.reference, **{field: value})))


@pytest.mark.parametrize("field,value", [("source_id", "cwe-local-selected-acquisition"),
    ("source_version", "2"), ("tool_version", "owned-tool"),
    ("invocation_sha256", "a" * 64),
    ("execution", AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.5))])
def test_RemoteRawRequiresExactImporterWithoutUnrelatedExecutionProvenance(field, value):
    """Rehashed metadata cannot borrow local or external-provider attribution."""

    envelope = Envelope()

    with pytest.raises(ValueError):
        replace(envelope, raw=replace(envelope.raw,
            provenance=replace(envelope.raw.provenance, **{field: value})))


@pytest.mark.parametrize("field,value", [("raw_sha256", "a" * 64), ("raw_size", 1000),
    ("catalog_version", "4.21"), ("max_bytes", 1)])
def test_EnvelopeJoinsExactSourcePinCatalogRawLengthAndEffectiveLimit(field, value):
    """A valid individual source or DTO cannot disagree with original-byte custody."""

    envelope = Envelope()

    if field == "catalog_version":
        change = {"source": replace(envelope.source, catalog_version=value)}

    elif field == "max_bytes":
        change = {field: value}

    else:
        change = {"selection": replace(envelope.selection, **{field: value})}

    with pytest.raises(ValueError):
        replace(envelope, **change)


def test_EnvelopeReferenceIncludesExactCanonicalLimitsTransportAndCompleteOriginalManifest():
    """Both source identity and effective execution bounds participate in outer custody identity."""

    envelope = Envelope()
    assert type(envelope.timeout_seconds) is float, "Envelope timeout was not canonicalized"
    assert envelope.Reference() == "cwe-https-selection:" + hashlib.sha256(
        CanonicalReferenceJson(envelope.ToDict()),
    ).hexdigest(), "Remote envelope omitted identity fields"
    assert replace(envelope, timeout_seconds=16).Reference() != envelope.Reference(), (
        "Remote CWE custody invariant changed"
    )
    assert replace(envelope, max_bytes=4194303).Reference() != envelope.Reference(), (
        "Remote CWE custody invariant changed"
    )
