# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise local CWE admission and complete fixed-notice identity without external inputs."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from fuzzy1337.intel_references import CanonicalReferenceJson
from fuzzy1337.intelligence_cwe_acquisition import (
    AcquireLocalCweSelection,
    BoundedEncode,
    CweLocalRequest,
    CweLocalSource,
    DecodeSelection,
    DecodeSource,
    JsonObject,
)
from fuzzy1337.intelligence_cwe_notice import CweNoticeBundle


@pytest.mark.parametrize("field,value", [
    ("catalog_version", None), ("catalog_version", 5.0), ("catalog_version", "latest"),
    ("expected_sha256", None), ("expected_sha256", "A" * 64), ("expected_sha256", "a" * 63),
    ("notice_profile", None), ("notice_profile", "unknown"),
])
def test_SourceRefusesUnboundedOrUnknownDeclarations(field, value):
    """Only exact closed catalog and captured notice identities can reach owning stores."""

    with pytest.raises(ValueError):
        replace(CweLocalSource("5.0", "a" * 64), **{field: value})


@pytest.mark.parametrize("field,value", [
    ("source", {}), ("payload", bytearray(b"owned")), ("payload", None),
    ("requested_ids", []), ("requested_ids", ()), ("requested_ids", ("CVE-2024-3094",)),
    ("requested_ids", ("CWE-9", "CWE-1")), ("requested_ids", ("CWE-1",) * 65),
    ("max_bytes", True), ("max_bytes", 0), ("max_bytes", 4194305),
])
def test_RequestRefusesAliasesAndRaisedLimits(field, value):
    """Request input types and canonical selection are validated before work or publication."""

    request = CweLocalRequest(CweLocalSource("5.0", "a" * 64), b"owned", ("CWE-79",))

    with pytest.raises(ValueError):
        replace(request, **{field: value})


def test_CompleteNoticeContainsExactCapturedTextAndDetachedProvenance():
    """Every copyright, license and disclaimer survives a value-detached fixed bundle."""

    bundle = CweNoticeBundle()
    text = bundle["text"]
    assert len(text.encode()) == 4329, "Captured notice content changed"
    assert hashlib.sha256(text.encode()).hexdigest() == (
        "d1595d0a2bc408587d9d3ba24974e381547400772693635d4b340f225e068c2f"
    ), "Captured notice content changed"
    assert "Copyright © 2006–2026, The MITRE Corporation." in text, (
        "Captured notice footer changed"
    )
    assert "DISCLAIMERS" in text and "Any copy you make" in text, "Captured notice content changed"
    assert bundle["legal_rights"] == bundle["publisher_authentication"] == "not-assessed", (
        "Captured bytes acquired an unsupported legal or authentication assessment"
    )
    assert len(CanonicalReferenceJson(bundle)) <= 16 * 1024, "Captured notice content changed"
    bundle["provenance"]["raw_html"]["sha256"] = "changed"
    assert CweNoticeBundle()["provenance"]["raw_html"]["sha256"] == (
        "c572b605b5753cd67b84d12fc64e9ccbfcde0188cf1332118be04c9996a92c45"
    ), "Captured notice content changed"


@pytest.mark.parametrize("value", [None, [], {"catalog_version": "5.0"}])
def test_DecodeSourceCannotAcceptMissingOrUntypedNotice(value):
    """A source label cannot substitute for captured notice contents and exact provenance."""

    with pytest.raises(ValueError):
        DecodeSource(value)


@pytest.mark.parametrize("payload", [b"{" + b'"x":[' * 80 + b"0" + b"]}" * 80,
    b'{"x":' + b"[" * 10000 + b"0" + b"]" * 10000 + b"}"])
def test_DeepJsonRefusesBeforeRecursiveReconstruction(payload):
    """Malformed or over-depth JSON fails as a profile refusal rather than recursion overflow."""

    with pytest.raises(ValueError):
        JsonObject(payload, 2 * 1024 * 1024)


def test_PublicRequestAndBoundedEncoderRefuseBeforeUnknownOwners(tmp_path):
    """Invalid typed requests and serializer overflow cannot silently enter publishing stores."""

    with pytest.raises(ValueError):
        AcquireLocalCweSelection(tmp_path, {}, scope_reference="scope:owned")

    with pytest.raises(ValueError):
        BoundedEncode({"source": "x" * 100}, 20)

    assert BoundedEncode({"a": 1}, 7) == b'{"a":1}', "Captured notice content changed"


@pytest.mark.parametrize("key", [
    "requested_ids", "records", "unsupported_entries", "unmatched_ids",
])
def test_SelectionArraysAreBoundedBeforeTupleCopy(key):
    """A small JSON envelope cannot smuggle a huge count into immutable DTO construction."""

    document = {"requested_ids": [], "records": [], "unsupported_entries": [], "unmatched_ids": []}
    document[key] = [None] * 65

    with pytest.raises(ValueError):
        DecodeSelection(document)
