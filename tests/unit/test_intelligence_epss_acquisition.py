# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify explicit local EPSS source declarations and profile admission bounds."""

from __future__ import annotations

from dataclasses import replace

import pytest

from fuzzy1337.intel_references import SourceOrigin
from fuzzy1337.intelligence_epss_acquisition import EpssLocalRequest, EpssLocalSource


def Source() -> EpssLocalSource:
    """Declare synthetic local source facts without official attribution or network admission."""

    return EpssLocalSource(SourceOrigin.SYNTHETIC, "Owned EPSS fixture",
        "https://example.invalid/synthetic.csv.gz", "Synthetic Apache-2.0 fixture",
        "https://example.invalid/LICENSE", ("https://example.invalid/terms",),
        "synthetic-model", "2026-11-02")


@pytest.mark.parametrize("field,value", [
    ("origin", "synthetic"), ("publisher", ""), ("publisher", " secret "),
    ("source_url", "https://example.invalid/source?cve=CVE-1900-0001"),
    ("source_url", "http://example.invalid/source"), ("license_url", "file:///tmp/license"),
    ("license_name", ""), ("terms_urls", []), ("terms_urls", ()),
    ("terms_urls", ("https://example.invalid/terms",) * 2),
    ("terms_urls", ("https://example.invalid/z", "https://example.invalid/a")),
    ("terms_urls", ("http://example.invalid/terms",)),
    ("terms_urls", tuple(f"https://example.invalid/{i}" for i in range(5))),
    ("model_version", ""), ("score_date", "2026-02-30"), ("expected_sha256", "F" * 64),
])
def test_SourceDeclarationCannotInventImplicitAttributionOrBroadenAdmission(field, value):
    """Metadata remains explicit, immutable and bounded with no arbitrary remote selection."""

    with pytest.raises(ValueError):
        replace(Source(), **{field: value})


@pytest.mark.parametrize("field,value", [
    ("source", None), ("payload", None), ("payload", bytearray(b"source")),
    ("requested_ids", ["CVE-1900-0001"]), ("requested_ids", ()),
    ("requested_ids", ("CVE-1900-0002", "CVE-1900-0001")),
    ("max_bytes", True), ("max_bytes", 0), ("max_bytes", 4 * 1024 * 1024 + 1),
])
def test_LocalRequestRefusesMutableSelectionsImplicitBytesAndRaisedBudgets(field, value):
    """A local request is never treated as a remote lookup or a full-corpus selection."""

    request = EpssLocalRequest(Source(), b"owned", ("CVE-1900-0001",))

    with pytest.raises(ValueError):
        replace(request, **{field: value})


def test_SourcePresentationIsDetachedAndPreservesSeparateTerms():
    """Primary license attribution and additional service terms remain distinct declared facts."""

    source = replace(Source(), expected_sha256="a" * 64)
    document = source.ToDict()
    document["terms_urls"].append("https://example.invalid/changed")
    assert source.terms_urls == ("https://example.invalid/terms",), "Source terms became mutable"
    assert source.expected_sha256 == "a" * 64, "Caller byte pin changed"
