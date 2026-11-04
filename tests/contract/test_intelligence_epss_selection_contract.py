# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Keep pure selected EPSS identity distinct from legacy stored snapshot contracts."""

from __future__ import annotations

import gzip
import hashlib

from fuzzy1337.intel_references import CanonicalReferenceJson
from fuzzy1337.intelligence import INTELLIGENCE_SCHEMA_VERSION, MAX_SOURCE_BYTES
from fuzzy1337.intelligence_acquisition import (
    ACQUISITION_SCHEMA_VERSION,
    CisaKevSource,
    SnapshotRequest,
)
from fuzzy1337.intelligence_epss_selection import ParseEpssSelection


def test_ProfileIdentityBindsSelectionAndExactRawBytesWithoutLegacyAdmissionChanges():
    """A separate family cannot impersonate schema-one normalized or acquisition evidence."""

    raw = (b"#model_version:synthetic-1,score_date:2026-11-02T12:00:30Z\n"
           b"cve,epss,percentile\nCVE-1900-0001,0.100,0.2\n")
    source = gzip.compress(raw, mtime=0)
    result = ParseEpssSelection(source, ["CVE-1900-0001", "CVE-1900-9999"],
                                model_version="synthetic-1", score_date="2026-11-02")
    document = result.ToDict()
    assert document["schema_version"] == 2 and document["profile_version"] == 1, "Profile changed"
    assert document["matched_ids"] == ["CVE-1900-0001"], "Selected match disappeared"
    assert document["unmatched_ids"] == ["CVE-1900-9999"], "Unknown acquired a zero score"
    assert document["limits"] == {"compressed_bytes": 4 * 1024 * 1024,
        "decoded_bytes": 16 * 1024 * 1024, "csv_rows": 500_000, "requested_ids": 64,
        "absolute_decimal_exponent": 32}, (
        "Fixed profile resource budgets changed"
    )
    assert result.Reference() == "epss-selection:" + hashlib.sha256(
        CanonicalReferenceJson(document),
    ).hexdigest(), "Profile identity omitted canonical source or selection content"
    alteredSelection = ParseEpssSelection(source, ["CVE-1900-0001"],
        model_version="synthetic-1", score_date="2026-11-02")
    alteredRaw = ParseEpssSelection(gzip.compress(raw, mtime=1), result.requested_ids,
        model_version="synthetic-1", score_date="2026-11-02")
    assert result.Reference() != alteredSelection.Reference() != alteredRaw.Reference(), (
        "Source or selection changes reused a profile reference"
    )
    assert INTELLIGENCE_SCHEMA_VERSION == ACQUISITION_SCHEMA_VERSION == 1, "Legacy schemas changed"
    assert MAX_SOURCE_BYTES == 16 * 1024 * 1024, "Shared source ceiling changed"
    request = SnapshotRequest(CisaKevSource("a" * 40, "synthetic-1"))
    assert request.source.feed.value == "cisa-kev-json", "Existing CISA admission changed"
