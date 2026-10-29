# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Preserve explicit query-input target truth without expanding current scanner authority."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from fuzzy1337.adapters.nuclei import CanonicalUrl
from fuzzy1337.requests import (
    Endpoint,
    InjectionLocation,
    InjectionPoint,
    RequestTemplate,
    ValueBinding,
)
from fuzzy1337.scope import Target, TargetKind
from tests.web_file_access_helpers import Oracle


def test_FileOracleDeclaresSixCasesWithoutScannerAcceptance():
    """Keep real disclosure, fixed behavior, missing state and documentation decoys distinct."""

    oracle = Oracle()
    assert (oracle["schema_version"], oracle["target_pack"], oracle["target_version"],
            oracle["provenance"]) == (
        1, "first-party.web-file-access", "1", "repository-owned-standard-library",
    ), "The independent target oracle must retain explicit versioned provenance"
    assert [(case["id"], case["expected_private_file_disclosure"]) for case in oracle["cases"]] == [
        ("public-baseline", False), ("private-traversal", True), ("fixed-traversal", False),
        ("fixed-public", False), ("missing-control", False), ("documentation-decoy", False),
    ], "Expected mechanism truth must not be inferred from a scanner or target response"
    assert oracle["configuration"] == {
        "bind_address": "127.0.0.1", "transport": "plaintext-http", "method": "GET",
        "input_location": "query", "input_name": "name", "maximum_request_bytes": 1024,
        "maximum_file_bytes": 256, "request_socket_timeout_seconds": 2, "credentials": False,
        "outbound_requests": 0, "scanner_detection": "not-assessed",
        "nuclei_exact_url_profile": "unsupported-query-input",
    }, "A target pack must not claim unsupported provider execution or detector coverage"


@pytest.mark.parametrize("case", Oracle()["cases"], ids=lambda case: case["id"])
def test_QueryInputRemainsExplicitAndExistingNucleiProfileRefusesIt(case):
    """A typed QUERY coordinate is representable without granting a live request or mutation."""

    supplied = "http://127.0.0.1:43123" + case["route"]
    parsed = urlsplit(supplied)
    assert parse_qs(parsed.query, strict_parsing=True) == {
        "name": [case["expected_behavior"]["input"]],
    }, "The declared input must stay visible as a query parameter, not hidden in an encoded path"
    endpoint = Endpoint("owned-file-access", "http://127.0.0.1:43123", parsed.path)
    point = InjectionPoint(InjectionLocation.QUERY, "name", ValueBinding("file_name"))
    template = RequestTemplate(endpoint, (point,))
    assert template.injection_points[0].Coordinate() == ("query", "name", 0), (
        "Existing structural request contracts must retain the query input coordinate"
    )
    assert "private/canary.txt" not in str(template.ToDict()), (
        "Structural request templates must not embed or resolve the actual mutation payload"
    )

    with pytest.raises(ValueError):
        CanonicalUrl(Target(TargetKind.URL, supplied).value)
