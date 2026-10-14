# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent target/configuration and status-only capability bounds for proxy regressions."""

from __future__ import annotations

from fuzzy1337.adapters.native_http import NativeHttpAdapter
from tests.proxy_regression_helpers import Oracle


def test_HandwrittenProxyOracleDeclaresExactCasesWithoutInventedScannerCapabilities():
    """Finite independent source expectations retain original native.http SAFE-only semantics."""

    oracle = Oracle()
    assert oracle["schema_version"] == 1 and oracle["configuration"] == {
        "bind_address": "127.0.0.1", "transport": "plaintext-http", "method": "GET",
        "backend_route": "/owned-resource", "redirect_route": "/never-followed",
        "backend_status": 200, "scanner_provider": "native.http", "scanner_profile_version": "1",
        "scanner_capability": "http.endpoint-discovery", "scanner_impact": "SAFE",
        "findings": 0, "related_to_relations": 0, "backend_product_objects": 0}, (
        "Proxy profile changed its explicit finite first-party transport/capability boundary"
    )
    assert [(case["id"], case["frontend_status"], case["backend_hits"], case["exit_code"])
        for case in oracle["cases"]] == [
        ("transparent", 200, ["/owned-resource"], 0), ("blocked", 403, [], 0),
        ("redirect", 302, [], 0), ("rewritten", 429, ["/owned-resource"], 0),
        ("timeout", None, [], 4)], "Independent handwritten proxy/source oracle changed"
    descriptor = NativeHttpAdapter(lambda reference: b"").Descriptor
    assert descriptor.adapter_id == "native.http" and descriptor.version == "1" and (
        descriptor.capabilities == ("http.endpoint-discovery",)
        and descriptor.maximum_impact.name == "SAFE"
    ), "Regression added scanner transport or WAF capability instead of testing existing discovery"
