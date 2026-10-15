# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent target/configuration and status-only capability bounds for proxy regressions."""

from __future__ import annotations

from fuzzy1337.adapters.native_http import NativeHttpAdapter
from tests.proxy_regression_helpers import TLS_FATAL_ALERT, Oracle, TlsOracle


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


def test_TlsOracleDeclaresNegotiationFailuresWithoutCertificateOrTrustClaims():
    """The finite first-party wire profile makes no successful TLS/certificate assertion."""

    oracle = TlsOracle()
    assert oracle["schema_version"] == 1 and oracle["configuration"] == {
        "bind_address": "127.0.0.1", "fatal_alert_hex": "15030300020228",
        "maximum_clienthello_record_bytes": 16384, "request_timeout_seconds": 2.0,
        "accept_timeout_seconds": 0.05, "clienthello_deadline_seconds": 3,
        "read_poll_seconds": 0.1,
        "stall_release_timeout_seconds": 5, "listener_backlog": 4,
        "successful_tls_handshakes": 0, "tls_http_requests": 0,
        "certificate_coverage": "not-assessed", "trust_configuration_changes": False,
        "redirect_route": "/never-followed", "findings": 0, "related_to_relations": 0,
    }, "TLS fixture changed its finite wire/configuration boundary or claimed certificate coverage"
    assert TLS_FATAL_ALERT.hex() == oracle["configuration"]["fatal_alert_hex"], (
        "Actual fatal handshake_failure alert differs from the handwritten source oracle"
    )
    assert [(case["id"], case["tls_connections"], case["worker_error"], case["failure_code"])
        for case in oracle["cases"]] == [
        ("tls-fatal-alert", 1, "tls", "provider"),
        ("tls-stalled-clienthello", 1, "timeout", "timeout"),
        ("http-to-https-redirect", 0, None, None),
    ], "TLS negotiation cases no longer match the independent source oracle"
