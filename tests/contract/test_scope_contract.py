# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent schema-v1 literal identity and fail-closed consent consumer contracts."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest

from fuzzy1337.scope import (
    SCOPE_SCHEMA_VERSION,
    ScopeDecisionReason,
    ScopeSnapshot,
    Target,
    TargetKind,
)


def test_TargetIdentityUsesExactlyCanonicalKindValueJson():
    """Cross-module references hash sorted compact UTF-8 kind/value JSON without a newline."""

    target = Target(TargetKind.DOMAIN, "EXAMPLE.TEST.")
    payload = b'{"kind":"domain","value":"example.test"}'

    assert target.Reference() == "target:" + hashlib.sha256(payload).hexdigest(), (
        "Target identity serialization changed from the declared cross-module contract"
    )
    assert target.Reference() != Target(TargetKind.URL, "http://example.test/").Reference(), (
        "Different explicit namespaces collapsed into one inferred target identity"
    )


def test_ScopeSchemaHasExactPortableFieldsAndExplicitUnknownConsent():
    """The library producer and independent consumer agree on all initial schema fields."""

    target = Target(TargetKind.IP, "192.0.2.1")
    snapshot = ScopeSnapshot("testing", "synthetic", targets=(target,), allow=(target,))
    expected = {
        "schema_version": 1, "scope_id": "testing", "workspace_id": "synthetic", "revision": 0,
        "authorization": {
            "state": "unknown", "authority_reference": None, "record_reference": None,
            "valid_from": None, "valid_until": None,
        },
        "targets": [{"kind": "ip", "value": "192.0.2.1"}],
        "allow": [{"kind": "ip", "value": "192.0.2.1"}], "deny": [], "exclusions": [],
    }

    assert SCOPE_SCHEMA_VERSION == 1, "Initial scope schema version drifted"
    assert snapshot.ToDict() == expected, "Schema producer contains unknown/missing fields"
    decoded = ScopeSnapshot.FromDict(expected)
    decision = decoded.Check(target, at=datetime(2026, 10, 5, tzinfo=timezone.utc))

    assert decoded.Reference() == "scope:testing", "Workspace-local scope identity changed"
    assert decision.reason == ScopeDecisionReason.AUTHORIZATION_UNKNOWN, (
        "Stored target/allow metadata was treated as implicit consent"
    )
    assert not decision.Allowed(), "Unknown consent became allowed membership"

    for unknown_version in (0, 2, "1", True):
        with pytest.raises(ValueError):
            ScopeSnapshot.FromDict({**expected, "schema_version": unknown_version})


def test_StoredTargetIdentityCannotChangeDuringDecode():
    """Noncanonical kind/value spellings are rejected rather than silently acquiring another ID."""

    document = ScopeSnapshot("testing", "synthetic").ToDict()
    document["targets"] = [{"kind": "domain", "value": "EXAMPLE.TEST"}]

    with pytest.raises(ValueError, match="canonical"):
        ScopeSnapshot.FromDict(document)
