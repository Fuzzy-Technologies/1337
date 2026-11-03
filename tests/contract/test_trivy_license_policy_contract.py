# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite Internal native occurrence surface without an implicit execution or model contract."""

from __future__ import annotations

from fuzzy1337 import trivy_license_policy
from fuzzy1337.model import CanonicalModelJson
from tests.integration.test_trivy_license_policy_persistence import (
    Evaluate,
    Owned,
    Package,
    Payload,
)


def test_OriginalTextAndDetachedResultKeepExistingPolicySemantics(tmp_path):
    """Native strings remain source assertions; no declared/concluded role or aggregate appears."""

    original = "  MIT OR Apache-2.0  "
    result = Evaluate(Owned(tmp_path, Payload([Package([original])])))
    assertion = result["packages"][0]["assertions"][0]
    assert assertion["source_text"] == original and assertion["source_role"] == "not-classified", (
        "Original native license text was normalized or assigned an invented source role."
    )
    assert assertion["evaluation"]["status"] == "allow" and "status" not in result, (
        "A syntax-only occurrence decision became a package/image aggregate verdict."
    )
    assert trivy_license_policy.__all__ == () and result["profile"] == (
        "trivy-0.75-original-license-policy-v1"
    ), "Internal opt-in projection gained a public export or changed its finite profile."
    assert b"declared" not in CanonicalModelJson(result) and b"concluded" not in (
        CanonicalModelJson(result)
    ), "Native occurrence interpretation invented a declared/concluded source role."
