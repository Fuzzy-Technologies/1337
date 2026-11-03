# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent original-choice policy oracles without license-list or legal conclusions."""

from __future__ import annotations

import pytest

from fuzzy1337.cyclonedx_license_policy import (
    EvaluateVerifiedCycloneDxLicenses,
    LicenseChoice,
)
from fuzzy1337.license_policy import LicensePolicy


def Policy():
    """Declare explicit synthetic exact-atom preferences rather than a default license decision."""

    return LicensePolicy("owned-review", ("MIT", "GPL-2.0-only WITH Classpath-exception-2.0"),
                         ("GPL-2.0-only", "Apache-2.0"))


@pytest.mark.parametrize("choice,status,reason", [
    ({"expression": "MIT OR Apache-2.0"}, "allow", "explicit-policy"),
    ({"expression": "MIT AND Apache-2.0"}, "deny", "explicit-policy"),
    ({"expression": "MIT AND Unknown"}, "unknown", "unconfigured-atoms"),
    ({"expression": "MIT OR ("}, "unknown", "unsupported-expression"),
    ({"expression": "LicenseRef-Owned"}, "unknown", "unsupported-expression"),
    ({"expression": "MIT\tOR Apache-2.0"}, "unknown", "unsupported-expression"),
    ({"license": {"id": "mit"}}, "allow", "explicit-policy"),
    ({"license": {"id": "Apache-2.0"}}, "deny", "explicit-policy"),
    ({"license": {"id": "Unconfigured"}}, "unknown", "unconfigured-atoms"),
    ({"license": {"id": "MIT OR Apache-2.0"}}, "unknown", "unsupported-license-identifier"),
    ({"license": {"id": "(MIT)"}}, "unknown", "unsupported-license-identifier"),
    ({"license": {"id": "GPL-2.0-only WITH Classpath-exception-2.0"}}, "unknown",
     "unsupported-license-identifier"),
    ({"license": {"id": "MIT+"}}, "unknown", "unconfigured-atoms"),
    ({"license": {"id": "NOASSERTION"}}, "unknown", "unsupported-license-identifier"),
    ({"expression": "MIT", "acknowledgement": "declared"}, "unknown",
     "unsupported-license-choice"),
    ({"license": {"id": "MIT", "name": "uninterpreted"}}, "unknown",
     "unsupported-license-choice"),
    ({"license": {"id": "MIT"}, "properties": []}, "unknown", "unsupported-license-choice"),
])
def test_OriginalSourceKindAndEveryUnknownRemainSeparate(choice, status, reason):
    """An ID is one atom; expressions consume all syntax and extra fields are unsupported."""

    result = LicenseChoice(choice, Policy())
    assert result["evaluation"]["status"] == status and result["evaluation"]["reason"] == reason, (
        "Independent original-choice oracle disagrees with explicit syntax-policy semantics."
    )
    source_field = "expression" if "expression" in choice else "license.id"
    original_text = choice["expression"] if "expression" in choice else choice["license"]["id"]
    assert result["source_field"] == source_field and result["source_text"] == original_text, (
        "Original source field or exact expression spelling was lost."
    )
    assert result["source_role"] == "not-classified", "Source statements gained an invented role."


def test_ExceptionAndVersionAtomsKeepTheExistingMatcherProfile():
    """A complete exception pair is distinct from its base atom, plus and later-version names."""

    result = LicenseChoice({"expression": "GPL-2.0-only WITH Classpath-exception-2.0"}, Policy())
    assert result["evaluation"] == {"status": "allow", "reason": "explicit-policy", "atoms": [
        {"atom": "gpl-2.0-only WITH classpath-exception-2.0", "status": "allow"},
    ]}, "The existing exact exception-pair policy decision changed."
    result = LicenseChoice({"expression": "MIT+ OR GPL-2.0-or-later"}, Policy())
    assert result["evaluation"] == {"status": "unknown", "reason": "unconfigured-atoms",
        "atoms": [{"atom": "gpl-2.0-or-later", "status": "unknown"},
                  {"atom": "mit+", "status": "unknown"}]}, (
        "A version or plus spelling inherited another atom's configured decision."
    )


def test_EntryPointRequiresExistingExactTypesBeforeReading(monkeypatch):
    """Implicit inputs cannot trigger workspace or evidence reads before validation."""

    from fuzzy1337 import cyclonedx_license_policy as projection

    def Refuse(*args, **kwargs):
        """Trip on evidence access from a malformed typed entry point."""

        raise AssertionError("Invalid policy inputs reached evidence verification.")

    monkeypatch.setattr(projection, "VerifyRecords", Refuse)
    values = {name: None for name in ("state", "record", "provenance", "image_identity", "policy")}

    with pytest.raises(ValueError, match="invalid-cyclonedx-license-policy-input"):
        EvaluateVerifiedCycloneDxLicenses(**values, workspace_root=None)
