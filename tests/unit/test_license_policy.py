# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent expression and caller-policy oracles, with finite hostile-input boundaries."""

from __future__ import annotations

import hashlib

import pytest

from fuzzy1337.license_policy import EvaluateLicenseExpression, LicensePolicy
from fuzzy1337.model import CanonicalModelJson


def Policy():
    """Declare synthetic local preferences without a bundled legal or license-list decision."""

    return LicensePolicy("owned-policy-v1", ("MIT", "Apache-2.0"), ("GPL-2.0-only",))


@pytest.mark.parametrize("expression, expected", [
    ("MIT", "allow"), ("mIt", "allow"), ("GPL-2.0-only", "deny"), ("Unconfigured", "unknown"),
    ("GPL-2.0-only OR MIT", "allow"), ("GPL-2.0-only AND MIT", "deny"),
    ("MIT OR Unconfigured", "allow"), ("MIT AND Unconfigured", "unknown"),
    ("GPL-2.0-only AND Unconfigured", "deny"), ("GPL-2.0-only OR Unconfigured", "unknown"),
    ("MIT OR GPL-2.0-only AND Unconfigured", "allow"),
    ("(MIT OR GPL-2.0-only) AND Unconfigured", "unknown"),
    ("MIT AND(Apache-2.0 OR GPL-2.0-only)", "allow"),
    ("(MIT)OR(GPL-2.0-only)", "allow"),
    ("GPL-2.0-only OR GPL-2.0-only", "deny"),
    ("MIT AND MIT", "allow"), ("UnknownA OR UnknownB", "unknown"),
    ("UnknownA AND UnknownB", "unknown"),
])
def test_ExplicitPolicyUsesThreeValuedOperatorPrecedence(expression, expected):
    """Choice and conjunction preserve unconfigured atoms under the declared finite grammar."""

    result = EvaluateLicenseExpression(expression, Policy())
    assert result["status"] == expected, "The independent truth/precedence oracle must hold"
    assert result["atoms"], "A supported expression must expose every normalized policy atom"


@pytest.mark.parametrize("expression", [
    "", " ", "MIT OR", "AND MIT", "MIT Apache-2.0", "MIT and Apache-2.0",
    "MIT or Apache-2.0", "MIT with Classpath-exception-2.0", "MIT XOR Apache-2.0",
    "MIT +", "MIT++", "(MIT", "MIT)", "()", "MIT OR ()", "(MIT) WITH Exception",
    "MIT WITH", "MIT WITH ", "WITH MIT", "MIT WITH Exception+", "MIT WITH(Exception)",
    "MIT WITH Exception WITH Other", "MIT OR LicenseRef-Owned", "DocumentRef-Owned:LicenseRef-X",
    "licenseref-Owned", "MIT OR NONE", "NOASSERTION", "NONE+", "MIT\nOR Apache-2.0",
    "MIT\tOR Apache-2.0", "MIT\x00", "MIT\x7f", "MIT OR ℳIT", "MIT OR \ud800",
    "MIT OR Unconfigured(", "MIT OR __import__('os')", "MIT OR *", "MIT; anything",
    None, 1, True, ["MIT"], "a" * 129, " " * 2049,
    "(" * 17 + "MIT" + ")" * 17, " OR ".join(["MIT"] * 65),
])
def test_UnsupportedOrOverBudgetTextCannotProduceAPartialAllow(expression):
    """All source tokens are consumed before a result; malformed allowed branches fail unknown."""

    result = EvaluateLicenseExpression(expression, Policy())
    assert result == {"status": "unknown", "reason": "unsupported-expression", "atoms": []}, (
        "Unsupported grammar, references and budgets must withhold every partial decision"
    )


def test_VersionAndExceptionAtomsRequireTheirOwnExplicitPolicyDecision():
    """No base license rule implicitly approves an exception or another version spelling."""

    policy = LicensePolicy("owned", ("GPL-2.0-only WITH Classpath-exception-2.0", "MIT+"),
                           ("GPL-2.0-only",))
    assert EvaluateLicenseExpression("GPL-2.0-only WITH Classpath-exception-2.0", policy)[
        "status"] == "allow", "A caller can decide the complete license/exception atom"

    for expression in ("GPL-2.0-only WITH Bison-exception-2.2", "GPL-2.0-or-later", "MIT"):
        assert EvaluateLicenseExpression(expression, policy)["status"] == "unknown", (
            "Neither exceptions nor later-version identifiers may inherit another atom decision"
        )

    result = EvaluateLicenseExpression("MIT+ OR GPL-2.0-only", policy)
    assert result["status"] == "allow" and result["atoms"] == [
        {"atom": "gpl-2.0-only", "status": "deny"}, {"atom": "mit+", "status": "allow"}
    ], "The adjacent plus suffix is an exact atom, distinct from an identifier without it"


@pytest.mark.parametrize("allowed, denied", [
    ((), ()), (("MIT",), ("mit",)), (("MIT", "mit"), ()),
    (("MIT AND Apache-2.0",), ()), (("(MIT)",), ()), ((" MIT",), ()),
    (("MIT ",), ()), (("LicenseRef-Owned",), ()), (("NONE",), ()),
    ((None,), ()), (("MIT",) * 65, ()), (["MIT"], ()), (("MIT",), ["GPL-2.0-only"]),
])
def test_ConflictingImplicitOrNonAtomicPolicyConfigurationIsRefused(allowed, denied):
    """A policy must be a finite unique explicit atom table, with no ambiguous precedence."""

    with pytest.raises(ValueError, match="invalid-license-policy"):
        LicensePolicy("owned", allowed, denied)


@pytest.mark.parametrize("policy_id", ["", "private marker", "../owned", "x" * 129, None, True])
def test_PolicyIdentityRequiresABoundedNonPathIdentifier(policy_id):
    """Caller descriptions are inert identities rather than path or retrieval instructions."""

    with pytest.raises(ValueError, match="invalid-license-policy"):
        LicensePolicy(policy_id, ("MIT",))


def test_PolicyDigestIsIndependentOfDeclarationOrderAndIdentifierCase():
    """The output identifies every decision and the exact versioned interpretation profile."""

    first = LicensePolicy("owned", ("MIT", "Apache-2.0"), ("GPL-2.0-only",)).Description()
    second = LicensePolicy("owned", ("apache-2.0", "mit"), ("gpl-2.0-ONLY",)).Description()
    assert first == second, "Equivalent explicit policies must have one normalized identity"
    digest = first.pop("sha256")
    assert digest == hashlib.sha256(CanonicalModelJson(first)).hexdigest(), (
        "The digest must commit to the caller ID, profile and both complete normalized atom sets"
    )


def test_SupportedMaximumNestingAndTokenChainRemainBoundedAndComplete():
    """The last supported input still evaluates all unknown atoms rather than truncating them."""

    assert EvaluateLicenseExpression("(" * 16 + "MIT" + ")" * 16, Policy())["status"] == (
        "allow"
    ), "The exact declared parenthesis limit remains supported"
    result = EvaluateLicenseExpression(" AND ".join(["MIT"] * 63 + ["Unconfigured"]), Policy())
    assert result["status"] == "unknown" and len(result["atoms"]) == 2, (
        "The complete maximum supported token chain must retain the last unknown conjunct"
    )


def test_ExpressionEvaluationRequiresAnExplicitTypedPolicy():
    """No accidental mapping or implicit default can become a configured policy."""

    with pytest.raises(ValueError, match="invalid-license-policy"):
        EvaluateLicenseExpression("MIT", {"allowed": ["MIT"]})
