# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Check pure declaration bounds and canonical identity without I/O."""

from __future__ import annotations

import pytest

from fuzzy1337.business_events import Digest, References, Text


@pytest.mark.parametrize("value", [None, False, 1, "", " ", "a\nb", "a\rb", "a\tb", "a\x00b",
                                 "a\x7fb", "\ud800", "é" * 5])
def test_DeclarationTextRejectsMalformedOrOversizedSourceFields(value):
    """Single-line UTF-8 size bounds deny coercion, controls and invalid code points."""

    with pytest.raises(ValueError):
        Text(value, 8)


def test_DeclarationTextPreservesExactNonemptyFieldAtItsInclusiveByteBound():
    """Owner declaration fields retain exact case and spacing."""

    assert Text(" éé ", 6) == " éé ", "Inclusive UTF-8 field bound or exact text changed"


@pytest.mark.parametrize("value", [None, [], (), "object:" + "a" * 64,
    ("object:" + "A" * 64,), ("relation:" + "a" * 64,), (1,),
    ("object:" + "a" * 64,) * 2, tuple("object:" + f"{index:064x}" for index in range(17))])
def test_ExplicitReferenceMembershipRejectsCoercionDuplicatesAndBounds(value):
    """Membership neither iterates arbitrary inputs nor collapses duplicate declarations."""

    with pytest.raises(ValueError):
        References(value)


def test_ReferencesAndSemanticDigestAreDeterministicWithoutMutatingCallerValues():
    """Canonical field ordering preserves original identities and exact case distinctions."""

    refs = ("object:" + "b" * 64, "object:" + "a" * 64)
    assert References(refs) == refs[::-1], "Membership canonical order changed"
    assert refs[0].endswith("b" * 64), "Original immutable membership changed"
    assert Digest({"b": 1, "a": 2}) == Digest({"a": 2, "b": 1}), "Field order entered identity"
    assert Digest({"title": "Owner"}) != Digest({"title": "owner"}), "Exact meaning collapsed"
