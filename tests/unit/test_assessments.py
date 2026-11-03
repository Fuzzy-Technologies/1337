# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise the real pinned UFS library through the pure numeric severity adapter."""

import json
import math
from dataclasses import FrozenInstanceError
from importlib.metadata import version

import pytest
from fuzzyroutines import CreateUniversalFuzzyScale, UniversalFuzzyScalePolicy

from fuzzy1337.assessments import (
    FUZZYROUTINES_VERSION,
    RULE_PROFILE,
    SCALE_PROFILE,
    InterpretSeverity,
)


@pytest.mark.parametrize(
    ("score", "level", "label"),
    [(0, "very_low", "Very low"), (1.25, "very_low", "Very low"),
     (2.3, "low", "Low"), (5.0, "medium", "Medium"),
     (7.0, "high", "High"), (10.0, "very_high", "Very high")],
)
def test_KnownPresetAnchorsRetainNumericInputAndLinguisticMeaning(score, level, label):
    """Known plateau/endpoints keep the original base score and all five grades."""

    interpreted = InterpretSeverity(score)
    document = interpreted.ToDict()

    assert interpreted.status == "interpreted", "A numeric source score became unknown"
    assert interpreted.input_value == score, "Interpretation replaced the source number"
    assert interpreted.normalized_value == score / 10, "Normalization changed from divide by ten"
    assert interpreted.selected_level == level, "Released UFS known-answer level changed"
    assert interpreted.label == label, "Human scale label changed"
    assert len(interpreted.memberships) == 5, "A level disappeared from the full grade trace"
    assert document["input_unit"] == "CVSS base score (0..10)", "Input units became ambiguous"
    assert "not exploitation probabilities" in document["meaning"], "Meaning warning disappeared"
    assert json.loads(json.dumps(document, allow_nan=False)) == document, (
        "Output is not strict JSON"
    )


def test_RealLibraryOutputsAreRetainedWithoutReweightingOrProbabilityNormalization():
    """The adapter delegates every grade and selection to the installed public preset API."""

    scale = CreateUniversalFuzzyScale()
    policy = UniversalFuzzyScalePolicy()

    for score in (0, 1.7, 2.3, 3.7, 4.0, 5.0, 6.3, 7.7, 8.0, 8.6, 9.5, 10):
        actual = InterpretSeverity(score)
        expected = scale.Fuzzify(score / 10, policy)

        assert tuple((item.library_term, item.grade) for item in actual.memberships) == tuple(
            (item.term.name, float(item.grade)) for item in expected.memberships
        ), "Memberships were recreated, rounded, normalized or reordered"
        assert actual.maximum_membership == expected.confidence, "Maximum grade lost precision"
        assert actual.memberships[
            [item.library_term for item in actual.memberships].index(expected.selectedTerms[0].name)
        ].level == actual.selected_level, "Adapter did not retain the library's selected term"

    overlapping = InterpretSeverity(3.7)
    grades = {item.level: item.grade for item in overlapping.memberships}

    assert grades["low"] == pytest.approx(0.5), "Low overlap was collapsed to a rigid interval"
    assert grades["medium"] == pytest.approx(0.5), "Medium overlap was lost"
    assert 0 < grades["very_low"] < 0.001, "Historical positive Min tail was discarded"
    assert sum(grades.values()) > 1, "UFS grades were falsely normalized into probabilities"
    assert InterpretSeverity(1.7).maximum_membership < 0.003, "Weak source coverage was inflated"


def test_MissingInputRemainsUnknownWithNoInventedNumericGrades():
    """Unknown source data never becomes zero severity or fabricated membership evidence."""

    actual = InterpretSeverity(None)
    document = actual.ToDict()

    assert actual.status == "unknown" and actual.label == "Unknown", "Missing data got a level"
    assert actual.input_value is actual.normalized_value is actual.selected_level is None, (
        "Missing source data was silently coerced to a numeric assessment"
    )
    assert actual.maximum_membership is None, "Unknown data gained a maximum grade"
    assert len(actual.memberships) == 5 and all(
        item.grade is None for item in actual.memberships
    ), (
        "Unknown levels were presented as measured zero grades"
    )
    assert document["memberships"][0]["grade"] is None, "Serialization replaced unknown with zero"
    assert InterpretSeverity(0).selected_level == "very_low", "Measured zero became missing"


@pytest.mark.parametrize(
    "value", [True, False, "5.0", [], {}, object(), -0.1, 10.1, float("nan"),
              float("inf"), -float("inf"), 10 ** 1000],
)
def test_InvalidInputsRefuseWithoutClampingOrCoercion(value):
    """Invalid caller values cannot be converted into a reassuring interpretation."""

    with pytest.raises(ValueError, match="CVSS base score must be a finite number"):
        InterpretSeverity(value)


def test_VersionedOutputIsImmutableDetachedAndReproducible():
    """Output names its actual dependency and scale/rule profiles without mutable grade storage."""

    first = InterpretSeverity(8.0)
    same = InterpretSeverity(8.0)
    document = first.ToDict()

    assert first == same and first.ToDict() == same.ToDict(), "Identical inputs became unstable"
    assert first.library_version == version("fuzzyroutines") == FUZZYROUTINES_VERSION == "2.1.0", (
        "Assessment metadata is disconnected from the pinned installed library"
    )
    assert first.scale_profile == SCALE_PROFILE and first.rule_profile == RULE_PROFILE, (
        "Reproducibility profile identifiers changed"
    )
    assert document["selection_policy"] == {
        "tie_policy": "last", "tie_tolerance": 0.0, "minimum_membership": 0.0,
    }, "Historic exact-maximum selection was not retained"

    with pytest.raises(FrozenInstanceError):
        first.label = "Changed"

    with pytest.raises(FrozenInstanceError):
        first.memberships[0].grade = 0.0

    document["memberships"][0]["grade"] = 0.99

    assert first.memberships[0].grade != 0.99, "Detached output mutated retained grade evidence"
    assert all(math.isfinite(item.grade) for item in first.memberships), "Grade is not finite"
