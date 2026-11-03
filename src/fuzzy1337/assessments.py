# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure five-level interpretation of explicit numeric CVSS base scores using FuzzyRoutines."""

from __future__ import annotations

import math
from dataclasses import dataclass
from importlib.metadata import version
from typing import Literal

from fuzzyroutines import CreateUniversalFuzzyScale, UniversalFuzzyScalePolicy

SeverityLevel = Literal["very_low", "low", "medium", "high", "very_high"]
ASSESSMENT_SCHEMA_VERSION = 1
SCALE_PROFILE = "fuzzyroutines-universal-fuzzy-scale-v1"
RULE_PROFILE = "cvss-base-divide-by-ten-ufs-last-exact-maximum-v1"
FUZZYROUTINES_VERSION = version("fuzzyroutines")
INPUT_UNIT = "CVSS base score (0..10)"
_LEVELS: tuple[tuple[SeverityLevel, str, str], ...] = (
    ("very_low", "Very low", "Min"),
    ("low", "Low", "Low"),
    ("medium", "Medium", "Med"),
    ("high", "High", "High"),
    ("very_high", "Very high", "Max"),
)


@dataclass(frozen=True, slots=True)
class SeverityMembership:
    """Retain a UFS term's membership without interpreting the grade as probability."""

    level: SeverityLevel
    label: str
    library_term: str
    grade: float | None

    def ToDict(self) -> dict[str, object]:
        """Return detached presentation fields, retaining unknown grades as null.

        Returns:
            One level's original library term, human label and membership grade.
        """

        return {
            "level": self.level, "label": self.label,
            "library_term": self.library_term, "grade": self.grade,
        }


@dataclass(frozen=True, slots=True)
class SeverityInterpretation:
    """Carry an immutable linguistic presentation separate from the source assessment."""

    status: Literal["interpreted", "unknown"]
    input_value: float | None
    normalized_value: float | None
    selected_level: SeverityLevel | None
    label: str
    memberships: tuple[SeverityMembership, ...]
    maximum_membership: float | None
    library_version: str = FUZZYROUTINES_VERSION
    scale_profile: str = SCALE_PROFILE
    rule_profile: str = RULE_PROFILE

    def ToDict(self) -> dict[str, object]:
        """Expose the input, full grade trace and versioned interpretation policy.

        Returns:
            Detached JSON-compatible values without mutation, provenance or risk claims.
        """

        return {
            "schema_version": ASSESSMENT_SCHEMA_VERSION,
            "assessment_kind": "cvss-base-linguistic-severity",
            "status": self.status, "input_value": self.input_value, "input_unit": INPUT_UNIT,
            "normalized_value": self.normalized_value,
            "selected_level": self.selected_level, "label": self.label,
            "memberships": [item.ToDict() for item in self.memberships],
            "maximum_membership": self.maximum_membership,
            "library_name": "fuzzyroutines", "library_version": self.library_version,
            "scale_profile": self.scale_profile, "rule_profile": self.rule_profile,
            "selection_policy": {
                "tie_policy": "last", "tie_tolerance": 0.0, "minimum_membership": 0.0,
            },
            "meaning": "Membership grades are not exploitation probabilities or action priorities.",
        }


def InterpretSeverity(value: float | None) -> SeverityInterpretation:
    """Interpret one explicit CVSS base score through the released library's UFS preset.

    Args:
        value: Finite numeric base score in 0..10, or None for missing source data.

    Returns:
        All five memberships, the library-selected level and reproducibility metadata.
        Missing data has no selected level and no numeric grades.

    Raises:
        ValueError: Input is boolean, nonnumeric, nonfinite or outside 0..10.
    """

    if value is None:
        return SeverityInterpretation(
            "unknown", None, None, None, "Unknown",
            tuple(SeverityMembership(level, label, term, None) for level, label, term in _LEVELS),
            None,
        )

    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError("CVSS base score must be a finite number in 0..10 or None")

    if not 0 <= value <= 10 or not math.isfinite(value):
        raise ValueError("CVSS base score must be a finite number in 0..10 or None")

    score = float(value)
    normalized_value = score / 10.0
    result = CreateUniversalFuzzyScale().Fuzzify(normalized_value, UniversalFuzzyScalePolicy())
    grades = {item.term.name: float(item.grade) for item in result.memberships}
    memberships = tuple(
        SeverityMembership(level, label, term, grades[term]) for level, label, term in _LEVELS
    )
    selected = result.selectedTerms[0].name
    selected_membership = next(item for item in memberships if item.library_term == selected)

    return SeverityInterpretation(
        "interpreted", score, normalized_value, selected_membership.level,
        selected_membership.label, memberships, float(result.confidence),
    )
