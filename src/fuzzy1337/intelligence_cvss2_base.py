# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Derive immutable CVSS 2 base scores separately from unchanged source assertions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import cast

from fuzzy1337.intelligence_cvss2 import CveCvss2Assessment, CveCvss2Statements

__all__ = ("CveCvss2BaseCalculations",)

_AV = MappingProxyType({"L": 395, "A": 646, "N": 1000})
_AC = MappingProxyType({"H": 350, "M": 610, "L": 710})
_AU = MappingProxyType({"M": 450, "S": 560, "N": 704})
_IMPACT = MappingProxyType({"N": 0, "P": 275, "C": 660})
_WEIGHT_SCALE = 1000
_PRODUCT_DENOMINATOR = _WEIGHT_SCALE ** 3
_IMPACT_DENOMINATOR = 100 * _PRODUCT_DENOMINATOR


def BaseScoreTenths(assessment: CveCvss2Assessment) -> int:
    """Evaluate FIRST equation 2.10 exactly, rounding only the final number of tenths.

    Args:
        assessment: Already validated immutable source metric containing all six base tokens.

    Returns:
        Integer tenths in 0..100, independent of optional metrics and asserted scores.
    """

    cvss = cast(Mapping[str, object], assessment.metric["cvssV2_0"])
    vector = cast(str, cvss["vectorString"])
    tokens = dict(component.split(":") for component in vector.split("/"))
    remaining_impact = (
        (_WEIGHT_SCALE - _IMPACT[tokens["C"]])
        * (_WEIGHT_SCALE - _IMPACT[tokens["I"]])
        * (_WEIGHT_SCALE - _IMPACT[tokens["A"]])
    )
    impact_numerator = 1041 * (_PRODUCT_DENOMINATOR - remaining_impact)

    if impact_numerator == 0:
        return 0

    exploitability_numerator = 20 * _AV[tokens["AV"]] * _AC[tokens["AC"]] * _AU[tokens["Au"]]
    # Impact has denominator 100*1000^3; exploitability has denominator 1000^3.
    # Multiplication by ten for tenths cancels the base expression's factor 1/10.
    base_tenths_numerator = (
        6 * impact_numerator + 4 * 100 * exploitability_numerator - 15 * _IMPACT_DENOMINATOR
    ) * 1176
    base_tenths_denominator = _IMPACT_DENOMINATOR * 1000
    quotient, remainder = divmod(base_tenths_numerator, base_tenths_denominator)

    # The complete valid six-token domain has no exact final half-tenth ties.
    return quotient + int(2 * remainder > base_tenths_denominator)


@dataclass(frozen=True, slots=True)
class BaseCalculation:
    """Keep one internally derived value linked only by its source assessment position."""

    assessment_index: int
    base_score_tenths: int
    algorithm: str = field(init=False, default="cvss2-base-2.10")

    def DisplayScore(self) -> str:
        """Render exact integer tenths without floating-point or Decimal conversion.

        Returns:
            Score with exactly one decimal digit, including 0.0 and 10.0.
        """

        return f"{self.base_score_tenths // 10}.{self.base_score_tenths % 10}"

    def ToDict(self) -> dict[str, object]:
        """Return a detached derived value without repeating source assertions.

        Returns:
            Assessment position, algorithm identifier and integer score in tenths.
        """

        return {"assessment_index": self.assessment_index, "algorithm": self.algorithm,
                "base_score_tenths": self.base_score_tenths}


@dataclass(frozen=True, slots=True)
class CveCvss2BaseCalculations:
    """Compute Experimental base-only values while retaining original typed statements once.

    Args:
        statements: Original immutable source inspection; no raw input or score coercion occurs.

    Raises:
        ValueError: Input is not a typed CveCvss2Statements value.

    Calculation is pure. Source scores, snapshot bytes, provider/scenario contexts and their
    positions remain unchanged. No applicability, severity or source-correction verdict follows.
    Computed fields are not constructor arguments. Direct source construction retains the
    original inspection API's limit: it cannot independently prove derivation from raw bytes.
    """

    statements: CveCvss2Statements
    calculations: tuple[BaseCalculation, ...] = field(init=False)

    def __post_init__(self) -> None:
        """Require typed statements and derive one immutable value per assessment in order."""

        if not isinstance(self.statements, CveCvss2Statements):
            raise ValueError("CVSS 2 base calculation requires typed source statements")

        calculations = tuple(
            BaseCalculation(index, BaseScoreTenths(assessment))
            for index, assessment in enumerate(self.statements.assessments)
        )
        object.__setattr__(self, "calculations", calculations)

    def ToDict(self) -> dict[str, object]:
        """Return detached source inspection once and a separate ordered calculation array.

        Returns:
            Unchanged statements and computed-only base values; no persisted decoder is defined.
        """

        return {"statements": self.statements.ToDict(),
                "calculations": [calculation.ToDict() for calculation in self.calculations]}
