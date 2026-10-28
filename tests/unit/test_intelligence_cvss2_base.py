# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify base-only production arithmetic against independent exact and published anchors."""

from __future__ import annotations

import hashlib
import inspect
import json
from collections.abc import Sequence
from dataclasses import FrozenInstanceError, replace
from decimal import ROUND_DOWN, ROUND_UP, Inexact, localcontext
from fractions import Fraction
from itertools import product
from pathlib import Path

import pytest

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.intel_references import ReferenceSource, SourceOrigin
from fuzzy1337.intelligence_cvss2 import CveCvss2Statements, ParseCveCvss2Statements
from fuzzy1337.intelligence_cvss2_base import CveCvss2BaseCalculations

PRIMARY_ANCHORS = json.loads(
    (Path(__file__).parents[1] / "fixtures/cvss2/base-score-v2.10.json").read_text(encoding="utf-8")
)
BASE_VECTOR = "AV:N/AC:L/Au:N/C:N/I:N/A:C"


def Statements(vectors: Sequence[str], state: str = "PUBLISHED") -> CveCvss2Statements:
    """Parse bounded synthetic containers with intentionally independent source scores.

    Args:
        vectors: Ordered validated-source vector candidates, split across bounded containers.
        state: Explicit source state, including rejected records with no positive inspection.

    Returns:
        Actual source-parser output bound to the exact synthetic payload bytes.
    """

    containers = []

    for offset in range(0, max(1, len(vectors)), 256):
        containers.append({
            "providerMetadata": {"orgId": f"synthetic-{offset // 256}"},
            "metrics": [{"cvssV2_0": {"version": "2.0", "vectorString": vector,
                                      "baseScore": 0.1}}
                        for vector in vectors[offset:offset + 256]],
        })

    raw = json.dumps({
        "dataType": "CVE_RECORD", "dataVersion": "5.2", "cveMetadata": {
            "cveId": "CVE-1900-9999", "state": state, "dateUpdated": "2026-10-28T10:00:00Z",
        }, "containers": {"cna": containers[0], "adp": containers[1:]},
    }).encode()
    digest = hashlib.sha256(raw).hexdigest()
    source = ReferenceSource(
        SourceOrigin.SYNTHETIC, "1337 synthetic fixture", "https://example.invalid/source",
        digest, "Apache-2.0 (synthetic fixture only)", "https://example.invalid/LICENSE",
        "2026-10-28T12:00:00Z", "synthetic-importer", "1",
    )
    evidence = EvidenceReference("intelligence-source", f"blobs/sha256/{digest}", digest,
                                 "application/json", len(raw))

    return ParseCveCvss2Statements(raw, "synthetic-1", source, evidence)


def Oracle(vector: str) -> tuple[Fraction, Fraction, Fraction]:
    """Transcribe FIRST 3.2.1 with rational decimal constants independently of production.

    Args:
        vector: Six valid base metrics; optional source tokens are ignored by the equation.

    Returns:
        Exact impact, exploitability and final unrounded base expression, with zero multiplier.
    """

    tokens = dict(component.split(":") for component in vector.split("/"))
    access_vector = {"L": Fraction("0.395"), "A": Fraction("0.646"), "N": Fraction("1.0")}
    complexity = {"H": Fraction("0.35"), "M": Fraction("0.61"), "L": Fraction("0.71")}
    authentication = {"M": Fraction("0.45"), "S": Fraction("0.56"), "N": Fraction("0.704")}
    impacts = {"N": Fraction("0.0"), "P": Fraction("0.275"), "C": Fraction("0.660")}
    impact = Fraction("10.41") * (
        1 - (1 - impacts[tokens["C"]]) * (1 - impacts[tokens["I"]])
        * (1 - impacts[tokens["A"]])
    )
    exploitability = (
        20 * access_vector[tokens["AV"]] * complexity[tokens["AC"]]
        * authentication[tokens["Au"]]
    )
    multiplier = Fraction(0) if impact == 0 else Fraction("1.176")
    raw_base = (Fraction("0.6") * impact + Fraction("0.4") * exploitability
                - Fraction("1.5")) * multiplier

    return impact, exploitability, raw_base


@pytest.mark.parametrize("anchor", PRIMARY_ANCHORS["cases"], ids=lambda case: case["id"])
def test_PublishedPrimaryAnchorsAreIndependentKnownAnswers(anchor):
    """Original fixture values retain published authority separately from our formula oracle."""

    result = CveCvss2BaseCalculations(Statements([anchor["vector"]]))
    calculation = result.calculations[0]

    assert calculation.base_score_tenths == anchor["base_score_tenths"], (
        f"Production disagrees with published primary score/vector anchor {anchor['id']}"
    )
    assert calculation.algorithm == PRIMARY_ANCHORS["algorithm"], "Algorithm version changed"
    assert anchor["reference"].startswith("https://"), "Primary anchor lacks source provenance"


def test_CompleteBaseDomainMatchesIndependentFractionOracle():
    """All 729 production values agree with rational equation evaluation and have no final ties."""

    vectors = [f"AV:{av}/AC:{ac}/Au:{au}/C:{c}/I:{i}/A:{a}"
               for av, ac, au, c, i, a in product("LAN", "HML", "MSN", "NPC", "NPC", "NPC")]
    calculated = CveCvss2BaseCalculations(Statements(vectors))
    zero_impact_count = 0

    pairs = zip(vectors, calculated.calculations, strict=True)

    for index, (vector, calculation) in enumerate(pairs):
        impact, _, raw_base = Oracle(vector)
        exact_tenths = 10 * raw_base
        lower = exact_tenths.numerator // exact_tenths.denominator

        assert exact_tenths - lower != Fraction(1, 2), f"Unexpected final tie for {vector}"
        assert calculation.base_score_tenths == round(exact_tenths), (
            f"Scaled-integer production disagrees with independent rational equation for {vector}"
        )
        assert type(calculation.base_score_tenths) is int, "Computed score is not integer tenths"
        assert 0 <= calculation.base_score_tenths <= 100, f"Base score out of bounds for {vector}"
        assert calculation.assessment_index == index, "Calculation positions lost source order"

        if impact == 0:
            zero_impact_count += 1

            assert calculation.base_score_tenths == 0, f"Zero-impact branch failed for {vector}"

    assert len(calculated.calculations) == 729, "Complete six-token domain was not exercised"
    assert zero_impact_count == 27, "Not all AV/AC/Au zero-impact combinations were checked"
    assert min(item.base_score_tenths for item in calculated.calculations) == 0, (
        "Zero endpoint disappeared from the complete domain"
    )
    assert max(item.base_score_tenths for item in calculated.calculations) == 100, (
        "Full score endpoint disappeared from the complete domain"
    )


@pytest.mark.parametrize(("vector", "raw_base", "tenths"), [
    ("AV:L/AC:L/Au:N/C:C/I:C/A:C", "7.150081900416", 72),
    ("AV:A/AC:H/Au:M/C:C/I:C/A:C", "6.249813446016", 62),
    ("AV:L/AC:H/Au:M/C:N/I:P/A:C", "4.355975736", 44),
])
def test_FinalRoundingBoundariesAndEarlyRoundingTrap(vector, raw_base, tenths):
    """Derived threshold cases test exact final rounding without claiming primary golden status."""

    _, _, actual_raw = Oracle(vector)
    result = CveCvss2BaseCalculations(Statements([vector]))

    assert actual_raw == Fraction(raw_base), "Independent derived boundary transcription changed"
    assert result.calculations[0].base_score_tenths == tenths, (
        "Production rounded an intermediate value or crossed the wrong final threshold"
    )


def test_FullImpactRemainsAboveTenAndSubscoresAreNeverRounded():
    """Known counterfactuals demonstrate why clamping and displayed subscores are invalid."""

    boundary = "AV:L/AC:L/Au:N/C:C/I:C/A:C"
    impact, exploitability, _ = Oracle(boundary)
    incorrectly_clamped = (
        Fraction("0.6") * 10 + Fraction("0.4") * exploitability - Fraction("1.5")
    ) * Fraction("1.176")
    trap = "AV:L/AC:H/Au:M/C:N/I:P/A:C"
    trap_impact, trap_exploitability, _ = Oracle(trap)
    incorrectly_rounded = (
        Fraction("0.6") * Fraction(round(10 * trap_impact), 10)
        + Fraction("0.4") * Fraction(round(10 * trap_exploitability), 10) - Fraction("1.5")
    ) * Fraction("1.176")
    result = CveCvss2BaseCalculations(Statements([boundary, trap]))

    assert impact == Fraction("10.00084536"), "Full impact was incorrectly limited to ten"
    assert round(10 * incorrectly_clamped) == 71, "Clamping counterexample no longer differs"
    assert round(10 * incorrectly_rounded) == 43, "Early-rounding counterexample no longer differs"
    assert [item.base_score_tenths for item in result.calculations] == [72, 44], (
        "Production adopted clamping or intermediate rounding"
    )


@pytest.mark.parametrize("vector", [
    BASE_VECTOR,
    "A:C/I:N/C:N/Au:N/AC:L/AV:N/AR:ND/E:ND",
    BASE_VECTOR + "/E:POC/RL:TF/RC:UR/CDP:LM/TD:M/CR:H/IR:L/AR:ND",
    BASE_VECTOR + "/E:H/RL:OF/RC:C/CDP:H/TD:H/CR:L/IR:H/AR:L",
])
def test_BaseIgnoresOptionalMetricsAndRetainsOriginalVector(vector):
    """Temporal/environmental source tokens and token order cannot change the base-only value."""

    statements = Statements([vector])
    before = statements.ToDict()
    result = CveCvss2BaseCalculations(statements)

    assert result.calculations[0].ToDict() == {
        "assessment_index": 0, "algorithm": "cvss2-base-2.10", "base_score_tenths": 78,
    }, "Optional metrics entered the base equation or created additional score outputs"
    assert statements.ToDict() == before, "Calculation changed original vector/source assertions"
    assert statements.assessments[0].metric["cvssV2_0"]["vectorString"] == vector, (
        "Calculation normalized original vector order or optional tokens"
    )


@pytest.mark.parametrize(("vectors", "state"), [([], "PUBLISHED"), ([BASE_VECTOR], "REJECTED")])
def test_EmptyAndRejectedInspectionsRemainEmpty(vectors, state):
    """No legacy assessment yields no score, including rejected source records."""

    statements = Statements(vectors, state)
    calculated = CveCvss2BaseCalculations(statements)

    assert calculated.calculations == (), "Absent positive assessments manufactured a score"
    assert calculated.ToDict() == {"statements": statements.ToDict(), "calculations": []}, (
        "Empty calculations changed source output or introduced an implied zero assessment"
    )


@pytest.mark.parametrize("value", [None, {}, [], BASE_VECTOR, 7.8, True, object()])
def test_UntypedInputCannotBeCoercedIntoSourceStatements(value):
    """Only original typed immutable inspection values cross the calculation boundary."""

    with pytest.raises(ValueError, match="typed source statements"):
        CveCvss2BaseCalculations(value)


@pytest.mark.parametrize("field", ["calculations", "assessment_index", "algorithm",
                                  "base_score_tenths", "base_score"])
def test_ComputedValuesAreNotPublicConstructorArguments(field):
    """Callers cannot inject explicit calculated scores or alter their source linkage."""

    statements = Statements([BASE_VECTOR])

    with pytest.raises(TypeError):
        CveCvss2BaseCalculations(statements, **{field: 1})

    assert list(inspect.signature(CveCvss2BaseCalculations).parameters) == ["statements"], (
        "The public constructor gained an explicit calculated-value path"
    )


def test_SourceAndOrderedCalculationsAreFrozenAndComputedFieldsCannotBeReplaced():
    """Frozen slots and tuple values preserve computed fields and original source identity."""

    statements = Statements([BASE_VECTOR])
    result = CveCvss2BaseCalculations(statements)
    calculation = result.calculations[0]

    with pytest.raises(FrozenInstanceError):
        result.statements = Statements([])

    with pytest.raises(FrozenInstanceError):
        result.calculations = ()

    with pytest.raises(FrozenInstanceError):
        calculation.base_score_tenths = 1

    with pytest.raises(FrozenInstanceError):
        calculation.assessment_index = 1

    with pytest.raises(FrozenInstanceError):
        calculation.algorithm = "changed"

    with pytest.raises(TypeError):
        result.calculations[0] = calculation

    with pytest.raises(ValueError, match="init=False"):
        replace(result, calculations=())

    assert result.statements is statements, "Calculation replaced original source inspection"
    assert result.calculations[0].base_score_tenths == 78, "Mutation changed computed score"


@pytest.mark.parametrize(("vector", "display"), [
    ("AV:N/AC:L/Au:N/C:N/I:N/A:N", "0.0"),
    (BASE_VECTOR, "7.8"),
    ("AV:N/AC:L/Au:N/C:C/I:C/A:C", "10.0"),
])
def test_DisplayUsesExactlyOneDecimalFromIntegerTenths(vector, display):
    """Presentation preserves exact endpoints and one decimal without numeric-context effects."""

    result = CveCvss2BaseCalculations(Statements([vector]))

    assert result.calculations[0].DisplayScore() == display, "Exact one-decimal display changed"


@pytest.mark.parametrize(("precision", "rounding"), [
    (1, ROUND_DOWN), (3, ROUND_UP), (50, ROUND_DOWN),
])
def test_AmbientDecimalPrecisionRoundingAndInexactTrapsHaveNoEffect(precision, rounding):
    """Production calculation and display use no ambient Decimal operations."""

    statements = Statements(["AV:L/AC:L/Au:N/C:C/I:C/A:C", BASE_VECTOR])

    with localcontext() as context:
        context.prec = precision
        context.rounding = rounding
        context.traps[Inexact] = True
        result = CveCvss2BaseCalculations(statements)

        assert [item.base_score_tenths for item in result.calculations] == [72, 78], (
            "Ambient Decimal settings affected exact integer arithmetic"
        )
        assert [item.DisplayScore() for item in result.calculations] == ["7.2", "7.8"], (
            "Ambient Decimal settings affected exact integer display"
        )
