# CVSS 2 base-score calculations

`fuzzy1337.intelligence_cvss2_base` is an Experimental, pure calculation API
separate from the [source inspection profile](INTELLIGENCE_CVSS2.md).
`CveCvss2BaseCalculations(statements)` accepts only an existing immutable
`CveCvss2Statements` result. It retains that exact result once and derives one
immutable calculation for each assessment, in its original order.

Each calculation has an `assessment_index` into `statements.assessments`, the
algorithm identifier `cvss2-base-2.10`, and integer `base_score_tenths` in
`0..100`. `DisplayScore()` renders exactly one decimal digit, such as `0.0`,
`7.8` or `10.0`. Calculation fields are computed internally; the public
constructor accepts no scores, algorithm, assessment positions or calculation
list. The ordered `calculations` tuple and its records are frozen.

```python
from fuzzy1337.intelligence_cvss2_base import CveCvss2BaseCalculations

# statements is an existing ParseCveCvss2Statements(...) result.
calculated = CveCvss2BaseCalculations(statements)
for calculation in calculated.calculations:
    assessment = calculated.statements.assessments[calculation.assessment_index]
    print(assessment.role, assessment.metric_index, calculation.DisplayScore())
```

The source profile keeps the original vector string, asserted `baseScore`,
optional source scores, complete provider/scenario context, container/metric
coordinates, snapshot bytes and snapshot reference unchanged. For example, an
asserted source score of `0.1` can remain alongside a separately derived `7.8`.
That difference does not correct or reject the publisher's statement or prefer
one score. No-v2 and rejected inspections produce an empty calculation tuple,
not an invented zero-score assessment.

## Arithmetic and scope

The equation and exact decimal weights follow
[FIRST CVSS 2 guide section 3.2.1](https://www.first.org/cvss/v2/guide#3-2-1-Base-Equation),
formula version `2.10`. All six required base tokens enter the equation;
temporal/environmental tokens remain source-validated but do not enter it.
The calculation uses exact scaled integers through impact, exploitability and
the full base expression. It returns zero for zero impact and rounds only the
final base expression to nearest integer tenths. It never rounds intermediate
subscores or clamps impact to ten. In particular, complete impact is exactly
`10.00084536`, which matters at a final rounding boundary.

Production uses no floating-point or Decimal arithmetic and is independent of
ambient Decimal precision, rounding modes and traps. The accepted finite-domain
analysis found no exact final half-tenth ties among the 729 valid six-token
combinations. This API relies on that finite domain; it does not assert a
general FIRST half-tie rule. Later CVSS versions' round-up rules do not apply.

`ToDict()` returns detached `statements` and `calculations` members. The source
inspection is serialized once, unchanged. Calculation records contain only
`assessment_index`, `algorithm` and `base_score_tenths`; they do not duplicate
or overwrite asserted source scores. No persisted decoder or replacement
intelligence snapshot is introduced.

The calculation performs no I/O, publisher authentication, target matching,
source correction, CVSS version conversion, temporal/environmental calculation,
or Finding/severity/risk mutation. Typed direct source construction retains the
inspection profile's limitation: it cannot independently prove derivation from
the original raw bytes. Calculation grants no applicability, review approval
or execution authorization.

## Verification boundary

The original hand-authored fixture
`tests/fixtures/cvss2/base-score-v2.10.json` records five published primary
score/vector anchors with URL and section/CVE provenance. Derived rounding
examples and a test-only Fraction oracle are separate from those published
answers. Focused unit/contract tests cover every valid six-token combination,
all 27 zero-impact combinations, final thresholds, clamping/early-rounding
counterexamples, optional metrics, source retention, immutable output and
rejected/untyped input. These checks establish the bounded calculation API;
they do not establish live publisher execution or complete Task #47 acceptance.

[ADR 0107](adr/0107-separate-cvss2-base-calculations.md) records the accepted
formula and API decision, source provenance and integration gates.
