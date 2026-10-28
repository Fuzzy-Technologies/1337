# ADR 0107: Separate CVSS 2 base-score calculations

- Status: Accepted design; implementation acceptance pending
- Date: 2026-10-28
- Decision owners: Fuzzy Technologies
- Related work: #47, #43; merged PR #372; ADR 0104
- Prerequisites: source profile accepted in PR #372; independent formula/API
  design review accepted; bounded implementation authorized on 2026-10-28.

## Problem and proposed boundary

ADR 0104 exposes immutable source-declared legacy assessments without computing
their scores. A separate pure calculation API can derive a CVSS 2 base score
from the six explicit base metrics while retaining the original assessment and
its source/provider/scenario context. A derived value must never replace a
publisher's asserted `baseScore` or silently create Finding severity.

Propose a separate Experimental module, `fuzzy1337.intelligence_cvss2_base`.
The pure `CveCvss2BaseCalculations(statements: CveCvss2Statements)` constructor
accepts only the original typed inspection result and derives its calculations
internally. Its immutable result retains that original result once
and a separate ordered calculation per assessment. Each calculation records its
assessment position, algorithm identifier `cvss2-base-2.10`, and an integer score
in tenths (`0` through `100`); a display value can be rendered with exactly one
decimal. Source asserted scores remain exclusively in the unchanged source
assessment. No mismatch implies correction, source rejection, or preference.

Direct construction accepts no score, algorithm identifier, assessment index or
calculation-list arguments. Those fields are computed-only (`init=False` or
private immutable fields), with one integer-tenths value for each original
assessment position. This removes a separate explicit-score validation path.
An additional calculation factory would add no contract and is not proposed.
Independent exact formula/API design review accepted this boundary before
implementation. Production acceptance remains subject to the evidence below.

Input source derivation has the same limits as ADR 0104: raw-byte derivation is
established by its parser, while directly constructed inspection values cannot
independently prove their derivation. Calculation creates no new publisher
authentication, applicability, review approval, or execution authorization.

## Primary formula authority

FIRST's [CVSS 2 guide, section 3.2.1](https://www.first.org/cvss/v2/guide#3-2-1-Base-Equation)
identifies formula version `2.10`. In the following mathematical transcription,
`I` is impact, `E` is exploitability, and `R1` means nearest one decimal:

```text
I = 10.41 * (1 - (1-C) * (1-I_metric) * (1-A))
E = 20 * AV * AC * Au
F = 0 when I = 0; otherwise 1.176
Base = R1((0.6*I + 0.4*E - 1.5) * F)
```

The same section supplies these weights:

| Metric | Tokens and exact decimal weights |
| ------ | -------------------------------- |
| AV     | L: 0.395; A: 0.646; N: 1.0       |
| AC     | H: 0.35; M: 0.61; L: 0.71        |
| Au     | M: 0.45; S: 0.56; N: 0.704       |
| C/I/A  | N: 0.0; P: 0.275; C: 0.660       |

Only the final base expression is rounded. No intermediate rounding or
impact clamping is in this equation. FIRST's worked sections 3.3.1–3.3.3
display shortened subscores; those display values must not replace the equation.

### Rounding authority and finite-domain result

The examined FIRST guide says `round_to_1_decimal`; an explicit half-tie policy
was not located in the primary material. Do not describe `ROUND_HALF_UP`, Python
`round`, or any general-purpose helper as an independently verified canonical
FIRST tie rule.

Research enumerated all `3^6 = 729` valid base combinations using exact rational
arithmetic and independently evaluated the same decimal constants with a local
50-digit Decimal context. All results agreed. There are 27 zero-impact vectors,
and no exact half-tenth ties. Therefore nearest-one-decimal has an unambiguous
result for every valid base input; a general tie convention is unnecessary for
this API. Optional temporal/environmental vector tokens do not enlarge the base
metric domain or enter this base-only equation.

Proposed arithmetic: exact integers/rationals through the entire expression,
then select the nearest integer number of tenths. Do not depend on ambient
Decimal precision, binary floating arithmetic, displayed subscores, or a later
CVSS version's round-up rule. Exact arithmetic also avoids having to invent a
tolerance near boundaries.

## Authoritative known answers

These are publisher-published score/vector anchors, distinct from our derived
enumeration. References were retrieved on 2026-10-28; no live provider was run.

| Vector                     | Base | Primary source                                                                                                                 |
| -------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------ |
| AV:N/AC:L/Au:N/C:N/I:N/A:C | 7.8  | FIRST guide 3.3.1, CVE-2002-0392                                                                                               |
| AV:N/AC:L/Au:N/C:C/I:C/A:C | 10.0 | FIRST guide 3.3.2, CVE-2003-0818                                                                                               |
| AV:L/AC:H/Au:N/C:C/I:C/A:C | 6.2  | FIRST guide 3.3.3, CVE-2003-0062                                                                                               |
| AV:N/AC:L/Au:N/C:N/I:N/A:N | 0.0  | [NVD CVE-1999-0637](https://nvd.nist.gov/vuln/detail/CVE-1999-0637)                                                            |
| AV:L/AC:L/Au:N/C:C/I:C/A:C | 7.2  | [NVD calculator](https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=AV%3AL%2FAC%3AL%2FAu%3AN%2FC%3AC%2FI%3AC%2FA%3AC) |

The last boundary anchor is also published as NVD's score/vector for
[CVE-2020-11271](https://nvd.nist.gov/vuln/detail/CVE-2020-11271).
NVD responses exposed zero readable lines on several direct opens. The cited
score/vector pairs were retrieved from indexed primary NVD pages; this is
published-source evidence, not proof that a live calculator executed during
this research. FIRST's three guide vectors were read directly in the guide.

## Derived boundary and failure examples

The following exact decimals are our calculations from the published formula,
not separately published FIRST golden answers:

| Case                | Vector                     | Exact unrounded base | Rounded base |
| ------------------- | -------------------------- | -------------------- | ------------ |
| Closest above a tie | AV:L/AC:L/Au:N/C:C/I:C/A:C | 7.150081900416       | 7.2          |
| Closest below a tie | AV:A/AC:H/Au:M/C:C/I:C/A:C | 6.249813446016       | 6.2          |
| Early-rounding trap | AV:L/AC:H/Au:M/C:N/I:P/A:C | 4.355975736          | 4.4          |

The above-boundary case has impact `10.00084536`; replacing it by `10` changes
the correct `7.2` result to `7.1`. Its distance above the `7.15` threshold is
exactly `0.000081900416`. The below-boundary case is `0.000186553984` below
`6.25`. The early-rounding trap becomes `4.3` if impact and exploitability are
rounded to one decimal before substitution. In this study's deliberately
incorrect shortcut, intermediate nearest-one-decimal rounding uses half-up ties;
that chosen counterfactual changes 232 of 729 results. It is not a
tie-convention-independent count: exploitability is exactly `3.15` when
`AV:N/AC:H/Au:M`, producing 27 intermediate ties across CIA combinations. The
reviewer's independent ties-down counterfactual changes 230 results. These
intermediate ties do not affect the correct final-only equation, whose valid
domain contains no final half-tenth ties.

All 27 all-None CIA combinations must produce `0.0`, regardless of AV/AC/Au,
through the explicit zero-impact multiplier. No positive subscore or negative
unmultiplied expression may leak through. All 729 final results lie in `[0, 10]`.

## Evidence plan before production acceptance

1. Independently inspect the exact formula/constants, zero branch, full-impact
   boundary and absence of half ties; do not approve from these research claims
   alone. Preserve the guide's section/CVE identifiers in fixture provenance.
2. Add hand-authored publisher golden-answer cases with URL/section provenance.
   Fixture code/data is original; do not bundle an official CVE corpus or copy
   explanatory source prose.
3. Use a test-only exact rational oracle separate from the proposed production
   arithmetic implementation, exhaustively covering all 729 base combinations.
   Compare each with the finite-domain summary and the primary anchors.
4. Directly test both boundary examples and the early-rounding trap. Prove no
   intermediate rounding/clamping and no ambient Decimal-context dependence.
5. Use real immutable ADR 0104 input values to cover multiple ordered providers,
   source metric positions, optional metrics and scenarios, no-v2/rejected empty
   results, detachment, invalid direct construction, and unchanged source scores,
   original snapshot bytes/references and original inspection output.
6. Keep optional metric validation in ADR 0104. Vary temporal/environmental
   tokens while asserting only the same base calculation; do not emit or claim
   their scores. Refuse invalid/untyped inputs without coercion.
7. Require focused unit/contract and applicable static/documentation checks,
   independent exact implementation review, branch coverage strictly above 80%,
   then final-ready exact-head shared CI. Run no duplicate local full gate.

## Explicit exclusions and remaining gates

Design approval does not establish production feature acceptance.
Temporal/environmental calculation, conversion to other CVSS
versions, Finding severity/risk changes, automatic source correction, target
matching, signature authentication and network execution remain outside this
proposal. Runtime calculation is pure and performs no I/O.

The independently reviewed proposal had SHA-256
`d83560b9986aec827acdc4409269653dfcdfe9c322740f89dd6026f5e8e3cd7f`.
A separate scaled-integer/common-denominator evaluation matched all 729 exact
research results, including 27 zero-impact cases and no final half-tenth ties.
The all-vector digest over sorted-key JSON research records was
`c4544073ede11ae17802123d60fd8575954cb398bb6c77e508145bf596903d5f`.

Research and independent design approval are not passing production feature
tests or completed Task #47 acceptance. Implementation requires its own focused
production/oracle, contract, coverage, source review and final shared CI evidence.

## Focused implementation evidence

The implementation now uses scaled integer constants and a common denominator
through the complete base expression. The public frozen constructor accepts
only `CveCvss2Statements`; its ordered immutable records are computed internally,
retain only assessment positions and derived values, and provide exact
one-decimal display. Detached output retains original source statements once.

On 2026-10-28, the new unit/contract selection passed 36 tests with `--no-cov`
and two process workers. This included one comparison of production with a
separate test-only Fraction equation across all 729 base combinations, all 27
zero-impact combinations, no final ties, the five published fixture anchors,
derived threshold/trap cases and real source-parser preservation. A separate
targeted branch-coverage run excluded the exhaustive comparison: 35 tests
passed, with all 47 new-module statements and all four branches covered (100%).
New-module strict mypy, changed-code Ruff and the source-documentation audit
passed. These are focused local results; they do not establish final shared CI,
independent implementation approval, integration or completion of Task #47.
