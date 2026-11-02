# ADR 0122: Five-level CVSS presentation through FuzzyRoutines

- Status: Accepted design; shared integration acceptance pending
- Date: 2026-11-02
- Decision owners: Fuzzy Technologies
- Related work: #393; M3; future explainable risk and action priorities #62, #67

## Context

The owner approved Python 3.13+ and a normal required, exact released
FuzzyRoutines dependency. M3 needs a small reproducible five-level
interpretation example; full contextual prioritization belongs to M5. Numeric
severity, observed exploitation and exploitation predictions have different
meanings and must not be collapsed into an unsupported business-risk score.

## Decision

Add the Experimental pure module `fuzzy1337.assessments`. Its
`InterpretSeverity(value: float | None)` accepts only an explicit finite numeric
CVSS base score in `0..10`, or an explicitly missing input. It divides the score
by ten and directly calls the pinned dependency's public UFS factory and policy.
No membership equations, fuzzy engines or fallback scales are duplicated.

Map the original `Min`, `Low`, `Med`, `High`, `Max` term names to five human
levels while retaining each original name. Preserve all unrounded grades and
the dependency's selected exact maximum. The preset's last-maximum policy, zero
tie tolerance, zero additional cutoff, weak coverage and positive Min tail are
part of this interpretation; grades are not renormalized or labelled as
probabilities. UFS levels do not replace conventional CVSS severity categories.

Return frozen `SeverityInterpretation` and `SeverityMembership` values with
original input/units, normalized coordinate, selected level, all grades, maximum
grade and exact installed library version plus stable scale/rule identifiers.
`ToDict()` is detached JSON-compatible presentation data. Missing input carries
unknown values rather than a reassuring numeric zero. Invalid inputs fail
without clamping or coercion.

The adapter has no canonical persistence, I/O, matching, evidence acquisition,
CVSS arithmetic or Finding mutation. A caller-supplied numeric score is not
independently authenticated by this adapter; its consumer must retain and
label original source provenance separately. Existing JSON/SARIF/JUnit/report
snapshot contracts remain unchanged. A human HTML view may use the adapter on
an actual retained source score and must keep the source and derived view
visibly distinct.

## Consequences and evidence

The new dependency is required at the platform layer; there is no optional
feature or internal numerical substitute. A numeric score receives an
explainable term trace; missing or categorical-only source data cannot fabricate
an assessment. The pilot does not perform contextual risk inference, change
triage or recommend action priorities. Those remain the scope of M5.

Focused deterministic tests use the actual installed FuzzyRoutines 2.1.0 and
exercise known anchors, overlap, preserved weak coverage, version/profile
metadata, invalid inputs, missing information, immutable output and detached
strict JSON. Integration must also execute the installed human report consumer
and pass the shared final-revision checks before acceptance.
