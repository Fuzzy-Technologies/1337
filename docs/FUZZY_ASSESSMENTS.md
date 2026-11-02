# Five-level severity interpretation

`fuzzy1337.assessments` is an Experimental, pure presentation API using the
required, pinned `fuzzyroutines==2.1.0` dependency. It adds a linguistic view of
one **explicit numeric CVSS base score**. It does not calculate CVSS, replace
its original source assessment, change a Finding's severity or triage, or
establish that a particular target is vulnerable.

```python
from fuzzy1337.assessments import InterpretSeverity

assessment = InterpretSeverity(8.0)
print(assessment.label)  # High
print(assessment.input_value)  # 8.0, still a CVSS base score in 0..10
print(assessment.ToDict())
```

The input is normalized by dividing by ten. The adapter calls FuzzyRoutines'
public `CreateUniversalFuzzyScale()` and `UniversalFuzzyScalePolicy()` APIs;
1337 does not copy membership functions or provide a substitute implementation.
The policy selects the last exact maximum, without a near-tie tolerance or an
additional minimum-membership cutoff. The output preserves every membership
and its maximum, without rounding or normalization into a probability vector.

| 1337 level  | Human label | Original UFS term |
| ----------- | ----------- | ----------------- |
| `very_low`  | Very low    | `Min`             |
| `low`       | Low         | `Low`             |
| `medium`    | Medium      | `Med`             |
| `high`      | High        | `High`            |
| `very_high` | Very high   | `Max`             |

These are the library's historical UFS shapes and selection semantics. They
are **not the conventional CVSS severity categories**. For example, a source
base score of `8.0` selects `High` here, with membership approximately `0.5`;
the original score, CVSS version/vector and any publisher category remain
separate source facts. At `3.7`, both Low and Medium have membership close to
`0.5`; the library retains its exact binary floating-point selection rather
than treating approximately equal values as a tie.

Membership grades describe compatibility with terms. They are not
probabilities of exploitation, certainty that an asset is vulnerable, or
priorities for remediation. Grades need not add to one. The original UFS has a
positive Min tail and weak coverage around normalized `0.17`; the adapter
retains these facts rather than inventing confidence. A report must show the
source input and the grade trace alongside a selected label.

## Missing values, validation and reproducibility

`InterpretSeverity(None)` returns status `unknown`, label `Unknown`, no selected
level and five memberships whose grades are `None`. Missing information never
becomes a zero score or zero membership. A measured score `0` is different: it
is interpreted through the actual library and selects Very low. A categorical
Finding severity alone is not enough to infer a numeric CVSS score.

Booleans, nonnumeric values, NaN, infinity and values outside the closed
`0..10` range raise `ValueError`; there is no clamping, string coercion or silent
fallback. The adapter makes no network requests and reads no target, workspace
or evidence artifacts. Normal package metadata supplies the installed dependency
version.

The frozen result exposes `input_value`, `normalized_value`, `status`,
`selected_level`, `label`, `memberships`, `maximum_membership`, `library_version`,
`scale_profile` and `rule_profile`. Membership records are also frozen.
`ToDict()` returns detached JSON-compatible data including input units, schema
version, dependency name/version, both profile identifiers and selection policy.
This is a derived presentation trace; it is not a replacement canonical
assessment or an authenticated source record. Reports retain their original
model and machine-export contracts.

The M3 pilot performs fuzzification only. Combining severity, exposure,
exploitation evidence, protective measures and business context into an
explainable action priority remains M5 work. No Mamdani/Sugeno inference or
LLM is implied by this single-value interpretation.

## Verification

The focused unit suite exercises the installed released library on preset
plateaus/endpoints and overlapping regions; it verifies original score
retention, exact grade delegation, version metadata, weak coverage, rejection,
unknowns, immutable output, detached serialization and reproducibility.

```bash
uv run --locked --extra dev pytest tests/unit/test_assessments.py -n 2 --no-cov
```

[ADR 0122](adr/0122-five-level-cvss-presentation.md) records the boundary and
[the FuzzyRoutines public project](https://github.com/Fuzzy-Technologies/FuzzyRoutines)
contains the dependency's own scale documentation and API reference.
