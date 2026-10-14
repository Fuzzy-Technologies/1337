# fuzzy1337.ci_gate

This Experimental profile evaluates an explicit finding predicate over one
original verified synthetic configuration execution and its exact saved model.
`CiFindingCriterion`, `CiPredicateResult` and `EvaluateConfigurationCriterion`
are the supported surface; remaining helpers are Internal.

Caller-selected severity/status sets and a bounded maximum matching count form
the complete criterion. Explicit acknowledgement of unassessed completeness is
required. Labels are not ranked or combined into a risk score. Original four-role
source/run proof, exact saved-snapshot digest and fresh acceptance checks precede
selection. Only original current-run detections enter the predicate; unrelated
retained findings remain report facts and operator triage is preserved.

Zero matching findings cannot substitute for missing original processing proof.
The result describes selected-profile predicate satisfaction or violation, with
`scan_completeness: not-assessed`. This profile adds no reachable-risk rule,
scanner coverage claim, native execution grant or Core schema change. See
[CI scan](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/CI_SCAN.md).

::: fuzzy1337.ci_gate
