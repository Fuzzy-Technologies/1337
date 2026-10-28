# fuzzy1337.ci_gate

This Experimental profile evaluates an explicit finding predicate over one
original verified synthetic configuration execution or image VERSION/SCAN pair
and its exact saved model. `CiFindingCriterion`, `CiPredicateResult`,
`EvaluateConfigurationCriterion` and additive `EvaluateImageCriterion` are the
Experimental version-one supported surface; remaining helpers are Internal.

Caller-selected severity/status sets and a bounded maximum matching count form
the complete criterion. Explicit acknowledgement of unassessed completeness is
required. Labels are not ranked or combined into a risk score. Original four-role
source/run proof, exact saved-snapshot digest and fresh acceptance checks precede
selection. Only original current-run detections enter the predicate; unrelated
retained findings remain report facts and operator triage is preserved.

`EvaluateImageCriterion` requires both original typed captures, their exact
original VERSION prerequisite and six immutable execution acquisitions. Both
envelopes/streams and current paired grant acceptance must verify through their
existing owners. Exact source-derived image inventory, relations, observations
and current finding detections must exist in the complete owner-read saved model.
The explicit snapshot pin covers all model contents; a revision, namespace,
finding count or detached operation summary does not establish this proof. Only
current original SCAN detections enter the predicate, with saved operator triage;
processed no-findings inventory neither selects nor resolves historical facts.

The Internal `EvaluateNativeImageCriterion` consumer additionally verifies the
existing native Trivy candidate proof and the exact original in-process
`NativeImageAcceptance` handle. Persisted replay alone supplies no current
authority. The complete current saved native inventory and detections are
required, and saved status/reason remain authoritative. The unchanged result
shape accepts the precise original `native-scan:<64 lowercase hexadecimal>` run
identity alongside the existing `artifact-run:<32 lowercase hexadecimal>` form.

Zero matching findings cannot substitute for missing original processing proof.
The result describes selected-profile predicate satisfaction or violation, with
`scan_completeness: not-assessed`. This profile adds no reachable-risk rule,
scanner coverage claim, native execution grant or Core schema change. See
[CI scan](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/CI_SCAN.md).

::: fuzzy1337.ci_gate
