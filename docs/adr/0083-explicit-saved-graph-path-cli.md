# ADR 0083: Explicit saved-graph path CLI

- Status: Accepted
- Date: 2026-10-14
- Decision owners: Fuzzy Technologies
- Related work: #55, #56; ADR 0047 and ADR 0066

## Context

The accepted reachability owner verifies original offline supplied attestations
against an exact saved model. Pure path analysis retains their original states,
proofs, uncertainty and independently bounded structural checks. A product caller
currently must compose those owners in Python. The next bounded product slice
needs one explicit read-only command without inventing attack semantics, source
support, semantic groups, authority or persisted analysis objects.

## Decision

Expose Experimental `1337 paths analyze`, profile version 1, over one selected
existing workspace. Require the exact expected saved revision and canonical
snapshot digest, distinct original source/target references, explicit existing
directed transitions, attribution context/scope, an aware analysis clock, freshness
and all finite search/cut budgets. Require original assessment manifest pins or
explicit `--no-assessments`; omission cannot become an inferred graph/source default.
Use the existing offline attribution rules. The analysis clock and stored source
provenance confer no current target, file-read or execution grant.

Validate actual selected manifests, their original identity/profile/context and
physical byte ceilings before their raw reads. Preflight all selected assessment
manifests before reading the first assessment body. Parse bounded declarations
through the existing SDK parsers, then preflight all declared supporting manifests
and retained observation joins before reading support bodies. Original roles and
format/provider versions remain distinct. Missing basis/evidence and temporal or
acquisition unusability remain for the SDK's honest UNKNOWN outcome; substitution
is refused. Check actual sizes, observed single links, physical parent/file kinds
and stable metadata/assessment read identities, reusing the existing Windows
path/handle allowance. No generic report reader enumerates unrelated same-blob
aliases. Original stored artifacts are never repaired, relabelled or overwritten.

Call the unchanged `ReadReachabilityClaims`, then `ProjectReachability`, then
`AnalyzeReachabilityPaths`. Their actual owners construct every sealed output;
no JSON-reconstructed claim/projection is admitted. Verify the full saved model
pin before those owners and reread current workspace/model before returning.
Preserve complete-workspace relocation and the existing cooperative local
pathname storage boundary. Make no SDK, model/evidence schema or authority change.

Render a detached one-MiB explanation containing original transition states,
reasons/proof references, individual supplied/effective confidence estimates,
original returned paths/barriers, participation and single-removal counts.
Incrementally account for repeated output records and refuse oversized results
without a partial analysis DTO. Keep search truncation/completeness separate from
independent cut-work truncation/completeness, witnessed route existence and
verified/alternative/unverified removal candidates. No raw evidence, observation
attributes or private seals appear. Human output explains the two completeness
results. Shell routing stays foreground with protected command-name history.

Write nothing durable, acquire no evidence, discover no missing graph/source,
run no scanner/process/network request and create no hidden output. Structural
counts and selected-graph cuts imply no probability, calibrated score, physical
reachability, mitigation efficacy or global completeness. The first grammar
accepts no semantic groups and only one explicit source/target pair.

## Verification and consequences

Compare an independently handwritten two-path/two-cut graph against the actual
handler and installed console. Exercise original six-phase source fixtures,
explicit unassessed UNKNOWN, unusability reasons, retained-source and model
tampering, relocation, pre-read wrong-profile/context/join/physical refusal,
separate truncation, finite output and no-write/no-network tripwires. Run only
focused parallel checks during implementation; the PR owns the full gate.

This advances #55/#56 and leaves both open for their unimplemented acceptance.
Existing SDK source support, schema, grouping, score and authority boundaries stay
unchanged. New source profiles, automatic grouping, sensor validation,
large-environment partitioning and multielement/cost/risk planning require their
own accepted decisions. No PyPI publication or release work is included.

## References

- [Attributed reachability ADR](0047-attributed-offline-reachability-projections.md)
- [Pure path-analysis ADR](0066-explainable-selected-graph-path-analysis.md)
- [Product usage](../PATHS_ANALYSIS.md)
