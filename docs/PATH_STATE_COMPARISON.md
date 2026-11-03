# Compare selected path states

`1337 paths compare` reads two explicit original assessment selections against
one exact saved model. Each side passes through the unchanged
[`paths analyze`](PATHS_ANALYSIS.md) evidence and analysis owners. The comparison
writes no model, workspace or evidence and performs no collection or execution.
This is an Experimental version-one product profile; its Python implementation
modules are Internal.

## Explicit common basis

Both sides share the original workspace/model revision and content digest,
source, target, selected transitions, context, scope, analysis clock, freshness
limit and all search/cut budgets. The command accepts no serialized graph file
or alternative model. Select one `--focus-transition` from the common original
transition set.

Select before and after assessment manifests independently. For either side,
use repeated `--before-assessment` or `--after-assessment`, or its explicit
`--before-no-assessments` or `--after-no-assessments` alternative. Each manifest
must belong to the actual owning workspace and pass the existing original
source, support, integrity and attribution checks. There is no implicit default
assessment discovery.

The following command is a template. Replace the model/object/relation values
with exact current references from an existing workspace. The no-assessments
example deliberately compares two unassessed selections and can report no
observed state change; it does not manufacture evidence.

```text
1337 paths compare WORKSPACE --json \
  --expected-revision MODEL_REVISION \
  --expected-snapshot-sha256 LOWERCASE_64_HEX_DIGEST \
  --source object:SOURCE_DIGEST --target object:TARGET_DIGEST \
  --transition relation:TRANSITION_DIGEST \
  --focus-transition relation:TRANSITION_DIGEST \
  --before-no-assessments --after-no-assessments \
  --context CONTEXT_REFERENCE --scope-reference SCOPE_REFERENCE \
  --as-of 2026-11-03T00:00:00Z --max-age-seconds 3600 \
  --max-depth 16 --max-paths 64 --max-work 4096 \
  --max-frontier 1024 --max-cut-work 100000
```

Use `--html` instead of `--json` for a standalone static comparison. Output is
stdout; redirect it explicitly if a file is wanted. The command creates no hidden
output file. Conflicting formats, repeated scalar options and abbreviated options
are refused.

## Meaning of the comparison

The separate `paths.compare` outcome retains both complete original analyze
outcomes, the focus transition and zero or one observed transition-state
difference. Only the focus relation may differ in its state label. A different
state on another selected relation exceeds this first finite profile and is
refused. Equal labels can still have different original claims, support,
confidence or reasons; both outcomes retain those differences.

Before and after are explicitly selected presentation roles. Their order does
not prove chronology or that a control caused a result. The command establishes
neither that only one control changed nor remediation effectiveness. It derives
no compromise probability, risk ranking or benefit score. UNKNOWN remains an
attributed unknown; it never becomes a zero-risk or measured-access result.

Each side retains its own candidate-path enumeration completeness, cut-check
completeness and original reasons. Truncated path counts do not establish all
possible access routes. A structural cut is a fact about the selected symbolic
graph, not proof that a physical remediation works. The actual workspace and
model are reread after both analyses; changed basis refuses the pair.

## Offline artifact and fixed limits

HTML shows separate Before and After static graphs, complete escaped proof
panels, state words and line patterns. Each graph is an isolated SVG data image;
no new JavaScript is required. Exact comparison JSON and both original static
SVGs can be downloaded. A restrictive CSP refuses external resources, scripts,
frames and forms. The existing interactive single-state renderer remains
available through `paths analyze --html`.

The underlying analysis, evidence and model limits remain unchanged, including
32 assessment manifests per side and the existing one-MiB analyze outcome.
Presentation allows at most 64 nodes and 128 transitions per side. The paired
JSON is capped at three MiB including its newline, and comparison HTML at eight
MiB UTF-8. These are separate paired-output limits; the existing single-state
HTML ceiling remains four MiB. Oversized results refuse rather than silently
omitting a proof, edge or selected node.

Exit 0 means both analyses and the bounded comparison completed, including an
honestly truncated analysis or no observed state change. Exit 2 indicates invalid
configuration; exit 4 indicates basis, original-proof, comparison-profile or
output refusal; exit 130 indicates interruption. A failed second side cannot
produce a successful first-only pair or partial HTML.

[ADR 0132](adr/0132-same-basis-selected-path-comparison.md) defines this finite
boundary. The broader #121 renderer/showcase task remains open, as do the
independent real scenario, pipeline, runner and performance acceptance tasks.
