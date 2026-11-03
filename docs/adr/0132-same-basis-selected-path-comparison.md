# ADR 0132: Same-basis selected-path state comparison

## Status

Accepted for implementation of one bounded Experimental product profile under
#121. This decision does not complete the broader showcase or establish a
remediation's effectiveness. Required product evidence, independent review and
exact-head shared CI remain separate completion requirements.

## Context

The accepted `paths analyze` command verifies original selected assessments and
support against an explicitly pinned saved model, then presents attributed
transition states, candidate paths and independent structural cuts. Its offline
HTML renderer shows one selected state. The showcase also needs a readable
comparison around an explicitly selected change, without inventing a second
model, accepting reconstructed graph JSON or treating a state label as risk.

## Decision

Add `paths compare WORKSPACE` with one common exact model revision/content pin,
source, target, selected transitions, context, scope, analysis clock and all
existing search/freshness/cut budgets. The caller explicitly selects separate
before and after original assessment sets, or explicitly selects no assessments
for either side. One required focus transition must already be in the common
selected transition set.

Invoke the unchanged owning `RunPathCommands` twice with generated `analyze`
arguments and machine output. Admit no serialized graph file, arbitrary forwarded
arguments, hidden discovery, alternate evidence reader or reimplementation of
the solver. Both original analyses must complete successfully; retain their exact
detached outcomes, including different original proof references, reasons,
confidence facts, limits and separate completeness indicators. Failed or refused
analysis must not become a successful comparison. Reread the actual owning
workspace and model after both analyses and require the same original identity,
revision and content digest before successful output.

The selected transition identities and endpoints must agree. Only the focus
transition may have a different observed transition-state label. Zero changed
state labels is valid and is reported as no observed state change. A state
difference outside the focus transition exceeds this finite profile and is
refused. Equal labels do not imply equal evidence, confidence or other facts;
both complete original outcomes remain available.

Before/after are caller-selected presentation roles. The comparison does not
establish chronological lineage, that only one control changed, causality,
remediation efficacy, measured access, global completeness or calibrated risk.
In particular UNKNOWN remains UNKNOWN, absent support does not become zero risk,
and a structural cut count is not a probability or a mitigation benefit score.

The new comparison uses a separate machine outcome family and bounded stdout
presentation. Its maximum combined JSON is 3 MiB and maximum HTML is 8 MiB;
these limits belong only to the paired presentation and do not enlarge either
underlying one-MiB analysis or existing single-state renderer limits. Oversized
output refuses without a hidden output file. No model, workspace or evidence
write occurs, and no scanner, provider, daemon, network operation or execution
authority is introduced.

## Offline presentation

HTML contains separately labelled original static graphs, escaped original proof
panels and exact JSON/SVG downloads. Reuse the existing `GraphSvg` producer through
isolated SVG data images rather than concatenating interactive documents with
duplicate DOM IDs or modifying its fixed script. The comparison needs no new
JavaScript. Use a restrictive CSP with data images only, no external resources,
scripts, frames, forms or base URL. Keep original references and state words
visible without relying only on color. The existing interactive single-state
renderer and default `paths analyze` output remain unchanged.

`fuzzy1337.path_comparison_commands` and any separate comparison presentation
module are Internal. The version-one product route is additive; canonical model,
evidence, path solver and persisted schemas retain their current contracts.

## Verification and remaining scope

Use owned original-source fixtures to produce independent confirmed and blocked
assessment sets against the same saved model. Exercise the installed CLI, focus
change, no change, UNKNOWN, unrelated change refusal, failed proof, corrupt source,
relocation, final-basis drift, output ceilings and no-write/no-network guards.
Verify exact downloaded JSON/SVG bytes, safe hostile strings and static rendering
with JavaScript disabled. Direct synthetic presentation tests do not establish
source admission; the owning product scenario must do so separately.

Keep #121 open for its remaining grouping and broader typed showcase criteria.
#119, #122, #123 and #125 retain their independent scenario, perspective, runner
and acceptance requirements. This comparison supplies no replacement acceptance
for those tasks and no proprietary or general M5 UX architecture.
