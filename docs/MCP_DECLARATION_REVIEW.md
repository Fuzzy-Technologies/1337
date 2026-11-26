# MCP declaration review

The Experimental review API compares an explicitly selected [MCP inventory](MCP_INVENTORY.md)
with the current operator-approved snapshot for the same workspace and server.
The selected snapshot and baseline can originate from separately verified
offline imports or approved HTTP metadata acquisitions.
Every review verifies the original redacted evidence manifests, their content
addresses and the historical observations that bind their declaration digest
and membership. It reads independent acquisitions of the same server from
immutable snapshots rather than the latest projection of a descriptor.

## Operator decisions

An operator inspects a verified acquisition and calls `ApproveMcpBaseline`
with its server reference, snapshot reference, operator reference, a unique
approval reference, decision time, and expected model revision. The first
decision establishes a baseline explicitly. Import and review do not create
an approval.

`ReviewMcpDrift` accepts the model, server reference, selected snapshot
reference, and expected model revision. For each resulting review, inspect the
changes, unknowns, and `reviewReference`. To advance the baseline, pass that
exact `reviewReference` with the reviewed snapshot to `ApproveMcpBaseline`.
The review must have used the current approval and the same selected snapshot.
Use fresh model CAS revisions after a rejected concurrent update. The
approval history retains the prior decision, exact snapshot revision and
digest, operator, and selected review. Replaying identical decision details
verifies the original snapshot and any supporting review before returning the
existing decision, including after a later approval takes effect.

The operator and approval references are explicit local attributions.
Baseline approval governs future metadata comparisons. Scope and capability
authorization keep their existing owners.

## Review outcomes

| Status        | Meaning                                                              |
| ------------- | -------------------------------------------------------------------- |
| `no-baseline` | A verified snapshot was selected before the first operator approval. |
| `unchanged`   | The compared declarations contain no proven change or coverage gap.  |
| `unknown`     | A membership section is partial or a known value cannot be compared. |
| `drift`       | At least one change is proven by the compared declarations.          |

Tools, resource URIs, and resource templates are compared by stable workspace
object identity. Membership is known from an observed declaration or absence
from an explicitly complete section. `incomplete`, `unsupported`, and
`unknown` leave unlisted membership undecided. This allows a positive change
and an unknown section to coexist.

For tools present in both snapshots, the review compares retained input-schema
structure and explicit side-effect hints. Schema changes carry fingerprints
and paths relative to the input schema. An array difference is represented
by its array path. Absent hints and instructions remain unknown. Omission on
both sides is recorded and allows an otherwise unchanged result. A declared
value opposite an unknown value makes that comparison incomplete. Server
instructions are compared solely as redacted fingerprints.

Tool output schemas, presentation text, prompts, capability declarations, and
non-locator resource metadata are outside this review profile. The importer
normalizes unordered declaration lists and retains order where a supported
schema keyword gives it meaning.

## Findings and evidence

Known changes produce informational findings with stable check IDs and
model object references. Confidence refers to the retained declaration
comparison. Unknown coverage produces no finding. The derived redacted
evidence retains both acquisition manifests, snapshot digests and references,
scope and acquisition times, the baseline decision, structural changes, and
unknown fields. It contains no original instructions, resource locators, or
redacted input-schema literals.

A successful review appends its review observation and findings in one model
CAS. Repeating a review of the same baseline decision and selected snapshot
verifies the existing evidence and retains the same model and finding history.
An independent evidence publication can remain after losing the model CAS.
A fresh review against the same selection reuses the immutable evidence.
