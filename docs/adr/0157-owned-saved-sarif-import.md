# ADR 0157: Owned saved SARIF source import

- Status: Accepted for the owner-authorized bounded M6 IMPORT-only continuation
- Date: 2026-11-25
- Related work: #76, #71; ADR 0014, ADR 0020, ADR 0027, ADR 0039

## Context

Existing `report export --format sarif` serializes a canonical model. It does not
read third-party reports. The ToolAdapter report boundary attributes governed
executor facts, so an existing external file cannot be admitted by inventing an
invocation or successful execution. Vendor rules, source severity, suppressions
and baselines have no automatic first-party Finding/triage/risk mapping.

## Decision

Add the Experimental operator commands `bridge sarif import` and `inspect`.
The caller selects one existing non-sensitive local file, exact original SHA-256,
existing workspace/scope and explicit actor/read-consent references. Reuse
`ReadArtifactFile` and `ArtifactReadConsent`: no symbolic/hard-link traversal,
unstable copy or oversized source is accepted. No physical-file reader,
scanner or transport is created.

Strictly decode the whole original UTF-8 JSON before retaining any normalized
assertion. This is a consumed-fields-only SARIF 2.1.0 profile, not complete
OASIS schema/conformance validation. It retains literal declared tool/version,
driver rule/result indices, physical URI/base-ID/index declarations, line/column,
column-kind and original result/message/classification/suppression fields.
Missing fields stay null; missing/null results differ from an explicit empty
array. Preserve source run/result order and duplicate result occurrences.

Same-document indices may fill a source descriptor or artifact declaration;
they never locate files. Duplicate descriptor IDs are disambiguated by the
explicit index, with no first-ID match. Admit a rule ID equal to its descriptor
or with one additional slash-delimited hierarchical component. Preserve an
explicit rule index of -1 as no join. Negative artifact indices are outside this
closed profile. Literal URI/base-ID pairs must agree when both a direct URI and
an indexed URI are supplied; alternate equivalent URI spellings are not resolved.

Do not compute SARIF effective defaults or render Markdown/message templates.
In particular, omitted level/kind/version/columnKind remain source-null.
Do not turn source `error` into impact, source suppression into dismissal,
baseline absence into resolution, or a producer execution claim into an
`AdapterExecution`. No target, canonical Finding, score, model/workspace update
or second canonical store is introduced. Future first-party mapping is separate.

Every source URI/path/base ID, `$schema` and help/information URI is inert.
Never open a reported local source file, resolve a relative path against CWD,
retrieve a schema or follow a remote URI. External-property files, inline external
properties, nonempty tool extensions and component-rule references are unsupported
and refuse before a projection. No code flow, graph, fix or invocation command is
executed or interpreted as reachability/privilege authority.

## Bounds

| Domain                    | Fixed initial maximum                           |
| ------------------------- | ----------------------------------------------- |
| Original JSON             | 1 MiB                                           |
| Runs / total results      | 16 / 256                                        |
| Driver rules / artifacts  | 1,024 each per run                              |
| Locations / suppressions  | 16 each per result                              |
| Invocations               | 16 per run                                      |
| JSON nodes / depth        | 20,000 / 24                                     |
| Original / selected text  | 64 KiB / 4 KiB per UTF-8 string                 |
| Indices / coordinates     | Signed 32-bit ceiling; lines/columns start at 1 |
| Projected facts / receipt | 1 MiB / 64 KiB                                  |
| Terminal output           | 2 MiB after complete ASCII-safe expansion       |

Bounds refuse excess, never truncate a successful projection. Same-document
artifact joins have an independent projection budget to limit repeated URI
amplification. Complete output is staged before its one write attempt.

## Original custody and replay

Use the existing evidence owner only: original role `bridge-sarif-original`,
media `application/sarif+json`, and receipt role `bridge-sarif-import-receipt`.
Fixed collection provenance is `bridge.sarif-local` /
`sarif-2.1.0-local-v1`, with actual local-copy instants and no tool version,
invocation or execution outcome. Producer identity/version remain source claims.

Validate copy/pin/format before immutable publication. Publish unchanged original
bytes, then a closed `bridge-sarif-local-v1` receipt binding the original manifest,
hash, original read descriptions and deterministic projection digest. Original
and receipt acknowledgements remain independent. Failed/lost returns can follow
actual publication; no rollback, deletion, silent retry or usable partial
projection follows. This is not one atomic cross-owner transaction.

Inspection requires independently selected original/receipt manifests and SHA.
Preflight both manifest/profile/provenance/scope contexts before eager original
body reads; then use the unchanged owning Get/hash checks, exact receipt and
complete original reparse. A raw record alone supplies no import custody.
Copy/relocation and external-file deletion preserve replay without a new clock,
read grant, acquisition or owner write. Hash integrity authenticates neither
publisher, collector nor declared analysis truth.

## Verification

The pinned Microsoft SARIF tutorial's original ESLint file is an external sample,
not a round-trip through 1337 export. Retain its exact body/SHA and upstream
attribution/license beside a handwritten golden projection. Execute installed
file intake, copy/reopen after deleting the old workspace/input, exact inspection,
repeat, mixed receipt/wrong pin/corrupt original refusal and guarded no-network/
execution/source-file/owner-write checks. New modules require strictly above
80% combined statement/branch coverage in the passive gate and a separate real
noneditable-wheel acceptance. Unexecuted checks remain unexecuted.
