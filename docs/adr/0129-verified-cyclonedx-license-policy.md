# ADR 0129: Verified original CycloneDX license-policy projection

## Status

Accepted — 2026-11-03

## Context

M4 task #377 retains broader source semantics after the accepted SPDX policy
slice in ADR 0125. The existing ADR 0040 owner accepts bounded CycloneDX 1.6 JSON
inventory, preserves original evidence and normalizes package/license assets.
Those shared assets cannot identify every original license occurrence or decide
whether separate source entries mean a conjunction, a choice or a legal result.

## Decision

Add the Internal `fuzzy1337.cyclonedx_license_policy` read-only function
`EvaluateVerifiedCycloneDxLicenses(state, record, provenance, image_identity,
workspace_root, policy)`. It accepts the existing exact model/evidence/provenance,
image and caller-authored `LicensePolicy` types. No CLI, Stable/Experimental
interface, saved model, schema, source field or native provider changes.

Verify original role, manifest, bytes, workspace, scope, source, provider version
and acquisition time through `VerifyRecords`. Reuse `ApplyVerifiedCycloneDx` to
validate the complete existing CycloneDX 1.6 inventory/root/package/alias profile;
discard its in-memory candidate and never save it. Retain original source SHA-256
and acquisition manifest ID separately. Caller-supplied config/manifest semantics
remain explicit; equal digest bytes do not infer another digest kind.

Project only existing accepted top-level components, their original `bom-ref`,
canonical versioned PURL package identity and each source `licenses` occurrence.
Keep component and license indexes, including repeated canonical packages under
distinct local aliases. Do not join normalized license assets or borrow facts
from another image/source. Include the complete supplied provenance and explicit
image/source identity with the bounded transient result. The Internal projection
profile is `cyclonedx-1.6-original-license-policy-v1`; it does not replace the
unchanged `spdx-expression-policy-v1` matcher.

For an exact `{expression: TEXT}` choice, reuse the complete existing expression
matcher. For an exact `{license: {id: TEXT}}` choice, require the existing single
`LicenseIdentifier` grammar before applying that matcher. An ID containing an
operator cannot become an expression. Keep original text and source field
separately from normalized atom decisions. License-list membership, compatibility
and exception/version equivalence remain unassessed.

Additional source choice/license keys remain raw evidence and yield explicit
`unknown` with reason `unsupported-license-choice`; do not interpret unapproved
role, name, URL or license-text fields. Invalid choices already rejected by the
existing inventory owner refuse the whole operation. Omitted and empty license
lists produce separate explicit unknown rows, with no invented assertion.
Source role is `not-classified`: this projection does not relabel CycloneDX
statements as SPDX declared/concluded facts. Report every original occurrence
independently; never infer `AND`, `OR`, select a license or aggregate a component,
package or image verdict. A policy match is not legal compliance or a Finding.

Retain the owner's four-MiB source and finite JSON/item budgets. Allow at most
4096 total projected rows, counting each omitted/empty component once and each
license occurrence once. Bound the complete canonical JSON result to one MiB.
A limit, malformed source or integrity failure raises a fixed `ValueError` or the
existing `EvidenceError`; no partial result is returned. Existing source strings
remain data; consumers must escape them when rendering.

## Finite projected-field matrix

| Source coordinate                      | Selected meaning                              | Unsupported or missing state       |
| -------------------------------------- | --------------------------------------------- | ---------------------------------- |
| `metadata.component.hashes`            | Existing owner binds selected SHA-256 root    | Existing owner refusal             |
| `components[*].bom-ref`                | Original local source alias and array index   | Existing owner refusal             |
| `components[*].purl`, name and version | Existing canonical package identity           | Existing owner refusal             |
| `licenses[*].expression` only          | Existing complete expression matcher          | Unsupported syntax is unknown      |
| `licenses[*].license.id` only          | One syntactic identifier atom                 | Compound/unsupported ID is unknown |
| Additional choice/license fields       | No additional role or semantic interpretation | Unknown for that occurrence        |
| Omitted or empty component licenses    | Original information state                    | Separate explicit unknown rows     |
| Root licenses and other raw fields     | No package-license assertion                  | Not projected                      |

## Consequences

- Existing callers and default SPDX/image command output remain unchanged.
- Original-evidence verification performs local reads only. There is no network,
  daemon/cluster collection, model/evidence publication or new authority.
- Deterministic source-occurrence results work after workspace relocation and
  deletion of the original selected file. They retain caller policy digest,
  image kind, acquisition ID, source digest and source-time attribution.
- This adds one finite source-policy row to #377. Other versions/formats,
  scoped license resolution, obligations, layer/file attribution and live runtime
  correlation remain outside this slice; #377 stays open.

## References

- [ADR 0040: Verified image/package owner](0040-verified-image-package-normalization.md)
- [ADR 0125: Existing explicit expression policy](0125-sbom-license-expression-policy.md)
- [CycloneDX 1.6 schema selected by ADR 0040](https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json)
