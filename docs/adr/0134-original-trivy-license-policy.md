# ADR 0134: Original native Trivy license-occurrence policy

## Status

Accepted — 2026-11-03

## Decision

Add Internal `fuzzy1337.trivy_license_policy.EvaluateVerifiedTrivyLicenses`
with exact existing model, report, provenance, evidence tuple and explicit
`LicensePolicy` inputs. This read-only historical projection admits only the
existing successful `native.trivy/image.archive-vulnerabilities` schema-2
container-image profile with observed Trivy 0.75.* metadata. It grants no current
execution authority and does not replace six-role native capture/receipt replay.

Preflight the exact three original roles before reading: stdout JSON at most
4 MiB, stderr text at most 1 MiB, and provider-version JSON at most 16 KiB.
Use the existing native bounded evidence store to apply those limits to actual
stored manifests before eager raw reads. Require immutable manifest equality,
`VerifyRecords` and complete `ApplyVerifiedTrivyImages` admission; discard the
candidate and never save. Preserve existing source owners and shared limits.

The transient `trivy-0.75-original-license-policy-v1` result retains config-domain
image identity, all three acquisition IDs, original stdout digest, provider
version, invocation/execution and complete supplied provenance. Project original
result/package/license array coordinates and canonical package references. Equal
hash manifest aliases never replace the config identity; repeated packages and
strings remain distinct. Target paths and unrelated original fields stay in raw
evidence rather than this projection.

Evaluate each original string independently with the unchanged finite expression
matcher. Original native text is not asserted to be validated SPDX and receives
`source_role=not-classified`. Omitted, null and empty license lists produce
separate explicit unknown rows. Unsupported expressions and unconfigured atoms
remain unknown. No sibling conjunction/disjunction, package/image aggregate,
license selection, legal-compliance verdict or Finding is produced. Any later
owner-invalid inventory field refuses the complete operation.

Keep existing source/JSON/item and policy limits. Add module-local ceilings of
4096 rows (each missing/null/empty package counts once) and 1 MiB complete
canonical result JSON. Preflight all row counts; bound incremental canonical
output growth and refuse without a partial result. Empty packages produce an
empty occurrence list without an allow verdict. Offline evaluation after complete
workspace relocation uses original evidence and performs no network or writes.

## Consequences

No CLI, saved schema, model migration, collector, source acquisition or public
compatibility contract changes. Synthetic owning-store tests establish SDK
behavior, not genuine Trivy execution or external-publisher acceptance. Broader
#377 formats, layer/file attribution and live runtime correlation remain open.
