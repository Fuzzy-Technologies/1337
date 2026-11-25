# ADR 0153: Offline installed extension manifest validation

- Status: Accepted for the owner-authorized M9 structural consumer operation
- Date: 2026-11-25
- Decision owners: Fuzzy Technologies
- Related work: #90; Compatibility Contract v1

## Context

The wheel supplies the sole canonical Stable v1 extension schema and example.
An external integrator needs to check one local manifest through the installed
product without cloning the repository or implementing another schema checker.
The current contract requires consumer validation but deliberately leaves
implementation locator resolution and activation to later decisions.

## Decision

Add Experimental `extension validate <manifest>` to the existing console,
module and interactive-shell dispatch. Use the existing pinned
`jsonschema==4.26.0` through optional `1337[validate]`; mandatory runtime
dependencies remain unchanged. Read the installed distribution's force-included
canonical schema. Do not maintain another copy or fall back to checkout files.

Validate the trusted schema and the admitted instance with Draft 2020-12 and
an empty `referencing.Registry` without a retrieval callback. Only the
packaged schema's in-memory fragment references resolve. Instance `$schema`
and schema-looking members never select resources. Do not resolve entry points,
import extensions, evaluate Core ranges, register plugins, open a workspace or
perform network operations. Do not tighten the Stable v1 version pattern or
claim that schema validity establishes full SemVer conformance.

Bound local input before validation to 64 KiB, 4,096 JSON value nodes and depth
32. Refuse ambiguous duplicate object members, invalid UTF-8/JSON, non-JSON
constants and non-finite parser results. These are consumer-profile operational
refusals, distinct from schema invalidity; they do not revise the schema.

Return fixed failure codes and at most 64 keyword/JSON-pointer diagnostics with
explicit truncation. Omit exception messages and rejected values. Record the
original admitted input and canonical schema digests. Reserve exits 0/1 for
schema-valid/schema-invalid, 2 for setup/input refusal, 4 for schema failure,
and 130 for interruption. Preserve these semantics across console, module and
shell entry points. Treat this output as Experimental profile one, not a public
Python SDK. Exclude manifest arguments from shell history like other private
local-file commands. The cmd.Cmd callback spelling requires one exact naming
baseline entry; no general exemption is added.

## Verification

Compare acceptance with the actual unchanged v1 schema, including legacy version
patterns, numeric integer semantics, closed objects and uniqueness. Exercise
input limits and distinct operational failures. Build a wheel and install it
outside the checkout: base help works without the optional validator, actual
validation refuses honestly, and the declared optional extra enables ordinary
console/module validation. Audit-denied network/process/import and source-directed
file operations prove that source schema and implementation locators remain
inert. Shared final-head CI remains the integration gate.
