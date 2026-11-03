# ADR 0125: Explicit source-bound SBOM license-expression policy

## Status

Accepted — 2026-11-03

## Context

M4 task #377 continues the broader SBOM semantics deliberately deferred from
the accepted M2 image inventory. Existing license assets preserve opaque source
declarations; SPDX observations already separate declared/concluded expressions
and omitted/NONE/NOASSERTION states. A caller needs a reproducible way to compare
these source assertions to an explicit local policy, retaining the distinction
between a source statement, a configured preference and license compliance.

## Decision

Extend the Experimental read-only `sbom image` command with opt-in
`--license-policy ID`, repeated `--allow-license ATOM` and `--deny-license ATOM`.
At least one atom is required. The Internal profile is
`spdx-expression-policy-v1`; its result appears only when explicitly selected.
The existing command's default output and all saved schemas remain unchanged.
The pure `license_policy` implementation is Internal, not a supported SDK.

Bind the finite grammar to SPDX **2.3.1 Annex D**, not an unspecified latest
SPDX release. Operators are uppercase `WITH`, `AND`, `OR`; identifiers match
case-insensitively. Adjacent `+` is part of an exact atom. Precedence is `+`,
`WITH`, `AND`, `OR`, with bounded parentheses. Only ASCII identifiers and spaces
are accepted in this selected one-line profile. Identifiers have at most 128
characters excluding `+`; expressions have at most 2048 UTF-8 bytes, 128 tokens
and 16 nested parentheses. Scoped LicenseRef/DocumentRef, invalid or unsupported
syntax and exceeded budgets return `unknown` with no partially evaluated atoms.
This is a syntactic profile, without an SPDX license/exception database or a
claim that an identifier belongs to an official list.

Caller policy contains at most 64 unique exact atoms, with a bounded non-path ID.
Conflicting, duplicated or compound entries refuse configuration. Normalize
identifier case and declaration order; return the complete normalized policy
and SHA-256 of its canonical JSON fields, including its versioned profile and ID.
A `WITH` pair is a complete distinct atom: a rule for its base license does not
approve or deny the exception pair. `+`, `-only` and `-or-later` spellings do not
inherit another atom's decision or imply version compatibility.

For `AND`, any denied conjunct means `deny`, all allowed conjuncts mean `allow`,
otherwise `unknown`. For `OR`, any allowed alternative means `allow`, all denied
alternatives mean `deny`, otherwise `unknown`. Parse the complete expression
before returning a result. These values describe only the caller's configured
syntactic rule; they do not choose a license, establish compliance or produce a
Finding. Preserve every normalized atom decision even when one determines the
expression result.

The product projection supports only original owned SPDX 2.3 local-graph imports
from ADR 0082. Select canonical packages through the unchanged exact image
containment view, then join each license observation to that **same** image
reference, original acquisition manifest, document digest, local SPDX alias and
provenance. Require the manifest in the saved workspace, revalidate its original
product custody and manifest/source context, and reparse the unchanged original
bytes through the existing `GraphCandidates` owner. The exact license
observation and source aliases must match the reconstruction. Reuse one parse
per source/context; allow at most 64 such contexts and 4096 assertion/package
rows, within the unchanged one-MiB total output ceiling.

Evaluate declared and concluded source roles independently. Preserve original
observation references, acquisition IDs, raw-source digests and SPDX aliases in
the output. Source absent/NONE/NOASSERTION states remain `unknown`. Older flat
SPDX observations without original graph custody remain explicitly unsupported;
other inventory sources without a selected supported assertion remain unknown.
Do not borrow another image's assertions through a shared package, a license
asset or an equal-byte config/manifest alias. Do not aggregate assertions into a
package or image compliance result.

## Consequences

- Operators can inspect a repeatable explicit policy match from retained original
  evidence, including after relocation and deletion of the original input file.
- The command retains preflight, complete evidence verification, original-source
  limits, basis-change refusal, safe diagnostics and truthful nonzero failures.
  It performs no collection, network request, source transformation or write.
- Native/CycloneDX/flat-SPDX policy projection, SPDX 3 grammar, scoped license
  identities, license-list validation, obligations, legal/compliance conclusions,
  broader SBOM formats and live runtime correlation remain outside this slice.
  Task #377 stays open.

## Primary specification

- [SPDX 2.3.1 Annex D: License expressions](https://spdx.github.io/spdx-spec/v2.3.1/SPDX-license-expressions/)
