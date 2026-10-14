# ADR 0082: Owned offline SPDX graph product import

## Status

Accepted bounded product implementation decision — 2026-10-14.
Advances #141 and #138 over the unchanged SDK contract in ADR 0073.

## Decision

Add explicit `1337 sbom import spdx-graph WORKSPACE` over
`ApplyVerifiedSpdxGraph`. The operator selects a caller-owned non-secret file,
actor/read-consent descriptions, source ID/version and optional declared provider
version; or an independently pinned original product acquisition manifest.
Image SHA256 and `config`/`manifest` kind, existing offline scope, run reference
and both current revision bases are always required. The SDK creates the image
through its existing identity owner; scope is workspace-local attribution as in
the accepted offline runtime importer. This adds no target/allow rule, collection
permission or execution grant.

Before original file reads, validate current model/workspace revisions, scope
ownership and workspace object references. File reads enforce the existing
four-MiB SDK ceiling, regular non-following paths, single-link ownership and
closed descriptor ownership. Full same-path and same-handle physical identities
must remain stable. The existing Windows path-versus-handle ctime tolerance
applies only across those two views.

Retained replay requires a known `sbom-import-source` observation independently
bound to the selected original manifest ID. Its image identity/kind, original
scope/source/time/provider fields, run and read descriptions are preserved.
Context substitutions and file-mode overrides fail before selected raw reads.
An arbitrary SDK raw-only acquisition has no product image/run/read custody and
is refused by this closed product replay admission; its direct SDK interface
remains unchanged.

Before generic owning evidence verification in either mode, preflight every
known original SBOM blob's actual four-MiB size and all same-SHA or same-locator
aliases in workspace metadata, model provenance and retained acquisition
manifests. Known model custody IDs remain independently verified even when an
earlier workspace reference save failed. Original source/scope/provider contexts
stay intact; older scopes are checked through their own workspace-local owner.
Aliases preserve each original role, media type and size. Unrelated non-SBOM
evidence retains its existing generic owner budgets. Metadata checks allocate no
selected raw bytes; original manifest identity stays distinct from content SHA256.

Apply the unchanged SDK transition, then fold the inert product custody fact
into that same in-memory revision. Save through the existing model CAS owner and
independent workspace CAS owner, retaining all original references and prior
finding disposition. Reopen current bases between phases and before success.
Exact original replay is a no-op, including after workspace relocation.

## Acknowledgements

Acquisition, model and workspace publication each retain an independent state:
`not-attempted`, `unknown`, `confirmed`, or an explicit CAS `not-committed`
refusal. A lost acknowledgement remains unknown even when bytes were actually
committed. A later failure preserves earlier confirmed owners and actual durable
state; this importer claims no atomic cross-store transaction or rollback.

Exit zero requires confirmed completion. Configuration refusal is two,
integrity/normalization/storage failure or uncertainty is four, and interruption
is 130. Diagnostics contain fixed categories and safe metadata, excluding
selected paths and original source contents.

## Preserved contracts

SPDX graph normalization, canonical package/image identities, source array
coordinates, inverse direction, shared aliases, direct containment, descriptive
dependency cycles, inert license facts and original unredacted evidence remain
owned by their existing SDK contracts. Existing findings and operator triage
remain intact. Dependency reachability stays UNKNOWN without separately verified
assessments. This adds no scanner, archive extraction, daemon/registry access,
remote retrieval, compliance evaluation, inferred score or Core schema change.
