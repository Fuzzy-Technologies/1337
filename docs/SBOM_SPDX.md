# Verified SPDX package inventory

[ADR 0043](adr/0043-verified-spdx-package-inventory.md) defines an Experimental
offline SPDX 2.3 JSON package-inventory profile implemented by
`fuzzy1337.sbom_spdx`. It changes no accepted image/model schema.

## Supported interface

`SPDX_IMPORT_VERSION = 1` and `ApplyVerifiedSpdx(state, record, provenance,
image_identity, workspace_root)` form the supported surface. Other module
helpers remain Internal. Supply an existing `ModelState`, independently acquired
immutable `EvidenceRecord` with role `sbom`, matching `ModelProvenance`, an explicit
`ImageIdentity` and the owning workspace root. The producer verifies the manifest
and original bytes through the existing evidence store before interpretation.
Offline source attribution cannot contain a fabricated invocation or execution.

The return value is one `(ModelState, ModelDelta)` in-memory transition. Persist it
with the existing `LocalModelStore.Save` boundary when the caller chooses to save.
Parsing/profile/graph/provenance errors raise sanitized `ValueError`; existing
evidence integrity/storage failures retain their `EvidenceError` contracts.
The importer grants no target, artifact-execution or retrieval authority.

## Exact profile

The document declares `spdxVersion: SPDX-2.3`, `dataLicense: CC0-1.0`,
`SPDXID: SPDXRef-DOCUMENT`, a bounded name, an absolute namespace without a
fragment and valid creation declarations. Namespace and download URLs are data;
they are never fetched, registered as targets or used to resolve credentials.
Document creation time is a source claim; acquired model observation time must
match the verified evidence record's completion time.

Packages require unique bounded local SPDXRef identifiers and explicit
`filesAnalyzed: false`. File/snippet/annotation graphs, external document or
extracted-license definitions and signatures are unsupported. Creation/supplier,
description, sourceInfo, download/copyright and extension values remain raw.

Exactly one described package has `primaryPackagePurpose: CONTAINER` and one
SHA256 checksum matching the caller's explicit ImageIdentity. The root must be
selected consistently by `documentDescribes` and/or a local DESCRIBES relationship
(DESCRIBED_BY is its inverse). Multiple/contradictory described roots fail.
Each non-root package must have one explicit flat CONTAINS relationship from the
image (CONTAINED_BY is its inverse). All endpoints must resolve. Duplicate,
self-referential, package-to-package or unsupported relationship types fail;
DEPENDS_ON never becomes image containment.

Every non-root package supplies bounded name/versionInfo and exactly one
PACKAGE-MANAGER externalRef of type purl, using the existing versioned PURL
profile. Name/version must agree with the PURL. Other security/CPE/URL references
are not vulnerability detections and remain solely in raw evidence. Root-package
PURLs are unsupported because generic OCI PURL identity is outside the accepted
image hash-kind profile.

Declared/concluded license fields remain separate attributed facts. Missing,
NONE and NOASSERTION license values create no license entity. Bounded other
declared expressions reuse existing declaration assets; no expression validity,
license-list membership or compliance is claimed. LicenseRef/DocumentRef meanings
need a separate scoped identity decision and are rejected in this profile,
including case variants inside compound expressions.

## Bounds and interpretation

Use existing limits: 4 MiB JSON bytes, 65536 nodes, depth 32, 4096 collection
items, 2048-character identity text and 64 KiB model attributes. Scope local SPDX
aliases to the verified document digest. Cross-source package identities remain
versioned PURL identities, while the caller's config/manifest kind stays explicit.
An SPDX SHA256 checksum cannot determine whether a caller means an OCI config or
manifest. Equal checksum bytes with different declared kinds retain distinct
image keys; this profile verifies checksum equality, not that semantic claim.
No package/file checksum proves archive contents, signatures or completeness.

`spdx-source-alias` observations bind each original local ID to its canonical asset
through document SHA256 and image reference. `spdx-package-license` observations
carry separate declared/concluded `state` and optional `expression` fields with
the same scoped coordinate. Supplier/download/source text and creator identities
are retained only in raw evidence. Repeated aliases for one PURL correlate to one
package asset; aliases across different documents remain distinct source facts.

Exact replay is a no-op. Original evidence remains unchanged. Inventory creates
no Finding and changes no existing disposition. Existing license assets describe
declared expressions only; concluded expressions remain source observations.

## Independent fixtures and acceptance

Hand-authored synthetic fixtures describe config and manifest roots, namespaced
packages, opaque declared/concluded license differences and information states.
They are not output from an executed scanner. Contract tests resolve emitted
aliases against those fixtures; integration tests use real owned evidence/model
stores and verify cross-Trivy/CycloneDX/SPDX deduplication and portable reopening.

Adversarial tests cover malformed JSON/resource limits, provenance/time/hash
substitution, duplicate/dangling/remote IDs, ambiguous roots, unsupported graphs,
wrong PURL versions, license scoping and private-value traceback redaction.
Full SPDX validation, SPDX 3 JSON-LD, dependencies, OS inference, file graphs,
signatures, VEX, active scanning and new artifact-execution policies remain open.
