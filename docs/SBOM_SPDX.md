# Verified SPDX package inventory

[ADR 0043](adr/0043-verified-spdx-package-inventory.md) defines an Experimental
offline SPDX 2.3 JSON package-inventory profile. The initial profile/fixture commit
precedes the importer implementation. It changes no accepted image/model schema.

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
need a separate scoped identity decision and are rejected in this profile.

## Bounds and interpretation

Use existing limits: 4 MiB JSON bytes, 65536 nodes, depth 32, 4096 collection
items, 2048-character identity text and 64 KiB model attributes. Scope local SPDX
aliases to the verified document digest. Cross-source package identities remain
versioned PURL identities, while the caller's config/manifest kind stays explicit.
No package/file checksum proves archive contents, signatures or completeness.

The producer will return one immutable model update for LocalModelStore.Save;
exact replay is a no-op. Original evidence remains unchanged. Inventory creates
no Finding, changes no existing disposition and grants no execution authority.

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
