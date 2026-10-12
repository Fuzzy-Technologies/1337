# ADR 0040: Verified offline image and package normalization

## Status

Accepted — 2026-10-13

## Context

Task #141 needs durable image/package correlation through the existing Security
Object Model, evidence store and Finding lifecycle. A tag is mutable, an OCI
manifest digest differs from a configuration digest, and a vulnerability affecting
one package version must not be associated with another installed version.
Offline interpretation must not imply authorization to execute a scanner.

## Decision

Add Experimental `fuzzy1337.images`, contract version 1. Keep the existing model
schema and ObjectKind enum unchanged. ASSET identities use domain-separated keys
for image configuration digests, image manifest digests, package versions,
operating systems, layer DiffIDs and declared licenses. Image digest kinds remain
distinct; related config/manifest records are provider-observed associations,
not cryptographic verification of archive contents or multi-platform selection.

Support verified Trivy schema-2 archive reports and CycloneDX 1.6 JSON documents
with an explicitly bound SHA-256 container root. No process, registry, daemon,
CLI command, network lookup or additional persistence store is introduced.
CycloneDX root-hash semantics are an explicit caller mapping; the reader does not
infer whether a root hash denotes an OCI manifest or configuration.

Validate raw evidence integrity and its manifest ownership, source, scope,
version, terminal state and exact invocation digest before preparing any update.
Scanner success and independently collected database provenance are required
for Trivy imports. An SBOM is interpreted as inventory, without inventing scan
execution or a vulnerability verdict. Unsupported formats/structures fail closed.

Package identities prefer bounded Package URL fields, including installed version
and distribution/architecture qualifiers. The initial profile supports versioned
PURLs with arch/distro/os/os_version qualifiers and no subpath. Ecosystem-specific
name equivalence beyond PyPI normalization is deferred; sources must otherwise
use canonical package names. Native packages without PURLs use ecosystem, OS,
name, version and architecture together to avoid cross-distribution conflation.

Each image contains package-version objects. Exact vulnerability-to-package
matching produces existing canonical Findings, shared across image origins of
the same package, with separate evidence-linked image observations. Detector
replay retains operator disposition. Resolved/dismissed findings require explicit
operator reopening through the existing Finding lifecycle.

Only finite whitelisted identity/advisory/license fields enter normalized state.
Raw environment, descriptions, credentials, arbitrary properties, file paths and
command histories remain in immutable source evidence. Provider strings are
untrusted data and downstream renderers must escape their output.

## Consequences

- Repeated imports deduplicate objects, relations, findings and observations.
  Additional origins retain their own provenance in the same canonical model.
- Config and manifest digest references can be used by later runtime/Kubernetes
  ingestion without using tags as authoritative identities.
- Raw bytes are preserved; an import writes no files and returns a snapshot for
  the existing LocalModelStore to save atomically.
- SPDX and other CycloneDX versions, signature verification, archive decoding,
  complete SPDX-expression evaluation and runtime discovery remain separate work.
- Local artifact execution-policy support is not implemented or bypassed here.

## References

- [CycloneDX 1.6 JSON schema](https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json)
- [Package URL specification](https://www.packageurl.org/docs/purl/introduction)
- [Trivy JSON reporting](https://trivy.dev/docs/v0.75/guide/configuration/reporting/)
