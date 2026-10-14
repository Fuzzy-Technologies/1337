# ADR 0073: Original local SPDX graph claims

- Status: Accepted
- Date: 2026-10-14
- Related work: #141, #138, ADR 0040, ADR 0043

## Context

The verified SPDX 2.3 inventory owner intentionally accepts only complete flat
image containment. Nested package containment and dependency claims are useful
source facts, but silently accepting them in that profile would weaken its
existing rejection contract. Local source identities can also collapse onto one
canonical package after PURL correlation, changing graph structure.

## Decision

Add the separate Experimental `fuzzy1337.sbom_graph` owner and explicit
`ApplyVerifiedSpdxGraph` opt-in. Preserve the flat parser, image/package identity
owners, Core schema, native authorization, finding triage and evidence/model
stores. The exact supported profile is in [SBOM graph](../SBOM_GRAPH.md).

Reuse strict SPDX envelope, local identifiers, versioned PURL identity and inert
license interpretation from the existing owner. Require one checksum-bound
CONTAINER root with caller-declared config/manifest semantics. Checksum equality
does not verify OCI content or prove digest-kind equivalence.

Accept only local DESCRIBES, CONTAINS and DEPENDS_ON relationships and their
inverses. Reject duplicated normalized coordinates. Containment must form a
rooted directed acyclic graph covering every package, including after canonical
package aliases collapse. Dependencies never establish containment. Dependency
cycles remain descriptive claims; they imply no runtime reachability,
exploitability, vulnerability verdict or transitive dependency relation.

Represent direct containment with existing CONTAINS edges and dependencies with
existing RELATED_TO edges carrying `association: spdx-dependency-claim`. Preserve
each accepted direct containment/dependency claim in an observation bound to its exact original
manifest ID, content digest, image context, JSON-array index, original direction
and normalized local/canonical endpoints. No new store or source-generated
execution receipt is introduced.

Revalidate exact typed model/evidence/provenance/image inputs at admission,
verify the original owning manifest and raw bytes, then apply one in-memory
transition. The caller retains the existing CAS save responsibility. Pure
transformations perform no filesystem, process or network operations.

## Consequences

- Existing flat-profile rejection guards and public contract remain unchanged.
- Declared/concluded licenses and absent/NONE/NOASSERTION states remain separate
  source facts. Only declared expressions create existing license assets;
  scoped LicenseRef/DocumentRef definitions and compliance evaluation stay out.
- Unconsumed creator, download, supplier, comment and security-reference data
  stays in original evidence. No URLs are fetched or authority granted.
- Acceptance includes handwritten graph/identity oracles, original acquisition,
  verification, normalization, save/reopen/relocation/replay and preserved triage.
- This advances a bounded subset of #141. General SPDX graphs, other formats,
  file/layer attribution, license evaluation and broader real runtime coverage
  remain open.

## Primary reference

- [SPDX 2.3.1 relationships](https://spdx.github.io/spdx-spec/v2.3.1/relationships-between-SPDX-elements/)
