# Verified local SPDX graph claims

[ADR 0073](adr/0073-original-local-spdx-graph-claims.md) defines a separate
Experimental SPDX 2.3 JSON graph profile. The existing
[flat inventory](SBOM_SPDX.md) remains unchanged and continues rejecting nested
containment and dependencies.

## Interface and custody

`SPDX_GRAPH_IMPORT_VERSION = 1` and `ApplyVerifiedSpdxGraph(state, record,
provenance, image_identity, workspace_root)` are the supported surface of
`fuzzy1337.sbom_graph`. Other helpers are Internal. Supply exact first-party
typed inputs, independently acquired immutable evidence with role `sbom`,
matching offline acquisition provenance, an explicit image identity and the
owning workspace root. Subclasses and structurally invalid mutated frozen fields
fail before evidence reads. Original immutable manifest identity and source bytes are
verified through `LocalEvidenceStore`; normalized bytes cannot substitute for
original evidence.

The result is one `(ModelState, ModelDelta)` in-memory transition. Persist with
`LocalModelStore.Save(updated, expected_revision=state.revision)`; its existing
CAS check protects against stale saved bases. The importer grants no collection,
retrieval, artifact-execution or native authorization. No producer execution
receipt or scan outcome is fabricated. Original evidence and existing finding
disposition are retained. Exact verified replay is a no-op, including after
saving, reopening and moving the owning workspace.

## Bounded profile

Envelope, unique local package IDs, `filesAnalyzed: false`, exactly one matching
versioned PURL for each non-root package, name/version agreement and unsupported
semantic fields follow the flat inventory contract. One consistently described
CONTAINER root requires exactly one matching SHA256 checksum. The caller's
config/manifest kind stays explicit; a generic checksum verifies equality only.
Equal checksum bytes with distinct kinds retain distinct image identities.

The accepted relationships are DESCRIBES, CONTAINS and DEPENDS_ON, with
DESCRIBED_BY, CONTAINED_BY and DEPENDENCY_OF normalized to their forward direction.
Description must link the document to its image root; other edges must resolve
to local packages. Duplicate normalized coordinates, self-referential local IDs,
dangling/external endpoints and other relationship kinds fail. NONE/NOASSERTION
relationship endpoints are unsupported. These guards apply atomically.

Explicit containment must form a rooted directed acyclic graph covering every
package. Nested containment and multiple parents are permitted. Canonical PURL
alias collapse must preserve acyclic containment. The importer emits only the
direct source containment edges; it does not flatten nested contents into new
image edges. Dependencies do not admit disconnected packages into image inventory.

Dependency cycles and dependencies whose different source aliases resolve to
the same package remain source claims. Existing RELATED_TO relations carry
`association: spdx-dependency-claim` in source-to-dependency direction. They prove
no runtime reachability, installed dependency completeness, exploitability or
transitive relation. File graphs, extracted licenses, external documents,
annotations, signatures, vulnerability/VEX graphs and specialized dependency
types remain unsupported.

Limits remain 4 MiB original JSON, 65536 nodes, depth 32, 4096 array items,
2048-character identity text and 64 KiB model attributes. Traversal is iterative
and bounded by the accepted catalog; no remote or package-manager lookup occurs.

## Source facts and licensing

Existing `spdx-source-alias` and `spdx-package-license` observations add the
original `evidence_id` beside `document_sha256`, `image_reference` and `spdx_id`.
Canonical packages reuse existing image/native/CycloneDX/flat-SPDX identities.
Repeated source aliases remain separate facts on one package asset.

Each direct source containment/dependency edge has a
`spdx-relationship-claim` observation on the canonical relation. Its fields bind
the original manifest/content/image, `relationship_index`, `original_source_id`,
`original_type`, `original_target_id`, normalized `source_id`,
`relationship_type`, `target_id`, `source_reference` and `target_reference`.
Consumers can resolve the index directly against retained original JSON and
recover inverse direction. Distinct aliases may contribute separate original
claims to one canonical relation. No duplicate relation fact is manufactured
from a direct/inverse duplicate coordinate because that input is rejected.

Declared and concluded licensing stays separate. Absent, NONE and NOASSERTION
create no license asset. Other bounded declared expressions reuse existing
license declaration assets; concluded expressions stay observations. No SPDX
expression validation, license-list membership or compliance is asserted.
LicenseRef/DocumentRef expressions remain rejected, including case variants.
Arbitrary creation, supplier, download, source, relationship comments and
security locators remain raw-only evidence.

## Acceptance evidence and remaining scope

Handwritten owned synthetic graph and independent identity/edge oracle fixtures
exercise nesting, inverse direction, shared PURL aliases, dependency cycles and
license states. Unit/contract tests cover strict resource budgets, unsupported
graphs, canonical collapse, exact typed/mutated inputs, source/manifest mismatch
and pure-transform I/O tripwires. Integration exercises actual raw acquisition,
verified application, CAS save, reopening, relocation, replay, cross-source
package linkage and retained owner triage. Fixtures are not executed scanner
output. Broader formats, layer/file attribution, real runtime/scanner coverage
and license evaluation remain outside this slice of #141.
