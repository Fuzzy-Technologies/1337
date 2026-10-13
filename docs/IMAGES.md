# Verified image and package normalization

`fuzzy1337.images` is an Experimental contract at version `1`, defined by
[ADR 0040](adr/0040-verified-image-package-normalization.md). It interprets already
collected, verified local evidence through the existing Security Object Model and
Finding lifecycle. It does not execute a scanner, contact a registry, access a
daemon, grant authorization or create another persistence store.

The native boundary verifies evidence and observed version metadata before its
Internal `TrivyCandidates` helper constructs the existing object, relation,
observation and Finding batch. This helper performs no evidence reads or model
application and does not expose a namespace or authority override. The supported
native signature, three roles and version record without execution facts remain
unchanged. The separate synthetic importer uses original typed VERSION/SCAN
proofs through the operation-aware artifact SDK, with its own live and read-only
historical boundaries. See the [consumer contract](SYNTHETIC_IMAGE_IMPORT_DESIGN.md)
and [assembled closed image workflow](IMAGE_WORKFLOW.md).

The Internal `SyntheticTrivyCandidates` helper prepares a detached batch in the
fixed `synthetic.trivy:owned-synthetic-image-wire-v1:` asset namespace. It rewrites
all relations, observation subjects and image references, and uses the distinct
`synthetic.supply-chain.vulnerability` Finding check. It neither admits evidence
nor applies or saves model state. Native import behavior is unchanged; live
six-role synthetic ingestion still requires the reviewed producer/consumer path.

## Identity and correlation

`ImageIdentity(digest, digest_kind)` requires lowercase `sha256:<64 hex>` and an
explicit `config` or `manifest` kind. These identify different ASSET objects,
even when their digest strings are equal. Tags and filesystem paths never become
image identities. Native Trivy ImageID selects the config identity; RepoDigests
create manifest assets linked by an attributed provider-reported association.
This does not attest archive contents or select a platform from an image index.
Later runtime consumers can reuse `ImageIdentity.Object(workspace_id)`.

`PackageIdentity` binds ecosystem, namespace, name, exact installed version and
distribution/architecture qualifiers. Repeated versioned PURLs share one package
asset across image origins and tools. The initial PURL profile supports only
`arch`, `distro`, `os`, `os_version` qualifiers and no subpath; percent encoding and
qualifier order are canonicalized. PyPI names use its published separator/case
normalization; other ecosystems require canonical source names. This profile is
not a complete PURL specification implementation. Native fallback identities
include OS version and architecture; they do not infer equivalence with a PURL.
Native epoch and release participate in installed-version correlation.
Native package names, versions and source ecosystems must agree with their
PURLs. The result-type aliases below map to the listed PURL types; other native
types require literal PURL type equality. When native `Arch` is supplied, its
exact value must also be present in the PURL `arch` qualifier. A contradictory or
missing qualifier fails instead of collapsing architecture-specific identities.

| Native result types                                 | PURL type |
| --------------------------------------------------- | --------- |
| python-pkg, pip, pipenv, poetry, uv, pylock         | pypi      |
| node-pkg, npm, yarn, pnpm, bun                      | npm       |
| jar, pom, gradle, sbt                               | maven     |
| gobinary, gomod                                     | golang    |
| bundler, gemspec                                    | gem       |
| rustbinary, cargo                                   | cargo     |
| alpine, chainguard, wolfi                           | apk       |
| debian, ubuntu                                      | deb       |
| redhat, centos, rocky, alma, amazon, fedora, oracle | rpm       |
| suse, sles, photon, cbl-mariner                     | rpm       |

This is a bounded source-classification profile, not complete Trivy/PURL type
equivalence. Unsupported native aliases must be added explicitly before they
can be paired with a different PURL type.

Existing CONTAINS/RELATED_TO relations connect images, package versions, OS,
declared licenses and layer DiffIDs. Layer order remains an evidence-attributed
observation. Config-layer DiffIDs are not distribution-blob digests. Declared
license strings/expressions are preserved without a license-compliance verdict.

## Verified native Trivy reports

`ApplyVerifiedTrivyImages(state, report, provenance, records, workspace_root)`
accepts successful `native.trivy` archive reports at the reviewed `0.75.x` /
adapter-`1` envelope. Supply explicit immutable EvidenceRecord manifests for
exactly stdout, stderr and independently collected provider-version JSON.
The import verifies each manifest identity and bytes through the owning
workspace's LocalEvidenceStore, then validates workspace, scope, source, tool
version, exact invocation SHA-256 and terminal execution. Model observation time
must match stdout collection completion; the version/DB probe precedes the scan.
Preserve the same cache revision between probing and scanning: times and provider
metadata do not attest database-file identity or freshness.

Native JSON requires schema 2 container_image metadata with ImageID. Provider
version, DB version/update time and optional native Trivy.Version must agree.
Each vulnerability must match exactly one installed package identity in its
result catalog, including PkgID where present. Wrong or ambiguous versions fail
closed. Findings use the existing Finding contract and retain evidence-linked
image-origin observations. Existing operator disposition remains unchanged on
re-detection. Reopening a closed disposition is an explicit TransitionFinding
operation; inventory import does not make that decision.

## Separate synthetic Trivy-format reports

`ApplyVerifiedSyntheticTrivyImages(state, version_proof, scan_outcome,
scan_prepared, scan_stage, records, workspace_root, *, context_provider)` accepts
only the closed `owned-synthetic-image-wire-v1` family and `synthetic.trivy`
source. It derives original SCAN provenance from six immutable acquisition
manifests, verifies both original operation capture envelopes and their exact
request/stage/grant/prerequisite bindings, then constructs the complete candidate
batch. The canonical SDK facade refreshes both original grants after all
evidence/candidate work; subsequent application uses pure `ApplyFindings` without
another evidence read. This boundary neither launches nor saves/publishes state.

Every config/manifest image, package, OS, layer and license key has the literal
`synthetic.trivy:owned-synthetic-image-wire-v1:` prefix. Finding checks use
`synthetic.supply-chain.vulnerability`; all relation/observation/Finding subjects
and the `image_reference` attribute stay inside that family. Matching digest/PURL
hints do not create native associations or attribute overlays. Existing synthetic
triage survives later accepted collections, and all entire colliding native
assets/provenance/dispositions remain unchanged.

`VerifySyntheticTrivyImageReplay(records, workspace_root)` separately verifies
original saved schema-2 receipts, strict capture/request/stage shapes, original
SDK replay digests, actual stream facts, collection chronology and package wire.
It returns immutable original SCAN `ModelProvenance`. It reads no current physical
stage, performs no live acceptance, issues no grant and saves/applies nothing.
Relocation keeps original receipt paths and bytes; it does not revive authority.
Legacy schema-1 artifact replay remains the artifact owner's original-shape
contract and cannot be upgraded into this richer image proof.

Synthetic inventory observations and reports retain `scan_completeness:
not-assessed`, including no_findings. The worker emits explicit fixture proposals;
these tests establish neither genuine Trivy/database compatibility nor detection
accuracy. Task #142 remains open for native acceptance.

## CycloneDX inventory

`ApplyVerifiedCycloneDx(state, record, provenance, image_identity, workspace_root)`
supports flat CycloneDX 1.6 JSON package/license inventory. The source must have
role `sbom`, matching immutable attribution and no invented scan outcome. Model
observation time must match verified document collection completion. The container
root needs exactly one SHA-256 hash matching the supplied ImageIdentity.
The caller declares whether that root hash denotes a config or manifest; the
reader cannot infer OCI hash semantics from a generic SBOM component hash.

Library/application/framework components need unique bom-ref values and matching
name/version/versioned PURLs. Namespace-qualified npm/Maven/Go names and explicit
CycloneDX groups must agree with their PURL identities.
Nested component profiles fail explicitly; dependency-graph semantics and SBOM
vulnerability interpretation are deferred. An inventory is not a successful
vulnerability scan or a claim that all packages/vulnerabilities were covered.
SPDX and other CycloneDX versions remain unsupported.

## State, bounds and trust

Imports return an immutable ModelState and one ModelDelta transition. Save through
the existing LocalModelStore with the original expected revision. Exact replay is
a no-op; additional image origins/source evidence merge attributable history.
Validation failure writes no state or evidence. Original tool/document bytes
remain unchanged in the evidence store.

JSON is limited to 4 MiB, 65,536 nodes and depth 32; collections are additionally
limited to 4,096 items and identity text to 2,048 characters. Duplicate keys,
non-finite values, malformed encoding, unsupported structures and inconsistent
provenance fail closed. Only whitelisted identity/advisory/license fields enter
normalized state. Arbitrary descriptions, environments, credentials, properties,
paths and command histories remain solely in raw evidence. This field selection
does not detect secret values placed in otherwise valid identity fields; callers
must supply non-secret metadata. Renderers must escape provider text.

Validation uses explicitly synthetic Trivy-format and CycloneDX data, real owned
workspace/evidence stores and model persistence. Tests cover repeated imports,
multiple image origins, installed-version mapping, disposition/reopening,
redaction of arbitrary fields, manifest corruption/provenance substitution and
strict parser/resource failures. No real scanner, database or external target is
claimed by these fixtures. Local-artifact execution-policy support remains a
separate acceptance boundary and is not bypassed using loopback authorization.
