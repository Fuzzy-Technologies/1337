# ADR 0112: Read-only verified image inventory and Docker use view

## Status

Accepted — 2026-10-29

## Context

Task #141 already has canonical image/package identities, verified native image
normalization, bounded CycloneDX/SPDX inventory and an installed original SPDX
graph importer. Owned Docker inspect import already reuses the same config image
identity and records explicit configured-image-use associations. Operators need a
small product interface to inspect this existing cross-source linkage.

## Decision

Add Experimental `1337 sbom image WORKSPACE --image-digest DIGEST
--image-digest-kind {config,manifest}`. Its implementation module
`fuzzy1337.image_sbom_view` and schema-one result are Internal. It creates no
additional persistence, model schema, relation, observation or finding.

The command preflights known original SBOM custody, role/media/size aliases and
the four-MiB original limit through the existing SBOM owner. It then uses
`OpenReportInput` to verify saved workspace/model attribution, scopes, original
acquisition manifests and complete retained source bytes under the existing
report quotas. Saved model and workspace snapshots must remain equal across
verification and projection. Success identifies the observed model revision and
canonical snapshot SHA-256; it does not promise isolation from future writers.
Output is bounded to one MiB and is withheld on failure.

The exact selected config/manifest identity must exist and agree with its image
attributes. Traverse only original CONTAINS edges to package assets, iteratively
with a visited set. Return unique package references and original containment
relation references. Do not manufacture transitive edges or treat dependency
claims, another image, licenses, OS objects or layers as package membership.
No supplied package membership means inventory status `unknown`; observed
membership means `observed`, without a completeness or vulnerability verdict.

Return only existing RELATED_TO associations from the selected config image with
`association: configured-image-use`, `basis: supplied-inspect` and a Docker
container endpoint whose explicit `image_reference` agrees. An equal-byte
manifest identity cannot borrow config inventory/use through a provider alias.
Each use returns its existing container/relation references, runtime reachability
`unknown` and reason `not-evaluated`. The view does not evaluate reachability
assessments or infer package execution, vulnerability exposure or exploitability.

## Consequences

- Operators can inspect accepted image/SBOM inventory and explicit owned Docker
  correlation through the installed product, resolving original references in
  the saved model and evidence-linked reports.
- Queries perform no selected source acquisition, scanner execution, live runtime
  discovery or write. Invalid configuration exits 2; refused state/evidence or
  quotas exit 4; interruption exits 130. Rejected paths and values stay out of
  failure diagnostics.
- Existing imports, replay, digest semantics, original custody and operator triage
  remain owned by their established interfaces.
- Additional formats, layer/file attribution, license evaluation, live runtime
  acquisition and Kubernetes image/workload correlation continue in
  [M4 task #377](https://github.com/Fuzzy-Technologies/1337/issues/377).
