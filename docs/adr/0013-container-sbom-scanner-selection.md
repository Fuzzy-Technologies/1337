# ADR 0013: Container and SBOM scanner selection

## Status

Accepted — 2026-09-16

## Context

M2 needs a local-first way to inspect container images and software bills of
materials without making a scanner, vulnerability database, registry, or cloud
service a mandatory startup dependency of 1337.

The first provider must produce machine-readable output, preserve the raw
report, identify its own version and data freshness, support a bounded local
image/archive workflow, and fit the existing Apache-2.0 Community repository.
It must also leave a clean interchange boundary for future provider diversity.

## Decision

Use **Trivy** as the first optional container-image and SBOM scanner provider.

- 1337 invokes a pinned external Trivy binary through the future ToolAdapter
  contract; it does not vendor Trivy code, templates, or vulnerability data.
- The first adapter accepts explicitly scoped local images, image archives, and
  supplied SBOM files. It does not contact a registry or update a vulnerability
  database unless an operator explicitly enables that behavior.
- The adapter preserves the exact argv, binary version, scanner configuration,
  database/cache freshness metadata where available, target identity/digest,
  exit status, and unmodified JSON output as immutable evidence.
- 1337 normalizes only stable provider-neutral facts into Security Objects,
  Findings, and Evidence. The raw Trivy report remains available for review.
- CycloneDX JSON and SPDX JSON are the initial interchange formats. A supplied
  SBOM is treated as source evidence with its own provenance; it is not assumed
  to be equivalent to an image scan.
- Cache and database locations are explicit, local, and rebuildable. Missing or
  stale data is an observable health/freshness result, never silent success.

Syft and Grype remain compatible future providers for independent SBOM and
vulnerability coverage. They are not installed or coupled to the M2 baseline
until a second concrete consumer justifies their maintenance cost.

## Evaluation matrix

| Candidate | License    | Image/SBOM scope                             | Machine output                        | M2 decision                     |
|-----------|------------|----------------------------------------------|---------------------------------------|---------------------------------|
| Trivy     | Apache-2.0 | Image, archive, SBOM, vulnerability, license | JSON; CycloneDX/SPDX interoperability | First optional provider         |
| Syft      | Apache-2.0 | Strong SBOM generation and inventory         | CycloneDX/SPDX/JSON                   | Deferred complementary provider |
| Grype     | Apache-2.0 | SBOM/image vulnerability matching            | JSON                                  | Deferred independent matcher    |

The selected tools are invoked as external programs. This decision grants no
authority to scan a remote registry, target, or third-party image without an
explicit authorized scope.

## Consequences

- Task #140 implements the Trivy adapter only after health, invocation,
  provenance, raw-evidence, parser, and failure contracts are specified.
- Task #141 normalizes provider-neutral image/package/SBOM facts and correlation
  keys; it must not make a Trivy JSON schema the 1337 domain model.
- Task #142 exposes the resulting bounded scan through Quick Scan and machine
  outputs without making it a base-install dependency.
- A future alternate provider must be testable against the same normalized
  fixture/evidence contract.

## References

- [Trivy container-image scanning](https://trivy.dev/docs/latest/target/container/)
- [Trivy SBOM scanning](https://trivy.dev/docs/latest/target/sbom/)
- [Trivy Apache-2.0 license](https://github.com/aquasecurity/trivy/blob/main/LICENSE)
- [Syft Apache-2.0 license](https://github.com/anchore/syft/blob/main/LICENSE)
- [Grype Apache-2.0 license](https://github.com/anchore/grype/blob/main/LICENSE)
