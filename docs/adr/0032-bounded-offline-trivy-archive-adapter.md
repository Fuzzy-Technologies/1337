# ADR 0032: Bounded offline Trivy image archive adapter

## Status

Accepted — 2026-10-11

## Context

Task #140 needs a concrete optional consumer of the accepted adapter, executor
and immutable evidence SDKs. ADR 0013 selects Trivy; image/package domain
correlation (#141), Quick Scan orchestration (#142), registry authorization and
local daemon integration remain separate work.

## Decision

Introduce Experimental `fuzzy1337.adapters.trivy`, version `1`, with one SAFE
`image.archive-vulnerabilities` capability. The supported CLI envelope is Trivy `0.75.x`; unknown versions fail explicitly.
Operators supply the trusted external
binary, an isolated physical workspace, one finite local image archive and a
pre-provisioned offline database cache. No dependency, executable or database is
installed by importing or constructing the adapter.

Preparation validates existing workspace-relative files/cache paths without
traversal or symlinks, a 512 MiB input limit and a 1–3600 second timeout. Fixed
shell-free argv selects JSON vulnerability scanning, disables dependency API
lookups and database/Java/check/version/VEX updates and telemetry, and explicitly disables
configuration/ignore files with `--config=` and `--ignorefile=`. Registry references, daemon access, raw flags,
credentials, configuration overlays and implicit downloads are absent.

The bounded local health exception runs only a version JSON command. It returns
executable health and exact finite stdout for caller-owned immutable evidence
storage. Version availability is not proof that vulnerability databases exist.
Successful scan normalization requires verified `stdout` and `provider-version`
evidence, schema-v2 `container_image` JSON, observed tool version and vulnerability
DB metadata. DB metadata is the provider's observation, not a hash/attestation
of actual database files; callers must preserve true collection provenance and
prevent cache replacement between collection and scanning.

A separate existing executor requires an exact invocation-bound authorization.
The adapter never issues authorization, starts target scans, persists evidence,
updates Security Objects or computes first-party risk. Finite strict JSON parsing
rejects duplicate keys, non-finite values and byte/node/depth budget violations.
Failed/timed-out/cancelled execution yields only an incomplete diagnostic and
preserves terminal facts and raw bytes; it never yields successful findings.
Successful packages/vulnerabilities are immutable generic SDK proposals retaining
provider attributes. Future #141 consumers own provider-neutral identities.

## Consequences

- Owned synthetic producer bytes prove the real executor → evidence → parser
  pipeline without claiming a genuine Trivy image scan or current database.
- The initial delivery is deliberately partial #140: local daemon image refs,
  registry targets and first-party SBOM/correlation behavior are deferred.
- Path checks are snapshots, not filesystem isolation against concurrent changes.
  Operators must protect the workspace/cache from untrusted cooperating writers.
- The executor bounds time and captured output; CPU, memory, decompressed image
  size and network sandbox enforcement remain outside this adapter's guarantee.
  A malicious operator-selected binary is outside the trust model.
- Executor environment/resources remain trusted upstream selections. Arbitrary
  caller-injected `TRIVY_*` configuration is outside this offline profile and may
  change provider behavior; no environment policy or network sandbox is added.
- Current CLI flags/schema follow official Trivy documentation. Genuine installed
  binary/archive compatibility remains an explicit unexecuted acceptance boundary.

## References

- [Image CLI](https://trivy.dev/docs/v0.75/guide/references/configuration/cli/trivy_image/)
- [Version CLI](https://trivy.dev/docs/v0.75/guide/references/configuration/cli/trivy_version/)
- [JSON reports](https://trivy.dev/docs/latest/guide/configuration/reporting/)
- [Offline operation](https://trivy.dev/docs/v0.55/guide/advanced/air-gap/)
- [Provider version fields](https://pkg.go.dev/github.com/aquasecurity/trivy/pkg/types#VersionInfo)
