# Optional offline Trivy archive adapter

`fuzzy1337.adapters.trivy` is an Experimental optional SDK surface at version
`1`, defined by [ADR 0032](adr/0032-bounded-offline-trivy-archive-adapter.md).
It prepares and interprets one SAFE `image.archive-vulnerabilities` profile.
It does not install Trivy, provision databases or grant scan authority.

The supported CLI envelope is Trivy `0.75.x`; unsupported observed versions
are degraded and cannot prepare scans. An operator supplies a trusted executable and an isolated physical workspace
containing a finite local image archive and a pre-provisioned `trivy-cache`
directory (or explicit relative cache path). Requests contain exactly `archive`
(workspace-relative portable path) and `timeout_seconds` (integer 1–3600).
Traversal, symlinks, missing/non-file inputs, archives above 512 MiB, credentials,
raw flags and registry/daemon references fail closed. File/cache checks are
snapshots; protect the workspace against concurrent replacement.

`PrepareInvocation` selects native JSON output, vulnerability scanning, all
package records and zero scanner finding exit code. It disables implicit DB,
Java DB, checks, version and VEX updates, telemetry, plus dependency API lookups.
Explicit
`--config=` / `--ignorefile=` flags disable ambient configuration/ignore files, preventing ambient default files from changing the
profile. These options request offline behavior; they do not create a network
sandbox. The trusted binary/archive decoder remains outside 1337's isolation
promise. Registry and local daemon image references are deferred.

`CheckHealth` observes only a bounded local version command, with 3 seconds and
16 KiB capture. `ProbeHealth` additionally returns the exact bounded version JSON
bytes so callers can store them with true collection times as `provider-version`
evidence. Executable availability alone does not establish database availability.
Health disables config-file loading and inherits no process environment.
Trivy remains operator installed.

Scan executor environment and resource overlays are trusted upstream inputs.
The default executor environment excludes `TRIVY_*` settings; callers must not
inject provider configuration such as `TRIVY_SERVER` or `TRIVY_CACHE_BACKEND`.
The adapter cannot validate or sandbox arbitrary caller-supplied overlays, and
its offline argv profile does not guarantee isolation against them.

Execute a prepared scan only through the governed executor with exact caller-issued
`ExecutionAuthorization`. Persist stdout/stderr through `LocalEvidenceStore`
with actual invocation, execution and collection provenance. A successful
`NormalizeReport` needs exactly one `stdout` and one `provider-version` reference;
length and SHA-256 are independently checked. Replay reconstructs invocation
metadata without requiring the original archive/cache to still exist. Tool
version must match the version bound in the invocation. Any optional native
`Trivy.Version` must match independently captured version evidence. Vulnerability DB metadata must include a positive integer
`Version` and provider-observed `UpdatedAt`. Java DB metadata is optional. These
records preserve provider observations, not database-file attestation; callers
must keep the same cache revision for probing and scanning.

Native output requires schema `2` and artifact type `container_image`. The JSON
parser bounds output to 4 MiB, 65,536 nodes and depth 32; duplicate keys, malformed
UTF-8 and non-finite scalars fail. Unknown optional provider fields remain raw
immutable evidence; missing/null optional package/vulnerability arrays are empty.

Normalization emits `trivy.run`, `image.package` observations and
`image.package-vulnerability` generic SDK findings. Package/vulnerability
attributes retain provider fields for later provider-neutral correlation; this
adapter does not construct shared Security Object identities or persist state.
Failed, cancelled or timed-out reports preserve the original report and emit only
an incomplete diagnostic, even if their captured JSON looks complete.

Validation uses an owned synthetic Trivy-compatible executable. It exercises
actual bounded execution, evidence storage/hash verification and native parsing,
with explicitly synthetic version/database/vulnerability values. This is evidence
of the integration contracts, not real Trivy detection accuracy or live database
freshness. No real Trivy scan is claimed by those tests.
