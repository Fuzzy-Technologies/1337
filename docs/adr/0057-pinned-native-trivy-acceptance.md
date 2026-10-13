# ADR 0057: Pinned native Trivy adapter acceptance

## Status

Accepted bounded acceptance design — 2026-10-13. Tasks #140/#142.
Actual native acceptance requires a passing exact-head `Genuine Trivy acceptance`
CI result with retained original evidence; an opt-in skip is not native acceptance.

## Decision

Validate the unchanged ADR 0032 `TrivyAdapter` and accepted low-level
`LocalExecutor` against the genuine upstream Trivy 0.75.0 Linux amd64 release and
one immutable official schema-2 vulnerability database snapshot. CI provisions
the checksum-pinned release and digest-pinned OCI database before scan isolation.
Selected executable and each database file receive separate observed SHA-256
receipts. The release archive checksum, binary checksum, database OCI manifest
digest, database file hashes, input archive checksum and image layer DiffID are
distinct identities and are never substituted for one another.

The repository-owned Docker-save builder creates a single inert metadata layer
with `requests` versions 2.30.0 or 2.31.0. The independent maintainer advisory
GHSA-j8r2-6x86-q33q / CVE-2023-32681 declares the former affected and latter fixed
for that advisory. These archives contain no Requests implementation, installed
package, exploit or synthetic provider output. Genuine Trivy performs image
decoding, package inventory and real database advisory matching. The negative
oracle excludes only the selected advisory; all other native results remain raw
and normalized evidence rather than being filtered to fabricate a clean scan.

Actual version/scan execution runs inside a Linux network namespace created by
CI, then drops back to the unprivileged runner identity. The test requires its
network namespace to differ from provisioning, only a loopback interface and no
external IPv4/IPv6 route. No live Internet probe is used to prove isolation.
Both native subprocesses inherit this namespace. Version probing retains the
existing empty-environment health boundary; scanning uses the exact unchanged
offline adapter argv and explicit owned home/config/cache/temp environment.
No provider credentials, registry target, daemon socket or arbitrary flags enter
the scan. Network acquisition during material provisioning is separate from scan
execution and contacts the explicitly pinned official release/database services.

Every owned scan uses the unchanged invocation-bound low-level executor request
and explicit test authorization. Actual stdout/stderr, terminal outcome,
invocation digest, observed collection times, version stdout, selected bytes and
network context are retained. Successful normalization requires the observed
provider version and database metadata. Cache database hashes match provisioning
before execution and remain unchanged afterward. Actual version-observed DB
schema/timestamps match selected cache metadata retained in the run document.
An additional genuine missing-DB
case must fail without download or successful empty interpretation. The current
health API discards version stderr and exposes health plus original stdout, not
a complete version execution receipt; this prerequisite does not claim otherwise.

## Boundaries

This is adapter/executor compatibility and known advisory matching acceptance,
not native product authorization. `ArtifactProfile.IMAGE` stays metadata-only;
the artifact SDK cannot issue native VERSION/SCAN grants. No guard is removed,
no source is relabelled and no fixture result is applied to durable native model
state. A future native artifact profile needs its separate current scope,
material, operation and paired acceptance contract before #142 product execution.

The owned archive has declared package metadata, not an installed or exploitable
Requests program. One pinned advisory boundary proves neither broad scanner
accuracy nor scan completeness. The intentionally historical database snapshot
is reproducible acceptance data, not a freshness guarantee or recommended live
database. Binary/DB pins detect selected bytes; they are not publisher signatures,
principal authentication or hostile concurrent-file attestation. The namespace
provides CI network isolation, not a product CPU/memory/filesystem sandbox.
No Trivy binary, database or third-party implementation is vendored, installed by
the base package or published to PyPI. Tasks #140/#142 remain open for their
remaining work and native product integration.

See [the acceptance guide](../TRIVY_ACCEPTANCE.md) for exact pins, commands and
retained evidence. ADRs 0013, 0032 and 0044 retain their existing production
contracts; the closed synthetic image CLI remains its separate accepted workflow.
