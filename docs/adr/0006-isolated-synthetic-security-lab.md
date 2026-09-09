# ADR 0006: Isolated synthetic security lab

- Status: Accepted
- Date: 2026-09-08
- Decision owners: Fuzzy Technologies
- Related issue: #11

## Context

1337 needs a deterministic environment for future scanner, evidence, graph, and
report validation. Internet demo targets and arbitrary private-network hosts are
not reproducible and must never become implicit authorization for security tests.

## Decision

The public repository owns an isolated synthetic security lab under `labs/`.

- M0 starts with only a safe deterministic HTTP health target.
- Lab services join the internal `synthetic-lab` Docker network and publish no
  host ports.
- Lab containers run unprivileged, read-only, with dropped Linux capabilities
  and `no-new-privileges`.
- Target families for web, API, network, identity, and attack-path testing have
  stable repository locations, but M0 does not supply vulnerable applications or
  scanner correctness claims.
- The Compose lifecycle and safe-target health contract are exercised in CI.

## Consequences

Future black-box scenarios, known-answer oracles, vulnerable application packs,
and regression scoring must extend this repository-owned boundary. They must not
substitute public demo systems or external hosts.

The lab does not authorize any activity outside its synthetic containers. A
passing M0 target health check proves only target lifecycle and isolation, not
scanner detection accuracy.
