# ADR 0007: Pytest-native functional test harness

## Status

Accepted — 2026-09-09

## Context

1337 needs reproducible black-box functional tests against only
repository-defined isolated targets. Ad-hoc Compose commands cannot provide
reliable scenario setup, readiness, cleanup, raw evidence, or failure diagnosis.

The M0 synthetic lab supplies an internal-only safe target. M1 needs a harness
that can exercise this target locally and in CI without introducing Internet
targets or bypassing test ownership.

## Decision

Functional tests are pytest-native.

- Scenario metadata declares the target provenance and version, capabilities,
  setup, health check, assessment profile, expected observations/findings,
  timeout, and cleanup.
- Pytest fixtures own Docker Compose startup, deterministic health checks,
  scenario exposure, teardown, and raw command evidence.
- Target-backed tests run only against repository-defined Docker services.
- When Docker Compose is unavailable, target-backed tests explicitly skip.
  Ubuntu CI is required to run them with Docker available.
- Raw lifecycle records are written to ignored local state and retained by CI
  when available for failure investigation.

## Consequences

Future target packs, scanner scenarios, known-answer oracles, and accuracy
metrics reuse one lifecycle and scenario contract. A skipped local test is not a
successful target validation; CI evidence remains required before review.

The harness does not make the safe M0 target a scanner benchmark and does not
authorize testing external systems.
