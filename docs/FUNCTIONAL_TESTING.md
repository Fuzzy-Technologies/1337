# Functional testing

## Purpose

Functional tests execute an assembled 1337 behavior against repository-owned,
isolated targets. They do not use Internet demo systems or authorize testing of
any target outside the repository synthetic lab.

## Running the suite

Run the suite from the repository root:

```bash
uv run --locked --extra dev pytest tests/functional
```

Docker Compose is required for target-backed scenarios. When Docker Compose is
not available, target-backed tests are explicitly skipped; they are not reported
as passed. Ubuntu CI must run the same tests with Docker available.

## Scenario contract

Each container-backed scenario is declared in `tests/functional/scenarios.py`. It records:

- target identifier, provenance, version, and Compose service;
- required capabilities;
- setup and cleanup commands;
- deterministic health check;
- assessment command and impact profile;
- expected observations and findings;
- timeout.

`web-safe.health` proves the harness against the safe M0 target. It is not a
scanner-accuracy claim. `web-micro.contract` is the first known-answer pack:
its routes and simulation markers are explicit inputs for future TP/FP/FN/TN
metrics. Its canaries never execute commands, access files, make outbound
requests, or persist uploads.

`attack-path-mini` keeps a data-only graph scenario as its versioned contract and
adds a repository-owned executable lab. Five isolated containers realize the exact
Internet-to-business-event identifiers through controlled HTTP service hops. The
functional suite confirms the canonical path, proves the signing-key path remains
policy-blocked, applies identity hardening, verifies the resulting path break, and
resets the state. No host port or external target is used. This proves the lab and
oracle boundary without claiming that the later production graph engine is already
implemented.

Target-backed tests own a shared Compose lifecycle and are marked `serial`.
They execute after the independent pytest worker pool rather than competing for
containers, ports, or generated functional evidence.

## Lifecycle and evidence

Pytest fixtures own startup, health checks, teardown, and raw command evidence.
Each Compose command writes a JSON record under `functional-evidence/`; this is
generated local state and must not be committed. CI retains the directory when
available so a failed lifecycle can be investigated from its actual stdout,
stderr, argv, and exit status.
