# ADR 0002: Container-first development baseline

- Status: Accepted
- Date: 2026-09-08
- Decision owners: Fuzzy Technologies
- Related issue: #10

## Context

1337 needs a reproducible development and quality environment across supported
host operating systems without making a host IDE, a local Python installation,
or a host package cache part of the product contract. The early bootstrap also
needs a safe boundary that the synthetic lab can extend without adding remote
targets or security-testing capability.

## Decision

The M0 baseline uses a repository-owned Dockerfile and Compose file.

- The image starts from the supported CPython 3.11 Debian slim family and
  installs the already pinned `uv==0.11.33` tool.
- Dependency resolution uses the committed `uv.lock` and fails when it is
  stale.
- The container executes as an unprivileged `workbench` user after image
  preparation.
- `compose.yaml` defines a persistent `workbench` service for interactive
  development and a one-shot `quality` service for the canonical
  `1337-dev check` gate.
- The development source is mounted only by Compose at `/workspace`; the
  virtual environment is kept outside that mount at `/opt/1337/.venv` so the
  container image remains usable with or without a bind mount.
- Compose supports an explicit unprivileged host UID/GID mapping for writable
  source mounts rather than relaxing the container to root.
- The baseline accepts only repository-local source and later repository-owned
  synthetic targets. It does not define a remote scan target, credential, or
  external service dependency.

## Consequences

Developers can use Docker Engine or Docker Desktop to run the same locked
quality command on Linux, Windows, and macOS. The host-native `uv` workflow
remains supported for fast feedback. Functional scenarios and vulnerable target
packs are deliberately deferred to their own tracked work; this decision adds
only the safe container boundary they require.

The Python base-image tag is intentionally centralized in the Dockerfile build
argument. Before a release, CI/release work must record a reviewed immutable
image digest for the selected tag; this M0 bootstrap does not claim an already
verified long-term image mirror.
