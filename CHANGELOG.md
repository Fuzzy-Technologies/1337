# 1337 Security Workbench Changelog

1337 Security Workbench Changelog — a chronological record of product development, documenting key features, fixes, architectural changes, optimizations, limitations, security boundaries, and release-relevant results for each version.

# Major 0

Major 0 — the pre-stable 1337 Security Workbench line, establishing the Community foundation, development contracts, security boundaries, core workbench experience, and the path toward the first stable release.

## Minor 0.1

### Patch 2 — v0.1.2 — 2026-09-08

#### Digest

- Made the Python bootstrap installable and established reproducible developer quality gates for issue #8.

#### Added

- Installed `1337` help/version and `1337-dev` quality-command entry points.
- Pinned build/development tools, a hashed dependency lock, and a packaging architecture decision.
- Strict type checks, branch coverage, and an executable per-module coverage gate requiring more than 80%.
- Failure-path unit tests, public manifest contract tests, and clean wheel-installation integration tests.

#### Fixed

- Explicit package selection now builds `fuzzy1337` from the `1337` distribution.
- Developer command descriptions and execution now share one registry; the full gate runs every declared check.
- Development commands no longer advertise a formatter outside the approved house-style contract.

#### Security

- Missing coverage reports/modules, invalid measurement data, and undocumented exclusions fail the quality gate.
- Developer subprocesses use argument arrays, bounded execution, and explicit failure propagation.

### Patch 1 — v0.1.1 — 2026-09-07

#### Digest

- Completed the M0 governance baseline for branch/release handling and public extension compatibility.
- Added a versioned machine-readable extension manifest contract without exposing implementation-private boundaries.

#### Added

- Canonical branch/release workflow covering protected branches, normal development, release branches, deterministic SemVer tags, hotfixes, and back-merges.
- Public Compatibility Contract v1 with Stable/Experimental/Internal surfaces, schema-version rules, deprecation policy, and extension-consumer requirements.
- JSON Schema Draft 2020-12 extension manifest v1 plus a validating public example.

#### Changed

- README development references now link the release workflow, compatibility policy, and machine-readable public contracts.

#### Security

- Unsupported security-sensitive contract versions are required to fail closed rather than be guessed or silently downgraded.
- Public extension manifests explicitly exclude secrets, credentials, license material, and machine-local absolute paths.

### Patch 0 — v0.1.0 — 2026-09-07

#### Digest

- Established the initial public Community repository identity for 1337 Security Workbench by Fuzzy Technologies.
- Added the first repository-level development, agent, security, language, Git, and changelog contracts before implementation work begins.

#### Added

- Root `AGENTS.md` as the mandatory entry point for AI agents and automation.
- Root `DEVELOPMENT_PROTOCOL.md` with the initial Python house style, branch/review flow, test discipline, evidence rules, and strict documentation contract.
- Minimal project README, security-reporting policy, ignore rules, and agent prompts.

#### Security

- Default automated security testing is limited to repository-defined synthetic/local targets unless the owner explicitly authorizes another target for the specific task.
- Secrets, unrelated local data, sibling repositories, and out-of-scope filesystem locations are excluded from agent scope.
