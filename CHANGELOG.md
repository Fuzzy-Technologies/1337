# 1337 Security Workbench Changelog

1337 Security Workbench Changelog — a chronological record of product development, documenting key features, fixes, architectural changes, optimizations, limitations, security boundaries, and release-relevant results for each version.

# Major 0

Major 0 — the pre-stable 1337 Security Workbench line, establishing the Community foundation, development contracts, security boundaries, core workbench experience, and the path toward the first stable release.

## Minor 0.1

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
