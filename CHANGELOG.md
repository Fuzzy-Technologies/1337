# 1337 Security Workbench Changelog

1337 Security Workbench Changelog — a chronological record of product development, documenting key features, fixes, architectural changes, optimizations, limitations, security boundaries, and release-relevant results for each version.

# Major 0

Major 0 — the pre-stable 1337 Security Workbench line, establishing the Community foundation, development contracts, security boundaries, core workbench experience, and the path toward the first stable release.

## Minor 0.2

### Patch 2 — v0.2.2 — 2026-10-11

#### Digest

- Prepared incremental Experimental Workbench foundations for the next development
  cycle. This is a development candidate; no v0.2.2 release has been published.
  Package installation examples continue to use the immutable v0.2.1 baseline.

#### Added

- Added typed, versioned subsystem contracts and documented APIs for incremental
  Workbench development, with deterministic validation and failure-path tests.
  The subsystem documentation describes the capabilities present in each change.

- Added `1337 scan quick` for explicitly approved SAFE HTTP(S) endpoint discovery,
  live job/model updates, immutable raw evidence and durable workspace reopen.
- Added an explicitly approved one-command owned localhost Workbench demo through
  ordinary workspace, scope, SAFE discovery and saved-workspace report commands.
  It retains actual live events, raw acquisitions, reopen checks and JSON/SARIF
  exports, with no-clobber output, interruption handling and target teardown.
- Added evidence-linked Finding lifecycle and report projections, strict JSON and
  SARIF serializers, read-only model lenses and attributed attack references.
- Added reviewed optional Nuclei HTTP-template and Trivy offline-image preparation
  and parsing, image/package normalization and verified flat SPDX inventory.
  Compatible native tools remain operator-supplied and optional.
- Added an explicitly confirmed STANDARD Nuclei workflow through governed jobs,
  retained raw evidence and durable canonical Findings, with current authority
  checks at launch and model Save and pinned genuine-provider loopback CI.
- Added opt-in genuine Trivy adapter acceptance with checksum/digest-pinned
  upstream material, owned inert image metadata, specific advisory boundary tests,
  original raw evidence and a Linux scan namespace without external routes.
  Native artifact product authorization remains separate and metadata-only.
- Added verified offline vulnerability intelligence and standards-mapping
  metadata, preserving source versions, evidence and uncertainty.
- Added offline OpenAPI request import, bounded synthetic API request generation
  and browser/API journey contracts without granting execution authority.
- Added opt-in bounded OpenAPI/Swagger YAML import and source-bound synthetic
  request previews with an optional pinned event parser. JSON defaults and
  identities remain compatible; aliases, unsafe tags, duplicate/non-string keys
  and resource excess are refused.
- Added attributed offline reachability states and deterministic bounded path
  search over selected model relations, with explicit conflicts and truncation.
- Added independent inert image-archive and Dockerfile/Kubernetes fixtures and
  future producer/consumer contracts. These fixtures do not claim native scanner
  acceptance or implemented image/configuration product workflows.
- Added selected-read-consent artifact capture, canonical input/scanner/material
  manifests, guarded staging and governed execution of closed synthetic workers.
  Native scanner profiles remain metadata-only until actual tool acceptance.
- Added independent closed synthetic image VERSION/SCAN operations, an immutable
  original VERSION prerequisite bound into SCAN authorization, fresh paired-run
  acceptance and strict original-shape read-only schema-1 receipt verification.
- Added bounded read-only verification of original synthetic image factory
  payloads, sharing live command grammar and preserving recorded path and privilege
  semantics without consulting current authority or granting execution.
- Added separate six-role synthetic image interpretation and read-only original
  capture verification, preserving native asset namespaces and operator triage.
  Interpretation returns an in-memory proposal; product workflows remain separate.
- Added a closed synthetic image workflow composing independent VERSION/SCAN runs,
  original selected-material and six-role evidence, canonical interpretation,
  durable model/workspace saves and separate JSON/SARIF export. Genuine Trivy
  acceptance remains separate work.
- Added explicit `1337 scan image --profile synthetic` and canonical manifest
  scope rules, reusing governed image execution, durable state, live events and
  separate JSON/SARIF exports. Read consent and SAFE approval remain explicit;
  genuine native Trivy acceptance remains separate.
- Added a bounded standalone Dockerfile/Kubernetes synthetic producer for five
  pinned source fixtures, retaining the independently authored result oracle.
- Added governed SCAN registration for the reviewed closed configuration worker,
  exact five-case source/material bindings, SAFE approvals, bounded raw capture
  and original-family replay. Native configuration and model projection remain
  separate.
- Added owner-verified supplied HTML capture frontiers, exact current URL scope
  checks and model projection that preserves existing Endpoint requests.
- Added governed acquisition of one owned loopback HTML page from the closed
  non-secret fixture catalog, with bounded transport parsing, retained evidence,
  existing lexical frontier projection and one durable model Save.

- Added explicit saved-workspace `report export` for bounded JSON and SARIF,
  owner-verifying every retained raw evidence reference and preserving failed
  execution, uncertainty and actual no-clobber publication outcomes.

#### Fixed

- Reject historical synthetic-image pairs that reuse one physical marker,
  including coherently rehashed captures with changed snapshot attributes.

- Preserved complementary page-provider loop-isolation and local-demo startup
  regressions, with active unit-network denial and subprocess phase diagnostics
  (Refs #40, #59).

- Reject test and suite budgets outside the supported 1–3600-second integer
  range before child startup or stale-report deletion, using fixed diagnostics
  rather than overflowing operating-system timer conversion.

- Separated the bounded whole-pytest invocation budget from individual test
  deadlines, keeping the 120-second per-test default and allowing a healthy
  expanded suite up to 600 seconds per invocation. Missing fresh JUnit evidence
  fails even when the child process exits zero; automatic retries remain disabled.

- Rejected malformed UTF-8 lens metadata and query text at construction/decoding,
  before clients attempt to emit machine-readable views.
- Preserved newer finding triage and detector metadata when an earlier attributed
  operator decision is retried; decision history survives workspace relocation.
- Rejected oversized integer finding confidence through the documented validation
  error boundary without numeric conversion overflow.
- Preserved awaited scan-job cleanup under concurrent forced cancellation and
  retained event-budget failure when a provider catches its notification error.
- Preserved terminal cancellation when cooperative provider cleanup finishes
  as the grace timer fires, without rescheduling an already finished job deadline.

- Preserved owned-process cleanup when an exited process group is already absent
  on macOS, while retaining denial for an inaccessible live group.
- Kept large boundary-test identifiers within Windows process-environment limits
  without weakening the tested payload sizes.
- Preserved canonical reachability model digests at exact size boundaries and
  rejected oversized projections before full model materialization.
- Preserved artifact path and handle identity across supported platforms and
  emitted synthetic worker results as exact LF bytes on Windows.
- Rejected literal Unicode controls before captured URL fragment handling while
  retaining exactly-once HTML5 character-reference interpretation.

- Kept report material paths out of interactive and native input history,
  preserving caller-owned entries and refusing unrecoverable native history gaps.

#### Changed

- Limited browser-based documentation rendering to the protected-master publication
  gate. Pull requests retain static source, locale, link, package and build checks.

- Factored pure native image candidate construction with equivalent owner-verified
  graph/delta bytes, validation ordering and triage/replay behavior.

#### Security

- Require a valid timezone-aware Trivy database update time and reject JSON
  integers exceeding decoder limits before accepting scan provenance.
- Reject control characters and the IPv4 limited-broadcast address in reviewed
  Nuclei targets, and fail closed on JSON integers exceeding decoder limits.
- New foundation APIs retain explicit workspace, scope and evidence boundaries.
  A query, model reference, job or adapter preparation does not grant authority
  to scan a target or broaden a previously approved execution plan.
- Verify full scope/policy/owner, exact destinations, impact and invocation at
  governed launch; preserve raw failure, cancellation and timeout outcomes.
- Reject forged or changed evidence/reference snapshots and stale/conflicting
  reachability proofs. Integrity checks do not authenticate an attestation author
  or prove physical reachability, exploitability or scanner accuracy.
- Native discovery uses explicit literal-IP endpoints, TLS 1.2 or later and finite
  request limits; it does not follow redirects or collect cookies or bodies.
- Bind artifact grants to full current scope, policy, consent, owner, selected
  content, executable and physical staging identities. Recheck authority after
  expensive verification and preserve actual raw execution/acceptance outcomes.
- Bind synthetic receipts to their original physical run and authorization
  window. Historical replay verifies evidence without issuing a new grant.
- Recheck synthetic SCAN and its original VERSION prerequisite at the same
  refreshed clock after authority lookup, denying launch or acceptance when only
  VERSION expires during that final lookup.
- Bound actual owning synthetic image record reads by their role before raw
  allocation, reject reused physical stage copies and refresh canonical paired
  authority after evidence/candidate checks before pure model application.
- Supplied HTML captures retain explicit owner verification and caller-attributed
  source association. Frontier interpretation grants no transport, browser or
  request execution authority and claims completeness only for its input profile.
- Bound report export reads and serialization by consumer quotas, rechecked
  saved input snapshots before publication and protected against physical-path
  aliases, foreign output files and interrupted publication acknowledgements.
- Keep owned localhost demo binding numeric, without an implicit host-dependent
  reverse DNS lookup before the explicitly approved discovery workflow starts.

### Patch 1 — v0.2.1 — 2026-10-09

#### Digest

- Refined the released Community Core and Shell documentation and refreshed
  development/publication dependencies. The API reference now starts in dark mode
  and exposes theme and language controls; the runtime capability boundary is unchanged.

#### Fixed

- Made the API reference dark by default, independent of operating-system theme,
  with a persistent light/dark choice and same-page English/Russian/Chinese navigation.
- Synchronized the hashed API documentation lock with mkdocstrings-python 2.0.9
  and added a regression check that rejects direct-requirement/lock drift.

#### Changed

- Updated development tooling to mypy 2.4.0 and Ruff 0.16.10, with locked
  ast-serialize 0.12.1 and librt 0.16.0 transitive dependencies.
- Updated SHA-pinned Pages upload/deploy actions to 5.0.0/5.0.1.
- Added completed/in-progress/planned roadmap markers and aligned release examples
  and public-site links with v0.2.1. Russian/Chinese API content retains explicit
  English fallback notices; no new runtime feature or approved translation is claimed.

### Patch 0 — v0.2.0 — 2026-10-08

#### Digest

- Completed the M1 Community Core and Shell foundation: interactive command
  discovery, local diagnostics, portable workspace/configuration and offline
  target/scope contracts. This pre-alpha also includes accepted Experimental
  execution, model, evidence and Nmap SDK foundations; M2/M3 remain in progress.

#### Added

- Added interactive shell entry, fuzzy completion, contextual help, command
  palette, reverse history search and local lens/view context.
- Added non-mutating `1337 doctor` and `1337 update [--json]` inspections.
- Added portable workspace creation/open/save, typed target registration,
  consent metadata and deterministic allow/deny/exclusion decisions.
- Added Experimental ToolAdapter and local Executor SDKs, immutable raw-evidence
  storage, Security Object Model persistence and an optional bounded Nmap adapter.
- Added deterministic web micro-targets, the attack-path mini lab, finite-oracle
  capability reports and an opt-in pinned Juice Shop regression pack.

#### Fixed

- Fixed parallel serial-test discovery and owned-process cleanup when lifecycle
  observers fail.
- Reconciled accepted `master` publications with `develop`, preserving the
  published project image route in the composed documentation artifact.

#### Changed

- Added process-isolated parallel testing, measured shell latency budgets,
  grouped dependency updates and completed-parent Feature reconciliation.
- Finalized package and lockfile metadata for the v0.2.0 pre-alpha release.

#### Documentation

- Added reproducible CLI, shell, workspace/scope API and isolated-lab quickstart
  examples, with explicit availability and authorization boundaries.
- Added the composed product-site/API-reference build, clean-wheel static API
  discovery, offline formula rendering, locale provenance, SPDX/source audits
  and Markdown table alignment checks.
- Published English API sources with explicitly marked English fallback content
  for Russian and Simplified Chinese routes; no approved API translation is claimed.

#### Security

- Scope membership and consent metadata do not issue execution authorization.
  Workspace/model references do not grant authority to tools or executors.
- The Nmap provider remains operator-supplied and optional. Test-backed examples
  use only repository-owned isolated targets or fixture-owned loopback sockets.
- Component inspection performs no installation, self-update or remote version
  check. Full TUI, native discovery, Quick Scan and AI/MCP workflows remain roadmap work.

## Minor 0.1

### Patch 8 — v0.1.8 — 2026-09-10

#### Digest

- Established the first public pre-alpha baseline: the completed M0 engineering
  foundation plus early M1 Command Registry and functional-test harness work.

#### Added

- Added machine-readable functional scenario contracts and a pytest-owned
  Docker Compose lifecycle for the repository-owned `web-safe` target.
- Added deterministic raw lifecycle evidence and a container-backed health
  contract test on Linux CI.
- Added functional-testing guidance and ADR 0007 for the harness boundary.

#### Documentation

- Added the public product vision, AI-agent discovery reference, compact machine
  summary, and ADR 0008 for the model-neutral cyber execution/state/evidence
  platform boundary.

#### Security

- Functional targets remain repository-owned and isolated. The first
  container-backed scenario runs only where Linux container capability is
  available; unsupported runners skip it explicitly.

### Patch 7 — v0.1.7 — 2026-09-09

#### Digest

- Added the M1 centralized Command Registry foundation for issue #16.

#### Added

- Added immutable command descriptors with canonical names, aliases, usage,
  summaries, and declared capability identifiers.
- Added deterministic command resolution, prefix completion, and search APIs
  for future shell, command-palette, documentation, and agent consumers.

#### Changed

- Bootstrap CLI help is now rendered from the Command Registry and exposes
  only the currently implemented `help` and `--version` commands.

### Patch 6 — v0.1.6 — 2026-09-08

#### Digest

- Added the isolated M0 synthetic security lab skeleton for issue #11.

#### Added

- Added the repository-owned safe web target, internal Docker network, and
  stable target-family locations for future lab packs.
- Added CI lifecycle and health-contract validation for the safe target.
- Added an architecture decision record for synthetic-lab isolation.

#### Security

- Lab services are unprivileged, read-only, capability-restricted, internal-only
  containers with no published host ports; M0 adds no vulnerable application or
  authorization beyond this repository-owned lab.

### Patch 5 — v0.1.5 — 2026-09-08

#### Digest

- Added the container-first development and quality baseline for issue #10.

#### Added

- Added the repository-owned Dockerfile, Compose services, and container
  development guidance for an interactive workbench and one-shot quality gate.
- Added CI validation of the Compose configuration, image build, and in-container
  `1337-dev check` execution.
- Added an architecture decision record for the M0 container boundary.
- Clarified the public README around the needs of security practitioners and
  security leaders, without presenting planned scanner capabilities as shipped.
- Added ADRs for the intelligence-first workbench, CLI-primary interaction
  model, and AI-neutral 1337Scope direction.

#### Security

- Container conventions use an unprivileged runtime user, a locked dependency
  environment, and repository-local inputs only; they do not authorize remote
  targets, privileged execution, secrets, or host networking.

### Patch 4 — v0.1.4 — 2026-09-08

#### Digest

- Established the canonical fast unit-test baseline for issue #91.

#### Added

- Added `1337-dev unit` as the deterministic fast feedback entry point for
  `tests/unit` with mandatory per-module coverage validation.
- Added an automatic unit-test isolation guard and a self-test that prove real
  network connections fail closed.

#### Changed

- Plain `pytest` now defaults to `tests/unit`; `1337-dev test` explicitly runs
  every test layer and remains part of the full `1337-dev check` gate.

#### Security

- Unit tests cannot silently reach network or external service sockets, while
  every production module must still exceed 80% combined statement/branch
  coverage in the fast lane.

### Patch 3 — v0.1.3 — 2026-09-08

#### Digest

- Completed the deterministic developer-command entry point for issue #9.

#### Added

- Added `1337-dev setup` for repeatable locked development-environment
  synchronization through the pinned `uv` tool.
- Added a typed command-step registry that describes Python and external-tool
  invocations from one source.

#### Fixed

- Developer-command execution now reports missing external tools explicitly
  and preserves fail-closed exit-code behavior across platforms.

#### Security

- The setup path resolves `uv` without a shell and retains the existing bounded
  timeout and argument-array execution contract.

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
