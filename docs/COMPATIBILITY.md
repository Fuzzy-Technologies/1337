# Public Compatibility Contract

This document defines the public compatibility boundary for **1337 Security Workbench by Fuzzy Technologies**.

The goal is simple: extensions should be able to depend on explicit public contracts without depending on repository internals, implementation layout, or confidential code.

## Contract version

This policy is **Compatibility Contract v1**.

Repository releases use Semantic Versioning. Individual machine-readable contract families also carry their own schema version so a schema can evolve independently from the repository release number.

## Stability classes

| Stability class  | Meaning                                                               | Compatibility promise                                              |
| ---------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **Stable**       | Explicitly documented public contract intended for external consumers | Breaking changes require the version transition defined below      |
| **Experimental** | Publicly visible preview surface that is still being designed         | May change between releases; changes must be documented            |
| **Internal**     | Implementation detail not declared as public                          | No compatibility promise; external consumers must not depend on it |

A surface is **not** Stable merely because it is importable, visible in source, reachable over HTTP, or present in a serialized file. Stability must be declared by public documentation or a versioned schema/SDK contract.

## Public contract boundaries

The following areas are the intended extension boundaries as they are introduced:

| Boundary                   | Public when                                                         | Not a public guarantee                                             |
| -------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Machine-readable contracts | Versioned schema is published under `contracts/`                    | Unversioned internal JSON/YAML/state                               |
| Python/API SDK             | Symbol is explicitly documented as public SDK surface               | Arbitrary internal modules, classes, helpers, or import paths      |
| Tool adapters              | Adapter interface/schema is published as a versioned contract       | Executor internals or third-party tool implementation details      |
| CLI                        | Command/option behavior is documented as a stable CLI contract      | Human-oriented formatting, spacing, colors, or incidental log text |
| REST/OpenAPI               | Endpoint/schema is included in a versioned public API specification | Internal routes, debug endpoints, or undocumented fields           |
| Evidence/finding formats   | A versioned schema is published                                     | Temporary runtime/cache/storage representation                     |
| Extension manifest         | Validates against `contracts/extension-manifest.schema.json`        | Extra undeclared fields or implementation-specific metadata        |

The M0 repository does **not** freeze a Python import namespace before packaging is implemented. Future packaging work may choose the concrete import/package names, but once a symbol is declared Stable it must follow this compatibility policy.

`fuzzy1337.workspace` is an Experimental Python SDK namespace and persisted
workspace document at schema version `1`. ADR 0019 and `docs/WORKSPACES.md`
define its portable metadata, reference, and cooperating-writer lifecycle contract.

`fuzzy1337.jobs` is an Experimental Python library at contract version `1`.
ADR 0026 defines its typed, bounded subsystem contract.
The interface grants no authority beyond an explicitly approved scope/policy.

`fuzzy1337.quickscan` and the workspace/scope/scan product commands are Experimental
at contract version `1`. ADR 0037 and `docs/QUICK_SCAN.md` define explicit consent,
SAFE-only capability opt-in, bounded streaming, terminal JSON/exit statuses and
durable model/evidence reopening. SDK workflow composition grants no authority.

`fuzzy1337.scope` is an Experimental Python library and persisted scope schema
at version `1`. ADR 0022 and `docs/SCOPE.md` define typed target identity,
explicit consent metadata, offline membership, and portable scope persistence.
Scope membership does not issue invocation-bound execution authorization.

`fuzzy1337.requests` is an Experimental Python library at contract version `1`.
ADR 0028 defines its typed, bounded subsystem contract.
The interface grants no authority beyond an explicitly approved scope/policy.

`fuzzy1337.openapi` is an Experimental offline Python importer at contract version
`1`. ADR 0038 defines bounded structural OpenAPI/Swagger JSON import and projection
into existing request/model contracts. It generates no concrete values or traffic.

`fuzzy1337.api_request_generation` is an Experimental offline Python producer at
generation profile version `1`. ADR 0042 and `docs/API_REQUEST_GENERATION.md` define
the exact anonymous synthetic schema/serialization subset, original-source
validation, bounded ephemeral previews and existing actual-target scope handoff.
It grants no scope, method, authentication or execution permission.

`fuzzy1337.captured_web` is an Experimental offline Python consumer at frontier
profile version `1`. ADR 0050 and `docs/CAPTURED_WEB.md` define owner-verified
explicit HTML artifacts, caller-associated sources, bounded lexical anchor
interpretation, exact per-URL scope preparation, deterministic partial frontiers
and pure existing request/model projection. Source hashes authenticate neither
transport nor collector; the consumer grants no browser/network execution authority.

`fuzzy1337.adapters.page_capture` and `fuzzy1337.page_capture` are Experimental
at page-capture profile version `1`. ADR 0052 and `docs/LOCAL_PAGE_CAPTURE.md`
define one governed anonymous GET to an explicitly owned canonical loopback URL,
admitting only the exact closed non-secret HTML fixture. Actual owner-verified
evidence feeds the existing captured-web frontier and one durable model Save.
NativeHTTP version 1 remains a separate capability. The packaged
`fuzzy1337.page_capture_worker` is Internal; its schema-1 flat record is verified
by the parent and does not grant caller-selected crawling or browser execution.

`fuzzy1337.adapters` is the first explicitly documented Python SDK namespace. ADR
0014 declares it Experimental at contract version `1`; other import paths remain
internal unless this document explicitly states otherwise.

`fuzzy1337.lenses` is an Experimental Python library at contract version `1`.
ADR 0029 defines its typed, bounded subsystem contract.
The interface grants no authority beyond an explicitly approved scope/policy.

`fuzzy1337.model` is an Experimental Python library and persisted model schema
at version `1`. ADR 0023 and `docs/SECURITY_MODEL.md` define deterministic object
identity, attributable updates, typed relations, observations, incremental deltas,
and portable model persistence. Scope/target references do not grant authority.

`fuzzy1337.reachability` is an Experimental offline Python library at profile `1`.
ADR 0047 and `docs/REACHABILITY.md` define exact current-basis source-attestation
verification, explicit existing transition projection and bounded deterministic
candidate search. Hop/path labels preserve source estimates; they grant no
execution authority or independent end-to-end network/exploit confirmation.

`fuzzy1337.findings` is an Experimental Python library at contract version `1`.
ADR 0027 defines its typed, bounded subsystem contract.
The interface grants no authority beyond an explicitly approved scope/policy.

`fuzzy1337.reporting` and `fuzzy1337.report_formats` are Experimental libraries.
ADR 0039 and `docs/REPORTING.md` define report projection schema `1`, SARIF `2.1.0`,
and a version-1 JUnit adapter. Reports preserve canonical state and do not imply
scanner completeness, authorization, verified bytes, or compliance. Pure reports
remain byte-unverified; verification requires the explicit owned evidence boundary.

The `report export` product command and schema-v1
`contracts/report-export-result.schema.json` are Experimental. ADR 0049 and
`docs/REPORT_EXPORT.md` define explicit saved-workspace reading, consumer quotas,
no-clobber output and terminal publication truth. Export success never establishes
scan completeness or upgrades failed source execution. `fuzzy1337.report_commands`
is Internal CLI implementation and adds no public authoritative store.

`fuzzy1337.evidence` is an Experimental local storage API and manifest schema
at version `1`. ADR 0020 defines immutable content/provenance identities;
[`docs/EVIDENCE.md`](EVIDENCE.md) defines the supported API and integrity/storage
failure semantics. Other evidence helpers remain Internal.

`fuzzy1337.adapters.trivy` is an Experimental optional adapter at version `1`.
ADR 0032 and `docs/TRIVY_ADAPTER.md` define offline finite archive invocations,
bounded version/DB observation, verified JSON and executor failure preservation.
The external tool/cache are operator supplied; daemon/registry targets are deferred.

`fuzzy1337.adapters.nmap` is an Experimental optional adapter at version `1`.
ADR 0024 and `docs/NMAP_ADAPTER.md` define finite invocation profiles, bounded
health, verified XML normalization, and preservation of executor/evidence facts.
Nmap is supplied by the operator; this adapter never grants execution authority.

`fuzzy1337.adapters.nuclei` is an Experimental Python library at contract version `1`.
ADR 0030 defines its typed, bounded subsystem contract.
The interface grants no authority beyond an explicitly approved scope/policy.

`fuzzy1337.nucleiscan` and `1337 scan nuclei` are Experimental at workflow schema
version `1`. ADR 0055 and `docs/NUCLEI_WORKFLOW.md` define operator-supplied reviewed
material, explicit STANDARD permission, exact-plan confirmation, fresh governed
launch and final acceptance, canonical Finding ingestion and durable reopening.
`NucleiAuthorityDeniedError` distinguishes operator denial from filesystem access
failures. Native authority-only host records require exact URL/scheme/port agreement;
existing full-URL records remain supported. Genuine pinned Nuclei 3.4.10 acceptance
uses a pytest-owned loopback target; the provider remains optional.

`fuzzy1337.executors` is an Experimental Python SDK namespace at executor
contract version `1`. ADR 0015 defines its governed local execution boundary.

`fuzzy1337.journeys` is an Experimental Python library and standalone scenario
schema at version `1`. ADR 0034 and `docs/JOURNEYS.md` define immutable finite
browser/API declarations and offline preparation against existing exact targets
and scope records. Preparation issues no invocation-bound execution authorization.

`fuzzy1337.standards_mapping` is an Experimental Python library and offline
mapping-pack schema at version `1`. Proposed ADR 0035 and `docs/STANDARDS_MAPPING.md`
define exact upstream identities, source provenance, review-bound content
references, and explicit finding associations. Candidate mappings never establish
control fulfillment, certification, or Evidence integrity.

`fuzzy1337.policy` is an Experimental Python library at contract version `1`.
ADR 0025 defines its typed, bounded subsystem contract.
The interface grants no authority beyond an explicitly approved scope/policy.

`fuzzy1337.images` is an Experimental offline interpretation library at contract
version `1`. ADR 0040 and `docs/IMAGES.md` define ASSET-based image/package identities,
verified native/SBOM imports and canonical Finding correlation without changing
the existing model schema or granting execution authority.
`TrivyCandidates` and `SyntheticTrivyCandidates` remain Internal pure helpers.
The synthetic helper has a fixed fixture namespace and does not admit evidence,
apply a model transition, grant execution or change native import behavior.

`fuzzy1337.image_evidence` and `fuzzy1337.image_workflow` are Internal closed-fixture
capture/orchestration modules. The capture helper retains original typed SDK
envelopes and acquisition provenance; `fuzzy1337.synthetic_images` remains the
single interpretation owner. One governed job composes independent VERSION/SCAN runs,
selected-material and six-role evidence, final current paired acceptance, durable
model/workspace CAS saves and separate JSON/SARIF publication, as described in
`docs/IMAGE_WORKFLOW.md`. The Experimental `1337 scan image --profile synthetic`
consumer calls that same workflow with explicit selected-file read consent,
ARTIFACT scope and SAFE capability approval (ADR 0056). Genuine supplied Trivy
acceptance remains separate; native import and reviewed worker/builder/oracle
bytes are unchanged.

`fuzzy1337.discovery` and `fuzzy1337.adapters.native_http` are Experimental
Python producer/sensor APIs at contract version `1`. ADR 0036 and
`docs/NATIVE_DISCOVERY.md` define finite SAFE literal-IP endpoint acquisition,
status-only evidence and canonical observed-model updates. The wire record is
published as `contracts/native-http-record.schema.json`; destination binding is
additionally enforced by the authoritative parser. `fuzzy1337.native_http_worker`
is Internal and must not be used as an independent authorization/execution API.

`fuzzy1337.sbom_spdx` is an Experimental offline package-inventory interpretation
library at contract version `1`. ADR 0043 and `docs/SBOM_SPDX.md` define a bounded
SPDX 2.3 JSON profile over existing image/package assets, verified evidence and
document-scoped aliases. `ApplyVerifiedSpdx` and `SPDX_IMPORT_VERSION` are its
supported surface; other helpers remain Internal. General SPDX graphs, VEX,
signatures and execution authority are outside this contract.

## Version compatibility rules

`fuzzy1337.demo` and `fuzzy1337.demo_commands` are Experimental schema-version-1
local-demo interfaces. ADR 0054 and `docs/DEMO.md` define explicit SAFE approval,
command-owned loopback service lifecycle, ordinary workspace/scan/report dispatch,
no-clobber output and actual partial-publication outcomes. They never substitute
demo data for findings or grant authority over an operator-selected external target.

`fuzzy1337.intelligence` is an Experimental Python library and snapshot schema
at version `1`. ADR 0041 and `docs/INTELLIGENCE.md` define the documented source,
record, parser, and verified finding-observation boundaries. Validation helpers
remain Internal. Catalog metadata does not establish vulnerability applicability,
authenticated source identity, approval, or execution authority.

### Repository releases

Before `1.0.0`:

- patch releases (`0.Y.Z` → `0.Y.Z+1`) must not intentionally break Stable contracts;
- a breaking change to a Stable contract requires at least the next minor release (`0.Y` → `0.Y+1`);
- Experimental surfaces may change in a patch or minor release, but the change must be documented;
- Internal surfaces may change at any time.

At and after `1.0.0`:

- breaking Stable-contract changes require a major version;
- backward-compatible additions may use a minor version;
- backward-compatible fixes use a patch version.

### Contract schemas

Each machine-readable contract family has an integer schema version starting at `1`.

- backward-compatible additions may retain the same schema version when old valid documents remain valid and semantics do not change incompatibly;
- incompatible field/meaning/removal changes require a new schema version;
- consumers must reject unsupported schema versions explicitly rather than guessing;
- schema-version negotiation/fallback must never silently weaken security or authorization semantics.

## Deprecation

Stable surfaces are deprecated before removal whenever practical.

For pre-1.0 development, a Stable contract should normally remain available for at least one subsequent minor release after deprecation before removal. Security fixes may require faster action; such exceptions must be documented with migration guidance.

Deprecated behavior must not be silently repurposed with different semantics.

## Extension manifest

`contracts/extension-manifest.schema.json` defines the first public machine-readable extension boundary.

The manifest declares:

- manifest schema version;
- extension identity and SemVer version;
- compatible 1337 core release range;
- required public contract schema versions;
- declared extension entry points;
- optional capability identifiers.

The manifest intentionally does **not** contain secrets, credentials, license material, executable source, or environment-specific absolute paths.

The concrete implementation locator syntax in `entry_points.*[].target` is intentionally not frozen by M0. Packaging/SDK work will define how locators are resolved while preserving the manifest structure or versioning it explicitly if an incompatible change is required.

## Entry-point families

Compatibility Contract v1 reserves these extension families:

- `tool_adapters` — security-tool/executor adapters;
- `commands` — additional command implementations;
- `reporters` — report/output providers;
- `integrations` — external-system connectors.

Adding a new optional family is backward-compatible when existing manifests and consumers remain valid. Changing the meaning of an existing family incompatibly requires a new manifest schema version.

## Capability identifiers

Capabilities are opaque, lowercase machine-readable identifiers such as:

```text
scanner.example
report.html
integration.example
```

A capability identifier advertises a declared ability; it is **not** authorization to execute that ability. Runtime scope, impact, authorization, and policy checks remain mandatory.

## Security boundary

Compatibility is never a reason to weaken security.

- Unknown or unsupported contract versions fail closed at security-sensitive boundaries.
- Extension metadata must not grant implicit authorization.
- Secrets must not be stored in public manifests.
- A compatible extension is still subject to scope, impact, executor, and evidence-integrity rules.
- Public contract stability does not guarantee that an unsafe action will remain enabled when security policy changes require restriction.

## Consumer rules

`fuzzy1337.artifact_inputs` and `fuzzy1337.artifact_policy` are Experimental
contract-version-1 selected-byte staging and same-store artifact authorization
surfaces. Native profile IDs are metadata-only and cannot obtain execution grants.
Synthetic execution is limited to the trusted running CPython runtime and a closed
reviewed producer SHA allowlist. `fuzzy1337.artifact_fixture_worker` remains
Internal fixture code, not a scanner API. Role-separated manifest identities and
historical receipts never replace current consent or authorize network policy.
Selected-byte manifests remain schema 1; new execution metadata uses schema 2
with explicit operation/family and original VERSION prerequisite bindings.
Strict read-only schema-1 replay retains its original field shapes and digests.
Only the reviewed richer synthetic image family admits VERSION and proof-bound
SCAN; lifecycle SCAN remains compatible and native profiles remain unavailable.
The reviewed configuration family admits only SCAN for synthetic Dockerfile and
Kubernetes profiles, with exact selected-source/material bindings and 16 KiB
stream ceilings. Its VERSION prerequisite fields are null; configuration cannot
consume an image proof or obtain native execution authority. ADR 0059 defines
this additive closed family; model projection remains separate.
See [Governed local artifacts](ARTIFACTS.md) and
[ADR 0044](adr/0044-governed-local-artifact-authorization.md).

`fuzzy1337.synthetic_images` is a separate Experimental version-1 consumer of the
closed schema-2 synthetic image operations. Its live import requires actual
original typed runs and six original source records, then uses the canonical SDK
fresh pair barrier before one pure in-memory transition. Read-only historical
verification returns immutable original attribution/refusal facts without live
stage lookup or new authority. Native `fuzzy1337.images` interfaces and evidence
roles remain unchanged. Durable saves, product workflow and native scanner
acceptance remain separate. See [the synthetic image consumer](SYNTHETIC_IMAGE_IMPORT_DESIGN.md).

External consumers should:

1. depend only on explicitly Stable public contracts;
2. declare the supported core range and schema versions;
3. validate manifests/schemas before activation;
4. treat unknown required fields/versions according to the schema rather than ignoring them silently;
5. avoid importing or scraping repository internals;
6. run compatibility tests against every supported release line.

## Producer rules

Changes to a Stable contract require:

1. impact review against known consumers;
2. contract/schema tests when tooling exists;
3. compatibility classification: backward-compatible, deprecation, or breaking;
4. changelog/migration notes when externally visible;
5. a version/schema change when required by this policy.

## Contract index

Current versioned public contracts:

| Contract family        | Schema version | Location                                                             | Status       |
| ---------------------- | -------------- | -------------------------------------------------------------------- | ------------ |
| Extension manifest     | `1`            | `contracts/extension-manifest.schema.json`                           | Stable       |
| Targets and Scope      | `1`            | `fuzzy1337.scope`; `docs/SCOPE.md`                                   | Experimental |
| Workspace state        | `1`            | `fuzzy1337.workspace`; `docs/WORKSPACES.md`                          | Experimental |
| ToolAdapter SDK        | `1`            | `fuzzy1337.adapters`; `docs/TOOL_ADAPTERS.md`                        | Experimental |
| Security Model         | `1`            | `fuzzy1337.model`; `docs/SECURITY_MODEL.md`                          | Experimental |
| Intel references       | `1`            | `fuzzy1337.intel_references`; `docs/INTEL_REFERENCES.md`             | Experimental |
| Local Evidence Store   | `1`            | `fuzzy1337.evidence`; `docs/EVIDENCE.md`                             | Experimental |
| Nmap adapter           | `1`            | `fuzzy1337.adapters.nmap`                                            | Experimental |
| Nuclei adapter         | `1`            | `fuzzy1337.adapters.nuclei`                                          | Experimental |
| Report projection      | `1`            | `fuzzy1337.reporting`; `report_formats`                              | Experimental |
| Report export outcome  | `1`            | `contracts/report-export-result.schema.json`                         | Experimental |
| Executor SDK           | `1`            | `fuzzy1337.executors`; `docs/EXECUTORS.md`                           | Experimental |
| Web request model      | `1`            | `fuzzy1337.requests`                                                 | Experimental |
| Offline API import     | `1`            | `fuzzy1337.openapi`; `docs/OPENAPI.md`                               | Experimental |
| Impact policy          | `1`            | `fuzzy1337.policy`                                                   | Experimental |
| Scan jobs              | `1`            | `fuzzy1337.jobs`                                                     | Experimental |
| Finding core           | `1`            | `fuzzy1337.findings`                                                 | Experimental |
| Image/package model    | `1`            | `fuzzy1337.images`; `docs/IMAGES.md`                                 | Experimental |
| Workflow lenses        | `1`            | `fuzzy1337.lenses`                                                   | Experimental |
| Quick Scan summary     | `1`            | `contracts/quick-scan-summary.schema.json`                           | Experimental |
| Synthetic journeys     | `1`            | `contracts/journey-scenario.schema.json`                             | Experimental |
| Standards Mappings     | `1`            | `fuzzy1337.standards_mapping`; `docs/STANDARDS_MAPPING.md`           | Experimental |
| Vulnerability Intel    | `1`            | `fuzzy1337.intelligence`; `docs/INTELLIGENCE.md`                     | Experimental |
| SPDX package inventory | `1`            | `fuzzy1337.sbom_spdx`; `docs/SBOM_SPDX.md`                           | Experimental |
| Synthetic API request  | `1`            | `fuzzy1337.api_request_generation`; `docs/API_REQUEST_GENERATION.md` | Experimental |
| Local artifacts        | `1`            | `contracts/artifact-manifest.schema.json`; `docs/ARTIFACTS.md`       | Experimental |
| Offline Reachability   | `1`            | `fuzzy1337.reachability`; `docs/REACHABILITY.md`                     | Experimental |
| Captured web frontier  | `1`            | `fuzzy1337.captured_web`; `docs/CAPTURED_WEB.md`                     | Experimental |

Examples are illustrative and live under `contracts/examples/`. An example does not create a new contract beyond the schema and this policy.
