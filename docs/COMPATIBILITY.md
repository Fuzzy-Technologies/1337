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

The first-party `owned-plaintext-proxy.v1` profile described in
[`docs/PROXY_REGRESSION.md`](PROXY_REGRESSION.md) is Internal test coverage of this
unchanged Quick Scan contract. Its versioned fixture oracle and independently
counted backend requests are test-only facts, not public evidence fields,
execution grants or reachability claims. It introduces no scanner proxy option,
transport change, TLS trust behavior or third-party WAF compatibility promise.

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
ADR 0061 adds explicit `document_format="yaml"` through the optional
`1337[openapi-yaml]` parser extra. The restricted JSON-compatible event profile
preserves exact original source-byte identity and existing JSON defaults; it
rejects aliases, unsafe tags, duplicate/non-string keys and resource excess.
`fuzzy1337.openapi_yaml` remains an Internal decoder behind these import APIs.

The Experimental version-one `api import openapi-json` console/shell command
adds original-file custody under ADR 0089. It imports all operations within the
existing JSON SDK profile and requires concrete endpoint paths with current exact
scope membership, explicit independent owner revisions and original-file read
consent. A separate one-MiB original evidence profile binds the exact optional
base context and complete per-endpoint operation collections. Known-original
replay preserves that context across relocation; unknown manifests cannot adopt
custody. Incompatible occupied API collections are refused. Independent storage
acknowledgements preserve truthful partial/unknown outcomes. The SDK's broader
structural and YAML defaults are unchanged. `fuzzy1337.openapi_commands` and the
shared product admission helpers remain Internal and confer no supported SDK,
network, authentication, target-registration or execution contract.

`fuzzy1337.api_request_generation` is an Experimental offline Python producer at
generation profile version `1`. ADR 0042 and `docs/API_REQUEST_GENERATION.md` define
the exact anonymous synthetic schema/serialization subset, original-source
validation, bounded ephemeral previews and existing actual-target scope handoff.
It grants no scope, method, authentication or execution permission.
Generation accepts the same explicit JSON/YAML selection as its original import;
the source, operation and resolution context must still agree exactly.

`fuzzy1337.structured_mutations` is an Experimental offline Python producer at
JSON mutation profile version `1`. ADR 0084 and `docs/STRUCTURED_MUTATIONS.md`
define bounded scalar and explicitly selected JSON-in-string transformations,
complete seed/path/content attribution and independent-reference replay.
ADR 0085 adds explicit canonical standard Base64 JSON selection at encoding
version `base64-json-v1`. The default encoding is omitted from metadata, preserving
existing selection shapes, deterministic order and references.
Public preparation and replay use the existing request template; they grant no
schema-validity, source-authenticity, persistence or execution guarantee. Direct
record constructors and decoding/rendering helpers remain Internal.

`fuzzy1337.graphql_import` is an Experimental offline Python profile at version
`1`. ADR 0065 and `docs/GRAPHQL_IMPORT.md` define explicit owned introspection
import, source-bound typed operation metadata and bounded query/mutation previews
using unchanged request/model/scope contracts. Subscriptions remain descriptive;
unsupported synthesis is refused. Import or preparation grants no execution,
authentication or permission to send introspection or mutation requests.

The Experimental contract-version-one `api import graphql-introspection` CLI and
foreground shell command compose that unchanged SDK with existing workspace,
scope, evidence and model owners under ADR 0081. Import requires an explicit
concrete query-free endpoint, current exact scope membership, run and independent
model/workspace revisions. Original-file selection requires explicit read actor/
consent references and a stable physical singly linked file within 512 KiB.
Original evidence is retained unredacted, including rejected normalization input;
terminal summaries omit source bodies, physical paths and rejected argument values.
Retained selection requires the exact original manifest and already known
`api-import-source` custody with unchanged endpoint/run/scope; a matching source
digest alone cannot establish that custody. An occupied Endpoint admits only
exactly matching complete `request_templates` and `graphql_import` collections;
partial/incompatible collections fail before model write. Independent acquisition,
model and workspace acknowledgements preserve confirmed partial commits and
unknown outcomes without promising rollback or a cross-store transaction.
No scope registration, request preview, introspection fetch, HTTP/native execution,
Finding or execution grant is produced. All `fuzzy1337.api_commands` classes,
methods, functions and helpers, including `ApiParser` and `RunApiCommands`, remain
Internal implementation surfaces and do not establish a supported Python SDK.

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

`fuzzy1337.web_traversal` is an additive Experimental controller under ADR 0062.
It traverses only four explicitly selected reviewed owned pages, with bounded
concurrent acquisitions and deterministic commit order through the existing
page-capture governor. Per-launch and pre-Save consent/scope remain current;
discovered links grant no authority and redirects are refused. The closed record
schema adds exact catalog cases while preserving the original page's grammar.
Its internal ordering hook and retained-frontier result do not enable arbitrary
HTTP crawling, browser execution or native security checks.
NativeHTTP version 1 remains a separate capability. The packaged
`fuzzy1337.page_capture_worker` is Internal; its schema-1 flat record is verified
by the parent and does not grant caller-selected crawling or browser execution.

ADR 0087 hardens current native HTTP and closed page preparation to isolated
`python -I -m` imports without changing provider versions or worker record shapes.
Exact historical non-isolated adapter reports remain accepted only by pure
normalization, with original invocation/digest unchanged. Current page-provider
launch validation remains isolated-only; legacy report acceptance supplies no
grant, launch path or authenticated historical worker identity.

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

`fuzzy1337.path_analysis` adds an Experimental offline Python profile `1` without
changing the reachability or model contracts. ADR 0066 and `docs/PATH_ANALYSIS.md`
define returned-candidate participation/removal counts, separate bounded selected
graph cut verification, and explicit lossless presentation groups. Unknown or
truncated results remain explicit; structural leverage grants no execution or
remediation-efficacy claim.

`1337 paths analyze` is an Experimental read-only product profile at version `1`,
defined by ADR 0083 and `docs/PATHS_ANALYSIS.md`. Exact full saved-model revision/
snapshot pins, one explicit source/target, caller-selected original transitions,
original assessment manifests or explicit `--no-assessments`, context/scope,
analysis clock, freshness and finite search/cut budgets are mandatory. The existing
512-eligible-object ceiling applies to the entire saved model before proof I/O;
no implicit partition or graph/source discovery bypasses it. Selected original
typed identity/profile/context, support joins and physical byte/link bounds are
preflighted before their raw reads, then unchanged reachability and path owners
construct admitted inputs and actual analysis results. UNKNOWN reasons retain original
declared estimates without effective confidence. Bounded schema-one explanations
keep returned-path counts, single-removal structural counts and independent
search/cut completeness separate; they establish no score, aggregate probability,
physical reachability or mitigation efficacy. Foreground shell context supplies
no missing input or authority and protected history retains only the namespace.
All `fuzzy1337.path_commands` classes, functions and helpers, including
`PathParser` and `RunPathCommands`, are Internal implementation surfaces, not a
supported Python SDK. The product command acquires nothing, writes no Core/model/
workspace/evidence or hidden output, and grants no target, network or execution
authority. Existing SDKs, schemas and grouping/source-support boundaries are
unchanged; original retained replay survives complete-workspace relocation.

`fuzzy1337.business_events` adds an Experimental offline Python profile `1` over
the unchanged Core model schema. ADR 0071 and `docs/BUSINESS_EVENTS.md` define
verified owner-declared unacceptable outcomes, explicit ordinary critical Assets,
attributed descriptive memberships and existing technical-path explanations.
Declarations remain scenarios: no incident, financial score, aggregate confidence
or execution authority is inferred. Identity retains the original definition
manifest; exact replay is idempotent, and bounded query limitations remain explicit.

`fuzzy1337.findings` is an Experimental Python library at contract version `1`.
ADR 0027 defines its typed, bounded subsystem contract.
The interface grants no authority beyond an explicitly approved scope/policy.

`fuzzy1337.reporting` and `fuzzy1337.report_formats` are Experimental libraries.

`fuzzy1337.ci_gate` and the `1337 ci scan` command add an Experimental
selected-profile finding predicate under ADR 0075. Required caller selections
and a count limit apply only to original verified current-run configuration
detections in the exact saved snapshot. Explicit unassessed-completeness
acknowledgement, source/run proof and current acceptance are mandatory. Three
report exports share the same snapshot pin and retain partial-publication truth.
No severity ranking, aggregate risk, reachable-risk criterion, native execution
grant or Core schema change is introduced. `fuzzy1337.ci_commands` is Internal.

The version-one `synthetic-image` CI profile extends the same explicit predicate
with original separate VERSION/SCAN captures, six immutable execution acquisitions,
exact source-derived saved inventory/detections and fresh paired acceptance.
`EvaluateImageCriterion` is an additive Experimental `fuzzy1337.ci_gate` surface.
The original JSON export's complete model pin and published-payload digest remain
distinct. Full reports preserve triage and historical/unrelated findings; only
current original SCAN detections enter the criterion. The Internal image summary
adds an optional trailing typed capture tuple in memory; prior positional fields
and detached JSON/operation summaries remain compatible. Cross-profile input and
SAFE approval options are refused before execution. Completeness stays
`not-assessed`; no native execution, scoring, reachability or Core change is added.

The report libraries retain their existing contracts:
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

ADR 0077 adds explicit `html` and `junit` product export selections alongside
JSON/SARIF over the same verified saved snapshot. The schema-1 command outcome
format enum grows additively; accepted renderers, source failure/triage semantics,
quotas and publication truth remain unchanged. A successfully published JUnit
report may contain failure cases; export success is not a finding or CI gate.

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

ADR 0092 adds Experimental `fuzzy1337.portscan` and the `scan ports` product
selection. Schema-one plans and terminal summaries compose the existing finite
TCP-connect adapter, explicit STANDARD policy/confirmation, original custody
and canonical Host/Port/Service owners. Existing adapter argv/profiles remain
unchanged; grouped/omitted ports remain unassessed individually. No service
probe, arbitrary flags or automatic permission is added.

`fuzzy1337.adapters.nuclei` is an Experimental Python library at contract version `1`.
ADR 0030 defines its typed, bounded subsystem contract.
The interface grants no authority beyond an explicitly approved scope/policy.
The exact-URL profile rejects paths whose spelling the reviewed provider would
change, including encoded aliases, nested escapes and unsupported non-ASCII
paths. This tightens preparation and report validation without silently changing
an approved destination; see `docs/NUCLEI_ADAPTER.md` for the pinned wire evidence.

`fuzzy1337.nucleiscan` and `1337 scan nuclei` are Experimental at workflow schema
version `1`. ADR 0055 and `docs/NUCLEI_WORKFLOW.md` define operator-supplied reviewed
material, explicit STANDARD permission, exact-plan confirmation, fresh governed
launch and final acceptance, canonical Finding ingestion and durable reopening.
`NucleiAuthorityDeniedError` distinguishes operator denial from filesystem access
failures. Native authority-only host records require exact URL/scheme/port agreement;
their decoded context URL/path must match the approved input's derived representation,
while `matched-at` keeps exact provider-stable URL validation. Existing full-URL
records remain supported. Genuine pinned Nuclei 3.4.10 acceptance
uses a pytest-owned loopback target; the provider remains optional.

`fuzzy1337.native_web`, `fuzzy1337.adapters.native_web` and
`1337 scan web --check git-head-exposure` are Experimental at version `1`.
ADR 0086 defines one explicitly selected first-party Git HEAD response check with
STANDARD exact-plan confirmation and the existing policy/executor/job/evidence/
Finding owners. `fuzzy1337.native_web_worker` is Internal. Existing status-only
discovery and closed HTML acquisition shapes are unchanged. Retained original
worker reports bind the observed predicate; absent transient response bodies
cannot be independently re-evaluated during replay. See
[Native web checks](NATIVE_WEB_CHECKS.md).

ADR 0088 adds Experimental `native.file-canary-disclosure` through SDK `check_id`
and CLI `--check file-canary-disclosure`. Its separate capability and closed
profile accept only the owned literal-loopback fixture paths and three exact
query values. Dedicated scope allow/exclude canary flags retain generic URL query
refusal. Existing Git defaults, invocation arguments and original report fields
remain unchanged. The canary report additionally binds its anonymous request
template and query injection references; response bodies remain transient.

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

Reviewed baseline pack revision `0.2.0` adds six approved exact-content relations
and seven pinned primary-source artifacts within unchanged schema `1`. ADR 0063
and `docs/STANDARDS_MAPPING_BASELINE.md` define the recorded content decisions,
selected historical versions, and advisory contextual relations. Typed finding
bindings validate the existing Finding projection without changing model identity
or triage; the original candidate baseline remains compatible.

`fuzzy1337.policy` is an Experimental Python library at contract version `1`.
ADR 0025 defines its typed, bounded subsystem contract.
The interface grants no authority beyond an explicitly approved scope/policy.

`fuzzy1337.native_image_capture` is an Internal bounded original VERSION/SCAN
custody producer under ADR 0058. Exact caller-issued execution authorization,
explicit selected reads, unchanged material facts and original receipt provenance
remain required. Observed provider version is separate from the original
unobserved VERSION invocation. The legacy importer is unchanged; native IMAGE
product authorization remains separate. The producer performs no model save.

`fuzzy1337.native_image_admission` is an Internal original-pair consumer under
ADR 0067. Six immutable owning manifests, original receipts, exact executed
requests and full VERSION prerequisite association precede canonical native
image/package/Finding interpretation. Existing model schema, provider-independent
identities and Finding triage remain unchanged. Legacy executionless VERSION
health ingestion and the isolated synthetic image family retain their existing
contracts. Admission proposes an in-memory transition; the caller owns model CAS
and workspace saves. Historical replay opens retained evidence without old
selected material or current execution authority. Native SDK execution grants
and the native CLI/job workflow remain separate work.

`fuzzy1337.images` is an Experimental offline interpretation library at contract
version `1`. ADR 0040 and `docs/IMAGES.md` define ASSET-based image/package identities,
verified native/SBOM imports and canonical Finding correlation without changing
the existing model schema or granting execution authority.
`TrivyCandidates` and `SyntheticTrivyCandidates` remain Internal pure helpers.
The synthetic helper has a fixed fixture namespace and does not admit evidence,
apply a model transition, grant execution or change native import behavior.

`fuzzy1337.docker_inventory` is an Experimental owned offline Docker container
inspect input profile at contract version `1`, defined by ADR 0070 and
`docs/DOCKER_INVENTORY.md`. It requires exact owning raw evidence attribution and
an existing explicit literal HOST. Host-scoped container/network/service/resource
facts reuse canonical model types and image config identity without a schema
change. Missing facts remain unknown; direct configured-condition findings
preserve operator triage and never confirm physical access or exploitability.
Associations remain UNKNOWN reachability inputs without separate admitted claims.
The importer returns one in-memory transition and grants no live daemon/network
authority. Other helpers remain Internal; daemon discovery and physical runtime
acceptance remain separate.

`runtime import docker-inspect` and `runtime import kubernetes-list` are the two
closed Experimental owned offline product profiles at contract version `1`,
defined by ADRs 0078/0079 and `docs/RUNTIME_IMPORT.md`. Docker requires explicit
`--host` with an existing literal HOST; Kubernetes requires explicit `--cluster`
with an existing declared cluster ASSET and matching literal cluster identity.
Both require local scope and exact model/workspace revision bases before source
reads, without default anchors or execution grants. New-file selection requires
explicit read-consent references and a bounded stable singly linked physical file;
retained selection verifies the exact original manifest and preserves its source
and first profile/anchor/run context. Selected manifests are identity/profile/
role/media/size/source-version preflighted without reading blobs, then bound to
the owning workspace/scope before retained raw reads. One source observation on
the selected HOST or cluster ASSET binds original acquisition
identity before separate model/workspace CAS saves. Schema-one terminal summaries
distinguish acquisition, model and workspace acknowledgements, including unknown
save outcomes and partial commits; they promise no cross-store atomic transaction.
Exact retained replay preserves owner bytes, triage and UNKNOWN source meanings.
All `fuzzy1337.runtime_commands` classes, functions and helpers, including
`RuntimeParser`, `RunRuntimeCommands`, `RuntimeProfile`, `RequireRuntimeAnchor` and
manifest-preflight helpers, remain Internal implementation surfaces. Existing
Docker custody attribute keys, HOST/run context, original source/version and
manifest replay meanings remain unchanged; no migration is required. Kubernetes
nominal RBAC, selectors, image declarations and effective permission/enforcement
unknowns keep SDK meanings. Original exports are unredacted and explicitly
caller-owned, including exports later refused by normalization. Both profiles
reuse unchanged SDKs without changing Core schemas, scores or issuing daemon,
cluster API, execution, physical reachability or policy grants.

Internal `PreflightKnownRuntimeReferences` now enforces each known original's
one-MiB profile bound before generic workspace/report raw verification in both
import modes. It scans retained manifest IDs, model custody IDs after a lost
workspace acknowledgement and workspace/model raw references. Every
custody-declared ID must match its original profile, source hash/version,
scope/provider/time, run, read descriptions and anchor before role classification;
physical size/ownership and same-digest or same-locator aliases are checked before
raw reads. The unchanged six-field Docker custody validator retains legacy null
read descriptions and byte-preserving replay. Older scopes/providers and
unrelated larger non-runtime evidence retain their own context and limits.
This enforces the existing Experimental v1 boundary without changing product
grammar, SDK/Core schemas, scores, execution grants or version promises.

`fuzzy1337.kubernetes_inventory` is an Experimental owned offline Kubernetes
`v1`/`List` input profile at contract version `1`, defined by ADR 0074 and
`docs/KUBERNETES_INVENTORY.md`. `KubernetesInventoryLimits` and
`ApplyVerifiedKubernetesList` are its supported surface; all other helpers remain
Internal. Exact original evidence attribution, a declared cluster ASSET and the
current persisted model basis precede one caller-persisted in-memory transition.
Cluster-separated UID identities, nominal RBAC and configured selector/owner/
Service/Ingress/NetworkPolicy associations reuse existing model types. Missing
facts, effective permissions, aggregation, CNI enforcement and image digest
domains remain unknown. OPEN configured-condition findings preserve operator
triage; relationships grant no authorization or confirmed reachability. Unsupported
kinds, including Secret, fail before normalization. Original bytes remain exact
and are not redacted; the caller supplies a non-sensitive owned export. Live
discovery and full privilege validation remain separate work.

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

`fuzzy1337.sbom_graph` is a separate Experimental offline local-package graph
interpretation library at contract version `1`. ADR 0073 and `docs/SBOM_GRAPH.md`
define its supported `SPDX_GRAPH_IMPORT_VERSION` and `ApplyVerifiedSpdxGraph`
surface; remaining helpers are Internal. It preserves the flat SPDX profile,
original evidence, canonical package/image identities and finding triage while
adding direct nested containment and attributed local dependency claims.
Containment must remain rooted and acyclic after package alias correlation;
dependencies assert no runtime reachability. Inert license roles remain separate,
and model persistence retains the existing explicit CAS save boundary. No Core
schema, native authorization or execution receipt contract changes.

`sbom import spdx-graph` is an Experimental owned offline product command at
contract version `1`, available in the installed CLI and interactive shell.
ADR 0082 and `docs/SBOM_IMPORT.md` define explicit original-file read consent,
source ID/version, image digest and `config`/`manifest` kind, existing offline
scope/run and current model/workspace revision bases. Retained mode accepts only
known product custody independently bound to the original acquisition manifest;
equal raw bytes supply no substitute identity or context override. Both modes
preflight all known original SBOM blobs and same-SHA/same-locator aliases before
generic evidence reads, including model-only custody after workspace-save loss.
Original unredacted bytes stay bounded to four MiB, older sources retain their
own scope/media context, and unrelated larger non-SBOM evidence keeps its existing
owner budgets. One unchanged SDK transition and custody fact share one model
revision, with separate acquisition/model/workspace acknowledgements and honest
partial or lost-save outcomes. Portable exact replay preserves bytes and triage;
dependency reachability stays UNKNOWN without verified assessment, and license
facts assert no compliance result. All classes, functions, methods and helpers
in `fuzzy1337.sbom_commands`, including `SbomParser` and `RunSbomCommands`, and
its schema-one terminal summary remain Internal. No SDK/Core schema, native
authorization, read-grant default, remote retrieval or scanner contract changes.

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

`fuzzy1337.ioc_artifacts` is an Experimental schema-one offline candidate and
evidence library under ADR 0076 and `docs/IOC_ARTIFACTS.md`. Its supported exports
are `IocSource`, `IocLimits`, `IocCandidate`, `IocRequest`, `IocSnapshot`,
`IocAcquisition`, `ParseIocArtifact`, `AcquireIocArtifact`, `ReplayIocArtifact`
and `LoadIocArtifact`; other helpers and module constants remain Internal. The
closed ASCII TSV profile preserves supplied IPv4/IPv6/DNS/SHA-256 occurrences,
original token/source/time declarations, separate observed acquisition clocks,
finite budgets and immutable raw/receipt/snapshot pins with portable reparse. It
requires an independent caller-retained original acquisition record/id alongside
the selected snapshot for replay; the candidate cannot choose its trusted anchor.
It adds no incident/event/Core schema, model mutation, probing or scan authority.

The Experimental contract-version-one `trace ioc import|inspect` CLI and
foreground shell commands expose that same original acquisition and independently
anchored replay under ADR 0080 and `docs/IOC_ARTIFACT_CLI.md`. Import requires
explicit owned non-secret file, source/version/license/hash/scope/read-consent
selections and finite quotas. Physical singly linked file identities must remain
stable within path and handle views; the accepted Windows cross-view ctime
allowance never permits a same-view change. Inspect requires separate original
snapshot and receipt manifest identities and accepts no source/consent override.
Schema-one summaries contain counts, observed hash/length, acquisition times and
confirmed evidence identifiers, without original tokens or physical paths.
Digest/parse refusal retains confirmed raw/receipt records; failed acknowledgement
may leave immutable evidence with `unknown` commitment and no rollback claim.
Neither action saves Core/workspace state, resolves names, probes hosts or grants
current authority. All `fuzzy1337.ioc_commands` classes, functions, methods and
helpers, including `IocParser` and `RunIocCommands`, remain Internal implementation
surfaces; their visibility does not establish a supported Python SDK.

`fuzzy1337.intelligence_acquisition` is an Experimental schema-v1 acquisition and
receipt library under ADR 0060. Explicit local source bytes or an immutable
official CISA mirror selection produce bounded immutable evidence and truthful
complete/partial outcomes; replay requires the original owning raw record and
receiver provenance. `fuzzy1337.intelligence_transport` and acquisition helpers
remain Internal. No publisher-signature authentication, automatic refresh,
applicability conclusion or scan authority is provided.

The Experimental `intel import|inspect|apply` CLI and shell commands expose
explicit local acquisition, verified receipt/snapshot inspection and selected
Finding enrichment through the existing CAS model owner. ADR 0069 and
`docs/INTELLIGENCE_CLI.md` define bounded schema-v1 JSON outcomes, original-record
verification, triage preservation and honest save uncertainty. The command
implementation remains Internal; no remote scheduling or automatic refresh is
introduced.

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

`fuzzy1337.configuration_evidence` and `fuzzy1337.configuration_workflow` are additive
Experimental consumers of the reviewed synthetic SCAN-only configuration family.
The Experimental `1337 scan config --profile synthetic` command under ADR 0072
adds explicit Dockerfile/Kubernetes type selection over this same five-case family,
without changing its source grammar, evidence identities or approval contract.
Its CLI and foreground-shell terminal outcomes and optional JSON/SARIF exports
preserve the existing workflow's actual execution and publication facts.

The exact four-role source/stream/receipt capture is schema 1; original SDK metadata
retains schema 2. Historical verification is read-only after relocation and grants
no current execution/model authority. Live interpretation requires original typed
runs and fresh canonical SDK acceptance. Assets use a separate synthetic configuration
namespace, and typed source-position Finding re-detection preserves operator triage.
The job uses the existing evidence, model, scope and workspace stores and revision
checks; model/workspace saves are distinct, with honest storage-failure outcomes
rather than a claimed transaction spanning both stores. JSON/SARIF export projects
the exact saved snapshot. Native configuration and arbitrary-source detection remain
unavailable; scan completeness is unassessed. See [the workflow](CONFIGURATION_WORKFLOW.md)
and [ADR 0068](adr/0068-configuration-evidence-workflow.md).

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
