# ADR 0010: Live Security Object Model, modular tooling, and operator lenses

## Status

Accepted — 2026-09-12

## Context

The existing architecture already defines a Security Object Model, Capability
Fabric, Scope/Policy, Executor Runtime, evidence/provenance, and reachability graph.
Recent roadmap work also defines native discovery, external tool adapters, DFIR,
DevSecOps, Purple workflows, integrations, and AI/MCP access.

The remaining risk is product shape: these components could be implemented as a
large centralized platform or as an orchestration layer around scanners, neither of
which matches the intended fast security workstation.

The Workbench must remain useful to one engineer with a local or portable
installation while still allowing larger integrations and AI clients later.

## Decision

### 1. Security Object Model is the center

The durable Security Object Model is the central operational state of 1337.

Native discovery creates the initial model. Built-in capabilities, external tools,
browsers, workload engines, imported evidence, and vendor integrations enrich the
same model with attributable observations.

No sensor/tool owns a parallel authoritative model.

### 2. Native discovery appears before advanced scanners

Quick Scan and the early useful Workbench must be able to discover enough
information to create a minimal model without requiring Kali or third-party scanners.

The minimal model may initially cover targets, domains/hosts, services/ports,
endpoints, technologies, observations, and relations. Later milestones extend the
same model with identities, controls, runtime objects, findings, reachability,
attack paths, forensic entities, and other domains.

### 3. Tooling is first-class and modular

A capability describes what operation is requested. Providers may include:

- native 1337 engines;
- external tools;
- Kali or other executor/tool packs;
- browsers;
- workload engines;
- vendor/commercial scanners;
- integrations and imported sources.

Providers are replaceable where contracts allow it.

Large dependencies are optional, installed/started on demand, locally cacheable, and
must not make the base Workbench slow to start.

### 4. Agentless-first

Core value must not require deployment of persistent 1337 agents to every target.

Agentless discovery, tool execution, browser/API traffic, imported logs/artifacts,
and existing vendor APIs are normal data sources. Persistent sensors may be added as
optional providers later.

### 5. One model, initial four lenses

The initial first-class lenses are:

```text
pentest
dfir
devsecops
purple
```

Lenses change focus, queries, contextual actions, mappings, preferred capabilities,
and presentation. They do not create alternate truth stores.

Additional lenses are added only when a real workflow justifies them.

### 6. Live terminal Workbench

The primary technical UX is keyboard-first and non-blocking.

```text
left: actions / commands / tools
right: relevant live Security Object Model slice
```

Long-running work streams job progress, observations, evidence references, and object
deltas. The operator can continue interacting while backend work runs.

The terminal does not need to render the full graph. It renders the useful slice for
the selected workspace, object, path, or lens.

### 7. Canonical state and search indexes are separate

Authoritative workspace state and evidence must be accessible independently from an
accelerated search engine.

Portable/local persistence is the default design constraint. Optional search indexes
such as Elasticsearch may be used for large JSON, logs, IOC, forensic, and full-text
workloads, but they remain rebuildable indexes rather than the only source of truth.

### 8. AI and integrations are peers around the Core

Human UI, CI/CD, vendor integrations, and AI systems consume the same domain state.

API/SDK/MCP may expose model queries, evidence, findings, paths, lenses, and bounded
capabilities. AI does not receive a privileged authorization bypass.

Vendor integrations use explicit import/enrich, execute, or export contracts.

### 9. Performance is a product invariant

The model may be rich; the workstation must stay fast.

Engineering must measure and guard:

- startup/readiness;
- command and palette response;
- local object/search response;
- lens/view changes;
- incremental model rendering;
- job progress visibility.

Backend operations may take time; the primary UI must remain responsive.

## Consequences

- M1 shell/TUI work must be designed as a live Workbench, not a disposable command
  parser.
- M2 must establish a minimal Security Object Model and native discovery baseline in
  addition to executor/tool-adapter work.
- Quick Scan must update the model as it discovers state.
- External tools are sensors/capability providers that enrich shared state.
- Lens contracts move earlier than mature domain workflows.
- Full DFIR ingestion, advanced graph UX, large Web UI, AI automation, and enterprise
  deployment remain later milestones.
- Kali, Elasticsearch, browsers, large scanners, and vendor systems remain optional
  providers rather than mandatory Core dependencies.

## Relationship to previous ADRs

This ADR clarifies and composes existing accepted decisions; it does not replace
their core boundaries.

- ADR 0003 remains the intelligence/evidence direction.
- ADR 0004 remains CLI-primary with complementary Web UI.
- ADR 0005 remains native 1337Scope and model-agnostic knowledge direction.
- ADR 0008 remains the durable execution/state/evidence Core boundary.
- ADR 0009 remains the shared-state profile model and orthogonal execution
  dimensions.

## Architectural invariants

> **Models reason. 1337 keeps state, governs execution, and preserves evidence.**

> **One Security Object Model. Multiple lenses. Any suitable tool.**

> **The model may be rich. The workstation must stay fast.**
