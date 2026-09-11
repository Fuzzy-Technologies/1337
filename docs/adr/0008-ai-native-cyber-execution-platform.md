# ADR 0008: AI-native security execution, state, and evidence platform

## Status

Accepted — 2026-09-10

> Terminology clarification — 2026-09-11: **model-agnostic** refers to
> independence from a particular AI model or provider. It does not refer to threat
> models. The ADR filename is retained to keep existing links stable.

## Context

ADR 0003 established 1337 as an intelligence-first security workbench where
specialist tools act as sensors and evidence, reachability, attack paths, and
remediation context matter more than raw vulnerability volume.

ADR 0005 established an model-agnostic security knowledge layer and requires future
human, automation, and AI clients to consume shared structured security data through
explicit contracts.

The remaining ambiguity is architectural positioning. If 1337 is treated mainly as
a scanner that later gains AI support, the project risks coupling its value to tool
launching while frontier models increasingly perform more security reasoning and
orchestration themselves.

At the same time, capable AI does not remove the need for durable security state,
authorized scope, governed execution, evidence, provenance, reachability, and audit.

## Decision

1337 is architected as a **model-agnostic security execution, state, and
evidence platform** whose public human-facing product remains **1337 Security
Workbench**.

Scanning is one family of capabilities executed by the platform.

AI is one family of clients using the platform.

Neither scanner logic nor a specific AI provider owns the Core architecture.

The durable Core boundary is:

```text
Security Object Model
        +
Capability Fabric
        +
Scope / Policy
        +
Executor Runtime
        +
Evidence / Provenance
        +
Reachability / Security Graph
```

Human interfaces, CI/CD, external agents, and future embedded agents must use the
same domain contracts wherever practical.

## Ownership boundary

A model provider may supply:

- reasoning;
- planning intelligence;
- general security knowledge;
- model-specific agent behavior.

1337 owns the platform contracts around that reasoning:

- workspace and persistent security state;
- Security Object Model;
- scope and authorization context;
- capability contracts;
- execution and executor selection;
- tool adapters and native engines;
- credential references;
- evidence and provenance;
- finding normalization;
- reachability and attack paths;
- business/security context;
- history, audit, and reporting.

The reasoning provider is replaceable. The security workspace is durable.

## Security Object Model

The shared domain model is a primary compatibility boundary. Planned first-class
object families include:

```text
Workspace
Scope
Asset
NetworkZone
Service
Endpoint
Identity
CredentialRef
Control
Capability
Action
ExecutionPlan
Job
Executor
Evidence
Finding
Reference
ReachabilityEdge
AttackPath
BusinessEvent
Report
```

Agents should reference stable security objects instead of reconstructing durable
state from natural-language chat context wherever possible.

## Capability Fabric

`Capability` is a Core primitive describing **what** security operation is requested.
A provider describes **how** it is implemented.

Illustrative capability identifiers include:

```text
network.discover
network.port_scan
service.enumerate
web.crawl
web.enumerate
tls.inspect
vulnerability.detect
vulnerability.validate
intel.enrich
report.build
```

A capability may be backed by an external tool adapter, native engine, browser,
commercial scanner, or private enterprise plugin. Higher-level workflows should not
need to depend directly on one implementation when a stable capability contract is
available.

## Human and AI symmetry

The target architecture treats these as peer interfaces over the same Core:

```text
CLI / TUI / Web / REST / SDK / MCP / AI agents / CI/CD
```

No agent-only privileged path may bypass scope, authorization, evidence, or audit
requirements that apply to the underlying action.

MCP is an adapter to the domain/capability layer, not the foundation of the domain
architecture.

## Agent execution boundary

Future AI integrations should use a governed execution gateway rather than receive
unrestricted host or root shell access by default.

Conceptually:

```text
Agent
  ↓
Capability request
  ↓
Identity + Scope + Policy + Impact checks
  ↓
Credential reference resolution
  ↓
Job / Executor
  ↓
Tool or native capability
  ↓
Structured result + Evidence + Audit
```

Raw expert CLI passthrough may remain available to human operators where authorized,
but it does not define the canonical agent contract.

## Durable state and model agnosticism

The Workspace is authoritative operational memory. An LLM context window is
transient working memory.

Security operations should therefore remain resumable across:

- model changes;
- provider changes;
- chat or process restarts;
- human-to-agent handoff;
- agent-to-human handoff;
- multi-agent handoff.

The architecture must permit bring-your-own-model integration without requiring
workspace migration when the reasoning provider changes.

## Evidence boundary

AI output is not automatically evidence.

1337 preserves the conceptual distinction:

```text
Raw Evidence
    ↓
Observation
    ↓
Finding
    ↓
Correlation / Inference
    ↓
AI Interpretation
```

Confirmed findings and security conclusions must remain attributable to supporting
evidence and execution context.

## Product consequences

For hackers and security engineers, the Community direction becomes an AI-ready
security workstation: a structured layer between specialist tooling, persistent
assessment state, evidence, and attack paths.

For enterprise security teams, the same Core can evolve toward governed continuous
security using the organization's approved AI and private execution environment.
The intended output is material security-state change and remediation priority, not
only vulnerability counts.

For AI and security-platform builders, 1337 becomes a reusable runtime for AI
security agents instead of requiring each integration to rebuild scope, adapters,
evidence storage, state, and attack-path context independently.

## Roadmap consequence

Agent **readiness** moves earlier than advanced autonomous-agent functionality.

Early milestones should establish machine-readable commands, stable object IDs,
capability contracts, structured execution results, and scope/policy hooks.

Advanced SDK/MCP integrations, distributed execution, provider routing, and
multi-agent workflows may remain later milestones.

This does not claim that the current pre-alpha already implements an Agent Execution
Gateway, attack graph, or AI integration.

## Alternatives considered

### Scanner-first platform with AI added later

Rejected as the primary architectural identity. Scanner execution remains important,
but scanner-first positioning underuses the existing evidence, reachability, and
model-agnostic domain direction.

### Proprietary cybersecurity foundation model

Rejected as a requirement for the platform. Specialized algorithms or reasoning
components may be developed later, but the Core must remain useful with external or
local models.

### AI penetration-testing agent as the entire product

Rejected. It narrows the platform to one agent implementation and does not serve the
shared human, defensive, enterprise, evidence, and graph use cases.

### MCP as the architecture

Rejected. MCP is an interoperability surface; stable security semantics belong in
the domain and capability contracts beneath it.

## Relationship to previous ADRs

This ADR **extends rather than supersedes** ADR 0003 and ADR 0005.

- ADR 0003 remains the evidence/intelligence/reachability reasoning direction.
- ADR 0005 remains the model-agnostic shared knowledge and authorization boundary.
- ADR 0008 clarifies that those primitives form a model-agnostic execution/state/
  evidence platform for both human and AI clients.

## Architectural invariant

> **Models reason. 1337 keeps state, governs execution, and preserves evidence.**

Any future AI-specific feature should be evaluated against this boundary before
introducing model-specific shortcuts into the Core.
