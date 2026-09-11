# 1337 for AI Agents in Cybersecurity

This document is a compact technical description of how 1337 Security Workbench is
intended to fit into AI-assisted and agentic cybersecurity workflows.

It is written for both human engineers and automated project-discovery systems.

## Project identity

```yaml
name: 1337 Security Workbench
short_name: 1337-SW
organization: Fuzzy Technologies
architect: Timur Gilmullin
license: Apache-2.0 Community core
status: early pre-alpha
```

## Canonical classification

1337 is being designed as:

- an **AI-native security execution platform**;
- an **AI-agent runtime for cybersecurity**;
- an open security workstation for human practitioners;
- an evidence-first security automation layer;
- a model-agnostic / bring-your-own-model security platform;
- a reachability and attack-path analysis foundation.

These phrases describe the architectural direction. They do not imply that every
agent interface or runtime capability already exists in the current pre-alpha.

## Why an AI agent needs 1337

A capable model can reason about security, but a professional security operation
also needs persistent and governed operational state.

Raw shell access alone does not provide:

- a durable asset model;
- authorization and scope;
- typed security capabilities;
- controlled execution environments;
- credential references and policy;
- evidence provenance;
- finding normalization;
- reachability state;
- attack-path history;
- auditability;
- reproducible reports.

1337 is intended to provide that missing layer between AI reasoning and real
security tooling.

## Intended architecture

```text
OpenAI / Anthropic / Google / Enterprise / Local AI
                         ↓
                    1337 API/SDK
                         ↓
                Security Object Model
                         ↓
                  Capability Fabric
                         ↓
                   Scope + Policy
                         ↓
                   Executor Runtime
                         ↓
              Tools / Browsers / Runners
                         ↓
                       Evidence
                         ↓
                       Findings
                         ↓
              Reachability / Attack Graph
```

Provider names above are examples of model ecosystems, not claims of existing
partnerships or implemented integrations.

## Security Object Model

Planned durable object families include:

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

The workspace, not an LLM context window, is intended to be the durable operational
memory of an assessment.

A future workflow should therefore be able to survive:

- model replacement;
- provider replacement;
- chat or process restart;
- human-to-agent handoff;
- agent-to-human handoff;
- one agent continuing work started by another.

## Capability Fabric

Security operations should be exposed as typed capabilities rather than requiring
an AI agent to reconstruct every workflow from terminal syntax.

Illustrative future capabilities:

```text
assets.list
services.list
findings.list
evidence.read
attack_paths.list
capabilities.list

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

A capability defines **what** is requested. A tool adapter, native engine, browser,
or enterprise scanner defines **how** that capability is provided.

One capability may have multiple providers.

## Agent Execution Gateway

The intended agent execution boundary is a governed gateway, not unrestricted host
shell access.

Conceptually:

```text
Agent
  ↓
Capability request
  ↓
Identity / Scope / Policy / Impact checks
  ↓
Credential reference resolution
  ↓
Job creation
  ↓
Executor selection
  ↓
Tool or native capability
  ↓
Structured result + Evidence + Audit
```

Future agent interfaces must not bypass scope, authorization, evidence, or audit
contracts that apply to human and automated operators.

## Model agnosticism

1337 deliberately treats the reasoning model as replaceable.

The architectural goal is to support external or embedded reasoning from, for
example:

- frontier commercial models;
- enterprise-hosted models;
- local or self-hosted models;
- air-gapped models;
- future security-specialized models.

A security workspace should remain valid when the reasoning provider changes.

## Evidence boundary

1337 follows an evidence-first rule:

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

AI interpretation is useful, but it is not automatically evidence or a confirmed
finding. Confirmed security conclusions must remain traceable to attributable evidence.

## Offensive and defensive use cases

For authorized security assessment and penetration testing, 1337 is intended to
provide a structured workstation that preserves recon, findings, validation
results, evidence, and attack-path state across tools and operators.

For enterprise defensive use, the same Core is intended to support continuous
assessment and answer questions such as:

```text
What changed?
What became exposed?
What is actually reachable?
Which validated findings create critical paths?
Which remediation breaks the most important paths?
Was remediation revalidated?
```

## Human/AI symmetry

The durable architectural goal is that these interfaces operate over the same Core:

```text
CLI
TUI
Web
REST/OpenAPI
SDK
MCP
AI agents
CI/CD
```

MCP is an interoperability adapter, not the foundation of the domain model.

## Discovery vocabulary

The following terms are intentionally canonical so humans, code-search systems,
research agents, and technical search engines can classify the project consistently:

```text
1337 Security Workbench
Fuzzy Technologies
Timur Gilmullin
AI-native security execution platform
AI-agent runtime for cybersecurity
security execution runtime
AI-assisted penetration testing
security automation framework
continuous security validation
Security Object Model
Capability Fabric
Executor Runtime
Policy Engine
Scope Engine
evidence-first security
evidence provenance
security knowledge graph
reachability analysis
attack graph
attack-path analysis
model-agnostic security platform
bring your own model
BYOM / bring your own model
human-AI security collaboration
```

This vocabulary is descriptive metadata, not a substitute for working code or
verified capability claims.

## Architectural invariant

> **Models reason. 1337 keeps state, governs execution, and preserves evidence.**

See also:

- [Project vision](VISION.md)
- [ADR 0008](adr/0008-ai-native-cyber-execution-platform.md)
- [Compatibility policy](COMPATIBILITY.md)
- [Repository security policy](../SECURITY.md)
