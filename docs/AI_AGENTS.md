# 1337 for AI Agents in Cybersecurity

This document describes how AI systems are intended to use 1337 Security Workbench.

## Project identity

```yaml
name: 1337 Security Workbench
short_name: 1337-SW
organization: Fuzzy Technologies
architect: Timur Gilmullin
license: Apache-2.0 Community core
status: early pre-alpha
```

## AI role

AI is a peer client of the 1337 Core, not the owner of security state,
authorization, evidence, or execution policy.

1337 is intended to expose the same durable workspace to humans, automation, CI/CD,
and external or embedded AI systems.

```text
Human TUI / CI / AI
        ↓
Lens + domain queries
        ↓
Security Object Model
        ↓
Scope / Policy
        ↓
Capabilities / Executors
        ↓
Tools / Native engines / Integrations
        ↓
Evidence + state updates
```

A model may reason, plan, correlate, summarize, and propose actions. Source evidence,
scope, impact permissions, execution records, and durable objects remain explicit
1337 state.

## Why an AI agent uses 1337

Raw shell access does not provide:

- a durable Security Object Model;
- explicit scope and authorization;
- typed, discoverable capabilities;
- controlled execution boundaries;
- evidence provenance;
- persistent findings and relations;
- reachability and attack-path state;
- workflow lenses;
- reproducible reports and machine exports.

1337 is intended to provide these reusable security-domain primitives so every AI
integration does not rebuild them independently.

## Lens-aware access

The initial first-class lenses are:

```text
pentest
dfir
devsecops
purple
```

A lens is a structured focus over the same state. It may define preferred object
types, relations, queries, contextual actions, mappings, and capabilities.

An AI client should be able to request a lens and receive the relevant slice of the
workspace without creating a separate domain model.

Illustrative future operations:

```text
workspace.get
objects.search
object.get
relations.query
evidence.read
findings.query
paths.query

lenses.list
lens.apply

capabilities.list
capability.execute
```

Names above are design direction, not current Stable API contracts.

## Capability execution

A capability describes what operation is requested; a provider describes how it is
implemented.

Providers may include native engines, external tools, Kali-based executors, browsers,
workload engines, vendor scanners, or private integrations.

AI execution remains governed:

```text
AI
 ↓
Capability request
 ↓
Identity + Scope + Policy + Impact
 ↓
Job / Executor / Provider
 ↓
Structured observations + Evidence
 ↓
Security Object Model update
```

MCP is an adapter to these domain/capability contracts. It is not the architecture
foundation and it must not provide an unrestricted shell bypass.

## Model agnosticism

The workspace must survive model/provider changes.

The architecture should support commercial frontier models, enterprise-hosted
models, local/self-hosted models, air-gapped models, and future security-specialized
models without migrating the underlying security state.

A model vendor should also be able to install/use 1337 as a reusable investigation
substrate: open or import a workspace, apply a lens, query the model, inspect
evidence, and request bounded capabilities.

## Evidence boundary

```text
Raw Evidence
    ↓
Observation
    ↓
Security Object / Relation
    ↓
Finding / Correlation
    ↓
Inference
    ↓
AI Interpretation
```

AI interpretation is not automatically evidence or a confirmed finding.

## Integrations

External systems may interact with 1337 as:

- **imports/sensors** that enrich the model;
- **execution providers** for capabilities;
- **exports/destinations** for findings, evidence, reports, or remediation work.

Large vendor-specific integrations belong behind reusable contracts. They do not
change the canonical Security Object Model.

## Architectural invariant

> **Models reason. 1337 keeps state, governs execution, and preserves evidence.**

See also:

- [Project vision](VISION.md)
- [ADR 0008](adr/0008-ai-native-cyber-execution-platform.md)
- [ADR 0010](adr/0010-live-security-object-model-modular-tooling-and-lenses.md)
- [Compatibility policy](COMPATIBILITY.md)
