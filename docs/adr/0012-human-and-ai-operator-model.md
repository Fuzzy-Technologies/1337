# ADR 0012: Human and AI Operator Model

## Status

Accepted

## Context

1337 is designed as a security workstation where different operators can work
with the same durable security state.

Supported operator types include:

- human security analysts;
- automation workflows;
- AI reasoning agents;
- CI/CD and external integrations.

The reasoning component must not become the owner of security truth,
authorization, or evidence. Security state must remain durable and independent
from a specific model, provider, or operator.

## Decision

1337 separates the operator layer from the security state layer.

Operators interact with the Workbench through controlled capabilities:

```text
Human operator
AI reasoning agent
Automation workflow
CI/CD integration
        |
        v
1337 Workbench
        |
        +-- Security Object Model
        +-- Evidence & Provenance
        +-- Scope & Policy
        +-- Capability Fabric
        +-- Executor Runtime
```

All operators:

- use the same Security Object Model;
- operate within Scope & Policy boundaries;
- execute through governed capabilities;
- produce Evidence & Provenance records.

AI models are replaceable reasoning clients. They may analyze, query, and
request bounded operations, but they do not own:

- durable security state;
- authorization decisions;
- evidence integrity.

## Consequences

Positive:

- human and AI workflows can coexist on the same workspace;
- model/provider changes do not invalidate security history;
- automation can reuse the same execution and evidence contracts;
- investigations remain reproducible.

Negative:

- stable API boundaries are required;
- execution contracts and provenance must be maintained carefully.

## Non-goals

1337 is not an autonomous hacking agent product.

1337 does not delegate authorization or evidence ownership to AI systems.

The goal is to provide a durable security operating environment for human,
automated, and AI-assisted security operations.

## Invariant

> Operators are replaceable. Security state is not.
