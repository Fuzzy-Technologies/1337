# ADR 0005: 1337Scope and model-agnostic security knowledge layer

- Status: Accepted
- Date: 2026-09-08
- Decision owners: Fuzzy Technologies

> Terminology clarification — 2026-09-11: **model-agnostic** means independent
> of a particular AI model or provider. It does not refer to threat models.

## Context

The differentiated value of 1337 depends on understanding attack surface and
reachability, not only detecting isolated web vulnerabilities. The platform must
also remain useful without a particular AI provider while allowing future agents
to reason from reliable security data.

## Decision

1337Scope is the future native attack-surface intelligence engine. Its direction
includes asset, web, and API discovery; technology and endpoint modelling;
evidence collection; security checks; and attack-surface and attack-path graphs.
Its purpose is to model what an attacker can see and reach, not to become only a
web-vulnerability scanner.

The shared security knowledge layer is model-agnostic. Human interfaces, automation,
and future AI agents consume structured evidence, findings, asset models, attack
paths, and remediation context through explicit contracts.

AI is not the source of truth for evidence, scope, authorization, or security
actions. It may assist reasoning and workflow only after the deterministic data
and policy boundaries are established.

## Consequences

Future Scope, graph, scanner, report, and agent work must preserve evidence
provenance and use the shared domain model rather than inventing isolated data
stores. No AI integration may receive implicit authorization to scan, validate,
or act on a target.

This ADR records product direction only. It does not claim that 1337Scope, an
attack graph, or an AI integration is implemented in the current release.
