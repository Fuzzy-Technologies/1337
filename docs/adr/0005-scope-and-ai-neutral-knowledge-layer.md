# ADR 0005: 1337Scope and model-agnostic security knowledge layer

- Status: Accepted
- Date: 2026-09-08
- Decision owners: Fuzzy Technologies

> Terminology clarification — 2026-09-11: **model-agnostic** means independent
> of a particular AI model or provider. It does not refer to threat models.

## Context

The differentiated value of 1337 depends on understanding an evolving system model,
attack surface, evidence, and reachability rather than only detecting isolated web
vulnerabilities.

The workstation also needs useful first-party discovery before optional third-party
tools are installed.

## Decision

1337Scope is the native discovery and attack-surface direction of the Workbench.

A minimal native discovery baseline should appear early enough to create and update
the first Security Objects for an authorized target. Advanced Web/API/browser and
reachability capabilities may arrive in later milestones.

Native discovery creates the initial model. Other tools do not create parallel truth
stores; they contribute attributable observations and evidence that enrich or
challenge existing objects and relations.

The broader direction includes:

- asset, host, domain, service, technology, web, and API discovery;
- endpoint and relationship modelling;
- evidence collection;
- safe security checks;
- authenticated/browser discovery;
- attack-surface and reachability modelling;
- attack-path graphs.

The shared security knowledge layer is model-agnostic. Human interfaces,
automation, integrations, and AI clients consume the same structured objects,
observations, evidence, findings, relations, paths, and remediation context through
explicit contracts.

AI is not the source of truth for evidence, scope, authorization, or security
actions.

## Consequences

- Quick Scan must produce/update Security Objects rather than only collect scanner
  output.
- Tool adapters act as sensors/capability providers and preserve source provenance.
- Scanner, graph, report, lens, and agent work reuse the shared domain model.
- No AI integration receives implicit authorization to scan, validate, or act.
- Native discovery remains useful without Kali, a commercial scanner, or an
  external AI provider.

This ADR records architecture direction, not a claim that 1337Scope or the live
Security Object Model is already implemented.

ADR 0010 further clarifies the Workbench-centered model and modular-tooling boundary.
