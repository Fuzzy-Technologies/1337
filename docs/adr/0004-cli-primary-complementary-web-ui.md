# ADR 0004: CLI-primary and complementary local Web UI

- Status: Accepted
- Date: 2026-09-08
- Decision owners: Fuzzy Technologies

## Context

Red-team and security-engineering workflows need a fast native command-line
experience that works well with Linux tooling, terminals, automation, and
scripts. At the same time, blue-team and management users need readable views
of assets, evidence, risk, remediation, and attack paths.

A Web UI should not turn the product into a slow replacement for the technical
workflow or hide the evidence needed by practitioners.

## Decision

The `1337` CLI and interactive shell are the primary technical interface. Future
shell work should support command discovery, contextual help, autocomplete,
aliases, and scriptable non-interactive commands.

The local Web UI is a complementary view over the same workspace and evidence
model. It does not replace the CLI.

- Security practitioners use the CLI and detailed views to work with targets,
  evidence, hypotheses, and technical findings.
- Security teams use the UI to understand affected assets, attack paths, and
  mitigation choices.
- Management-facing views emphasize business context, priorities, remediation
  progress, and decision-ready explanations.

Commands such as `1337 scan`, `1337 assets`, `1337 findings`, `1337 graph`, and
`1337 report` illustrate the intended interaction model. Their syntax and
availability remain future public contracts until the corresponding product work
defines and tests them.

## Consequences

CLI and Web UI features must consume compatible workspace, evidence, finding,
and graph contracts rather than create separate interpretations of an assessment.
No user interface may weaken authorization, scope, or impact controls; a friendly
flow is not permission to assess an unapproved target.
