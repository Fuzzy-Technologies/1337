# ADR 0004: CLI-primary and complementary local Web UI

- Status: Accepted
- Date: 2026-09-08
- Decision owners: Fuzzy Technologies

## Context

Hands-on security workflows need a fast native command-line experience that works
well with Linux tooling, terminals, automation, scripts, and direct expert use.
At the same time, the Security Object Model, evidence, paths, and timelines need
interactive views that are more useful than raw command output.

A Web UI must not become a prerequisite for the technical workflow or hide the
underlying evidence and commands.

## Decision

The `1337` CLI and interactive terminal workbench are the primary technical
interface. The local Web UI is a complementary view over the same workspace and
domain contracts.

The terminal workbench direction is split-pane and keyboard-first:

```text
┌────────────────────────────┬────────────────────────────────────┐
│ Actions / commands / tools │ Live Security Object Model slice   │
│ contextual operations      │ selected lens / object / path      │
│ palette / history / raw CLI│ evidence / findings / timeline     │
└────────────────────────────┴────────────────────────────────────┘
```

The model pane is intentionally a focused slice rather than an attempt to render the
entire graph in a terminal.

The shell should support:

- fast startup and interactive readiness;
- fuzzy command discovery and contextual help;
- command palette and history search;
- raw expert CLI workflows where authorized;
- object-aware contextual actions;
- lens switching;
- non-blocking job execution;
- streaming progress, observations, evidence references, and model deltas.

The local Web UI may later provide large analytical tables, larger graph views,
semantic zoom, reports, and management-oriented presentation, but it consumes the
same Security Object Model and evidence.

Commands such as `1337 scan`, `1337 objects`, `1337 findings`, `1337 paths`,
and `1337 report` remain illustrative until their product tasks define public
contracts.

## Consequences

- TUI and Web views must not create competing security state.
- Long-running work must not freeze the operator interface.
- Performance budgets for startup, search, view changes, object lookup, and
  incremental rendering are measured and regression-tested.
- Friendly interfaces do not weaken scope, policy, impact, or authorization.
- Large graph visualization remains a later analytical-UX concern; the terminal
  only needs the relevant live slice.

This ADR is clarified by ADR 0010.
