# 1337 Security Workbench

## Open security workbench · Live Security Object Model · Modular tooling

**1337 Security Workbench (1337-SW) by Fuzzy Technologies** is a fast, local-first
workbench for hands-on security work.

Built-in discovery creates an initial **Security Object Model** of the system under
study. Native and external tools then enrich that model with observations, evidence,
findings, relationships, reachability, and attack paths.

> **Models reason. 1337 keeps state, governs execution, and preserves evidence**

> **Technologies · Knowledge · Science**

## What 1337 is

Security work is spread across terminals, scanners, browsers, files, logs, reports,
and vendor consoles. The difficult part is not producing another scanner result; it
is preserving what was learned, why it is believed, and how the pieces connect.

1337 keeps that state in one workspace:

```text
Human / AI / CI
      ↓
Workflow Lens
      ↓
Security Object Model
      ↑
      ├── Built-in discovery
      ├── Native capabilities
      ├── External tools / Kali toolsets
      ├── Browser / workload engines
      └── Imports / vendor integrations
      ↓
Observations + Evidence + Findings + Relationships
      ↓
Reachability / Attack Paths / Reports
```

The initial workflow lenses are:

- **Pentest** — attack surface, footholds, pivots, findings, reachability, and attack paths;
- **DFIR** — evidence, timelines, entities, provenance, and observed attack paths;
- **DevSecOps** — source, dependencies, images, deployments, APIs, and release risk;
- **Purple Team** — authorized actions, telemetry, detections, controls, and retest results.

## Design principles

**Tools remain tools.** 1337 does not hide specialist utilities behind a mandatory
workflow engine. Experienced operators can keep using familiar command-line tools;
typed adapters add structured state, evidence, and repeatability where useful.

**The model updates while you work.** Long-running jobs are intended to stream
progress, observations, and object changes instead of blocking the interface. The
planned terminal workbench places actions and commands on the left and a focused
view of the evolving model on the right.

**The base installation stays lightweight.** Core workflows are local-first and do
not require persistent endpoint agents. Large scanners, browser runtimes, Kali
toolsets, search indexes, and vendor connectors are optional components enabled only
when needed.

**AI is another client of the Core.** API/SDK/MCP interfaces are intended to expose
the same state and governed capabilities used by human operators and automation.
AI does not own authorization, source evidence, or durable workspace state.

## Status

1337 is in **early pre-alpha**.

Current code covers the engineering baseline and early M1 work. The live workbench,
built-in discovery, production scanner adapters, Security Object Model workflows,
evidence/reachability pipelines, workflow lenses, AI interfaces, and advanced
integrations remain roadmap work unless explicitly documented otherwise.

The Community repository is licensed under Apache-2.0.

## Roadmap

| Phase | Focus | Target outcome |
| --- | --- | --- |
| [**M0**](https://github.com/Fuzzy-Technologies/1337/milestone/1) | Foundation | Repository baseline, CI, containers, synthetic lab, engineering and architecture contracts |
| [**M1**](https://github.com/Fuzzy-Technologies/1337/milestone/2) | Community Core & Live Workbench | Fast shell/TUI, workspace, scope, persistence boundaries, live model-view foundations, diagnostics, performance budgets |
| [**M2**](https://github.com/Fuzzy-Technologies/1337/milestone/3) | Execution, Discovery & Security Object Model MVP | Executor runtime, built-in discovery, minimal live model, tool adapters, Quick Scan, initial workflow lenses |
| [**M3**](https://github.com/Fuzzy-Technologies/1337/milestone/4) | Evidence, Intelligence & Mapping | Evidence, findings, vulnerability/attack intelligence, standards mappings, reports |
| [**M4**](https://github.com/Fuzzy-Technologies/1337/milestone/5) | Advanced Discovery & Attack Paths | Web/API/browser/runtime discovery, user journeys, reachability, attack paths, reproducible showcase |
| [**M5**](https://github.com/Fuzzy-Technologies/1337/milestone/6) | Analytical UX | Large-scale tables, graph visualization, prioritization, advanced mapping UX |
| [**M6**](https://github.com/Fuzzy-Technologies/1337/milestone/7) | Automation, Integrations & AI | Domain API/SDK, CI/CD, vendor integrations, remote executors, MCP, AI access |
| [**M7**](https://github.com/Fuzzy-Technologies/1337/milestone/8) | Authorized Validation | Fuzzy Striker and mature Purple Team validation workflows |
| [**M8**](https://github.com/Fuzzy-Technologies/1337/milestone/9) | 1337 Trace | DFIR ingestion, evidence integrity/custody, incident timeline, observed attack graph |
| [**M9**](https://github.com/Fuzzy-Technologies/1337/milestone/10) | Cloud & Enterprise Contracts | Verified assets, cloud-safe contracts, stable enterprise extension interfaces |

Detailed planning lives in the linked GitHub milestones and issues.

## Architecture and project docs

- [Vision](docs/VISION.md)
- [ADR 0010: live Security Object Model, modular tooling, and operator lenses](docs/adr/0010-live-security-object-model-modular-tooling-and-lenses.md)
- [ADR 0008: model-agnostic execution, state, and evidence platform](docs/adr/0008-ai-native-cyber-execution-platform.md)
- [ADR 0009: operator profiles and orthogonal execution dimensions](docs/adr/0009-operator-profiles-and-orthogonal-execution-dimensions.md)
- [1337 for AI agents in cybersecurity](docs/AI_AGENTS.md)
- [Machine-readable project summary](llms.txt)
- [Compatibility](docs/COMPATIBILITY.md)
- [Terminology](docs/TERMINOLOGY.md)

## Development

Use Python 3.11+ from the repository root:

```bash
python -m pip install uv==0.11.33
uv run --locked 1337-dev setup
uv run --locked 1337 --version
uv run --locked 1337-dev unit
uv run --locked 1337-dev check
```

See [Python development](docs/DEVELOPMENT.md),
[Container development](docs/CONTAINERS.md),
[Development protocol](DEVELOPMENT_PROTOCOL.md), and
[Release workflow](docs/RELEASE_WORKFLOW.md).

The stable public branch is `master`. Active integration development occurs on
`develop`; feature work is performed on short-lived branches and reviewed before
merge.

## Responsible use

1337 is intended for defensive security engineering, authorized security assessment,
investigations, training, research, CTF/lab environments, and systems you own or are
explicitly authorized to assess.

See [SECURITY.md](SECURITY.md).

## License

Apache License 2.0.

Copyright © Fuzzy Technologies.
