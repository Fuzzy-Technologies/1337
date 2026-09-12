# 1337 Security Workbench

## Open security workstation · Live Security Object Model · Modular security tooling

**1337 Security Workbench (1337-SW) by Fuzzy Technologies** is a fast, local-first
security workstation for hands-on security work. Native discovery builds an initial
**Security Object Model** of the system under study; built-in and pluggable tools
then enrich the same model with observations, evidence, findings, relations,
reachability, and attack paths.

The same durable state is presented through focused workflow lenses rather than
separate products or databases. The initial lens set is:

- **Pentest** — attack surface, footholds, pivots, findings, reachability, and paths;
- **DFIR** — evidence, timeline, entities, provenance, and observed attack paths;
- **DevSecOps** — source, dependencies, images, deployments, APIs, and release risk;
- **Purple Team** — authorized actions, telemetry, detections, controls, and retest.

> **Models reason. 1337 keeps state, governs execution, and preserves evidence**

> **Technologies · Knowledge · Science**

## Why 1337

Security work is fragmented across terminals, scanners, browsers, files, logs,
reports, and vendor consoles. The useful unit is not one scanner result; it is the
evolving model of the system and the evidence behind it.

1337 is designed around one shared state:

```text
Human / AI / CI
      ↓
Workflow Lens
      ↓
Security Object Model
      ↑
      ├── Native discovery
      ├── Built-in capabilities
      ├── External tools / Kali packs
      ├── Browser / workload engines
      └── Imports / vendor integrations
      ↓
Observations + Evidence + Findings + Relations
      ↓
Reachability / Attack Paths / Reports
```

**Tooling is first-class.** 1337 does not hide specialist tools behind a mandatory
workflow engine. Expert users may keep the native CLI experience; typed adapters and
capabilities add structured state, evidence, and repeatability when useful.

**The model is live.** Long-running jobs should stream observations and object
changes while the operator keeps working. The planned terminal workbench keeps
actions and commands on the left and a focused slice of the evolving model on the
right.

**The deployment stays lightweight.** Core operation is agentless-first and
local-first. Heavy providers, scanners, browsers, search indexes, Kali-based
executors, and vendor connectors are optional modules installed or started when the
workflow needs them.

AI remains a peer client of the same Core through stable API/SDK/MCP contracts. It
does not own authorization, source evidence, or the durable security state.

## Status

`1337` is in **early pre-alpha**. The public repository is the Apache-2.0 Community
foundation. Implemented code currently covers the engineering baseline and early M1
foundations; the live workbench, native discovery, production scanner adapters,
Security Object Model workflows, evidence/reachability pipelines, lenses, AI-agent
interfaces, and advanced integrations remain roadmap work unless explicitly
documented otherwise.

1337 is built around these durable principles:

- one fast entry point: `1337`;
- local-first and agentless-first operation;
- Security Object Model as the durable center of the workstation;
- native discovery creates the initial model;
- external tools and sensors enrich the same model;
- modular, replaceable, on-demand capability providers;
- evidence and interpretation remain separate;
- one security state, multiple lenses;
- non-blocking, streaming operator UX;
- AI, CI/CD, and integrations use the same domain contracts as human operators;
- a useful Community edition, not a crippled demo.

## Product direction

1337 Community is the only current public edition. The roadmap describes design
intent, not a claim that every capability already exists.

| Track | Engineering intention | Current boundary |
| --- | --- | --- |
| **Community** | Portable security workstation with native discovery, live Security Object Model, powerful modular tooling, evidence, reachability, attack paths, lenses, reports, and open integration surfaces | Public pre-alpha foundation; capability follows the roadmap |
| **Enterprise direction** | Optional governed deployment, integration, audit, private execution, and organization-specific controls over the same Core | Not released or available; design direction only |

The architectural boundary remains simple: models and tools are replaceable;
the workspace, security objects, authorization context, evidence, and graph are durable.

## Responsible use

1337 is intended for defensive security engineering, authorized security assessment,
training, research, CTF/lab environments, and systems you own or are explicitly
authorized to test.

Do not use the project to scan, probe, exploit, or disrupt third-party systems
without authorization.

See [SECURITY.md](SECURITY.md).

## Roadmap

| Phase | Focus | Target outcome |
| --- | --- | --- |
| [**M0**](https://github.com/Fuzzy-Technologies/1337/milestone/1) | Foundation | Repository baseline, engineering controls, CI, containers, synthetic test lab, durable architecture contracts |
| [**M1**](https://github.com/Fuzzy-Technologies/1337/milestone/2) | Community Core & Live Workbench | Fast shell/TUI, workspace, scope, persistence boundaries, live model-view/event foundations, command palette, diagnostics, and performance budgets |
| [**M2**](https://github.com/Fuzzy-Technologies/1337/milestone/3) | Execution, Discovery & Security Object Model MVP | Executor runtime, native discovery, minimal live Security Object Model, tool adapters, modular providers, Quick Scan, and initial workflow lenses |
| [**M3**](https://github.com/Fuzzy-Technologies/1337/milestone/4) | Evidence, Intelligence & Mapping | Evidence, findings, vulnerability/attack intelligence, standards/classifier mappings, and Fuzzy reports |
| [**M4**](https://github.com/Fuzzy-Technologies/1337/milestone/5) | Advanced Discovery & Attack Paths | Advanced Web/API/browser/runtime discovery, user journeys, reachability, attack paths, and the reproducible attack-path showcase |
| [**M5**](https://github.com/Fuzzy-Technologies/1337/milestone/6) | Analytical UX | Large-scale tables, attack-graph visualization, business context, explainable prioritization, and advanced mapping UX |
| [**M6**](https://github.com/Fuzzy-Technologies/1337/milestone/7) | Automation, Integrations & AI | Domain API/SDK, CI/CD, vendor integrations, remote executors, MCP, and AI-agent access |
| [**M7**](https://github.com/Fuzzy-Technologies/1337/milestone/8) | Authorized Validation | Fuzzy Striker and mature offensive/Purple validation workflows |
| [**M8**](https://github.com/Fuzzy-Technologies/1337/milestone/9) | 1337 Trace | DFIR ingestion, evidence integrity/custody, incident timeline, and observed attack graph |
| [**M9**](https://github.com/Fuzzy-Technologies/1337/milestone/10) | Cloud & Enterprise Contracts | Verified assets, cloud-safe contracts, and stable enterprise extension interfaces |

Roadmap scope and ordering may evolve as the Community workstation matures. Detailed
planning is tracked through the linked GitHub milestones and issues.

The M4 milestone includes the reproducible attack-path showcase tracked in
[Feature #115](https://github.com/Fuzzy-Technologies/1337/issues/115). It is a
repository-owned lab driven by real discovery, evidence, Security Objects,
reachability, validation, and graph updates rather than a prerecorded animation.

## Project vision and architecture

- [Vision](docs/VISION.md) — concise product and architecture direction;
- [ADR 0010: live Security Object Model, modular tooling, and operator lenses](docs/adr/0010-live-security-object-model-modular-tooling-and-lenses.md) — workbench-centered clarification;
- [ADR 0008: model-agnostic security execution, state, and evidence platform](docs/adr/0008-ai-native-cyber-execution-platform.md) — durable Core boundary;
- [ADR 0009: operator profiles and orthogonal execution dimensions](docs/adr/0009-operator-profiles-and-orthogonal-execution-dimensions.md) — shared-state workflow model;
- [1337 for AI agents in cybersecurity](docs/AI_AGENTS.md) — AI/MCP integration direction;
- [Machine-readable project summary](llms.txt) — compact discovery metadata;
- [Compatibility](docs/COMPATIBILITY.md) — public stability and extension-boundary contract;
- [Terminology](docs/TERMINOLOGY.md) — canonical public security terminology.

## Development

The Python bootstrap provides installable `1337` and `1337-dev` commands.
Use Python 3.11+ and run from the repository root:

```bash
python -m pip install uv==0.11.33
uv run --locked 1337-dev setup
uv run --locked 1337 --version
uv run --locked 1337-dev unit
uv run --locked 1337-dev check
```

`1337-dev setup` synchronizes the development environment with the committed
lockfile (`uv sync --locked --extra dev`). It is safe to repeat and refuses stale
dependency metadata.

`1337-dev unit` is the default fast feedback path. It runs only `tests/unit`,
blocks real network connections, and enforces strictly greater than 80% combined
branch/statement coverage for every production module. The full `check` gate also
checks compilation, lint, types, all test layers, and packaging. The bootstrap CLI
currently provides help/version only.

See [Python development](docs/DEVELOPMENT.md) and
[Container development](docs/CONTAINERS.md).

Project development and compatibility references:

- [DEVELOPMENT_PROTOCOL.md](DEVELOPMENT_PROTOCOL.md) — development workflow, Python house style, testing, Git, and documentation rules;
- [docs/RELEASE_WORKFLOW.md](docs/RELEASE_WORKFLOW.md) — protected branches, merge policy, deterministic releases, tags, hotfixes, and documentation/site publication;
- [contracts/](contracts) — versioned machine-readable public contracts and examples;
- [CHANGELOG.md](CHANGELOG.md) — strict chronological project history.

The stable public branch is `master`. Active integration development occurs on
`develop`; feature work is performed on short-lived branches and reviewed before
merge.

## License

The Community repository is distributed under the Apache License 2.0.

Copyright © Fuzzy Technologies.
