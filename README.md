# 1337 Security Workbench

## The cybersecurity runtime for humans and AI agents

**1337 Security Workbench (1337-SW) by Fuzzy Technologies** is an open security
workstation for security engineers, penetration testers, researchers, and security
teams — and a model-neutral execution, state, and evidence layer for future AI
security agents.

> **Bring your model. 1337 brings the cyber workspace.**
> 
> **Models reason. 1337 remembers, governs, executes and proves.**

> **Technologies · Knowledge · Science**

## Why 1337

Security practitioners already have excellent specialist tools. The hard part is
turning their disconnected outputs into a durable picture of **what exists, what is
reachable, what is proven, what changed, and what should be fixed first**.

1337 is not another all-in-one scanner and does not try to replace Nmap, Nuclei,
browsers, commercial scanners, or frontier AI models. It is designed to connect
them through one security workspace:

```text
Human / AI Agent / CI/CD
          ↓
         1337
Security Objects + Capabilities
     Scope + Policy
          ↓
 Tools / Executors / Browsers
          ↓
        Evidence
          ↓
        Findings
          ↓
Reachability / Attack Paths
          ↓
 Security & Business Decisions
```

**For hackers and security engineers**

> One entry point to build a security workstation, connect specialist tools,
> preserve evidence and context, and understand real attack paths.

**For AI security builders**

> A model-neutral cyber agent runtime / security harness: structured security
> objects and typed capabilities between AI reasoning and raw security tooling.

**For security teams and CISOs**

> A future continuous-security layer for answering what changed, what is actually
> reachable, which critical paths matter, and which remediation should come first.

The architectural core is intentionally AI-neutral and local-first. The same
workspace is intended to remain useful when the human operator, AI model, tool,
or execution environment changes.

Canonical concepts include **Security Object Model**, **Capability Fabric**,
**Executor Runtime**, **evidence-first security**, **reachability and attack-path
reasoning**, and **bring-your-own-model (BYO-AI)** integration.

## Status

`1337` is in **early pre-alpha**. The public repository is the Apache-2.0 Community
foundation of the platform. The implemented code currently covers the engineering
baseline and early M1 foundations; the interactive shell, scanners, attack graph,
and AI-agent interfaces remain roadmap work unless explicitly documented otherwise.

1337 is built around a few durable principles:

- one fast entry point: `1337`;
- local-first, container-first operation;
- modular adapters for specialist tools rather than dependence on one distribution;
- structured evidence before conclusions;
- attack paths and reachability, not severity scores alone;
- human and future AI clients over the same domain contracts;
- a useful Community edition, not a crippled demo.

## Product direction

1337 Community is the only current public edition. The roadmap describes design
intent, not a claim that every capability already exists.

| Track                    | Engineering intention                                                                                                                                        | Current boundary                                             |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------|
| **Community**            | Open security workstation connecting specialist tools, structured evidence, security objects, reachability, attack paths, and future AI-agent interfaces.    | Public pre-alpha foundation; capability follows the roadmap. |
| **Enterprise direction** | Governed continuous security using an organization's approved AI, private execution, correlation, business context, prioritization, audit, and integrations. | Not released or available; design direction only.            |

The strategic boundary is simple: **models provide replaceable reasoning; 1337
provides durable security state, governed execution, evidence, and the security
graph.**

## Responsible use

1337 is intended for defensive security engineering, authorized security assessment,
training, research, CTF/lab environments, and systems you own or are explicitly
authorized to test.

Do not use the project to scan, probe, exploit, or disrupt third-party systems
without authorization.

See [SECURITY.md](SECURITY.md).

## Roadmap

| Phase  | Focus                        | Target outcome                                                                                                |
|--------|------------------------------|---------------------------------------------------------------------------------------------------------------|
| **M0** | Foundation                   | Repository baseline, engineering controls, CI, containers, synthetic test lab, durable architecture contracts |
| **M1** | Community Core & Shell       | `1337` shell, workspace, scope, diagnostics, localization, machine-readable command/capability foundations    |
| **M2** | Scanner & Execution MVP      | Executor runtime, tool adapters, structured capability execution, impact profiles, Quick Scan                 |
| **M3** | Evidence & Intelligence      | Evidence, findings, CVE/CWE/KEV/EPSS enrichment, graph-lite foundations, Fuzzy reports                        |
| **M4** | 1337 Scope                   | Attack surface, reachability, attack paths, native Web Scanner NG                                             |
| **M5** | Security Intelligence UX     | Tables, attack graphs, business events, explainable risk, standards mapping                                   |
| **M6** | Automation & Agents          | CI/CD, integrations, distributed execution, Domain API, SDK, MCP, advanced agent workflows                    |
| **M7** | Fuzzy Striker                | Red/Blue/Purple workflows and authorized validation                                                           |
| **M8** | 1337 Trace                   | DFIR, incident timeline, observed attack graph                                                                |
| **M9** | Cloud & Enterprise Contracts | Verified assets, cloud-safe contracts and stable enterprise extension interfaces                              |

Roadmap scope and ordering may evolve as the Community platform matures. Detailed
planning is tracked through GitHub milestones and issues.

## Project vision and architecture

- [Vision](docs/VISION.md) — the human-facing product thesis and long-term direction;
- [1337 for AI security agents](docs/AI_AGENTS.md) — model-neutral agent/runtime concepts and discovery vocabulary;
- [ADR 0008: AI-native cyber execution, state, and evidence platform](docs/adr/0008-ai-native-cyber-execution-platform.md) — the architectural boundary;
- [Machine-readable project summary](llms.txt) — compact discovery metadata for automated readers;
- [Compatibility](docs/COMPATIBILITY.md) — public stability and extension-boundary contract.

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
dependency metadata. The initial one-time prerequisite is the pinned `uv`
installation shown above.

`1337-dev unit` is the default fast feedback path. It runs only `tests/unit`,
blocks real network connections, and enforces strictly greater than 80% combined
branch/statement coverage for every production module. The full `check` gate also
checks compilation, lint, types, all test layers, and packaging. The bootstrap CLI
provides help/version; the interactive shell and scanners remain planned work.
See [Python development](docs/DEVELOPMENT.md) for individual commands, test layers,
package validation, and dependency handling.

For Docker Engine or Docker Desktop development, see
[Container development](docs/CONTAINERS.md). The container workflow runs the same
locked quality gate and is restricted to this source tree and repository-defined
synthetic targets.

Project development and compatibility references:

- [DEVELOPMENT_PROTOCOL.md](DEVELOPMENT_PROTOCOL.md) — development workflow, Python house style, testing, Git, and documentation rules;
- [docs/RELEASE_WORKFLOW.md](docs/RELEASE_WORKFLOW.md) — protected branches, merge policy, deterministic releases, tags, and hotfix flow;
- [contracts/](contracts) — versioned machine-readable public contracts and examples;
- [CHANGELOG.md](CHANGELOG.md) — strict chronological project history.

The stable branch is `master`. Active integration development occurs on `develop`;
feature work is performed on short-lived branches and reviewed before merge.

## License

The Community repository is distributed under the Apache License 2.0.

Copyright © Fuzzy Technologies.
