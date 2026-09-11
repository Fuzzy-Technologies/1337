# 1337 Security Workbench

## Open security workstation · Model-agnostic runtime for AI security agents

**1337 Security Workbench (1337-SW) by Fuzzy Technologies** is an open security
workspace for penetration testers, security engineers, researchers, and security
teams. It turns output from specialist tools into attributable evidence and durable
security state for reachability and attack-path analysis.

> **Bring your model. 1337 brings the cyber workspace**
>
> **Models reason. 1337 keeps state, governs execution, and preserves evidence**

> **Technologies · Knowledge · Science**

## Why 1337

Security practitioners already have excellent specialist tools. The hard part is
turning their disconnected output into a durable picture of **what exists, what is
reachable, what is proven, what changed, and what should be fixed first**.

1337 is not another all-in-one scanner and does not try to replace Nmap, Nuclei,
browsers, commercial scanners, or AI models. It is designed to provide the state
and evidence layer around them:

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

**For penetration testers and security engineers**

> Keep tool output, evidence, scope, and investigation context together so
> meaningful attack paths do not have to be reconstructed from terminal history
> and notes.

**For AI-agent builders**

> Connect the AI model your organization trusts to the same structured security
> state and typed capabilities. Scope, execution policy, and evidence stay outside
> model discretion, so the model can change without redesigning the workflow.

**For security teams**

> Maintain context across findings, identities, controls, and assets so teams can
> focus on reachable risk, attack paths, and the remediation that reduces the most
> exposure.

The core is intentionally agnostic to the AI model and provider, and local-first.
The same workspace is designed to remain useful when the human operator, AI model,
tool, or execution environment changes.

Canonical concepts include **Security Object Model**, **Capability Fabric**,
**Executor Runtime**, **evidence-first security**, **reachability and attack-path
analysis**, and **bring-your-own-model (BYOM)** integration.

## Status

`1337` is in **early pre-alpha**. The public repository is the Apache-2.0 Community
foundation of the platform. The implemented code currently covers the engineering
baseline and early M1 foundations; the interactive shell, production scanner
adapters, findings/reachability workflows, attack graph UX, AI-agent interfaces,
and enterprise capabilities remain roadmap work unless explicitly documented
otherwise.

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

| Track                    | Engineering intention                                                                                                                                    | Current boundary                                             |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| **Community**            | Open security workstation connecting specialist tools, structured evidence, security objects, reachability, attack paths, and future AI-agent interfaces | Public pre-alpha foundation; capability follows the roadmap  |
| **Enterprise direction** | Governed continuous security with approved AI models, private execution, correlation, business context, prioritization, audit, and integrations          | Not released or available; design direction only             |

The strategic boundary is simple: **models provide replaceable reasoning; 1337
provides durable security state, governed execution, evidence, and the security
graph**.

## DFIR and investigations

The M8 **1337 Trace / DFIR** direction extends the same evidence-first security
state into incident response, digital forensics, internal investigations, CERT/CSIRT
work, forensic consulting, and cybercrime investigations.

The planned evidence model is intended to preserve more than a finding or alert:

```text
Case / Investigation
        ↓
Evidence / Artifact
        ↓
Acquisition + Integrity Hash
        ↓
Custody / Provenance
        ↓
Timeline / Correlation
        ↓
Observed Attack Path
        ↓
Investigation Report / Evidence Bundle
```

Source, acquisition time, collector/examiner, hashes, original-versus-derived
artifacts, parser/tool provenance, custody events, normalized timestamps, and the
boundary between evidence and interpretation should remain auditable.

This makes 1337 relevant not only to SOC teams, but also to IR teams, forensic
consultants, CERT/CSIRT, internal investigations, and — where organizations choose
to adopt it — law-enforcement investigations and forensic workflows supporting
judicial proceedings.

Legal and evidentiary rules vary by jurisdiction. 1337 does not claim that data is
automatically admissible in court; the goal is to preserve factual provenance,
integrity, chain of custody, and reproducibility so local forensic and legal
procedures can be applied.

See [M8 evidence ingestion #83](https://github.com/Fuzzy-Technologies/1337/issues/83)
and [incident timeline / observed attack graph #84](https://github.com/Fuzzy-Technologies/1337/issues/84).

## Responsible use

1337 is intended for defensive security engineering, authorized security assessment,
training, research, CTF/lab environments, and systems you own or are explicitly
authorized to test.

Do not use the project to scan, probe, exploit, or disrupt third-party systems
without authorization.

See [SECURITY.md](SECURITY.md).

## Roadmap

| Phase                                                             | Focus                          | Target outcome                                                                                                                                                                                 |
| ----------------------------------------------------------------- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**M0**](https://github.com/Fuzzy-Technologies/1337/milestone/1)  | Foundation                     | Repository baseline, engineering controls, CI, containers, synthetic test lab, durable architecture contracts                                                                                  |
| [**M1**](https://github.com/Fuzzy-Technologies/1337/milestone/2)  | Community Core & Shell         | `1337` shell, workspace, scope, diagnostics, localization, machine-readable command/capability foundations                                                                                     |
| [**M2**](https://github.com/Fuzzy-Technologies/1337/milestone/3)  | Scanner & Execution MVP        | Executor runtime, tool adapters, structured capability execution, impact profiles, Quick Scan                                                                                                  |
| [**M3**](https://github.com/Fuzzy-Technologies/1337/milestone/4)  | Evidence & Intelligence        | Evidence, findings, CVE/CWE/KEV/EPSS enrichment, graph-lite foundations, Fuzzy reports                                                                                                         |
| [**M4**](https://github.com/Fuzzy-Technologies/1337/milestone/5)  | 1337 Scope                     | Attack surface, reachability, attack paths, native Web Scanner NG, and the full reproducible attack-path showcase ([#115](https://github.com/Fuzzy-Technologies/1337/issues/115))              |
| [**M5**](https://github.com/Fuzzy-Technologies/1337/milestone/6)  | Security Intelligence UX       | Tables, attack graphs, business events, explainable risk, standards mapping                                                                                                                    |
| [**M6**](https://github.com/Fuzzy-Technologies/1337/milestone/7)  | Automation & Agents            | CI/CD, integrations, distributed execution, Domain API, SDK, MCP, advanced agent workflows                                                                                                     |
| [**M7**](https://github.com/Fuzzy-Technologies/1337/milestone/8)  | Fuzzy Striker                  | Red/Blue/Purple workflows and authorized validation                                                                                                                                            |
| [**M8**](https://github.com/Fuzzy-Technologies/1337/milestone/9)  | 1337 Trace                     | DFIR, evidence integrity and chain of custody, incident timeline, observed attack graph                                                                                                        |
| [**M9**](https://github.com/Fuzzy-Technologies/1337/milestone/10) | Cloud & Enterprise Contracts   | Verified assets, cloud-safe contracts and stable enterprise extension interfaces                                                                                                               |

Roadmap scope and ordering may evolve as the Community platform matures. Detailed
planning is tracked through the linked GitHub milestones and issues.

The M4 milestone includes the **full reproducible attack-path showcase** tracked in
[Feature #115](https://github.com/Fuzzy-Technologies/1337/issues/115): one
repository-owned Docker Compose lab, three attack-path scenarios, and the same
evidence-backed security state underneath them. The showcase is intended to be
independently runnable and verifiable rather than prerecorded.

## Project vision and architecture

- [Vision](docs/VISION.md) — the human-facing product thesis and long-term direction;
- [1337 for AI security agents](docs/AI_AGENTS.md) — AI-model-agnostic agent/runtime concepts and discovery vocabulary;
- [ADR 0008: AI-native security execution, state, and evidence platform](docs/adr/0008-ai-native-cyber-execution-platform.md) — the architectural boundary;
- [Machine-readable project summary](llms.txt) — compact discovery metadata for automated readers;
- [Compatibility](docs/COMPATIBILITY.md) — public stability and extension-boundary contract;
- [Terminology](docs/TERMINOLOGY.md) — canonical public security terminology for English and Russian copy.

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
provides help/version; the interactive shell and production scanner adapters remain
planned work.

See [Python development](docs/DEVELOPMENT.md) for individual commands, test layers,
package validation, and dependency handling.

For Docker Engine or Docker Desktop development, see
[Container development](docs/CONTAINERS.md). The container workflow runs the same
locked quality gate and is restricted to this source tree and repository-defined
synthetic targets.

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
