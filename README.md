# 1337 Security Workbench

**1337 Security Workbench by Fuzzy Technologies** is a fast, extensible security workbench for humans, tools, automation, and AI agents.

> **Technology · Knowledge · Science**

## Status

`1337` is in early pre-alpha bootstrap. The public repository is the Community/open-source foundation of the platform.

The project is being designed around a few durable principles:

- one fast entry point: `1337`;
- native CLI feel with structured evidence;
- useful Community edition rather than a crippled demo;
- local-first and container-first operation;
- modular scanner/tool adapters instead of a hard dependency on one distribution;
- deterministic evidence and findings before AI interpretation;
- reachability and attack paths, not severity scores alone;
- vendor-neutral APIs for humans, automation, and AI agents;
- English as the canonical language for code, commands, APIs, and documentation;
- localization as a first-class extension boundary.

## Responsible use

1337 is intended for defensive security engineering, authorized security assessment, training, research, CTF/lab environments, and systems you own or are explicitly authorized to test.

Do not use the project to scan, probe, exploit, or disrupt third-party systems without authorization.

See [SECURITY.md](SECURITY.md).

## Roadmap

| Phase  | Focus                        | Target outcome                                                                           |
| ------ | ---------------------------- | ---------------------------------------------------------------------------------------- |
| **M0** | Foundation                   | Repository baseline, engineering controls, CI, containers, synthetic test lab            |
| **M1** | Community Core & Shell       | `1337` shell, workspace, scope, diagnostics, localization and functional-test foundation |
| **M2** | Scanner MVP                  | Executor runtime, tool adapters, impact profiles, Quick Scan, useful Community scanner   |
| **M3** | Evidence & Intelligence      | Evidence, findings, CVE/CWE/KEV/EPSS enrichment, Fuzzy reports                           |
| **M4** | 1337 Scope                   | Attack surface, reachability, attack paths, native Web Scanner NG                        |
| **M5** | Security Intelligence UX     | Tables, attack graphs, business events, explainable risk, standards mapping              |
| **M6** | Automation & Agents          | CI/CD, integrations, distributed execution, Domain API, SDK, MCP                         |
| **M7** | Fuzzy Striker                | Red/Blue/Purple workflows and authorized validation                                      |
| **M8** | 1337 Trace                   | DFIR, incident timeline, observed attack graph                                           |
| **M9** | Cloud & Enterprise Contracts | Verified assets, cloud-safe contracts and stable enterprise extension interfaces         |

Roadmap scope and ordering may evolve as the Community platform matures. Detailed planning is tracked through GitHub milestones and issues.

## Development

Repository-level rules for humans and AI agents are defined in:

- [AGENTS.md](AGENTS.md) — mandatory agent entry point and project-scope policy;
- [DEVELOPMENT_PROTOCOL.md](DEVELOPMENT_PROTOCOL.md) — development workflow, Python house style, testing, Git, and documentation rules;
- [CHANGELOG.md](CHANGELOG.md) — strict chronological project history.

The stable branch is `master`. Active integration development occurs on `develop`; feature work is performed on short-lived branches and reviewed before merge.

## License

The Community repository is distributed under the Apache License 2.0.

Copyright © Fuzzy Technologies.
