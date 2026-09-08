# 1337 Security Workbench

**1337 Security Workbench by Fuzzy Technologies** is an open security workstation
for practitioners and security teams.

> **Technologies · Knowledge · Science**

## Why 1337

**For hackers and security engineers**

> The modern open security workstation: one command to build your hacking lab.

**For security leaders**

> Attack-path intelligence: understand what attackers can actually reach and what to fix first.

## Status

`1337` is in early pre-alpha bootstrap. The public repository is the Apache-2.0
Community foundation of the platform; the currently implemented scope is the M0
engineering baseline, not a finished scanner.

1337 is built around a few durable principles:

- one fast entry point: `1337`;
- local-first, container-first operation;
- modular adapters for specialist tools rather than dependence on one distribution;
- structured evidence before conclusions;
- attack paths and reachability, not severity scores alone;
- a useful Community edition, not a crippled demo.

## Product direction

1337 Community is the only current public edition. It is an Apache-2.0,
early pre-alpha foundation; the roadmap describes intent, not a claim that every
capability already exists.

| Track                    | Engineering intention                                                                                                                                     | Current boundary                                                                                                    |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **Community**            | An open security workstation connecting specialist tools, their evidence, attack paths, and remediation priorities.                                       | The public foundation. M0 provides the engineering baseline; capability follows the published roadmap.              |
| **Enterprise direction** | A future commercial direction for governed security decisions through correlation, business context, prioritization, automation, audit, and integrations. | Not released or available. This is a design direction, not a feature list, delivery date, or commercial commitment. |

1337 is not trying to replace every specialist scanner. It is the layer that
connects tools, evidence, and risk decisions into a usable security picture.

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
- [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) — public compatibility, stability, versioning, and extension-boundary contract;
- [contracts/](contracts/) — versioned machine-readable public contracts and examples;
- [CHANGELOG.md](CHANGELOG.md) — strict chronological project history.

The stable branch is `master`. Active integration development occurs on `develop`; feature work is performed on short-lived branches and reviewed before merge.

## License

The Community repository is distributed under the Apache License 2.0.

Copyright © Fuzzy Technologies.
