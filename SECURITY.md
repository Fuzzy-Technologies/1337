# Security Policy

## Responsible use

1337 Security Workbench is intended for defensive security engineering, authorized assessment, training, research, CTF/lab environments, and systems you own or are explicitly authorized to test.

Do not use 1337 to scan, probe, fuzz, exploit, brute-force, disrupt, or access third-party systems without authorization.

## Reporting a vulnerability

Please do **not** open a public GitHub issue containing exploit details, credentials, sensitive logs, or a proof of concept for an unpatched vulnerability in 1337.

Preferred reporting path:

1. use GitHub's private vulnerability reporting / Security Advisory flow for this repository when available;
2. otherwise contact the Fuzzy Technologies maintainers through an official private organization channel and request a private security-reporting path.

Include only what is necessary to reproduce and understand the issue:

- affected version/commit;
- affected component;
- impact;
- reproduction steps;
- minimal proof of concept;
- suggested mitigation, if known.

Do not include real third-party target data or secrets.

## Supported versions

1337 is currently pre-1.0. During pre-alpha development, security fixes target the latest active development line and the latest stable tagged release when one exists.

A formal support matrix will be published before stable commercial releases.

## Disclosure

Please allow maintainers reasonable time to reproduce, fix, test, and publish a security update before public disclosure.

We will aim to:

- acknowledge valid private reports;
- preserve reporter attribution when requested and legally possible;
- avoid requesting unnecessary sensitive data;
- publish remediation information with the fixed release.

## Project security boundaries

Contributions must preserve:

- explicit scope and authorization controls;
- safe-by-default scan profiles;
- no hidden intrusive behavior;
- fail-closed validation at security boundaries;
- secrets outside source control;
- exact evidence/provenance for scanner execution;
- separation of raw evidence from normalized findings.

See [AGENTS.md](AGENTS.md) and [DEVELOPMENT_PROTOCOL.md](DEVELOPMENT_PROTOCOL.md) for mandatory development rules.
