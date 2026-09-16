# Synthetic security lab

## Purpose

This directory is the repository-owned, isolated target boundary for 1337
development. It contains only local synthetic targets. It is never a list of
Internet hosts and it does not authorize assessment of a target outside this
repository-owned lab.

## Implemented targets

`web-safe` is the only implemented M0 target. It is a deliberately safe,
unprivileged HTTP service with two deterministic routes:

- `/health` returns a JSON health response;
- `/` returns a JSON description of the synthetic target.

The target has no published host port. Compose connects it only to the internal
`synthetic-lab` network, and the target has no external network route.

`web-micro` is the M1 first-party known-answer pack. It adds deterministic
routes for discovery, redirects, headers, cookies, forms, bounded query/body/
JSON/upload inputs, status behavior, and explicit simulation canaries. The
canaries never execute commands, access files, make outbound requests, or
persist uploads.

Start and wait for the target from the repository root:

```bash
docker compose --profile lab up --build --wait lab-web-safe
docker compose ps
docker compose down
```

Start the known-answer target separately:

```bash
docker compose --profile lab up --build --wait lab-web-micro
docker compose ps
docker compose down
```

## Reserved target families

The following repository directories reserve stable homes for future synthetic
target packs: `web-vulnerable`, `api-vulnerable`, `network-mini`,
`identity-mini`, and `attack-path-mini`. They intentionally supply no
unreviewed external target, black-box scanner scenario, or regression score.

Those capabilities belong to the separately tracked functional-test work. Until
then, do not add external demo targets, live credentials, or unreviewed target
images to this lab.
