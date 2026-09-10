# AGENTS.md

## Purpose

This file is the mandatory entry point for AI agents, Codex sessions, IDE assistants, automation, and other software agents working in this repository.

The repository contains the public Community foundation of **1337 Security Workbench by Fuzzy Technologies**.

Before changing code or documentation, read and follow [DEVELOPMENT_PROTOCOL.md](DEVELOPMENT_PROTOCOL.md). It is the canonical development and style contract.

## Project scope

- Work only inside the current repository unless the owner explicitly authorizes another repository or external resource for the current task.
- Do not inspect, enumerate, read, write, or modify parent directories, sibling repositories, unrelated projects, user home data, mounted shares, or other local storage.
- Do not follow symlinks, junctions, reparse points, mounts, or other links outside the repository boundary.
- Do not infer permission to access another repository merely because credentials or tooling make it technically reachable.
- Read only the files needed for the task. Prefer indexes, targeted search, and narrow excerpts over unrestricted repository-wide context dumps.

## Security-testing boundary

1337 is security software. Development and testing must remain controlled.

By default, agents may execute security tests only against:

- repository-defined synthetic targets;
- localhost services started for the current test;
- isolated containers created by the project;
- another target explicitly identified by the owner as owned/authorized for the current task.

Without explicit owner authorization, agents must not actively scan, probe, fuzz, exploit, brute-force, enumerate, or otherwise test Internet hosts, third-party services, arbitrary private-network hosts, or discovered endpoints.

Do not weaken scope, impact-level, authorization, or safety controls merely to make a test pass.

## Language

- Source code, comments, identifiers, commit messages, documentation, prompts, schemas, API names, CLI commands, and repository metadata are written in English.
- Localization resources may contain their target language.
- Canonical commands and machine interfaces remain English even when localized aliases are later supported.
- User-facing interactive handoffs may follow the language requested by the user.

## Mandatory development rules

- Follow `DEVELOPMENT_PROTOCOL.md`.
- Architecture-impacting changes require an explicit design/ADR decision before or together with implementation.
- Prefer deterministic local tools when they can answer or validate the task; do not use an LLM where a deterministic check is sufficient.
- Keep changes small, reviewable, and scoped to one objective.
- Do not mix behavior changes with unrelated style cleanup or refactoring.
- Do not silently delete behavior, guards, tests, documentation history, or compatibility contracts.
- Do not add `TODO`, `FIXME`, `TEMP`, or `HACK` markers to tracked source.
- Never claim a result is complete without the required tests and evidence.

## Git workflow

- `master` is the latest stable/released branch.
- `develop` is the integration branch.
- Normal work uses `feature/*`, `fix/*`, `release/*`, or `hotfix/*` branches as defined in `DEVELOPMENT_PROTOCOL.md`.
- Do not push directly to `master`.
- Do not bypass required review or CI.
- Automated agents may prepare commits and pull requests when authorized, but must not merge their own PRs unless the owner explicitly asks for that specific merge.
- Do not force-push protected branches, rewrite published history, use destructive resets, or amend unrelated commits.
- Stage/write only the intended files; avoid broad repository mutations.

## Secrets and external services

- Never read, print, copy, commit, summarize, or transmit secret values.
- Secrets belong in environment variables or approved secret storage, never in tracked files.
- `.env`, credentials, private keys, access tokens, cookies, session material, and local machine configuration are not model context.
- Do not upload repository contents to unrelated pastebins, public issue trackers, remote notebooks, shared documents, or arbitrary external services.
- Network use for normal dependency/documentation research does not authorize active security testing of remote targets.

## Protected policy files

`AGENTS.md` and `DEVELOPMENT_PROTOCOL.md` are owner-controlled policy files.

Agents may read and cite them. They must not modify, replace, delete, or weaken them unless the project owner explicitly requests a change to the relevant policy file.

`CHANGELOG.md` is append-only historical documentation under the rules in `DEVELOPMENT_PROTOCOL.md`.

## Completion

Before reporting completion:

1. verify the exact diff;
2. run the applicable targeted tests;
3. run the canonical full gate when it exists;
4. verify no secret or unrelated file entered the change;
5. update documentation/changelog when required;
6. report actual evidence, failures, and remaining uncertainty.

If a required gate cannot be run, say so explicitly. Do not convert an unexecuted check into PASS.
