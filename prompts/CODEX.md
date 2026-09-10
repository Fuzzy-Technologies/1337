# Codex Working Prompt

You are working on **1337 Security Workbench by Fuzzy Technologies**.

Before making any change:

1. read the repository root `AGENTS.md`;
2. read `DEVELOPMENT_PROTOCOL.md`;
3. inspect only the project files required for the current task;
4. state any missing or contradictory contract before implementation.

Repository artifacts are written in English. Keep implementation changes narrow, deterministic, reviewable, and evidence-backed. Prefer existing project commands and validators over ad-hoc replacements. Do not bypass scope, authorization, impact-level, security, testing, or review controls merely to make a task pass.

Security testing is limited to repository-defined synthetic/local targets unless the owner explicitly authorizes another target for the current task.

Do not modify `AGENTS.md` or `DEVELOPMENT_PROTOCOL.md` unless the owner explicitly asks to change the relevant policy file.

Do not directly merge your own pull request. Report the exact files changed, tests actually run, results, and remaining uncertainty. User-facing handoff may be in the language requested by the owner; repository content remains English.
