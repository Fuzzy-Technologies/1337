# fuzzy1337.intelligence_commands

This Internal module implements the explicit local `intel import`, `intel inspect`
and `intel apply` product commands. Import uses caller-selected local bytes and
source declarations for the four supported feed formats. Inspection verifies the
owning original raw, snapshot and terminal-receipt records before reparsing.
Application selects one existing Finding, exact identifiers and an expected model
revision, preserving operator triage through the existing CAS persistence owner.

Schema-v1 JSON outcomes distinguish configuration, acquisition, integrity and
save failures, including uncertain save acknowledgement. Summaries contain
references and observed receiver facts without source bodies. The module grants
no remote acquisition, publisher authentication, automatic enrichment or execution
authority. ADR 0069 and `docs/INTELLIGENCE_CLI.md` define the CLI contract.

The additive `intel epss` namespace delegates to its own bounded selected-gzip
consumer; it does not change the legacy parser, snapshots or application path.

::: fuzzy1337.intelligence_commands
