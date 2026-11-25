# fuzzy1337.intelligence_commands

This Internal module implements the explicit local `intel import`, `intel inspect`,
`intel preview` and `intel apply` product commands. Import uses caller-selected
local bytes and source declarations for the four supported feed formats. Inspection verifies the
owning original raw, snapshot and terminal-receipt records before reparsing.
Application selects one existing Finding, exact identifiers and an expected model
revision, preserving operator triage through the existing CAS persistence owner.
Preview verifies the same original local source and explicit interpretation
inputs, then returns the candidate observation without calling the save owner.
It keeps the saved and proposed revisions distinct and reserves no future write.

Schema-v1 JSON outcomes distinguish configuration, acquisition, integrity and
save failures, including uncertain save acknowledgement. Summaries contain
references and observed receiver facts without original source bodies; explicit
inspection and preview also expose verified assertions with source attribution.
Refused or interrupted previews omit the candidate payload. These legacy
commands grant no remote acquisition, publisher authentication, automatic
enrichment or execution authority. ADR 0069 and `docs/INTELLIGENCE_CLI.md` define
the CLI contract; ADR 0149 defines the read-only preview extension.

The additive `intel epss` namespace delegates to its own bounded selected-gzip
consumer; it does not change the legacy parser, snapshots or application path.
The explicit `intel cve https` route delegates to
`fuzzy1337.intelligence_cve_https_commands` for exact-commit, byte-pinned single
CVE acquisition and offline original-custody inspection. That separate family
does not broaden the legacy remote admission or Finding application contract.

::: fuzzy1337.intelligence_commands
