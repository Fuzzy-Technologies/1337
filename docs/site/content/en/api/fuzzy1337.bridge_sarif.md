# fuzzy1337.bridge_sarif

Internal bounded SARIF 2.1.0 source decoding and original/receipt verification.
This module introduces no public Python SDK or canonical Finding/target schema.
The Experimental operator interface is described in the
[saved SARIF guide](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/BRIDGE_SARIF_IMPORT.md)
and [ADR 0157](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/adr/0157-owned-saved-sarif-import.md).

`ParseSarif` consumes complete UTF-8 JSON under fixed byte/tree/text/array and
independent projection budgets. Literal tool/rule/classification/position facts
and unknowns retain source order, including duplicates. Same-document indices
never become filesystem/network lookups. Effective SARIF defaults, Markdown,
message templates, code flows, fixes and external-property files are not resolved.

`BoundedSarifStore` preflights exact manifest/profile and role/media/byte domains
before owning body reads. `LoadSavedSarif` verifies workspace/scope/provenance,
original/receipt/SHA joins and complete original reparse before returning any
projection. It performs no acquisition, clock call, owner write, authentication
or risk interpretation. Receipt content binds source bytes and original read
descriptions without granting new read or execution authority.

::: fuzzy1337.bridge_sarif
