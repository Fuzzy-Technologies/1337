# Selected CWE ZIP/XML decoder

Experimental pure profile with exactly four exports: `CweSelectedRecord`,
`CweUnsupportedEntry`, `CweSelection` and `ParseCweSelection`. Other helpers are
Internal. Exact original ZIP bytes and an exact, already lexically sorted unique
tuple of 1..64 canonical CWE IDs select one closed release/namespace/member mode:
5.0 / namespace 8 / `cwec_v5.0.xml`, or 4.21 / namespace 7 / `cwec_v4.21.xml`.

Only direct Weakness entries become retained records. Selected Category,
Grouping and View identities retain their exact unsupported source kind;
unmatched IDs are absent from recognized kinds in the supplied bytes. The three
sorted disjoint partitions cover the request exactly, including zero Weakness
matches. Mode 5.0 recognizes both Category and Grouping; mode 4.21 refuses a
Groupings collection. All consumed source-entry fields and uniqueness are checked,
including unselected entries. Ignored nested content still consumes budgets.

The frozen DTO retains exact modes, root Name/Version/Date, source names/statuses,
raw ZIP/member facts, actual expanded hashes/CRC, partitions and observed resource
counters. Civil `catalog_date` keeps day precision without a publisher instant
or `effective_at`. Detached schema/profile-one dictionaries use
`profile="cwe-zipped-xml-selected"`; the separate `cwe-selection:` reference hashes
their complete bounded canonical content. Direct construction validates
structure, not hashes against unavailable original bytes.

No result is returned before complete ZIP/DEFLATE EOF/size/CRC, strict UTF-8 XML
completion and all profile bounds succeed. Ceilings include four MiB ZIP,
32 MiB expanded XML, one MiB selected canonical JSON, 64 requested IDs and
256 UTF-8 bytes for both raw lexical and namespace-expanded QNames. The Internal
ZIP and XML owners enforce the remaining finite framing/event/token budgets.
Shared legacy parser/snapshot limits and references remain unchanged.

This is consumed-field parsing, without full XSD validation, publisher
authentication, legal entitlement, source acquisition/custody/replay, CLI,
applicability, scoring or model integration. CWE data notices remain distinct
from schema and implementation licenses; a later source profile must preserve
applicable MITRE notices and attribution. ADR 0131 defines this foundation.

::: fuzzy1337.intelligence_cwe_selection
