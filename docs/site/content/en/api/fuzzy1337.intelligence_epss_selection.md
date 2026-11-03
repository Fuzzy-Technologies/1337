# fuzzy1337.intelligence_epss_selection

Experimental pure decoder for one bounded dated EPSS gzip corpus and one explicit
selection of at most 64 CVE identifiers. The separate schema-two/profile-one DTO
and `epss-selection:` reference preserve original source hashes, decode facts,
model revision, actual score clock, requested scope and unmatched identifiers.
The source metadata must match the caller's expected model and archive day.
Finite decimal assertions, including bounded scientific notation, remain original strings; unmatched identifiers do not receive
zero scores or an inferred risk level.

The profile checks all CSV rows and rejects duplicates, malformed fields,
non-finite/out-of-range decimals, incomplete gzip data, concatenated members and
trailing bytes. Its private ceilings are 4 MiB compressed, 16 MiB decoded and
500,000 rows; shared legacy limits remain unchanged.

This foundation performs no acquisition, persistence, receipt authentication,
Finding enrichment or CLI inspection. A successful decode does not establish
publisher authenticity or complete product source acceptance. Original source
licensing and attribution must be retained by the future acquisition profile;
this decoder grants no license to publisher data.

::: fuzzy1337.intelligence_epss_selection
