# ADR 0133: Local selected CWE ZIP custody

Status: Accepted for this bounded implementation.

## Context

ADR 0131 supplies a pure selected CWE decoder. A DTO alone cannot prove retention
of original source bytes. The local custody slice for #47 must preserve exact ZIP
bytes, source declarations, notices, immutable manifests and successful receipts.
The existing snapshot and EPSS/CVE families remain unchanged.

## Decision

Add an Experimental SDK-only `intelligence_cwe_acquisition` family with exact
`CweLocalSource`, `CweLocalRequest`, `AcquireLocalCweSelection` and
`LoadAcquiredCweSelection` interfaces. Source declarations admit only catalog 5.0
or 4.21, a mandatory SHA-256 pin and one closed captured notice profile. Official
source URLs and publisher names are declarations, never authenticated provenance.
Synthetic test bytes remain expressly owned fixtures.

Retain the complete captured terms page text (4,329 UTF-8 bytes), including all
license/disclaimer and copyright/trademark text, plus extraction and raw HTML
hash provenance in `cwe-terms-complete-page-20261103-v1`. Its original raw capture
has 17,670 bytes and SHA-256
`c572b605b5753cd67b84d12fc64e9ccbfcde0188cf1332118be04c9996a92c45`.
Full text SHA-256 is
`d1595d0a2bc408587d9d3ba24974e381547400772693635d4b340f225e068c2f`.
This finite complete-text selection is the product notice bundle. Capture date,
page update date and catalog date do not establish notice applicability, legal
rights or publisher authentication; all three assessments remain not assessed.
Later notices require new versioned bundles without changing historical replay.

Use existing owning workspace/evidence stores and separate roles:
`cwe-local-zip-source`, `cwe-local-zip-partial`,
`cwe-local-selected-envelope`, `cwe-local-selected-acquisition`.
The `cwe-local-selection:` envelope identity includes the complete source/notice,
original manifest, effective request limit and unchanged nested `cwe-selection:`.
The original ZIP cap is at most 4 MiB, selected envelope 2 MiB, receipt 64 KiB.
Notice bundle and source declaration are fixed below 16 KiB and 32 KiB respectively.
The pure decoder keeps all its existing 32 MiB expanded/1 MiB selected limits.

Record local-copy instants separately from the catalog civil day. Retain bounded
partial original prefixes on size refusal without producing assertions. Digest,
complete ZIP/XML parse and storage failures retain their actual acknowledged
artifacts and never imply rollback. Each publication enters UNKNOWN before Put,
then CONFIRMED only after its immutable handle returns. Receipt body records
pre-receipt facts; receipt acknowledgement belongs only to the returned outcome.
Publication budget failure becomes STORAGE_FAILED without a usable envelope.

Reopen explicit selection and receipt roots only. Owning Read overrides preflight
exact role/media/size before Get's implicit body verification. Strict bounded JSON
reconstructs the exact source, selection DTO and receipt, then owning original
manifest identity and full original ZIP reparse must agree. This is read-only,
portable after relocation and independent of an original caller file.

## Consequences

No CLI, receiver, remote acquisition, model write, apply, automatic source discovery,
full XSD validation, legal-rights conclusion or publisher authentication is added.
Zero Weakness matches, unsupported source kinds and absent IDs remain separate
source facts. This slice advances #47/#43 and does not complete either task.
