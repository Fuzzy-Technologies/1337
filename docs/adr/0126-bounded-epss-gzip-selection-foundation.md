# ADR 0126: Bounded EPSS gzip selected-record foundation

## Status

Accepted Experimental pure-parser foundation. Acquisition, receipt publication,
stored-profile reopening and installed CLI support are not implemented by this
slice. This does not complete #43 or #47 or establish official-source acceptance.

## Context

FIRST daily EPSS archives provide the original model revision and full score
clock. API version or a date-only response cannot substitute for those facts.
The existing schema-one CSV parser normalizes the complete input; a real daily
corpus can exceed its normalized snapshot budget even when source bytes fit.
Raising a shared limit would not define explicit selection or source custody.

## Decision

Add a separate pure `ParseEpssSelection` profile for original gzip bytes and an
explicit unique selection of canonical CVE identifiers. Its detached result uses
`schema_version: 2`, `profile_version: 1` and an `epss-selection:` reference
family. It is not accepted by the legacy snapshot loader. Identity binds exact
raw/decoded hashes and lengths, original metadata, explicit model/day, normalized
source clock, requested/matched/unmatched IDs, selected decimal source tokens,
validated row count and profile budgets.

| Resource             | Fixed profile ceiling |
| -------------------- | --------------------- |
| Original gzip bytes  | 4 MiB                 |
| Expanded UTF-8 bytes | 16 MiB                |
| Original CSV rows    | 500,000               |
| Requested CVE IDs    | 64                    |
| Original header      | 512 UTF-8 bytes       |
| Numeric token        | 32 characters         |
| Absolute exponent    | 32                    |

Expansion is bounded before materializing decoded content. The gzip decoder
checks actual EOF, CRC and size and refuses trailing bytes or a second member,
including an empty member. ISIZE is never trusted as an allocation budget. The
bounded decoded corpus is materialized for strict UTF-8/CSV validation; this is
not an unbounded streaming-corpus implementation. Duplicate detection retains at
most 500,000 bounded canonical CVE identifiers. Only at most 64 selected rows
become normalized assertion DTOs.

Validate every row, including unselected identifiers and numeric values. Require
exact original columns and original model/full timestamp metadata; caller model
and dated archive day must match. Source day is the calendar day written by the
publisher before explicit-zone normalization. No absent time or model value is
invented. Probability and percentile retain their original decimal tokens and
are not interpreted as target compromise probability, membership or composite
risk. Absent selected IDs remain unmatched with no fabricated zero-score row.

Numeric spelling permits ordinary decimals and scientific decimal tokens such as
the publisher's `6e-05` percentile. Validate lexical length and bounded exponent
before exact `Decimal` range comparison. Negative mantissas, NaN, infinity,
out-of-range values and excessive exponents refuse; no binary-float underflow
can turn a positive token into zero. Legacy CSV grammar is unchanged.

Exported DTO constructors require immutable tuples, a canonical requested and
matched/unmatched partition, valid scalar assertions, exact metadata clocks,
lowercase digests and typed bounded sizes/counts. Structural validation does not
prove claimed digests against source bytes that are absent from a DTO; only the
parser computes those hashes from actual bytes. DTO construction is not source
authentication or acquisition evidence.

## Compatibility and remaining work

Legacy schema-one serialization, references, parsers, 16 MiB limit, CISA remote
admission, query rejection and Finding semantics remain unchanged. No transport
or generic URL validator is broadened. The result is pure parsing output rather
than an evidence receipt or publisher authentication. Original payload retention,
attribution and exact raw EvidenceReference binding must be supplied by a future
separately reviewed acquisition/replay family before product consumption.

Follow-up work must cover pinned official selection, source terms, complete SDK
GET/hash/decode/reopen evidence, receipt and selection tampering, storage/partial
outcomes, relocation, installed inspection and legacy replay. No official corpus
is redistributed as a fixture. Deterministic synthetic tests cover malformed
members, budgets, metadata, all-row validation and separate profile identity.
