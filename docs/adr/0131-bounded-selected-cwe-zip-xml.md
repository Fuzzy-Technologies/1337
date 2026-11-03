# ADR 0131: Bounded selected CWE ZIP/XML foundation

## Status

Accepted Experimental pure-decoder foundation under #43/#47. This is a separate
profile, without acquisition, storage, replay, CLI or model integration. Source
prerequisite research is verified; implementation and product acceptance remain
separate requirements. Existing source and normalized snapshot limits are unchanged.

## Context and source evidence

The legacy `cwe-xml-7` parser materializes one bounded source and its normalized
snapshot. The complete supplied CWE 5.0 and 4.21 XML members exceed that legacy
source ceiling. Namespace substitution or raising a shared limit would neither
define source selection nor preserve compatible legacy references.

The guarded research job in run 41656354959, head
`ab482cbfff482748655e4d061fae599cf4334676`, retrieved four literal pinned official
inputs once each. Its original artifact SHA-256 is
`d92cdc41bdf3b355839cc8aa9f827c688fcfdd685387637296f3e4da261f1fe3`.
Original files, exact XSD enumeration slices and executed JUnit were independently
checked. The earlier local zero-byte timeouts remain failures. This external
research is not a product SDK receiver, publisher authentication or source custody.

| Mode               | Exact namespace              | Sole fixed member | Actual expanded bytes | Actual CRC32 |
| ------------------ | ---------------------------- | ----------------- | --------------------- | ------------ |
| `5.0` / XSD `8.0`  | `http://cwe.mitre.org/cwe-8` | `cwec_v5.0.xml`   | 19,105,731            | `c01f0a7d`   |
| `4.21` / XSD `7.4` | `http://cwe.mitre.org/cwe-7` | `cwec_v4.21.xml`  | 18,571,978            | `0575b537`   |

Both sources contain 984 Weaknesses and 62 Views. Version 5.0 has 431 Groupings;
4.21 has 431 Categories. These observed counts do not become expected universal
publisher totals. The actual schema-8 XSD also permits Categories: preserve their
exact kind in supplied bytes rather than rewriting Categories into Groupings.
Both exact XSDs declare Deprecated/Draft/Incomplete/Obsolete/Stable/Usable status
values. These are source labels, never severity or applicability.

## Decision and compatibility

Add `fuzzy1337.intelligence_cwe_selection` with only four Experimental exports:
`CweSelectedRecord`, `CweUnsupportedEntry`, `CweSelection` and
`ParseCweSelection(payload, requested_ids, *, catalog_version)`.
Require exact bytes and an exact immutable, lexically sorted unique tuple of
1..64 canonical CWE identifiers. Only the two release/namespace/member tuples
above are admitted. No caller-selected path, URL, open stream, decoder policy,
callback, budget or source license/authentication declaration is accepted.

Only direct namespace-qualified Weakness entries become retained records.
Requested Category/Grouping/View identities form a separate known-unsupported
partition. Truly absent IDs form an unmatched partition. The three sorted,
disjoint immutable partitions must exactly cover the request; zero Weakness
matches is valid. Validate consumed ID/Name/Status on every recognized entry,
including unselected entries, and reject duplicate identities across kinds.
Recognize exact root collections; schema-7 Groupings remain unsupported grammar.
Ignored nested content still counts against every applicable resource bound.

Retain source names/statuses and strict root Name/Version/Date. XML attribute
normalization is distinct from exact original-byte identity; add no prose
rewriting. A real `YYYY-MM-DD` root date stays a civil day with
`date_precision="day"`, without midnight, timezone or inferred publisher instant.
No current clock, risk score, target matching or model projection is introduced.

Frozen DTO construction validates exact scalar/container/record types, hashes,
closed mode, counters, limits and complete partition relationships. It proves
structure, not claimed hashes against unavailable bytes. Detached `ToDict()` uses
its own schema/profile version one and `profile="cwe-zipped-xml-selected"`.
`Reference()` hashes the complete bounded canonical dictionary with the distinct
`cwe-selection:` prefix, including original/expanded/member facts, source metadata,
requested scope and counters. No serialized loader or legacy family is reused.

## Resource and parser ownership

Keep three concrete owners: the public module owns DTO/admission/composition;
Internal `intelligence_cwe_zip` owns strict framing and bounded complete decode;
Internal `intelligence_cwe_xml` owns the lexical gate and namespace-aware Expat
collector. Helpers import no public DTO and expose no supported SDK. The ZIP
owner consumes into an Internal sink and returns facts only after complete actual
EOF/size/CRC verification. The XML owner must finish a complete root, lexical
state and strict UTF-8 stream before the public module constructs any result.

| Resource                                                          | Profile-only maximum                    |
| ----------------------------------------------------------------- | --------------------------------------- |
| Original ZIP / expanded XML                                       | 4 MiB / 32 MiB                          |
| Selected canonical JSON / requested IDs                           | 1 MiB / 64                              |
| Central directory / local or central extras                       | 16 KiB / 256 bytes and 8 TLVs           |
| Compressed input and decoded chunks                               | 64 KiB each                             |
| Ordinary markup / comment or PI / live reference                  | 64 KiB / 64 KiB / 10 bytes              |
| Source entries / XML nodes / depth                                | 10,000 / 1,000,000 / 32                 |
| Parsed text / attribute bytes                                     | 24 MiB / 4 MiB                          |
| Attributes per element / raw and expanded QName / attribute value | 32 / 256 UTF-8 bytes / 8192 UTF-8 bytes |
| Per-entry nodes / text plus attributes                            | 65,536 / 1 MiB                          |

Enforce before extending bounded buffers; canonical encoding is incremental.
Count unselected/ignored/XHTML text, comments, processing instructions and
namespace declarations, independently of feed/callback segmentation. Keep only
bounded counters, stack, source identities and selected fields, not an expanded
tree or accumulated ignored strings. These are finite allocation/work bounds,
not a realtime deadline or a claim of 64-KiB total resident memory.

The QName ceiling covers raw lexical names before parsing and expanded element
and ordinary attribute names in callbacks. A long namespace URI must not amplify
a bounded source into many permanently interned expanded strings. The first
token remains bounded before its callback refuses an oversized expanded name.

ZIP admission requires one exact local/central/EOCD chain, no stub/gap/trailer,
extraction version 20, flags zero, method 8 and Unix creator host 3 with a regular
file type. Creator-version low bytes are metadata. Admit internal attributes
0 or 1; refuse DOS directory/volume bits and nonregular Unix types. Require exact
ASCII fixed basenames and matching local/central CRC, sizes, offsets and ranges.
Refuse ZIP64, multi-disk, encryption, descriptors and archive/member comments.
Bounded independent extra TLVs may differ (observed local 28 versus central 24
bytes); reject duplicate/truncated/ZIP64 TLVs and never interpret metadata as an
alternate path, size or encoding. Never extract a member path.
Opaque non-ZIP64 IDs remain admissible within these bounds; the two observed
timestamp/UID metadata IDs do not imply an extra-field whitelist.

Use bounded raw-DEFLATE input/output, including empty-input drains, with actual
expanded SHA-256/CRC/size and EOF/no-unused-data checks. Never use an unlimited
flush or a no-progress loop. Finding selected IDs does not permit early success.

Before Expat sees unfinished markup, a linear incremental lexical gate bounds
tags, comments, PI and live references across chunks. Stream text/CDATA with only
necessary delimiter suffixes. Permit only the five XML builtin escapes and
bounded decimal/hex character-reference spellings. Refuse DTD declarations in
the gate; explicit DTD/entity/external/skipped/parameter callbacks provide defense
in depth. Never resolve XInclude, external schemas or entities. Strict UTF-8 and
an explicit XML-1.0/UTF-8-or-omitted declaration guard are both required: forced
UTF-8 alone was observed accepting a conflicting ASCII encoding declaration.
Keep `buffer_text=False` and enabled runtime reparse deferral; no unsafe fallback.

## Verification and remaining work

Owned fixtures must exercise framing, malformed/unselected fields, all source
kinds, partitions, global/per-entry/token/reference caps, complete tail refusal,
DTD/entity/XInclude denial and immutable identity. Test direct constructors and
real producer/consumer composition, including chunk-invariant counters. All
production owners require direct failure tests and branch coverage above 80%.
Verify the installed pure SDK separately against retained original inputs; the
research probe is not a substitute decoder or installed product acceptance.

CWE data terms are separate from implementation/XSD licensing. Research did not
find a complete applicable copyright/license notice in the raw catalog; keyword
presence cannot establish legal coverage. A future custody/source profile must
retain the applicable MITRE notices and explicit attribution separately. Legal
rights and publisher authentication remain not assessed. No official corpus is
redistributed as a tracked fixture. Full XSD validation, richer field projection,
source acquisition/replay, CLI and model integration remain outside this slice;
#43/#47 stay open.
