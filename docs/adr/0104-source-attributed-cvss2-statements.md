# ADR 0104: Source-attributed CVSS 2 statements

- Status: Proposed for delegated owner review
- Date: 2026-10-28
- Decision owners: Fuzzy Technologies
- Related work: #47; ADR 0041, ADR 0060, ADR 0100

## Context

The original intelligence schema-one CVE snapshot reports `cvssV2_0` as an
unsupported metric while retaining its exact source bytes. Adding a newly
normalized assessment to that existing snapshot would change historical source
reparsing and exact replay. Operators still need a typed way to inspect legacy
assessments and their source context without converting their scores.

## Decision

Add Experimental `fuzzy1337.intelligence_cvss2` inspection profile `1` with
`ParseCveCvss2Statements(payload, catalog_version, source, evidence)`. It accepts
explicit CVE Record `5.2`/`5.2.0` bytes and reuses the original snapshot parser for
metadata and exact source/evidence binding. The source profile is pinned to
CVEProject schema commit `5533f6038cc0434e544e69240c704906d591de46`, its
`schema/imports/cvss/cvss-v2.0.json` blob
`caa64037aab6d6feffae1a25929c7c27f13714dd`, and the
[FIRST CVSS 2 guide](https://www.first.org/cvss/v2/guide).

Frozen `CveCvss2Statements` retains the unchanged original snapshot and ordered
`CveCvss2Assessment` values. Each value retains CNA/ADP role and container index,
the original metric-array index, complete provider metadata, and the complete
original metric object. This preserves optional `format` and `scenarios`,
including omission, alongside its `cvssV2_0` object. Separate metrics and providers
are never combined. Rejected records produce no positive assessments; a published
record with no CVSS 2 metric produces an empty assessment tuple.

Validate the consumed CVSS 2 object: required exact `version` of `2.0`, bounded
unprefixed `vectorString`, required `baseScore`, all six base metrics exactly
once, recognized optional metric names and values, and finite numeric source
scores in `[0, 10]`. Reject booleans for every score. Reject duplicate metrics,
unknown assessment fields, and unsupported metric values. Recognized optional
enumerated assessment fields retain their exact source values. Malformed
consumed CVSS 2 assessments fail explicitly rather than disappearing. When the source
also spells out a vector metric as an assessment field, require those explicit
declarations to agree. Omitted optional fields remain omitted. Vector metric
order remains exactly as supplied; the imported schema permits any order. Scores
remain source assertions and are never recomputed, rounded, or compared with
formula output. This reader validates consumed structure rather than full CVE
JSON Schema conformance.

Nested source objects are detached and frozen; `ToDict` returns editable detached
JSON-compatible data. Direct construction applies the same type, size, position,
assessment and immutability checks, while source derivation requires the parser.
Existing source limits remain 16 MiB and depth 32. This profile limits containers
to one CNA plus 64 ADPs, metric arrays to 256 entries per container, retained
assessments to 1,024 total, and provider/metric objects to 64 KiB each. Vector text
is limited to 2,048 UTF-8 bytes.

## Boundaries and compatibility

Original schema-one snapshot contents, references, serialization, replay, import
receipts, Finding enrichment, and CLI behavior remain unchanged. In particular,
the original snapshot still explicitly lists `cvssV2_0` as unsupported. The new
profile supplies inspection statements only; it introduces no persisted decoder
or replacement snapshot.

Byte hashes establish custody, without authenticating the publisher or proving
score correctness. The reader performs no score calculation or conversion,
finding severity change, target applicability matching, network request,
filesystem write, review approval, or execution authorization. It does not close
the broader intelligence task.

## Evidence

Deterministic unit and contract tests use synthetic source records, not a bundled
official corpus or live feed. They cover every metric family, optional explicit
fields, source-context/order preservation, omitted versus explicit metadata,
immutability, malformed/duplicate/conflicting metric declarations, numeric and
byte/count/depth limits, raw-source/evidence disagreement, rejected/no-v2 records,
direct-construction invariants, and unchanged original snapshot serialization.
