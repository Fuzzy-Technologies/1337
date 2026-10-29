# Source-attributed CVSS 2 statements

`fuzzy1337.intelligence_cvss2` is Experimental inspection profile `1` under
[ADR 0104](adr/0104-source-attributed-cvss2-statements.md). The documented Python
interfaces are `CveCvss2Assessment`, `CveCvss2Statements`, and
`ParseCveCvss2Statements`. Other module helpers and constants are Internal.

The profile exposes legacy source assessments from explicit CVE Record
`5.2`/`5.2.0` bytes. It reuses the existing source/license/import attribution and
raw evidence binding, and retains the unchanged original intelligence snapshot.
Original schema-one snapshots continue to report `cvssV2_0` as unsupported; their
serialization, source reparse, Finding enrichment and replay remain unchanged.

```python
from fuzzy1337.intelligence_cvss2 import ParseCveCvss2Statements

# raw, source, and evidence identify the same explicitly supplied source artifact.
result = ParseCveCvss2Statements(raw, catalog_revision, source, evidence)
for assessment in result.ToDict()["assessments"]:
    print(assessment["role"], assessment["index"], assessment["metric_index"])
    print(assessment["providerMetadata"], assessment["metric"]["cvssV2_0"])
```

## Source meaning and shape

The consumed source format is pinned to CVEProject schema commit
[`5533f6038cc0434e544e69240c704906d591de46`](https://github.com/CVEProject/cve-schema/tree/5533f6038cc0434e544e69240c704906d591de46),
its [CVSS 2 import](https://github.com/CVEProject/cve-schema/blob/5533f6038cc0434e544e69240c704906d591de46/schema/imports/cvss/cvss-v2.0.json)
(Git blob `caa64037aab6d6feffae1a25929c7c27f13714dd`), and the
[FIRST CVSS 2 guide](https://www.first.org/cvss/v2/guide). This bounded reader
validates consumed assessment structure rather than full CVE schema conformance.

`ToDict` returns `profile_version`, the exact `format_version`, the unchanged
`snapshot`, its `snapshot_reference`, and ordered `assessments`. Each assessment
retains its container `role` (`cna` or `adp`), container `index`, `metric_index`,
complete `providerMetadata`, and complete original `metric` object. CNA index is
zero; ADP index is its position in the source ADP array. Metric index is its
position in that container's metrics array, including earlier non-CVSS-2 entries.

The full metric wrapper preserves optional `format`, source `scenarios`, and
other co-located metric formats. An omitted scenario stays omitted; this profile
does not invent `GENERAL`. Separate source providers and assessments remain
separate, with original array order. A published record without CVSS 2 returns an
empty assessment tuple. A rejected record exposes no positive assessments.

The consumed `cvssV2_0` object requires exact version `2.0`, an unprefixed vector,
and a numeric `baseScore`. All six base metrics must appear exactly once.
Recognized temporal and environmental metrics may also occur, including explicit
`ND` values. Source vector ordering remains unchanged, as permitted by the
imported schema; no canonical ordering is manufactured. Unknown or duplicate
metric names, malformed values, prefixed/parenthesized vectors, and unknown
CVSS 2 object fields fail explicitly.

Recognized optional enumerated assessment fields remain present. When an
assessment field and its corresponding vector token are both explicit, their
values must agree. An absent vector token or absent assessment field is not
filled in. `baseScore`, `temporalScore`, and `environmentalScore` must be finite
numbers in `[0, 10]`, without string or boolean coercion. Source scores retain
their values without formula recomputation, rounding, comparison, or conversion.

## Integrity and bounds

The original parser verifies the source SHA-256 and raw evidence length/hash
before inspection. Input remains limited to 16 MiB of UTF-8 JSON and depth 32,
with duplicate JSON keys refused. This profile permits one CNA plus 64 ADPs,
256 metric entries per container, 1,024 retained assessments, 64 KiB per provider
or metric object, and 2,048 UTF-8 bytes per vector.

Frozen dataclasses, read-only nested mappings, and tuples prevent mutation.
`ToDict` returns editable detached JSON-compatible data. Direct construction
enforces the same assessment, position, byte, depth and immutability constraints.
It cannot prove derivation from original bytes; use the parser for source-bound
inspection.

Hashes establish byte custody. They do not authenticate a publisher or prove
that its asserted scores are correct. The profile performs no score calculation,
conversion to another CVSS version, severity change, target-applicability
matching, Finding mutation, network request, or filesystem write. It confers no
review approval or execution authority and defines no new persistence format.

Deterministic tests use original synthetic source records with explicit fixture
attribution. They fetch no live feed and bundle no official CVE corpus.
