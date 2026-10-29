# Source-attributed CVE product declarations

`fuzzy1337.intelligence_applicability` adds an Experimental read-only inspection
profile `1` under [ADR 0100](adr/0100-source-attributed-cve-applicability-statements.md).
Its documented Python interfaces are `CveAffectedContainer`,
`CveAffectedStatements`, and `ParseCveAffectedStatements`. Other module helpers
and constants are Internal. It exposes source product/version declarations from
explicit CVE bytes without deciding whether a particular target is vulnerable.

## Source contract

The profile supports CVE Record format labels `5.2` and `5.2.0`, pinned to the
official CVEProject [v5.2.0 schema at commit
`5533f6038cc0434e544e69240c704906d591de46`](https://github.com/CVEProject/cve-schema/blob/5533f6038cc0434e544e69240c704906d591de46/schema/CVE_Record_Format.json)
(schema Git blob `223e94b7fb38632b4ea46ae00d479221c4096f5f`). It validates
consumed declaration structure and bounded metadata, with no claim of full JSON
Schema conformance or official-corpus completeness. Existing intelligence
schema-v1 support for older CVE formats is unchanged.

The caller supplies authorized uncompressed UTF-8 source bytes, an exact
source-list revision, the existing `ReferenceSource` attribution, and the existing
raw `EvidenceReference`. The original
[`ParseIntelligenceSnapshot`](INTELLIGENCE.md) checks the digest/length binding and
CVE metadata. Its complete unchanged snapshot is retained as `result.snapshot`;
no new portable snapshot decoder or persistence format is introduced.

```python
from fuzzy1337.intelligence_applicability import ParseCveAffectedStatements

# raw, source, and evidence refer to the same explicitly supplied CVE artifact.
result = ParseCveAffectedStatements(raw, catalog_revision, source, evidence)
inspection = result.ToDict()
for container in inspection["containers"]:
    print(container["role"], container["index"], container["providerMetadata"])
    for product in container.get("affected", []):
        print(product.get("vendor"), product.get("product"), product.get("versions"))
```

`ToDict` returns `profile_version`, the exact `format_version`, the original
`snapshot_reference`, the original snapshot content, and ordered `containers`.
Each container returns `role` (`cna` or `adp`), `index`, complete original
`providerMetadata`, and its original `affected` products when present. The CNA
index is zero; an ADP index is its position in the original ADP array. All arrays
retain source order. Frozen dataclasses, read-only nested mappings, and tuples
prevent mutation; `ToDict` returns editable detached JSON-compatible data.

## Meaning and uncertainty

Product identity requires either `vendor` plus `product`, or `collectionURL` plus
`packageName`. A product requires `versions` or `defaultStatus`. Each source
status stays exactly `affected`, `unaffected`, or `unknown`. An omitted
`defaultStatus` stays omitted, even though the official source algorithm defines
an unknown fallback; this inspection profile invents no explicit source field.
An ADP may omit `affected`, and that omission remains visible. Present empty
`affected` and `versions` arrays are invalid. Rejected CVE records retain their
rejected snapshot and expose no product containers.

Exact version declarations, optional `versionType`, exclusive `lessThan` or
inclusive `lessThanOrEqual` bounds, and status `changes` remain unchanged.
Ranges require a nonempty declared `versionType`, but unfamiliar types remain
inspectable. Source versions and changes are never compared or sorted. A future
matching consumer must implement the appropriate comparison semantics and handle
source change ordering; this reader supplies no matching result.

Complete supported product qualifiers remain present: `collectionURL`,
`packageName`, `packageURL`, `repo`, `cpes`, `platforms`, `modules`, `programFiles`,
and `programRoutines`. These strings are metadata only; no URL is resolved and no
package/CPE syntax is interpreted. Other container content, including separate
`cpeApplicability`, configurations and CVSS scenarios, remains in original raw
evidence and is outside this affected-product profile. Unknown product/version
fields fail explicitly. Provider metadata is preserved in full within its bound.

Duplicate JSON keys fail in the original parser. Exact duplicates in version,
change and qualifier arrays fail where the pinned schema requires uniqueness.
Repeated change `at` positions additionally fail rather than assigning precedence
to conflicting source status changes. Product declarations remain separate,
including identical entries and independent CNA/ADP assertions.

## Bounds and integrity

The existing source boundary limits bytes to 16 MiB and JSON depth to 32. This
profile limits containers to one CNA plus 64 ADPs, products to 128 per container
and 1,024 total, and versions/changes/qualifier arrays to 256 entries. Each product
and provider object is limited to 64 KiB; scalar metadata has explicit UTF-8 byte
limits. Direct dataclass construction enforces the same declaration bounds and
immutability. It cannot independently establish derivation from source bytes;
call the parser when inspecting an original artifact.

Source/evidence hashes establish exact byte custody. They authenticate neither
the publisher nor the product assertions. This profile makes no finding changes,
applicability verdicts, version comparisons, severity conversions, risk scores,
publisher signature checks, network calls or filesystem writes. It creates no
review approval or execution authority. Existing source import receipts,
schema-v1 snapshots, finding observations, and exact replay are unchanged.

Tests use fixed original synthetic records with explicit fixture attribution;
they fetch no live feed and redistribute no official CVE corpus.
