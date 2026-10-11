# Offline standards mappings

`fuzzy1337.standards_mapping` is an Experimental schema-v1 library for descriptive
framework relations. It keeps upstream classifiers, controls, rationale, source
versions, and review provenance separate from Security Object identity and raw
Evidence. A mapping never establishes certification or a passed control.

## Portable contract

`StandardIdentity(family, catalog_version, external_id)` preserves exact upstream
content versions and item IDs. Built-in candidate families are `cwe`, `capec`,
`attack`, `owasp-top10`, `owasp-asvs`, and `nist-csf`. `atlas` and future national,
regulatory, or vendor families use the same contract without changes to Core IDs.
Names are descriptive; the library does not validate external catalog existence.

`MappingSource` requires publisher, source version, HTTPS URL, source locator, and
offset-aware acquisition time. The optional `artifact_sha256` hashes actual source
bytes when the producer has pinned them; `None` means source bytes are unpinned.
URLs cannot contain userinfo, a query, whitespace, backslashes, or invalid ports.
Fragments may identify source sections. URLs are metadata and are never fetched.
Callers remain responsible for secret-free, truthful provenance fields.

`StandardsMapping` declares distinct endpoints and one typed relation:
`classified-by`, `related-attack-pattern`, `related-technique`, or `relevant-control`.
Every relation retains its rationale and 1..16 unique citations. Its `mapping:`
SHA-256 content reference covers all these fields. Neither relation direction nor
relation kind grants authority, control fulfillment, or observed exploitation.

Unreviewed relations have state `candidate`. `MappingReview` records a supplied
`approved` or `rejected` decision with reviewer, time, external decision reference,
and exact content reference. Changed content invalidates that review. Validation
proves structural freshness, not authenticated reviewer identity; the caller owns
review authorization and decision verification. Automation must not synthesize
human approval.

`MappingPack` declares a pack ID, pack version, and at most 1024 mappings. Pack
references cover exact content and review decisions; producers increment their
pack version when publishing changed content or decisions. `ToBytes` and
`FromBytes` use deterministic UTF-8 JSON bounded to 1 MiB. Imports reject unknown
schemas/fields, duplicate keys, nonfinite values, invalid types, duplicate IDs,
and tampered references. Equivalent mapping/citation order yields identical bytes.
`FromDict` applies the same typed schema and record limits; the byte limit belongs
to the bytes interchange boundary. The module performs no file writes or live sync.

## Finding associations

The owning finding subsystem passes its canonical object reference and an explicit
classifier with an exact catalog version. `BindFindingMappings` returns immutable
bindings to exact matching sources and the selected pack digest. It selects only
approved mappings by default. `include_candidates=True` exposes honest candidate
states for review or exploratory reports; rejected relations remain excluded.
Selection never follows another mapping transitively or implies reverse relations.
The caller must verify that the referenced object exists and is a finding.

```python
from fuzzy1337.standards_mapping import (
    BindFindingMappings, CandidateBaseline, MappingPack, StandardIdentity,
)

pack = MappingPack.FromBytes(CandidateBaseline().ToBytes())
classifier = StandardIdentity("cwe", "4.20", "CWE-89")
synthetic_finding = "object:" + "a" * 64
assert BindFindingMappings(pack, synthetic_finding, classifier) == ()
candidates = BindFindingMappings(
    pack, synthetic_finding, classifier, include_candidates=True,
)
assert len(candidates) == 4
```

The example uses an opaque synthetic reference and does not establish a real
finding or evidence-backed compliance outcome.

## Baseline provenance and review scope

`CandidateBaseline()` constructs five review-needed relations. It is deliberately
narrow, historical, and versioned. Source citation bytes are unpinned and no review
approval is recorded. These relations are not a complete framework crosswalk:

| Source identity      | Target identity              | Relation               | Basis                                                                                      |
| -------------------- | ---------------------------- | ---------------------- | ------------------------------------------------------------------------------------------ |
| CWE 4.20 / CWE-89    | OWASP Top 10 2021 / A03:2021 | classified-by          | Official CWE list in the category                                                          |
| CWE 4.20 / CWE-89    | OWASP ASVS 4.0.3 / V5.3.4    | relevant-control       | Official requirement CWE column                                                            |
| CWE 4.20 / CWE-89    | CAPEC 3.9 / CAPEC-66         | related-attack-pattern | Official Related Weaknesses entry                                                          |
| CWE 4.20 / CWE-89    | NIST CSF 2.0 / ID.RA-01      | relevant-control       | 1337 contextual interpretation; an individual finding does not fulfill the outcome         |
| CAPEC 3.9 / CAPEC-66 | ATT&CK 19 / T1190            | related-technique      | 1337 contextual interpretation; public exposure and exploitation require separate evidence |

Primary sources:

- [MITRE CWE-89, catalog 4.20](https://cwe.mitre.org/data/definitions/89.html).
- [OWASP Top 10 2021 A03](https://top10.owasp.org/2021/A03_2021-Injection/).
- [OWASP ASVS 4.0.3 V5.3](https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x13-V5-Validation-Sanitization-Encoding.md).
- [MITRE CAPEC-66, catalog 3.9](https://capec.mitre.org/data/definitions/66.html).
- [NIST CSF 2.0, Appendix A, printed page 18](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf).
- [MITRE ATT&CK 19 T1190, technique version 2.8](https://attack.mitre.org/versions/v19/techniques/T1190/).

An exact sourced ATLAS baseline relation and accountable owner review remain open
for #68. No automatic publication-current claim is made for any source. This
contract can later bind independently owned Intel identities through an explicit
version-aware bridge; it imports no pending Intel implementation.
