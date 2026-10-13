# Reviewed standards baseline source record

The selected schema-v1 revision `fuzzy1337.baseline` / `0.2.0` contains six
narrow relations. These are versioned historical selections, not complete or
publication-current framework catalogs. The historical `CandidateBaseline()`
remains unchanged.

## Relation basis

| Mapping                          | Source identity      | Target identity             | Basis                          |
| -------------------------------- | -------------------- | --------------------------- | ------------------------------ |
| `prompt-injection.atlas-context` | cwe 4.20 / CWE-1427  | atlas 2026.09 / AML.T0051   | 1337 contextual interpretation |
| `sql-injection.asvs`             | cwe 4.20 / CWE-89    | owasp-asvs 4.0.3 / V5.3.4   | Direct publisher relationship  |
| `sql-injection.attack-context`   | capec 3.9 / CAPEC-66 | attack 19.0 / T1190         | 1337 contextual interpretation |
| `sql-injection.capec`            | cwe 4.20 / CWE-89    | capec 3.9 / CAPEC-66        | Direct publisher relationship  |
| `sql-injection.nist`             | cwe 4.20 / CWE-89    | nist-csf 2.0 / ID.RA-01     | 1337 contextual interpretation |
| `sql-injection.top10`            | cwe 4.20 / CWE-89    | owasp-top10 2021 / A03:2021 | Direct publisher relationship  |

CWE-89 selects four approved exact-source matches. It does not inherit the
CAPEC-to-ATT&CK relation transitively. CWE-1427 has one explicitly contextual
ATLAS association. A supplied classifier must match the exact source identity
and version; neither helper guesses classification or checks attack occurrence.

## Primary-source acquisition

All seven artifacts were actually acquired on 2026-10-13. Each digest below
covers the complete raw downloaded artifact, before parsing or selecting an
item. The CWE digest covers the ZIP bytes, not its uncompressed XML member.
The package contains descriptive citation metadata and mapping content, not
copies of the catalogs or security Evidence.

| Publisher / version | Exact acquired source                                                                                                                                           | Raw SHA-256                                                        |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| MITRE / 19.0        | [Enterprise ATT&CK STIX catalog](https://raw.githubusercontent.com/mitre/cti/25c22924b59b05ace30bbd824e48bd15b208410f/enterprise-attack/enterprise-attack.json) | `987d0cfddb1e65797457cf2b045df9161140ede71fd627f15dfdd73c2a2c72ab` |
| MITRE / 2026.09     | [ATLAS format-6 YAML catalog](https://raw.githubusercontent.com/mitre-atlas/atlas-data/3259f388d19cbcca11bacf12a0ef97f4198f711b/dist/v6/ATLAS-2026.09.yaml)     | `935efa93e28294432d3e2f537eb94991ef8d1f8c58341cd360ea3321ddb66688` |
| MITRE / 3.9         | [CAPEC versioned XML catalog](https://capec.mitre.org/data/xml/capec_v3.9.xml)                                                                                  | `70279a2dff0cb0ad79e546adb07828335a704ad5210e047e09e986172fc9e34d` |
| MITRE / 4.20        | [CWE versioned XML ZIP](https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip)                                                                                      | `3976f599e5e5200219a3108bb896d06e2a88fbb293369e1883cb423a5e9d7d50` |
| NIST / 2.0          | [NIST CSWP 29 PDF](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)                                                                                     | `3c31f46fee98cac0c4323453e5109291a213b4de7fef8c058af9bf67f717433c` |
| OWASP / 2021        | [Top 10 A03:2021 source](https://raw.githubusercontent.com/OWASP/Top10/3a31f35346c3f4e90f350395124382fa53af2afe/2021/docs/en/A03_2021-Injection.md)             | `c660dd06c1d62d634f41607b243708f5bef1d2865d883065e4601332911a0060` |
| OWASP / 4.0.3       | [ASVS V5 source](https://raw.githubusercontent.com/OWASP/ASVS/719cd32389a155b7b39d8ce665faacb5fbf60473/4.0/en/0x13-V5-Validation-Sanitization-Encoding.md)      | `8d5b8e494a0c27d184215e051cdba454bf44aff555bd5eb4a53ad6e1a16108ab` |

Locators preserved in the mapping pack identify:

- CWE ZIP member `cwec_v4.20.xml`, weakness IDs 89 and 1427, their descriptions,
  CWE-89 related CAPEC-66, and CWE-1427 mapping notes.
- CAPEC `Attack_Pattern[@ID="66"]/Related_Weaknesses`, specifically CWE-89.
- OWASP Top 10 A03:2021, the CWE-89 entry in List of Mapped CWEs.
- ASVS V5.3 row 5.3.4, its explicit CWE column 89.
  The selected English chapter is byte-identical to the official
  [4.0.3 release](https://github.com/OWASP/ASVS/releases/tag/v4.0.3_release)
  at commit `d31389d213b320cc2ef0cb1c30792cc80104d8ff`. The upstream
  `v4.0.3` ref is a branch; its later immutable selected commit retains the
  same released chapter bytes. No nonexistent `v4.0.3` Git tag is claimed.
- ATT&CK STIX `attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c`,
  external ID T1190 and technique version 2.8. The selected object is neither
  revoked nor deprecated; a different legacy mitigation sharing external ID
  T1190 is not the technique being cited.
- ATLAS format 6.0.0 / collection version 2026.09, `techniques["AML.T0051"]`.
  Its bytes match the publisher release-asset digest
  `935efa93e28294432d3e2f537eb94991ef8d1f8c58341cd360ea3321ddb66688`.
  The deprecated `dist/ATLAS.yaml` version 5.6.0 is not selected.
- NIST CSWP 29 dated 2024-02-26, Appendix A ID.RA-01, printed page 18
  (PDF page 23). The associated 1337 interpretation does not fulfill that outcome.

GitHub source URLs use immutable commit paths. Versioned source URLs and
observed SHA-256 values establish reproducible selection and byte identity,
not publisher authenticity or signatures. No source fetching occurs when a
consumer calls `ReviewedBaseline()` or binds a finding.

The ASVS chapter at the selected immutable commit is byte-identical to the
official [`v4.0.3_release`](https://github.com/OWASP/ASVS/releases/tag/v4.0.3_release)
chapter at `d31389d213b320cc2ef0cb1c30792cc80104d8ff`. The official
[`ATT&CK-v19.0`](https://github.com/mitre/cti/releases/tag/ATT%26CK-v19.0)
annotated tag `e98cf9825e301ad8852c50448134e4dbca479e2d` resolves to the selected
`25c22924b59b05ace30bbd824e48bd15b208410f` commit. The tag is unsigned; it does
not add signature verification to this byte/content provenance record.

## Content review

The six exact mapping references reviewed by the coordinator are:

| Mapping                          | Exact content reference                                                    |
| -------------------------------- | -------------------------------------------------------------------------- |
| `prompt-injection.atlas-context` | `mapping:1f0a63b1b79a7c2612b52d6fddbd79a3298fc71cfd029b731db901a35bbb0268` |
| `sql-injection.asvs`             | `mapping:94f038c48a92d6cb02da94f57ac634b192711afa68ce0a3a3bd26c6e927f8ed4` |
| `sql-injection.attack-context`   | `mapping:cce80f52fa562054123d6e63fbf3e0a51a634bd1c0ff363ae5d53b4aadf4d717` |
| `sql-injection.capec`            | `mapping:996f9638534994fb75dc5154c5aac502d2ad653b158a9615307fefbf55888203` |
| `sql-injection.nist`             | `mapping:4ae059eae5738229af7e4f4b625cf45ccb054e890afe0a2e1277492af31bb243` |
| `sql-injection.top10`            | `mapping:7669b9e70e607612c33635e023aa8916c409594a86a0591b531423781f133f83` |

The actual [owner-account source-content decision](https://github.com/Fuzzy-Technologies/1337/issues/68#issuecomment-6152224036)
was recorded by `Tim55667757` at `2026-10-13T18:19:24Z` after independent
inspection of the seven artifacts, version facts, and these six unchanged
mapping references. Each `MappingReview` retains that decision URL, account,
time, and mapping reference. This content decision is separate from the
implementation/CI integration review; no human or publisher identity is
synthesized by the package loader.

The approved pack reference, which additionally covers these review decisions,
is `mapping-pack:1eb56765bb50dcc561cfd0e32b528d7352284a0032623e19ee0fa7c1bd485eb2`.
A structural review record cannot authenticate its issuer. Later content
changes invalidate its review and require another accountable decision and
pack revision.

See [ADR 0063](adr/0063-reviewed-standards-baseline.md) and the
[generic mapping contract](STANDARDS_MAPPING.md).

No relation proves exploitation, validates a classifier, establishes that
an object belongs to a model, verifies security Evidence, passes a control,
or certifies compliance. Finding triage remains owned by the finding subsystem.
