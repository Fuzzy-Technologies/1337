# Selected official intelligence source acceptance

This records selected original-source executions separately from deterministic
synthetic tests. It establishes acceptance only for the exact source bytes and
executed product paths. The original downloaded corpus and workspace evidence are
untracked; no official corpus is redistributed in this repository.

## Selected source

| Fact                   | Observed value                                                     |
| ---------------------- | ------------------------------------------------------------------ |
| Publisher/source       | Official `cisagov/kev-data` mirror                                 |
| Exact commit           | `7ccba8e1223ccec82d12c7736bf3fae11e5bee86`                         |
| Catalog version        | `2026.10.30`                                                       |
| Publisher release time | `2026-10-30T17:02:45.3665Z`                                        |
| Original bytes         | `1826755`                                                          |
| Original SHA-256       | `3aa9cf3c01f116362a29d111702979175453c425e3733bde80fc4f6f8e2294e5` |
| Catalog records        | `1766`                                                             |
| Source licensing       | Same-revision `LICENSE`, `CC0-1.0`                                 |

The exact [original JSON](https://raw.githubusercontent.com/cisagov/kev-data/7ccba8e1223ccec82d12c7736bf3fae11e5bee86/known_exploited_vulnerabilities.json)
and [license](https://github.com/cisagov/kev-data/blob/7ccba8e1223ccec82d12c7736bf3fae11e5bee86/LICENSE)
are independently pinned to that commit. This is historical selected content,
not a claim of latest coverage or publisher-signature verification.

## Product results

A bounded external HTTPS download retrieved the exact selected file. Actual
`1337 intel import` then used the original local file, external origin, explicit
CISA source/license metadata, exact catalog version, exact expected SHA-256 and
an original-byte ceiling of `1826755`.

| Executed path                           | Observed result                                                                       |
| --------------------------------------- | ------------------------------------------------------------------------------------- |
| Local product import                    | Exit `0`, `succeeded`, all `1766` records                                             |
| Exact receipt/snapshot inspection       | Exit `0`, successful original-source reparse                                          |
| Selected `CVE-2015-5477` inspection     | One source assertion; original catalog/source attribution retained                    |
| Retained raw artifact comparison        | Byte-for-byte identical to the downloaded original                                    |
| Terminal receipt                        | `succeeded`; source/receipt/receiver provenance agree                                 |
| Target applicability                    | `not-evaluated`                                                                       |
| Publisher authentication                | `not-assessed`                                                                        |
| CLI diagnostics                         | No stderr or traceback                                                                |
| Separate SDK isolated HTTPS acquisition | `transport-failed`, zero received bytes, no usable snapshot, failure receipt retained |

The last result records the local environment's network-path failure separately
from its successful external download/local import. The isolated receiver's
certificate, environment, proxy, redirect and source-selection policies were not
weakened. A later hosted execution below resolves live acceptance for the exact
selected source, without converting that local failure into a success.

## Hosted isolated-receiver acceptance

The guarded [GitHub Actions execution](https://github.com/Fuzzy-Technologies/1337/actions/runs/41530326913)
passed on source commit `0d8b9db4f0582e56355b436eaf95284274a3fd4d`.
The ordinary SDK performed one HTTPS acquisition from the pinned official mirror;
the verifier reopened every original manifest, compared the complete terminal
receipt, joined its raw reference to the snapshot's exact evidence reference and
reparsed all `1766` records. HTTP status was `200`, the body was complete and the
exact original size and SHA-256 above matched. No fallback or transport retry ran.

Job `125568541511` uploaded the original workspace/receipt and deterministic
wrapper-test results as [artifact 13182380874](https://github.com/Fuzzy-Technologies/1337/actions/runs/41530326913/artifacts/13182380874),
archive SHA-256 `4db05ecc89eb60f2da8d61ded9545e4e2767390e82e62150b19a9b0bfc5886e5`.
Artifact retention is seven days; the exact source selection and verification
script remain in version control for reproduction. This is acceptance of one
fixed historical source, not moving-feed coverage, publisher-signature
authentication or target applicability. Those two verdicts remain explicitly
`not-assessed` and `not-evaluated`.

## Pinned selected EPSS HTTPS checkpoint

The separate [pinned EPSS profile](INTELLIGENCE_EPSS_HTTPS.md) selects archive
commit `489cd9fcf989cdc3ec87168b873c858938a53517`, day `2026-11-02`, model
`v2026.06.15` and raw SHA-256
`86885067d459c6f3ca888bfeb6219d536b428afda9a776c14b48c82bb6a85635`.
Expected source facts are 2,796,673 gzip bytes, 12,129,716 decoded bytes and
398,815 original rows. These pins originate from the accepted local source
checkpoint; they do not alone establish remote acquisition.

The actual isolated SDK attempt in this local environment returned
`transport-failed`, no HTTP status and zero received bytes. It retained confirmed
partial raw/failure receipt evidence, did not publish a usable selection and did
not change model state. This remains a failed network acceptance.

The guarded Draft-only hosted lane runs `tools/epss_https_acceptance.py` using a
fresh installed wheel. It requires the actual complete HTTP 200 SDK body, exact
source pins and original remote roots, full gzip reparse, explicit matched and
unmatched CVEs, unchanged decimal spelling and offline replay after relocation.
Its terminal facts and original workspace are retained separately from the local
failure. [Hosted run 41628694763](https://github.com/Fuzzy-Technologies/1337/actions/runs/41628694763)
passed on head `dc934ae7fa025b431edb243d167baed6b76bc433`, tree
`5c3b3ea7f74c2cace9c22f400495b4a4f1e4ea95`. Job `125892447105` actually
built/installed the wheel and executed that unchanged receiver: complete HTTP
200, the exact raw hash/size above, all 398,815 rows validated, two selected
assertions and one unmatched CVE. Original `6e-05` spelling and score clock
`2026-11-02T12:00:30Z` were retained; relocated original-source reopening and
unchanged model state passed. No fallback or retry supplied the body.

[EPSS artifact 13227615267](https://github.com/Fuzzy-Technologies/1337/actions/runs/41628694763/artifacts/13227615267)
has archive SHA-256
`8417a4a12f4ce2619d35be894b2df27006477de830e3b6b5b8aefab27e4d727b`.
Its original evidence, terminal JSON and installed wheel were downloaded and the
archive digest checked independently. The clean installed offline CLI reopened
the same original selection/receipt and raw bytes locally without a model write.
The artifact's five production source hashes match this profile's source files;
the later acceptance-record update changes documentation only.

The same run's CISA job `125892446719` also passed complete original HTTPS
acquisition/reparse of 1,766 records after extraction of shared receiver ownership.
[CISA artifact 13227411518](https://github.com/Fuzzy-Technologies/1337/actions/runs/41628694763/artifacts/13227411518)
has independently checked archive SHA-256
`a48285473f6fb4c6ef615afe1e35d611e2f8b6a18bee73a21bf50dd035123f43`.
Both artifacts have seven-day retention. Exact source pins and verification tools
remain versioned. This is bounded historical source acceptance, with publisher
authentication `not-assessed` and target applicability separate. It does not
complete the broader CVE/CWE/terms/assurance scope of #43/#47.

## Pinned selected CVE 5.2 HTTPS checkpoint

The separate [CVE HTTPS profile](INTELLIGENCE_CVE_HTTPS.md) selects one published
wire-5.2 record, with distinct original remote custody and finite one-MiB source,
two-MiB envelope and 32-KiB receipt limits. The candidate is `CVE-2024-3094` at
commit `124afead838875e8bf8f5f0bbaf929340216d81b`, with 23,216 expected bytes and
raw SHA-256
`f9f0858cc058006963ed8338b802cadaf559f4fa5c501c53752407dfaf3227f9`.
Research retrieval established Git content identity and existing pure-parser
compatibility. It did not establish SDK HTTPS acquisition.

Owned deterministic tests and clean installed synthetic SDK replay cover exact
wire/state/ID admission, original manifests and source notices, independent
publication outcomes, request-limit identity, corruption/mixed-source refusal
and offline relocation. The actual product CLI is also exercised through a real
isolated owned worker. These are fixture results, not public-source acceptance.

The actual clean installed CLI attempt in this local environment returned
`transport-failed`, no HTTP status and zero bytes. Partial raw and failure receipt
publication were confirmed, selection publication was not attempted and model
commit remained `not-attempted`. That network attempt is retained as a failure;
receiver policy was not weakened and no fallback supplied replacement bytes.

The separate guarded hosted lane uses `tools/cve_https_acceptance.py` through a
fresh installed wheel. It requires the actual complete HTTP 200 body, exact pins
and requested byte/deadline limits, original source/envelope/receipt joins,
unchanged nested assertions/model and relocated offline SDK plus CLI inspection.
Publisher authentication and legal rights stay `not-assessed`.

[Hosted run 41640143215](https://github.com/Fuzzy-Technologies/1337/actions/runs/41640143215)
passed on head `08f423c4c9bf6c39fb0e1dd48e3056f3cd977aab`, tree
`ac266efcaf042857e0a0ea83040c706f561c9249`. Actual CVE job `125931299029`
built/installed the wheel and fetched the exact original record once: complete
HTTP 200, the size/hash above, matching wire/state/CVE and original request limits
of 23,216 bytes and 30 seconds. Original SDK receipt/reparse, relocated offline
CLI inspection and unchanged canonical model state passed. The KEV/EPSS source
jobs were skipped; their earlier acceptance is separate.

[Artifact 13232686390](https://github.com/Fuzzy-Technologies/1337/actions/runs/41640143215/artifacts/13232686390)
has archive SHA-256
`2a5a32046164ee874f20164f369d93273b4be8c6509a666ae229ecd62333cf11`.
Its wheel SHA-256 is
`87f7a67be6430a4df73b0c13431bdb831dbe61f63765b811f7e7b502264b9da0`.
Both were downloaded and independently hashed. The five exercised production
hashes agree with current source and wheel members. A clean installed Main CLI
reopened the same downloaded original roots locally; source/snapshot/raw bytes,
request limits and model bytes agreed. The later acceptance-record update is
documentation only. Artifact retention is seven days; exact source pins and
verification tools remain versioned.

This establishes the one selected historical PUBLISHED record through this
finite profile. It does not establish complete JSON-schema/catalog coverage,
other source states, batch/delta acquisition, publisher signatures, downstream
legal rights or target applicability. The wider #43/#47 scope stays open.

## Selected CWE pure-decoder checkpoint

The separate [pure selected decoder](INTELLIGENCE_CWE_SELECTION.md) supports exact
catalog 5.0 / namespace 8 and 4.21 / namespace 7 consumed-field modes under
[ADR 0131](adr/0131-bounded-selected-cwe-zip-xml.md). Its 4 MiB ZIP, 32 MiB actual
XML and 1 MiB selected canonical-JSON ceilings are profile-local; legacy source
and normalized snapshot limits remain unchanged. Only explicit selected
Weaknesses become records. Category, Grouping and View identities remain known
unsupported kinds, while absent IDs remain separately unmatched.

Dedicated [research run 41656354959](https://github.com/Fuzzy-Technologies/1337/actions/runs/41656354959)
at `ab482cbfff482748655e4d061fae599cf4334676` retrieved four literal pinned
XSD/ZIP inputs once. Original artifact `13238544847`, SHA-256
`d92cdc41bdf3b355839cc8aa9f827c688fcfdd685387637296f3e4da261f1fe3`,
retains exact inputs, hash-bound status-enumeration slices, complete bounded
DEFLATE/CRC/XML metrics and 22 executed cases without skips/failures. Original
hashes, enum slices and complete expanded facts were independently rechecked.
Earlier local zero-byte transport timeouts remain failures. This external
research is separate from product SDK acquisition.

| Catalog | Actual expanded bytes / CRC32 | Actual source entry kinds           |
| ------- | ----------------------------- | ----------------------------------- |
| 5.0     | 19,105,731 / `c01f0a7d`       | 984 Weakness, 431 Grouping, 62 View |
| 4.21    | 18,571,978 / `0575b537`       | 984 Weakness, 431 Category, 62 View |

A separate clean installed pure-SDK exercise consumed both retained original
ZIPs without network access, matching original/expanded hashes, complete CRC,
counters and exact partitions. The wheel SHA-256 is
`e90ec2ffdc773e5e11194e13e59a9aa467902ff3de4fa4db4f7ff53db61b878c`;
all three installed decoder members matched the reviewed source. `CWE-79` and
`CWE-89` matched Weakness records, `CWE-1000` retained its unsupported View kind,
and `CWE-9999999999` remained absent. These are finite observations of those
exact supplied bytes, not universal publisher counts or full XSD validation.

Neither the research probe nor this pure decoder creates an acquisition record,
stored selection, receipt, original-source custody or CLI workflow. Raw XML did
not establish complete applicable copyright/license notice coverage; a future
source/custody profile must retain the applicable MITRE notices and attribution
separately. Legal rights, publisher authentication, applicability and contextual
scoring remain not assessed. #43/#47 stay open.

## Local selected CWE custody and CLI consumer

The accepted [local SDK custody](CWE_LOCAL_CUSTODY.md) under
[ADR 0133](adr/0133-local-selected-cwe-custody.md) retains an explicitly supplied
original ZIP, attributed selected envelope and exact terminal receipt. The
bounded profile admits catalog 5.0/schema 8 or 4.21/schema 7, a mandatory exact
original-byte pin, one to 64 explicit CWE IDs and the fixed complete captured
MITRE notice bundle. Original-byte, expanded XML and selected-content ceilings
remain profile-local; legacy snapshot budgets are unchanged.

The additive [local CLI consumer](adr/0135-local-selected-cwe-cli.md) exposes
`intel cwe import|inspect` over this SDK, including explicit immutable selection
and receipt roots. Import requires three independent confirmed ACKs for usable
success. Inspection verifies exact owner/provenance/notice/limit joins and full
original reparse, writes no files or model, and survives input deletion/workspace
relocation. SDK publication ACKs and verified-present inspection facts remain
distinct. Weakness matches, known unsupported source kinds and absent IDs remain
separate source assertions without risk or applicability conclusions.

The complete captured terms text and provenance are preserved in source/envelope/
receipt identities. An inert attributed fixture retains the exact original HTML
and full UTF-8 text for reproducible notice identity checks without another fetch.
Neither retention nor a matching hash establishes legal rights, historical notice
applicability or publisher authentication. The prior pure-decoder checkpoint
above remains evidence of that historical boundary; SDK and assembled CLI
acceptance are separately verified through their actual interfaces. The wider
#43/#47 profiles and assurance scope remain open.

On 2026-11-03, a clean installed console exercised both retained original ZIPs
without another source fetch. Each import used its exact compressed byte length
as the inclusive ceiling, confirmed all three publications and preserved the
complete notice. After deleting the acceptance input and relocating its workspace,
installed inspection returned identical source/selection facts under network,
process and store-write tripwires. Missing receipt roots refused without writes.
The reviewed wheel SHA-256 was
`de12e1da0ba6dcf3737a7b74446765d02a33045435d043d30b458f9a2fdc568b`.
A separate independently authored installed synthetic oracle passed Weakness,
unsupported View, absent-ID and max-plus-one partial-custody cases. These finite
local consumer checks are distinct from exact-head shared integration CI.

## Publisher-prose regression

The first real import failed honestly with `parse-failed`. The selected catalog
contains surrounding prose whitespace, including the name for `CVE-2015-5477`,
and internal U+202F narrow no-break spaces in the product/name for
`CVE-2025-54236`. These are publisher prose, not identifier or score semantics.

The KEV input parser now maps only Unicode category `Zs` separators to ASCII
spaces and removes surrounding whitespace in vendor/product/name/action prose.
Printable internal spacing is retained. Normalized record decoding remains
strict; internal tabs, line breaks, controls, directional formatting, empty text,
wrong types and excessive original prose still fail. Identifiers, dates, source
attribution, CVSS and raw bytes are not normalized. Existing accepted snapshots
retain their exact reparse behavior.

Fixed synthetic regression cases reproduce the two observed source shapes
without bundling the catalog. Deterministic tests additionally retain all raw
hash/length and portable decoding checks and prove denied inputs stay denied.

See [ADR 0123](adr/0123-selected-intelligence-inspection.md) for finite source
support; compressed/full corpora and publisher authentication remain outside
this acceptance. Task #47 remains open for its unresolved broader criteria.
