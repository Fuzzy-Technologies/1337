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
