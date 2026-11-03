# Selected official intelligence source acceptance

This records one actual 2026-11-02 smoke separately from deterministic synthetic
tests. It establishes acceptance only for the exact selected source bytes and
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
