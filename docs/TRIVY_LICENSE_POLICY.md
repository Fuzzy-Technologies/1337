# Original native Trivy license-policy projection

Internal `EvaluateVerifiedTrivyLicenses(state, report, provenance, records,
workspace_root, policy)` evaluates retained original package-license occurrences
from one successful native Trivy 0.75.* schema-2 container-image report. It is an
opt-in SDK projection with no CLI, scanner invocation, daemon/cluster access,
source collection or storage writes. Historical report evidence grants no current
execution authority and does not replace six-role native capture/receipt replay.

The original workspace and exactly three source roles are mandatory: stdout
`application/json` at most 4 MiB, stderr `text/plain` at most 1 MiB and
provider-version `application/json` at most 16 KiB. Actual stored manifests are
bounded before eager raw allocation. Immutable manifest equality, original
source/scope/version/time/invocation/execution joins and complete unchanged image
owner validation precede projection; the in-memory candidate is discarded.

The transient `trivy-0.75-original-license-policy-v1` result retains the explicit
config-domain image reference, original stdout SHA-256, all three acquisition
manifest IDs, observed provider version, invocation/execution and complete
supplied provenance. Equal-byte manifest aliases never replace config identity.
Each package keeps its original result/package array indexes, canonical package
reference and every license array occurrence/index in order. Repeated packages
and strings remain independent; Target paths and unrelated fields stay raw.

| Original native field                        | Result meaning                                      | Missing or unsupported state                            |
| -------------------------------------------- | --------------------------------------------------- | ------------------------------------------------------- |
| `Metadata.ImageID`                           | Config-domain image identity                        | Whole-owner refusal                                     |
| `Results[*].Type` and `Packages[*]` identity | Original coordinates and canonical package          | Whole-owner refusal                                     |
| Each `Packages[*].Licenses[*]` string        | Original text with independent syntax-policy result | Unknown for unsupported expression or unconfigured atom |
| Omitted `Licenses`                           | One unknown row                                     | `information_state=omitted`                             |
| Null `Licenses`                              | One unknown row                                     | `information_state=null`                                |
| Empty `Licenses`                             | One unknown row                                     | `information_state=empty`                               |
| No packages                                  | Empty projection                                    | No overall allow verdict                                |

Each original string is evaluated separately through the unchanged caller-authored
`LicensePolicy` and finite expression matcher. Native source text is not asserted
to be formally validated SPDX. `source_role=not-classified` preserves that
boundary. Results do not infer declared/concluded roles, combine sibling strings,
select a license or issue an aggregate package/image compliance verdict. They are
not legal advice, license entitlements or vulnerability Findings.

All existing source, JSON, array and matcher limits remain. Additional local
ceilings are 4096 rows, counting each omitted/null/empty package once, and 1 MiB of
complete canonical output JSON. Row counts are preflighted; serialized output
size is checked incrementally for each occurrence before append. Owner-invalid
later data, corruption, foreign attribution and limits refuse the entire call
without a partial result. Consumers must escape retained source text in HTML.

Deterministic offline reevaluation after complete workspace relocation and removal
of the initial selected file uses the same retained original manifests and bytes.
Synthetic owning-store tests verify this SDK behavior without claiming genuine
Trivy execution or external-publisher acceptance. ADR 0134 defines this finite
Internal slice; broader #377 format, layer/file and live runtime criteria remain.
