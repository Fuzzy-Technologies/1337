# Original CycloneDX license-policy projection

Internal opt-in `EvaluateVerifiedCycloneDxLicenses` reads one original CycloneDX
1.6 JSON inventory using the existing model, evidence, provenance and image
owners. It verifies original workspace, source, scope, provider version, time,
manifest and bytes, then reuses the complete existing inventory admission. Its
in-memory inventory candidate is discarded. There is no CLI, network collection,
model save or evidence publication.

The transient `cyclonedx-1.6-original-license-policy-v1` result retains original
component indexes, `bom-ref` aliases and license-occurrence indexes, canonical
package references, exact source text/field, image digest kind and complete
supplied provenance. Repeated aliases sharing a package and repeated license
entries remain independent. Root license fields do not supply package assertions.

Exact expression-only choices reuse the existing caller-authored expression
policy. Exact `license.id` choices require one syntactic identifier; an operator
inside an ID is unsupported. Accepted choices with extra fields yield explicit
unknown. Omitted and empty lists produce distinct unknown information states;
malformed inventories rejected by the existing owner refuse the whole call.
Each occurrence has `source_role="not-classified"`. Results do not infer SPDX
declared/concluded roles, combine sibling entries or establish legal compliance.

Existing four-MiB source and finite JSON/array limits remain in force. Additional
ceilings are 4096 projected rows and one MiB of complete canonical result JSON.
Refusal returns no partial projection. Reopening retained original evidence
works after complete workspace relocation and deletion of the selected input
file. ADR 0129 defines this Internal profile; saved schemas and the existing
`spdx-expression-policy-v1` matcher remain unchanged.

::: fuzzy1337.cyclonedx_license_policy
