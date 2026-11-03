# Original CycloneDX license-policy projection

`fuzzy1337.cyclonedx_license_policy.EvaluateVerifiedCycloneDxLicenses` is an
Internal opt-in SDK function for one retained CycloneDX 1.6 JSON inventory. It
evaluates original component license occurrences against an explicit
caller-authored `LicensePolicy`. There is no new command or default image-import
behavior. This is one bounded slice of #377; broader SBOM formats, source roles,
obligations and runtime correlation remain open.

Supply the existing owning `ModelState`, exact original `EvidenceRecord`,
matching `ModelProvenance`, explicit `ImageIdentity`, workspace root and policy.
Original role, acquisition manifest, bytes, workspace, source, scope, provider
version and time are verified through the existing owners. The complete
`ApplyVerifiedCycloneDx` admission then validates the original inventory,
container root binding, component/PURL identities and unique source aliases.
Its candidate model is discarded. Evaluation reads local evidence without
networking, launching tools, saving a model or publishing evidence.

The following invocation assumes those exact objects already come from the
owning source workflow. The policy is an illustrative caller preference, not a
project default or legal recommendation:

```python
from fuzzy1337.cyclonedx_license_policy import EvaluateVerifiedCycloneDxLicenses
from fuzzy1337.license_policy import LicensePolicy

policy = LicensePolicy("owned-review", ("MIT",), ("Apache-2.0",))
result = EvaluateVerifiedCycloneDxLicenses(
    state, record, provenance, image_identity, workspace_root, policy,
)
```

Keep the caller's config/manifest digest-kind selection explicit. Equal digest
bytes do not establish the other image identity. Original normalized license
assets are not a replacement for the source acquisition or its original
occurrences.

## Finite source profile

Only top-level components admitted by the existing CycloneDX owner participate.
Source text and fields remain separate from normalized policy atoms. The exact
choice shapes below apply after the complete original owner has accepted the
document:

| Original field or shape                    | Projection behavior                                                               |
| ------------------------------------------ | --------------------------------------------------------------------------------- |
| `metadata.component.hashes`                | Existing owner requires the explicitly selected container SHA-256 binding         |
| Component `bom-ref`, name, version, PURL   | Existing owner validates aliases and canonical versioned package identity         |
| `{expression: TEXT}` only                  | Existing complete expression matcher returns allow, deny or explicit unknown      |
| `{license: {id: TEXT}}` only               | One identifier atom; compound IDs remain `unsupported-license-identifier` unknown |
| Accepted choice with extra source fields   | `unsupported-license-choice` unknown; extra fields remain in original evidence    |
| Omitted component `licenses`               | One unknown row with `information_state="omitted"` and reason `source-omitted`    |
| Empty component `licenses: []`             | One unknown row with `information_state="empty"` and reason `source-empty`        |
| Owner-invalid choices or inventory         | Whole-operation refusal; no partial result or substitution with unknown           |
| Root licenses and other unprojected fields | No package-license assertion supplied                                             |

For example, with the illustrative policy, an expression occurrence
`MIT OR Apache-2.0` evaluates to allow, while a separate ID occurrence
`Apache-2.0` evaluates to deny. They remain two independent results. An ID
containing `MIT OR Apache-2.0` is unknown because an identifier is not an
expression. A license-name-only choice, simultaneous `license` and `expression`,
null license list or empty required text is rejected by the unchanged inventory
owner before policy projection. Unknown does not mean allow, deny or zero risk.

The existing expression matcher consumes its complete finite grammar and retains
unknown for unsupported syntax or unconfigured atoms. It does not verify SPDX
license-list membership, expand later-version names, infer exception equivalence
or select a license. The supplied normalized policy rules and digest accompany
the projection.

## Original occurrence identity and limits

The result profile is `cyclonedx-1.6-original-license-policy-v1`. It includes the
original acquisition `evidence_id`, source SHA-256, supplied provenance, image
reference/digest/kind and policy description. Each component retains its original
`component_index`, `source_bom_ref` and canonical package reference. Every license
occurrence retains `license_index`, `source_field`, exact `source_text` and its
independent evaluation. Missing/empty rows use null license index, source field
and text.
All rows use `source_role="not-classified"`.

Repeated source aliases that share one canonical package remain separate, as do
repeated identical license entries. Sibling entries are never joined with `AND`
or `OR`, deduplicated, selected or aggregated into a component/package/image
verdict. CycloneDX statements are not relabeled as SPDX declared or concluded
facts. A syntax-policy result is neither legal compliance nor a Finding.

The original source ceiling is four MiB, with the existing finite JSON and
4096-item array checks. The projection additionally permits at most 4096 rows:
each license occurrence counts once, and each omitted/empty component counts
once. Complete canonical result JSON must fit one MiB. A limit or owner-admission
failure raises `ValueError`; original-evidence integrity failures raise
`EvidenceError`. No partial projection is returned. Source strings remain data;
rendering consumers must escape them.

Re-evaluation uses retained original evidence after the entire owning workspace
is relocated and the selected input file is deleted. Focused integration tests
exercise independent source occurrences, full-owner refusal, corruption,
provenance, resource limits and read-only relocation with handwritten owned
fixtures. Installed-package verification uses the same synthetic evidence
workflow; it does not establish acceptance of an external publisher's SBOM.

See [ADR 0129](adr/0129-verified-cyclonedx-license-policy.md) and
[the existing expression-policy decision](adr/0125-sbom-license-expression-policy.md).
