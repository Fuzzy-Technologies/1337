# ADR 0043: Verified SPDX package inventory

- Status: Accepted
- Date: 2026-10-12
- Related work: #141, #138, ADR 0040

## Context

The verified image interpretation owner already provides deterministic image and
package identities, immutable raw evidence and portable model updates. SPDX
documents add a different source graph and licensing vocabulary. A document's
package list does not imply that every package is contained in its described
image. Package dependency relationships and license conclusions must not be
rewritten as containment or author declarations.

## Decision

Add an Experimental offline `fuzzy1337.sbom_spdx` inventory producer. Its first
profile accepts SPDX 2.3 JSON package metadata, with `spdxVersion` equal to
`SPDX-2.3`. SPDX 2.3.1 errata do not introduce a different wire-version string.
The exact profile is specified in `docs/SBOM_SPDX.md`. Initial documentation and
independent synthetic fixtures precede implementation.

Reuse the reviewed `fuzzy1337.images` interpretation boundary and the existing
model/evidence/finding owners. Keep `images.py`, existing image/package keys,
ObjectKind, RelationKind and the persisted model schema unchanged. There is no
additional store, command, network request or process invocation.

Require independently acquired immutable evidence with role `sbom`, matching
workspace/source/scope/version and acquisition completion time. No document
creation timestamp replaces the evidence observation time, and no inventory
creates a scan outcome or vulnerability verdict.

Bind exactly one described CONTAINER package to a supplied ImageIdentity through
one matching SHA256 checksum. The caller declares config versus manifest
semantics. This is an attributed document claim, not verification of OCI content
or selection from an image index. Resolve only local SPDX identifiers. Every
package must have explicit flat containment under that root; dependency or
co-occurrence never substitutes for containment.

Package identities require one matching versioned PURL and use the existing
supported qualifier/name profile. Document-scoped SPDX identifiers remain source
aliases scoped by the verified document digest. They never become canonical
package keys. Repeated inventories and additional sources reuse existing assets
and preserve finding disposition.

Keep declared and concluded licenses separate. NONE, NOASSERTION and omitted
values express information states; they are not license entities. Other bounded
declared expressions reuse existing attributed declarations without evaluating
license compliance. Reject LicenseRef and DocumentRef expressions because their
meaning requires a scoped license identity absent from the accepted model.

## Consequences

- Parse strict bounded JSON before returning any update. Validate all consumed
  identifiers, containment and package bindings before one in-memory transition.
- Keep arbitrary creators, suppliers, URLs, descriptions, source information,
  annotations, copyright and full license text in original raw evidence only.
- General dependency graphs, file/snippet graphs, external documents, SPDX 3,
  VEX/vulnerability interpretation, signatures and license-expression evaluation
  remain outside this profile. Unsupported semantic graphs fail explicitly.
- This extends #141 without completing the whole supply-chain feature or granting
  authority to collect an SBOM. Publication follows acceptance of the reviewed
  image interpretation dependency.

## Primary references

- [SPDX 2.3.1 package information](https://spdx.github.io/spdx-spec/v2.3.1/package-information/)
- [SPDX document creation](https://spdx.github.io/spdx-spec/v2.3.1/document-creation-information/)
- [SPDX relationships](https://spdx.github.io/spdx-spec/v2.3.1/relationships-between-SPDX-elements/)
- [Official SPDX 2.3 JSON example](https://github.com/spdx/spdx-examples/blob/master/software/example11/spdx2.3/sbom.spdx.json)
