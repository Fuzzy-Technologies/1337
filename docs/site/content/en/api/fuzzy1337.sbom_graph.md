# fuzzy1337.sbom_graph

This Experimental library adds an explicit opt-in SPDX 2.3 local package graph
profile. The supported surface is `SPDX_GRAPH_IMPORT_VERSION` and
`ApplyVerifiedSpdxGraph`; all remaining helpers are Internal. The existing flat
SPDX inventory profile and canonical image/package identities remain unchanged.

Admission revalidates exact typed inputs and verifies the original immutable
offline evidence manifest and bytes. One described CONTAINER root requires a
checksum matching the caller's explicit config/manifest image identity. Nested
containment must form a rooted acyclic graph covering every package, including
after canonical PURL aliases collapse. Only direct source containment edges are
emitted. Local dependency claims and their inverses use attributed RELATED_TO
relations; cycles imply no runtime reachability or transitive relation.

Original relationship coordinates retain manifest, content, image and local-to-
canonical endpoint bindings. Declared/concluded licenses and missing/NONE/
NOASSERTION states remain distinct inert facts without compliance evaluation.
The returned model/delta requires explicit model-store CAS saving. Actual
save/reopen/relocate/replay preserves original evidence and existing finding
triage. No scanner receipt or execution/retrieval authorization is created.
File/external-document graphs, scoped LicenseRef definitions, vulnerability/VEX
graphs, signatures and broader layer/runtime coverage remain outside this
profile. See [Verified local SPDX graph claims](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/SBOM_GRAPH.md).

::: fuzzy1337.sbom_graph
