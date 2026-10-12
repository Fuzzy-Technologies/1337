# fuzzy1337.standards_mapping

This Experimental schema-v1 library defines immutable versioned standard identities,
source citations, typed mappings, accountable review decisions, finite offline
packs, and explicit finding associations. Pack and mapping digests preserve
interpretation provenance independently from canonical Security Object identity.

`CandidateBaseline` supplies five sourced candidate relations. No owner approval
is synthesized. `BindFindingMappings` selects only approved exact source matches
by default; explicit candidate opt-in preserves unreviewed status. Relations do
not prove control fulfillment, certification, evidence integrity, or exploitation.

The supported surface is documented in `docs/STANDARDS_MAPPING.md` and proposed
ADR 0035. `MappingText`, `MappingDigest`, and `MappingReference` are Internal
validation helpers. No runtime fetching,
catalog synchronization, scanner execution, or persistence is performed.

::: fuzzy1337.standards_mapping
