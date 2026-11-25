# fuzzy1337.sbom_commands

The installed CLI and interactive shell expose Experimental contract-version-one
`sbom import spdx-graph`, `sbom import cyclonedx` and the verified read-only
`sbom image` view. This module
is their Internal implementation. All classes,
functions, methods and helpers, including `SbomParser`, `RunSbomCommands`,
`SbomFailure`, `SbomArgumentParser`, `SbomEvidenceStore`, `SbomPath`,
`ReadOwnedSbom`, `CheckBases`, `CheckKnownSbomSources`, `SourceFact`,
`ApplySourceFact` and `ReferenceProposal`, remain Internal. Their importability
does not establish a supported Python SDK or extension interface.

Import requires an existing workspace/model and workspace-local offline scope,
an explicit run reference, image SHA-256 digest and `config`/`manifest` digest
kind, and current model/workspace revision bases. Digest kind is never inferred
from checksum equality, an archive or source bytes. The unchanged
`ApplyVerifiedSpdxGraph` or `ApplyVerifiedCycloneDx` SDK creates the image and
canonical package linkage according to the explicitly selected source profile.
Scope attributes offline evidence and grants no collection or execution authority.

File mode requires explicit `--file`, `--owner`, `--read-consent-reference`,
`--source-id` and `--source-version`; optional `--provider-version` is declared
metadata, not an observed tool invocation. Both revision bases, current scope
and workspace object references validate before selected bytes are read. One
regular single-link original file is bounded to four MiB before reading, with
non-following path and parent checks and owned descriptor closure. Full same-path
and same-handle physical identities remain stable. Existing Windows ctime
tolerance applies only across path/handle views, preserving same-view checks.
Original bytes remain complete unredacted evidence; choose owned non-secret
exports suitable for retention.

CycloneDX file mode additionally requires a lowercase `--expected-sha256` of
the complete original file. Its pin grammar validates before source reads, and
its digest must match before evidence publication. The unchanged finite SDK
admits only its existing CycloneDX 1.6 inventory; no wider schema, license policy
or file/layer attribution is inferred. Its profile-tagged original read fact is
created only by that actual product operation. Repeated scalar flags and option
abbreviations are refused in this new profile.

Retained mode requires `--evidence` naming the exact original acquisition
manifest, independently bound to a known `sbom-import-source` custody observation.
Original source/version/provider/time, image digest/kind, run, scope and read
descriptions remain unchanged. Content SHA-256 is distinct from manifest identity;
same-byte different acquisitions and changed context cannot borrow original
custody. File-mode overrides and unknown SDK raw-only acquisitions fail before
selected raw reads. A different image kind needs its own original file acquisition.
CycloneDX replay also refuses a replacement source hash. Workspace references or
already normalized SDK objects cannot substitute missing product read custody.

Before generic owning evidence reads in either import mode or the saved image
view, `CheckKnownSbomSources`
preflights every known original SBOM blob's four-MiB ceiling and physical size.
All same-SHA or same-locator aliases in workspace/model references and original
manifests retain the original role, media type and size. Known custody originals
present only in the model remain independently verified after a prior workspace
save failed. Older originals retain their own source/provider/scope context and
their scopes validate through the existing owner. Unrelated larger non-SBOM
evidence keeps its own existing generic owner budgets. Its optional incoming
reference is absent only for a saved-state view; all known original custody is
still checked before the unchanged report owner verifies the saved snapshot.

The unchanged graph transition and original custody observation compose one
in-memory model revision, followed by the existing model CAS and independent
workspace CAS owners. Nested containment, direct/inverse source coordinates,
shared aliases, inert license facts, prior findings and operator triage survive.
Dependency claims remain UNKNOWN for runtime reachability without separate
verified assessments; license metadata asserts no compliance result. Exact known
original replay is a byte-preserving no-op, including after workspace relocation.

The Internal schema-one terminal summary separates `acquisition_commit`,
`model_commit` and `workspace_commit`: `not-attempted`, `unknown`, `confirmed` or
explicit CAS refusal `not-committed`. Lost acknowledgement remains unknown even
when bytes were saved, and later failure preserves prior confirmed owners.
There is no cross-store atomicity or rollback claim. Exit `0` requires confirmed
completion, `2` means invalid configuration, `4` means source/integrity/
normalization/storage failure or uncertainty, and `130` means interruption.
Diagnostics exclude selected paths and original contents; static help reads no
local state. Shell history protects the command arguments before dispatch.

This product adds no scanner execution, archive extraction, daemon or registry
access, remote retrieval, native grant, implicit read consent, inferred score or
Core/SDK schema change. The existing flat SPDX and graph SDK contracts remain
unchanged.

The read-only image route accepts an optional explicit `--license-policy ID`
with repeated `--allow-license`/`--deny-license` atoms. The selected finite policy
profile matches original owned SPDX graph assertions only, keeping their exact
source/image/alias references and declared/concluded roles separate. It creates
no compliance or aggregated package/image verdict. Invalid policy is refused
before saved owners are read; default output remains unchanged without policy.

See [Owned SPDX graph import](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/SBOM_IMPORT.md)
and [ADR 0082](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/adr/0082-owned-offline-spdx-graph-import.md).
The separate [owned CycloneDX import](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/SBOM_CYCLONEDX_IMPORT.md)
is defined by [ADR 0154](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/adr/0154-owned-offline-cyclonedx-import.md).

::: fuzzy1337.sbom_commands
