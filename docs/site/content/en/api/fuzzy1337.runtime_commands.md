# fuzzy1337.runtime_commands

The installed CLI and interactive shell expose Experimental contract-version-one
`runtime import docker-inspect` and `runtime import kubernetes-list`. This module
is their Internal implementation:
all classes, methods, functions and helpers, including `RuntimeParser` and
`RunRuntimeCommands`, are Internal and do not establish a supported Python SDK.
`RuntimeFailure`, `RuntimeArgumentParser`, `RuntimeEvidenceStore`, `RuntimePath`,
`ReadOwnedInspect`, `CheckBases`, `SourceFact`, `ApplySourceFact` and
`ReferenceProposal`, `RuntimeProfile`, `RequireRuntimeAnchor` and
`RuntimeEvidenceStore.CheckReference`, `.Manifest` and `.Get` keep that same
implementation status. `PreflightKnownRuntimeReferences` is also Internal.
The profile lookup is closed; it is not an extension or
native discovery interface.

Import requires an existing workspace/model, explicit profile anchor, existing
local scope, run reference and exact caller-selected model/workspace revisions.
New-file mode requires explicit `ArtifactReadConsent` actor and record references.
Docker requires `--host` naming an existing literal HOST. Kubernetes requires
`--cluster` naming an existing ASSET with `asset_type=kubernetes-cluster`, bounded
literal `cluster_id` and matching `kubernetes-cluster:<cluster_id>` identity.
No anchor or context is created or inferred; cross-profile flags fail before
acquisition. Current anchor validation precedes any raw read.

Retained mode verifies the exact original selected-profile `application/json`
manifest and bytes without a new external-file read, consent or provider-version
override. Original source/version/time/scope attribution and previously selected
profile/anchor/run context remain unchanged; a never-applied record receives its explicit
first interpretation context.

`RuntimeEvidenceStore.Manifest` verifies original identity, selected role/media/
size, fixed source ID/version and absence of execution attribution without a blob
read. The caller binds original workspace/scope before existing retained-evidence
verification; owning Get still verifies canonical identity and complete bytes.
Docker keeps role `docker-inspect`, source `inventory.docker-inspect` and version
`owned-docker-container-inspect-v1`. Kubernetes keeps role `kubernetes-list`, source
`inventory.kubernetes-list` and version `owned-kubernetes-list-v1`.

`PreflightKnownRuntimeReferences` runs in both source modes before generic
workspace/report evidence verification. It scans workspace manifest IDs,
custody IDs left after a confirmed model save and lost workspace acknowledgement,
and retained workspace/model raw references. Metadata-only preflight binds
every custody-declared original ID to its old profile before role classification.
A different role cannot reclassify that original as unrelated evidence.
The unchanged `SourceFact` validator checks its original source
hash/version, scope/time/provider, run, read descriptions and existing anchor.
Legacy null read descriptions remain valid; older originals keep their own
scope/provider context independently of the current selection.

`RuntimeEvidenceStore.CheckReference` checks exact profile role, JSON media,
the one-MiB ceiling, canonical locator/digest and actual singly linked physical
size before raw access. All aliases sharing a known original's digest or locator
must match its canonical reference, including role/media/size/hash. Unrelated
larger non-runtime originals retain their existing owner's limits. Budget
preflight performs no custody adoption, scope mutation or execution authorization.

Original file acquisition admits one physical singly linked regular file,
non-following parent checks, the existing one-MiB byte ceiling plus one overflow
byte and actual local observation times. Full path identity stays stable
before/after reading, and full handle identity stays stable opened/finished.
The existing artifact-read cross-view comparison permits Windows API ctime
differences only across path/handle views. Same-view ctime and each view's single
link remain required. Original bytes and their complete SHA-256 are retained;
optional provider version is caller-declared and omission remains unknown.

One inert `runtime-import-source` observation on the existing HOST or cluster ASSET binds the
exact original manifest identity, content hash and offline provenance. File mode
retains explicit non-secret read descriptions; externally acquired original
records leave them unknown. Same-byte acquisitions remain distinct manifests.
The selected unchanged SDK and source fact compose one in-memory model
revision, followed by one model CAS and separate workspace CAS reference
retention. Exact retained replay is a byte-preserving owner no-op after relocation.
Core/model/SDK schemas and existing execution or policy grants are unchanged.
Accepted Docker custody retains exactly the original `profile`, `evidence_id`,
`source_sha256`, `source_version`, `read_actor_reference` and
`read_consent_reference` attribute keys, HOST subject and original provenance.
Its manifest replay requires no migration or new read authority.

Schema-one terminal summaries separate `acquisition_commit`, `model_commit` and
`workspace_commit`: `not-attempted`, `confirmed`, `not-committed` or `unknown`.
Storage failures after replacement can leave committed bytes with unknown
acknowledgement. A confirmed model save followed by failed workspace retention
remains a failed partial result without rollback or cross-store atomicity claims.
Success returns `0`, invalid setup/read consent `2`, integrity/conflict/busy/save
failure `4`, and interruption `130`. Static help reads no local state.

Raw original bytes are not redacted. Caller-selected owned source must be safe
to retain; filenames, rejected values, environment, labels, commands, health
output, annotations, Secret references, User/Group names and other unconsumed
provider fields are excluded from normalized metadata
and outcomes. Shell local/native history and replay retain only the protected
runtime namespace. Existing image facts and operator triage survive refresh;
missing facts and unassessed reachability remain UNKNOWN. Import connects to no
daemon or cluster API, creates no HOST/cluster by default and grants no native execution,
physical access, exploitability or network authority. Live/physical runtime
acceptance and broader workload profiles remain separate work.
Kubernetes resource/container declarations, nominal RBAC and configured
Ingress/Service/selector/NetworkPolicy associations describe the explicit export.
Effective permissions, aggregation, CNI enforcement and CRI image digest domains
remain unknown. Unsupported kinds and incomplete exports fail normalization;
legitimately acquired unredacted original bytes can remain with confirmed custody
and no saved graph. Tasks #151/#152 remain partial for live/effective/physical acceptance.

See [Owned runtime import](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/RUNTIME_IMPORT.md)
and [ADR 0078](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/adr/0078-owned-offline-runtime-import.md).
The Kubernetes profile is defined by
[ADR 0079](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/adr/0079-owned-offline-kubernetes-runtime-import.md).

::: fuzzy1337.runtime_commands
