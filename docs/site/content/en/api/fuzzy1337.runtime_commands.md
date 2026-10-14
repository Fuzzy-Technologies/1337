# fuzzy1337.runtime_commands

The installed CLI and interactive shell expose Experimental contract-version-one
`runtime import docker-inspect`. This module is its Internal implementation:
all classes, methods, functions and helpers, including `RuntimeParser` and
`RunRuntimeCommands`, are Internal and do not establish a supported Python SDK.
`RuntimeFailure`, `RuntimeArgumentParser`, `RuntimeEvidenceStore`, `RuntimePath`,
`ReadOwnedInspect`, `CheckBases`, `SourceFact`, `ApplySourceFact` and
`ReferenceProposal` keep that same implementation status.

Import requires an existing workspace/model, explicit literal HOST, existing
local scope, run reference and exact caller-selected model/workspace revisions.
New-file mode requires explicit `ArtifactReadConsent` actor and record references.
Retained mode verifies the exact original `docker-inspect`/`application/json`
manifest and bytes without a new external-file read, consent or provider-version
override. Original source/version/time/scope attribution and previously selected
HOST/run context remain unchanged; a never-applied record receives its explicit
first interpretation context.

Original file acquisition admits one physical singly linked regular file,
non-following parent checks, the existing one-MiB byte ceiling plus one overflow
byte and actual local observation times. Full path identity stays stable
before/after reading, and full handle identity stays stable opened/finished.
The existing artifact-read cross-view comparison permits Windows API ctime
differences only across path/handle views. Same-view ctime and each view's single
link remain required. Original bytes and their complete SHA-256 are retained;
optional provider version is caller-declared and omission remains unknown.

One inert `runtime-import-source` observation on the existing HOST binds the
exact original manifest identity, content hash and offline provenance. File mode
retains explicit non-secret read descriptions; externally acquired original
records leave them unknown. Same-byte acquisitions remain distinct manifests.
The existing Docker inspect SDK and source fact compose one in-memory model
revision, followed by one model CAS and separate workspace CAS reference
retention. Exact retained replay is a byte-preserving owner no-op after relocation.
Core/model/SDK schemas and existing execution or policy grants are unchanged.

Schema-one terminal summaries separate `acquisition_commit`, `model_commit` and
`workspace_commit`: `not-attempted`, `confirmed`, `not-committed` or `unknown`.
Storage failures after replacement can leave committed bytes with unknown
acknowledgement. A confirmed model save followed by failed workspace retention
remains a failed partial result without rollback or cross-store atomicity claims.
Success returns `0`, invalid setup/read consent `2`, integrity/conflict/busy/save
failure `4`, and interruption `130`. Static help reads no local state.

Raw original bytes are not redacted. Caller-selected owned source must be safe
to retain; filenames, rejected values, environment, labels, commands, health
output and other unconsumed Docker fields are excluded from normalized metadata
and outcomes. Shell local/native history and replay retain only the protected
runtime namespace. Existing image facts and operator triage survive refresh;
missing facts and unassessed reachability remain UNKNOWN. Import connects to no
daemon or socket, creates no HOST by default and grants no native execution,
physical access, exploitability or network authority. Live/physical runtime
acceptance and broader workload profiles remain separate work.

See [Owned runtime import](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/RUNTIME_IMPORT.md)
and [ADR 0078](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/adr/0078-owned-offline-runtime-import.md).

::: fuzzy1337.runtime_commands
