# ADR 0078: Owned offline runtime import

- Status: Accepted for the bounded offline product import
- Date: 2026-10-14
- Related work: #149, #148, ADR 0070

## Context

The verified Docker inspect SDK already imports bounded original evidence into
the canonical model. Its callers currently own acquisition, model saving and
workspace reference retention. A product command can compose those existing
boundaries without inventing daemon discovery or converting historical source
attribution into current execution authority.

## Decision

Add the Internal `fuzzy1337.runtime_commands` handler and register its sole profile in the
installed console, command registry and interactive shell. Its profile is
`runtime import docker-inspect`, specified in [Runtime import](../RUNTIME_IMPORT.md).
Require an existing workspace/model, explicit literal HOST, existing local scope,
run reference and exact expected model/workspace revisions. Preserve the SDK,
Core schema, image identity, native authorization and finding triage contracts.

New-file import requires explicit `ArtifactReadConsent` actor and record
references, checks the selected physical regular file without following observed
links, and reads at most the existing one-MiB ceiling plus one overflow byte.
Actual local observation times surround that read. Require full same-view
path/handle identity checks before/after reading and a single
physical link in every observation. Across path/handle APIs, use the existing
artifact-read identity comparison, including Windows' cross-view ctime exception;
same-view ctime remains stable on every platform. Retain original bytes with
the SDK's fixed source ID/version; optional provider version is caller-declared,
never detected or defaulted to a known value. Selected filenames and unconsumed
Docker fields are not projected into command/model metadata.

Retained selection verifies the exact bounded original manifest and blob. Its
source/version/time/scope remain original acquisition facts. Previously
interpreted selections must preserve existing host/run provenance; a verified
never-applied record receives its explicit first interpretation context. Neither
selection launches Docker, probes a socket, resolves mount paths or creates an
execution receipt or policy grant.

Retain one inert `runtime-import-source` observation on the existing HOST with
the exact original manifest ID, content hash and original offline provenance.
File acquisition adds explicit bounded non-secret actor/consent descriptions;
externally acquired retained records leave those descriptions unknown. Original
source facts preserve these descriptions on replay without issuing read authority.
Fold this fact into the SDK's same one in-memory revision before a single model
save. Same-byte acquisitions retain their distinct original manifest identities.

Apply the unchanged SDK, CAS-save the model, then verify the same workspace
basis and saved model before CAS-retaining source, scope and object references.
Unchanged exact replay skips workspace saving. Existing scopes serve attribution;
import does not check or issue a historical scanner execution grant.

Report acquisition, model and workspace acknowledgements separately. A known
conflict/busy refusal is not committed. Storage/cleanup/interruption failures
during a save retain unknown acknowledgement, including when replacement may
already have happened. A confirmed model save followed by failed workspace
retention is a partial outcome, never success or rollback. These two owners do
not form an atomic cross-store transaction; final snapshot checks expose observed
intervening changes rather than claiming stronger isolation.

## Consequences

- Installed-console subprocess verification crosses public workspace/scope setup,
  explicit SDK HOST seeding, file import, durable owners, portable retained replay
  and report consumers. The handler itself remains Internal.
- Shell argument dispatch uses the same explicit handler and protects raw runtime
  arguments in local/native history and empty-line replay. Static help reads no state.
- Actual acceptance crosses raw acquisition, SDK application, both CAS owners,
  reopen/relocation/retained replay and existing JSON/SARIF report export.
- Tests preserve image correlation, operator triage and unassessed UNKNOWN
  reachability, and cover denied selections, malformed source, races and failed
  acknowledgement before/after committed storage.
- Task #149 remains partial: live daemon/socket acquisition, broader workload
  support, physical runtime acceptance and exploit validation remain open.
