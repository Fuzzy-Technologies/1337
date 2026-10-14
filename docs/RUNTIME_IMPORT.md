# Owned offline runtime import

[ADR 0078](adr/0078-owned-offline-runtime-import.md) defines a bounded product
command over the existing [Docker inspect SDK](DOCKER_INVENTORY.md). The Internal
`fuzzy1337.runtime_commands.RuntimeParser` and `RunRuntimeCommands` support one
explicit `runtime import docker-inspect` profile, registered in the installed
`1337` console and interactive shell. `1337 runtime --help` describes the exact
selections without opening local state. The shell forwards only explicit
arguments and protects runtime arguments from local/native history and replay.

## Explicit selections

New-file grammar:

```text
1337 runtime import docker-inspect WORKSPACE --file FILE
  --owner ACTOR_REFERENCE --read-consent-reference CONSENT_REFERENCE
  --host OBJECT_REFERENCE --scope SCOPE_ID --run RUN_REFERENCE
  --expected-revision MODEL_REVISION
  --expected-workspace-revision WORKSPACE_REVISION
  [--provider-version DECLARED_VERSION]
```

Retained-source grammar:

```text
1337 runtime import docker-inspect WORKSPACE --evidence sha256:MANIFEST
  --host ORIGINAL_HOST_REFERENCE --scope ORIGINAL_SCOPE_ID --run ORIGINAL_RUN
  --expected-revision MODEL_REVISION
  --expected-workspace-revision WORKSPACE_REVISION
```

The existing canonical HOST must be an explicit literal IP object; no host is
created or discovered. Scope must exist in that workspace and is attribution,
without issuance or reuse of scanner execution authority. Both expected revisions
are exact caller selections. New-file mode requires the existing non-secret
`ArtifactReadConsent` actor/record contract. Retained mode supplies no new-file
read consent or provider-version override.

The file must be one regular singly linked physical file with non-following
parent checks. Its actual local observation times surround bounded reading;
path observations before/after and handle observations opened/finished must each
retain their full device/inode/size/mtime/ctime identity and single link. Path and
handle views use the existing artifact-read identity comparison; Windows may
differ in ctime across those APIs only, while each API's own ctime remains stable.
Observed file changes, resource excess or unsupported JSON fail. Original bytes
are retained unchanged with role `docker-inspect`, media `application/json`,
source `inventory.docker-inspect` and source version
`owned-docker-container-inspect-v1`. Provider version is an optional explicit
caller declaration; omission stays unknown. No daemon command or original
scanner execution is claimed. Environment, labels, commands, health output and
filenames are never projected into model attributes or command outcomes.

Retained mode verifies the exact immutable manifest and original bytes before
SDK interpretation. Source/version/time/scope remain manifest-owned. Previously
interpreted selections retain their original host/run context, allowing exact
portable replay. An original record not yet represented in the model can receive
its explicitly supplied first normalization context. Original source retention
grants no current artifact, daemon, policy or network permission.

One inert `runtime-import-source` observation on the existing HOST binds the
original manifest ID, content hash and exact offline provenance. File mode
retains explicit non-secret actor/read-consent references; an externally acquired
retained record leaves them unknown. Exact replay preserves original descriptions
without creating a read grant. Same-byte acquisitions remain distinct manifests.
This source fact is folded into the SDK's same one in-memory revision, followed
by one model save; it adds no receipt, job or competing store.

## Saves and terminal outcomes

The handler verifies owning model/workspace bases, applies the existing bounded
SDK in memory, saves through model CAS, then retains verified raw/manifest/scope/
object references through workspace CAS. Both owners are reopened for observed
snapshot changes. Exact replay is a no-op for model and workspace bytes.
Configured image/package identities, finding disposition and unknown facts retain
the SDK's meanings; configured associations do not prove reachability.

JSON terminal summaries use schema version `1` and separate `acquisition_commit`,
`model_commit` and `workspace_commit` values: `not-attempted`, `confirmed`,
`not-committed` or `unknown`. Summary fields contain immutable IDs, hashes,
counts/revisions and fixed diagnostic categories rather than raw source or
rejected argument values. Retained selection confirms existing acquisition
verification without claiming a new read of a selected external file.

Success returns `0`; invalid grammar/read-consent/configuration returns `2`;
integrity, normalization, conflict/busy or save failure returns `4`; interruption
returns `130`. Failed interpretation can leave legitimately acquired raw evidence.
A save error can occur after replacement: unknown acknowledgement is honest,
and the operator must reopen before retrying. A confirmed model commit followed
by failed workspace retention remains a failed partial result. The handler never
deletes evidence, removes someone else's writer lock or rolls back another
owner's state. Separate model/workspace CAS does not promise one atomic global
transaction.

## Functional proof and remaining scope

Tests exercise the actual installed console subprocess and public handler with
the handwritten owned Docker
fixture/oracle, source acquisition, SDK normalization, durable owner saves,
reopen/relocation/retained replay and existing JSON/SARIF export. The known-answer
configured-condition oracle remains six positives, zero false positives/misses
and three explicit negatives. Missing facts and selected unassessed reachability
remain UNKNOWN; prior image facts and operator triage survive refreshed evidence.
Failure tests cover input/path/consent/host/scope/source refusal, bounded original
reads, exact provenance, competing writers and acknowledgement loss before and
after real committed saves. Network/process tripwires enforce offline behavior.
The installed-console workflow creates workspace/scope through their public
commands, seeds an explicit synthetic literal HOST through the SDK, and exercises
new-file import, prior image facts, refreshed triage, relocation, exact retained
replay, authoritative reopen and JSON/SARIF export. Console refusal cases include
missing consent/source, stale model/workspace pins, physical links, malformed
input and existing owner locks. Registered dispatcher tests retain truthful
unknown acknowledgements before/after actual owner replacement and interruption.

This advances #149 without completing live daemon/socket discovery, native
runtime processes, physical runtime acceptance or broader workload profiles.
