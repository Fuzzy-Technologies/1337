# Owned offline runtime import

[ADR 0078](adr/0078-owned-offline-runtime-import.md) defines a bounded product
command over the existing [Docker inspect SDK](DOCKER_INVENTORY.md). The Internal
`fuzzy1337.runtime_commands.RuntimeParser` and `RunRuntimeCommands` support explicit
`runtime import docker-inspect` and `runtime import kubernetes-list` profiles in the installed
`1337` console and interactive shell. `1337 runtime --help` describes the exact
selections without opening local state. The shell forwards only explicit
arguments and protects runtime arguments from local/native history and replay.
The Kubernetes profile is defined by
[ADR 0079](adr/0079-owned-offline-kubernetes-runtime-import.md) over the unchanged
[owned Kubernetes List SDK](KUBERNETES_INVENTORY.md).

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

## Explicit Kubernetes List selections

```text
1337 runtime import kubernetes-list WORKSPACE
  (--file FILE --owner ACTOR_REFERENCE --read-consent-reference CONSENT_REFERENCE
   | --evidence sha256:MANIFEST)
  --cluster OBJECT_REFERENCE --scope SCOPE_ID --run RUN_REFERENCE
  --expected-revision MODEL_REVISION
  --expected-workspace-revision WORKSPACE_REVISION
  [--provider-version DECLARED_VERSION]
```

Kubernetes selection requires an existing declared ASSET with
`asset_type=kubernetes-cluster`, a bounded literal `cluster_id` and matching
`kubernetes-cluster:<cluster_id>` identity. No cluster, context or HOST is created
or selected implicitly. `--cluster` is required for this profile, while `--host`
belongs only to Docker inspect. Validate the current anchor before any raw read.

The same explicit read consent, physical identity guards, actual observation
times and one-MiB ceiling apply. Retain original `kubernetes-list` /
`application/json` bytes with source `inventory.kubernetes-list` and source version
`owned-kubernetes-list-v1`. Selected retained manifests are identity/profile
preflighted without reading blobs, then checked against the owning workspace/scope
before existing retained-evidence verification. Retained mode supplies no new-file
consent or provider-version override and preserves original cluster/run context.

The unchanged SDK accepts only its bounded supported `v1` / `List` export profile.
Unsupported kinds, incomplete pagination, malformed or contradictory resources
fail normalization without a saved graph. Original bytes are **not redacted**:
callers must provide non-sensitive owned exports. A refused export can still have
confirmed original acquisition; the command does not pretend that raw retention
was rolled back. The command launches no kubectl/API operation, including
Secret/ConfigMap retrieval.

One original-manifest-bound `runtime-import-source` observation is retained on
the selected cluster ASSET. Resource/container declarations, nominal RBAC and
configured selector/Ingress/Service/NetworkPolicy associations keep SDK meanings.
Effective permissions, enforcement, image digest domains and unassessed physical
reachability remain UNKNOWN. Prior facts and operator triage survive refresh;
same-byte acquisitions remain distinct original manifests.

## Saves and terminal outcomes

Both source modes preflight every already known Docker/Kubernetes original
before generic workspace/report verification can read evidence. The scan covers
workspace manifest IDs, model custody IDs even after a lost workspace
acknowledgement, and retained workspace/model raw references. It checks the
closed profile, original manifest identity/context, one-MiB ceiling, actual blob
size/physical ownership and compatible same-digest or same-locator aliases before
raw access.
Every manifest named by original runtime custody must match that custody's old
profile, source hash/version, attribution, read descriptions and anchor before
role classification. A different role cannot make a custody-owned original
unrelated evidence. The unchanged validator also accepts legacy null read fields.
Each older original retains its own scope/provider attribution; budget checks
neither adopt missing custody nor grant execution authority. Unrelated evidence
keeps its existing owner's limits. Existing Docker custody fields and both SDK
profiles remain unchanged.

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

The Kubernetes console workflow preserves its independent 25-object, 46-relation,
three-finding oracle and one source custody observation: three true positives,
zero false positives/misses and three explicit negatives. It exercises original
file acquisition, cluster/scope setup, model/workspace CAS, refreshed triage,
relocation, source-deleted retained replay, public reopen and JSON/SARIF consumers.
Refusal and tripwire tests cover profile/context preflight before raw reads,
unsupported exports, stale bases, physical links, owner locks and acknowledgement
loss before/after actual replacement. Tasks #151/#152 remain open for live
discovery, effective authorization, image/workload correlation and independently
admitted physical reachability.
