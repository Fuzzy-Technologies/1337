# ADR 0079: Owned offline Kubernetes runtime import

- Status: Accepted for the bounded offline product import
- Date: 2026-10-14
- Related work: #151, #152, ADR 0074, ADR 0078

## Context

The existing verified Kubernetes List SDK imports bounded original export evidence
and descriptive configured associations. The owned runtime command already
composes explicit file acquisition, original manifest custody and independent
model/workspace CAS owners. A second closed profile can reuse those boundaries
without introducing cluster discovery, effective permission claims or a new store.

## Decision

Add Experimental version-one `runtime import kubernetes-list` to the existing
Internal runtime handler, specified in [Runtime import](../RUNTIME_IMPORT.md).
Require an existing declared cluster ASSET, local scope, run reference and exact
model/workspace revision selections. The cluster must have
`asset_type=kubernetes-cluster`, a bounded literal `cluster_id` and matching
`kubernetes-cluster:<cluster_id>` identity. Validate that current anchor before
any raw source or retained evidence read. Create no default cluster, context or HOST.

Keep only the closed Docker inspect and Kubernetes List profiles. Source role,
source ID/version and original byte ceiling follow the explicitly parsed profile.
Selected retained manifests are identity/profile preflighted without blob reading;
their workspace/scope context is checked before existing workspace evidence
verification. The owning Get still verifies canonical manifest identity and exact
raw bytes. The Docker profile retains its original role, source identity, source
fact and acknowledgement meanings.

New-file mode requires explicit non-secret artifact read-consent descriptions.
Reuse singly linked physical-file guards, full same-view path/handle identities,
the existing Windows cross-view ctime allowance, bounded reading and actual local
observation times. Original bytes are retained unchanged with role `kubernetes-list`,
media `application/json`, source `inventory.kubernetes-list` and source version
`owned-kubernetes-list-v1`. Optional provider version is caller-declared; omission
remains unknown. Explicit raw exports are not redacted, so callers must provide
non-sensitive owned input. An unsupported export may remain legitimately acquired
while SDK normalization refuses it without a saved graph.

Apply unchanged `ApplyVerifiedKubernetesList` with its fixed byte/resource/container/
collection/relationship and decoder budgets. Fold one original-manifest-bound
`runtime-import-source` observation on the selected cluster into that same one
in-memory revision. Preserve original profile/cluster/run/source/read descriptions
on replay; same-byte acquisitions remain distinct manifest identities. Original
custody descriptions provide no current execution or file-read grant.

Reuse current-basis checks, one model CAS, subsequent workspace reference CAS and
final observed snapshot verification. Report acquisition, model and workspace
acknowledgements separately, including unknown save acknowledgements and partial
commits. Do not roll back another owner, remove its writer lock or claim one atomic
cross-store transaction. Retained replay requires no current external file and
preserves exact owner bytes after relocation.

## Consequences

- The installed console exercises public workspace/scope setup, explicit SDK
  cluster seeding, original acquisition, unchanged normalization, durable owners,
  refreshed triage, portable replay and existing JSON/SARIF consumers.
- The handwritten fixture keeps 25 objects, 46 relations and three configured
  findings, with three true positives, zero false positives/misses and three
  explicit negative conditions. Product custody adds one inert source observation.
- Nominal RBAC and configured selectors remain descriptive. Effective permission,
  CNI enforcement, CRI image digest domains and unassessed reachability remain UNKNOWN.
- No Core/model/SDK schema, score, policy grant, native executor, cluster API,
  kubectl dependency or daemon behavior changes. Tasks #151 and #152 stay open
  for their remaining live, effective-authorization and physical acceptance.
