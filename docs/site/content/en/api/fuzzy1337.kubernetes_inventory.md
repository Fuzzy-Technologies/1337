# fuzzy1337.kubernetes_inventory

This Experimental offline input profile imports one caller-owned Kubernetes
`v1`/`List` JSON evidence record into the existing Security Object Model. It
performs no live discovery, cluster API call, kubectl execution or policy update.

`KubernetesInventoryLimits` and `ApplyVerifiedKubernetesList` are the supported
surface. All other helpers remain Internal. The importer requires an existing
declared cluster ASSET, the current persisted model basis, an immutable owning
`kubernetes-list`/`application/json` record and exact source/workspace/scope/version/
time/reference attribution. Exact typed inputs, frozen contracts and fixed
byte/resource/collection ceilings are revalidated before owning reads. Selected
source shapes and the current model basis are validated before atomic application.
The caller owns canonical model CAS persistence.

Supported namespaces, workloads, Pods, container declarations, Services, Ingress,
ServiceAccounts, nominal RBAC and NetworkPolicy metadata reuse existing canonical
types. Resource identities include the declared cluster and literal exported UID.
Same-export selector and owner-reference associations retain their configured
meaning; missing references do not create resources. Labels are used transiently
for selector matching and never projected. Arbitrary labels, annotations,
environment, commands, credentials, User/Group names and CRI imageIDs remain
outside normalized metadata. Unsupported item kinds, including Secret, are
refused before resource normalization. Original evidence remains exact and is
not redacted; callers must supply non-sensitive owned exports.

Direct OPEN advisory findings describe configured conditions and preserve operator
triage on refresh. Effective permissions, ClusterRole aggregation, CNI enforcement
and image digest domains remain unknown. Relations grant no authorization or
physical reachability; existing reachability projections remain UNKNOWN without
separate admitted proof. One in-memory transition supports exact no-op replay and
workspace relocation without a model schema change. Live discovery and effective
privilege validation remain separate work.

See [Owned Kubernetes inventory](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/KUBERNETES_INVENTORY.md)
and [ADR 0074](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/adr/0074-owned-kubernetes-list-inventory.md).

::: fuzzy1337.kubernetes_inventory
