# ADR 0074: Owned Kubernetes List inventory

Status: Accepted for the experimental offline input profile

## Context

Tasks #151 and #152 need attributable Kubernetes inventory, nominal RBAC and
configured relationships. A supplied export cannot establish completeness,
effective authorization, CNI enforcement, running container image identity or
physical reachability. Kubernetes objects can contain credentials and arbitrary
private annotations, labels, commands and environment values.

## Decision

Add one explicit `ApplyVerifiedKubernetesList` library interface for immutable
`kubernetes-list` / `application/json` evidence in the current workspace. Require
source `inventory.kubernetes-list`, source version `owned-kubernetes-list-v1` and
exact scope, provider version, observation time and original reference matches.
Offline attribution has no invented invocation or execution result. Revalidate
exact runtime contract types and reconstruct frozen contracts before owner reads.
The caller declares an existing ASSET anchor with `asset_type=kubernetes-cluster`,
a bounded literal `cluster_id` and identity key `kubernetes-cluster:<cluster_id>`.

Accept only a nonempty bounded `v1` / `List` document. Require every exported
resource to have a unique UID, kind/name/namespace coordinate and supported API
version. Unsupported kinds, including Secret and ConfigMap, fail before resource
normalization. Reuse existing ASSET and SERVICE types, canonical observations,
Findings and CONTAINS / RELATED_TO associations. Resource identities include the
declared cluster reference, API version, kind and UID. Never synthesize missing
resources or interpret an export as a complete live cluster inventory.

The supported kinds are Namespace, Pod, Service, ServiceAccount; apps/v1
Deployment, StatefulSet, DaemonSet and ReplicaSet; batch/v1 Job and CronJob;
networking.k8s.io/v1 Ingress and NetworkPolicy; and rbac.authorization.k8s.io/v1
Role, ClusterRole, RoleBinding and ClusterRoleBinding. Normalize selected container
image declarations and explicit security booleans, service ports, nominal RBAC
rules and ServiceAccount references. Labels and selector requirements are used
only transiently to compute same-export pod matches; no label value is projected.
Owner references require exported UID/kind/name/namespace agreement. Ingress
service backends and policy-selected pods describe configuration only.

Keep missing values unknown. Do not infer a default ServiceAccount, effective
permissions, aggregate ClusterRole semantics, NetworkPolicy enforcement or CRI
image digest domains. User/Group subject names, credentials, arbitrary labels,
annotations, environment, commands, Secret references and imageID status values
are not projected. Direct configured privileged/host-namespace and RBAC wildcard
Findings are OPEN advisories and preserve existing operator triage on refresh.

Validate the complete source and batch before one in-memory application. Existing
workspace/evidence/model owners remain authoritative; the caller performs CAS
persistence. Explicit RELATED_TO selection by ProjectReachability remains UNKNOWN
without separately admissible original proof. The importer performs no API call,
subprocess, kubectl action, policy grant, remediation or schema transition.

## Consequences

Original bytes and owning manifests survive import, model save/reopen and workspace
relocation. Replay is deterministic and a no-op. Strict byte, node, depth, string,
resource, collection and relationship ceilings reject excess rather than producing
partial success. Forged contracts, foreign workspaces, incomplete paginated Lists,
contradictory identities and unsupported selected structures fail closed.

Both tasks remain partial: live discovery, full privilege validation, arbitrary
resource/API support and physical network/security acceptance need separate work.

Semantics are grounded in the primary Kubernetes references for
[RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/),
[labels and selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/),
[Services](https://kubernetes.io/docs/concepts/services-networking/service/),
[NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
and [owners](https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/).
