# Owned Kubernetes inventory

`fuzzy1337.kubernetes_inventory` provides an Experimental offline library profile
for one explicitly supplied, caller-owned Kubernetes JSON export. It performs no
cluster discovery, API request, kubectl execution, policy update or native process
operation. Tasks #151 and #152 remain partial for live discovery and effective
privilege validation.

The caller supplies an existing persisted model snapshot and declared ASSET anchor
in the same workspace. The anchor has `asset_type=kubernetes-cluster`, a literal
bounded `cluster_id`, and identity key `kubernetes-cluster:<cluster_id>`. The
importer revalidates the current persisted basis before evidence reads and again
before applying the candidate. Model persistence remains caller-owned CAS.

## Original source profile

Supply immutable evidence with role `kubernetes-list`, media type
`application/json`, source `inventory.kubernetes-list` and source version
`owned-kubernetes-list-v1`. The source workspace, scope, optional provider version,
observation time and exact evidence reference must match `ModelProvenance`.
Offline provenance has no invocation digest or execution result.

The original document is a nonempty `apiVersion: v1`, `kind: List` JSON object.
Every item requires a unique lowercase UUID UID and unique kind/name/namespace
coordinate. A List with a nonempty continuation token or remaining items is
refused. JSON duplicate keys, non-finite numbers and malformed selected fields
fail closed. Unsupported item kinds fail before resource normalization.

| API version                    | Supported resource kinds                           |
| ------------------------------ | -------------------------------------------------- |
| `v1`                           | Namespace, Pod, Service, ServiceAccount            |
| `apps/v1`                      | Deployment, StatefulSet, DaemonSet, ReplicaSet     |
| `batch/v1`                     | Job, CronJob                                       |
| `networking.k8s.io/v1`         | Ingress, NetworkPolicy                             |
| `rbac.authorization.k8s.io/v1` | Role, ClusterRole, RoleBinding, ClusterRoleBinding |

Secret, ConfigMap, Node, EndpointSlice, custom resources, alternate List shapes
and other versions are outside this profile. No Secret value is normalized or
acquired by the importer. Original evidence is preserved exactly and is **not
redacted**: the caller must provide an owned, non-sensitive export. Unsupported
kind rejection cannot remove values from a record the caller already acquired.

## Selected facts and relationships

Resource identities include the cluster reference, supported API version, kind
and UID. Namespace/resource containment and owner references describe the supplied
export. Owner references require exact exported UID/kind/name/scope agreement;
missing owners remain unresolved and never create synthetic resources.

Pod and workload templates retain declared regular, init and ephemeral containers,
configured image references and explicit security booleans. Templates remain
declarations; they never become runtime Pods. Missing flags and ServiceAccount
names stay unknown. Image tags, manifest-like configuration and opaque CRI
`imageID` status values never become image config or manifest identities.

Services retain configured type, literal cluster IP and selected ports. Their
nonempty equality selector maps can match explicit labelled Pods in the same
export and namespace. Workload and NetworkPolicy LabelSelectors support
`matchLabels` plus ANDed `In`, `NotIn`, `Exists` and `DoesNotExist` requirements.
`NotIn` admits an absent key on known label data; missing label data stays unknown.
Empty Service selectors select no automatic backend. Label keys/values and
selector requirements are used transiently and are never projected.

RBAC objects retain supplied nominal rules, role references and exported
ServiceAccount subject associations. A RoleBinding can reference a ClusterRole
while retaining its namespace fact, and can name a ServiceAccount from another
namespace. Missing references remain unresolved. User/Group subject counts are
retained without copying their names. Aggregation, effective permissions and
authorization decisions remain unknown.

Ingress retains Service backend/port associations. NetworkPolicy retains selected
Pods, explicit policy types and ingress/egress rule counts. Resource backends,
policy peer evaluation, CNI enforcement, route execution and TLS secret material
are not interpreted. Configured associations use existing CONTAINS/RELATED_TO
relations. When the same canonical endpoints carry several descriptions, the
relation retains an `associations` collection with separate original observations.

Direct configured privileged-container, host-namespace and nominal RBAC wildcard
conditions yield OPEN advisory Findings. RBAC suffix globs are included. No
condition proves effective permission, isolation failure, exploitability or
physical exposure. Existing operator triage survives refreshed original evidence.
The existing reachability consumer keeps explicitly selected edges UNKNOWN until
separate admissible original proof supplies an assessment.

Arbitrary labels, annotations, environment, commands, Secret references, tokens,
User/Group names and CRI imageIDs remain outside normalized attributes and errors.
Earlier canonical facts remain attributed to their existing sources; this bounded
profile does not withdraw previous inventory or establish snapshot completeness.

## Applying an explicit owned record

The workspace and cluster must already exist. Acquisition is an explicit caller
action; the importer does not search for exports or create storage.

```python
from pathlib import Path

from fuzzy1337.kubernetes_inventory import ApplyVerifiedKubernetesList
from fuzzy1337.model import LocalModelStore

# record is the existing immutable kubernetes-list evidence manifest;
# provenance exactly joins its source/scope/time/version/reference to the cluster.
workspace_root = Path("owned-workspace")
model_store = LocalModelStore(workspace_root)
basis = model_store.Open()
proposed, delta = ApplyVerifiedKubernetesList(
    basis,
    record,
    provenance,
    cluster_reference=cluster_reference,
    workspace_root=workspace_root,
)
saved = model_store.Save(proposed, expected_revision=basis.revision)
```

This code is a library call pattern, not an executable acquisition recipe.
`KubernetesInventoryLimits` has fixed maxima of 1 MiB original bytes, 128 exported
resources, 16 total containers per Pod/template, 32 selected collection entries
and 2,048 canonical relationships. The decoder also caps depth at 24, nodes at
20,000 and original strings at 4,096 UTF-8 bytes. Callers can tighten these limits;
zero, booleans, larger limits, subclass overrides and forged frozen fields fail.
Excess or invalid input produces no partial saved graph. Existing model/evidence
owners enforce their additional canonical integrity and persistence limits.

Exact replay is a no-op and remains valid after workspace relocation. Original
bytes/manifests, source attribution and persisted findings remain unchanged by
import. The separate [owned runtime command](RUNTIME_IMPORT.md) now composes
explicit file or retained-manifest selection with this unchanged SDK, existing
declared cluster and independent CAS owners. The SDK adds no runtime dependency
or model schema version and performs no acquisition itself.

Design: [ADR 0074](adr/0074-owned-kubernetes-list-inventory.md).
