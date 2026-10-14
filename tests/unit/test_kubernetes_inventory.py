# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic Kubernetes input, quota, privacy, attribution and configured-fact boundaries."""

from __future__ import annotations

import stat
from dataclasses import replace
from traceback import format_exception

import pytest

from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.evidence import EvidenceError, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.findings import Findings
from fuzzy1337.kubernetes_inventory import (
    ApplyVerifiedKubernetesList,
    BoundedListStore,
    Decode,
    KubernetesInventoryLimits,
)
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelProvenance
from tests.kubernetes_helpers import (
    AcquireKubernetes,
    KubernetesPayload,
    KubernetesResource,
    OwnedKubernetesContext,
)


@pytest.fixture
def context(tmp_path):
    """Provide one isolated actual workspace/evidence/model basis for each boundary probe."""

    return OwnedKubernetesContext(tmp_path / "workspace")


def ApplyKubernetes(context, payload=None, *, record=None, provenance=None, **options):
    """Exercise the production importer against independently acquired original evidence.

    Args:
        context: Actual owned test stores and declared cluster.
        payload: Independent raw/source mutation or original handwritten document.
        record: Optional independently substituted immutable manifest.
        provenance: Optional independently substituted model attribution.
        options: Explicit importer option substitutions.

    Returns:
        Actual validated transition and delta.
    """

    if record is None:
        record, original = AcquireKubernetes(context, payload)
        provenance = original if provenance is None else provenance

    fields = {"state": context[1], "record": record, "provenance": provenance,
              "cluster_reference": context[2].Reference(), "workspace_root": context[0]}
    fields.update(options)

    return ApplyVerifiedKubernetesList(**fields)


def SetKubernetesField(payload, path, value):
    """Mutate one explicit source fixture path without invoking production normalizers.

    Args:
        payload: Independently handwritten source fixture.
        path: Actual object/array path with string or integer components.
        value: Exact negative source substitution.
    """

    target = payload

    for key in path[:-1]:
        target = target[key]

    target[path[-1]] = value


@pytest.mark.parametrize(("field", "value"), [
    ("max_bytes", 0), ("max_bytes", 1048577), ("max_bytes", True),
    ("max_resources", 0), ("max_resources", 129), ("max_containers", 17),
    ("max_entries", 33), ("max_relations", 2049), ("max_relations", 1.0),
])
def test_KubernetesLimitConstructorRejectsRelaxedOrNonintegerBudgets(field, value):
    """The caller cannot relax fixed quotas or substitute booleans/fractions."""

    with pytest.raises(ValueError):
        KubernetesInventoryLimits(**{field: value})


@pytest.mark.parametrize("raw", [b"", b"[", b"\xff", b"[]", b"{}", b"null",
    b'{"apiVersion":"v1","kind":"List","items":[]}',
    b'{"apiVersion":"v1","kind":"List","kind":"List","items":[]}',
    b'{"ignored":NaN}', b'{"ignored":Infinity}', b'{"ignored":1e9999}',
    b'{"ignored":"\\ud800"}', b'{"ignored":"line\\nvalue"}',
    CanonicalModelJson({"ignored": "x" * 4097}), b"[" * 1100 + b"]" * 1100,
    CanonicalModelJson([[] for _ in range(20001)]),
    b"[" * 25 + b"0" + b"]" * 25,
], ids=["empty", "truncated", "utf8", "array", "object", "null", "no-items", "duplicate",
        "nan", "infinity", "overflow", "surrogate", "control", "text", "recursion",
        "nodes", "depth"])
def test_KubernetesBoundedOriginalJsonDecoderRefusesMalformedAndExcessiveInput(raw):
    """Complete strict UTF-8 JSON plus depth/node/string budgets precede resource interpretation."""

    with pytest.raises(ValueError):
        Decode(raw, KubernetesInventoryLimits())


@pytest.mark.parametrize(("path", "value"), [
    (("apiVersion",), "v2"), (("kind",), "PodList"), (("items",), {}),
    (("metadata", "continue"), "next-page"), (("metadata", "remainingItemCount"), False),
    (("metadata", "remainingItemCount"), 1), (("items", 0, "metadata", "uid"), "short"),
    (("items", 0, "metadata", "name"), "bad_namespace"),
    (("items", 0, "metadata", "namespace"), "blue"),
    (("items", 2, "metadata", "namespace"), None),
    (("items", 2, "metadata", "name"), "../unsafe"),
    (("items", 4, "apiVersion"), "apps/v1beta1"),
    (("items", 4, "spec", "template", "spec", "hostNetwork"), 1),
    (("items", 4, "spec", "template", "spec", "containers"), {}),
    (("items", 4, "spec", "template", "spec", "containers", 0, "name"), "Main"),
    (("items", 4, "spec", "template", "spec", "containers", 0, "image"), "https://private.invalid"),
    (("items", 4, "spec", "template", "spec", "containers", 0, "image"), "user:private@host/image"),
    (("items", 4, "spec", "selector"), {"unsupported": {}}),
    (("items", 4, "spec", "selector", "matchLabels"), {"bad/key/shape": "value"}),
    (("items", 4, "spec", "selector", "matchLabels"), {"bad_prefix/name": "value"}),
    (("items", 4, "spec", "selector", "matchLabels"), {"app": "bad/value"}),
    (("items", 4, "spec", "selector", "matchExpressions", 0, "operator"), "Equals"),
    (("items", 4, "spec", "selector", "matchExpressions", 0, "operator"), []),
    (("items", 4, "spec", "selector", "matchExpressions", 0, "values"), []),
    (("items", 4, "spec", "selector", "matchExpressions", 0, "values"), ["batch", "batch"]),
    (("items", 5, "metadata", "ownerReferences", 0, "uid"), "bad"),
    (("items", 5, "metadata", "ownerReferences", 0, "uid"),
        "00000000-0000-0000-0000-000000000003"),
    (("items", 9, "spec", "type"), []), (("items", 9, "spec", "type"), "Unknown"),
    (("items", 9, "spec", "clusterIP"), "private.invalid"),
    (("items", 9, "spec", "clusterIP"), "fe80::1%eth0"),
    (("items", 9, "spec", "ports", 0, "port"), False),
    (("items", 9, "spec", "ports", 0, "targetPort"), True),
    (("items", 9, "spec", "ports", 0, "protocol"), "QUIC"),
    (("items", 9, "spec", "ports", 0, "protocol"), []),
    (("items", 11, "rules", 0, "verbs"), []),
    (("items", 11, "rules", 0, "verbs"), ["get", "get"]),
    (("items", 11, "rules", 0, "verbs"), ["Invalid"]),
    (("items", 11, "rules", 0, "resources"), ["pods//log"]),
    (("items", 11, "rules", 0, "apiGroups"), ["invalid/group"]),
    (("items", 14, "roleRef", "apiGroup"), "wrong"),
    (("items", 14, "roleRef", "kind"), []),
    (("items", 15, "roleRef", "kind"), "Role"),
    (("items", 14, "subjects", 0, "kind"), "Secret"),
    (("items", 14, "subjects", 0, "kind"), []),
    (("items", 14, "subjects", 0, "apiGroup"), "rbac.authorization.k8s.io"),
    (("items", 14, "subjects", 2, "apiGroup"), "wrong"),
    (("items", 14, "subjects", 2, "namespace"), "blue"),
    (("items", 16, "spec", "defaultBackend"), {"resource": {"kind": "Storage"}}),
    (("items", 16, "spec", "defaultBackend", "service", "port"), {}),
    (("items", 16, "spec", "defaultBackend", "service", "port"), {"number": 80, "name": "web"}),
    (("items", 17, "spec", "policyTypes"), ["Both"]),
], ids=lambda value: str(value[-1])[:20] if isinstance(value, tuple) else type(value).__name__)
def test_KubernetesSelectedMalformedSourceFailsWithoutPersistedMutation(context, path, value):
    """Malformed selected facts never reach a partial saved graph or overwrite earlier facts."""

    payload = KubernetesPayload()
    SetKubernetesField(payload, path, value)

    with pytest.raises(ValueError):
        ApplyKubernetes(context, payload)

    assert LocalModelStore(context[0]).Open() == context[1], "Invalid source changed saved state"


@pytest.mark.parametrize("kind", ["Secret", "ConfigMap", "Node", "EndpointSlice", [], None])
def test_KubernetesUnsupportedKindFailsBeforeAnyResourceNormalization(context, monkeypatch, kind):
    """Unsupported/Secret resources fail before normalization of any preceding valid items."""

    payload = KubernetesPayload()
    payload["items"][-1]["kind"] = kind

    def Refuse(*args, **kwargs):
        """Trip if unsupported-kind preflight reaches source normalization."""

        raise AssertionError("Unsupported resource reached normalization")

    monkeypatch.setattr("fuzzy1337.kubernetes_inventory.Resource", Refuse)

    with pytest.raises(ValueError):
        ApplyKubernetes(context, payload)


@pytest.mark.parametrize("collection", ["resource", "uid", "container", "owner", "subject",
                                        "rule", "port"])
def test_KubernetesDuplicateSourceIdentitiesAndCollectionsAreRefused(context, collection):
    """Repeated coordinates, UIDs or declaration identities cannot overwrite prior entries."""

    payload = KubernetesPayload()
    items = payload["items"]

    if collection == "resource":
        duplicate = {**items[0], "metadata": {**items[0]["metadata"],
            "uid": "00000000-0000-0000-0000-000000000099"}}
        items.append(duplicate)

    elif collection == "uid":
        items[1]["metadata"]["uid"] = items[0]["metadata"]["uid"]

    else:
        paths = {"container": (4, "spec", "template", "spec", "containers"),
            "owner": (5, "metadata", "ownerReferences"), "subject": (14, "subjects"),
            "rule": (11, "rules"), "port": (9, "spec", "ports")}
        target = items

        for key in paths[collection]:
            target = target[key]

        target.append(target[0])

    with pytest.raises(ValueError):
        ApplyKubernetes(context, payload)


@pytest.mark.parametrize("limits", [KubernetesInventoryLimits(max_bytes=64),
    KubernetesInventoryLimits(max_resources=2), KubernetesInventoryLimits(max_entries=1),
    KubernetesInventoryLimits(max_relations=1)])
def test_KubernetesPositiveTighterCeilingsRefuseExcessRatherThanPartialSuccess(context, limits):
    """Caller-tightened quotas retain atomic failure semantics across actual owner reads."""

    with pytest.raises(ValueError):
        ApplyKubernetes(context, limits=limits)


@pytest.mark.parametrize("changes", [
    {"source_id": "foreign.source"}, {"source_version": "foreign-version"},
    {"workspace_id": "foreign"}, {"scope_reference": "scope:foreign"},
    {"invocation_sha256": "a" * 64},
    {"execution": AdapterExecution(ExecutionState.SUCCEEDED, 0, 1)},
])
def test_KubernetesOriginalSourceAttributionCannotBeForged(context, changes):
    """Matching content does not authorize a changed source/workspace/scope/execution join."""

    record, provenance = AcquireKubernetes(context, source_changes=changes)

    if "scope_reference" in changes:
        provenance = replace(provenance, scope_reference="scope:owned")

    with pytest.raises(ValueError):
        ApplyKubernetes(context, record=record, provenance=provenance)


@pytest.mark.parametrize("changes", [
    {"source_id": "foreign.source"}, {"scope_reference": "scope:foreign"},
    {"provider_version": "foreign"}, {"target_reference": "target:foreign"},
    {"observed_at": "2026-10-14T12:00:01Z"}, {"evidence_references": ()},
    {"execution": AdapterExecution(ExecutionState.SUCCEEDED, 0, 1)},
])
def test_KubernetesModelAttributionMustMatchExactOriginalRecord(context, changes):
    """Scope/source/time/version/target/reference joins remain exact for immutable raw bytes."""

    record, provenance = AcquireKubernetes(context)

    with pytest.raises(ValueError):
        ApplyKubernetes(context, record=record, provenance=replace(provenance, **changes))


@pytest.mark.parametrize(("role", "media_type"), [("stdout", "application/json"),
    ("kubernetes-list", "text/plain")])
def test_KubernetesExactOriginalEvidenceRoleAndMediaType(context, role, media_type):
    """An unrelated evidence role/media type cannot masquerade as the declared export profile."""

    record, provenance = AcquireKubernetes(context, role=role, media_type=media_type)

    with pytest.raises(ValueError):
        ApplyKubernetes(context, record=record, provenance=provenance)


def test_KubernetesManifestAndBlobRemainAuthoritative(context):
    """Invented acquisition, missing manifest and changed raw bytes fail through existing owners."""

    record, provenance = AcquireKubernetes(context)
    forged = EvidenceRecord(record.reference, replace(record.provenance,
        started_at="2026-10-14T11:59:59Z"))

    with pytest.raises(EvidenceError):
        ApplyKubernetes(context, record=forged, provenance=provenance)

    blob = context[0] / "evidence" / record.reference.locator
    blob.chmod(stat.S_IWRITE | stat.S_IREAD)
    blob.write_bytes(blob.read_bytes()[:-1])

    with pytest.raises(EvidenceError):
        ApplyKubernetes(context, record=record, provenance=provenance)

    manifest = context[0] / "evidence" / "records" / (record.evidence_id[7:] + ".json")
    manifest.unlink()

    with pytest.raises(EvidenceError):
        ApplyKubernetes(context, record=record, provenance=provenance)


@pytest.mark.parametrize("field", ["state", "record", "provenance", "limits"])
def test_KubernetesUntypedPublicInputsFailBeforeOwningReads(context, monkeypatch, field):
    """Public boundary does not trust untyped caller fields or perform storage reads for them."""

    record, provenance = AcquireKubernetes(context)

    def Refuse(*args, **kwargs):
        """Trip if invalid runtime types reach owning reads."""

        raise AssertionError("Invalid typed input reached owning reads")

    monkeypatch.setattr("fuzzy1337.kubernetes_inventory.LocalWorkspaceStore.Open", Refuse)
    options = {"state": context[1], "record": record, "provenance": provenance,
        "limits": KubernetesInventoryLimits(), "cluster_reference": context[2].Reference(),
        "workspace_root": context[0]}
    options[field] = None

    with pytest.raises(ValueError):
        ApplyVerifiedKubernetesList(**options)


def test_KubernetesFrozenMutationsAndSubclassOverridesFailBeforeOwningReads(context, monkeypatch):
    """Hostile subclasses and frozen mutations cannot bypass quota/provenance/model invariants."""

    class RelaxedLimits(KubernetesInventoryLimits):
        """Deliberately hostile subclass replacing the immutable quota validator."""

        def __post_init__(self):
            """Skip the canonical validator only for this boundary probe."""

            return None

    class RelaxedProvenance(ModelProvenance):
        """Deliberately hostile subclass bypassing canonical attribution validation."""

        def __post_init__(self):
            """Skip the canonical validator only for this boundary probe."""

            return None

    record, provenance = AcquireKubernetes(context)
    limits = KubernetesInventoryLimits()
    object.__setattr__(limits, "max_entries", 33)
    forged_provenance = replace(provenance)
    object.__setattr__(forged_provenance, "run_reference", "")
    forged_record = replace(record)
    object.__setattr__(forged_record, "evidence_id", "sha256:" + "a" * 64)
    forged_state = replace(context[1])
    object.__setattr__(forged_state, "revision", -1)

    def Refuse(*args, **kwargs):
        """Trip if frozen mutation or hostile subclass reaches owner reads."""

        raise AssertionError("Forged frozen contract reached owning reads")

    monkeypatch.setattr("fuzzy1337.kubernetes_inventory.LocalWorkspaceStore.Open", Refuse)
    variants = [{"limits": limits}, {"limits": RelaxedLimits(max_entries=33)},
        {"provenance": forged_provenance}, {"record": forged_record}, {"state": forged_state},
        {"provenance": RelaxedProvenance("inventory.kubernetes-list", "", provenance.observed_at,
            provenance.scope_reference, provenance.target_reference)}]

    for options in variants:
        fields = {"record": record, "provenance": provenance, **options}

        with pytest.raises(ValueError):
            ApplyKubernetes(context, **fields)


def test_KubernetesActualParsedOwnerReferenceIsBoundedBeforeRawRead(context, monkeypatch):
    """Actual owner role/media/size validation precedes unchanged storage integrity reads."""

    record, _ = AcquireKubernetes(context)

    def Refuse(*args, **kwargs):
        """Trip if an oversized actual manifest reaches the underlying owner read."""

        raise AssertionError("Oversized manifest reached raw owner reads")

    monkeypatch.setattr(LocalEvidenceStore, "Read", Refuse)

    with pytest.raises(ValueError):
        BoundedListStore(context[0] / "evidence", 1).Get(record.evidence_id)


def test_KubernetesUnselectedValuesAndRejectedTextNeverLeak(context):
    """Raw private source fields remain in owning evidence without projection or error rendering."""

    marker = "OWNED_PRIVATE_SOURCE_MARKER"
    payload = KubernetesPayload()
    pod = KubernetesResource(payload, "Pod", "web-one", "blue")
    pod["metadata"]["labels"]["private"] = marker
    pod["metadata"]["annotations"] = {"private": marker}
    pod["spec"]["containers"][0]["env"] = [{"name": "PRIVATE", "value": marker}]
    pod["spec"]["containers"][0]["command"] = [marker]
    pod["spec"]["imagePullSecrets"] = [{"name": marker}]
    pod["status"]["containerStatuses"][0]["imageID"] = marker
    state, _ = ApplyKubernetes(context, payload)
    assert marker not in repr(state), "Unselected private values entered normalized facts"
    pod["spec"]["containers"][0]["name"] = marker

    with pytest.raises(ValueError) as failure:
        ApplyKubernetes(context, payload)

    assert marker not in "".join(format_exception(failure.value)), (
        "Rejected source text leaked through exception rendering"
    )


@pytest.mark.parametrize(("selector", "expected"), [
    ({}, {"web-one", "web-batch", "unlabelled"}),
    ({"matchExpressions": [{"key": "tier", "operator": "NotIn", "values": ["batch"]}]},
        {"web-one", "unlabelled"}),
    ({"matchExpressions": [{"key": "app", "operator": "Exists"}]}, {"web-one", "web-batch"}),
    ({"matchExpressions": [{"key": "tier", "operator": "DoesNotExist"}]}, {"unlabelled"}),
    ({"matchExpressions": [{"key": "tier", "operator": "In", "values": ["frontend"]}]},
        {"web-one"}),
], ids=["empty-all-known", "notin-absent", "exists", "does-not-exist", "in"])
def test_KubernetesSelectorKnownAnswersUseAndAbsentKeyAndExactNamespace(
    context, selector, expected,
):
    """All supported LabelSelector operators obey a handwritten same-namespace candidate oracle."""

    payload = KubernetesPayload()
    policy = KubernetesResource(payload, "NetworkPolicy", "web", "blue")
    policy["spec"]["podSelector"] = selector
    state, _ = ApplyKubernetes(context, payload)
    resources = {item.Reference(): item for item in state.objects
                 if item.attributes.get("asset_type") == "kubernetes-resource"}
    selected = next(item for item in resources.values()
                    if item.attributes["resource_kind"] == "NetworkPolicy")
    names = {resources[edge.target_reference].attributes["name"] for edge in state.relations
             if edge.source_reference == selected.Reference()}
    assert names == expected, "Selector interpretation differs from its handwritten operator oracle"


def test_KubernetesAbsentLabelsAndServiceSelectorsStayUnknownOrUnselected(context):
    """Absent Pod labels are unknown; empty/missing Services never auto-select exported Pods."""

    payload = KubernetesPayload()
    KubernetesResource(payload, "Pod", "web-one", "blue")["metadata"].pop("labels")
    KubernetesResource(payload, "Service", "web", "blue")["spec"]["selector"] = {}
    KubernetesResource(payload, "NetworkPolicy", "web", "blue")["spec"]["podSelector"] = {}
    state, _ = ApplyKubernetes(context, payload)
    resources = {item.Reference(): item for item in state.objects
                 if item.attributes.get("asset_type") == "kubernetes-resource"}
    selected = [edge for edge in state.relations
                if edge.attributes["association"] == "configured-pod-selector-match"]
    policy = next(item for item in resources.values()
                  if item.attributes["resource_kind"] == "NetworkPolicy")
    assert {resources[edge.target_reference].attributes["name"] for edge in selected
            if edge.source_reference == policy.Reference()} == {"web-batch", "unlabelled"}, (
        "Missing labels were defaulted to known-empty selector candidates"
    )
    assert not any(resources[edge.source_reference].attributes["resource_kind"] == "Service"
                   for edge in selected), "Empty Service selector selected Pods"


@pytest.mark.parametrize(("kind", "version"), [("StatefulSet", "apps/v1"),
    ("DaemonSet", "apps/v1"), ("ReplicaSet", "apps/v1"), ("Job", "batch/v1"),
    ("CronJob", "batch/v1")])
def test_KubernetesSupportedWorkloadTemplatesRemainDeclarations(context, kind, version):
    """Selected workload variants reuse explicit templates without inventing runtime instances."""

    payload = KubernetesPayload()
    workload = KubernetesResource(payload, "Deployment", "web", "blue")
    workload["kind"] = kind
    workload["apiVersion"] = version
    pod = KubernetesResource(payload, "Pod", "web-one", "blue")
    pod["metadata"]["ownerReferences"] = []

    if kind == "CronJob":
        workload["spec"] = {"jobTemplate": {"spec": workload["spec"]}}

    state, _ = ApplyKubernetes(context, payload)
    source = next(item for item in state.objects if item.attributes.get("resource_kind") == kind)
    containers = [item for item in state.objects
                  if item.attributes.get("resource_reference") == source.Reference()]
    assert len(containers) == 1 and source.attributes["pod_spec_known"] is True, (
        "Explicit workload template did not retain its single configured container declaration"
    )
    pods = [item for item in state.objects if item.attributes.get("resource_kind") == "Pod"]
    assert len(pods) == 4, (
        "A workload template was promoted into a runtime Pod"
    )


def test_KubernetesContainerCategoriesExplicitFlagsAndOpaqueImagesRemainDescriptive(context):
    """Init/ephemeral declarations preserve unknown effective runtime and image semantics."""

    payload = KubernetesPayload()
    pod = KubernetesResource(payload, "Pod", "web-one", "blue")
    pod["spec"].update({"hostPID": True, "hostIPC": True,
        "initContainers": [{"name": "initialize", "securityContext": {"privileged": False}}],
        "ephemeralContainers": [{"name": "diagnose", "image": "owned/image:tag"}]})
    state, _ = ApplyKubernetes(context, payload)
    checks = {item.check_id for item in Findings(state)}
    assert {"kubernetes.configured.host-pid", "kubernetes.configured.host-ipc"} <= checks, (
        "Explicit host namespace settings lost their configured advisory checks"
    )
    declarations = [item for item in state.objects
                    if item.attributes.get("container_name") in {"initialize", "diagnose"}]
    categories = {item.attributes["container_category"] for item in declarations}
    assert categories == {"init", "ephemeral"}, (
        "Source container categories were conflated"
    )
    assert all(item.attributes["image_digest_kind"] is None and
               item.attributes["effective_privileges"] is None for item in declarations), (
        "Declared container acquired effective access or guessed image identity"
    )


@pytest.mark.parametrize(("urls", "expected"), [(["/healthz/*"], True), (["/healthz"], False)])
def test_KubernetesNominalNonresourceUrlWildcardKnownAnswers(context, urls, expected):
    """A suffix glob is a configured wildcard advisory; a literal URL has no wildcard finding."""

    payload = KubernetesPayload()
    role = KubernetesResource(payload, "ClusterRole", "pod-wildcard")
    role["rules"] = [{"nonResourceURLs": urls, "verbs": ["get"]}]
    state, _ = ApplyKubernetes(context, payload)
    role_object = next(item for item in state.objects
                       if item.attributes.get("name") == "pod-wildcard"
                       and item.attributes.get("resource_kind") == "ClusterRole")
    detected = any(item.check_id == "kubernetes.configured.rbac-wildcard" and
                   item.subject_reference == role_object.Reference() for item in Findings(state))
    assert detected is expected, "Nominal suffix-glob wildcard oracle changed"
    assert role_object.attributes["effective_permissions"] is None, "Wildcard became authority"


def test_KubernetesNominalMissingRbacReferencesAndSubjectDataNeverSynthesizeResources(context):
    """Unmatched roles and absent subject namespaces remain unresolved configuration facts."""

    payload = KubernetesPayload()
    binding = KubernetesResource(payload, "RoleBinding", "reader", "blue")
    binding["roleRef"].update({"kind": "ClusterRole", "name": "missing"})
    binding["subjects"] = [{"kind": "ServiceAccount", "name": "build"}]
    KubernetesResource(payload, "ClusterRoleBinding", "pod-wildcard").pop("subjects")
    state, _ = ApplyKubernetes(context, payload)
    resource = next(item for item in state.objects
                    if item.attributes.get("resource_kind") == "RoleBinding")
    assert resource.attributes["role_reference_resolved"] is False, "Missing role became resolved"
    assert not any(edge.source_reference == resource.Reference() for edge in state.relations), (
        "Missing role or ServiceAccount namespace created an invented resource association"
    )
    cluster_binding = next(item for item in state.objects
                           if item.attributes.get("resource_kind") == "ClusterRoleBinding")
    assert cluster_binding.attributes["subject_counts"] is None, "Absent subjects became defaults"


def test_KubernetesRoleBindingCanNominallyReferenceExportedClusterRole(context):
    """A namespaced binding retains a ClusterRole reference with unknown effective authority."""

    payload = KubernetesPayload()
    binding = KubernetesResource(payload, "RoleBinding", "reader", "blue")
    binding["roleRef"].update({"kind": "ClusterRole", "name": "pod-wildcard"})
    state, _ = ApplyKubernetes(context, payload)
    resource = next(item for item in state.objects
                    if item.attributes.get("resource_kind") == "RoleBinding")
    edge = next(item for item in state.relations if item.source_reference == resource.Reference()
                and item.attributes["association"] == "nominal-role-reference")
    assert edge.attributes["binding_namespace"] == "blue", "RoleBinding lost its namespace fact"
    assert edge.attributes["effective_permissions"] is None, "Nominal ClusterRole became a grant"


def test_KubernetesUnknownSpecsEmptyRulesAndUnresolvedBackendsPreserveUnknown(context):
    """Missing sections stay unknown and no backend/owner/default ServiceAccount is synthesized."""

    payload = KubernetesPayload()
    KubernetesResource(payload, "Deployment", "web", "blue")["spec"] = {}
    KubernetesResource(payload, "Role", "reader", "blue")["rules"] = None
    KubernetesResource(payload, "Ingress", "web", "blue")["spec"] = {
        "defaultBackend": {"service": {"name": "missing", "port": {"number": 80}}}}
    pod = KubernetesResource(payload, "Pod", "web-one", "blue")
    pod["metadata"]["ownerReferences"][0]["kind"] = "UnknownOwner"
    state, _ = ApplyKubernetes(context, payload)
    deployment = next(item for item in state.objects
                      if item.attributes.get("resource_kind") == "Deployment")
    role = next(item for item in state.objects if item.attributes.get("resource_kind") == "Role")
    ingress = next(item for item in state.objects
                   if item.attributes.get("resource_kind") == "Ingress")
    assert deployment.attributes["pod_spec_known"] is False, "Missing template became runtime facts"
    assert deployment.attributes["host_network"] is None, "Missing host flag became a safe default"
    assert role.attributes["nominal_rules"] is None, "Missing RBAC rules became effective denial"
    assert not any(item.source_reference == ingress.Reference() for item in state.relations), (
        "Missing backend Service was synthesized"
    )


@pytest.mark.parametrize("dependent", ["cross-namespace-pod", "cluster-role"])
def test_KubernetesExportedOwnerUidCannotBypassNamespaceOrClusterScope(context, dependent):
    """Known exported UIDs with forbidden scope cannot become valid owner relationships."""

    payload = KubernetesPayload()
    source = KubernetesResource(payload, "Pod", "web-red", "red") if (
        dependent == "cross-namespace-pod") else KubernetesResource(payload, "ClusterRole",
                                                                   "pod-wildcard")
    source["metadata"]["ownerReferences"] = [{"apiVersion": "apps/v1", "kind": "Deployment",
        "name": "web", "uid": "00000000-0000-0000-0000-000000000005"}]

    with pytest.raises(ValueError):
        ApplyKubernetes(context, payload)


def test_KubernetesModelBasisRaceFailsBeforeBatchApplication(context, monkeypatch):
    """The importer rechecks the actual persisted basis after interpretation and before applying."""

    record, provenance = AcquireKubernetes(context)
    owner_open = LocalModelStore.Open
    reads = []

    def Open(self):
        """Simulate an independent owner revision between the two required basis reads.

        Args:
            self: Actual canonical model owner.

        Returns:
            Actual basis, then an independently advanced canonical revision.
        """

        reads.append(self.root)
        state = owner_open(self)

        return state if len(reads) == 1 else replace(state, revision=state.revision + 1)

    def Refuse(*args, **kwargs):
        """Trip if a stale model basis reaches in-memory batch application."""

        raise AssertionError("Stale model basis reached batch application")

    monkeypatch.setattr(LocalModelStore, "Open", Open)
    monkeypatch.setattr("fuzzy1337.kubernetes_inventory.ApplyBatch", Refuse)

    with pytest.raises(ValueError):
        ApplyKubernetes(context, record=record, provenance=provenance)

    assert len(reads) == 2, "Current basis was not checked both before reads and before application"
