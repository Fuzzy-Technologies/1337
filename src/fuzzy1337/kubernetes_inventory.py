# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental owned Kubernetes List facts without live discovery or effective access claims."""

from __future__ import annotations

import ipaddress
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.findings import Finding, FindingSeverity
from fuzzy1337.images import ApplyBatch
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelDelta,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Observation,
    Relation,
    RelationKind,
    RequireModelReference,
    SecurityObject,
)
from fuzzy1337.workspace import LocalWorkspaceStore

__all__ = ["KubernetesInventoryLimits", "ApplyVerifiedKubernetesList"]

_SOURCE_ID = "inventory.kubernetes-list"
_SOURCE_VERSION = "owned-kubernetes-list-v1"
_VERSIONS = {
    "Namespace": "v1", "Pod": "v1", "Service": "v1", "ServiceAccount": "v1",
    "Deployment": "apps/v1", "StatefulSet": "apps/v1", "DaemonSet": "apps/v1",
    "ReplicaSet": "apps/v1", "Job": "batch/v1", "CronJob": "batch/v1",
    "Ingress": "networking.k8s.io/v1", "NetworkPolicy": "networking.k8s.io/v1",
    "Role": "rbac.authorization.k8s.io/v1", "ClusterRole": "rbac.authorization.k8s.io/v1",
    "RoleBinding": "rbac.authorization.k8s.io/v1",
    "ClusterRoleBinding": "rbac.authorization.k8s.io/v1",
}
_CLUSTER_KINDS = {"Namespace", "ClusterRole", "ClusterRoleBinding"}
_WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
_UID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$")
_LABEL_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$")
_DNS = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def Integer(value: object, maximum: int) -> int:
    """Require an exact positive integer within one fixed inclusive ceiling.

    Args:
        value: Supplied quota or port, excluding boolean substitutions.
        maximum: Inclusive maximum.

    Returns:
        Validated positive integer.
    """

    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("Kubernetes inventory integer exceeds its positive bound")

    return value


@dataclass(frozen=True, slots=True)
class KubernetesInventoryLimits:
    """Bound original bytes, resources, containers, selected collections and associations."""

    max_bytes: int = 1024 * 1024
    max_resources: int = 128
    max_containers: int = 16
    max_entries: int = 32
    max_relations: int = 2048

    def __post_init__(self) -> None:
        """Reject relaxed or malformed ceilings even for explicitly caller-owned input."""

        for name, maximum in (("max_bytes", 1024 * 1024), ("max_resources", 128),
                              ("max_containers", 16), ("max_entries", 32),
                              ("max_relations", 2048)):
            Integer(getattr(self, name), maximum)


def Text(value: object, maximum: int = 4096, *, empty: bool = False) -> str:
    """Validate selected UTF-8 text without including rejected source values in errors.

    Args:
        value: Selected scalar source text, never environment or credential fields.
        maximum: Inclusive UTF-8 byte ceiling.
        empty: Whether an explicit empty string is meaningful in this field.

    Returns:
        Original single-line text.
    """

    if type(value) is not str or (not value and not empty) or any(
        ord(character) < 32 for character in value
    ):
        raise ValueError("Kubernetes inventory selected text must be bounded single-line text")

    try:
        size = len(value.encode("utf-8"))

    except UnicodeError:
        raise ValueError("Kubernetes inventory selected text must be valid UTF-8") from None

    if size > maximum:
        raise ValueError("Kubernetes inventory selected text exceeds its byte budget")

    return value


def Fields(value: object) -> dict[str, object]:
    """Require an actual decoded JSON object without coercing custom mappings.

    Args:
        value: Selected source object.

    Returns:
        String-keyed object.
    """

    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ValueError("Kubernetes inventory selected section requires an object")

    return cast(dict[str, object], value)


def OptionalFields(value: object) -> dict[str, object]:
    """Preserve absent/null nested fields as unknown lookup entries.

    Args:
        value: Selected object or unknown value.

    Returns:
        Original fields or an empty lookup object.
    """

    return {} if value is None else Fields(value)


def Items(value: object, maximum: int) -> list[object]:
    """Require a bounded actual JSON array rather than arbitrary iteration.

    Args:
        value: Selected collection.
        maximum: Inclusive collection ceiling.

    Returns:
        Original array.
    """

    if type(value) is not list or len(value) > maximum:
        raise ValueError("Kubernetes inventory selected collection exceeds its array budget")

    return value


def Name(value: object, *, namespace: bool = False) -> str:
    """Validate literal resource or namespace names without interpreting path-like text.

    Args:
        value: Explicit selected source name.
        namespace: Whether to require a DNS label instead of the bounded resource grammar.

    Returns:
        Exact literal name.
    """

    name = Text(value, 63 if namespace else 253)

    if not (_DNS if namespace else _NAME).fullmatch(name):
        raise ValueError("Kubernetes inventory name is outside its literal profile")

    return name


def OptionalBool(value: object) -> bool | None:
    """Keep unknown security flags and refuse numeric/string boolean substitutions.

    Args:
        value: Selected explicit boolean or absent/null.

    Returns:
        Exact configured flag or None.
    """

    if value is not None and type(value) is not bool:
        raise ValueError("Kubernetes inventory flags require explicit booleans or unknown")

    return value


def UniqueFields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys even in ignored fields without echoing their values.

    Args:
        pairs: Decoder-supplied ordered object entries.

    Returns:
        Unique-key mapping.
    """

    fields: dict[str, object] = {}

    for key, value in pairs:
        if key in fields:
            raise ValueError("Kubernetes List JSON contains a duplicate key")

        fields[key] = value

    return fields


def RejectConstant(value: str) -> None:
    """Refuse non-standard numeric tokens without exposing source text.

    Args:
        value: Decoder token outside standard JSON.

    Raises:
        ValueError: Non-finite constants are outside the profile.
    """

    raise ValueError("Kubernetes List JSON cannot contain non-finite constants")


def FiniteFloat(value: str) -> float:
    """Reject overflowed JSON numeric notation even in unselected provider fields.

    Args:
        value: Original JSON numeric token.

    Returns:
        Finite number.
    """

    number = float(value)

    if not math.isfinite(number):
        raise ValueError("Kubernetes List JSON cannot contain non-finite numbers")

    return number


def Decode(raw: bytes, limits: KubernetesInventoryLimits) -> list[dict[str, object]]:
    """Admit a complete bounded supported List before normalizing any resource.

    Args:
        raw: Exact original bytes from the unchanged evidence owner.
        limits: Revalidated immutable source and collection ceilings.

    Returns:
        Supported original records sorted by UID.
    """

    if not 1 <= len(raw) <= limits.max_bytes:
        raise ValueError("Kubernetes List original bytes exceed the source budget")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=UniqueFields,
                           parse_constant=RejectConstant, parse_float=FiniteFloat)

    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("Kubernetes List source requires complete bounded UTF-8 JSON") from None

    pending = [(value, 0)]
    nodes = 0

    while pending:
        item, depth = pending.pop()
        nodes += 1

        if depth > 24 or nodes > 20000:
            raise ValueError("Kubernetes List source exceeds its depth/node budget")

        if type(item) is dict:
            pending.extend((entry, depth + 1) for entry in item.values())
            pending.extend((key, depth + 1) for key in item)

        elif type(item) is list:
            pending.extend((entry, depth + 1) for entry in item)

        elif type(item) is str:
            Text(item, empty=True)

    document = Fields(value)

    if document.get("apiVersion") != "v1" or document.get("kind") != "List":
        raise ValueError("Kubernetes inventory requires the explicit v1 List export profile")

    metadata = OptionalFields(document.get("metadata"))

    remaining = metadata.get("remainingItemCount")

    if metadata.get("continue") not in (None, "") or (remaining is not None and (
        type(remaining) is not int or remaining != 0
    )):
        raise ValueError("Kubernetes inventory refuses incomplete paginated List evidence")

    records = [Fields(item) for item in Items(document.get("items"), limits.max_resources)]

    if not records:
        raise ValueError("Kubernetes inventory requires a nonempty supported List")

    for record in records:
        kind = record.get("kind")

        if type(kind) is not str or kind not in _VERSIONS or (
            record.get("apiVersion") != _VERSIONS[kind]
        ):
            raise ValueError("Kubernetes List contains an unsupported resource kind or API version")

    uids: set[str] = set()
    coordinates: set[tuple[str, str, str | None]] = set()

    for record in records:
        kind = cast(str, record["kind"])
        metadata = Fields(record.get("metadata"))
        uid = Text(metadata.get("uid"), 36)

        if not _UID.fullmatch(uid) or uid in uids:
            raise ValueError("Kubernetes inventory requires unique literal resource UIDs")

        uids.add(uid)
        namespace = None if kind in _CLUSTER_KINDS else Name(metadata.get("namespace"),
                                                             namespace=True)

        if kind in _CLUSTER_KINDS and metadata.get("namespace") not in (None, ""):
            raise ValueError("Kubernetes cluster resource cannot have a namespace")

        coordinate = (kind, Name(metadata.get("name"), namespace=kind == "Namespace"), namespace)

        if coordinate in coordinates:
            raise ValueError("Kubernetes inventory contains contradictory resource coordinates")

        coordinates.add(coordinate)

    return sorted(records, key=lambda item: cast(str, Fields(item["metadata"])["uid"]))


def Labels(value: object, limits: KubernetesInventoryLimits) -> dict[str, str] | None:
    """Read bounded label data only for transient selector matching, never model projection.

    Args:
        value: Explicit source labels or absent/null.
        limits: Selected collection ceiling.

    Returns:
        Transient labels; missing data remains unknown.
    """

    if value is None:
        return None

    fields = Fields(value)

    if len(fields) > limits.max_entries:
        raise ValueError("Kubernetes inventory labels exceed the transient collection budget")

    labels: dict[str, str] = {}

    for key, value in fields.items():
        parts = Text(key, 317).split("/")

        if len(parts) > 2 or not _LABEL_NAME.fullmatch(parts[-1]) or (
            len(parts) == 2 and (len(parts[0]) > 253 or any(
                not _DNS.fullmatch(label) for label in parts[0].split(".")
            ))
        ):
            raise ValueError("Kubernetes inventory label key is unsupported")

        text = Text(value, 63, empty=True)

        if text and not _LABEL_NAME.fullmatch(text):
            raise ValueError("Kubernetes inventory label value is unsupported")

        labels[key] = text

    return labels


def Selector(value: object, limits: KubernetesInventoryLimits, *, service: bool = False
             ) -> list[tuple[str, str, tuple[str, ...]]] | None:
    """Validate supported selector requirements without retaining arbitrary keys or values.

    Args:
        value: LabelSelector or Service selector map, or unknown value.
        limits: Selected collection ceiling.
        service: Whether the source is a Service's equality-only map.

    Returns:
        Transient AND requirements, or unknown/no automatic selection for missing/empty Services.
    """

    if value is None:
        return None

    fields = Fields(value)
    labels = Labels(fields if service else fields.get("matchLabels", {}), limits) or {}
    requirements: list[tuple[str, str, tuple[str, ...]]] = [
        (key, "In", (item,)) for key, item in sorted(labels.items())]

    if service:
        return requirements or None

    if set(fields) - {"matchLabels", "matchExpressions"}:
        raise ValueError("Kubernetes inventory selector has unsupported fields")

    for item in Items(fields.get("matchExpressions", []), limits.max_entries):
        expression = Fields(item)
        key = Text(expression.get("key"), 317)
        Labels({key: ""}, limits)
        operator = expression.get("operator")

        if type(operator) is not str or operator not in {"In", "NotIn", "Exists", "DoesNotExist"}:
            raise ValueError("Kubernetes inventory selector operator is unsupported")

        values = tuple(Text(entry, 63, empty=True) for entry in Items(
            expression.get("values", []), limits.max_entries))

        if len(set(values)) != len(values) or any(
            item and not _LABEL_NAME.fullmatch(item) for item in values
        ) or (operator in {"In", "NotIn"}) != bool(values):
            raise ValueError("Kubernetes inventory selector values disagree with their operator")

        requirements.append((key, operator, tuple(sorted(values))))

    if len(requirements) > limits.max_entries:
        raise ValueError("Kubernetes inventory selector exceeds its requirement budget")

    return requirements


def Matches(requirements: list[tuple[str, str, tuple[str, ...]]],
            labels: dict[str, str]) -> bool:
    """Evaluate an explicit AND selector against known transient labels without defaults.

    Args:
        requirements: Validated source selector requirements.
        labels: Explicit known labels on one exported candidate Pod.

    Returns:
        Whether every supported requirement matches; NotIn also admits an absent key.
    """

    for key, operator, values in requirements:
        present = key in labels

        if (operator == "In" and (not present or labels[key] not in values)) or (
            operator == "NotIn" and present and labels[key] in values
        ) or (operator == "Exists" and not present) or (operator == "DoesNotExist" and present):
            return False

    return True


class InventoryBatch:
    """Collect a bounded fully attributed candidate while existing stores retain ownership."""

    def __init__(self, state: ModelState, provenance: ModelProvenance, cluster: str,
                 limits: KubernetesInventoryLimits, records: list[dict[str, object]]) -> None:
        """Retain verified basis and transient exported-resource lookup coordinates.

        Args:
            state: Reconstructed canonical workspace snapshot.
            provenance: Exact immutable acquisition attribution.
            cluster: Validated existing declared cluster reference.
            limits: Revalidated profile ceilings.
            records: Complete supported source records.
        """

        self.state = state
        self.provenance = provenance
        self.cluster = cluster
        self.limits = limits
        self.records = records
        self.objects: dict[str, SecurityObject] = {}
        self.relations: dict[str, Relation] = {}
        self.observations: list[Observation] = []
        self.findings: list[Finding] = []
        self.resources: dict[tuple[str, str, str | None], SecurityObject] = {}

    def Object(self, identity: ObjectIdentity, attributes: Mapping[str, object]) -> SecurityObject:
        """Retain only selected facts, leaving earlier source facts with canonical merge logic.

        Args:
            identity: Existing canonical identity family.
            attributes: Whitelisted source interpretation.

        Returns:
            Validated immutable model entity.
        """

        entity = SecurityObject(identity, attributes, (self.provenance,))

        if entity.Reference() in self.objects:
            raise ValueError("Kubernetes inventory contains a duplicate canonical identity")

        self.objects[entity.Reference()] = entity
        self.observations.append(Observation("kubernetes-list-fact", entity.Reference(),
                                             attributes, self.provenance))

        return entity

    def Edge(self, source: str, target: str, association: str,
             attributes: Mapping[str, object] | None = None, *,
             kind: RelationKind = RelationKind.RELATED_TO) -> None:
        """Retain configuration associations without asserting authorization or reachability.

        Args:
            source: Existing or candidate source reference.
            target: Existing or candidate target reference.
            association: Fixed descriptive source meaning.
            attributes: Selected additional association facts.
            kind: Existing canonical relation kind.
        """

        fields = {"association": association, "basis": "supplied-kubernetes-list",
                  **(attributes or {})}
        relation = Relation(kind, source, target, fields, (self.provenance,))
        previous = self.relations.get(relation.Reference())

        if previous is not None:
            if previous.attributes == relation.attributes:
                return

            entries = list(cast(tuple[Mapping[str, object], ...], previous.attributes[
                "associations"])) if previous.attributes["association"] == (
                    "configured-associations") else [dict(previous.attributes)]

            if fields not in entries:
                entries.append(fields)

            combined = {"association": "configured-associations",
                        "basis": "supplied-kubernetes-list",
                        "associations": sorted(entries, key=CanonicalModelJson)}
            relation = Relation(kind, source, target, combined, (self.provenance,))

        if previous is None and len(self.relations) >= self.limits.max_relations:
            raise ValueError("Kubernetes inventory exceeds its association budget")

        self.relations[relation.Reference()] = relation
        self.observations.append(Observation("kubernetes-list-association", relation.Reference(),
                                             fields, self.provenance))

    def Finding(self, entity: SecurityObject, check: str, location: str, summary: str,
                severity: FindingSeverity) -> None:
        """Describe a direct configured condition without modifying effective access or triage.

        Args:
            entity: Validated selected subject.
            check: Fixed configured-condition suffix.
            location: Stable selected source location.
            summary: Fixed advisory text without provider values.
            severity: Explicit configured-condition severity.
        """

        self.findings.append(Finding(entity.Reference(), "kubernetes.configured." + check,
            location, summary, (self.provenance,), severity, 1.0))


def PodSpec(record: dict[str, object]) -> dict[str, object] | None:
    """Select explicit Pod or workload-template specification without creating runtime Pods.

    Args:
        record: Supported original resource.

    Returns:
        Explicit selected specification or None when the template/spec is unknown.
    """

    spec = OptionalFields(record.get("spec"))

    if record["kind"] == "Pod":
        return None if record.get("spec") is None else spec

    if record["kind"] == "CronJob":
        spec = OptionalFields(OptionalFields(spec.get("jobTemplate")).get("spec"))

    template = OptionalFields(spec.get("template"))

    return None if template.get("spec") is None else Fields(template["spec"])


def Containers(batch: InventoryBatch, resource: SecurityObject, spec: dict[str, object]) -> None:
    """Normalize bounded declared containers, selected booleans and advisory conditions.

    Args:
        batch: Verified in-memory candidate.
        resource: Exported Pod or workload resource, never a synthesized runtime instance.
        spec: Explicit selected Pod specification or workload template.
    """

    names: set[str] = set()
    total = 0

    for section, category in (("containers", "regular"), ("initContainers", "init"),
                              ("ephemeralContainers", "ephemeral")):
        if spec.get(section) is None:
            continue

        for item in Items(spec[section], batch.limits.max_containers):
            fields = Fields(item)
            name = Name(fields.get("name"), namespace=True)
            total += 1

            if name in names or total > batch.limits.max_containers:
                raise ValueError("Kubernetes inventory containers exceed unique-name/total budgets")

            names.add(name)
            image = None if fields.get("image") is None else Text(fields["image"], 512)

            if image is not None and (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_@-]*", image)
                or "://" in image or ("@" in image and not re.fullmatch(
                    r"[^@]+@sha256:[0-9a-f]{64}", image))):
                raise ValueError("Kubernetes inventory image declaration is unsupported")

            security = OptionalFields(fields.get("securityContext"))
            attributes = {"asset_type": "kubernetes-container-declaration", "provider": _SOURCE_ID,
                "resource_reference": resource.Reference(), "container_name": name,
                "container_category": category, "configured_image": image,
                "image_digest_kind": None, "effective_privileges": None,
                "privileged": OptionalBool(security.get("privileged")),
                "allow_privilege_escalation": OptionalBool(
                    security.get("allowPrivilegeEscalation")),
                "read_only_root_filesystem": OptionalBool(security.get("readOnlyRootFilesystem")),
                "run_as_non_root": OptionalBool(security.get("runAsNonRoot"))}
            container = batch.Object(ObjectIdentity(batch.state.workspace_id, ObjectKind.ASSET,
                f"kubernetes-container:{resource.Reference()}:{category}:{name}"), attributes)
            batch.Edge(resource.Reference(), container.Reference(), "declared-container",
                       kind=RelationKind.CONTAINS)

            if attributes["privileged"] is True:
                batch.Finding(container, "privileged", "securityContext.privileged",
                    "Container is configured privileged; effective privileges are unverified.",
                    FindingSeverity.HIGH)


def StringList(value: object, maximum: int, *, empty: bool = False) -> list[str]:
    """Validate bounded unique selected RBAC tokens with no environment/credential projection.

    Args:
        value: Actual source array.
        maximum: Inclusive entry ceiling.
        empty: Whether an explicit empty string is valid, as for the core API group.

    Returns:
        Sorted unique original tokens.
    """

    values = [Text(item, 253, empty=empty) for item in Items(value, maximum)]

    if len(set(values)) != len(values):
        raise ValueError("Kubernetes inventory selected token collection must be unique")

    return sorted(values)


def Rules(record: dict[str, object], limits: KubernetesInventoryLimits) -> list[dict[str, object]]:
    """Retain supplied nominal resource/non-resource RBAC rules without permission evaluation.

    Args:
        record: Supported original Role or ClusterRole.
        limits: Selected collection ceiling.

    Returns:
        Sorted selected rules; the resource caller separately preserves absent rules as unknown.
    """

    normalized: list[dict[str, object]] = []

    for item in Items(record.get("rules", []), limits.max_entries):
        rule = Fields(item)
        verbs = StringList(rule.get("verbs"), limits.max_entries)

        if not verbs or any(not re.fullmatch(r"[a-z]+|\*", verb) for verb in verbs):
            raise ValueError("Kubernetes inventory RBAC verbs are outside the nominal profile")

        resources = None if rule.get("resources") is None else StringList(
            rule["resources"], limits.max_entries)
        urls = None if rule.get("nonResourceURLs") is None else StringList(
            rule["nonResourceURLs"], limits.max_entries)
        groups = None if rule.get("apiGroups") is None else StringList(
            rule["apiGroups"], limits.max_entries, empty=True)
        names = None if rule.get("resourceNames") is None else StringList(
            rule["resourceNames"], limits.max_entries)

        if bool(resources) == bool(urls) or (resources is not None and groups is None) or (
            urls is not None and (record["kind"] != "ClusterRole" or groups is not None
                                 or names is not None)
        ) or (resources is not None and any(not re.fullmatch(
            r"[a-z0-9*]+(?:/[a-z0-9*]+)?", token) for token in resources)
        ) or (groups is not None and any(not re.fullmatch(r"[a-z0-9.-]*|\*", token)
                                        for token in groups)) or (
            urls is not None and any(not token.startswith("/") or "?" in token
                or "#" in token or ("*" in token and (
                    not token.endswith("*") or token.count("*") != 1)) for token in urls)
        ):
            raise ValueError("Kubernetes inventory RBAC rule is outside the nominal profile")

        normalized.append({"verbs": verbs, "api_groups": groups, "resources": resources,
                           "resource_names": names, "non_resource_urls": urls})

    encoded = [CanonicalModelJson(item) for item in normalized]

    if len(set(encoded)) != len(encoded):
        raise ValueError("Kubernetes inventory nominal RBAC rules must be unique")

    return sorted(normalized, key=CanonicalModelJson)


def ServicePorts(value: object, limits: KubernetesInventoryLimits
                 ) -> list[dict[str, object]] | None:
    """Preserve explicit configured ports without assuming listening endpoints or exposure.

    Args:
        value: Supplied Service port array or unknown value.
        limits: Selected collection ceiling.

    Returns:
        Selected configured ports or None.
    """

    if value is None:
        return None

    ports: list[dict[str, object]] = []

    for item in Items(value, limits.max_entries):
        fields = Fields(item)
        target = fields.get("targetPort")

        if target is not None:
            target = Integer(target, 65535) if type(target) is int else Name(target,
                                                                           namespace=True)

        protocol = fields.get("protocol")

        if protocol is not None and (type(protocol) is not str or protocol not in {
            "TCP", "UDP", "SCTP"
        }):
            raise ValueError("Kubernetes inventory Service port protocol is unsupported")

        ports.append({"name": None if fields.get("name") is None else Name(fields["name"],
            namespace=True), "port": Integer(fields.get("port"), 65535),
            "target_port": target, "protocol": protocol,
            "node_port": None if fields.get("nodePort") is None else Integer(
                fields["nodePort"], 65535)})

    encoded = [CanonicalModelJson(item) for item in ports]

    if len(set(encoded)) != len(encoded):
        raise ValueError("Kubernetes inventory Service ports must be unique")

    return sorted(ports, key=CanonicalModelJson)


def Resource(batch: InventoryBatch, record: dict[str, object]) -> None:
    """Normalize one supported exported resource's selected facts and direct advisory checks.

    Args:
        batch: Verified candidate owner.
        record: Original supported UID-bearing resource.
    """

    metadata = Fields(record["metadata"])
    kind = cast(str, record["kind"])
    namespace = None if kind in _CLUSTER_KINDS else cast(str, metadata["namespace"])
    spec = OptionalFields(record.get("spec"))
    attributes: dict[str, object] = {"asset_type": "kubernetes-resource", "provider": _SOURCE_ID,
        "cluster_reference": batch.cluster, "api_version": record["apiVersion"],
        "resource_kind": kind, "resource_uid": metadata["uid"], "name": metadata["name"],
        "namespace": namespace, "effective_permissions": None}

    if kind == "Service":
        serviceType = spec.get("type")

        if serviceType is not None and (type(serviceType) is not str or serviceType not in {
            "ClusterIP", "NodePort", "LoadBalancer", "ExternalName"
        }):
            raise ValueError("Kubernetes inventory Service type is unsupported")

        address = spec.get("clusterIP")

        if address not in (None, "None"):
            try:
                literal = Text(address, 64)

                if "%" in literal:
                    raise ValueError("Kubernetes Service address cannot use a machine-local zone")

                address = str(ipaddress.ip_address(literal))

            except ValueError:
                raise ValueError("Kubernetes Service address requires a literal IP") from None

        attributes.update({"service_type": "kubernetes-service", "configured_type": serviceType,
            "configured_cluster_ip": address,
            "ports": ServicePorts(spec.get("ports"), batch.limits),
            "physical_reachability": None})

    if kind in {"Role", "ClusterRole"}:
        rules = None if record.get("rules") is None else Rules(record, batch.limits)
        attributes.update({"nominal_rules": rules,
            "aggregation_unresolved": True if record.get("aggregationRule") is not None else None})

    if kind == "NetworkPolicy":
        policyTypes = None if spec.get("policyTypes") is None else StringList(
            spec["policyTypes"], batch.limits.max_entries)

        if policyTypes is not None and any(item not in {"Ingress", "Egress"}
                                            for item in policyTypes):
            raise ValueError("Kubernetes inventory NetworkPolicy type is unsupported")

        attributes.update({"configured_policy_types": policyTypes, "cni_enforcement": None,
            "ingress_rule_count": None if spec.get("ingress") is None else len(Items(
                spec["ingress"], batch.limits.max_entries)),
            "egress_rule_count": None if spec.get("egress") is None else len(Items(
                spec["egress"], batch.limits.max_entries))})

    if kind == "ServiceAccount":
        attributes["automount_service_account_token"] = OptionalBool(
            record.get("automountServiceAccountToken"))

    if kind in _WORKLOADS or kind == "Pod":
        podSpec = PodSpec(record)
        attributes["pod_spec_known"] = podSpec is not None

        for source, field in (("hostNetwork", "host_network"), ("hostPID", "host_pid"),
                              ("hostIPC", "host_ipc")):
            attributes[field] = OptionalBool((podSpec or {}).get(source))

    objectKind = ObjectKind.SERVICE if kind == "Service" else ObjectKind.ASSET
    entity = batch.Object(ObjectIdentity(batch.state.workspace_id, objectKind,
        f"kubernetes-resource:{batch.cluster}:{record['apiVersion']}:{kind}:{metadata['uid']}"),
        attributes)
    batch.resources[(kind, cast(str, metadata["name"]), namespace)] = entity
    batch.Edge(batch.cluster, entity.Reference(), "declared-cluster-resource",
               kind=RelationKind.CONTAINS)

    if kind in {"Role", "ClusterRole"} and attributes["nominal_rules"] is not None:
        wildcard = any("*" in cast(list[str], rule[field] or [])
            for rule in cast(list[dict[str, object]], attributes["nominal_rules"])
            for field in ("verbs", "resources", "api_groups")) or any(
                token.endswith("*")
                for rule in cast(list[dict[str, object]], attributes["nominal_rules"])
                for token in cast(list[str], rule["non_resource_urls"] or []))

        if wildcard:
            batch.Finding(entity, "rbac-wildcard", "rules",
                "Supplied RBAC rule contains a wildcard; effective authorization is unverified.",
                FindingSeverity.MEDIUM)

    if kind in _WORKLOADS or kind == "Pod":
        for field in ("host_network", "host_pid", "host_ipc"):
            if attributes[field] is True:
                batch.Finding(entity, field.replace("_", "-"), "spec." + field,
                    "Pod spec requests a host namespace; effective isolation is unverified.",
                    FindingSeverity.MEDIUM)

        if podSpec is not None:
            Containers(batch, entity, podSpec)


def SelectedPods(batch: InventoryBatch, record: dict[str, object], entity: SecurityObject) -> None:
    """Associate explicit same-export pod selector matches without copying labels or policy claims.

    Args:
        batch: Verified candidate and original record lookup.
        record: Supported workload, Service or NetworkPolicy.
        entity: Corresponding selected model resource.
    """

    kind = record["kind"]

    if kind not in (_WORKLOADS - {"CronJob"}) | {"Service", "NetworkPolicy"}:
        return

    spec = OptionalFields(record.get("spec"))
    requirements = Selector(spec.get("podSelector" if kind == "NetworkPolicy" else "selector"),
                            batch.limits, service=kind == "Service")

    if requirements is None:
        return

    for candidate in batch.records:
        metadata = Fields(candidate["metadata"])

        if candidate["kind"] != "Pod" or (
            metadata.get("namespace") != entity.attributes["namespace"]
        ):
            continue

        labels = Labels(metadata.get("labels"), batch.limits)

        if labels is not None and Matches(requirements, labels):
            pod = batch.resources[("Pod", cast(str, metadata["name"]),
                                   cast(str, metadata["namespace"]))]
            batch.Edge(entity.Reference(), pod.Reference(), "configured-pod-selector-match",
                {"candidate_basis": "same-export", "effective_enforcement": None})


def Binding(batch: InventoryBatch, record: dict[str, object], entity: SecurityObject) -> None:
    """Retain nominal role and exported ServiceAccount subject links without permission grants.

    Args:
        batch: Verified candidate and exported resource coordinates.
        record: Supported original binding.
        entity: Corresponding binding object.
    """

    role = Fields(record.get("roleRef"))
    roleKind = role.get("kind")

    if role.get("apiGroup") != "rbac.authorization.k8s.io" or type(roleKind) is not str or (
        roleKind not in {
        "Role", "ClusterRole"
    }) or (record["kind"] == "ClusterRoleBinding" and roleKind != "ClusterRole"):
        raise ValueError("Kubernetes inventory binding role reference is unsupported")

    namespace = entity.attributes["namespace"]
    roleName = Name(role.get("name"))
    target = batch.resources.get((roleKind, roleName,
                                 cast(str | None, namespace) if roleKind == "Role" else None))
    roleResolved = target is not None

    if target is not None:
        batch.Edge(entity.Reference(), target.Reference(), "nominal-role-reference",
                   {"binding_namespace": namespace, "effective_permissions": None})

    subjects = None if record.get("subjects") is None else Items(record["subjects"],
                                                                 batch.limits.max_entries)
    counts = {"ServiceAccount": 0, "User": 0, "Group": 0}
    seen: set[bytes] = set()

    for item in subjects or []:
        subject = Fields(item)
        subjectKind = subject.get("kind")

        if type(subjectKind) is not str or subjectKind not in counts:
            raise ValueError("Kubernetes inventory binding subject kind is unsupported")

        name = Text(subject.get("name"), 253)
        subjectNamespace = subject.get("namespace")

        if subjectKind == "ServiceAccount":
            name = Name(name)

            if subject.get("apiGroup") not in (None, ""):
                raise ValueError("Kubernetes ServiceAccount subject cannot use an RBAC API group")

            subjectNamespace = None if subjectNamespace is None else Name(subjectNamespace,
                                                                            namespace=True)

        elif subject.get("apiGroup") != "rbac.authorization.k8s.io" or (
            subjectNamespace is not None
        ):
            raise ValueError("Kubernetes User/Group subject requires its nominal API group")

        token = CanonicalModelJson([subjectKind, name, subjectNamespace])

        if token in seen:
            raise ValueError("Kubernetes inventory binding subjects must be unique")

        seen.add(token)
        counts[subjectKind] += 1
        target = batch.resources.get(("ServiceAccount", name, subjectNamespace))

        if subjectKind == "ServiceAccount" and target is not None:
            batch.Edge(entity.Reference(), target.Reference(), "nominal-service-account-subject",
                       {"binding_namespace": namespace, "effective_permissions": None})

    fields = {"role_ref_kind": roleKind, "role_ref_name": roleName,
              "role_reference_resolved": roleResolved,
              "subject_counts": None if subjects is None else counts,
              "subject_count": None if subjects is None else len(subjects)}
    original = dict(entity.attributes)
    original.update(fields)
    replacement = SecurityObject(entity.identity, original, entity.provenance)
    batch.objects[entity.Reference()] = replacement
    batch.observations.append(Observation("kubernetes-binding-fact", entity.Reference(),
                                         fields, batch.provenance))


def Ingress(batch: InventoryBatch, record: dict[str, object], entity: SecurityObject) -> None:
    """Associate only configured Service backends, retaining routing and TLS secrets outside model.

    Args:
        batch: Verified candidate and exported service lookup.
        record: Supported networking/v1 Ingress.
        entity: Corresponding resource.
    """

    spec = OptionalFields(record.get("spec"))
    backends = [] if spec.get("defaultBackend") is None else [spec["defaultBackend"]]

    for item in Items(spec.get("rules", []), batch.limits.max_entries):
        http = OptionalFields(Fields(item).get("http"))

        for path in Items(http.get("paths", []), batch.limits.max_entries):
            backends.append(Fields(path).get("backend"))

    if len(backends) > batch.limits.max_entries:
        raise ValueError("Kubernetes inventory Ingress backends exceed their total budget")

    targets: dict[str, list[dict[str, object]]] = {}

    for item in backends:
        backend = Fields(item)

        if backend.get("resource") is not None:
            raise ValueError("Kubernetes inventory supports only Ingress Service backends")

        service = Fields(backend.get("service"))
        name = Name(service.get("name"))
        port = Fields(service.get("port"))

        if (port.get("number") is None) == (port.get("name") is None):
            raise ValueError("Kubernetes Ingress backend requires exactly one port selector")

        fields: dict[str, object] = {"port_number": None if port.get("number") is None else Integer(
            port["number"], 65535), "port_name": None if port.get("name") is None else Name(
                port["name"], namespace=True)}
        target = batch.resources.get(("Service", name, cast(str, entity.attributes["namespace"])))

        if target is not None:
            entries = targets.setdefault(target.Reference(), [])

            if fields not in entries:
                entries.append(fields)

    for targetReference, ports in sorted(targets.items()):
        batch.Edge(entity.Reference(), targetReference, "configured-ingress-service-backend",
                   {"backend_ports": sorted(ports, key=CanonicalModelJson),
                    "physical_reachability": None})


def Associations(batch: InventoryBatch, record: dict[str, object]) -> None:
    """Resolve selected exported references without inventing missing resources or live state.

    Args:
        batch: Fully normalized candidate and original export lookup.
        record: Supported source resource.
    """

    metadata = Fields(record["metadata"])
    kind = cast(str, record["kind"])
    namespace = None if kind in _CLUSTER_KINDS else cast(str, metadata["namespace"])
    entity = batch.resources[(kind, cast(str, metadata["name"]), namespace)]
    ownerNamespace = batch.resources.get(("Namespace", namespace, None)) if namespace else None

    if ownerNamespace is not None:
        batch.Edge(ownerNamespace.Reference(), entity.Reference(), "declared-namespace-resource",
                   kind=RelationKind.CONTAINS)

    seen: set[str] = set()

    for item in Items(metadata.get("ownerReferences", []), batch.limits.max_entries):
        owner = Fields(item)
        uid = Text(owner.get("uid"), 36)

        if not _UID.fullmatch(uid) or uid in seen:
            raise ValueError("Kubernetes inventory owner references require unique literal UIDs")

        seen.add(uid)
        ownerKind = owner.get("kind")
        name = Name(owner.get("name"))

        if type(ownerKind) is not str or ownerKind not in _VERSIONS or (
            owner.get("apiVersion") != _VERSIONS[ownerKind]
        ):
            continue

        target = batch.resources.get((ownerKind, name,
            None if ownerKind in _CLUSTER_KINDS else namespace))
        exported = next((item for item in batch.resources.values()
                         if item.attributes["resource_uid"] == uid), None)

        if exported is not None and (target is None or target.Reference() != exported.Reference()):
            raise ValueError("Kubernetes owner reference differs from its exported scope/identity")

        if target is not None:
            if target.attributes["resource_uid"] != uid:
                raise ValueError("Kubernetes inventory owner reference disagrees with exported UID")

            batch.Edge(target.Reference(), entity.Reference(), "declared-owner-reference",
                {"controller": OptionalBool(owner.get("controller"))})

    if kind == "Pod" or kind in _WORKLOADS:
        spec = PodSpec(record)
        accountName = None if spec is None or spec.get("serviceAccountName") is None else Name(
            spec["serviceAccountName"])
        target = batch.resources.get(("ServiceAccount", accountName, namespace)) if (
            accountName) else None

        if target is not None:
            batch.Edge(entity.Reference(), target.Reference(), "configured-service-account-use",
                       {"effective_permissions": None})

    SelectedPods(batch, record, entity)

    if kind in {"RoleBinding", "ClusterRoleBinding"}:
        Binding(batch, record, entity)

    if kind == "Ingress":
        Ingress(batch, record, entity)


class BoundedListStore(LocalEvidenceStore):
    """Check the actual parsed owner reference before an eager immutable-blob read."""

    def __init__(self, root: Path, maximum: int) -> None:
        """Retain the explicit evidence root and revalidated original-byte budget.

        Args:
            root: Existing owned workspace evidence directory.
            maximum: Inclusive original-byte ceiling.
        """

        super().__init__(root)
        self.maximum = maximum

    def Read(self, reference: EvidenceReference) -> bytes:
        """Validate actual owning role/media/size before unchanged integrity and storage checks.

        Args:
            reference: Actual parsed immutable owner reference.

        Returns:
            Exact original bytes verified by the existing evidence owner.
        """

        if type(reference) is not EvidenceReference or reference.role != "kubernetes-list" or (
            reference.media_type != "application/json"
        ):
            raise ValueError("Kubernetes inventory evidence requires its exact JSON role")

        Integer(reference.size_bytes, self.maximum)

        return super().Read(reference)


def ApplyVerifiedKubernetesList(
    state: ModelState, record: EvidenceRecord, provenance: ModelProvenance, *,
    cluster_reference: str, workspace_root: Path,
    limits: KubernetesInventoryLimits = KubernetesInventoryLimits(),
) -> tuple[ModelState, ModelDelta]:
    """Apply bounded caller-owned List evidence through existing workspace/evidence/model owners.

    Args:
        state: Current canonical snapshot in the explicit existing workspace.
        record: Exact original kubernetes-list / application/json evidence manifest.
        provenance: Matching source, scope, time, provider version and raw reference attribution.
        cluster_reference: Existing declared ASSET cluster anchor with a literal cluster_id.
        workspace_root: Owned existing workspace, accessed only through canonical storage owners.
        limits: Positive fixed ceilings; excess never means partial success.

    Returns:
        Atomic validated in-memory transition and delta ready for caller-owned CAS persistence.
        Exact replay is a no-op; refreshed detector evidence preserves existing finding triage.

    Raises:
        ValueError: Contracts, original profile, cluster basis or selected facts are invalid.
        EvidenceError: Original owner manifest/blob is missing, corrupt or unsafe.
        OSError: Existing workspace metadata cannot be read.

    This experimental function performs only explicit owning reads. It executes no command,
    contacts no cluster and grants no authorization, enforcement or reachability claim.
    """

    if type(state) is not ModelState or type(record) is not EvidenceRecord or (
        type(provenance) is not ModelProvenance or type(limits) is not KubernetesInventoryLimits
    ) or type(record.reference) is not EvidenceReference or (
        type(record.provenance) is not EvidenceProvenance
    ):
        raise ValueError("Kubernetes inventory requires exact typed canonical input contracts")

    limits = KubernetesInventoryLimits(limits.max_bytes, limits.max_resources,
        limits.max_containers, limits.max_entries, limits.max_relations)
    provenance = ModelProvenance(provenance.source_id, provenance.run_reference,
        provenance.observed_at, provenance.scope_reference, provenance.target_reference,
        provenance.provider_version, provenance.evidence_references, provenance.execution)
    source = record.provenance
    source = EvidenceProvenance(source.workspace_id, source.scope_reference, source.source_id,
        source.source_version, source.tool_version, source.started_at, source.finished_at,
        source.invocation_sha256, source.execution)
    reference = record.reference
    reference = EvidenceReference(reference.role, reference.locator, reference.sha256,
                                  reference.media_type, reference.size_bytes)
    rebuilt = EvidenceRecord(reference, source, record.schema_version)

    if rebuilt != record:
        raise ValueError("Kubernetes inventory evidence contract differs from its literal manifest")

    state = ModelState.FromDict(state.ToDict())
    cluster = RequireModelReference(cluster_reference)
    entity = next((item for item in state.objects if item.Reference() == cluster), None)

    if entity is None or entity.identity.kind is not ObjectKind.ASSET or (
        entity.attributes.get("asset_type") != "kubernetes-cluster"
    ):
        raise ValueError("Kubernetes inventory requires an existing declared cluster ASSET")

    clusterId = Name(entity.attributes.get("cluster_id"))

    if entity.identity.key != "kubernetes-cluster:" + clusterId:
        raise ValueError("Kubernetes inventory cluster identity differs from its literal basis")

    if source.workspace_id != state.workspace_id or source.source_id != _SOURCE_ID or (
        source.source_version != _SOURCE_VERSION
        or source.scope_reference != provenance.scope_reference
        or source.source_id != provenance.source_id
        or source.tool_version != provenance.provider_version
        or source.finished_at != provenance.observed_at
        or source.invocation_sha256 is not None or source.execution is not None
        or provenance.execution is not None or provenance.target_reference != cluster
        or provenance.evidence_references != (reference,)
    ):
        raise ValueError("Kubernetes attribution differs from its original offline profile")

    Integer(reference.size_bytes, limits.max_bytes)
    workspace = LocalWorkspaceStore(workspace_root)

    if workspace.Open().workspace_id != state.workspace_id:
        raise ValueError("Kubernetes inventory belongs to another workspace")

    if LocalModelStore(workspace.root).Open() != state:
        raise ValueError("Kubernetes inventory requires the current persisted model basis")

    store = BoundedListStore(workspace.root / "evidence", limits.max_bytes)

    if store.Get(record.evidence_id) != record:
        raise ValueError("Kubernetes inventory differs from its immutable owning manifest")

    records = Decode(store.Read(reference), limits)
    batch = InventoryBatch(state, provenance, cluster, limits, records)

    for resource in records:
        Resource(batch, resource)

    for resource in records:
        Associations(batch, resource)

    if LocalModelStore(workspace.root).Open() != state:
        raise ValueError("Kubernetes inventory model basis changed before batch application")

    return ApplyBatch(state, list(batch.objects.values()), list(batch.relations.values()),
                      batch.observations, batch.findings, workspace.root)
