# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental owned Docker inspect facts without daemon access or physical reachability claims."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.evidence import EvidenceRecord, LocalEvidenceStore
from fuzzy1337.findings import Finding, FindingSeverity
from fuzzy1337.images import ApplyBatch, ImageIdentity
from fuzzy1337.model import (
    CanonicalModelJson,
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

__all__ = ["DockerInventoryLimits", "ApplyVerifiedDockerInspect"]

_SOURCE_ID = "inventory.docker-inspect"
_SOURCE_VERSION = "owned-docker-container-inspect-v1"
_FULL_ID = re.compile(r"^[0-9a-f]{64}$")
_PORT = re.compile(r"^([1-9][0-9]{0,4})/(tcp|udp|sctp)$")
_CAPABILITIES = {
    "ALL", "AUDIT_CONTROL", "AUDIT_READ", "AUDIT_WRITE", "BLOCK_SUSPEND", "BPF",
    "CHECKPOINT_RESTORE",
    "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "IPC_LOCK", "IPC_OWNER", "KILL",
    "LEASE", "LINUX_IMMUTABLE", "MAC_ADMIN", "MAC_OVERRIDE", "MKNOD", "NET_ADMIN",
    "NET_BIND_SERVICE",
    "NET_BROADCAST", "NET_RAW", "PERFMON", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_ADMIN",
    "SYS_BOOT", "SYS_CHROOT", "SYS_MODULE", "SYS_NICE", "SYS_PACCT", "SYS_PTRACE", "SYS_RAWIO",
    "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "SYSLOG", "WAKE_ALARM",
}
_POWERFUL = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "DAC_READ_SEARCH"}
_SOCKETS = {"/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock"}
_SENSITIVE = {"/", "/proc", "/sys", "/dev", "/etc", "/var/lib/docker"}


def Integer(value: object, maximum: int) -> int:
    """Require a positive exact integer within one inclusive resource ceiling.

    Args:
        value: Supplied quota or port number, excluding booleans.
        maximum: Inclusive fixed upper bound.

    Returns:
        Validated integer.
    """

    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("Docker inventory integer exceeds its positive bound")

    return value


@dataclass(frozen=True, slots=True)
class DockerInventoryLimits:
    """Bound original bytes and each container's selected inventory collections."""

    max_bytes: int = 1024 * 1024
    max_containers: int = 32
    max_networks: int = 16
    max_ports: int = 32
    max_mounts: int = 32

    def __post_init__(self) -> None:
        """Admit exact positive limits without relaxing the profile's fixed maximum budgets."""

        for name, maximum in (("max_bytes", 1024 * 1024), ("max_containers", 32),
                              ("max_networks", 16), ("max_ports", 32), ("max_mounts", 32)):
            Integer(getattr(self, name), maximum)


def Text(value: object, maximum: int = 4096) -> str:
    """Validate selected non-secret single-line UTF-8 text without echoing rejected values.

    Args:
        value: Explicit selected text, never arbitrary labels or environment fields.
        maximum: Inclusive UTF-8 byte ceiling.

    Returns:
        Original selected text.
    """

    if not isinstance(value, str) or any(ord(character) < 32 for character in value):
        raise ValueError("Docker inventory selected text must be single-line text")

    try:
        size = len(value.encode("utf-8"))

    except UnicodeError:
        raise ValueError("Docker inventory selected text must be valid UTF-8") from None

    if size > maximum:
        raise ValueError("Docker inventory selected text exceeds its byte bound")

    return value


def Fields(value: object) -> dict[str, object]:
    """Require a selected JSON object without interpreting its unselected fields.

    Args:
        value: Already decoded JSON mapping.

    Returns:
        Exact string-keyed mapping.
    """

    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError("Docker inventory selected fields require an object")

    return cast(dict[str, object], value)


def OptionalFields(value: object) -> dict[str, object]:
    """Treat absent/null selected sections as unknown while rejecting other malformed shapes.

    Args:
        value: Selected nested section or None.

    Returns:
        Supplied fields or an empty lookup mapping for unknown fields.
    """

    return {} if value is None else Fields(value)


def Items(value: object, maximum: int) -> list[object]:
    """Require one bounded actual JSON array rather than iterable coercion.

    Args:
        value: Selected JSON collection.
        maximum: Inclusive element ceiling.

    Returns:
        Exact supplied list.
    """

    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError("Docker inventory collection exceeds its array bound")

    return value


def FullId(value: object) -> str:
    """Require an immutable full lowercase Docker identifier rather than a name or short ID.

    Args:
        value: Selected container or network identifier.

    Returns:
        Full 64-character identifier.
    """

    if not isinstance(value, str) or not _FULL_ID.fullmatch(value):
        raise ValueError("Docker inventory requires a full lowercase identifier")

    return value


def OptionalBool(value: object) -> bool | None:
    """Preserve unknown flags and reject integer/string boolean substitutions.

    Args:
        value: Supplied JSON boolean or absent/null value.

    Returns:
        Exact flag or None for unknown.
    """

    if value is not None and type(value) is not bool:
        raise ValueError("Docker inventory flags must be booleans or unknown")

    return value


def Choice(value: object, choices: set[str]) -> str | None:
    """Admit only a selected known enum while retaining absent/null as unknown.

    Args:
        value: Selected enum field or None.
        choices: Fixed admitted source values.

    Returns:
        Selected enum or None.
    """

    if value is not None and (not isinstance(value, str) or value not in choices):
        raise ValueError("Docker inventory selected enum is unsupported")

    return value


def Namespace(value: object) -> str | None:
    """Categorize namespace configuration without preserving an opaque cross-container selector.

    Args:
        value: Supplied Docker namespace mode or None.

    Returns:
        Known fixed mode, container mode, named-network mode or unknown.
    """

    if value is None:
        return None

    mode = Text(value, 256)

    if mode in {"", "host", "private", "none", "default", "bridge", "shareable"}:
        return "default" if not mode else mode

    if mode.startswith("container:"):
        FullId(mode[10:])

        return "container"

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", mode):
        raise ValueError("Docker inventory namespace mode is unsupported")

    return "named"


def UserCategory(value: object) -> str | None:
    """Describe configured user intent without copying a username or claiming effective UID.

    Args:
        value: Docker Config.User field or None.

    Returns:
        root, numeric-nonroot or named; missing/null is unknown.
    """

    if value is None:
        return None

    user = Text(value, 256).split(":", 1)[0]

    if user in {"", "root"} or (user.isascii() and user.isdecimal() and int(user) == 0):
        return "root"

    if user.isascii() and user.isdecimal():
        return "numeric-nonroot"

    return "named"


def Capabilities(value: object) -> list[str] | None:
    """Retain explicit admitted capability names without inferring the effective capability set.

    Args:
        value: CapAdd or CapDrop JSON array or absent/null.

    Returns:
        Sorted unique capability names or unknown.
    """

    if value is None:
        return None

    names = [Text(item, 64).removeprefix("CAP_") for item in Items(value, 64)]

    if len(set(names)) != len(names) or any(name not in _CAPABILITIES for name in names):
        raise ValueError("Docker inventory capabilities must be unique known names")

    return sorted(names)


def Address(value: object, version: int | None = None) -> str | None:
    """Normalize supplied literal address text while keeping empty/missing addresses unknown.

    Args:
        value: Explicit address text or absent/null; DNS is never consulted.
        version: Optional exact required IP version.

    Returns:
        Canonical literal address or None.
    """

    if value is None or value == "":
        return None

    text = Text(value, 64)

    if "%" in text:
        raise ValueError("Docker inventory addresses cannot have machine-local zones")

    try:
        address = ipaddress.ip_address(text)

    except ValueError:
        raise ValueError("Docker inventory address must be a literal IP") from None

    if version is not None and address.version != version:
        raise ValueError("Docker inventory address family differs from its selected field")

    return str(address)


def MountPath(value: object) -> str:
    """Validate a supplied POSIX mount path lexically without opening or resolving it.

    Args:
        value: Explicit source/destination path in the selected Linux inspect profile.

    Returns:
        Exact absolute path with redundant trailing separators removed.
    """

    path = Text(value, 2048)

    if not path.startswith("/") or "\\" in path or any(
        part in {".", ".."} for part in path.split("/")
    ) or "//" in path:
        raise ValueError("Docker inventory mount path must be an absolute lexical POSIX path")

    return path.rstrip("/") or "/"


def UniqueFields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate keys even in ignored fields without including their values in errors.

    Args:
        pairs: Original JSON object entries from the standard decoder.

    Returns:
        Mapping retaining every unique entry for bounded selection.
    """

    fields: dict[str, object] = {}

    for key, value in pairs:
        if key in fields:
            raise ValueError("Docker inspect JSON contains a duplicate key")

        fields[key] = value

    return fields


def RejectConstant(value: str) -> None:
    """Refuse non-standard JSON numeric constants without repeating the source value.

    Args:
        value: Standard decoder's rejected non-finite token.

    Raises:
        ValueError: JSON numeric constants are outside this input profile.
    """

    raise ValueError("Docker inspect JSON cannot contain non-finite constants")


def FiniteFloat(value: str) -> float:
    """Reject overflowed JSON number notation even in unselected provider fields.

    Args:
        value: Original finite-number token supplied by the JSON decoder.

    Returns:
        Finite numeric value used only by subsequent bounded selection.
    """

    number = float(value)

    if not math.isfinite(number):
        raise ValueError("Docker inspect JSON cannot contain non-finite numbers")

    return number


def Decode(raw: bytes, limits: DockerInventoryLimits) -> list[dict[str, object]]:
    """Parse original bounded bytes with fixed depth/node/string limits before interpretation.

    Args:
        raw: Exact original evidence bytes verified by the evidence owner.
        limits: Explicit immutable positive collection/byte budgets.

    Returns:
        Nonempty list of unique full-ID container records.
    """

    if not 1 <= len(raw) <= limits.max_bytes:
        raise ValueError("Docker inspect bytes exceed the source budget")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=UniqueFields,
                           parse_constant=RejectConstant, parse_float=FiniteFloat)

    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("Docker inspect source must be complete bounded UTF-8 JSON") from None

    pending = [(value, 0)]
    nodes = 0

    while pending:
        item, depth = pending.pop()
        nodes += 1

        if depth > 24 or nodes > 20000:
            raise ValueError("Docker inspect source exceeds its depth/node budget")

        if isinstance(item, dict):
            pending.extend((entry, depth + 1) for entry in item.values())
            pending.extend((key, depth + 1) for key in item)

        elif isinstance(item, list):
            pending.extend((entry, depth + 1) for entry in item)

        elif isinstance(item, str):
            Text(item)

    records = [Fields(item) for item in Items(value, limits.max_containers)]
    identifiers = [FullId(item.get("Id")) for item in records]

    if not records or len(set(identifiers)) != len(identifiers):
        raise ValueError("Docker inspect requires nonempty unique containers")

    return sorted(records, key=lambda item: cast(str, item["Id"]))


class InventoryBatch:
    """Build one validated in-memory model batch, leaving authoritative stores with their owners."""

    def __init__(self, state: ModelState, provenance: ModelProvenance) -> None:
        """Retain the typed model basis and exact acquisition attribution.

        Args:
            state: Existing canonical workspace snapshot.
            provenance: Fully verified model/evidence binding.
        """

        self.state = state
        self.provenance = provenance
        self.objects: dict[str, SecurityObject] = {}
        self.relations: dict[str, Relation] = {}
        self.observations: list[Observation] = []
        self.findings: list[Finding] = []

    def Object(self, identity: ObjectIdentity, attributes: Mapping[str, object]) -> SecurityObject:
        """Build supplied facts while canonical Apply preserves existing interpretation fields.

        Args:
            identity: Typed canonical natural identity.
            attributes: Whitelisted non-secret interpretation.

        Returns:
            Validated immutable model object retained for batch application.
        """

        entity = SecurityObject(identity, attributes, (self.provenance,))
        previous = self.objects.get(entity.Reference())

        if previous is not None and previous.attributes != entity.attributes:
            raise ValueError("Docker inventory shared identity has contradictory selected facts")

        self.objects[entity.Reference()] = entity
        self.observations.append(Observation("docker-inspect-fact", entity.Reference(),
                                             attributes, self.provenance))

        return entity

    def Asset(self, key: str, attributes: Mapping[str, object]) -> SecurityObject:
        """Use existing ASSET identities for container/network/resource provider subtypes.

        Args:
            key: Domain-separated host-scoped natural identity.
            attributes: Whitelisted provider-owned subtype facts.

        Returns:
            Validated attributed asset.
        """

        return self.Object(ObjectIdentity(self.state.workspace_id, ObjectKind.ASSET, key),
                           attributes)

    def Edge(self, source: str, target: str, association: str,
             attributes: Mapping[str, object] | None = None,
             kind: RelationKind = RelationKind.RELATED_TO) -> None:
        """Retain explicit source associations without issuing network reachability assertions.

        Args:
            source: Existing or batch source object reference.
            target: Existing or batch target object reference.
            association: Fixed profile meaning for this configured association.
            attributes: Optional selected non-secret association facts.
            kind: Existing canonical relation kind.
        """

        fields = {"association": association, "basis": "supplied-inspect", **(attributes or {})}
        relation = Relation(kind, source, target, fields, (self.provenance,))
        previous = self.relations.get(relation.Reference())

        if previous is not None and association == "configured-mount":
            entries = [*cast(tuple[object, ...], previous.attributes["mounts"]),
                       *cast(list[object], fields["mounts"])]
            fields["mounts"] = sorted(entries, key=CanonicalModelJson)
            relation = Relation(kind, source, target, fields, (self.provenance,))

        if previous is not None and previous.attributes != relation.attributes:
            if association != "configured-mount":
                raise ValueError("Docker inventory association has contradictory selected facts")

        self.relations[relation.Reference()] = relation
        self.observations.append(Observation("docker-inspect-association", relation.Reference(),
                                             fields, self.provenance))

    def Finding(self, container: SecurityObject, check: str, location: str,
                summary: str, severity: FindingSeverity) -> None:
        """Describe one direct configured condition without changing triage or proving exploitation.

        Args:
            container: Existing validated container subject.
            check: Fixed first-party check identifier suffix.
            location: Stable selected source location.
            summary: Fixed advisory text without provider values.
            severity: Explicit configured-condition severity.
        """

        self.findings.append(Finding(container.Reference(), f"docker.configured.{check}", location,
            summary, (self.provenance,), severity, 1.0))


def Container(batch: InventoryBatch, record: dict[str, object], host: str,
              limits: DockerInventoryLimits) -> None:
    """Normalize one selected record and its direct configuration conditions without live access.

    Args:
        batch: Verified in-memory batch builder.
        record: Complete selected container inspect object.
        host: Existing explicit literal HOST reference.
        limits: Byte/collection budgets already validated by the input boundary.
    """

    identifier = FullId(record.get("Id"))
    image_identity = ImageIdentity(cast(str, record.get("Image")))
    image = batch.Object(image_identity.Object(batch.state.workspace_id),
        {"asset_type": "image", "digest": image_identity.digest, "digest_kind": "config"})
    config = OptionalFields(record.get("Config"))
    host_config = OptionalFields(record.get("HostConfig"))
    state = OptionalFields(record.get("State"))
    health = OptionalFields(state.get("Health"))
    settings = OptionalFields(record.get("NetworkSettings"))
    fields: dict[str, object] = {
        "asset_type": "container", "provider": _SOURCE_ID, "container_id": identifier,
        "host_reference": host, "image_reference": image.Reference(),
        "user_category": UserCategory(config.get("User")),
        "privileged": OptionalBool(host_config.get("Privileged")),
        "readonly_rootfs": OptionalBool(host_config.get("ReadonlyRootfs")),
        "cap_add": Capabilities(host_config.get("CapAdd")),
        "cap_drop": Capabilities(host_config.get("CapDrop")),
        "pid_mode": Namespace(host_config.get("PidMode")),
        "ipc_mode": Namespace(host_config.get("IpcMode")),
        "userns_mode": Namespace(host_config.get("UsernsMode")),
        "network_mode": Namespace(host_config.get("NetworkMode")),
        "reported_running": OptionalBool(state.get("Running")),
        "reported_status": Choice(state.get("Status"),
            {"created", "running", "paused", "restarting", "removing", "exited", "dead"}),
        "reported_health": Choice(health.get("Status"), {"starting", "healthy", "unhealthy"}),
        "mount_count": None if record.get("Mounts") is None else len(
            Items(record["Mounts"], limits.max_mounts)),
        "network_count": None if settings.get("Networks") is None else len(
            Fields(settings["Networks"])),
        "port_count": None if settings.get("Ports") is None else len(Fields(settings["Ports"])),
    }
    container = batch.Asset(f"docker-container:{host}:{identifier}", fields)
    batch.Edge(host, container.Reference(), "reported-host-container", kind=RelationKind.CONTAINS)
    batch.Edge(image.Reference(), container.Reference(), "configured-image-use")

    if fields["privileged"] is True:
        batch.Finding(container, "privileged", "HostConfig.Privileged",
            "Container is configured in privileged mode; effective access is unverified.",
            FindingSeverity.HIGH)

    if fields["user_category"] == "root":
        batch.Finding(container, "root-user", "Config.User",
            "Container user is configured as root; effective UID and mapping are unverified.",
            FindingSeverity.LOW)

    for name in ("pid_mode", "ipc_mode", "userns_mode", "network_mode"):
        if fields[name] == "host":
            batch.Finding(container, "host-" + name.replace("_mode", ""), "HostConfig." + name,
                "Container uses a configured host namespace; physical isolation is unverified.",
                FindingSeverity.MEDIUM)

    if fields["cap_add"] is not None and _POWERFUL.intersection(cast(list[str], fields["cap_add"])):
        batch.Finding(container, "powerful-capability", "HostConfig.CapAdd",
            "Container configuration adds a powerful capability; effective access is unverified.",
            FindingSeverity.HIGH)

    Networks(batch, container, settings.get("Networks"), host, limits)
    Ports(batch, container, settings.get("Ports"), host, identifier, limits)
    Mounts(batch, container, record.get("Mounts"), host, limits)


def Networks(batch: InventoryBatch, container: SecurityObject, value: object,
             host: str, limits: DockerInventoryLimits) -> None:
    """Retain reported network membership and literal assigned addresses without DNS or probing.

    Args:
        batch: Verified candidate builder.
        container: Owning selected container object.
        value: Docker NetworkSettings.Networks section or unknown.
        host: Explicit host identity reference.
        limits: Per-container collection ceilings.
    """

    if value is None:
        return

    networks = Fields(value)

    if len(networks) > limits.max_networks:
        raise ValueError("Docker inventory network collection exceeds its budget")

    for name in sorted(networks):
        fields = Fields(networks[name])
        identifier = FullId(fields.get("NetworkID"))
        network = batch.Asset(f"docker-network:{host}:{identifier}",
            {"asset_type": "container-network", "provider": _SOURCE_ID,
             "network_id": identifier, "host_reference": host})
        batch.Edge(container.Reference(), network.Reference(), "reported-network-membership",
            {"ipv4_address": Address(fields.get("IPAddress"), 4),
             "ipv6_address": Address(fields.get("GlobalIPv6Address"), 6)})


def Ports(batch: InventoryBatch, container: SecurityObject, value: object,
          host: str, identifier: str, limits: DockerInventoryLimits) -> None:
    """Model configured port declarations and bindings without inferring listening/reachability.

    Args:
        batch: Verified candidate builder.
        container: Owning selected container.
        value: Docker NetworkSettings.Ports section or unknown.
        host: Explicit host reference, never a socket connection destination.
        identifier: Full selected container identity.
        limits: Per-container collection ceilings.
    """

    if value is None:
        return

    ports = Fields(value)

    if len(ports) > limits.max_ports:
        raise ValueError("Docker inventory port collection exceeds its budget")

    for name in sorted(ports):
        match = _PORT.fullmatch(name)

        if match is None:
            raise ValueError("Docker inventory port declaration is unsupported")

        port = Integer(int(match[1]), 65535)
        bindings: list[dict[str, object]] | None = None

        if ports[name] is not None:
            bindings = []

            for item in Items(ports[name], 16):
                binding = Fields(item)
                host_port = Text(binding.get("HostPort"), 5)

                if not re.fullmatch(r"[1-9][0-9]{0,4}", host_port):
                    raise ValueError("Docker inventory host port must be a positive decimal port")

                bindings.append({"host_address": Address(binding.get("HostIp")),
                                 "host_port": Integer(int(host_port), 65535)})

            encoded = [CanonicalModelJson(item) for item in bindings]

            if len(set(encoded)) != len(encoded):
                raise ValueError("Docker inventory port bindings must be unique")

            bindings.sort(key=CanonicalModelJson)

        service = batch.Object(ObjectIdentity(batch.state.workspace_id, ObjectKind.SERVICE,
            f"docker-container-port:{host}:{identifier}:{name}"),
            {"provider": _SOURCE_ID, "service_type": "configured-container-port",
             "container_port": port, "transport": match[2], "host_bindings": bindings})
        batch.Edge(container.Reference(), service.Reference(), "configured-port-declaration")


def Mounts(batch: InventoryBatch, container: SecurityObject, value: object,
           host: str, limits: DockerInventoryLimits) -> None:
    """Retain lexical mount relationships and direct risky source-path configuration facts.

    Args:
        batch: Verified candidate builder.
        container: Owning selected container.
        value: Complete selected mount array or unknown.
        host: Explicit host reference used for resource identity separation.
        limits: Per-container collection ceilings.
    """

    if value is None:
        return

    destinations: set[str] = set()

    for item in Items(value, limits.max_mounts):
        fields = Fields(item)
        mount_type = Choice(fields.get("Type"), {"bind", "volume", "tmpfs"})

        if mount_type is None:
            raise ValueError("Docker inventory mounts require an explicit known type")

        destination = MountPath(fields.get("Destination"))

        if destination in destinations:
            raise ValueError("Docker inventory mount destinations must be unique")

        destinations.add(destination)
        source = MountPath(fields.get("Source")) if mount_type == "bind" else None
        volume = Text(fields.get("Name"), 128) if mount_type == "volume" else None

        if volume is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", volume):
            raise ValueError("Docker inventory volume name is unsupported")

        natural = {"host": host, "type": mount_type, "source": source, "volume": volume,
                   "container": container.Reference() if mount_type == "tmpfs" else None,
                   "destination": destination if mount_type == "tmpfs" else None}
        digest = hashlib.sha256(CanonicalModelJson(natural)).hexdigest()
        resource = batch.Asset("docker-mount-resource:" + digest,
            {"asset_type": "container-mount-source", "mount_type": mount_type,
             "source_path": source, "volume_name": volume, "host_reference": host})
        batch.Edge(container.Reference(), resource.Reference(), "configured-mount",
            {"mounts": [{"destination": destination,
                         "read_write": OptionalBool(fields.get("RW"))}]})

        if source in _SOCKETS:
            batch.Finding(container, "management-socket-mount", "Mounts:" + destination,
                "Container binds a configured management socket; daemon access is unverified.",
                FindingSeverity.HIGH)

        if source in _SENSITIVE:
            batch.Finding(container, "sensitive-bind-mount", "Mounts:" + destination,
                "Container binds a configured sensitive host path; effective access is unverified.",
                FindingSeverity.MEDIUM)


class BoundedInspectStore(LocalEvidenceStore):
    """Admit the actual parsed owner reference before Get eagerly reads any substituted blob."""

    def __init__(self, root: Path, maximum: int) -> None:
        """Retain one owned evidence root and validated byte budget.

        Args:
            root: Existing operator-owned workspace evidence directory.
            maximum: Inclusive configured original-byte ceiling.
        """

        super().__init__(root)
        self.maximum = maximum

    def Read(self, reference: EvidenceReference) -> bytes:
        """Check the manifest's actual role, media type and byte limit before owner integrity reads.

        Args:
            reference: Actual parsed or explicitly supplied immutable evidence reference.

        Returns:
            Original exact bytes verified by the unchanged evidence owner.
        """

        if not isinstance(reference, EvidenceReference) or reference.role != "docker-inspect" or (
            reference.media_type != "application/json"
        ):
            raise ValueError("Docker inventory evidence requires its exact JSON role")

        Integer(reference.size_bytes, self.maximum)

        return super().Read(reference)


def ApplyVerifiedDockerInspect(
    state: ModelState, record: EvidenceRecord, provenance: ModelProvenance, *,
    host_reference: str, workspace_root: Path,
    limits: DockerInventoryLimits = DockerInventoryLimits(),
) -> tuple[ModelState, ModelDelta]:
    """Apply one bounded owned offline inspect profile through existing evidence/model contracts.

    Args:
        state: Canonical model snapshot belonging to the explicit workspace.
        record: Original immutable docker-inspect/application-json evidence manifest.
        provenance: Exact matching source/scope/version/time/raw-reference attribution.
        host_reference: Existing caller-supplied literal HOST reference; no host is discovered.
        workspace_root: Existing operator-owned workspace used through its storage owners.
        limits: Explicit positive source/collection ceilings, never a partial-success option.

    Returns:
        Fully validated in-memory transition and delta ready for LocalModelStore.Save.
        Exact replay is a no-op; detector refresh preserves existing finding triage.

    Raises:
        ValueError: Shape, bounds, host, provenance, source identity or selected facts are invalid.
        EvidenceError: Original owning manifest/blob is missing, corrupt or unsafe.
        OSError: Workspace metadata cannot be read.

    This function performs only explicit owning reads. It never connects to Docker,
    discovers sockets, executes commands, writes storage or asserts physical reachability.
    """

    if type(state) is not ModelState or type(record) is not EvidenceRecord or (
        type(provenance) is not ModelProvenance or type(limits) is not DockerInventoryLimits
    ):
        raise ValueError("Docker inventory requires typed model, evidence, provenance and limits")

    limits = DockerInventoryLimits(limits.max_bytes, limits.max_containers, limits.max_networks,
                                   limits.max_ports, limits.max_mounts)
    provenance = ModelProvenance(provenance.source_id, provenance.run_reference,
        provenance.observed_at, provenance.scope_reference, provenance.target_reference,
        provenance.provider_version, provenance.evidence_references, provenance.execution)
    state = ModelState.FromDict(state.ToDict())
    host = RequireModelReference(host_reference)
    entity = next((item for item in state.objects if item.Reference() == host), None)

    if entity is None or entity.identity.kind is not ObjectKind.HOST:
        raise ValueError("Docker inventory requires an existing explicit literal HOST")

    workspace = LocalWorkspaceStore(workspace_root)

    if workspace.Open().workspace_id != state.workspace_id:
        raise ValueError("Docker inventory belongs to another workspace")

    source = record.provenance

    if source.workspace_id != state.workspace_id or source.source_id != _SOURCE_ID or (
        source.source_version != _SOURCE_VERSION
        or source.scope_reference != provenance.scope_reference
        or source.source_id != provenance.source_id
        or source.tool_version != provenance.provider_version
        or source.finished_at != provenance.observed_at
        or source.invocation_sha256 is not None or source.execution is not None
        or provenance.execution is not None or provenance.target_reference != host
        or provenance.evidence_references != (record.reference,)
    ):
        raise ValueError("Docker inventory attribution differs from its offline source profile")

    store = BoundedInspectStore(workspace.root / "evidence", limits.max_bytes)
    Integer(record.reference.size_bytes, limits.max_bytes)

    if store.Get(record.evidence_id) != record:
        raise ValueError("Docker inventory evidence differs from its immutable owning manifest")

    containers = Decode(store.Read(record.reference), limits)
    batch = InventoryBatch(state, provenance)

    for container in containers:
        Container(batch, container, host, limits)

    return ApplyBatch(state, list(batch.objects.values()), list(batch.relations.values()),
                      batch.observations, batch.findings, workspace.root)
