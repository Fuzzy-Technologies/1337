# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise owned Docker inventory parser, source integrity and configured-condition boundaries."""

from __future__ import annotations

from dataclasses import replace
from traceback import format_exception

import pytest

from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.docker_inventory import ApplyVerifiedDockerInspect, DockerInventoryLimits
from fuzzy1337.evidence import EvidenceError, EvidenceRecord
from fuzzy1337.findings import Findings
from fuzzy1337.images import ImageIdentity
from fuzzy1337.model import LocalModelStore, ModelProvenance, ObjectKind
from tests.docker_helpers import Acquire, OwnedContext, Payload


@pytest.fixture
def context(tmp_path):
    """Create only owned first-party evidence/model stores without Docker or network access."""

    return OwnedContext(tmp_path / "workspace")


def Apply(context, record=None, provenance=None, **kwargs):
    """Call the production importer with actual acquired bytes and explicit owning context.

    Args:
        context: Existing synthetic storage owners.
        record: Explicit acquired or hostile evidence record.
        provenance: Matching or hostile attribution.
        kwargs: Explicit public import options.

    Returns:
        Real in-memory model transition and delta.
    """

    root, state, host, _ = context

    if record is None:
        record, provenance = Acquire(context)

    return ApplyVerifiedDockerInspect(state, record, provenance,
        host_reference=host.Reference(), workspace_root=root, **kwargs)


def Change(payload, path, value):
    """Substitute an explicitly selected fixture field independently of production validation.

    Args:
        payload: Isolated handwritten mutable fixture document.
        path: Explicit nested dictionary/list path.
        value: Hostile or alternative synthetic input.
    """

    current = payload

    for component in path[:-1]:
        current = current[component]

    current[path[-1]] = value


@pytest.mark.parametrize(("path", "value"), [
    ((0, "Id"), "short"), ((0, "Image"), "owned:tag"), ((0, "Config"), []),
    ((0, "HostConfig"), []), ((0, "HostConfig", "Privileged"), 1),
    ((0, "HostConfig", "ReadonlyRootfs"), "false"),
    ((0, "HostConfig", "CapAdd"), "SYS_ADMIN"),
    ((0, "HostConfig", "CapAdd"), ["SYS_ADMIN", "CAP_SYS_ADMIN"]),
    ((0, "HostConfig", "CapDrop"), ["UNKNOWN_CAPABILITY"]),
    ((0, "HostConfig", "PidMode"), "container:short"),
    ((0, "HostConfig", "NetworkMode"), "invalid/mode"),
    ((0, "Config", "User"), False), ((0, "Config", "User"), "invalid\nname"),
    ((0, "State"), []), ((0, "State", "Running"), 1),
    ((0, "State", "Status"), "invented"), ((0, "State", "Health"), []),
    ((0, "State", "Health", "Status"), "invented"),
    ((0, "NetworkSettings"), []), ((0, "NetworkSettings", "Networks"), []),
    ((0, "NetworkSettings", "Networks", "owned-network", "NetworkID"), "short"),
    ((0, "NetworkSettings", "Networks", "owned-network", "IPAddress"), "owned.invalid"),
    ((0, "NetworkSettings", "Networks", "owned-network", "IPAddress"), "::1"),
    ((0, "NetworkSettings", "Networks", "owned-network", "GlobalIPv6Address"), "192.0.2.2"),
    ((0, "NetworkSettings", "Networks", "owned-network", "GlobalIPv6Address"), "fe80::1%eth0"),
    ((0, "NetworkSettings", "Ports"), []),
    ((0, "NetworkSettings", "Ports"), {"0/tcp": []}),
    ((0, "NetworkSettings", "Ports"), {"65536/tcp": []}),
    ((0, "NetworkSettings", "Ports"), {"80/unknown": []}),
    ((0, "NetworkSettings", "Ports", "80/tcp"), {}),
    ((0, "NetworkSettings", "Ports", "80/tcp", 0, "HostPort"), "0"),
    ((0, "NetworkSettings", "Ports", "80/tcp", 0, "HostPort"), "65536"),
    ((0, "NetworkSettings", "Ports", "80/tcp", 0, "HostIp"), "owned.invalid"),
    ((0, "Mounts"), {}), ((0, "Mounts", 0, "Type"), "image"),
    ((0, "Mounts", 0, "Type"), None), ((0, "Mounts", 0, "Source"), "relative"),
    ((0, "Mounts", 0, "Source"), "/a/../b"),
    ((0, "Mounts", 0, "Source"), "/a//b"),
    ((0, "Mounts", 0, "Source"), "/a\\b"),
    ((0, "Mounts", 0, "RW"), 1), ((0, "Mounts", 2, "Name"), "bad/volume"),
])
def test_MalformedSelectedFactsFailWithoutModelMutation(context, path, value):
    """Every selected hostile fact is denied before any authoritative model write."""

    payload = Payload()
    Change(payload, path, value)
    record, provenance = Acquire(context, payload)

    with pytest.raises(ValueError):
        Apply(context, record, provenance)

    assert LocalModelStore(context[0]).Open() == context[1], "Rejected input mutated owner model"


@pytest.mark.parametrize("raw", [
    b"", b"[", b"[{}", b"\xff", b"{}", b"[]", b"[null]",
    b'[{"Id":"a","Id":"b"}]', b'[{"ignored":NaN}]', b'[{"ignored":1e999}]',
    b'[{"ignored":"\\ud800"}]', b"[" * 1001 + b"0" + b"]" * 1001,
])
def test_InvalidOriginalSourcesFailClosed(context, raw):
    """Truncated, malformed, duplicate, non-finite and invalid UTF-8 sources never import."""

    record, provenance = Acquire(context, raw)

    with pytest.raises(ValueError):
        Apply(context, record, provenance)


@pytest.mark.parametrize("field", ["max_bytes", "max_containers", "max_networks",
                                  "max_ports", "max_mounts"])
@pytest.mark.parametrize("value", [0, False, 1024 * 1024 + 1, 1.0])
def test_QuotaConstructorsRejectInvalidRuntimeTypesAndCeilings(field, value):
    """Public resource budgets reject booleans/coercion and values outside fixed ceilings."""

    with pytest.raises(ValueError):
        DockerInventoryLimits(**{field: value})


@pytest.mark.parametrize("limits", [DockerInventoryLimits(max_bytes=20),
    DockerInventoryLimits(max_containers=1), DockerInventoryLimits(max_ports=1),
    DockerInventoryLimits(max_mounts=1)])
def test_ExplicitBudgetsDoNotConvertExcessIntoPartialSuccess(context, limits):
    """Source and collection ceilings deny the whole input rather than truncating its inventory."""

    with pytest.raises(ValueError):
        Apply(context, limits=limits)


def test_NetworkNodeDepthAndStringBudgetsAreActuallyEnforced(context):
    """Selected networks and unselected parser material all remain bounded."""

    documents = []
    payload = Payload()
    payload[0]["NetworkSettings"]["Networks"]["second"] = {
        "NetworkID": "e" * 64, "IPAddress": "192.0.2.30"}
    documents.append((payload, DockerInventoryLimits(max_networks=1)))
    payload = Payload()
    payload[0]["ignored"] = [0] * 20000
    documents.append((payload, DockerInventoryLimits()))
    payload = Payload()
    nested = 0

    for _ in range(26):
        nested = [nested]

    payload[0]["ignored"] = nested
    documents.append((payload, DockerInventoryLimits()))
    payload = Payload()
    payload[0]["ignored"] = "x" * 4097
    documents.append((payload, DockerInventoryLimits()))

    for payload, limits in documents:
        record, provenance = Acquire(context, payload)

        with pytest.raises(ValueError):
            Apply(context, record, provenance, limits=limits)


@pytest.mark.parametrize("changes", [
    {"workspace_id": "foreign"}, {"source_id": "foreign.source"}, {"source_version": "2"},
    {"invocation_sha256": "a" * 64},
    {"execution": AdapterExecution(ExecutionState.SUCCEEDED, 0, 1)},
    {"execution": AdapterExecution(ExecutionState.TIMED_OUT, None, 1)},
    {"execution": AdapterExecution(ExecutionState.FAILED, 1, 1)},
])
def test_OfflineImportsRefuseForeignUnsupportedOrExecutedSourceClaims(context, changes):
    """Offline bytes cannot acquire execution or foreign-source authority."""

    record, provenance = Acquire(context, source_changes=changes)

    with pytest.raises(ValueError):
        Apply(context, record, provenance)


@pytest.mark.parametrize("changes", [
    {"source_id": "foreign.source"}, {"scope_reference": "scope:foreign"},
    {"provider_version": "foreign-version"}, {"target_reference": "target:foreign"},
    {"observed_at": "2026-10-14T09:00:01Z"}, {"evidence_references": ()},
    {"execution": AdapterExecution(ExecutionState.SUCCEEDED, 0, 1)},
])
def test_ModelAttributionMustMatchExactOriginalAcquisition(context, changes):
    """Matching bytes never allow a changed scope/source/time/version/host join."""

    record, provenance = Acquire(context)

    with pytest.raises(ValueError):
        Apply(context, record, replace(provenance, **changes))


@pytest.mark.parametrize(("role", "media_type"), [("stdout", "application/json"),
    ("docker-inspect", "text/plain")])
def test_RawRoleAndMediaTypeAreExact(context, role, media_type):
    """Alternate evidence roles/media cannot masquerade as the explicit inspect source profile."""

    record, provenance = Acquire(context, role=role, media_type=media_type)

    with pytest.raises(ValueError):
        Apply(context, record, provenance)


def test_OwningManifestCannotBeReplacedByMatchingBytesOrForgedProvenance(context):
    """Original blob presence alone never proves an invented evidence-manifest attribution."""

    record, provenance = Acquire(context)
    forged = EvidenceRecord(record.reference, replace(record.provenance,
        started_at="2026-10-14T08:59:59Z"))

    with pytest.raises(EvidenceError):
        Apply(context, forged, provenance)

    manifest = context[0] / "evidence" / "records" / (record.evidence_id[7:] + ".json")
    manifest.unlink()

    with pytest.raises(EvidenceError):
        Apply(context, record, provenance)


def test_CorruptOriginalBlobIsNotAcceptedAsCompleteRuntimeFacts(context):
    """Raw-byte digest mismatch fails through the actual unchanged evidence owner."""

    record, provenance = Acquire(context)
    path = context[0] / "evidence" / record.reference.locator
    path.write_bytes(path.read_bytes()[:-1])

    with pytest.raises(EvidenceError):
        Apply(context, record, provenance)


def test_DuplicateContainerMountAndBindingIdentitiesAreRefused(context):
    """Contradictory or duplicate producer identities cannot overwrite earlier batch entries."""

    payloads = []
    payload = Payload()
    payload[1]["Id"] = payload[0]["Id"]
    payloads.append(payload)
    payload = Payload()
    payload[0]["Mounts"][1]["Destination"] = payload[0]["Mounts"][0]["Destination"]
    payloads.append(payload)
    payload = Payload()
    payload[0]["NetworkSettings"]["Ports"]["80/tcp"] *= 2
    payloads.append(payload)

    for payload in payloads:
        record, provenance = Acquire(context, payload)

        with pytest.raises(ValueError):
            Apply(context, record, provenance)


def test_ForgedFrozenQuotaFieldsAndSubclassOverridesFailBeforeOwnerReads(context, monkeypatch):
    """Typed runtime inputs cannot bypass the fixed budgets through mutation or inherited guards."""

    class RelaxedLimits(DockerInventoryLimits):
        """Deliberately hostile typed subclass skipping the real quota constructor."""

        def __post_init__(self):
            """Skip the guarded base constructor for the negative boundary probe."""

            return None

    record, provenance = Acquire(context)
    forged = DockerInventoryLimits()
    object.__setattr__(forged, "max_bytes", 1024 * 1024 + 1)

    def RefuseRead(*args, **kwargs):
        """Fail if invalid quota validation reaches the actual storage owner.

        Args:
            args: Attempted owning read arguments.
            kwargs: Attempted owning read options.
        """

        raise AssertionError("Invalid quota reached owning reads")

    monkeypatch.setattr("fuzzy1337.docker_inventory.LocalWorkspaceStore.Open", RefuseRead)

    for limits in (forged, RelaxedLimits(max_bytes=1024 * 1024 + 1)):
        with pytest.raises(ValueError):
            Apply(context, record, provenance, limits=limits)


def test_ErrorRenderingNeverCopiesAnUnselectedOwnedPrivateMarker(context):
    """Ignored provider fields and malformed-address errors do not leak original source values."""

    marker = "OWNED_PRIVATE_SOURCE_MARKER"
    payload = Payload()
    payload[0]["Config"]["Labels"] = {"unselected": marker}
    payload[0]["Config"]["Cmd"] = [marker]
    record, provenance = Acquire(context, payload)
    state, _ = Apply(context, record, provenance)
    assert marker not in repr(state), "Unselected provider values leaked into normalized metadata"
    payload[0]["NetworkSettings"]["Networks"]["owned-network"]["IPAddress"] = marker
    record, provenance = Acquire(context, payload)

    with pytest.raises(ValueError) as failure:
        Apply(context, record, provenance)

    rendered = "".join(format_exception(failure.value))
    assert marker not in rendered, "Rejected source value leaked through exception rendering"


def test_MalformedTypedAttributionIsRejectedBeforeOwningReadsOrPersistedState(context, monkeypatch):
    """Subclass-skipped and forged frozen provenance cannot produce an unreadable saved model."""

    class RelaxedProvenance(ModelProvenance):
        """Deliberately hostile subclass that bypasses canonical provenance invariants."""

        def __post_init__(self):
            """Skip the guarded provenance constructor only for the negative probe."""

            return None

    record, provenance = Acquire(context)
    fields = {name: getattr(provenance, name) for name in (
        "source_id", "run_reference", "observed_at", "scope_reference", "target_reference",
        "provider_version", "evidence_references", "execution")}
    fields["run_reference"] = ""
    malformed = RelaxedProvenance(**fields)
    forged = replace(provenance)
    object.__setattr__(forged, "run_reference", "")
    original = context[1]

    def RefuseRead(*args, **kwargs):
        """Trip if malformed typed attribution reaches the explicit storage owner.

        Args:
            args: Attempted owning read arguments.
            kwargs: Attempted owning read options.
        """

        raise AssertionError("Malformed attribution reached owning reads")

    with monkeypatch.context() as guard:
        guard.setattr("fuzzy1337.docker_inventory.LocalWorkspaceStore.Open", RefuseRead)

        for candidate in (malformed, forged):
            with pytest.raises(ValueError):
                Apply(context, record, candidate)

    assert LocalModelStore(context[0]).Open() == original, "Malformed attribution changed state"


@pytest.mark.parametrize(("user", "category", "root"), [
    ("", "root", True), ("root", "root", True), ("000:1000", "root", True),
    ("1000:1000", "numeric-nonroot", False), ("owned-user", "named", False),
    (None, None, False),
])
def test_UserCategoriesPreserveConfiguredIntentWithoutEffectiveUidClaims(context, user,
                                                                        category, root):
    """Named users stay unresolved; root detection never asserts actual namespace/effective UID."""

    payload = Payload()
    payload[0]["Config"]["User"] = user
    record, provenance = Acquire(context, payload)
    state, _ = Apply(context, record, provenance)
    container = next(item for item in state.objects
        if item.attributes.get("container_id") == "a" * 64)
    assert container.attributes["user_category"] == category, "User intent was misclassified"
    detected = any(item.check_id == "docker.configured.root-user" for item in Findings(state))
    assert detected is root, "Configured root check differs from the independent user oracle"


def test_ConfigAndManifestDigestsKeepTheirExistingSeparateIdentityDomains(context):
    """Config digest must equal existing ImageIdentity with a separate manifest identity."""

    state, _ = Apply(context)
    digest = "sha256:" + "d" * 64
    expected = ImageIdentity(digest, "config").Object(state.workspace_id)
    manifest = ImageIdentity(digest, "manifest").Object(state.workspace_id)
    images = [item for item in state.Objects(ObjectKind.ASSET)
              if item.attributes.get("asset_type") == "image"]
    assert [item.identity for item in images] == [expected], "Config image correlation broke"
    assert images[0].Reference() != manifest.Reference(), "Config and manifest domains conflated"
