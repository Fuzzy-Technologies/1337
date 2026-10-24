# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Native authority units use controlled proof/provider doubles, never genuine engine acceptance."""

from __future__ import annotations

import asyncio
import os
import shutil
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from fuzzy1337 import artifact_inputs
from fuzzy1337 import native_image_policy as native
from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.artifact_policy import (
    ArtifactDeniedError,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
)
from fuzzy1337.executors import LocalExecutionRequest
from fuzzy1337.native_image_bounded_capture import CaptureBoundedNativeTrivyOperation
from fuzzy1337.native_image_capture import NativeTrivyOperation, NativeTrivySelection
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scope import AuthorizationState, LocalScopeStore, ScopeAuthorization, ScopeSnapshot
from tests.unit.test_native_image_bounded_capture import collector as collector
from tests.unit.test_native_image_material_worker import material_control as material_control
from tests.unit.test_native_image_observation import observation_runner as observation_runner
from tests.unit.test_native_image_observation import simulated_observer as simulated_observer

AT = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)


def ControlIdentityView(info, **changes):
    """Retain a real owned metadata observation with explicitly selected unit-view changes."""

    fields = {name: getattr(info, name) for name in (
        "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink",
    )}
    fields.update(changes)

    return SimpleNamespace(**fields)


@pytest.fixture
def private_control(tmp_path, monkeypatch):
    """Prepare inert private controls before applying any isolated cross-view matching seam."""

    path = tmp_path / "control.json"

    if os.name == "nt":
        selected_os = SimpleNamespace(**vars(os))
        selected_os.fchmod = lambda descriptor, mode: None
        monkeypatch.setattr(native, "os", selected_os)
        monkeypatch.setattr(native, "stat", SimpleNamespace(S_IMODE=lambda mode: 0o600))
        monkeypatch.setattr(native, "SyncDirectory", lambda directory: None)

    return path


def ControlMatcher(monkeypatch, windows):
    """Apply canonical view compatibility only while this policy read matches its own views."""

    original = native.MatchesArtifactReadIdentity

    def Match(path_info, handle_info):
        """Keep preparatory filesystem reads outside the unit's selected platform seam."""

        with monkeypatch.context() as selected:
            selected.setattr(artifact_inputs, "_WINDOWS_STAT_VIEWS", windows)

            return original(path_info, handle_info)

    monkeypatch.setattr(native, "MatchesArtifactReadIdentity", Match)


@pytest.mark.parametrize("operation", ["read", "write"])
@pytest.mark.parametrize("windows", [False, True], ids=["strict-posix", "windows-views"])
def test_PrivateControlRetainsPathIdentityAcrossSeparateStableCtimeViews(
    private_control, monkeypatch, operation, windows,
):
    """Only canonical Windows cross-API matching accepts two stable distinct ctime views."""

    path = private_control
    raw = b'{"owned":true}'

    if operation == "read":
        path.write_bytes(raw)
        path.chmod(0o600)

    original_handle = native.ArtifactHandleInfo

    def Handle(descriptor):
        """Expose a stable distinct handle ctime without changing the original path observation."""

        info = original_handle(descriptor)

        return ControlIdentityView(info, st_ctime_ns=info.st_ctime_ns + 1)

    monkeypatch.setattr(native, "ArtifactHandleInfo", Handle)
    ControlMatcher(monkeypatch, windows)

    def Exercise():
        """Read or create this exact control through the original owner without another payload."""

        if operation == "read":
            native.ReadControl(path, raw, native.PhysicalIdentity(native.ArtifactPathInfo(path)))

            return

        actual, identity = native.WriteControl(path, {"owned": True})
        assert actual == raw and identity == native.PhysicalIdentity(
            native.ArtifactPathInfo(path)), (
            "Immutable control identity must retain all original path fields, never handle ctime"
        )

    if not windows:
        with pytest.raises(ArtifactDeniedError):
            Exercise()

        return

    Exercise()


@pytest.mark.parametrize("operation", ["read", "write"])
@pytest.mark.parametrize("view", ["path", "handle"])
@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"])
def test_PrivateControlRejectsEverySameApiIdentityMutation(
    private_control, monkeypatch, operation, view, field,
):
    """Windows cross-view compatibility never accepts a mutation in either API's five fields."""

    path = private_control
    raw = b'{"owned":true}'

    if operation == "read":
        path.write_bytes(raw)
        path.chmod(0o600)

    original_path = native.ArtifactPathInfo
    original_handle = native.ArtifactHandleInfo
    identity = None if operation == "write" else native.PhysicalIdentity(original_path(path))
    calls = {"path": 0, "handle": 0}

    def Handle(descriptor):
        """Change only the selected second handle observation after a stable initial view."""

        info = original_handle(descriptor)
        info = ControlIdentityView(info, st_ctime_ns=info.st_ctime_ns + 1)
        calls["handle"] += 1

        return ControlIdentityView(info, **{field: getattr(info, field) + 1}) if (
            view == "handle" and calls["handle"] == 2) else info

    def PathInfo(selected_path, **options):
        """Change only the selected second path observation, without touching owned disk bytes."""

        info = original_path(selected_path, **options)

        if selected_path == path:
            calls["path"] += 1

            if view == "path" and calls["path"] == 2:
                return ControlIdentityView(info, **{field: getattr(info, field) + 1})

        return info

    monkeypatch.setattr(native, "ArtifactPathInfo", PathInfo)
    monkeypatch.setattr(native, "ArtifactHandleInfo", Handle)
    ControlMatcher(monkeypatch, True)

    with pytest.raises(ArtifactDeniedError):
        if operation == "write":
            native.WriteControl(path, {"owned": True})

        else:
            native.ReadControl(path, raw, identity)

    assert calls[view] == 2 and path.read_bytes() == raw, (
        "Full same-API mutation refusal must preserve the immutable original control bytes"
    )


@pytest.fixture
def authority(collector, monkeypatch):
    """Create registered canonical scope and policy around the original unit-only proof issuer."""

    root = collector.selection.workspace_root
    owner = collector.observer
    prepared = native.PrepareNativeImageOperation(NativeTrivyOperation.VERSION,
        collector.selection, collector.store, observer=owner, material_proof=collector.initial,
        operation_reference="pair:collector-unit")
    target = prepared.input_manifest.Target()
    scope = LocalScopeStore(root).Create(ScopeSnapshot("native-unit", owner.workspace_id,
        authorization=ScopeAuthorization(AuthorizationState.GRANTED, "attester:independent",
            "consent:owned-unit", AT.isoformat(), (AT + timedelta(hours=1)).isoformat()),
        targets=(target,), allow=(target,)))
    policy = ImpactPolicy("native-unit", permissions=(CapabilityPermission(
        "image.archive-vulnerabilities", "native.trivy", ImpactLevel.SAFE),))
    context = ArtifactPolicyContext(scope, policy, owner.owner_reference)
    engine = ArtifactPolicyEngine()
    arguments = {"observer": owner, "material_proof": collector.initial, "at": AT}

    if os.name == "nt":
        # These are portable protocol units, not actual Windows private-mode/fsync acceptance.
        selected_os = SimpleNamespace(**vars(os))
        selected_os.fchmod = lambda descriptor, mode: None
        monkeypatch.setattr(native, "os", selected_os)
        monkeypatch.setattr(native, "stat", SimpleNamespace(S_IMODE=lambda mode:
            0o700 if stat.S_ISDIR(mode) else 0o600))
        monkeypatch.setattr(native, "SyncDirectory", lambda path: None)

    def Grant(selected=prepared, *, proof=None, context_override=None, **changes):
        """Issue through the canonical engine with explicit native approval unless overridden."""

        options = dict(arguments, material_proof=collector.initial if proof is None else proof)
        options.update(changes)

        return engine.AuthorizeNativeImageOperation(selected, context_override or context,
            approve_safe_image=True, **options)

    def Claim(grant, selected=prepared, *, proof=None, **changes):
        """Reserve before this unit's controlled collector can check cancellation or setup."""

        options = dict(arguments, material_proof=collector.initial if proof is None else proof)
        options.update(changes)

        return engine.ClaimNativeImageExecution(grant, selected, context, **options)

    def Request(grant, selected=prepared, *, name="native-image-owned-unit"):
        """Create only the actual fixed collector request profile and explicit private scratch."""

        scratch = root / name
        scratch.mkdir(mode=0o700)

        return LocalExecutionRequest(selected.invocation, native.NATIVE_IMAGE_CAPABILITY,
            grant.authorization, name, native.NativeEnvironment(scratch), selected.resources)

    def Run(selected, grant, claim, proof):
        """Bind the fresh attempt's first callback unconditionally, then only validate."""

        first = True

        def Fresh(request):
            """Refresh current original scope/policy at every actual collector boundary."""

            nonlocal first
            options = {"observer": owner, "material_proof": proof, "at": AT}

            if first:
                engine.BindNativeImageRequest(claim, request, context, **options)
                first = False

            else:
                engine.ValidateNativeImageClaim(claim, request, context, **options)

        return collector.run(CaptureBoundedNativeTrivyOperation(selected.operation,
            selected.selection, selected.invocation, grant.authorization, collector.store,
            owner.workspace_id, owner.owner_reference, observer=owner, budget=collector.budget,
            material_proof=proof, operation_reference=selected.operation_reference,
            version_prerequisite=None if selected.version_prerequisite is None else (
                selected.version_prerequisite.capture), validate_authority=Fresh))

    return SimpleNamespace(collector=collector, root=root, prepared=prepared, engine=engine,
        context=context, arguments=arguments, Grant=Grant, Claim=Claim, Request=Request, Run=Run)


def test_DescriptiveNativePlanRequiresNoApprovalAndLeavesAllExecutionNamespacesAbsent(authority):
    """Planning checks current policy and registered input facts without consuming execution."""

    plan = authority.engine.PlanNativeImageOperation(authority.prepared, authority.context,
                                                     **authority.arguments)
    assert plan.provider_version is None and authority.prepared.invocation.timeout_seconds == 3, (
        "An original VERSION plan must remain unknown-version and exactly three seconds"
    )
    assert plan.target_reference == authority.prepared.input_manifest.Target().Reference(), (
        "Native authority must use the distinct canonical INPUT manifest artifact target"
    )
    assert not (authority.root / "native-image-claims").exists(), (
        "Descriptive planning cannot reserve execution or create a persistent claim namespace"
    )
    assert authority.collector.state.calls == [], "Planning cannot execute the selected provider."


@pytest.mark.parametrize("approval", [False, 1, "yes", None])
def test_NativeAuthorizationRequiresExactExplicitBooleanApproval(authority, approval):
    """Workflow opt-in cannot be coerced or inferred from existing policy permission."""

    with pytest.raises(ArtifactDeniedError):
        authority.engine.AuthorizeNativeImageOperation(authority.prepared, authority.context,
            approve_safe_image=approval, **authority.arguments)

    assert not (authority.root / "native-image-claims").exists(), (
        "Missing explicit approval cannot consume or manufacture execution authority"
    )


@pytest.mark.parametrize("change", ["owner", "permission", "impact", "scope", "policy-content"])
def test_FreshContextChangesCannotReuseNativeGrantOrCreateReservation(authority, change):
    """Owner, consent, permission and complete same-revision policy contents are actual bindings."""

    grant = authority.Grant()
    context = authority.context

    if change == "owner":
        context = replace(context, owner_ref="owner:different")

    elif change == "permission":
        context = replace(context, policy=replace(context.policy, permissions=()))

    elif change == "impact":
        context = replace(context, policy=replace(context.policy,
            maximum_impact=ImpactLevel.PASSIVE))

    elif change == "scope":
        saved = LocalScopeStore(authority.root).Save(replace(context.scope,
            authorization=replace(context.scope.authorization, state=AuthorizationState.REVOKED)))
        context = replace(context, scope=saved)

    else:
        context = replace(context, policy=replace(context.policy, max_authorization_seconds=200))

    with pytest.raises(ArtifactDeniedError):
        authority.engine.ClaimNativeImageExecution(grant, authority.prepared, context,
                                                   **authority.arguments)

    assert not (authority.root / "native-image-claims").exists(), (
        "Unauthorized or changed context must refuse before a grant is consumed"
    )


def test_NativeGrantExpiryIsExclusiveAndBoundByRecordedConsent(authority):
    """The earliest explicit consent expiry applies at claim issuance and final acceptance."""

    scope = LocalScopeStore(authority.root).Save(replace(authority.context.scope,
        authorization=replace(authority.context.scope.authorization,
            valid_until=(AT + timedelta(seconds=20)).isoformat())))
    context = replace(authority.context, scope=scope)
    grant = authority.Grant(context_override=context)
    assert datetime.fromisoformat(grant.valid_until) == AT + timedelta(seconds=20), (
        "Native grants cannot outlive the independently recorded current scope consent"
    )

    with pytest.raises(ArtifactDeniedError):
        authority.engine.ClaimNativeImageExecution(grant, authority.prepared, context,
            **dict(authority.arguments, at=AT + timedelta(seconds=20)))

    with pytest.raises(ValueError, match="timezone-aware"):
        authority.engine.PlanNativeImageOperation(authority.prepared, context,
            **dict(authority.arguments, at=datetime(2026, 10, 23)))


def test_ClaimReservationConsumesAcrossFreshEnginesAndNeverReleasesAfterSetupFailure(authority):
    """A fresh engine issuing the same grant identity still encounters durable exclusion."""

    grant = authority.Grant()
    claim = authority.Claim(grant)
    namespace = authority.root / "native-image-claims"
    directories = tuple(path.parent for path in namespace.glob("*/reservation.json"))
    assert len(directories) == 1 and (directories[0] / "reservation.json").is_file(), (
        "One successful claim must durably reserve one canonical hash-of-grant directory"
    )
    assert not (directories[0] / "binding.json").exists(), (
        "Reservation must precede collector setup and its first actual full request"
    )
    second = ArtifactPolicyEngine()
    second_grant = second.AuthorizeNativeImageOperation(authority.prepared, authority.context,
        approve_safe_image=True, **authority.arguments)
    assert second_grant.authorization == grant.authorization, (
        "The cross-engine duplicate test must target the exact same canonical original grant ID"
    )

    with pytest.raises(ArtifactDeniedError):
        second.ClaimNativeImageExecution(second_grant, authority.prepared, authority.context,
                                         **authority.arguments)

    with pytest.raises(ArtifactDeniedError):
        authority.Claim(grant)

    with pytest.raises(ValueError):
        native.NativeImageExecutionClaim()

    assert native.OriginalClaim(authority.engine, claim).directory == directories[0], (
        "Refused setup or repeated claim must never release the original consumed reservation"
    )


@pytest.mark.parametrize("replacement", ["copy-handle", "foreign-engine", "copied-grant"])
def test_CopiedOrForeignOpaqueAuthorityCannotBindAnOriginalExecution(authority, replacement):
    """Persisted bytes and equivalent records cannot replace original engine object identity."""

    grant = authority.Grant()
    claim = authority.Claim(grant)
    request = authority.Request(grant)
    engine = authority.engine

    if replacement == "copy-handle":
        claim = object.__new__(native.NativeImageExecutionClaim)

    elif replacement == "foreign-engine":
        engine = ArtifactPolicyEngine()

    else:
        with pytest.raises(ArtifactDeniedError):
            authority.Claim(replace(grant))

        return

    with pytest.raises(ArtifactDeniedError):
        engine.BindNativeImageRequest(claim, request, authority.context, **authority.arguments)

    assert not tuple((authority.root / "native-image-claims").glob("*/binding.json")), (
        "Copied or foreign original-object associations cannot create a launch binding"
    )


@pytest.mark.parametrize("changed", ["environment", "resources", "workspace", "invocation"])
def test_FullRequestBindingRejectsEveryChangedFiniteProfileField(authority, changed):
    """An invocation hash cannot authorize changed scratch, flags, resources or environment."""

    grant = authority.Grant()
    claim = authority.Claim(grant)
    request = authority.Request(grant)

    if changed == "environment":
        request = replace(request, environment=dict(request.environment, TRIVY_DEBUG="1"))

    elif changed == "resources":
        request = replace(request, resources=replace(request.resources, max_stdout_bytes=65536))

    elif changed == "workspace":
        request = replace(request, workspace="native-image-owned-unit/nested")

    else:
        invocation = replace(request.invocation, argv=(*request.invocation.argv, "--debug"))
        authorization = replace(request.authorization,
            invocation_sha256=native.InvocationDigest(invocation))
        request = replace(request, invocation=invocation, authorization=authorization)

    with pytest.raises(ArtifactDeniedError):
        authority.engine.BindNativeImageRequest(claim, request, authority.context,
                                                 **authority.arguments)

    assert not tuple((authority.root / "native-image-claims").glob("*/binding.json")), (
        "A changed request profile must never create an accepted persistent full-request binding"
    )


def test_OneShotFullBindingCannotResumeAndLiveValidationCannotInferFinalPhase(authority):
    """Repeated bind refuses; missing launch scratch never selects post-capture validation."""

    grant = authority.Grant()
    claim = authority.Claim(grant)
    request = authority.Request(grant)
    authority.engine.BindNativeImageRequest(claim, request, authority.context,
                                             **authority.arguments)
    authority.engine.ValidateNativeImageClaim(claim, request, authority.context,
                                              **authority.arguments)
    binding = next((authority.root / "native-image-claims").glob("*/binding.json"))
    original = binding.read_bytes()

    with pytest.raises(ArtifactDeniedError):
        authority.engine.BindNativeImageRequest(claim, request, authority.context,
                                                 **authority.arguments)

    shutil.rmtree(authority.root / request.workspace)

    with pytest.raises((ArtifactDeniedError, ValueError)):
        authority.engine.ValidateNativeImageClaim(claim, request, authority.context,
                                                  **authority.arguments)

    assert binding.read_bytes() == original, "Refused repeated bind cannot rewrite original bytes."


@pytest.mark.parametrize("file_name", ["reservation.json", "binding.json"])
def test_ChangedPersistentClaimControlCannotBeRepairedOrAccepted(authority, file_name):
    """A replaced, changed or partial original marker consumes authority and refuses live reuse."""

    grant = authority.Grant()
    claim = authority.Claim(grant)
    request = authority.Request(grant)
    authority.engine.BindNativeImageRequest(claim, request, authority.context,
                                             **authority.arguments)
    path = next((authority.root / "native-image-claims").glob("*/" + file_name))
    original = path.read_bytes()
    path.write_bytes(original[:-1])

    with pytest.raises(ArtifactDeniedError):
        authority.engine.ValidateNativeImageClaim(claim, request, authority.context,
                                                  **authority.arguments)

    assert path.read_bytes() == original[:-1], "Partial original controls must never be repaired."


def test_ActualBoundedPairUsesFreshClaimsAndFinalValidationAfterScratchCleanup(
    authority, monkeypatch,
):
    """Controlled original outcomes compose through both authorities without synchronous hashing."""

    original = NativeTrivySelection.Material

    def WorkerOnly(selection):
        """Permit tiny fixture hashing only inside the explicit material-worker transport double."""

        assert authority.collector.state.reading, "Authority called legacy whole-file hashing."

        return original(selection)

    monkeypatch.setattr(NativeTrivySelection, "Material", WorkerOnly)
    grant = authority.Grant()
    claim = authority.Claim(grant)
    version = authority.Run(authority.prepared, grant, claim, authority.collector.initial)
    assert not (authority.root / version.capture.request.workspace).exists(), (
        "The collector must legitimately clean its actual VERSION scratch before returning"
    )
    options = dict(authority.arguments, material_proof=version.material_proof)
    prerequisite = authority.engine.AcceptNativeImageVersion(claim, version.capture,
                                                              authority.context, **options)
    prepared = native.PrepareNativeImageOperation(NativeTrivyOperation.SCAN,
        authority.collector.selection, authority.collector.store,
        operation_reference=authority.prepared.operation_reference,
        version_prerequisite=prerequisite, timeout_seconds=30,
        observer=options["observer"], material_proof=options["material_proof"])
    scan_grant = authority.Grant(prepared, proof=version.material_proof)
    scan_claim = authority.Claim(scan_grant, prepared, proof=version.material_proof)
    scan = authority.Run(prepared, scan_grant, scan_claim, version.material_proof)
    authority.engine.ValidateNativeImagePairFresh(prerequisite, prepared, scan_grant,
        scan_claim, scan.capture, authority.context,
        **dict(options, material_proof=scan.material_proof))
    assert grant.authorization.authorization_id != scan_grant.authorization.authorization_id, (
        "Original VERSION and SCAN require distinct grants and persistent execution claims"
    )
    assert authority.collector.budget.ObservationCount == 3, (
        "Stable post-VERSION material must reuse its original proof without a fourth observation"
    )
    assert not (authority.root / scan.capture.request.workspace).exists(), (
        "Final pair validation must use original binding after legitimate SCAN scratch cleanup"
    )
    assert len(tuple((authority.root / "native-image-claims").glob("*/binding.json"))) == 2, (
        "Confirmed collector cleanup must preserve both consumed persistent full-request bindings"
    )

    with pytest.raises(ArtifactDeniedError):
        authority.engine.ValidateNativeImagePairFresh(replace(prerequisite), prepared, scan_grant,
            scan_claim, scan.capture, authority.context,
            **dict(options, material_proof=scan.material_proof))

    with pytest.raises(ArtifactDeniedError):
        authority.engine.AcceptNativeImageVersion(claim, replace(version.capture),
                                                   authority.context, **options)

    index = native.OriginalClaim(authority.engine, scan_claim).indexes[-1]
    original_index = index.path.read_bytes()
    index.path.write_bytes(original_index[:-1])

    with pytest.raises(ArtifactDeniedError):
        authority.engine.ValidateNativeImagePairFresh(prerequisite, prepared, scan_grant,
            scan_claim, scan.capture, authority.context,
            **dict(options, material_proof=scan.material_proof))

    assert index.path.read_bytes() == original_index[:-1], (
        "Final validation after scratch cleanup must reject changed indexes without repairing them"
    )


def test_PreCancelledClaimRemainsConsumedWithoutAnyCollectorSetup(authority):
    """The reservation exists before a cancelled operation can reach the bounded collector."""

    grant = authority.Grant()
    authority.Claim(grant)
    cancelled = asyncio.Event()
    cancelled.set()
    prepared = authority.prepared
    owner = authority.collector.observer

    with pytest.raises(asyncio.CancelledError):
        authority.collector.run(CaptureBoundedNativeTrivyOperation(prepared.operation,
            prepared.selection, prepared.invocation, grant.authorization, authority.collector.store,
            owner.workspace_id, owner.owner_reference, observer=owner,
            budget=authority.collector.budget, material_proof=authority.collector.initial,
            operation_reference=prepared.operation_reference, cancellation=cancelled))

    with pytest.raises(ArtifactDeniedError):
        authority.Claim(grant)

    assert authority.collector.state.calls == [] and (
        len(tuple((authority.root / "native-image-claims").glob("*/reservation.json"))) == 1
    ), "Pre-cancelled execution must retain its consumed grant without starting a provider."
    assert not tuple(authority.root.glob("native-image-bounded-*")), (
        "Cancellation after claim cannot fabricate collector custody or bind a request"
    )


@pytest.mark.parametrize("phase", ["observations", "operations", "reservation", "binding"])
def test_PartialExclusiveControlConsumesGrantWithoutRepairOrRetry(authority, monkeypatch, phase):
    """Partial storage failure consumes authority even when no usable handle or binding returns."""

    grant = authority.Grant()
    claim = authority.Claim(grant) if phase == "binding" else None
    request = authority.Request(grant) if phase == "binding" else None
    original_os = native.os
    calls = []

    def Partial(descriptor, raw):
        """Write one genuine partial prefix, then fail before complete control custody."""

        calls.append(len(raw))

        if len(calls) > 1:
            raise OSError("controlled private metadata write failure")

        return original_os.write(descriptor, raw[:len(raw) // 2])

    selected_os = SimpleNamespace(**vars(original_os))
    selected_os.write = Partial
    original_write = native.WriteControl

    def SelectedWrite(path, value):
        """Inject partial storage only into the selected immutable acquisition stage."""

        selected = path.parent.name == phase if phase in {"observations", "operations"} else (
            path.name == phase + ".json")

        if selected:
            with monkeypatch.context() as isolated_os:
                isolated_os.setattr(native, "os", selected_os)

                return original_write(path, value)

        return original_write(path, value)

    with monkeypatch.context() as isolated:
        isolated.setattr(native, "WriteControl", SelectedWrite)

        with pytest.raises(OSError):
            if phase != "binding":
                authority.Claim(grant)

            else:
                authority.engine.BindNativeImageRequest(claim, request, authority.context,
                    **authority.arguments)

    pattern = phase + "/*.json" if phase in {"observations", "operations"} else (
        "*/" + phase + ".json")
    partial = next((authority.root / "native-image-claims").glob(pattern))
    original = partial.read_bytes()

    with pytest.raises((ArtifactDeniedError, OSError)):
        if phase != "binding":
            authority.Claim(grant)

        else:
            authority.engine.BindNativeImageRequest(claim, request, authority.context,
                **authority.arguments)

    assert partial.read_bytes() == original and not original.endswith(b"}"), (
        "Partial exclusive controls must remain unchanged and cannot resume successful binding"
    )


@pytest.mark.parametrize("field_name", ["material", "resources", "workspace_id", "operation_id"])
def test_AlteredNativeRecipeRefusesBeforeReservation(authority, field_name):
    """A self-consistent typed prepared dataclass cannot replace the fixed original recipe."""

    grant = authority.Grant()
    changes = {"material": (replace(authority.prepared.material[0], sha256="b" * 64),
        *authority.prepared.material[1:]),
        "resources": replace(authority.prepared.resources, max_stdout_bytes=32768),
        "workspace_id": "different-workspace", "operation_id": "operation:arbitrary"}
    prepared = replace(authority.prepared, **{field_name: changes[field_name]})

    with pytest.raises((ArtifactDeniedError, ValueError)):
        authority.engine.ClaimNativeImageExecution(grant, prepared, authority.context,
                                                   **authority.arguments)

    assert not (authority.root / "native-image-claims").exists(), (
        "Malformed or changed recipes must fail before consuming the original execution grant"
    )


@pytest.mark.parametrize("method", ["plan", "authorize"])
def test_NativeSurplusPolicyPrivilegesRefuseBeforeUnusableGrant(authority, method):
    """The historical native receipt profile forbids stripping or propagating surplus privileges."""

    permission = replace(authority.context.policy.permissions[0],
                         granted_privileges=("filesystem-read",))
    context = replace(authority.context,
        policy=replace(authority.context.policy, permissions=(permission,)))

    with pytest.raises(ArtifactDeniedError):
        if method == "plan":
            authority.engine.PlanNativeImageOperation(authority.prepared, context,
                                                       **authority.arguments)

        else:
            authority.engine.AuthorizeNativeImageOperation(authority.prepared, context,
                approve_safe_image=True, **authority.arguments)

    assert not (authority.root / "native-image-claims").exists(), (
        "Surplus native policy privileges must refuse before grant consumption or collector setup"
    )


@pytest.mark.parametrize("reuse", ["same-proof", "same-operation", "same-both"])
def test_PersistentFreshnessRefusesNewGrantWithConsumedOperationOrObservation(authority, reuse):
    """Later issuance time or a fresh engine cannot bypass either consumed original identity."""

    original_grant = authority.Grant()
    authority.Claim(original_grant)
    selected = authority.prepared
    proof = authority.collector.initial

    if reuse == "same-proof":
        selected = native.PrepareNativeImageOperation(NativeTrivyOperation.VERSION,
            selected.selection, authority.collector.store,
            observer=authority.collector.observer, material_proof=proof,
            operation_reference=selected.operation_reference)

    elif reuse == "same-operation":
        proof = authority.collector.run(authority.collector.observer.Observe(
            authority.collector.budget, operation_reference=selected.operation_reference))

    engine = ArtifactPolicyEngine()
    arguments = dict(authority.arguments, material_proof=proof, at=AT + timedelta(seconds=1))
    grant = engine.AuthorizeNativeImageOperation(selected, authority.context,
        approve_safe_image=True, **arguments)
    assert grant.authorization.authorization_id != original_grant.authorization.authorization_id, (
        "The freshness test must target a genuinely different grant rather than per-grant exclusion"
    )

    with pytest.raises(ArtifactDeniedError):
        engine.ClaimNativeImageExecution(grant, selected, authority.context, **arguments)

    namespace = authority.root / "native-image-claims"
    assert len(tuple(namespace.glob("*/reservation.json"))) == 1, (
        "A later grant cannot reserve a second execution using either consumed operation or proof"
    )

    if reuse == "same-operation":
        assert (namespace / "observations" / (proof.Digest() + ".json")).is_file(), (
            "A newly consumed proof stays consumed when the later operation index collides"
        )


@pytest.mark.parametrize("kind", ["observations", "operations"])
def test_ChangedConsumptionIndexDeniesBoundLiveClaimWithoutRepair(authority, kind):
    """Original grant and binding cannot mask a modified operation or observation index."""

    grant = authority.Grant()
    claim = authority.Claim(grant)
    request = authority.Request(grant)
    authority.engine.BindNativeImageRequest(claim, request, authority.context,
                                             **authority.arguments)
    key = authority.collector.initial.Digest() if kind == "observations" else (
        native.Digest(authority.prepared.operation_id))
    path = authority.root / "native-image-claims" / kind / (key + ".json")
    original = path.read_bytes()
    path.write_bytes(original[:-1])

    with pytest.raises(ArtifactDeniedError):
        authority.engine.ValidateNativeImageClaim(claim, request, authority.context,
                                                   **authority.arguments)

    assert path.read_bytes() == original[:-1], "Consumed index controls must never be repaired."


def test_ConcurrentClaimsConsumeOneOriginalObservationAndOperation(authority):
    """Two genuinely concurrent authorized attempts cannot create two usable opaque handles."""

    grant = authority.Grant()

    def Attempt():
        """Return only the actual exclusive acquisition result, without retrying any failure."""

        try:
            return authority.Claim(grant)

        except ArtifactDeniedError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(lambda index: Attempt(), range(2)))

    assert sum(value is not None for value in outcomes) == 1, (
        "Exactly one concurrent attempt may receive an original usable claim handle"
    )
    namespace = authority.root / "native-image-claims"
    assert len(tuple(namespace.glob("observations/*.json"))) == 1 and (
        len(tuple(namespace.glob("operations/*.json"))) == 1
    ), "Concurrent claim exclusion must retain one exact operation and one exact observation index."
