# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure artifact authority, closed producer/runtime and exact request binding regressions."""

from __future__ import annotations

import inspect
import json
import stat
import traceback
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from artifact_helpers import AT, OwnedArtifact, OwnedImageArtifact

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ImpactLevel
from fuzzy1337.artifact_inputs import (
    ArtifactOperation,
    ArtifactProfile,
    ArtifactSelection,
    ArtifactStage,
)
from fuzzy1337.artifact_policy import (
    ArtifactAcceptance,
    ArtifactDenialReason,
    ArtifactDeniedError,
    ArtifactPolicyEngine,
    GovernedArtifactExecutor,
    ParseObservedImageVersion,
    PrepareArtifact,
    PreparedArtifact,
    ProfileCapability,
)
from fuzzy1337.executors import ExecutionEventKind, ExecutionResources
from fuzzy1337.policy import PolicyContext, PolicyDeniedError, PolicyEngine
from fuzzy1337.scope import AuthorizationState, LocalScopeStore, Target, TargetKind


@pytest.mark.parametrize(
    "change",
    [
        "scope-content",
        "scope-revision",
        "owner",
        "policy-content",
        "policy-revision",
        "permission",
        "excluded",
        "expired",
        "revoked",
    ],
)
def test_FreshGrantRejectsEveryChangedAuthorityBinding(tmp_path, change):
    """Same-revision changes, policy changes and actual stored revocation fail closed."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    changed = context

    if change in {"scope-content", "scope-revision", "excluded", "revoked"}:
        scope = context.scope

        if change == "scope-content":
            scope = replace(
                scope, authorization=replace(scope.authorization, record_reference="consent:other")
            )

        elif change == "scope-revision":
            scope = replace(scope, revision=scope.revision + 1)

        elif change == "excluded":
            scope = replace(scope, exclusions=(stage.input.manifest.Target(),))

        else:
            scope = replace(
                scope, authorization=replace(scope.authorization, state=AuthorizationState.REVOKED)
            )

        changed = replace(context, scope=scope)

    elif change == "owner":
        changed = replace(context, owner_ref="owner:replacement")

    elif change == "policy-content":
        changed = replace(context, policy=replace(context.policy, max_authorization_seconds=10))

    elif change == "policy-revision":
        changed = replace(context, policy=replace(context.policy, revision=1))

    elif change == "permission":
        changed = replace(context, policy=replace(context.policy, permissions=()))

    with pytest.raises(ArtifactDeniedError):
        ArtifactPolicyEngine().Validate(
            grant,
            prepared,
            stage,
            changed,
            at=AT + timedelta(hours=2) if change == "expired" else AT,
        )

    assert context.scope.authorization.authority_reference != context.owner_ref, (
        "Fixture must preserve attester-versus-executor distinction"
    )


@pytest.mark.parametrize(
    "change",
    [
        "argv",
        "parameters",
        "env",
        "workspace",
        "stdout-limit",
        "timeout",
        "capability",
        "provider",
        "envelope",
    ],
)
def test_ExactRequestCannotBeSubstituted(tmp_path, change):
    """Fields omitted by legacy InvocationDigest are still in the artifact grant."""

    _, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    invocation = prepared.invocation
    changed = prepared

    if change == "argv":
        changed = replace(
            prepared,
            invocation=replace(invocation, argv=invocation.argv + ("--server=owned-invalid",)),
        )

    elif change == "parameters":
        changed = replace(
            prepared,
            invocation=replace(invocation, request=replace(invocation.request, parameters={})),
        )

    elif change == "env":
        changed = replace(
            prepared, environment={**prepared.environment, "TRIVY_SERVER": "owned-invalid"}
        )

    elif change == "workspace":
        changed = replace(prepared, workspace=".")

    elif change == "stdout-limit":
        changed = replace(prepared, resources=replace(prepared.resources, max_stdout_bytes=1024))

    elif change == "timeout":
        changed = replace(prepared, invocation=replace(invocation, timeout_seconds=1))

    elif change == "capability":
        changed = replace(
            prepared, capability=replace(prepared.capability, identifier="arbitrary.command")
        )

    elif change == "provider":
        changed = replace(prepared, invocation=replace(invocation, adapter_id="native.trivy"))

    else:
        grant = replace(
            grant, authorization=replace(grant.authorization, authorization_id="other:grant")
        )

    with pytest.raises(ArtifactDeniedError):
        ArtifactPolicyEngine().Validate(grant, changed, stage, context, at=AT)


@pytest.mark.parametrize(
    "native", [ArtifactProfile.IMAGE, ArtifactProfile.DOCKERFILE, ArtifactProfile.KUBERNETES]
)
def test_NativeMetadataCannotAuthorizeEvenWithPinnedMaterial(tmp_path, native):
    """Attested version strings and copied bytes never substitute for real native acceptance."""

    _, stage, prepared, context, _ = OwnedArtifact(tmp_path)
    stage = replace(
        stage, input=replace(stage.input, manifest=replace(stage.input.manifest, profile=native))
    )

    with pytest.raises(ArtifactDeniedError):
        PrepareArtifact(stage, prepared.workspace_root)

    with pytest.raises(ArtifactDeniedError):
        ArtifactPolicyEngine().Authorize(prepared, stage, context, at=AT)

    assert ProfileCapability(native).adapter_id == "native.trivy", "Native metadata was relabeled"


def test_ArbitraryProducerAndExecutableSubstitutionCannotBecomeSafe(tmp_path):
    """Pinned caller code and a caller executable are rejected independently of file hashes."""

    root, stage, prepared, _, _ = OwnedArtifact(tmp_path)
    hostile = tmp_path.resolve() / "arbitrary.py"
    hostile.write_text("raise SystemExit('owned-denied-program')\n")
    original = stage.input.directory / "image.tar"
    material = stage.material.directory / "policy.json"
    alternate = ArtifactStage.Create(
        root / "other-stage",
        stage.input.manifest.profile,
        stage.input.consent,
        (ArtifactSelection("image.tar", original),),
        ArtifactSelection("executable", stage.executable),
        stage.version,
        producer=ArtifactSelection("producer.py", hostile),
        material=(ArtifactSelection("policy.json", material),),
    )

    with pytest.raises(ArtifactDeniedError):
        PrepareArtifact(alternate, root)

    fake_runtime = tmp_path.resolve() / "fake-runtime"
    fake_runtime.write_bytes(b"owned-invalid-executable")

    with pytest.raises(ArtifactDeniedError):
        PrepareArtifact(replace(stage, executable=fake_runtime), prepared.workspace_root)


def test_NetworkContextAndIssuanceCannotUseArtifactAuthority(tmp_path):
    """Allowed literal IPs cannot turn artifact targets into network authority."""

    _, stage, _, context, _ = OwnedArtifact(tmp_path)
    target = stage.input.manifest.Target()
    ip = Target(TargetKind.IP, "192.0.2.1")

    with pytest.raises(ValueError):
        PolicyContext(context.scope, context.policy, target, (ip,))

    network = PolicyContext(context.scope, context.policy, ip, (ip,))
    object.__setattr__(network, "target", target)
    capability = ProfileCapability(ArtifactProfile.IMAGE)
    invocation = AdapterInvocation(
        "native.trivy",
        AdapterRequest(capability.identifier, target.Reference(), ImpactLevel.SAFE),
        ("not-launched",),
        1,
    )

    with pytest.raises(PolicyDeniedError):
        PolicyEngine().Authorize(invocation, capability, network, at=AT)


def test_PhysicalMaterialReplacementAndSameBytesExtraFileDeny(tmp_path):
    """Equal content at a replaced physical path and unlisted cache files invalidate the lease."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    path = stage.material.directory / "policy.json"
    original = path.read_bytes()
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    path.unlink()
    path.write_bytes(original)

    with pytest.raises(ArtifactDeniedError):
        ArtifactPolicyEngine().Validate(grant, prepared, stage, context, at=AT)


def test_FinalLaunchRefreshDeniesScopeDriftWithoutContact(tmp_path):
    """Actual pre-launch check uses fresh persisted scope before creating any run marker."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    calls = 0

    def Current():
        """Revoke only when the executor calls its final launch boundary."""

        nonlocal calls
        calls += 1

        if calls == 2:
            scope = LocalScopeStore(root).Save(
                replace(
                    context.scope,
                    authorization=replace(
                        context.scope.authorization,
                        state=AuthorizationState.REVOKED,
                    ),
                )
            )

            return replace(context, scope=scope)

        return context

    coroutine = GovernedArtifactExecutor(root, clock=lambda: AT).Execute(
        prepared, stage, grant, Current
    )

    with pytest.raises(ArtifactDeniedError):
        coroutine.send(None)

    assert not tuple((stage.root / "scratch").iterdir()), "Denied launch created scratch/contact"


def test_CoroutineContextRejectedAndClosedWithoutLaunch(tmp_path):
    """Async callbacks cannot silently skip synchronous final authority validation."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)

    async def Wrong():
        """Provide a deliberately unsupported async authority result."""

        return context

    response = Wrong()
    operation = GovernedArtifactExecutor(root, clock=lambda: AT).Execute(
        prepared,
        stage,
        grant,
        lambda: response,
    )

    with pytest.raises(ValueError):
        operation.send(None)

    assert inspect.getcoroutinestate(response) == inspect.CORO_CLOSED, "Rejected coroutine leaked"


@pytest.mark.parametrize(
    "timeout,resources",
    [
        (0, None),
        (True, None),
        (301, None),
        (1, ExecutionResources(max_stdout_bytes=17 * 1024 * 1024)),
        (1, ExecutionResources(terminate_grace_seconds=6)),
    ],
)
def test_ProfileResourcesRemainFinite(tmp_path, timeout, resources):
    """Caller-selected bounded budgets cannot turn fixed execution into an unbounded command."""

    root, stage, _, _, _ = OwnedArtifact(tmp_path)

    with pytest.raises(ValueError):
        PrepareArtifact(stage, root, timeout_seconds=timeout, resources=resources)


def test_ArtifactGrantCannotBePassedToNetworkPolicy(tmp_path):
    """Distinct grant types fail closed before network issuance/validation can proceed."""

    _, _, _, _, grant = OwnedArtifact(tmp_path)

    with pytest.raises(ValueError):
        PolicyEngine().Validate(grant, None, None, None, at=AT)


@pytest.mark.parametrize("ceiling", ["policy", "permission"])
def test_PassiveCeilingCannotAuthorizeSafeArtifactExecution(tmp_path, ceiling):
    """Accepted PASSIVE policy ceilings remain stricter than SAFE fixed profiles."""

    _, stage, prepared, context, grant = OwnedArtifact(tmp_path)

    if ceiling == "policy":
        policy = replace(context.policy, maximum_impact=ImpactLevel.PASSIVE)

    else:
        policy = replace(
            context.policy,
            permissions=(
                replace(
                    context.policy.permissions[0],
                    maximum_impact=ImpactLevel.PASSIVE,
                ),
            ),
        )

    changed = replace(context, policy=policy)

    with pytest.raises(ArtifactDeniedError):
        ArtifactPolicyEngine().Authorize(prepared, stage, changed, at=AT)

    with pytest.raises(ArtifactDeniedError):
        ArtifactPolicyEngine().Validate(grant, prepared, stage, changed, at=AT)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":true,"fixture_id":"owned-artifact-lifecycle-v1","mode":"success"}',
        b'{"schema_version":1.0,"fixture_id":"owned-artifact-lifecycle-v1","mode":"success"}',
        b'{"schema_version":1,"fixture_id":"owned-artifact-lifecycle-v1","mode":"failure","mode":"success"}',
        b'{"schema_version":NaN,"fixture_id":"owned-artifact-lifecycle-v1","mode":"success"}',
        b'{"schema_version":1,"fixture_id":"owned-artifact-lifecycle-v1","mode":null}',
        b"\xff",
    ],
    ids=["boolean-version", "float-version", "duplicate-mode", "nonfinite", "null-mode", "utf8"],
)
def test_MalformedPinnedMaterialDeniedBeforeGrantOrLaunch(tmp_path, payload):
    """A content hash cannot make ambiguous JSON policy into approved SAFE material."""

    with pytest.raises(ArtifactDeniedError):
        OwnedArtifact(tmp_path, policy_payload=payload)

    scratch = tmp_path.resolve() / "workspace/artifacts-stage/scratch"

    assert not tuple(scratch.iterdir()), "Malformed material launched or initialized a run"


def test_GrantExpiryDuringFinalMaterialHashingCannotLaunch(tmp_path, monkeypatch):
    """A fresh clock after expensive final hashing denies contact before any run marker."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    actual_verify = ArtifactStage.Verify
    now = AT
    calls = 0

    def Verify(selected, **options):
        """Advance only this owned stage's clock after its final full hash check."""

        nonlocal now, calls
        actual_verify(selected, **options)
        calls += 1

        if calls == 2:
            now = AT + timedelta(seconds=301)

    monkeypatch.setattr(ArtifactStage, "Verify", Verify)
    operation = GovernedArtifactExecutor(root, clock=lambda: now).Execute(
        prepared,
        stage,
        grant,
        lambda: context,
    )

    with pytest.raises(ArtifactDeniedError):
        operation.send(None)

    assert not tuple((stage.root / "scratch").iterdir()), "Expired final check initialized launch"


@pytest.mark.parametrize("mutation", ["owner", "policy-impact", "permissions", "policy-content"])
def test_AuthorityChangedDuringFinalHashingIsRefreshedBeforeLaunch(tmp_path, monkeypatch, mutation):
    """Current owner and same-revision policy cannot drift during an expensive hash window."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    actual_verify = ArtifactStage.Verify
    current = context
    calls = 0

    def Verify(selected, **options):
        """Change only owned authority after its final real material verification."""

        nonlocal current, calls
        actual_verify(selected, **options)
        calls += 1

        if calls != 2:
            return

        if mutation == "owner":
            current = replace(context, owner_ref="owner:changed")

        elif mutation == "policy-impact":
            current = replace(
                context, policy=replace(context.policy, maximum_impact=ImpactLevel.PASSIVE)
            )

        elif mutation == "permissions":
            current = replace(context, policy=replace(context.policy, permissions=()))

        else:
            current = replace(context, policy=replace(context.policy, max_authorization_seconds=10))

    monkeypatch.setattr(ArtifactStage, "Verify", Verify)
    operation = GovernedArtifactExecutor(root, clock=lambda: AT).Execute(
        prepared,
        stage,
        grant,
        lambda: current,
    )

    with pytest.raises(ArtifactDeniedError):
        operation.send(None)

    assert not tuple((stage.root / "scratch").iterdir()), (
        "Changed final authority initialized launch"
    )


def test_PreparedEnvironmentFreezesCallerAliasesAndDivergentMapping(tmp_path):
    """One immutable environment representation governs payload and actual request values."""

    _, _, prepared, _, grant = OwnedArtifact(tmp_path)
    caller = dict(prepared.environment)
    frozen = replace(prepared, environment=caller)
    caller["ARTIFACT_REVIEW_PROBE"] = "owned-unapproved"
    caller["PATH"] = "owned-unapproved"

    assert dict(frozen.environment) == dict(prepared.environment), "Caller changed frozen request"
    assert frozen.Request(grant) == prepared.Request(grant), "Caller alias changed launch values"

    class DivergentEnvironment(Mapping):
        """Expose harmless extra values only through the caller-controlled items view."""

        def __iter__(self):
            """Expose the original declared names."""

            return iter(prepared.environment)

        def __len__(self):
            """Expose the original declared count."""

            return len(prepared.environment)

        def __getitem__(self, name):
            """Expose original declared values by key."""

            return prepared.environment[name]

        def Items(self):
            """Supply a different environment to a naive process request constructor."""

            return (*prepared.environment.items(), ("ARTIFACT_REVIEW_PROBE", "owned-unapproved"))

        items = Items

    hostile = replace(prepared, environment=DivergentEnvironment())

    assert hostile.Payload()["environment"] == dict(hostile.environment), (
        "Payload and process request used different mapping views"
    )

    with pytest.raises(ArtifactDeniedError):
        hostile.Request(grant)


def test_FinalLaunchComparesActualRequestWithRebuiltCanonicalRequest(tmp_path, monkeypatch):
    """The captured request alone cannot substitute unapproved process-affecting fields."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    actual_request = PreparedArtifact.Request
    calls = 0

    def Request(selected, authorization):
        """Inject an extra harmless environment value into only the first local request."""

        nonlocal calls
        calls += 1
        canonical = actual_request(selected, authorization)

        if calls == 1:
            return replace(
                canonical,
                environment={**canonical.environment, "ARTIFACT_REVIEW_PROBE": "owned-unapproved"},
            )

        return canonical

    monkeypatch.setattr(PreparedArtifact, "Request", Request)
    events = []
    operation = GovernedArtifactExecutor(root, clock=lambda: AT).Execute(
        prepared, stage, grant, lambda: context, on_event=events.append
    )

    with pytest.raises(ArtifactDeniedError):
        operation.send(None)

    assert calls == 2, "Final hook trusted only its previously captured request"
    assert not any(event.kind == ExecutionEventKind.STARTED for event in events), (
        "An unapproved actual environment reached a child"
    )
    assert not tuple((stage.root / "scratch").iterdir()), "Request substitution initialized launch"


@pytest.mark.parametrize("mutation", ["owner", "policy-impact", "permissions", "scope", "expiry"])
def test_AuthorityChangedDuringScratchSetupCannotLaunch(tmp_path, monkeypatch, mutation):
    """The final cheap guard refreshes authority and time after owned directory setup."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    actual_mkdir = Path.mkdir
    current = context
    now = AT

    def Mkdir(path, *args, **options):
        """Mutate only owned authority after the last scratch directory is initialized."""

        nonlocal current, now
        actual_mkdir(path, *args, **options)

        if path != stage.root / "scratch/cache":
            return

        if mutation == "owner":
            current = replace(context, owner_ref="owner:changed")

        elif mutation == "policy-impact":
            current = replace(
                context, policy=replace(context.policy, maximum_impact=ImpactLevel.PASSIVE)
            )

        elif mutation == "permissions":
            current = replace(context, policy=replace(context.policy, permissions=()))

        elif mutation == "scope":
            changed = replace(
                context.scope,
                authorization=replace(
                    context.scope.authorization, state=AuthorizationState.REVOKED
                ),
            )
            LocalScopeStore(root).Save(changed)
            current = replace(context, scope=changed)

        else:
            now = AT + timedelta(seconds=301)

    monkeypatch.setattr(Path, "mkdir", Mkdir)
    events = []
    operation = GovernedArtifactExecutor(root, clock=lambda: now).Execute(
        prepared, stage, grant, lambda: current, on_event=events.append
    )

    with pytest.raises(ArtifactDeniedError):
        operation.send(None)

    assert (stage.root / "scratch/run-lease.json").is_file(), "Setup window was not exercised"
    assert not any(event.kind == ExecutionEventKind.STARTED for event in events), (
        "Changed final authority reached a child"
    )


def test_ReceiptMarkerMetadataIsFiniteAndFreezesCallerAlias(tmp_path):
    """A receipt never consumes an unbounded marker iterable or retains a mutable alias."""

    _, stage, _, _, grant = OwnedArtifact(tmp_path)
    caller_identity = [0, 0, 0, 0, 0]
    receipt = ArtifactAcceptance(
        "artifact-run:owned",
        grant.authorization.authorization_id,
        stage.lease_id,
        "0" * 64,
        AT.isoformat(),
        None,
        caller_identity,
    )
    caller_identity[0] = 1

    assert receipt.marker_identity == (0, 0, 0, 0, 0), "Caller alias changed physical marker facts"

    class MarkerIterator:
        """Reject arbitrary iteration before trusting observed physical metadata."""

        def __iter__(self):
            """Fail if a supposedly finite constructor consumes caller-controlled iteration."""

            raise AssertionError("An unbounded marker iterator was consumed")

    with pytest.raises(ValueError):
        replace(receipt, marker_identity=MarkerIterator())


@pytest.mark.parametrize(
    "mutation", ["policy-limit", "consent-limit", "shorter", "outside-consent"]
)
def test_CoherentEnvelopeCannotChangeCanonicalOriginalLifetime(tmp_path, mutation):
    """Unsigned envelope self-consistency cannot extend policy or bypass issuance consent."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    engine = ArtifactPolicyEngine()
    issued_at = grant.issued_at
    valid_until = (AT + timedelta(hours=1)).isoformat()

    if mutation == "consent-limit":
        scope = replace(
            context.scope,
            authorization=replace(
                context.scope.authorization, valid_until=(AT + timedelta(seconds=60)).isoformat()
            ),
        )
        scope = LocalScopeStore(root).Save(scope)
        context = replace(context, scope=scope)
        grant = engine.Authorize(prepared, stage, context, at=AT)
        valid_until = (AT + timedelta(seconds=300)).isoformat()

    elif mutation == "shorter":
        valid_until = (AT + timedelta(seconds=1)).isoformat()

    elif mutation == "outside-consent":
        issued_at = (AT - timedelta(seconds=1)).isoformat()
        valid_until = (AT + timedelta(seconds=299)).isoformat()

    changed = replace(
        grant,
        issued_at=issued_at,
        valid_until=valid_until,
        authorization=engine.Envelope(grant.plan, issued_at, valid_until),
    )

    with pytest.raises(ArtifactDeniedError):
        engine.Validate(changed, prepared, stage, context, at=AT)

    with pytest.raises(ArtifactDeniedError):
        engine.ValidateCurrent(changed, prepared, stage, context, at=AT)

    events = []
    operation = GovernedArtifactExecutor(root, clock=lambda: AT).Execute(
        prepared, stage, changed, lambda: context, on_event=events.append
    )

    with pytest.raises(ArtifactDeniedError):
        operation.send(None)

    assert not any(event.kind == ExecutionEventKind.STARTED for event in events), (
        "Noncanonical lifetime reached a child"
    )
    assert not tuple((stage.root / "scratch").iterdir()), "Noncanonical lifetime initialized launch"


def test_ExpiryArithmeticOverflowAtIssuanceIsTypedDenial(tmp_path):
    """An aware upper datetime boundary cannot escape as an unclassified arithmetic failure."""

    root, stage, prepared, context, _ = OwnedArtifact(tmp_path)
    scope = replace(
        context.scope,
        authorization=replace(context.scope.authorization, valid_from=None, valid_until=None),
    )
    scope = LocalScopeStore(root).Save(scope)
    context = replace(context, scope=scope)

    with pytest.raises(ArtifactDeniedError) as denied:
        ArtifactPolicyEngine().Authorize(
            prepared, stage, context, at=datetime.max.replace(tzinfo=timezone.utc)
        )

    assert denied.value.reason == ArtifactDenialReason.PLAN_CHANGED, "Overflow escaped typed denial"
    assert not tuple((stage.root / "scratch").iterdir()), "Impossible expiry initialized launch"


def test_ClosedRicherVersionBindsOperationFamilyEnvironmentAndExactWire(tmp_path, monkeypatch):
    """Reviewed VERSION has its own exact factory wire without parent provider overlays."""

    monkeypatch.setenv("TRIVY_SERVER", "owned-private-server")
    monkeypatch.setenv("PYTHONPATH", "owned-private-python-overlay")
    root, stage, prepared, _, grant = OwnedImageArtifact(tmp_path)
    assert prepared.operation == ArtifactOperation.VERSION, "VERSION became implicit SCAN"
    assert prepared.producer_family == "owned-synthetic-image-wire-v1", "Family was relabeled"
    assert prepared.invocation.argv == (
        str(stage.executable), "-I", "-S", str(stage.root / "scanner/producer.py"),
        "--fixture-policy", str(stage.root / "material/policy.json"), "--cache-dir",
        str(stage.root / "scratch/cache"), "--config=", "--version", "--format", "json",
    ), "VERSION received SCAN flags or caller-selected argv"
    assert prepared.invocation.timeout_seconds == 3, "VERSION exact deadline drifted"
    assert (
        prepared.resources.max_stdout_bytes == prepared.resources.max_stderr_bytes == 16 * 1024
    ), (
        "VERSION must retain its exact 16 KiB capture ceiling for both raw streams"
    )
    assert prepared.VersionBindings() == {
        "version_run_id": None, "version_grant_id": None, "version_prerequisite_sha256": None,
    }, "VERSION invented an earlier prerequisite"
    assert (
        "TRIVY_SERVER" not in prepared.environment and "PYTHONPATH" not in prepared.environment
    ), (
        "Prepared VERSION must exclude ambient provider and Python environment overlays"
    )
    assert prepared.environment["PATH"] == "" and prepared.environment["PATHEXT"] == "", (
        "Prepared VERSION must disable inherited executable and extension search paths"
    )
    assert grant.plan.operation == prepared.operation, "Plan omitted its operation"
    assert grant.plan.producer_family == prepared.producer_family, "Plan omitted its family"
    assert prepared.workspace_root == root, "Physical workspace changed"


@pytest.mark.parametrize("timeout", [True, 1.0, "3", 2, 4, 0, 61],
                         ids=["bool", "float", "text", "short", "long", "zero", "oversized"])
def test_RicherVersionHasExactIntegerDeadline(tmp_path, timeout):
    """No bool/float/string/default override can weaken the reviewed VERSION deadline."""

    root, stage, _, _, _ = OwnedImageArtifact(tmp_path)

    with pytest.raises(ValueError):
        PrepareArtifact(stage, root, operation=ArtifactOperation.VERSION, timeout_seconds=timeout)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_RicherVersionCaptureHasFixedStreamCeilings(tmp_path, stream):
    """Caller resource declarations cannot expand either 16 KiB VERSION stream ceiling."""

    root, stage, _, _, _ = OwnedImageArtifact(tmp_path)
    resources = ExecutionResources(**{"max_" + stream + "_bytes": 16 * 1024 + 1})

    with pytest.raises(ValueError):
        PrepareArtifact(stage, root, operation=ArtifactOperation.VERSION, resources=resources)


@pytest.mark.parametrize("profile", [
    ArtifactProfile.SYNTHETIC_IMAGE, ArtifactProfile.SYNTHETIC_DOCKERFILE,
    ArtifactProfile.SYNTHETIC_KUBERNETES,
])
def test_LifecycleProducerNeverReceivesRicherVersionRoute(tmp_path, profile):
    """The old lifecycle family remains SCAN-only regardless of its shared profile identity."""

    root, stage, prepared, _, _ = OwnedArtifact(tmp_path, profile=profile)
    assert prepared.invocation.timeout_seconds == 120, "Legacy default deadline changed"

    with pytest.raises(ArtifactDeniedError):
        PrepareArtifact(stage, root, operation=ArtifactOperation.VERSION)


@pytest.mark.parametrize("payload", [
    b'{"schema_version":true}', b'{"schema_version":1,"schema_version":1}',
    b'{"schema_version":NaN}', b"\xff", b'{"private":"OWNED_PRIVATE_POLICY_MARKER"}',
    b"x" * 513,
], ids=["bool", "duplicate", "nonfinite", "utf8", "private", "oversized"])
def test_RicherPolicyRefusesAmbiguityWithSanitizedTraceback(tmp_path, payload):
    """Pinned policy bytes cannot widen their family or expose private source text on refusal."""

    with pytest.raises(ArtifactDeniedError) as refused:
        OwnedImageArtifact(tmp_path, policy_payload=payload)

    rendered = "".join(traceback.format_exception(refused.value))
    assert "OWNED_PRIVATE_POLICY_MARKER" not in rendered, "Private policy escaped diagnostics"
    assert refused.value.reason == ArtifactDenialReason.MATERIAL_CHANGED, (
        "Malformed immutable image policy must receive the typed material refusal"
    )


@pytest.mark.parametrize("mutation", ["database-bool", "extra", "fixture", "duplicate", "deep"])
def test_ObservedVersionParserRejectsUnsupportedRawWire(mutation):
    """No self-claim, nested type alias or ambiguous result can manufacture a VERSION proof."""

    version = {
        "Version": "0.75.0-synthetic", "VulnerabilityDB": {
            "Version": 2, "UpdatedAt": "2026-10-01T00:00:00Z",
            "NextUpdate": "2026-10-02T00:00:00Z", "DownloadedAt": "2026-10-01T01:00:00Z",
        }, "Fixture": "synthetic; no Trivy binary or vulnerability database",
    }

    if mutation == "database-bool":
        version["VulnerabilityDB"]["Version"] = True

    elif mutation == "extra":
        version["extra"] = "OWNED_PRIVATE_VERSION_MARKER"

    elif mutation == "fixture":
        version["Fixture"] = "native"

    payload = json.dumps(version).encode()

    if mutation == "duplicate":
        payload = b'{"Version":"0.75.0-synthetic","Version":"0.75.0-synthetic"}'

    elif mutation == "deep":
        payload = b"[" * 1100 + b"0" + b"]" * 1100

    with pytest.raises(ArtifactDeniedError) as refused:
        ParseObservedImageVersion(payload)

    assert "OWNED_PRIVATE_VERSION_MARKER" not in "".join(
        traceback.format_exception(refused.value)
    ), "Observed VERSION refusal must not expose private raw values in its traceback"
