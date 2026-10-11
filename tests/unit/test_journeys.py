# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Known-answer journey parsing, bounded workloads, immutable preparation, and denials."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone

import pytest

from fuzzy1337.journeys import (
    JOURNEY_SCHEMA_VERSION,
    MAX_JOURNEY_BYTES,
    JourneyAssertion,
    JourneyAssertionKind,
    JourneyHttpMethod,
    JourneyOperation,
    JourneyScenario,
    JourneyStep,
    PreparedJourney,
    PrepareJourney,
    WorkloadLimits,
)
from fuzzy1337.scope import (
    AuthorizationState,
    ScopeAuthorization,
    ScopeDecision,
    ScopeDecisionReason,
    ScopeSnapshot,
    Target,
    TargetKind,
)

AT = datetime(2026, 10, 11, tzinfo=timezone.utc)


def Scenario() -> JourneyScenario:
    """Return a mixed browser/API declaration without contacting either synthetic URL."""

    page = Target(TargetKind.URL, "http://127.0.0.1:19001/")
    api = Target(TargetKind.URL, "http://127.0.0.1:19001/api/orders")
    status = JourneyAssertion(JourneyAssertionKind.HTTP_STATUS, 200)
    element = JourneyAssertion(JourneyAssertionKind.ELEMENT_PRESENT, "#checkout")
    steps = [
        JourneyStep("home", JourneyOperation.NAVIGATE, page, [status], 0),
        JourneyStep("name", JourneyOperation.FILL, page, [element], 10,
                    selector='[data-test="name"]', test_data_key="name"),
        JourneyStep("checkout", JourneyOperation.CLICK, page, [element], 10, selector="#go"),
        JourneyStep("orders", JourneyOperation.API_REQUEST, api, [status], 0,
                    method=JourneyHttpMethod.POST, test_data_key="order"),
    ]

    return JourneyScenario(
        "synthetic-shopping", "synthetic-workspace", "synthetic-scope", [page, api], steps,
        WorkloadLimits(2, 2, 1, 20, 120), "test-data:synthetic-shopping", "session:synthetic-user",
    )


def Scope(scenario: JourneyScenario) -> ScopeSnapshot:
    """Bind the declared exact URLs to synthetic consent and explicit allow rules."""

    return ScopeSnapshot(
        scenario.scope_id, scenario.workspace_id,
        ScopeAuthorization(AuthorizationState.GRANTED, "operator:synthetic", "consent:synthetic"),
        revision=7, targets=scenario.allowed_targets, allow=scenario.allowed_targets,
    )


def test_JourneyCanonicalRoundTripAndDigest():
    """Preserve explicit nulls, ordering, existing target references, and compact digest input."""

    scenario = Scenario()
    text = scenario.ToJson()

    assert JOURNEY_SCHEMA_VERSION == 1, "Initial journey schema version changed"
    assert JourneyScenario.FromJson(text) == scenario, "JSON producer/consumer contract diverged"
    assert JourneyScenario.FromDict(scenario.ToDict()) == scenario, "Typed round trip changed state"
    assert scenario.Digest() == "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(), (
        "Scenario digest does not bind the canonical JSON bytes"
    )
    assert "\n" not in text and ": " not in text, "Digest JSON is no longer compact"
    assert scenario.steps[0].target.Reference() == scenario.allowed_targets[0].Reference(), (
        "Journey code forked existing exact target identity"
    )
    assert json.loads(text)["steps"][0]["method"] is None, "Absent bindings must remain explicit"


def test_PreparationPinsImmutableScenarioScopeRevisionAndMembershipOnly():
    """Changing decoded dictionaries, original lists, or scope proposals cannot alter a plan."""

    scenario = Scenario()
    scope = Scope(scenario)
    prepared = PrepareJourney(scenario, scope, at=AT)
    document = scenario.ToDict()
    document["scenario_id"] = "changed"
    later_scope = replace(scope, revision=8, deny=scenario.allowed_targets)

    assert prepared.scenario == scenario, "Prepared scenario was replaced by mutable input"
    assert prepared.scenario_digest == scenario.Digest(), "Preparation lost its content binding"
    assert prepared.scope_revision == 7 and later_scope.revision == 8, (
        "Preparation did not pin the observed scope revision"
    )
    assert prepared.checked_at == AT.isoformat(), "Explicit scope-check time was lost"
    assert [item.target_reference for item in prepared.decisions] == [
        target.Reference() for target in scenario.allowed_targets
    ], "Preparation decisions do not bind every exact declared URL"
    assert all(item.Allowed() for item in prepared.decisions), "Declared URLs were not checked"
    assert scope == Scope(scenario), "Preparation mutated registration or consent"
    assert not hasattr(prepared, "authorization"), "Membership evidence became executor authority"

    with pytest.raises(FrozenInstanceError):
        prepared.scope_revision = 9

    with pytest.raises(FrozenInstanceError):
        prepared.scenario.steps[0].think_time_ms = 20


@pytest.mark.parametrize("state", [AuthorizationState.UNKNOWN, AuthorizationState.REVOKED])
def test_PreparationRejectsMissingOrRevokedConsent(state):
    """A scenario allowlist and synthetic steps do not bypass existing consent state."""

    scenario = Scenario()
    scope = replace(Scope(scenario), authorization=ScopeAuthorization(state))

    with pytest.raises(PermissionError, match="authorization_" + state.value):
        PrepareJourney(scenario, scope, at=AT)


@pytest.mark.parametrize("bound, value, reason", [
    ("valid_from", "2026-10-12T00:00:00+00:00", "authorization_not_yet_valid"),
    ("valid_until", "2026-10-11T00:00:00+00:00", "authorization_expired"),
])
def test_PreparationRetainsExplicitConsentValidity(bound, value, reason):
    """The supplied preparation time cannot extend an expired or future consent window."""

    scenario = Scenario()
    scope = Scope(scenario)
    scope = replace(scope, authorization=replace(scope.authorization, **{bound: value}))

    with pytest.raises(PermissionError, match=reason):
        PrepareJourney(scenario, scope, at=AT)


@pytest.mark.parametrize("change, reason", [
    ({"targets": ()}, "unregistered"),
    ({"allow": ()}, "not_allowed"),
    ({"deny": (Target(TargetKind.IP, "127.0.0.1"),)}, "denied"),
    ({"exclusions": (Target(TargetKind.NETWORK, "127.0.0.0/8"),)}, "excluded"),
    ({"allow": (Target(TargetKind.IP, "127.0.0.1"),)}, "not_allowed"),
])
def test_PreparationUsesExactScopeDenyAndNoCrossKindAllow(change, reason):
    """Existing host/network restrictions deny URLs while IP allow does not mint URL authority."""

    scenario = Scenario()

    with pytest.raises(PermissionError, match=reason):
        PrepareJourney(scenario, replace(Scope(scenario), **change), at=AT)


def test_UnusedDeclaredTargetsAreAlsoScopeChecked():
    """An unused URL in the scenario allowlist cannot smuggle authority into future execution."""

    scenario = Scenario()
    extra = Target(TargetKind.URL, "http://127.0.0.1:19001/undeclared")
    expanded = replace(scenario, allowed_targets=(*scenario.allowed_targets, extra))

    with pytest.raises(PermissionError, match="unregistered"):
        PrepareJourney(expanded, Scope(scenario), at=AT)


@pytest.mark.parametrize("change", [
    {"scope_id": "other"}, {"workspace_id": "other"},
])
def test_PreparationRejectsAnotherScopeOrWorkspace(change):
    """Portable preparation requires both existing owner and exact scope identity."""

    scenario = Scenario()

    with pytest.raises(ValueError, match="identity"):
        PrepareJourney(scenario, replace(Scope(scenario), **change), at=AT)


@pytest.mark.parametrize("at", [None, "2026-10-11", datetime(2026, 10, 11)])
def test_PreparationRejectsImplicitOrNaiveTime(at):
    """Membership preparation uses explicit aware time rather than a hidden clock."""

    scenario = Scenario()

    with pytest.raises(ValueError, match="timezone-aware"):
        PrepareJourney(scenario, Scope(scenario), at=at)


@pytest.mark.parametrize("scenario, scope", [
    (None, None), (Scenario(), None), (None, Scope(Scenario())),
])
def test_PreparationRejectsUntypedInputs(scenario, scope):
    """Duck-typed metadata cannot bypass the existing scope binding contract."""

    with pytest.raises(ValueError, match="JourneyScenario and ScopeSnapshot"):
        PrepareJourney(scenario, scope, at=AT)


@pytest.mark.parametrize("version", [0, 2, "1", True, 1.0, None])
def test_UnsupportedVersionsAndNumericCoercionFailClosed(version):
    """Each serialized scenario has an explicit integer schema version."""

    with pytest.raises(ValueError):
        JourneyScenario.FromDict({**Scenario().ToDict(), "schema_version": version})


@pytest.mark.parametrize("field, maximum", [
    ("iterations", 1000), ("concurrency", 16), ("requests_per_second", 100),
    ("max_requests", 100000), ("max_duration_seconds", 3600),
])
@pytest.mark.parametrize("invalid", [0, -1, True, 1.0, "1", None, float("inf")])
def test_WorkloadBoundsRejectUnlimitedAndUntypedValues(field, maximum, invalid):
    """Every workload field is a positive capped integer with explicit units."""

    valid = WorkloadLimits(1000, 16, 100, 100000, 3600).ToDict()

    with pytest.raises(ValueError):
        WorkloadLimits.FromDict({**valid, field: invalid})

    with pytest.raises(ValueError):
        WorkloadLimits.FromDict({**valid, field: maximum + 1})


def test_WorkloadCrossFieldAndActionCountCeilings():
    """Finite fields also cap aggregate iterations and parallel users before execution."""

    with pytest.raises(ValueError, match="concurrency"):
        WorkloadLimits(1, 2, 1, 1, 1)

    scenario = Scenario()
    steps = tuple(replace(scenario.steps[0], step_id=f"step-{index}") for index in range(11))

    with pytest.raises(ValueError, match="multiplied"):
        replace(scenario, steps=steps, workload=WorkloadLimits(1000, 1, 1, 10000, 3600))

    maximum = replace(
        scenario, steps=steps[:10], workload=WorkloadLimits(1000, 1, 1, 10000, 3600)
    )
    assert len(maximum.steps) * maximum.workload.iterations == 10000, (
        "Inclusive aggregate action ceiling changed"
    )


@pytest.mark.parametrize("change", [
    {"scenario_id": "x" * 129}, {"scenario_id": "Invalid"},
    {"scenario_id": "{{template}}"}, {"session_reference": "token:synthetic"},
    {"session_reference": "session:" + "x" * 129}, {"session_reference": 42},
    {"test_data_reference": "session:synthetic"}, {"test_data_reference": "test-data:../escape"},
    {"allowed_targets": ()}, {"allowed_targets": "http://127.0.0.1/"},
    {"allowed_targets": (Target(TargetKind.IP, "127.0.0.1"),)},
    {"steps": ()}, {"steps": ("navigate",)}, {"workload": None},
    {"test_data_reference": None},
])
def test_ScenarioRejectsAmbiguousBindingsContainersAndReferences(change):
    """Only typed finite metadata and opaque external data/session references enter scenarios."""

    with pytest.raises(ValueError):
        replace(Scenario(), **change)


def test_ScenarioRejectsDuplicatesUndeclaredTargetsAndOversizedMetadata():
    """Duplicate identities and undeclared URLs are rejected before preparation."""

    scenario = Scenario()

    for change in (
        {"allowed_targets": (*scenario.allowed_targets, scenario.allowed_targets[0])},
        {"steps": (*scenario.steps, scenario.steps[0])},
        {"allowed_targets": scenario.allowed_targets[:1]},
        {"steps": tuple(replace(scenario.steps[0], step_id=f"step-{i}") for i in range(65))},
        {"allowed_targets": tuple(
            Target(TargetKind.URL, f"http://127.0.0.1/{i}") for i in range(65)
        )},
    ):
        with pytest.raises(ValueError):
            replace(scenario, **change)

    target = Target(TargetKind.URL, "http://127.0.0.1/" + "a" * 4000)
    steps = tuple(replace(scenario.steps[0], step_id=f"step-{i}", target=target) for i in range(20))

    with pytest.raises(ValueError, match="byte ceiling"):
        replace(scenario, allowed_targets=(target,), steps=steps)


def test_PostNormalizationUrlCeilingPreservesSchemaAndRuntimeRoundTrip():
    """Unicode expansion must not create an in-memory target too long for its own decoder."""

    scenario = Scenario()
    expanded = Target(TargetKind.URL, "http://127.0.0.1/" + "\u2603" * 1000)

    with pytest.raises(ValueError, match="bounded exact URL"):
        replace(scenario, allowed_targets=(*scenario.allowed_targets, expanded))

    with pytest.raises(ValueError, match="bounded exact URL"):
        replace(scenario.steps[0], target=expanded)


@pytest.mark.parametrize("change", [
    {"operation": "navigate"}, {"target": None}, {"target": Target(TargetKind.IP, "127.0.0.1")},
    {"selector": "#go"}, {"method": JourneyHttpMethod.GET}, {"test_data_key": "name"},
    {"assertions": ()}, {"assertions": ("status",)}, {"think_time_ms": True},
    {"think_time_ms": -1}, {"think_time_ms": 60001}, {"step_id": "bad id"},
])
def test_StepActionCombinationsAndBoundsFailClosed(change):
    """Fields belong to explicit operations; scripts and implicit request semantics are absent."""

    with pytest.raises(ValueError):
        replace(Scenario().steps[0], **change)


def test_FillAndApiRequireFiniteDataMethodAndAssertions():
    """Fill binds external data and API requests cannot pretend to assert browser DOM state."""

    scenario = Scenario()

    with pytest.raises(ValueError, match="external test_data_key"):
        replace(scenario.steps[1], test_data_key=None)

    with pytest.raises(ValueError, match="simple"):
        replace(scenario.steps[1], selector="document.body")

    with pytest.raises(ValueError, match="JourneyHttpMethod"):
        replace(scenario.steps[3], method=None)

    with pytest.raises(ValueError, match="DOM"):
        replace(scenario.steps[3], assertions=scenario.steps[1].assertions)

    with pytest.raises(ValueError, match="templates"):
        replace(scenario.steps[3], test_data_key="${script}")

    no_data = replace(scenario.steps[3], test_data_key=None, method=JourneyHttpMethod.GET)
    anonymous = replace(
        scenario, steps=(no_data,), test_data_reference=None, session_reference=None
    )
    assert JourneyScenario.FromJson(anonymous.ToJson()) == anonymous, (
        "Explicit unauthenticated API declarations were rejected"
    )


@pytest.mark.parametrize("kind, expected", [
    ("http_status", 200), (JourneyAssertionKind.HTTP_STATUS, True),
    (JourneyAssertionKind.HTTP_STATUS, 600), (JourneyAssertionKind.HTTP_STATUS, 99),
    (JourneyAssertionKind.TEXT_CONTAINS, ""), (JourneyAssertionKind.TEXT_CONTAINS, "x" * 257),
    (JourneyAssertionKind.TEXT_CONTAINS, "{{variable}}"),
    (JourneyAssertionKind.TEXT_CONTAINS, "<script>alert(1)</script>"),
    (JourneyAssertionKind.TEXT_CONTAINS, "bad\ttext"),
    (JourneyAssertionKind.ELEMENT_PRESENT, "//xpath"),
    (JourneyAssertionKind.ELEMENT_PRESENT, "#x > script"),
])
def test_AssertionGrammarRejectsCoercionsTemplatesAndScripts(kind, expected):
    """Assertion text is bounded literal metadata and element selectors use a finite grammar."""

    with pytest.raises(ValueError):
        JourneyAssertion(kind, expected)


@pytest.mark.parametrize("selector", ["button", "#checkout", ".notice", '[data-test="name"]'])
def test_SimpleSelectorGrammarRoundTrips(selector):
    """Each permitted finite selector representation survives exact-field decoding."""

    assertion = JourneyAssertion(JourneyAssertionKind.ELEMENT_PRESENT, selector)
    text = JourneyAssertion(JourneyAssertionKind.TEXT_CONTAINS, "Synthetic shop")

    assert JourneyAssertion.FromDict(assertion.ToDict()) == assertion, "Selector changed spelling"
    assert JourneyAssertion.FromDict(text.ToDict()) == text, "Literal assertion text changed"


@pytest.mark.parametrize("value", [None, 42, " ", "{" * 2000 + "}" * 2000,
                                       "[" * 2000 + "]" * 2000, '"\ud800"',
                                       '{"schema_version":1,"schema_version":1}',
                                       '{"schema_version":NaN}', "x" * (MAX_JOURNEY_BYTES + 1)])
def test_JsonDecodeRejectsInvalidSizeEncodingNestingDuplicatesAndConstants(value):
    """Untrusted JSON cannot use duplicate fields, non-finite constants, or pathological nesting."""

    with pytest.raises(ValueError):
        JourneyScenario.FromJson(value)


def test_DecodingRejectsMalformedCollectionsAndNoncanonicalUrls():
    """Decoding never repairs persisted URL spelling or coerces arrays and child values."""

    for field in ("allowed_targets", "steps"):
        for value in (None, (), [None], [None] * 65):
            with pytest.raises(ValueError):
                JourneyScenario.FromDict({**Scenario().ToDict(), field: value})

    step = Scenario().steps[0].ToDict()

    for value in (None, (), [None], [None] * 17):
        with pytest.raises(ValueError):
            JourneyStep.FromDict({**step, "assertions": value})

    with pytest.raises(ValueError):
        JourneyAssertion.FromDict({"kind": "http_status", "expected": None})

    with pytest.raises(ValueError, match="canonical"):
        JourneyStep.FromDict({**step, "target": {"kind": "url", "value": "http://LOCALHOST/"}})


def test_PreparedEvidenceRejectsInconsistentDigestTimeRevisionAndDecisionBindings():
    """Direct construction preserves content/reference consistency without authenticating grants."""

    scenario = Scenario()
    prepared = PrepareJourney(scenario, Scope(scenario), at=AT)
    allowed = prepared.decisions[0]

    for change in (
        {"scenario": None}, {"scenario_digest": "sha256:" + "0" * 64},
        {"scope_revision": True}, {"checked_at": "2026-10-11"}, {"decisions": ()},
        {"decisions": (allowed,)},
        {"decisions": (replace(allowed, scope_reference="scope:other"), *prepared.decisions[1:])},
        {"decisions": (replace(allowed, target_reference="target:other"), *prepared.decisions[1:])},
        {"decisions": (ScopeDecision(ScopeDecisionReason.DENIED, allowed.scope_reference,
                                    allowed.target_reference), *prepared.decisions[1:])},
    ):
        with pytest.raises(ValueError):
            replace(prepared, **change)

    assert isinstance(prepared, PreparedJourney), (
        "Preparation stopped returning membership evidence"
    )
