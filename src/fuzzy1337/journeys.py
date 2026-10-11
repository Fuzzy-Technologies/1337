# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded offline journey contracts and scope preparation without execution authority."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import TypeVar

from fuzzy1337.adapters.contracts import RequireIdentifier
from fuzzy1337.scope import NormalizeTime, ScopeDecision, ScopeSnapshot, Target, TargetKind
from fuzzy1337.workspace import (
    RejectWorkspaceConstant,
    RequireWorkspaceInteger,
    RequireWorkspaceText,
    UniqueWorkspaceObject,
    WorkspaceFields,
)

JOURNEY_SCHEMA_VERSION = 1
MAX_JOURNEY_BYTES = 65536
MAX_JOURNEY_STEPS = 64
MAX_JOURNEY_ACTIONS = 10000
_SELECTOR_PATTERN = re.compile(
    r'(?:[a-z][a-z0-9-]*|[.#][A-Za-z][A-Za-z0-9_-]*|\[data-test="[a-z][a-z0-9_-]*"\])'
)
_REFERENCE_PATTERN = re.compile(r"(?:session|test-data):[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")
JourneyItem = TypeVar("JourneyItem")


class JourneyOperation(StrEnum):
    """Declare finite browser actions and exact API requests, never executable source."""

    NAVIGATE = "navigate"
    CLICK = "click"
    FILL = "fill"
    API_REQUEST = "api_request"


class JourneyAssertionKind(StrEnum):
    """Select finite status, literal text, or simple element-presence assertions."""

    HTTP_STATUS = "http_status"
    TEXT_CONTAINS = "text_contains"
    ELEMENT_PRESENT = "element_present"


class JourneyHttpMethod(StrEnum):
    """Declare bounded HTTP method semantics without headers, bodies, or credentials."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


def JourneyInteger(value: object, name: str, minimum: int, maximum: int) -> int:
    """Require a capped integer without coercion or unbounded workload arithmetic.

    Args:
        value: Candidate JSON integer; booleans and floats are rejected.
        name: Field name used in validation failures.
        minimum: Inclusive minimum allowed value.
        maximum: Inclusive maximum allowed value.

    Returns:
        The validated integer unchanged.

    Raises:
        ValueError: The candidate is not an integer within both bounds.
    """

    result = RequireWorkspaceInteger(value, name)

    if not minimum <= result <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")

    return result


def JourneyText(value: object, name: str, *, maximum: int = 256) -> str:
    """Require bounded plain text without controls, markup, or expression templates.

    Args:
        value: Literal text, never a script or template expression.
        name: Field name used in validation failures.
        maximum: Inclusive character-count ceiling.

    Returns:
        Validated text without substitution or evaluation.

    Raises:
        ValueError: Text is empty, oversized, contains controls, markup, or braces.
    """

    result = RequireWorkspaceText(value, name)

    if len(result) > maximum or any(
        ord(char) < 32 or ord(char) == 127 or char in "{}<>" for char in result
    ):
        raise ValueError(f"{name} must be bounded literal text without controls or templates")

    return result


def JourneyIdentifier(value: object, name: str) -> str:
    """Validate a portable identifier with a finite size.

    Args:
        value: Lowercase identifier following the existing adapter grammar.
        name: Field name used in validation failures.

    Returns:
        Identifier limited to 128 characters.

    Raises:
        ValueError: The candidate violates identifier grammar or its size ceiling.
    """

    result = JourneyText(value, name, maximum=128)
    RequireIdentifier(result, name)

    return result


def JourneySelector(value: object) -> str:
    """Validate one simple tag, ID, class, or data-test selector without code syntax.

    Args:
        value: Literal selector with no combinators, XPath, or template substitution.

    Returns:
        Bounded selector retaining exact declaration spelling.

    Raises:
        ValueError: The candidate is outside the finite selector grammar.
    """

    result = JourneyText(value, "selector")

    if not _SELECTOR_PATTERN.fullmatch(result):
        raise ValueError("selector must be a simple tag, #id, .class, or data-test selector")

    return result


def JourneyReference(value: object, family: str) -> str | None:
    """Accept only a reference to caller-owned session or synthetic test-data state.

    Args:
        value: Null or an opaque reference; raw session material is unsupported.
        family: Required session or test-data reference prefix.

    Returns:
        Validated opaque reference, or None for an explicitly absent binding.

    Raises:
        ValueError: A reference has an unsupported prefix, grammar, or size.
    """

    if value is None:
        return None

    reference = JourneyText(value, family + " reference", maximum=138)

    if not reference.startswith(family + ":") or not _REFERENCE_PATTERN.fullmatch(reference):
        raise ValueError(f"reference must identify {family} state, never its material")

    JourneyIdentifier(reference.split(":", 1)[1], family + " identifier")

    return reference


def JourneyItems(
    value: object, item_type: type[JourneyItem], name: str, maximum: int,
) -> tuple[JourneyItem, ...]:
    """Freeze a bounded typed collection before any consumer can mutate it.

    Args:
        value: Tuple or list of already validated immutable items.
        item_type: Required runtime type for every item.
        name: Field name used in validation failures.
        maximum: Inclusive nonempty collection size ceiling.

    Returns:
        Immutable tuple in declaration order.

    Raises:
        ValueError: Container, item type, or bounded nonempty size is invalid.
    """

    if not isinstance(value, (tuple, list)) or not 1 <= len(value) <= maximum:
        raise ValueError(f"{name} must contain between 1 and {maximum} items")

    if not all(isinstance(item, item_type) for item in value):
        raise ValueError(f"{name} must contain {item_type.__name__} items")

    return tuple(value)


def JourneyArray(value: object, name: str, maximum: int) -> list[object]:
    """Bound a decoded JSON array before constructing typed children.

    Args:
        value: Decoded JSON array, without tuple coercion.
        name: Field name used in validation failures.
        maximum: Inclusive nonempty array size ceiling.

    Returns:
        Original bounded list for deterministic typed decoding.

    Raises:
        ValueError: Input is not a nonempty JSON array within the finite bound.
    """

    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise ValueError(f"{name} must be a JSON array of 1 to {maximum} items")

    return value


def JourneyUrl(value: object) -> Target:
    """Require an existing exact URL Target whose canonical value remains bounded.

    Args:
        value: Typed existing target; no identity inference or authority expansion occurs.

    Returns:
        Original URL target whose canonical value is at most 4096 characters.

    Raises:
        ValueError: Type, namespace, or post-normalization URL size is unsupported.
    """

    if not isinstance(value, Target) or value.kind != TargetKind.URL or len(value.value) > 4096:
        raise ValueError("journey actions require a bounded exact URL Target")

    return value


@dataclass(frozen=True, slots=True)
class JourneyAssertion:
    """One finite expected status, literal response text, or simple DOM element."""

    kind: JourneyAssertionKind
    expected: int | str

    def __post_init__(self) -> None:
        """Validate typed assertions and reject scripts, templates, and coercions."""

        if not isinstance(self.kind, JourneyAssertionKind):
            raise ValueError("assertion kind must be a JourneyAssertionKind")

        if self.kind == JourneyAssertionKind.HTTP_STATUS:
            JourneyInteger(self.expected, "expected status", 100, 599)

        elif self.kind == JourneyAssertionKind.ELEMENT_PRESENT:
            JourneySelector(self.expected)

        else:
            JourneyText(self.expected, "expected text")

    def ToDict(self) -> dict[str, object]:
        """Return exact version-owned assertion fields.

        Returns:
            A JSON-compatible assertion, never executable source.
        """

        return {"kind": self.kind.value, "expected": self.expected}

    @classmethod
    def FromDict(cls, value: object) -> JourneyAssertion:
        """Decode one finite assertion without ignoring extra fields.

        Args:
            value: Exact kind/expected object from a scenario document.

        Returns:
            A validated immutable assertion.

        Raises:
            ValueError: Fields, kind, or expected value are unsupported.
        """

        record = WorkspaceFields(value, {"kind", "expected"}, "journey assertion")
        expected = record["expected"]

        if not isinstance(expected, (int, str)):
            raise ValueError("expected assertion must be an integer or string")

        return cls(JourneyAssertionKind(JourneyText(record["kind"], "kind")), expected)


@dataclass(frozen=True, slots=True)
class WorkloadLimits:
    """Requested finite workload and mandatory stop ceilings; no scheduling occurs."""

    iterations: int
    concurrency: int
    requests_per_second: int
    max_requests: int
    max_duration_seconds: int

    def __post_init__(self) -> None:
        """Reject unlimited workloads, numeric coercion, or excess parallel users."""

        for name, maximum in (
            ("iterations", 1000), ("concurrency", 16), ("requests_per_second", 100),
            ("max_requests", 100000), ("max_duration_seconds", 3600),
        ):
            JourneyInteger(getattr(self, name), name, 1, maximum)

        if self.concurrency > self.iterations:
            raise ValueError("concurrency must not exceed iterations")

    def ToDict(self) -> dict[str, object]:
        """Return explicit workload units and ceilings with no implicit defaults.

        Returns:
            Exact schema-v1 integer fields.
        """

        return {
            "iterations": self.iterations, "concurrency": self.concurrency,
            "requests_per_second": self.requests_per_second,
            "max_requests": self.max_requests, "max_duration_seconds": self.max_duration_seconds,
        }

    @classmethod
    def FromDict(cls, value: object) -> WorkloadLimits:
        """Decode capped workload fields without accepting unbounded extensions.

        Args:
            value: Exact JSON workload object with all ceilings present.

        Returns:
            Immutable workload declarations without executing or allocating workers.

        Raises:
            ValueError: Fields, types, bounds, or parallel-user count are invalid.
        """

        names = {
            "iterations", "concurrency", "requests_per_second", "max_requests",
            "max_duration_seconds",
        }
        record = WorkspaceFields(value, names, "workload limits")
        fields = {name: RequireWorkspaceInteger(record[name], name) for name in names}

        return cls(**fields)


@dataclass(frozen=True, slots=True)
class JourneyStep:
    """An exact-URL action with finite assertions, test-data key, and think time."""

    step_id: str
    operation: JourneyOperation
    target: Target
    assertions: tuple[JourneyAssertion, ...]
    think_time_ms: int
    selector: str | None = None
    method: JourneyHttpMethod | None = None
    test_data_key: str | None = None

    def __post_init__(self) -> None:
        """Freeze typed assertions and enforce action-specific fields without I/O."""

        JourneyIdentifier(self.step_id, "step_id")

        if not isinstance(self.operation, JourneyOperation):
            raise ValueError("operation must be a JourneyOperation")

        JourneyUrl(self.target)

        object.__setattr__(self, "assertions", JourneyItems(
            self.assertions, JourneyAssertion, "assertions", 16
        ))
        JourneyInteger(self.think_time_ms, "think_time_ms", 0, 60000)

        if self.operation in {JourneyOperation.CLICK, JourneyOperation.FILL}:
            JourneySelector(self.selector)

        elif self.selector is not None:
            raise ValueError("selector is supported only by click and fill")

        if self.operation == JourneyOperation.API_REQUEST:
            if not isinstance(self.method, JourneyHttpMethod):
                raise ValueError("api_request requires an explicit JourneyHttpMethod")

            if any(item.kind == JourneyAssertionKind.ELEMENT_PRESENT for item in self.assertions):
                raise ValueError("API assertions cannot assert DOM elements")

        elif self.method is not None:
            raise ValueError("HTTP method is supported only by api_request")

        if self.test_data_key is not None:
            JourneyIdentifier(self.test_data_key, "test_data_key")

            if self.operation not in {JourneyOperation.FILL, JourneyOperation.API_REQUEST}:
                raise ValueError("test_data_key is supported only by fill and api_request")

        elif self.operation == JourneyOperation.FILL:
            raise ValueError("fill requires an external test_data_key")

    def ToDict(self) -> dict[str, object]:
        """Render exact fields, keeping absent optional bindings explicitly null.

        Returns:
            JSON-compatible step without inline data, headers, or session material.
        """

        return {
            "step_id": self.step_id, "operation": self.operation.value,
            "target": self.target.ToDict(),
            "assertions": [item.ToDict() for item in self.assertions],
            "think_time_ms": self.think_time_ms, "selector": self.selector,
            "method": None if self.method is None else self.method.value,
            "test_data_key": self.test_data_key,
        }

    @classmethod
    def FromDict(cls, value: object) -> JourneyStep:
        """Decode one step with finite fields and canonical existing target identity.

        Args:
            value: Exact serialized action object; script fields are unsupported.

        Returns:
            Immutable step whose target uses scope schema-v1 spelling and identity.

        Raises:
            ValueError: Fields, types, action combination, or target are invalid.
        """

        record = WorkspaceFields(value, {
            "step_id", "operation", "target", "assertions", "think_time_ms",
            "selector", "method", "test_data_key",
        }, "journey step")
        assertions = JourneyArray(record["assertions"], "assertions", 16)
        method = record["method"]
        selector = record["selector"]
        data_key = record["test_data_key"]

        return cls(
            JourneyIdentifier(record["step_id"], "step_id"),
            JourneyOperation(JourneyText(record["operation"], "operation")),
            Target.FromDict(record["target"]),
            tuple(JourneyAssertion.FromDict(item) for item in assertions),
            JourneyInteger(record["think_time_ms"], "think_time_ms", 0, 60000),
            None if selector is None else JourneySelector(selector),
            None if method is None else JourneyHttpMethod(JourneyText(method, "method")),
            None if data_key is None else JourneyIdentifier(data_key, "test_data_key"),
        )


@dataclass(frozen=True, slots=True)
class JourneyScenario:
    """A portable hand-written scenario, isolated from authorization and session storage."""

    scenario_id: str
    workspace_id: str
    scope_id: str
    allowed_targets: tuple[Target, ...]
    steps: tuple[JourneyStep, ...]
    workload: WorkloadLimits
    test_data_reference: str | None = None
    session_reference: str | None = None

    def __post_init__(self) -> None:
        """Validate exact URL declarations, unique steps, external data, and finite work."""

        for name in ("scenario_id", "workspace_id", "scope_id"):
            JourneyIdentifier(getattr(self, name), name)

        object.__setattr__(self, "allowed_targets", JourneyItems(
            self.allowed_targets, Target, "allowed_targets", MAX_JOURNEY_STEPS
        ))
        object.__setattr__(self, "steps", JourneyItems(
            self.steps, JourneyStep, "steps", MAX_JOURNEY_STEPS
        ))

        for target in self.allowed_targets:
            JourneyUrl(target)

        if len(set(self.allowed_targets)) != len(self.allowed_targets):
            raise ValueError("allowed_targets must contain unique target identities")

        if len({step.step_id for step in self.steps}) != len(self.steps):
            raise ValueError("steps must contain unique step_id values")

        if not isinstance(self.workload, WorkloadLimits):
            raise ValueError("workload must be WorkloadLimits")

        if len(self.steps) * self.workload.iterations > MAX_JOURNEY_ACTIONS:
            raise ValueError("steps multiplied by iterations exceeds the finite action ceiling")

        JourneyReference(self.test_data_reference, "test-data")
        JourneyReference(self.session_reference, "session")

        for step in self.steps:
            if step.target not in self.allowed_targets:
                raise ValueError("every step target must belong to scenario allowed_targets")

            if step.test_data_key is not None and self.test_data_reference is None:
                raise ValueError("test_data_key requires an external test_data_reference")

        if len(self.ToJson().encode("utf-8")) > MAX_JOURNEY_BYTES:
            raise ValueError("journey document exceeds the byte ceiling")

    def ToDict(self) -> dict[str, object]:
        """Return the complete schema-v1 document with declaration order preserved.

        Returns:
            Portable JSON-compatible fields, containing references rather than secrets.
        """

        return {
            "schema_version": JOURNEY_SCHEMA_VERSION, "scenario_id": self.scenario_id,
            "workspace_id": self.workspace_id, "scope_id": self.scope_id,
            "allowed_targets": [target.ToDict() for target in self.allowed_targets],
            "steps": [step.ToDict() for step in self.steps], "workload": self.workload.ToDict(),
            "test_data_reference": self.test_data_reference,
            "session_reference": self.session_reference,
        }

    def ToJson(self) -> str:
        """Render canonical compact UTF-8 JSON text with sorted keys and no newline.

        Returns:
            Deterministic standards-compliant serialization used by scenario identity.
        """

        return json.dumps(self.ToDict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def Digest(self) -> str:
        """Return the immutable scenario content digest without making an authority claim.

        Returns:
            sha256-prefixed digest of canonical ToJson UTF-8 bytes.
        """

        return "sha256:" + hashlib.sha256(self.ToJson().encode("utf-8")).hexdigest()

    @classmethod
    def FromDict(cls, value: object) -> JourneyScenario:
        """Decode exact fields/version and bound collections before child construction.

        Args:
            value: Decoded JSON object; duplicate keys must have been rejected upstream.

        Returns:
            A deeply immutable hand-written scenario, without any execution grant.

        Raises:
            ValueError: Version, fields, types, bounds, or typed bindings are invalid.
        """

        record = WorkspaceFields(value, {
            "schema_version", "scenario_id", "workspace_id", "scope_id", "allowed_targets",
            "steps", "workload", "test_data_reference", "session_reference",
        }, "journey scenario")

        if (
            RequireWorkspaceInteger(record["schema_version"], "schema_version")
            != JOURNEY_SCHEMA_VERSION
        ):
            raise ValueError("unsupported journey schema version")

        targets = JourneyArray(record["allowed_targets"], "allowed_targets", MAX_JOURNEY_STEPS)
        steps = JourneyArray(record["steps"], "steps", MAX_JOURNEY_STEPS)

        return cls(
            JourneyIdentifier(record["scenario_id"], "scenario_id"),
            JourneyIdentifier(record["workspace_id"], "workspace_id"),
            JourneyIdentifier(record["scope_id"], "scope_id"),
            tuple(Target.FromDict(target) for target in targets),
            tuple(JourneyStep.FromDict(step) for step in steps),
            WorkloadLimits.FromDict(record["workload"]),
            JourneyReference(record["test_data_reference"], "test-data"),
            JourneyReference(record["session_reference"], "session"),
        )

    @classmethod
    def FromJson(cls, value: str) -> JourneyScenario:
        """Decode bounded JSON with duplicate-key and non-finite-number rejection.

        Args:
            value: At most MAX_JOURNEY_BYTES UTF-8 bytes of serialized scenario text.

        Returns:
            A validated immutable scenario; no source code, URL, or reference is evaluated.

        Raises:
            ValueError: Encoding, byte size, nesting, JSON, version, or contract is invalid.
        """

        if not isinstance(value, str):
            raise ValueError("journey JSON must be text")

        try:
            if len(value) > MAX_JOURNEY_BYTES or len(value.encode("utf-8")) > MAX_JOURNEY_BYTES:
                raise ValueError("journey document exceeds the byte ceiling")

            record = json.loads(
                value, object_pairs_hook=UniqueWorkspaceObject,
                parse_constant=RejectWorkspaceConstant,
            )

        except (UnicodeError, RecursionError) as error:
            raise ValueError("journey JSON encoding or nesting is invalid") from error

        return cls.FromDict(record)


@dataclass(frozen=True, slots=True)
class PreparedJourney:
    """Immutable membership evidence; this record is never an executor authorization."""

    scenario: JourneyScenario
    scenario_digest: str
    scope_revision: int
    checked_at: str
    decisions: tuple[ScopeDecision, ...]

    def __post_init__(self) -> None:
        """Preserve consistent immutable evidence, never a claim of an authentic grant."""

        if not isinstance(self.scenario, JourneyScenario):
            raise ValueError("prepared scenario must be a JourneyScenario")

        if self.scenario_digest != self.scenario.Digest():
            raise ValueError("prepared digest must match the immutable scenario")

        RequireWorkspaceInteger(self.scope_revision, "scope_revision")
        object.__setattr__(self, "checked_at", NormalizeTime(self.checked_at))
        object.__setattr__(self, "decisions", JourneyItems(
            self.decisions, ScopeDecision, "decisions", MAX_JOURNEY_STEPS
        ))

        if len(self.decisions) != len(self.scenario.allowed_targets):
            raise ValueError("prepared decisions must cover every declared target")

        for target, decision in zip(self.scenario.allowed_targets, self.decisions, strict=True):
            if (
                not decision.Allowed()
                or decision.scope_reference != "scope:" + self.scenario.scope_id
            ):
                raise ValueError("prepared decision must show membership in the bound scope")

            if decision.target_reference != target.Reference():
                raise ValueError("prepared decision must bind the exact declared target")


def PrepareJourney(
    scenario: JourneyScenario, scope: ScopeSnapshot, *, at: datetime,
) -> PreparedJourney:
    """Check declared exact targets against one explicit scope revision, without I/O.

    Args:
        scenario: Validated immutable scenario with explicit workspace/scope binding.
        scope: Existing typed scope snapshot; no registration or consent is added.
        at: Explicit timezone-aware membership time; never a hidden current clock.

    Returns:
        Immutable scenario digest, scope revision, decision time, and allowed decisions.
        This is preparation evidence, not invocation-bound execution authorization.

    Raises:
        ValueError: Types, workspace/scope binding, or decision time are invalid.
        PermissionError: Any declared target fails the existing scope membership check.
    """

    if not isinstance(scenario, JourneyScenario) or not isinstance(scope, ScopeSnapshot):
        raise ValueError("preparation requires a JourneyScenario and ScopeSnapshot")

    if scenario.workspace_id != scope.workspace_id or scenario.scope_id != scope.scope_id:
        raise ValueError("scenario must bind the exact scope and workspace identity")

    decisions = []

    for target in scenario.allowed_targets:
        decision = scope.Check(target, at=at)

        if not decision.Allowed():
            raise PermissionError(f"journey target rejected by scope: {decision.reason.value}")

        decisions.append(decision)

    return PreparedJourney(
        scenario, scenario.Digest(), scope.revision, at.isoformat(), tuple(decisions)
    )
